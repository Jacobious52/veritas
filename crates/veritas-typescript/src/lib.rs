use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    ffi::OsStr,
    fs,
    hash::{Hash, Hasher},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;
use tree_sitter::{Node, Parser};
use veritas_core::{
    config::{MutationConfig, TypeScriptPluginConfig},
    persist_mutation_record_artifacts, start_mutation_run,
};
use veritas_plugin_api::{
    finalize_mutation_metrics, mutation_taxonomy, ArtifactKind, ArtifactStatus, BehaviorReplayCase,
    BehaviorReplayObservation, BehaviorReplayStatus, CommandRecord, CoverageReport, Failure,
    FailureSeverity, GeneratedArtifact, LanguagePlugin, LineRange, MutationAttribution,
    MutationRecord, MutationStatus, PluginCapability, ProjectInfo, ReproCase, RiskLevel, RunStatus,
    SourceSpan, TargetKind, TestRunResult, VerificationPlan, VerificationQuality,
    VerificationStrategy, VerificationTarget,
};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct TypeScriptPlugin {
    config: TypeScriptPluginConfig,
}

#[derive(Debug, Clone)]
struct TypeScriptFunction {
    path: Utf8PathBuf,
    name: String,
    symbol: String,
    owner: Option<String>,
    params: Vec<String>,
    signature: String,
    line_range: LineRange,
    start_byte: usize,
    end_byte: usize,
    calls: Vec<String>,
}

#[derive(Debug, Clone)]
struct TypeScriptMutationCandidate {
    path: Utf8PathBuf,
    function: String,
    label: String,
    from: String,
    to: String,
    start_byte: usize,
    end_byte: usize,
    line_range: LineRange,
}

#[derive(Debug, Clone, Serialize)]
struct TypeScriptSymbolGraph<'a> {
    target_id: &'a str,
    symbols: Vec<TypeScriptSymbolNode<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct TypeScriptSymbolNode<'a> {
    id: String,
    path: &'a Utf8PathBuf,
    symbol: &'a str,
    name: &'a str,
    owner: Option<&'a str>,
    signature: &'a str,
    line_range: &'a LineRange,
    risk: RiskLevel,
    calls: &'a [String],
    params: &'a [String],
}

impl TypeScriptPlugin {
    pub fn new(config: TypeScriptPluginConfig) -> Self {
        Self { config }
    }
}

impl LanguagePlugin for TypeScriptPlugin {
    fn id(&self) -> &'static str {
        "typescript"
    }

    fn display_name(&self) -> &'static str {
        "TypeScript/JavaScript"
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::TargetDiscovery,
            PluginCapability::SymbolGraph,
            PluginCapability::GeneratedTests,
            PluginCapability::ExistingTests,
            PluginCapability::PropertyTests,
            PluginCapability::MutationChecks,
            PluginCapability::DifferentialReplay,
            PluginCapability::ResourceBudgets,
        ]
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo> {
        if !root.join("package.json").exists()
            && !root.join("tsconfig.json").exists()
            && !root.join("jsconfig.json").exists()
            && !contains_typescript_file(root)
        {
            return Err(anyhow!("TypeScript/JavaScript project not found"));
        }
        let name = root
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("typescript-project")
            .to_string();
        let manifests = [
            "package.json",
            "bun.lock",
            "bun.lockb",
            "tsconfig.json",
            "jsconfig.json",
        ]
        .into_iter()
        .filter(|path| root.join(path).exists())
        .map(Utf8PathBuf::from)
        .collect();
        Ok(ProjectInfo {
            language: "typescript".to_string(),
            name,
            root: utf8_path(root)?,
            manifests,
        })
    }

    fn discover_targets(&self, root: &Path) -> Result<Vec<VerificationTarget>> {
        let mut targets = vec![VerificationTarget {
            id: "typescript:project".to_string(),
            language: "typescript".to_string(),
            kind: TargetKind::Project,
            path: Utf8PathBuf::from("."),
            symbol: None,
            signature: None,
            line_range: None,
            description: "TypeScript/JavaScript project".to_string(),
            risk: RiskLevel::Medium,
        }];

        for function in discover_functions(root)? {
            targets.push(VerificationTarget {
                id: format!("typescript:{}:{}", function.path, function.symbol),
                language: "typescript".to_string(),
                kind: TargetKind::Function,
                path: function.path.clone(),
                symbol: Some(function.symbol.clone()),
                signature: Some(function.signature.clone()),
                line_range: Some(function.line_range.clone()),
                description: if let Some(owner) = &function.owner {
                    format!("TypeScript/JavaScript method {owner}.{}", function.name)
                } else {
                    format!("TypeScript/JavaScript function {}", function.name)
                },
                risk: infer_risk(&function.symbol),
            });
        }

        Ok(targets)
    }

    fn generate_tests(
        &self,
        target: &VerificationTarget,
        plan: &VerificationPlan,
    ) -> Result<Vec<GeneratedArtifact>> {
        let root = std::env::current_dir()?;
        let functions = discover_functions(&root).unwrap_or_default();
        let mut artifacts = vec![symbol_graph_artifact(
            &target.id,
            &target.path,
            target.symbol.as_deref(),
            &functions,
        )?];
        if plan
            .strategies
            .contains(&VerificationStrategy::PropertyTests)
        {
            if let Some(artifact) =
                property_candidate_artifact(target, target.symbol.as_deref(), &functions)?
            {
                artifacts.push(artifact);
            }
        }
        if plan
            .strategies
            .contains(&VerificationStrategy::MutationChecks)
        {
            artifacts.push(typescript_mutation_manifest_artifact(
                target,
                target.symbol.as_deref(),
                &functions,
            )?);
        }
        Ok(artifacts)
    }

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        _plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        let start = Instant::now();
        if !bun_available(root) {
            return Ok(TestRunResult {
                language: "typescript".to_string(),
                status: RunStatus::Skipped,
                commands: vec![skipped_bun_command(
                    root,
                    "bun not found; install Bun to run TypeScript/JavaScript tests",
                )?],
                failures: Vec::new(),
                duration_ms: start.elapsed().as_millis(),
                quality: VerificationQuality::default(),
            });
        }

        let command = run_command(root, "bun", ["test"], self.config.command_timeout_seconds)?;
        let status = command.status.clone();
        let failures = if status == RunStatus::Failed {
            vec![Failure {
                id: None,
                message: "bun test failed".to_string(),
                severity: FailureSeverity::Error,
                target_id: artifacts.first().map(|artifact| artifact.target_id.clone()),
                artifact_id: artifacts.first().map(|artifact| artifact.id.clone()),
                command: command_line(&command.program, &command.args),
                stdout_excerpt: excerpt(&command.stdout),
                stderr_excerpt: excerpt(&command.stderr),
                repro: Some(ReproCase {
                    command: command_line(&command.program, &command.args),
                    input: None,
                    path: None,
                }),
            }]
        } else {
            Vec::new()
        };

        let mut commands = vec![command];
        let mut failures = failures;
        let mut status = status;
        let mut quality = VerificationQuality::default();

        let property = run_typescript_property_artifacts(root, artifacts, &self.config)?;
        if property.status == RunStatus::Failed {
            status = RunStatus::Failed;
        }
        commands.extend(property.commands);
        failures.extend(property.failures);
        quality.property = property.quality.property;

        if artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        {
            let mutation = run_typescript_mutations(root, artifacts, &self.config)?;
            if mutation.status == RunStatus::Failed {
                status = RunStatus::Failed;
            }
            commands.extend(mutation.commands);
            failures.extend(mutation.failures);
            quality.mutation = mutation.quality.mutation;
        }

        Ok(TestRunResult {
            language: "typescript".to_string(),
            status,
            commands,
            failures,
            duration_ms: start.elapsed().as_millis(),
            quality,
        })
    }

    fn collect_coverage(&self, _root: &Path) -> Result<Option<CoverageReport>> {
        Ok(Some(CoverageReport {
            tool: "bun coverage".to_string(),
            summary: "not collected: TypeScript/JavaScript coverage is not implemented yet"
                .to_string(),
            files: Vec::new(),
        }))
    }

    fn replay_behavior(
        &self,
        root: &Path,
        target: &VerificationTarget,
        case: &BehaviorReplayCase,
    ) -> Result<Option<BehaviorReplayObservation>> {
        let functions = discover_functions(root)?;
        let Some(function) = functions
            .iter()
            .find(|function| typescript_target_matches_function(&target.id, function))
        else {
            return Ok(None);
        };
        replay_typescript_function(root, function, case, &self.config).map(Some)
    }

    fn replay_behaviors(
        &self,
        root: &Path,
        target: &VerificationTarget,
        cases: &[BehaviorReplayCase],
    ) -> Result<BTreeMap<String, BehaviorReplayObservation>> {
        let functions = discover_functions(root)?;
        let Some(function) = functions
            .iter()
            .find(|function| typescript_target_matches_function(&target.id, function))
        else {
            return Ok(BTreeMap::new());
        };
        replay_typescript_function_batch(root, function, cases, &self.config)
    }
}

fn discover_functions(root: &Path) -> Result<Vec<TypeScriptFunction>> {
    let mut functions = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry.path(), entry.file_name()))
    {
        let entry = entry?;
        if !entry.file_type().is_file() || !is_typescript_source(entry.path()) {
            continue;
        }
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let mut parser = parser_for_path(entry.path())?;
        let tree = parser.parse(&contents, None).ok_or_else(|| {
            anyhow!(
                "failed to parse TypeScript/JavaScript source {}",
                entry.path().display()
            )
        })?;
        let path = relative_utf8(root, entry.path())?;
        collect_typescript_functions(tree.root_node(), &contents, &path, &mut functions)?;
    }
    functions.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.symbol.cmp(&right.symbol))
    });
    functions.dedup_by(|left, right| left.path == right.path && left.symbol == right.symbol);
    Ok(functions)
}

fn parser_for_path(path: &Path) -> Result<Parser> {
    let mut parser = Parser::new();
    match path.extension().and_then(OsStr::to_str) {
        Some("tsx") => parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .map_err(|error| anyhow!("failed to load tree-sitter TSX grammar: {error}"))?,
        Some("ts") => parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .map_err(|error| anyhow!("failed to load tree-sitter TypeScript grammar: {error}"))?,
        Some("js" | "jsx" | "mjs" | "cjs") => parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .map_err(|error| anyhow!("failed to load tree-sitter JavaScript grammar: {error}"))?,
        _ => return Err(anyhow!("unsupported TypeScript/JavaScript source path")),
    }
    Ok(parser)
}

fn collect_typescript_functions(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
    functions: &mut Vec<TypeScriptFunction>,
) -> Result<()> {
    if matches!(
        node.kind(),
        "function_declaration" | "generator_function_declaration" | "method_definition"
    ) {
        if let Some(function) = parse_named_function(node, source, path)? {
            functions.push(function);
        }
    } else if node.kind() == "variable_declarator" {
        if let Some(function) = parse_variable_function(node, source, path)? {
            functions.push(function);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_typescript_functions(child, source, path, functions)?;
    }
    Ok(())
}

fn parse_named_function(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
) -> Result<Option<TypeScriptFunction>> {
    let Some(name_node) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let name = node_text(name_node, source)?.to_string();
    if should_skip_symbol(&name) {
        return Ok(None);
    }
    let owner = function_owner(node, source)?;
    let symbol = owner
        .as_ref()
        .map(|owner| format!("{owner}.{name}"))
        .unwrap_or_else(|| name.clone());
    Ok(Some(TypeScriptFunction {
        path: path.clone(),
        name,
        symbol,
        owner,
        params: function_params(node, source)?,
        signature: signature_text(node, source)?.trim().to_string(),
        line_range: node_line_range(node),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        calls: calls_in_function(node, source)?,
    }))
}

fn parse_variable_function(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
) -> Result<Option<TypeScriptFunction>> {
    let Some(value) = node.child_by_field_name("value") else {
        return Ok(None);
    };
    if !matches!(
        value.kind(),
        "arrow_function" | "function_expression" | "generator_function"
    ) {
        return Ok(None);
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let name = node_text(name_node, source)?.trim().to_string();
    if should_skip_symbol(&name) || name.contains(['{', '[', '.']) {
        return Ok(None);
    }
    Ok(Some(TypeScriptFunction {
        path: path.clone(),
        symbol: name.clone(),
        owner: None,
        name,
        params: function_params(value, source)?,
        signature: signature_text(node, source)?.trim().to_string(),
        line_range: node_line_range(node),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        calls: calls_in_function(value, source)?,
    }))
}

fn function_owner(node: Node<'_>, source: &str) -> Result<Option<String>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "class_declaration" | "class") {
            return Ok(parent
                .child_by_field_name("name")
                .map(|node| node_text(node, source).unwrap_or_default().to_string()));
        }
        current = parent.parent();
    }
    Ok(None)
}

fn function_params(node: Node<'_>, source: &str) -> Result<Vec<String>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Ok(Vec::new());
    };
    let mut params = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        match child.kind() {
            "required_parameter" | "optional_parameter" | "formal_parameter" => {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    let name = node_text(pattern, source)?.trim();
                    if !name.is_empty() {
                        params.push(name.to_string());
                    }
                } else {
                    let name = node_text(child, source)?
                        .split([':', '=', '?'])
                        .next()
                        .unwrap_or_default()
                        .trim();
                    if !name.is_empty() && name != "," {
                        params.push(name.to_string());
                    }
                }
            }
            "identifier" => {
                let name = node_text(child, source)?.trim();
                if !name.is_empty() {
                    params.push(name.to_string());
                }
            }
            _ => {}
        }
    }
    params.sort();
    params.dedup();
    Ok(params)
}

fn calls_in_function(node: Node<'_>, source: &str) -> Result<Vec<String>> {
    let mut calls = Vec::new();
    collect_calls(node, source, &mut calls)?;
    calls.sort();
    calls.dedup();
    Ok(calls)
}

fn collect_calls(node: Node<'_>, source: &str, calls: &mut Vec<String>) -> Result<()> {
    if matches!(
        node.kind(),
        "call_expression" | "new_expression" | "optional_call_expression"
    ) {
        if let Some(function) = node.child_by_field_name("function") {
            let text = node_text(function, source)?.trim();
            if !text.is_empty() {
                calls.push(text.to_string());
            }
        } else if node.kind() == "new_expression" {
            let mut cursor = node.walk();
            let child = node
                .children(&mut cursor)
                .find(|child| child.kind() == "identifier");
            if let Some(child) = child {
                calls.push(node_text(child, source)?.trim().to_string());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_calls(child, source, calls)?;
    }
    Ok(())
}

fn symbol_graph_artifact(
    target_id: &str,
    target_path: &Utf8PathBuf,
    target_symbol: Option<&str>,
    functions: &[TypeScriptFunction],
) -> Result<GeneratedArtifact> {
    let symbols = functions
        .iter()
        .filter(|function| {
            if let Some(symbol) = target_symbol {
                function.symbol == symbol && function.path == *target_path
            } else {
                target_path.as_str() == "." || function.path == *target_path
            }
        })
        .map(|function| TypeScriptSymbolNode {
            id: format!("typescript:{}:{}", function.path, function.symbol),
            path: &function.path,
            symbol: &function.symbol,
            name: &function.name,
            owner: function.owner.as_deref(),
            signature: &function.signature,
            line_range: &function.line_range,
            risk: infer_risk(&function.symbol),
            calls: &function.calls,
            params: &function.params,
        })
        .collect::<Vec<_>>();
    let contents = serde_json::to_string_pretty(&TypeScriptSymbolGraph { target_id, symbols })?;
    Ok(GeneratedArtifact {
        id: format!("typescript-symbol-{}", safe_ident(target_id)),
        language: "typescript".to_string(),
        kind: ArtifactKind::SymbolGraph,
        target_id: target_id.to_string(),
        path: Utf8PathBuf::from(format!(
            ".veritas/symbols/typescript_{}.json",
            safe_ident(target_id)
        )),
        contents,
        description: "Tree-sitter TypeScript/JavaScript symbol graph for selected target"
            .to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn property_candidate_artifact(
    target: &VerificationTarget,
    target_symbol: Option<&str>,
    functions: &[TypeScriptFunction],
) -> Result<Option<GeneratedArtifact>> {
    let selected = functions
        .iter()
        .filter(|function| {
            if let Some(symbol) = target_symbol {
                function.symbol == symbol && function.path == target.path
            } else {
                target.path.as_str() == "." || function.path == target.path
            }
        })
        .filter(|function| {
            function.owner.is_none() && !function.params.is_empty() && function.params.len() <= 4
        })
        .take(8)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(None);
    }
    let contents = render_typescript_property_test(&selected)?;
    Ok(Some(GeneratedArtifact {
        id: format!("typescript-property-{}", safe_ident(&target.id)),
        language: "typescript".to_string(),
        kind: ArtifactKind::PropertyTest,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(format!(
            ".veritas/properties/typescript_{}.test.ts",
            safe_ident(&target.id)
        )),
        contents,
        description: "Reviewable executable TypeScript/JavaScript property checks".to_string(),
        status: ArtifactStatus::Planned,
    }))
}

fn render_typescript_property_test(functions: &[&TypeScriptFunction]) -> Result<String> {
    let mut contents = String::from(
        "import { expect, test } from \"bun:test\";\n\n\
         const observe = (call: () => unknown) => {\n\
           try {\n\
             const value = call();\n\
             return { status: \"ok\", value: JSON.stringify(value) };\n\
           } catch (error) {\n\
             return { status: \"error\", value: error instanceof Error ? error.name : String(error) };\n\
           }\n\
         };\n\n",
    );

    let mut imports = BTreeMap::<Utf8PathBuf, Vec<String>>::new();
    for function in functions {
        imports
            .entry(function.path.clone())
            .or_default()
            .push(function.name.clone());
    }
    for (path, names) in imports {
        let import_path = format!("../../{}", path.as_str());
        contents.push_str(&format!(
            "import {{ {} }} from {:?};\n",
            names.join(", "),
            import_path
        ));
    }
    contents.push('\n');

    for function in functions {
        let cases = property_cases(function)?;
        let params = function.params.join(", ");
        contents.push_str(&format!(
            "test(\"veritas property: {} is deterministic for seeded inputs\", () => {{\n\
               const cases = {};\n\
               for (const args of cases) {{\n\
                 const first = observe(() => {}(...args));\n\
                 const second = observe(() => {}(...args));\n\
                 expect(first).toEqual(second); // is_deterministic\n\
                 expect([\"ok\", \"error\"]).toContain(first.status); // prop_assert does_not_panic\n\
               }}\n\
             }});\n\n",
            function.symbol,
            serde_json::to_string(&cases)?,
            function.name,
            function.name
        ));
        contents.push_str(&format!(
            "// Params for {}: {}\n\n",
            function.symbol,
            if params.is_empty() { "<none>" } else { &params }
        ));
    }
    Ok(contents)
}

fn property_cases(function: &TypeScriptFunction) -> Result<Vec<Vec<serde_json::Value>>> {
    let seeds = function
        .params
        .iter()
        .map(|param| property_values_for_param(param))
        .collect::<Vec<_>>();
    let mut cases = Vec::new();
    for index in 0..4 {
        cases.push(
            seeds
                .iter()
                .map(|values| values[index.min(values.len().saturating_sub(1))].clone())
                .collect::<Vec<_>>(),
        );
    }
    Ok(cases)
}

fn property_values_for_param(param: &str) -> Vec<serde_json::Value> {
    let lowered = param.to_ascii_lowercase();
    if lowered.contains("cents")
        || lowered.contains("amount")
        || lowered.contains("total")
        || lowered.contains("count")
        || lowered.contains("limit")
        || lowered.contains("price")
    {
        vec![0.into(), 1.into(), 5_000.into(), 50_001.into()]
    } else if lowered.contains("role") {
        vec!["admin".into(), "support".into(), "viewer".into(), "".into()]
    } else if lowered.contains("enabled") || lowered.starts_with("is") || lowered.starts_with("has")
    {
        vec![true.into(), false.into(), true.into(), false.into()]
    } else {
        vec![
            "".into(),
            " 1200 ".into(),
            "VIP".into(),
            "not-a-number".into(),
        ]
    }
}

fn typescript_mutation_manifest_artifact(
    target: &VerificationTarget,
    target_symbol: Option<&str>,
    functions: &[TypeScriptFunction],
) -> Result<GeneratedArtifact> {
    let selected = functions
        .iter()
        .filter(|function| {
            if let Some(symbol) = target_symbol {
                function.symbol == symbol && function.path == target.path
            } else {
                target.path.as_str() == "." || function.path == target.path
            }
        })
        .map(|function| {
            serde_json::json!({
                "id": format!("typescript:{}:{}", function.path, function.symbol),
                "path": &function.path,
                "symbol": &function.symbol,
                "signature": &function.signature,
                "line_range": &function.line_range,
                "risk": infer_risk(&function.symbol),
                "operators": [
                    "comparison_boundary",
                    "boolean_guard",
                    "strict_equality",
                    "default_return",
                    "string_normalization"
                ],
            })
        })
        .collect::<Vec<_>>();
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "language": "typescript",
        "mode": "mutation_manifest",
        "target_id": target.id,
        "status": "planned",
        "targets": selected,
        "next_step": "TypeScript/JavaScript mutation execution uses Bun test and the shared mutation record taxonomy.",
    }))?;
    Ok(GeneratedArtifact {
        id: format!("typescript-mutation-{}", safe_ident(&target.id)),
        language: "typescript".to_string(),
        kind: ArtifactKind::MutationCheck,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(format!(
            ".veritas/mutations/typescript_{}.json",
            safe_ident(&target.id)
        )),
        contents,
        description: "Tree-sitter TypeScript/JavaScript mutation target/operator manifest"
            .to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn run_typescript_property_artifacts(
    root: &Path,
    artifacts: &[GeneratedArtifact],
    config: &TypeScriptPluginConfig,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let property_paths = artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::PropertyTest)
        .map(|artifact| format!("./{}", artifact.path))
        .collect::<Vec<_>>();
    if property_paths.is_empty() {
        return Ok(TestRunResult {
            language: "typescript".to_string(),
            status: RunStatus::Skipped,
            commands: Vec::new(),
            failures: Vec::new(),
            duration_ms: 0,
            quality: VerificationQuality::default(),
        });
    }
    let mut args = vec!["test".to_string()];
    args.extend(property_paths);
    let command = run_command(
        root,
        "bun",
        args.iter().map(String::as_str),
        config.command_timeout_seconds.min(60),
    )?;
    let mut quality = VerificationQuality::default();
    quality.property.generated_artifacts = 1;
    quality.property.no_panic_properties = 1;
    quality.property.deterministic_properties = 1;
    if command.status == RunStatus::Failed {
        quality.property.failed_generated_tests = 1;
    }
    let failures = if command.status == RunStatus::Failed {
        vec![Failure {
            id: None,
            message: "generated TypeScript/JavaScript property checks failed".to_string(),
            severity: FailureSeverity::Warning,
            target_id: artifacts
                .iter()
                .find(|artifact| artifact.kind == ArtifactKind::PropertyTest)
                .map(|artifact| artifact.target_id.clone()),
            artifact_id: artifacts
                .iter()
                .find(|artifact| artifact.kind == ArtifactKind::PropertyTest)
                .map(|artifact| artifact.id.clone()),
            command: command_line(&command.program, &command.args),
            stdout_excerpt: excerpt(&command.stdout),
            stderr_excerpt: excerpt(&command.stderr),
            repro: Some(ReproCase {
                command: command_line(&command.program, &command.args),
                input: None,
                path: artifacts
                    .iter()
                    .find(|artifact| artifact.kind == ArtifactKind::PropertyTest)
                    .map(|artifact| artifact.path.clone()),
            }),
        }]
    } else {
        Vec::new()
    };
    Ok(TestRunResult {
        language: "typescript".to_string(),
        status: command.status.clone(),
        commands: vec![command],
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality,
    })
}

fn run_typescript_mutations(
    root: &Path,
    artifacts: &[GeneratedArtifact],
    config: &TypeScriptPluginConfig,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let functions = discover_functions(root)?;
    let candidates = typescript_mutation_candidates(root, &functions, artifacts)?
        .into_iter()
        .filter(|candidate| typescript_mutation_candidate_in_shard(candidate, &config.mutation))
        .filter(|candidate| {
            config.mutation.report_filtered
                || typescript_mutation_candidate_allowed(candidate, config)
        })
        .collect::<Vec<_>>();
    let mut quality = VerificationQuality::default();
    quality.mutation.generated = candidates.len();
    quality.mutation.effective_workers = 1;
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut status = RunStatus::Passed;
    let run_dir = start_mutation_run(root, "typescript")?;

    for candidate in candidates
        .into_iter()
        .take(config.mutation.max_mutants.unwrap_or(8))
    {
        let domain = typescript_mutation_domain(&candidate);
        let operator = typescript_mutation_operator(&candidate.label);
        record_mutation_generated(&mut quality.mutation.by_domain, &domain);
        record_mutation_generated(&mut quality.mutation.by_operator, &operator);
        if !typescript_mutation_candidate_allowed(&candidate, config) {
            let mut record = typescript_mutation_record(
                &candidate,
                &domain,
                &operator,
                MutationStatus::Skipped,
                None,
                0,
            );
            record.skip_reason = Some("filtered by mutation config".to_string());
            persist_mutation_record_artifacts(root, &run_dir, &mut record, None)?;
            quality.mutation.records.push(record);
            continue;
        }
        if config.mutation.dry_run {
            quality.mutation.runnable += 1;
            record_mutation_runnable(&mut quality.mutation.by_domain, &domain);
            record_mutation_runnable(&mut quality.mutation.by_operator, &operator);
            let mut record = typescript_mutation_record(
                &candidate,
                &domain,
                &operator,
                MutationStatus::Runnable,
                None,
                0,
            );
            persist_mutation_record_artifacts(root, &run_dir, &mut record, None)?;
            quality.mutation.records.push(record);
            continue;
        }

        quality.mutation.runnable += 1;
        quality.mutation.executed += 1;
        record_mutation_runnable(&mut quality.mutation.by_domain, &domain);
        record_mutation_runnable(&mut quality.mutation.by_operator, &operator);
        record_mutation_executed(&mut quality.mutation.by_domain, &domain);
        record_mutation_executed(&mut quality.mutation.by_operator, &operator);

        let path = root.join(&candidate.path);
        let original = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut mutated = original.clone();
        mutated.replace_range(candidate.start_byte..candidate.end_byte, &candidate.to);
        fs::write(&path, mutated).with_context(|| {
            format!(
                "failed to write TypeScript/JavaScript mutation {} in {}",
                candidate.label,
                path.display()
            )
        })?;
        let command = run_command(
            root,
            "bun",
            ["test"],
            config.command_timeout_seconds.min(60),
        );
        fs::write(&path, original)
            .with_context(|| format!("failed to restore {}", path.display()))?;
        let command = command?;
        let command_text = command_line(&command.program, &command.args);
        let mutation_status = if command.status == RunStatus::Passed {
            quality.mutation.survived += 1;
            record_mutation_survived(&mut quality.mutation.by_domain, &domain);
            record_mutation_survived(&mut quality.mutation.by_operator, &operator);
            status = RunStatus::Failed;
            failures.push(typescript_mutation_failure(
                artifacts,
                &candidate,
                &command,
                &command_text,
            ));
            MutationStatus::Lived
        } else if typescript_mutation_not_viable(&command) {
            quality.mutation.not_viable += 1;
            record_mutation_not_viable(&mut quality.mutation.by_domain, &domain);
            record_mutation_not_viable(&mut quality.mutation.by_operator, &operator);
            MutationStatus::NotViable
        } else {
            quality.mutation.killed += 1;
            record_mutation_killed(&mut quality.mutation.by_domain, &domain);
            record_mutation_killed(&mut quality.mutation.by_operator, &operator);
            MutationStatus::Killed
        };
        let mut record = typescript_mutation_record(
            &candidate,
            &domain,
            &operator,
            mutation_status,
            Some(&command_text),
            command.duration_ms,
        );
        persist_mutation_record_artifacts(root, &run_dir, &mut record, Some(&command))?;
        quality.mutation.records.push(record);
        commands.push(command);
    }
    finalize_mutation_skips(&mut quality.mutation.by_domain);
    finalize_mutation_skips(&mut quality.mutation.by_operator);
    finalize_mutation_metrics(&mut quality.mutation);

    Ok(TestRunResult {
        language: "typescript".to_string(),
        status,
        commands,
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality,
    })
}

fn typescript_mutation_candidates(
    root: &Path,
    functions: &[TypeScriptFunction],
    artifacts: &[GeneratedArtifact],
) -> Result<Vec<TypeScriptMutationCandidate>> {
    let mut candidates = Vec::new();
    for function in functions {
        if !typescript_function_selected_for_mutation(function, artifacts) {
            continue;
        }
        let path = root.join(&function.path);
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if function_has_mutation_skip_annotation(&contents, function.start_byte, function.end_byte)
        {
            continue;
        }
        for (from, to, label) in [
            ("<=", "<", "boundary comparison mutation"),
            (">=", ">", "boundary comparison mutation"),
            ("===", "!==", "strict equality mutation"),
            ("!==", "===", "strict equality mutation"),
            ("&&", "||", "boolean guard mutation"),
            ("||", "&&", "boolean guard mutation"),
            ("return false", "return true", "default return mutation"),
            ("return true", "return false", "default return mutation"),
            ("return null", "return 0", "default null mutation"),
            (".trim()", "", "string normalization mutation"),
            (".toLowerCase()", "", "string normalization mutation"),
            (".toUpperCase()", "", "string normalization mutation"),
        ] {
            push_typescript_mutation(&contents, function, from, to, label, &mut candidates);
        }
    }
    candidates.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.start_byte.cmp(&right.start_byte))
            .then(left.label.cmp(&right.label))
    });
    candidates.dedup_by(|left, right| {
        left.path == right.path
            && left.start_byte == right.start_byte
            && left.end_byte == right.end_byte
            && left.to == right.to
    });
    Ok(candidates)
}

fn push_typescript_mutation(
    contents: &str,
    function: &TypeScriptFunction,
    from: &str,
    to: &str,
    label: &str,
    candidates: &mut Vec<TypeScriptMutationCandidate>,
) {
    let Some(source) = contents.get(function.start_byte..function.end_byte) else {
        return;
    };
    let Some(offset) = source.find(from) else {
        return;
    };
    let start_byte = function.start_byte + offset;
    candidates.push(TypeScriptMutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: label.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        start_byte,
        end_byte: start_byte + from.len(),
        line_range: function.line_range.clone(),
    });
}

fn function_has_mutation_skip_annotation(source: &str, start_byte: usize, end_byte: usize) -> bool {
    source
        .get(start_byte..end_byte)
        .is_some_and(|body| body.contains("veritas:skip-mutation"))
}

fn typescript_function_selected_for_mutation(
    function: &TypeScriptFunction,
    artifacts: &[GeneratedArtifact],
) -> bool {
    artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        .any(|artifact| {
            artifact.target_id == "typescript:project"
                || artifact.target_id == format!("typescript:{}", function.path)
                || artifact.target_id == format!("typescript:{}:{}", function.path, function.symbol)
        })
}

fn typescript_mutation_failure(
    artifacts: &[GeneratedArtifact],
    candidate: &TypeScriptMutationCandidate,
    command: &CommandRecord,
    command_text: &str,
) -> Failure {
    Failure {
        id: None,
        message: format!(
            "mutation survived in TypeScript/JavaScript function `{}`: {}",
            candidate.function, candidate.label
        ),
        severity: FailureSeverity::Warning,
        target_id: Some(format!(
            "typescript:{}:{}",
            candidate.path, candidate.function
        )),
        artifact_id: artifacts
            .iter()
            .find(|artifact| artifact.kind == ArtifactKind::MutationCheck)
            .map(|artifact| artifact.id.clone()),
        command: command_text.to_string(),
        stdout_excerpt: excerpt(&command.stdout),
        stderr_excerpt: excerpt(&command.stderr),
        repro: Some(ReproCase {
            command: format!(
                "replace `{}` with `{}` in {} and run {}",
                candidate.from, candidate.to, candidate.path, command_text
            ),
            input: None,
            path: Some(candidate.path.clone()),
        }),
    }
}

fn typescript_mutation_record(
    candidate: &TypeScriptMutationCandidate,
    domain: &str,
    operator: &str,
    status: MutationStatus,
    command: Option<&str>,
    duration_ms: u128,
) -> MutationRecord {
    MutationRecord {
        id: typescript_mutation_candidate_id(candidate),
        language: "typescript".to_string(),
        path: candidate.path.clone(),
        symbol: candidate.function.clone(),
        operator: operator.to_string(),
        domain: domain.to_string(),
        status,
        from: Some(candidate.from.clone()),
        to: Some(candidate.to.clone()),
        line_range: Some(candidate.line_range.clone()),
        source_span: Some(SourceSpan {
            start_byte: candidate.start_byte,
            end_byte: candidate.end_byte,
        }),
        diff: Some(typescript_mutation_diff(candidate)),
        diff_path: None,
        outcome_path: None,
        command_log_path: None,
        stdout_log_path: None,
        stderr_log_path: None,
        risk_note: Some(mutation_taxonomy::risk_note(domain, operator).to_string()),
        suggested_test: Some(mutation_taxonomy::suggested_test(domain, operator).to_string()),
        skip_reason: mutation_skip_reason(status),
        selected_test_command: command.map(ToString::to_string),
        test_selection_hint: None,
        test_selection_fallback: None,
        brittleness_probe: domain == "brittleness",
        command: command.map(ToString::to_string),
        duration_ms,
    }
}

fn typescript_mutation_candidate_id(candidate: &TypeScriptMutationCandidate) -> String {
    format!(
        "typescript:{}:{}:{}:{}",
        candidate.path, candidate.function, candidate.start_byte, candidate.end_byte
    )
}

fn typescript_mutation_diff(candidate: &TypeScriptMutationCandidate) -> String {
    format!(
        "--- {}\n+++ {}\n@@ bytes {}..{} @@\n-{}\n+{}",
        candidate.path,
        candidate.path,
        candidate.start_byte,
        candidate.end_byte,
        candidate.from,
        candidate.to
    )
}

fn mutation_skip_reason(status: MutationStatus) -> Option<String> {
    match status {
        MutationStatus::NotCovered => Some("no selected tests cover this mutant".to_string()),
        MutationStatus::Skipped => Some("mutation was skipped before execution".to_string()),
        MutationStatus::TimedOut => Some("mutation test command timed out".to_string()),
        MutationStatus::NotViable => Some("mutation did not compile or could not run".to_string()),
        _ => None,
    }
}

fn typescript_mutation_domain(candidate: &TypeScriptMutationCandidate) -> String {
    let value = format!("{} {}", candidate.function, candidate.label).to_ascii_lowercase();
    mutation_taxonomy::normalize_domain(&value).to_string()
}

fn typescript_mutation_operator(label: &str) -> String {
    mutation_taxonomy::normalize_operator(label).to_string()
}

fn typescript_mutation_candidate_allowed(
    candidate: &TypeScriptMutationCandidate,
    config: &TypeScriptPluginConfig,
) -> bool {
    let path = candidate.path.as_str();
    if !config.mutation.include_paths.is_empty()
        && !config
            .mutation
            .include_paths
            .iter()
            .any(|pattern| text_matches(path, pattern))
    {
        return false;
    }
    if config
        .mutation
        .exclude_paths
        .iter()
        .any(|pattern| text_matches(path, pattern))
    {
        return false;
    }
    if !config.mutation.include_symbols.is_empty()
        && !config
            .mutation
            .include_symbols
            .iter()
            .any(|pattern| text_matches(&candidate.function, pattern))
    {
        return false;
    }
    if config
        .mutation
        .exclude_symbols
        .iter()
        .any(|pattern| text_matches(&candidate.function, pattern))
    {
        return false;
    }
    let target_id = format!("typescript:{}:{}", candidate.path, candidate.function);
    if !config.mutation.include_target_ids.is_empty()
        && !config
            .mutation
            .include_target_ids
            .iter()
            .any(|pattern| text_matches(&target_id, pattern))
    {
        return false;
    }
    if config
        .mutation
        .exclude_target_ids
        .iter()
        .any(|pattern| text_matches(&target_id, pattern))
    {
        return false;
    }
    let id = typescript_mutation_candidate_id(candidate);
    if !config.mutation.include_mutant_ids.is_empty()
        && !config
            .mutation
            .include_mutant_ids
            .iter()
            .any(|pattern| text_matches(&id, pattern))
    {
        return false;
    }
    if config
        .mutation
        .exclude_mutant_ids
        .iter()
        .any(|pattern| text_matches(&id, pattern))
    {
        return false;
    }
    let domain = typescript_mutation_domain(candidate);
    if !config.mutation.enabled_domains.is_empty()
        && !config
            .mutation
            .enabled_domains
            .iter()
            .any(|enabled| taxonomy_matches(&domain, enabled))
    {
        return false;
    }
    if config
        .mutation
        .disabled_domains
        .iter()
        .any(|disabled| taxonomy_matches(&domain, disabled))
    {
        return false;
    }
    let operator = typescript_mutation_operator(&candidate.label);
    if !config.mutation.enabled_operators.is_empty()
        && !config
            .mutation
            .enabled_operators
            .iter()
            .any(|enabled| taxonomy_matches(&operator, enabled))
    {
        return false;
    }
    !config
        .mutation
        .disabled_operators
        .iter()
        .any(|disabled| taxonomy_matches(&operator, disabled))
}

fn typescript_mutation_candidate_in_shard(
    candidate: &TypeScriptMutationCandidate,
    config: &MutationConfig,
) -> bool {
    let Some(shard_count) = config.shard_count else {
        return true;
    };
    let shard_index = config.shard_index.unwrap_or(0);
    if shard_index >= shard_count {
        return false;
    }
    let mut hasher = DefaultHasher::new();
    candidate.path.hash(&mut hasher);
    candidate.function.hash(&mut hasher);
    candidate.start_byte.hash(&mut hasher);
    candidate.end_byte.hash(&mut hasher);
    (hasher.finish() as usize % shard_count) == shard_index
}

fn taxonomy_matches(operator: &str, configured: &str) -> bool {
    let configured = configured.replace('-', "_").to_ascii_lowercase();
    text_matches(operator, configured.trim())
}

fn text_matches(text: &str, pattern: &str) -> bool {
    if let Some(exact) = pattern.strip_prefix("exact:") {
        return text.eq_ignore_ascii_case(exact);
    }
    let pattern = pattern.strip_prefix("glob:").unwrap_or(pattern);
    let text = text.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_suffix('$') {
        return text.ends_with(suffix);
    }
    if pattern.contains('*') {
        let mut rest = text.as_str();
        for part in pattern.split('*').filter(|part| !part.is_empty()) {
            let Some(offset) = rest.find(part) else {
                return false;
            };
            rest = &rest[offset + part.len()..];
        }
        return true;
    }
    text.contains(&pattern)
}

fn record_mutation_generated(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().generated += 1;
}

fn record_mutation_runnable(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().runnable += 1;
}

fn record_mutation_executed(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().executed += 1;
}

fn record_mutation_killed(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().killed += 1;
}

fn record_mutation_survived(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().survived += 1;
}

fn record_mutation_not_viable(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().not_viable += 1;
}

fn finalize_mutation_skips(metrics: &mut BTreeMap<String, MutationAttribution>) {
    for metric in metrics.values_mut() {
        metric.skipped = metric.generated.saturating_sub(metric.executed);
    }
}

fn typescript_mutation_not_viable(command: &CommandRecord) -> bool {
    let output = format!("{}\n{}", command.stdout, command.stderr).to_ascii_lowercase();
    output.contains("syntaxerror")
        || output.contains("typeerror")
        || output.contains("referenceerror")
        || output.contains("cannot find module")
        || output.contains("build failed")
}

fn replay_typescript_function(
    root: &Path,
    function: &TypeScriptFunction,
    case: &BehaviorReplayCase,
    config: &TypeScriptPluginConfig,
) -> Result<BehaviorReplayObservation> {
    let observations =
        replay_typescript_function_batch(root, function, std::slice::from_ref(case), config)?;
    Ok(observations
        .get(&case.name)
        .cloned()
        .unwrap_or_else(|| unsupported_typescript_replay("replay case did not execute")))
}

fn replay_typescript_function_batch(
    root: &Path,
    function: &TypeScriptFunction,
    cases: &[BehaviorReplayCase],
    config: &TypeScriptPluginConfig,
) -> Result<BTreeMap<String, BehaviorReplayObservation>> {
    let mut observations = BTreeMap::new();
    if cases.is_empty() {
        return Ok(observations);
    }
    if function.owner.is_some() {
        insert_unsupported_typescript_replay(
            &mut observations,
            cases,
            "method replay requires receiver construction",
        );
        return Ok(observations);
    }
    if function.params.is_empty() {
        insert_unsupported_typescript_replay(
            &mut observations,
            cases,
            "executable replay requires at least one supported argument",
        );
        return Ok(observations);
    }
    if !bun_available(root) {
        insert_unsupported_typescript_replay(
            &mut observations,
            cases,
            "bun not found; install Bun to run TypeScript/JavaScript replay",
        );
        return Ok(observations);
    }

    let runnable = cases
        .iter()
        .filter(|case| {
            if case.inputs.is_empty() {
                observations.insert(
                    case.name.clone(),
                    unsupported_typescript_replay(
                        "executable replay requires at least one seeded input",
                    ),
                );
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();
    if runnable.is_empty() {
        return Ok(observations);
    }

    let script = render_typescript_replay_batch_script(function, &runnable)?;
    let script_path = root.join(".veritas").join(format!(
        "tmp_typescript_replay_{}_{}.mjs",
        std::process::id(),
        safe_ident(&function.symbol)
    ));
    if let Some(parent) = script_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&script_path, script)
        .with_context(|| format!("failed to write {}", script_path.display()))?;
    let command = run_command(
        root,
        "bun",
        [script_path.to_string_lossy().as_ref()],
        config.command_timeout_seconds.min(30),
    );
    let cleanup = fs::remove_file(&script_path)
        .with_context(|| format!("failed to remove {}", script_path.display()));
    let command = command?;
    cleanup?;

    let mut by_case = parse_replay_case_marker_output(&command.stdout);
    for case in runnable {
        observations.insert(
            case.name.clone(),
            replay_observation_from_command(
                &command,
                by_case.remove(&case.name).unwrap_or_default(),
            ),
        );
    }
    Ok(observations)
}

fn render_typescript_replay_batch_script(
    function: &TypeScriptFunction,
    cases: &[&BehaviorReplayCase],
) -> Result<String> {
    let cases = cases
        .iter()
        .map(|case| {
            serde_json::json!({
                "name": &case.name,
                "inputs": &case.inputs,
            })
        })
        .collect::<Vec<_>>();
    let cases = serde_json::to_string(&cases)?;
    let import_path = format!("../{}", function.path.as_str());
    Ok(format!(
        r#"import {{ {name} as target }} from {import_path:?};

const cases = JSON.parse({cases:?});
const arity = {arity};

const callArgs = (value) => {{
  if (arity === 1) return [value];
  if (Array.isArray(value) && value.length === arity) return value;
  throw new Error("replay input does not match target arity");
}};

for (const replayCase of cases) {{
  for (const value of replayCase.inputs) {{
    let status = "observed";
    let output = "";
    try {{
      output = JSON.stringify(target(...callArgs(value)));
    }} catch (error) {{
      status = "exception";
      output = error instanceof Error ? `${{error.name}}:${{error.message}}` : String(error);
    }}
    console.log(`__VERITAS_REPLAY_CASE__${{replayCase.name}}\t${{JSON.stringify(value)}}\t${{status}}\t${{output}}`);
  }}
}}
"#,
        name = function.name,
        import_path = import_path,
        arity = function.params.len(),
        cases = cases
    ))
}

fn parse_replay_case_marker_output(stdout: &str) -> BTreeMap<String, Vec<serde_json::Value>> {
    let mut by_case: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    for line in stdout.lines() {
        let Some(marker) = line.find("__VERITAS_REPLAY_CASE__") else {
            continue;
        };
        let payload = &line[marker + "__VERITAS_REPLAY_CASE__".len()..];
        let mut parts = payload.splitn(4, '\t');
        let Some(case) = parts.next() else {
            continue;
        };
        let Some(input) = parts.next() else {
            continue;
        };
        let Some(status) = parts.next() else {
            continue;
        };
        let output = parts.next().unwrap_or_default();
        by_case
            .entry(case.to_string())
            .or_default()
            .push(serde_json::json!({
                "input": input,
                "status": status,
                "output": output,
            }));
    }
    by_case
}

fn unsupported_typescript_replay(reason: &str) -> BehaviorReplayObservation {
    BehaviorReplayObservation {
        status: BehaviorReplayStatus::Unsupported,
        output: serde_json::json!({ "reason": reason }),
        command: None,
        stdout_excerpt: None,
        stderr_excerpt: None,
        duration_ms: None,
    }
}

fn insert_unsupported_typescript_replay(
    observations: &mut BTreeMap<String, BehaviorReplayObservation>,
    cases: &[BehaviorReplayCase],
    reason: &str,
) {
    for case in cases {
        observations.insert(case.name.clone(), unsupported_typescript_replay(reason));
    }
}

fn replay_observation_from_command(
    command: &CommandRecord,
    outputs: Vec<serde_json::Value>,
) -> BehaviorReplayObservation {
    let has_outputs = !outputs.is_empty();
    let output = if outputs.is_empty() {
        serde_json::json!({
            "observations": [],
            "stderr": excerpt(&command.stderr),
        })
    } else {
        serde_json::json!({ "observations": outputs })
    };
    let status = if command.status == RunStatus::Passed && has_outputs {
        BehaviorReplayStatus::Observed
    } else {
        BehaviorReplayStatus::Failed
    };
    BehaviorReplayObservation {
        status,
        output,
        command: Some(command_line(&command.program, &command.args)),
        stdout_excerpt: Some(excerpt(&command.stdout)),
        stderr_excerpt: Some(excerpt(&command.stderr)),
        duration_ms: Some(command.duration_ms),
    }
}

fn typescript_target_matches_function(target_id: &str, function: &TypeScriptFunction) -> bool {
    target_id == format!("typescript:{}:{}", function.path, function.symbol)
}

fn bun_available(root: &Path) -> bool {
    Command::new("bun")
        .arg("--version")
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn skipped_bun_command(root: &Path, stderr: &str) -> Result<CommandRecord> {
    Ok(CommandRecord {
        program: "bun".to_string(),
        args: vec!["test".to_string()],
        cwd: utf8_path(root)?,
        exit_code: None,
        status: RunStatus::Skipped,
        stdout: String::new(),
        stderr: stderr.to_string(),
        duration_ms: 0,
    })
}

fn run_command<I, S>(
    root: &Path,
    program: &str,
    args: I,
    timeout_seconds: u64,
) -> Result<CommandRecord>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let start = Instant::now();
    let args = args.into_iter().map(Into::into).collect::<Vec<String>>();
    let mut child = Command::new(program)
        .args(&args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {}", command_line(program, &args)))?;
    let timeout = Duration::from_secs(timeout_seconds.max(1));
    loop {
        if child
            .try_wait()
            .with_context(|| format!("failed to poll {}", command_line(program, &args)))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .with_context(|| format!("failed to read {}", command_line(program, &args)))?;
            let status = if output.status.success() {
                RunStatus::Passed
            } else {
                RunStatus::Failed
            };
            return Ok(CommandRecord {
                program: program.to_string(),
                args,
                cwd: utf8_path(root)?,
                exit_code: output.status.code(),
                status,
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                duration_ms: start.elapsed().as_millis(),
            });
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output().with_context(|| {
                format!(
                    "failed to collect timed-out {}",
                    command_line(program, &args)
                )
            })?;
            let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if !stderr.is_empty() {
                stderr.push('\n');
            }
            stderr.push_str(&format!("command timed out after {}s", timeout.as_secs()));
            return Ok(CommandRecord {
                program: program.to_string(),
                args,
                cwd: utf8_path(root)?,
                exit_code: output.status.code(),
                status: RunStatus::Failed,
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr,
                duration_ms: start.elapsed().as_millis(),
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn signature_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    let line_start = source[..node.start_byte()]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let boundary = source[node.start_byte()..node.end_byte()]
        .find(['{', '\n'])
        .map(|index| node.start_byte() + index)
        .unwrap_or(node.end_byte());
    source
        .get(line_start..boundary)
        .ok_or_else(|| anyhow!("node byte range is invalid"))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.start_byte()..node.end_byte())
        .ok_or_else(|| anyhow!("node byte range is invalid"))
}

fn node_line_range(node: Node<'_>) -> LineRange {
    LineRange {
        start: node.start_position().row + 1,
        end: node.end_position().row + 1,
    }
}

fn should_skip_symbol(name: &str) -> bool {
    name.is_empty() || name.starts_with('_')
}

fn infer_risk(symbol: &str) -> RiskLevel {
    let lowered = symbol.to_ascii_lowercase();
    if lowered.contains("auth")
        || lowered.contains("permission")
        || lowered.contains("role")
        || lowered.contains("token")
        || lowered.contains("refund")
        || lowered.contains("money")
        || lowered.contains("cents")
        || lowered.contains("amount")
        || lowered.contains("parse")
        || lowered.contains("serial")
        || lowered.contains("delete")
        || lowered.contains("admin")
    {
        RiskLevel::High
    } else if lowered.contains("normalize")
        || lowered.contains("validate")
        || lowered.contains("convert")
        || lowered.contains("format")
    {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn contains_typescript_file(root: &Path) -> bool {
    WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry.path(), entry.file_name()))
        .filter_map(Result::ok)
        .any(|entry| entry.file_type().is_file() && is_typescript_source(entry.path()))
}

fn is_typescript_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
    ) && !is_typescript_test_file(path)
}

fn is_typescript_test_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".test.jsx")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.jsx")
}

fn is_ignored(path: &Path, name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    if matches!(
        name.as_ref(),
        ".git"
            | ".hg"
            | ".svn"
            | ".veritas"
            | "node_modules"
            | "dist"
            | "build"
            | "coverage"
            | ".turbo"
            | ".next"
            | ".nuxt"
            | "target"
    ) {
        return true;
    }
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_string_lossy().as_ref(),
            ".git"
                | ".veritas"
                | "node_modules"
                | "dist"
                | "build"
                | "coverage"
                | ".turbo"
                | ".next"
                | ".nuxt"
                | "target"
        )
    })
}

fn safe_ident(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "target".to_string()
    } else {
        out
    }
}

fn relative_utf8(root: &Path, path: &Path) -> Result<Utf8PathBuf> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("failed to relativize {}", path.display()))?;
    Utf8PathBuf::from_path_buf(relative.to_path_buf())
        .map_err(|path| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn utf8_path(path: &Path) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path.to_path_buf())
        .map_err(|path| anyhow!("path is not valid UTF-8: {}", path.display()))
}

fn command_line(program: &str, args: &[impl AsRef<str>]) -> String {
    let mut parts = vec![program.to_string()];
    parts.extend(args.iter().map(|arg| {
        let arg = arg.as_ref();
        if arg.contains(char::is_whitespace) {
            format!("{arg:?}")
        } else {
            arg.to_string()
        }
    }));
    parts.join(" ")
}

fn excerpt(value: &str) -> String {
    let mut lines = value.lines().take(20).collect::<Vec<_>>().join("\n");
    if value.lines().count() > 20 {
        lines.push_str("\n...");
    }
    lines
}
