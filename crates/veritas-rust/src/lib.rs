use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;
use tree_sitter::{Node, Parser};
use veritas_core::config::RustPluginConfig;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, CommandRecord, CoverageReport, Failure, FailureSeverity,
    GeneratedArtifact, LanguagePlugin, LineRange, MutationAttribution, PluginCapability,
    ProjectInfo, ReproCase, RiskLevel, RunStatus, TargetKind, TestRunResult, VerificationPlan,
    VerificationQuality, VerificationReport, VerificationStrategy, VerificationTarget,
};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct RustPlugin {
    config: RustPluginConfig,
}

#[derive(Debug, Clone)]
struct CargoPackage {
    package_name: String,
    crate_name: String,
    root: Utf8PathBuf,
    virtual_workspace: bool,
}

#[derive(Debug, Clone)]
struct RustFunction {
    name: String,
    symbol: String,
    owner: Option<String>,
    path: Utf8PathBuf,
    params: Vec<RustParam>,
    returns_value: bool,
    return_type: Option<String>,
    signature: String,
    line_range: LineRange,
    start_byte: usize,
    end_byte: usize,
    crate_name: String,
    package_root: Utf8PathBuf,
    calls: Vec<String>,
}

#[derive(Debug, Clone)]
struct RustParam {
    name: String,
    type_name: String,
}

#[derive(Debug, Clone, Serialize)]
struct RustSymbolGraph<'a> {
    target_id: &'a str,
    symbols: Vec<RustSymbolNode<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct RustSymbolNode<'a> {
    id: String,
    path: &'a Utf8PathBuf,
    symbol: &'a str,
    name: &'a str,
    owner: Option<&'a str>,
    signature: &'a str,
    line_range: &'a LineRange,
    risk: RiskLevel,
    calls: &'a [String],
}

impl RustPlugin {
    pub fn new(config: RustPluginConfig) -> Self {
        Self { config }
    }
}

impl LanguagePlugin for RustPlugin {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn display_name(&self) -> &'static str {
        "Rust"
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::TargetDiscovery,
            PluginCapability::SymbolGraph,
            PluginCapability::GeneratedTests,
            PluginCapability::ExistingTests,
            PluginCapability::PropertyTests,
            PluginCapability::MutationChecks,
            PluginCapability::Coverage,
            PluginCapability::DifferentialReplay,
            PluginCapability::CorpusReplay,
            PluginCapability::RegressionPromotion,
            PluginCapability::ResourceBudgets,
        ]
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo> {
        let manifest = root.join("Cargo.toml");
        if !manifest.exists() {
            return Err(anyhow!("Cargo.toml not found"));
        }
        let package = cargo_package(root)?;
        Ok(ProjectInfo {
            language: "rust".to_string(),
            name: package.package_name,
            root: utf8_path(root)?,
            manifests: vec![Utf8PathBuf::from("Cargo.toml")],
        })
    }

    fn discover_targets(&self, root: &Path) -> Result<Vec<VerificationTarget>> {
        let package = cargo_package(root)?;
        let mut targets = vec![VerificationTarget {
            id: "rust:project".to_string(),
            language: "rust".to_string(),
            kind: TargetKind::Project,
            path: Utf8PathBuf::from("."),
            symbol: None,
            signature: None,
            line_range: None,
            description: format!("Rust package {}", package.package_name),
            risk: RiskLevel::Medium,
        }];

        for function in discover_functions(root)? {
            targets.push(VerificationTarget {
                id: format!("rust:{}:{}", function.path, function.symbol),
                language: "rust".to_string(),
                kind: TargetKind::Function,
                path: function.path.clone(),
                symbol: Some(function.symbol.clone()),
                signature: Some(function.signature.clone()),
                line_range: Some(function.line_range.clone()),
                description: if let Some(owner) = &function.owner {
                    format!("public Rust method {owner}.{}", function.name)
                } else {
                    format!("public Rust function {}", function.name)
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
        let root = project_root_from_target(target)?;
        let package = cargo_package(&root)?;
        let functions = discover_functions(&root)?;
        let selected: Vec<RustFunction> = functions
            .iter()
            .filter(|function| {
                if let Some(symbol) = &target.symbol {
                    function.symbol == *symbol && function.path == target.path
                } else {
                    function.path == target.path || target.kind == TargetKind::Project
                }
            })
            .filter(|function| supports_proptest(function))
            .cloned()
            .collect();

        let mut artifacts = Vec::new();
        artifacts.push(symbol_graph_artifact(
            &target.id,
            &target.path,
            target.symbol.as_deref(),
            &functions,
        )?);
        if self.config.property_framework == "proptest"
            && plan
                .strategies
                .iter()
                .any(|strategy| matches!(strategy, VerificationStrategy::PropertyTests))
            && !selected.is_empty()
        {
            let mut by_package: std::collections::BTreeMap<Utf8PathBuf, Vec<RustFunction>> =
                std::collections::BTreeMap::new();
            for function in selected {
                by_package
                    .entry(function.package_root.clone())
                    .or_default()
                    .push(function);
            }

            for (package_root, functions) in by_package {
                if !package_supports_proptest(&root, &package_root)? {
                    continue;
                }
                let module_name = module_slug(&target.path, target.symbol.as_deref());
                let test_root = if package_root.as_str() == "." {
                    Utf8PathBuf::from("tests")
                } else {
                    package_root.join("tests")
                };
                let module_path = test_root.join(format!("veritas_generated/{module_name}.rs"));
                let index_path = test_root.join("veritas_generated.rs");
                let crate_name = functions
                    .first()
                    .map(|function| function.crate_name.as_str())
                    .unwrap_or(package.crate_name.as_str());
                let module_contents = render_property_module(crate_name, &functions);
                let index_contents = render_index(&module_name);

                artifacts.push(GeneratedArtifact {
                    id: format!("rust-property-{module_name}"),
                    language: "rust".to_string(),
                    kind: ArtifactKind::PropertyTest,
                    target_id: target.id.clone(),
                    path: module_path,
                    contents: module_contents,
                    description:
                        "Generated proptest properties that assert selected functions do not panic"
                            .to_string(),
                    status: ArtifactStatus::Planned,
                });
                artifacts.push(GeneratedArtifact {
                    id: format!("rust-property-index-{module_name}"),
                    language: "rust".to_string(),
                    kind: ArtifactKind::HarnessIndex,
                    target_id: target.id.clone(),
                    path: index_path,
                    contents: index_contents,
                    description: "Cargo integration-test index for veritas generated modules"
                        .to_string(),
                    status: ArtifactStatus::Planned,
                });
            }
        }

        if plan
            .strategies
            .iter()
            .any(|strategy| matches!(strategy, VerificationStrategy::MutationChecks))
        {
            let slug = module_slug(&target.path, target.symbol.as_deref());
            artifacts.push(GeneratedArtifact {
                id: format!("rust-mutation-{slug}"),
                language: "rust".to_string(),
                kind: ArtifactKind::MutationCheck,
                target_id: target.id.clone(),
                path: Utf8PathBuf::from(format!(".veritas/mutations/rust_{slug}.txt")),
                contents: format!(
                    "language=rust\ntarget_id={}\npath={}\nsymbol={}\n",
                    target.id,
                    target.path,
                    target.symbol.as_deref().unwrap_or("")
                ),
                description: "Deterministic Rust mutation probes for selected functions"
                    .to_string(),
                status: ArtifactStatus::Planned,
            });
        }

        Ok(artifacts)
    }

    fn promote_regression(
        &self,
        root: &Path,
        report: &VerificationReport,
        finding: &Failure,
        index: usize,
    ) -> Result<Vec<GeneratedArtifact>> {
        promoted_rust_regression_artifacts(root, report, finding, index)
    }

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        let start = Instant::now();
        let mut commands = Vec::new();
        let mut quality = VerificationQuality::default();
        let package_roots = test_package_roots(root, artifacts)?;
        let test_commands = run_cargo_tests(root, &package_roots, &self.config)?;
        let mut status = if test_commands
            .iter()
            .any(|command| command.status == RunStatus::Failed)
        {
            RunStatus::Failed
        } else {
            RunStatus::Passed
        };
        let mut failures =
            failures_for_failed_commands(root, &test_commands, artifacts, "cargo test failed");
        commands.extend(test_commands);

        if status == RunStatus::Passed
            && artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        {
            if budget_nearly_spent(start, plan.budget_seconds) {
                commands.push(skipped_command(
                    root,
                    "rust mutation checks",
                    "global budget nearly exhausted after existing tests",
                )?);
            } else {
                let mutation = run_mutation_checks(
                    root,
                    artifacts,
                    &self.config,
                    start,
                    plan,
                    &package_roots,
                )?;
                if mutation.status == RunStatus::Failed {
                    status = RunStatus::Failed;
                }
                quality.mutation = mutation.quality.mutation.clone();
                failures.extend(mutation.failures.clone());
                commands.extend(mutation.commands);
            }
        }

        Ok(TestRunResult {
            language: "rust".to_string(),
            status,
            commands,
            failures,
            duration_ms: start.elapsed().as_millis(),
            quality,
        })
    }

    fn collect_coverage(&self, root: &Path) -> Result<Option<CoverageReport>> {
        if !self.config.coverage_enabled {
            return Ok(Some(CoverageReport {
                tool: "cargo-llvm-cov".to_string(),
                summary: "not collected: disabled by Rust plugin config".to_string(),
                files: vec![],
            }));
        }

        let mut args = vec![
            "llvm-cov".to_string(),
            "--summary-only".to_string(),
            "--all-targets".to_string(),
        ];
        if cargo_package(root)?.virtual_workspace {
            args.insert(2, "--workspace".to_string());
        }
        args.extend([
            "--ignore-filename-regex".to_string(),
            "tests/veritas_generated".to_string(),
        ]);
        let command = run_command(
            root,
            "cargo",
            &args,
            &self.config,
            self.config.coverage_timeout_seconds,
        );

        let Ok(command) = command else {
            return Ok(Some(CoverageReport {
                tool: "cargo-llvm-cov".to_string(),
                summary: "not collected: failed to start cargo llvm-cov".to_string(),
                files: vec![],
            }));
        };

        if command.status == RunStatus::Failed {
            return Ok(Some(CoverageReport {
                tool: "cargo-llvm-cov".to_string(),
                summary: format!("not collected: {}", excerpt(&command.stderr)),
                files: vec![],
            }));
        }

        Ok(Some(CoverageReport {
            tool: "cargo-llvm-cov".to_string(),
            summary: coverage_summary(&command.stdout),
            files: vec![],
        }))
    }
}

fn package_supports_proptest(root: &Path, package_root: &Utf8PathBuf) -> Result<bool> {
    let manifest = root.join(package_root).join("Cargo.toml");
    let contents = fs::read_to_string(&manifest)
        .with_context(|| format!("failed to read {}", manifest.display()))?;
    Ok(contents.contains("proptest"))
}

fn project_root_from_target(target: &VerificationTarget) -> Result<PathBuf> {
    let current = std::env::current_dir()?;
    if target.path.is_absolute() {
        Ok(target
            .path
            .parent()
            .map(|path| path.as_std_path().to_path_buf())
            .unwrap_or(current))
    } else {
        Ok(current)
    }
}

fn cargo_package(root: &Path) -> Result<CargoPackage> {
    let manifest = root.join("Cargo.toml");
    let contents = fs::read_to_string(&manifest)
        .with_context(|| format!("failed to read {}", manifest.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {}", manifest.display()))?;
    let package_name = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(|name| name.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            value.get("workspace").map(|_| {
                root.file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or("workspace")
                    .to_string()
            })
        })
        .ok_or_else(|| anyhow!("Cargo.toml is missing [package].name or [workspace]"))?;
    let crate_name = package_name.replace('-', "_");
    Ok(CargoPackage {
        package_name,
        crate_name,
        root: Utf8PathBuf::from("."),
        virtual_workspace: value.get("package").is_none() && value.get("workspace").is_some(),
    })
}

fn discover_functions(root: &Path) -> Result<Vec<RustFunction>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Rust grammar: {error}"))?;

    let mut functions = Vec::new();
    for package in discover_rust_packages(root)? {
        let package_root = root.join(&package.root);
        let src = package_root.join("src");
        if !src.exists() {
            continue;
        }
        for entry in WalkDir::new(&src)
            .into_iter()
            .filter_entry(|entry| !is_hidden(entry.file_name()))
        {
            let entry = entry?;
            if !entry.file_type().is_file() || entry.path().extension() != Some(OsStr::new("rs")) {
                continue;
            }
            let contents = fs::read_to_string(entry.path())
                .with_context(|| format!("failed to read {}", entry.path().display()))?;
            let tree = parser
                .parse(&contents, None)
                .ok_or_else(|| anyhow!("failed to parse Rust source {}", entry.path().display()))?;
            let path = relative_utf8(root, entry.path())?;
            collect_rust_functions(tree.root_node(), &contents, &path, &package, &mut functions)?;
        }
    }

    Ok(functions)
}

fn discover_rust_packages(root: &Path) -> Result<Vec<CargoPackage>> {
    let root_package = cargo_package(root)?;
    if !root_package.virtual_workspace {
        return Ok(vec![root_package]);
    }

    let mut packages = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_entry(|entry| !is_ignored_workspace_entry(entry.file_name()))
    {
        let entry = entry?;
        if !entry.file_type().is_file() || entry.file_name() != OsStr::new("Cargo.toml") {
            continue;
        }
        if entry.path() == root.join("Cargo.toml") {
            continue;
        }
        let package_root = entry.path().parent().unwrap_or(root);
        let Ok(mut package) = cargo_package(package_root) else {
            continue;
        };
        package.root = relative_utf8(root, package_root)?;
        packages.push(package);
    }
    packages.sort_by(|left, right| left.root.cmp(&right.root));
    Ok(packages)
}

fn collect_rust_functions(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
    package: &CargoPackage,
    functions: &mut Vec<RustFunction>,
) -> Result<()> {
    if node.kind() == "function_item" && is_public_rust_function(node, source) {
        if let Some(function) = parse_rust_function(node, source, path, package)? {
            functions.push(function);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_functions(child, source, path, package, functions)?;
    }
    Ok(())
}

fn parse_rust_function(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
    package: &CargoPackage,
) -> Result<Option<RustFunction>> {
    let Some(name_node) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let name = node_text(name_node, source)?.to_string();
    let owner = rust_function_owner(node, source)?;
    let symbol = owner
        .as_ref()
        .map(|owner| format!("{owner}.{name}"))
        .unwrap_or_else(|| name.clone());
    let params = node
        .child_by_field_name("parameters")
        .map(|parameters| parse_rust_params(node_text(parameters, source).unwrap_or_default()))
        .unwrap_or_default();
    let signature = signature_text(node, source)?.trim().to_string();
    let return_type = rust_return_type(&signature);
    let returns_value = return_type.is_some();

    Ok(Some(RustFunction {
        name,
        symbol,
        owner,
        path: path.clone(),
        params,
        returns_value,
        return_type,
        signature,
        line_range: LineRange {
            start: node.start_position().row + 1,
            end: node.end_position().row + 1,
        },
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        crate_name: package.crate_name.clone(),
        package_root: package.root.clone(),
        calls: rust_calls_in_function(node, source)?,
    }))
}

fn is_public_rust_function(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let is_public = node.children(&mut cursor).any(|child| {
        child.kind() == "visibility_modifier"
            && node_text(child, source).is_ok_and(|text| text.trim_start().starts_with("pub"))
    });
    is_public
}

fn rust_function_owner(node: Node<'_>, source: &str) -> Result<Option<String>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "impl_item" {
            return Ok(parent
                .child_by_field_name("type")
                .map(|node| clean_rust_owner(node_text(node, source).unwrap_or_default())));
        }
        if parent.kind() == "trait_item" {
            return Ok(parent
                .child_by_field_name("name")
                .map(|node| node_text(node, source).unwrap_or_default().to_string()));
        }
        current = parent.parent();
    }
    Ok(None)
}

fn clean_rust_owner(owner: &str) -> String {
    owner
        .split('<')
        .next()
        .unwrap_or(owner)
        .trim()
        .trim_start_matches('&')
        .trim()
        .to_string()
}

fn rust_calls_in_function(node: Node<'_>, source: &str) -> Result<Vec<String>> {
    let mut calls = BTreeSet::new();
    collect_rust_calls(node, source, &mut calls)?;
    Ok(calls.into_iter().collect())
}

fn collect_rust_calls(node: Node<'_>, source: &str, calls: &mut BTreeSet<String>) -> Result<()> {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            let text = normalize_call_text(node_text(function, source)?);
            if !text.is_empty() {
                calls.insert(text);
            }
        }
    } else if node.kind() == "macro_invocation" {
        if let Some(macro_node) = node.child_by_field_name("macro") {
            let text = normalize_call_text(node_text(macro_node, source)?);
            if !text.is_empty() {
                calls.insert(format!("{text}!"));
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_calls(child, source, calls)?;
    }
    Ok(())
}

fn normalize_call_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_rust_params(parameters: &str) -> Vec<RustParam> {
    let trimmed = parameters
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    split_top_level(trimmed)
        .into_iter()
        .filter_map(|param| {
            let (name, type_name) = param.split_once(':')?;
            let name = name.trim().trim_start_matches("mut ").trim();
            let type_name = normalize_rust_type(type_name.trim());
            Some(RustParam {
                name: name.to_string(),
                type_name,
            })
        })
        .collect()
}

fn normalize_rust_type(type_name: &str) -> String {
    let type_name = type_name.replace(' ', "");
    if type_name == "&str" || type_name.ends_with("str") && type_name.starts_with("&'") {
        "&str".to_string()
    } else {
        type_name
    }
}

fn split_top_level(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in value.char_indices() {
        match ch {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let piece = value[start..idx].trim();
                if !piece.is_empty() {
                    parts.push(piece);
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let piece = value[start..].trim();
    if !piece.is_empty() {
        parts.push(piece);
    }
    parts
}

fn signature_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    let function_text = node_text(node, source)?;
    let signature_end = function_text.find('{').unwrap_or(function_text.len());
    Ok(&function_text[..signature_end])
}

fn rust_return_type(signature: &str) -> Option<String> {
    let (_, return_type) = signature.split_once("->")?;
    let return_type = return_type
        .split("where")
        .next()
        .unwrap_or(return_type)
        .trim()
        .trim_end_matches('{')
        .trim();
    if return_type.is_empty() {
        None
    } else {
        Some(normalize_rust_type(return_type))
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.start_byte()..node.end_byte())
        .ok_or_else(|| anyhow!("tree-sitter node byte range was invalid"))
}

fn supports_proptest(function: &RustFunction) -> bool {
    function.owner.is_none()
        && function
            .params
            .iter()
            .all(|param| param.name != "self" && param.name != "&self" && param.name != "&mut self")
        && function.params.len() <= 2
        && function
            .params
            .iter()
            .all(|param| proptest_strategy(&param.type_name).is_some())
}

fn symbol_graph_artifact(
    target_id: &str,
    target_path: &Utf8PathBuf,
    target_symbol: Option<&str>,
    functions: &[RustFunction],
) -> Result<GeneratedArtifact> {
    let symbols = functions
        .iter()
        .filter(|function| {
            target_symbol
                .map(|symbol| function.symbol == symbol && function.path == *target_path)
                .unwrap_or_else(|| function.path == *target_path || target_path.as_str() == ".")
        })
        .map(|function| RustSymbolNode {
            id: format!("rust:{}:{}", function.path, function.symbol),
            path: &function.path,
            symbol: &function.symbol,
            name: &function.name,
            owner: function.owner.as_deref(),
            signature: &function.signature,
            line_range: &function.line_range,
            risk: infer_risk(&function.symbol),
            calls: &function.calls,
        })
        .collect::<Vec<_>>();
    let graph = RustSymbolGraph { target_id, symbols };
    let contents = serde_json::to_string_pretty(&graph)?;
    let slug = module_slug(target_path, target_symbol);
    Ok(GeneratedArtifact {
        id: format!("rust-symbol-graph-{slug}"),
        language: "rust".to_string(),
        kind: ArtifactKind::SymbolGraph,
        target_id: target_id.to_string(),
        path: Utf8PathBuf::from(format!(".veritas/symbol_graph/rust_{slug}.json")),
        contents,
        description: "Machine-readable Rust symbol graph with method owners and call hints"
            .to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn render_property_module(crate_name: &str, functions: &[RustFunction]) -> String {
    let mut out = String::new();
    out.push_str("// Generated by veritas. Review before committing.\n");
    out.push_str("use proptest::prelude::*;\n");
    out.push_str(&format!("use {crate_name}::*;\n\n"));
    out.push_str("proptest! {\n");
    for function in functions {
        let Some(params) = function
            .params
            .iter()
            .map(|param| {
                proptest_strategy(&param.type_name)
                    .map(|strategy| format!("{} in {}", safe_ident(&param.name), strategy))
            })
            .collect::<Option<Vec<_>>>()
            .map(|params| params.join(", "))
        else {
            continue;
        };
        let call_args = function
            .params
            .iter()
            .map(render_call_arg)
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str("    #[test]\n");
        if params.is_empty() {
            out.push_str(&format!(
                "    fn veritas_{}_does_not_panic() {{\n",
                safe_ident(&function.name)
            ));
        } else {
            out.push_str(&format!(
                "    fn veritas_{}_does_not_panic({params}) {{\n",
                safe_ident(&function.name)
            ));
        }
        out.push_str("        let result = std::panic::catch_unwind(|| {\n");
        if function.returns_value {
            out.push_str(&format!(
                "            let _ = {}({call_args});\n",
                function.name
            ));
        } else {
            out.push_str(&format!("            {}({call_args});\n", function.name));
        }
        out.push_str("        });\n");
        out.push_str("        prop_assert!(result.is_ok());\n");
        out.push_str("    }\n");

        if comparable_return_type(function.return_type.as_deref()) {
            out.push_str("    #[test]\n");
            if params.is_empty() {
                out.push_str(&format!(
                    "    fn veritas_{}_is_deterministic() {{\n",
                    safe_ident(&function.name)
                ));
            } else {
                out.push_str(&format!(
                    "    fn veritas_{}_is_deterministic({params}) {{\n",
                    safe_ident(&function.name)
                ));
            }
            let first_args = function
                .params
                .iter()
                .map(render_reusable_call_arg)
                .collect::<Vec<_>>()
                .join(", ");
            let second_args = function
                .params
                .iter()
                .map(render_call_arg)
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "        let first = {}({first_args});\n",
                function.name
            ));
            out.push_str(&format!(
                "        let second = {}({second_args});\n",
                function.name
            ));
            out.push_str("        prop_assert_eq!(first, second);\n");
            out.push_str("    }\n");
        }
    }
    out.push_str("}\n");
    out
}

fn render_index(module_name: &str) -> String {
    format!(
        "// Generated by veritas. Review before committing.\n#[path = \"veritas_generated/{module_name}.rs\"]\nmod {module_name};\n"
    )
}

fn promoted_rust_regression_artifacts(
    root: &Path,
    report: &VerificationReport,
    finding: &Failure,
    index: usize,
) -> Result<Vec<GeneratedArtifact>> {
    let target = finding
        .target_id
        .as_ref()
        .and_then(|target_id| report.targets.iter().find(|target| &target.id == target_id));
    let functions = discover_functions(root).unwrap_or_default();
    let function = target.and_then(|target| {
        let symbol = target.symbol.as_deref()?;
        functions
            .iter()
            .find(|function| function.path == target.path && function.symbol == symbol)
    });
    let package_root = function
        .map(|function| function.package_root.clone())
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    let test_dir = if package_root.as_str() == "." {
        Utf8PathBuf::from("tests")
    } else {
        package_root.join("tests")
    };
    let slug = function
        .map(|function| module_slug(&function.path, Some(&function.symbol)))
        .or_else(|| target.map(|target| module_slug(&target.path, target.symbol.as_deref())))
        .unwrap_or_else(|| format!("finding_{index}"));
    let path = test_dir.join(format!("veritas_regression_{index}_{slug}.rs"));
    let contents = render_rust_regression_scaffold(finding, target, function, index);

    Ok(vec![GeneratedArtifact {
        id: format!("rust-promoted-regression-{index}"),
        language: "rust".to_string(),
        kind: ArtifactKind::RegressionTest,
        target_id: finding
            .target_id
            .clone()
            .unwrap_or_else(|| "rust:unknown".to_string()),
        path,
        contents,
        description: "Reviewable Rust regression test scaffold promoted from a veritas finding"
            .to_string(),
        status: ArtifactStatus::Planned,
    }])
}

fn render_rust_regression_scaffold(
    finding: &Failure,
    target: Option<&VerificationTarget>,
    function: Option<&RustFunction>,
    index: usize,
) -> String {
    let name = function
        .map(|function| safe_ident(&function.symbol))
        .or_else(|| target.and_then(|target| target.symbol.as_deref().map(safe_ident)))
        .unwrap_or_else(|| "target".to_string());
    let mut out = String::new();
    out.push_str("// Generated by veritas. Review before committing.\n");
    out.push_str("// Replace the ignored placeholder with an assertion that fails for the recorded finding.\n");
    push_rust_comment(&mut out, &format!("Finding: {}", finding.message));
    push_rust_comment(&mut out, &format!("Command: {}", finding.command));
    if let Some(target_id) = &finding.target_id {
        push_rust_comment(&mut out, &format!("Target: {target_id}"));
    }
    if let Some(repro) = &finding.repro {
        push_rust_comment(&mut out, &format!("Repro: {}", repro.command));
        if let Some(input) = &repro.input {
            push_rust_comment(&mut out, &format!("Input: {}", input.trim()));
        }
    }
    out.push('\n');
    out.push_str("#[test]\n");
    out.push_str(
        "#[ignore = \"review and replace the veritas placeholder with a real assertion\"]\n",
    );
    out.push_str(&format!("fn veritas_regression_{index}_{name}() {{\n"));
    if let Some(function) = function {
        out.push_str("    // Candidate assertion seed synthesized by veritas:\n");
        if function.owner.is_none() {
            let args = rust_regression_seed_args(function).join(", ");
            out.push_str(&format!(
                "    // let actual = {}::{}({args});\n",
                function.crate_name, function.name
            ));
            out.push_str("    // assert_eq!(actual, /* reviewed expected value */);\n");
        } else {
            out.push_str("    // Construct the receiver state, call the method, and assert the reviewed expected value.\n");
        }
    } else {
        out.push_str("    // Arrange the smallest input or state that exposes the finding.\n");
    }
    out.push_str(
        "    // Assert the exact expected behavior so the original mutant or repro is killed.\n",
    );
    out.push_str("    panic!(\"veritas regression scaffold requires a reviewed assertion\");\n");
    out.push_str("}\n");
    out
}

fn rust_regression_seed_args(function: &RustFunction) -> Vec<String> {
    function
        .params
        .iter()
        .map(|param| match param.type_name.as_str() {
            "&str" => "\"veritas-seed\"".to_string(),
            "String" => "\"veritas-seed\".to_string()".to_string(),
            "bool" => "true".to_string(),
            "u8" | "u16" | "u32" | "u64" | "usize" => "1".to_string(),
            "i8" | "i16" | "i32" | "i64" | "isize" => "1".to_string(),
            "f32" => "1.0_f32".to_string(),
            "f64" => "1.0_f64".to_string(),
            _ => "Default::default()".to_string(),
        })
        .collect()
}

fn push_rust_comment(out: &mut String, line: &str) {
    for line in line.lines() {
        out.push_str("// ");
        out.push_str(line.trim());
        out.push('\n');
    }
}

fn render_call_arg(param: &RustParam) -> String {
    let ident = safe_ident(&param.name);
    match param.type_name.as_str() {
        "&str" => format!("{ident}.as_str()"),
        _ => ident,
    }
}

fn render_reusable_call_arg(param: &RustParam) -> String {
    let ident = safe_ident(&param.name);
    match param.type_name.as_str() {
        "String" => format!("{ident}.clone()"),
        "&str" => format!("{ident}.as_str()"),
        _ => ident,
    }
}

fn comparable_return_type(return_type: Option<&str>) -> bool {
    let Some(return_type) = return_type else {
        return false;
    };
    matches!(
        return_type,
        "bool"
            | "String"
            | "&str"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "usize"
    )
}

fn proptest_strategy(type_name: &str) -> Option<&'static str> {
    match type_name {
        "i8" => Some("any::<i8>()"),
        "i16" => Some("any::<i16>()"),
        "i32" => Some("any::<i32>()"),
        "i64" => Some("any::<i64>()"),
        "isize" => Some("any::<isize>()"),
        "u8" => Some("any::<u8>()"),
        "u16" => Some("any::<u16>()"),
        "u32" => Some("any::<u32>()"),
        "u64" => Some("any::<u64>()"),
        "usize" => Some("any::<usize>()"),
        "bool" => Some("any::<bool>()"),
        "String" => Some("\".*\""),
        "&str" => Some("\".*\""),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct MutationCandidate {
    path: Utf8PathBuf,
    function: String,
    label: String,
    from: String,
    to: String,
    start_byte: usize,
    end_byte: usize,
}

fn run_mutation_checks(
    root: &Path,
    artifacts: &[GeneratedArtifact],
    config: &RustPluginConfig,
    run_start: Instant,
    plan: &VerificationPlan,
    package_roots: &BTreeSet<Utf8PathBuf>,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let functions = discover_functions(root)?;
    let candidates = rust_mutation_candidates(&functions, root, artifacts)?;
    let generated = candidates.len();
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut status = RunStatus::Passed;
    let mut quality = VerificationQuality::default();
    quality.mutation.generated = generated;

    for candidate in candidates.into_iter().take(8) {
        let domain = mutation_domain_from_label(&candidate.label);
        let operator = mutation_operator_from_label(&candidate.label);
        record_mutation_generated(&mut quality.mutation.by_domain, &domain);
        record_mutation_generated(&mut quality.mutation.by_operator, &operator);
        if budget_nearly_spent(run_start, plan.budget_seconds) {
            commands.push(skipped_command(
                root,
                "rust mutation checks",
                "global budget nearly exhausted before remaining mutants",
            )?);
            break;
        }
        quality.mutation.executed += 1;
        record_mutation_executed(&mut quality.mutation.by_domain, &domain);
        record_mutation_executed(&mut quality.mutation.by_operator, &operator);
        let path = root.join(&candidate.path);
        let original = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut mutated = original.clone();
        mutated.replace_range(candidate.start_byte..candidate.end_byte, &candidate.to);
        fs::write(&path, mutated).with_context(|| {
            format!(
                "failed to write Rust mutation {} in {}",
                candidate.label,
                path.display()
            )
        })?;

        let mutation_commands = run_cargo_tests(root, package_roots, config);
        fs::write(&path, original)
            .with_context(|| format!("failed to restore {}", path.display()))?;
        let mutation_commands = mutation_commands?;
        let mut mutant_survived = true;
        let mut representative_command = None;
        for command in mutation_commands {
            if command.status == RunStatus::Failed {
                mutant_survived = false;
            }
            representative_command.get_or_insert_with(|| command.clone());
            commands.push(command);
        }

        if mutant_survived {
            quality.mutation.survived += 1;
            record_mutation_survived(&mut quality.mutation.by_domain, &domain);
            record_mutation_survived(&mut quality.mutation.by_operator, &operator);
            let command = representative_command.unwrap_or(skipped_command(
                root,
                "rust mutation checks",
                "no package commands were selected for mutant",
            )?);
            status = RunStatus::Failed;
            failures.push(Failure {
                id: None,
                message: format!(
                    "mutation survived in Rust function `{}`: {}",
                    candidate.function, candidate.label
                ),
                severity: FailureSeverity::Warning,
                target_id: Some(format!("rust:{}:{}", candidate.path, candidate.function)),
                artifact_id: artifacts
                    .iter()
                    .find(|artifact| artifact.kind == ArtifactKind::MutationCheck)
                    .map(|artifact| artifact.id.clone()),
                command: command_line(&command.program, &command.args),
                stdout_excerpt: excerpt(&command.stdout),
                stderr_excerpt: excerpt(&command.stderr),
                repro: Some(ReproCase {
                    command: format!(
                        "replace `{}` with `{}` in {} and run cargo test --all-targets",
                        candidate.from, candidate.to, candidate.path
                    ),
                    input: None,
                    path: Some(candidate.path.clone()),
                }),
            });
        } else {
            quality.mutation.killed += 1;
            record_mutation_killed(&mut quality.mutation.by_domain, &domain);
            record_mutation_killed(&mut quality.mutation.by_operator, &operator);
        }
    }
    quality.mutation.skipped = quality
        .mutation
        .generated
        .saturating_sub(quality.mutation.executed);
    quality.mutation.score_percent = (quality.mutation.killed * 100)
        .checked_div(quality.mutation.executed)
        .map(|score| score.try_into().unwrap_or(100));
    finalize_mutation_skips(&mut quality.mutation.by_domain);
    finalize_mutation_skips(&mut quality.mutation.by_operator);

    Ok(TestRunResult {
        language: "rust".to_string(),
        status,
        commands,
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality,
    })
}

fn cargo_test_args(root: &Path, config: &RustPluginConfig) -> Result<Vec<String>> {
    let mut args = vec!["test".to_string()];
    if config.cargo_jobs > 0 {
        args.extend(["--jobs".to_string(), config.cargo_jobs.to_string()]);
    }
    if cargo_package(root)?.virtual_workspace {
        args.push("--workspace".to_string());
    }
    args.push("--all-targets".to_string());
    Ok(args)
}

fn mutation_domain_from_label(label: &str) -> String {
    for domain in [
        "auth/permission",
        "money",
        "parsing/normalization",
        "serialization",
        "error handling",
        "boundary",
    ] {
        if label.contains(domain) {
            return domain.to_string();
        }
    }
    "general".to_string()
}

fn mutation_operator_from_label(label: &str) -> String {
    for operator in [
        "comparison",
        "equality",
        "boolean",
        "arithmetic",
        "default",
        "nil",
        "error",
        "boundary",
    ] {
        if label.contains(operator) {
            return operator.to_string();
        }
    }
    "general".to_string()
}

fn record_mutation_generated(metrics: &mut BTreeMap<String, MutationAttribution>, key: &str) {
    metrics.entry(key.to_string()).or_default().generated += 1;
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

fn finalize_mutation_skips(metrics: &mut BTreeMap<String, MutationAttribution>) {
    for metric in metrics.values_mut() {
        metric.skipped = metric.generated.saturating_sub(metric.executed);
    }
}

fn test_package_roots(
    root: &Path,
    artifacts: &[GeneratedArtifact],
) -> Result<BTreeSet<Utf8PathBuf>> {
    let packages = discover_rust_packages(root)?;
    let mut roots = BTreeSet::new();
    if artifacts.is_empty()
        || artifacts
            .iter()
            .any(|artifact| artifact.target_id == "rust:project")
    {
        roots.insert(Utf8PathBuf::from("."));
    }

    for artifact in artifacts {
        if let Some(path) = rust_path_from_target_id(&artifact.target_id) {
            if let Some(package) = owning_rust_package(&packages, &path) {
                roots.insert(package.root.clone());
            }
        }
        if let Some(package) = owning_rust_package(&packages, &artifact.path) {
            roots.insert(package.root.clone());
        }
    }

    if roots.is_empty() {
        roots.insert(Utf8PathBuf::from("."));
    }
    Ok(roots)
}

fn run_cargo_tests(
    root: &Path,
    package_roots: &BTreeSet<Utf8PathBuf>,
    config: &RustPluginConfig,
) -> Result<Vec<CommandRecord>> {
    let mut commands = Vec::new();
    for package_root in package_roots {
        let cwd = root.join(package_root);
        let test_args = cargo_test_args(&cwd, config)?;
        commands.push(run_command(
            &cwd,
            "cargo",
            &test_args,
            config,
            config.command_timeout_seconds,
        )?);
    }
    Ok(commands)
}

fn rust_path_from_target_id(target_id: &str) -> Option<Utf8PathBuf> {
    let rest = target_id.strip_prefix("rust:")?;
    if rest == "project" {
        return None;
    }
    let path = rest.rsplit_once(':').map(|(path, _)| path).unwrap_or(rest);
    Some(Utf8PathBuf::from(path))
}

fn owning_rust_package<'a>(
    packages: &'a [CargoPackage],
    path: &Utf8PathBuf,
) -> Option<&'a CargoPackage> {
    packages
        .iter()
        .filter(|package| package.root.as_str() == "." || path.starts_with(&package.root))
        .max_by_key(|package| package.root.as_str().len())
}

fn rust_mutation_candidates(
    functions: &[RustFunction],
    root: &Path,
    artifacts: &[GeneratedArtifact],
) -> Result<Vec<MutationCandidate>> {
    let mutation_targets = artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        .map(|artifact| artifact.target_id.as_str())
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Rust grammar: {error}"))?;
    let mut functions_by_path: std::collections::BTreeMap<Utf8PathBuf, Vec<&RustFunction>> =
        std::collections::BTreeMap::new();

    for function in functions {
        if !mutation_targets
            .iter()
            .any(|target_id| rust_target_matches_function(target_id, function))
        {
            continue;
        }
        functions_by_path
            .entry(function.path.clone())
            .or_default()
            .push(function);
    }

    for (path, path_functions) in functions_by_path {
        let contents = fs::read_to_string(root.join(&path))
            .with_context(|| format!("failed to read {}", path))?;
        let tree = parser
            .parse(&contents, None)
            .ok_or_else(|| anyhow!("failed to parse Rust source {}", path))?;
        for function in path_functions {
            collect_rust_mutation_nodes(tree.root_node(), &contents, function, &mut candidates)?;
        }
    }

    Ok(candidates)
}

fn collect_rust_mutation_nodes(
    node: Node<'_>,
    source: &str,
    function: &RustFunction,
    candidates: &mut Vec<MutationCandidate>,
) -> Result<()> {
    if node.end_byte() <= function.start_byte || node.start_byte() >= function.end_byte {
        return Ok(());
    }

    if node.start_byte() >= function.start_byte && node.end_byte() <= function.end_byte {
        if node.kind() == "binary_expression" {
            if let Some(candidate) = rust_mutation_candidate_from_binary(node, function) {
                candidates.push(candidate);
            }
        } else if node.kind() == "field_identifier" || node.kind() == "identifier" {
            if let Some(candidate) =
                rust_mutation_candidate_from_identifier(node, source, function)?
            {
                candidates.push(candidate);
            }
        } else if node.kind() == "boolean_literal" {
            if let Some(candidate) = rust_mutation_candidate_from_boolean(node, source, function)? {
                candidates.push(candidate);
            }
        } else if node.kind() == "integer_literal" {
            if let Some(candidate) = rust_mutation_candidate_from_integer(node, source, function)? {
                candidates.push(candidate);
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_mutation_nodes(child, source, function, candidates)?;
    }
    Ok(())
}

fn rust_mutation_candidate_from_binary(
    node: Node<'_>,
    function: &RustFunction,
) -> Option<MutationCandidate> {
    let operator = rust_binary_operator_node(node)?;
    let op = operator.kind();
    let (label, to) = match op {
        "==" => ("equality inversion", "!="),
        "!=" => ("equality inversion", "=="),
        ">=" => ("comparison boundary mutation", ">"),
        "<=" => ("comparison boundary mutation", "<"),
        ">" => ("comparison boundary mutation", ">="),
        "<" => ("comparison boundary mutation", "<="),
        "&&" => ("boolean connector inversion", "||"),
        "||" => ("boolean connector inversion", "&&"),
        "+" => ("arithmetic direction mutation", "-"),
        "-" => ("arithmetic direction mutation", "+"),
        "*" => ("arithmetic operator mutation", "/"),
        "/" => ("arithmetic operator mutation", "*"),
        _ => return None,
    };
    Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(&function.symbol, label),
        from: op.to_string(),
        to: to.to_string(),
        start_byte: operator.start_byte(),
        end_byte: operator.end_byte(),
    })
}

fn rust_mutation_candidate_from_identifier(
    node: Node<'_>,
    source: &str,
    function: &RustFunction,
) -> Result<Option<MutationCandidate>> {
    let text = node_text(node, source)?;
    let Some((label, to)) = (match text {
        "min" => Some(("boundary inversion", "max")),
        "max" => Some(("boundary inversion", "min")),
        "saturating_sub" => Some(("arithmetic direction", "saturating_add")),
        "saturating_add" => Some(("arithmetic direction", "saturating_sub")),
        "checked_sub" => Some(("checked arithmetic direction", "checked_add")),
        "checked_add" => Some(("checked arithmetic direction", "checked_sub")),
        "wrapping_sub" => Some(("wrapping arithmetic direction", "wrapping_add")),
        "wrapping_add" => Some(("wrapping arithmetic direction", "wrapping_sub")),
        "is_ok" => Some(("result branch inversion", "is_err")),
        "is_err" => Some(("result branch inversion", "is_ok")),
        _ => None,
    }) else {
        return Ok(None);
    };
    if !has_ancestor_kind(node, "call_expression") {
        return Ok(None);
    }
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(&function.symbol, label),
        from: text.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn rust_mutation_candidate_from_boolean(
    node: Node<'_>,
    source: &str,
    function: &RustFunction,
) -> Result<Option<MutationCandidate>> {
    let text = node_text(node, source)?;
    let to = match text {
        "true" => "false",
        "false" => "true",
        _ => return Ok(None),
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(&function.symbol, "boolean inversion"),
        from: text.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn rust_mutation_candidate_from_integer(
    node: Node<'_>,
    source: &str,
    function: &RustFunction,
) -> Result<Option<MutationCandidate>> {
    let text = node_text(node, source)?;
    let to = match text {
        "0" => "1",
        "1" => "0",
        _ => return Ok(None),
    };
    if !ancestor_text_contains(node, source, "call_expression", "unwrap_or")? {
        return Ok(None);
    }
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(&function.symbol, "default value perturbation"),
        from: text.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn rust_binary_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let operator = node.children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "==" | "!=" | ">=" | "<=" | ">" | "<" | "&&" | "||" | "+" | "-" | "*" | "/"
        )
    });
    operator
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn ancestor_text_contains(node: Node<'_>, source: &str, kind: &str, needle: &str) -> Result<bool> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return Ok(node_text(parent, source)?.contains(needle));
        }
        current = parent.parent();
    }
    Ok(false)
}

fn rust_target_matches_function(target_id: &str, function: &RustFunction) -> bool {
    if target_id == "rust:project" {
        return true;
    }
    let Some(rest) = target_id.strip_prefix("rust:") else {
        return false;
    };
    if rest == function.path.as_str() {
        return true;
    }
    if let Some((path, symbol)) = rest.rsplit_once(':') {
        return path == function.path.as_str() && symbol == function.symbol;
    }
    false
}

fn domain_mutation_label(symbol: &str, base: &str) -> String {
    let lowered = symbol.to_ascii_lowercase();
    let domain = if lowered.contains("auth")
        || lowered.contains("permission")
        || lowered.contains("token")
    {
        Some("auth/permission")
    } else if lowered.contains("money")
        || lowered.contains("price")
        || lowered.contains("invoice")
        || lowered.contains("total")
        || lowered.contains("refund")
        || lowered.contains("discount")
    {
        Some("money")
    } else if lowered.contains("parse")
        || lowered.contains("format")
        || lowered.contains("normalize")
    {
        Some("parsing/normalization")
    } else if lowered.contains("serialize")
        || lowered.contains("deserialize")
        || lowered.contains("json")
    {
        Some("serialization")
    } else if lowered.contains("error")
        || lowered.contains("err")
        || lowered.contains("result")
        || lowered.contains("option")
    {
        Some("error handling")
    } else if lowered.contains("limit")
        || lowered.contains("threshold")
        || lowered.contains("min")
        || lowered.contains("max")
    {
        Some("boundary")
    } else {
        None
    };

    match domain {
        Some(domain) => format!("{domain} {base}"),
        None => base.to_string(),
    }
}

fn run_command(
    root: &Path,
    program: &str,
    args: &[String],
    config: &RustPluginConfig,
    timeout_seconds: u64,
) -> Result<CommandRecord> {
    let start = Instant::now();
    let (effective_program, effective_args) =
        resource_limited_command(program, args, config, timeout_seconds);
    let mut child = Command::new(&effective_program)
        .args(&effective_args)
        .current_dir(root)
        .env("CARGO_BUILD_JOBS", config.cargo_jobs.max(1).to_string())
        .env("RUST_TEST_THREADS", config.test_threads.max(1).to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to run {}",
                command_line(&effective_program, &effective_args)
            )
        })?;
    let timeout = Duration::from_secs(timeout_seconds.max(1));
    loop {
        if child
            .try_wait()
            .with_context(|| {
                format!(
                    "failed to poll {}",
                    command_line(&effective_program, &effective_args)
                )
            })?
            .is_some()
        {
            let output = child.wait_with_output().with_context(|| {
                format!(
                    "failed to read {}",
                    command_line(&effective_program, &effective_args)
                )
            })?;
            let status = if output.status.success() {
                RunStatus::Passed
            } else {
                RunStatus::Failed
            };
            return Ok(CommandRecord {
                program: effective_program,
                args: effective_args,
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
                    command_line(&effective_program, &effective_args)
                )
            })?;
            let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if !stderr.is_empty() {
                stderr.push('\n');
            }
            stderr.push_str(&format!(
                "command timed out after {}s: {}",
                timeout.as_secs(),
                command_line(&effective_program, &effective_args)
            ));
            return Ok(CommandRecord {
                program: effective_program,
                args: effective_args,
                cwd: utf8_path(root)?,
                exit_code: output.status.code(),
                status: RunStatus::Failed,
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr,
                duration_ms: start.elapsed().as_millis(),
            });
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn resource_limited_command(
    program: &str,
    args: &[String],
    config: &RustPluginConfig,
    timeout_seconds: u64,
) -> (String, Vec<String>) {
    if !config.systemd_scope {
        return (program.to_string(), args.to_vec());
    }

    let mut systemd_args = vec![
        "--user".to_string(),
        "--scope".to_string(),
        "-q".to_string(),
        "-p".to_string(),
        format!("RuntimeMaxSec={}s", timeout_seconds.max(1)),
    ];
    if let Some(memory_max) = &config.memory_max {
        systemd_args.extend(["-p".to_string(), format!("MemoryMax={memory_max}")]);
    }
    if let Some(cpu_quota) = &config.cpu_quota {
        systemd_args.extend(["-p".to_string(), format!("CPUQuota={cpu_quota}")]);
    }
    systemd_args.extend([
        format!("--setenv=CARGO_BUILD_JOBS={}", config.cargo_jobs.max(1)),
        format!("--setenv=RUST_TEST_THREADS={}", config.test_threads.max(1)),
        program.to_string(),
    ]);
    systemd_args.extend(args.iter().cloned());
    ("systemd-run".to_string(), systemd_args)
}

fn failures_for_failed_commands(
    root: &Path,
    commands: &[CommandRecord],
    artifacts: &[GeneratedArtifact],
    message: &str,
) -> Vec<Failure> {
    commands
        .iter()
        .filter(|command| command.status == RunStatus::Failed)
        .map(|command| {
            let artifact = artifact_for_failed_command(root, command, artifacts);
            Failure {
                id: None,
                message: message.to_string(),
                severity: FailureSeverity::Error,
                target_id: artifact.map(|artifact| artifact.target_id.clone()),
                artifact_id: artifact.map(|artifact| artifact.id.clone()),
                command: command_line(&command.program, &command.args),
                stdout_excerpt: excerpt(&command.stdout),
                stderr_excerpt: excerpt(&command.stderr),
                repro: Some(ReproCase {
                    command: command_line(&command.program, &command.args),
                    input: None,
                    path: None,
                }),
            }
        })
        .collect()
}

fn artifact_for_failed_command<'a>(
    root: &Path,
    command: &CommandRecord,
    artifacts: &'a [GeneratedArtifact],
) -> Option<&'a GeneratedArtifact> {
    let combined_output = format!("{}\n{}", command.stdout, command.stderr);
    artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.kind,
                ArtifactKind::UnitTest | ArtifactKind::PropertyTest | ArtifactKind::FuzzHarness
            )
        })
        .find(|artifact| {
            combined_output.contains(artifact.path.as_str())
                || artifact_package_root(root, artifact)
                    .map(|package_root| package_root == command.cwd)
                    .unwrap_or(false)
        })
        .or_else(|| {
            artifacts.iter().find(|artifact| {
                matches!(
                    artifact.kind,
                    ArtifactKind::UnitTest
                        | ArtifactKind::PropertyTest
                        | ArtifactKind::FuzzHarness
                        | ArtifactKind::HarnessIndex
                )
            })
        })
}

fn artifact_package_root(root: &Path, artifact: &GeneratedArtifact) -> Option<Utf8PathBuf> {
    let parts = artifact.path.components().collect::<Vec<_>>();
    let tests_position = parts
        .iter()
        .position(|component| component.as_str() == "tests")?;
    let relative_root = if tests_position == 0 {
        Utf8PathBuf::from(".")
    } else {
        parts[..tests_position]
            .iter()
            .fold(Utf8PathBuf::new(), |path, component| path.join(component))
    };
    utf8_path(&root.join(relative_root)).ok()
}

fn budget_nearly_spent(start: Instant, budget_seconds: u64) -> bool {
    start.elapsed() + Duration::from_secs(5) >= Duration::from_secs(budget_seconds.max(1))
}

fn skipped_command(root: &Path, label: &str, reason: &str) -> Result<CommandRecord> {
    Ok(CommandRecord {
        program: "veritas".to_string(),
        args: vec!["skip".to_string(), label.to_string()],
        cwd: utf8_path(root)?,
        exit_code: None,
        status: RunStatus::Skipped,
        stdout: String::new(),
        stderr: reason.to_string(),
        duration_ms: 0,
    })
}

fn coverage_summary(stdout: &str) -> String {
    stdout
        .lines()
        .find(|line| line.trim_start().starts_with("TOTAL"))
        .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
        .map(str::trim)
        .unwrap_or("coverage collected")
        .to_string()
}

fn infer_risk(name: &str) -> RiskLevel {
    let lowered = name.to_ascii_lowercase();
    let high_risk_terms = [
        "parse",
        "auth",
        "permission",
        "money",
        "price",
        "invoice",
        "token",
        "crypto",
        "unsafe",
        "serialize",
        "deserialize",
        "network",
        "refund",
        "discount",
    ];
    if high_risk_terms.iter().any(|term| lowered.contains(term)) {
        RiskLevel::High
    } else if lowered.starts_with("validate") || lowered.starts_with("apply") {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn module_slug(path: &Utf8PathBuf, symbol: Option<&str>) -> String {
    let base = format!("{}_{}", path, symbol.unwrap_or("target"));
    safe_ident(&base)
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
    out.trim_matches('_').to_string()
}

fn relative_utf8(root: &Path, path: &Path) -> Result<Utf8PathBuf> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    Utf8PathBuf::from_path_buf(relative.to_path_buf()).map_err(|path| {
        anyhow!(
            "path contains non-UTF-8 data and cannot be represented: {}",
            path.display()
        )
    })
}

fn utf8_path(path: &Path) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path.to_path_buf()).map_err(|path| {
        anyhow!(
            "path contains non-UTF-8 data and cannot be represented: {}",
            path.display()
        )
    })
}

fn is_hidden(name: &OsStr) -> bool {
    name.to_string_lossy().starts_with('.')
}

fn is_ignored_workspace_entry(name: &OsStr) -> bool {
    matches!(
        name.to_string_lossy().as_ref(),
        ".git" | ".veritas" | "target" | "tests" | "fixtures"
    )
}

fn command_line(program: &str, args: &[impl AsRef<str>]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!(
            "{} {}",
            program,
            args.iter()
                .map(|arg| arg.as_ref())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn excerpt(value: &str) -> String {
    value
        .lines()
        .rev()
        .take(30)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn discovers_public_free_functions_and_methods() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "Cargo.toml",
            "[package]\nname = \"tree-sitter-rust-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write_file(
            root.path(),
            "src/lib.rs",
            "pub struct Invoice;\n\nimpl Invoice {\n    pub fn authorize_refund(&self, amount: u64) -> bool {\n        amount <= 100\n    }\n}\n\npub fn parse_total(input: &str) -> u64 {\n    input.parse().unwrap_or(0)\n}\n",
        );

        let functions = discover_functions(root.path()).expect("discover functions");

        assert!(functions
            .iter()
            .any(|function| function.symbol == "Invoice.authorize_refund"));
        assert!(functions
            .iter()
            .any(|function| function.symbol == "parse_total"));
        let method = functions
            .iter()
            .find(|function| function.symbol == "Invoice.authorize_refund")
            .expect("method symbol");
        assert_eq!(method.owner.as_deref(), Some("Invoice"));
    }

    #[test]
    fn rust_mutation_candidates_use_ast_nodes_not_string_literals() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "Cargo.toml",
            "[package]\nname = \"tree-sitter-rust-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let source = "pub fn authorize_refund(amount: u64, approved: bool) -> bool {\n    let _ = \"amount == 0 && amount + 1\";\n    approved && amount + 1 >= 2\n}\n";
        write_file(root.path(), "src/lib.rs", source);
        let functions = discover_functions(root.path()).expect("discover functions");
        let artifact = GeneratedArtifact {
            id: "rust-mutation-src_lib_rs_authorize_refund".to_string(),
            language: "rust".to_string(),
            kind: ArtifactKind::MutationCheck,
            target_id: "rust:src/lib.rs:authorize_refund".to_string(),
            path: Utf8PathBuf::from(".veritas/mutations/rust_src_lib_rs_authorize_refund.txt"),
            contents: String::new(),
            description: String::new(),
            status: ArtifactStatus::Planned,
        };

        let candidates =
            rust_mutation_candidates(&functions, root.path(), &[artifact]).expect("mutations");

        let string_start = source
            .find("\"amount == 0 && amount + 1\"")
            .expect("string literal");
        let string_end = string_start + "\"amount == 0 && amount + 1\"".len();
        assert!(candidates.iter().any(|candidate| candidate.from == ">="));
        assert!(candidates.iter().any(|candidate| candidate.from == "&&"));
        assert!(candidates.iter().any(|candidate| candidate.from == "+"));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.start_byte < string_start
                || candidate.start_byte >= string_end));
    }

    #[test]
    fn symbol_graph_artifact_reports_methods_and_calls() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "Cargo.toml",
            "[package]\nname = \"tree-sitter-rust-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write_file(
            root.path(),
            "src/lib.rs",
            "pub struct Invoice;\n\nimpl Invoice {\n    pub fn normalize(&self, input: &str) -> String {\n        input.trim().to_string()\n    }\n}\n",
        );
        let functions = discover_functions(root.path()).expect("discover functions");

        let artifact = symbol_graph_artifact(
            "rust:src/lib.rs:Invoice.normalize",
            &Utf8PathBuf::from("src/lib.rs"),
            Some("Invoice.normalize"),
            &functions,
        )
        .expect("symbol graph");

        assert_eq!(artifact.kind, ArtifactKind::SymbolGraph);
        assert!(artifact.contents.contains("Invoice.normalize"));
        assert!(artifact.contents.contains("input.trim"));
    }

    #[test]
    fn failed_generated_test_commands_are_attributed_to_generated_artifacts() {
        let root = TempRoot::new();
        let artifact = GeneratedArtifact {
            id: "rust-property-example".to_string(),
            language: "rust".to_string(),
            kind: ArtifactKind::PropertyTest,
            target_id: "rust:project".to_string(),
            path: Utf8PathBuf::from("examples/rust-invoice/tests/veritas_generated/target.rs"),
            contents: String::new(),
            description: String::new(),
            status: ArtifactStatus::Written,
        };
        let command = CommandRecord {
            program: "cargo".to_string(),
            args: vec!["test".to_string()],
            cwd: utf8_path(&root.path().join("examples/rust-invoice")).expect("utf8 cwd"),
            exit_code: Some(101),
            status: RunStatus::Failed,
            stdout: String::new(),
            stderr: "tests/veritas_generated/target.rs: assertion failed".to_string(),
            duration_ms: 1,
        };

        let failures =
            failures_for_failed_commands(root.path(), &[command], &[artifact], "cargo test failed");

        assert_eq!(
            failures[0].artifact_id.as_deref(),
            Some("rust-property-example")
        );
        assert_eq!(failures[0].target_id.as_deref(), Some("rust:project"));
    }

    fn write_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("test file should have a parent"))
            .expect("create test parent");
        fs::write(path, contents).expect("write test file");
    }

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after UNIX_EPOCH")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("veritas-rust-test-{nanos}"));
            fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
