use std::{
    collections::hash_map::DefaultHasher,
    collections::BTreeMap,
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
    config::{MutationConfig, PythonPluginConfig},
    persist_mutation_record_artifacts, start_mutation_run,
};
use veritas_plugin_api::{
    finalize_mutation_metrics, mutation_taxonomy, ArtifactKind, ArtifactStatus, BehaviorReplayCase,
    BehaviorReplayObservation, BehaviorReplayStatus, CommandRecord, CoverageFile, CoverageReport,
    Failure, FailureSeverity, GeneratedArtifact, LanguagePlugin, LineRange, MutationAttribution,
    MutationRecord, MutationStatus, PluginCapability, ProjectInfo, ReproCase, RiskLevel, RunStatus,
    SourceSpan, TargetKind, TestRunResult, VerificationPlan, VerificationQuality,
    VerificationStrategy, VerificationTarget,
};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct PythonPlugin {
    config: PythonPluginConfig,
}

#[derive(Debug, Clone)]
struct PythonFunction {
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
struct PythonMutationCandidate {
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
struct PythonSymbolGraph<'a> {
    target_id: &'a str,
    symbols: Vec<PythonSymbolNode<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct PythonSymbolNode<'a> {
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

impl PythonPlugin {
    pub fn new(config: PythonPluginConfig) -> Self {
        Self { config }
    }
}

impl LanguagePlugin for PythonPlugin {
    fn id(&self) -> &'static str {
        "python"
    }

    fn display_name(&self) -> &'static str {
        "Python"
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::TargetDiscovery,
            PluginCapability::SymbolGraph,
            PluginCapability::GeneratedTests,
            PluginCapability::ExistingTests,
            PluginCapability::MutationChecks,
            PluginCapability::DifferentialReplay,
            PluginCapability::RegressionPromotion,
            PluginCapability::ResourceBudgets,
        ]
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo> {
        if !root.join("pyproject.toml").exists()
            && !root.join("setup.py").exists()
            && !contains_python_file(root)
        {
            return Err(anyhow!("Python project not found"));
        }
        let name = root
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("python-project")
            .to_string();
        let manifests = ["pyproject.toml", "setup.py"]
            .into_iter()
            .filter(|path| root.join(path).exists())
            .map(Utf8PathBuf::from)
            .collect();
        Ok(ProjectInfo {
            language: "python".to_string(),
            name,
            root: utf8_path(root)?,
            manifests,
        })
    }

    fn discover_targets(&self, root: &Path) -> Result<Vec<VerificationTarget>> {
        let mut targets = vec![VerificationTarget {
            id: "python:project".to_string(),
            language: "python".to_string(),
            kind: TargetKind::Project,
            path: Utf8PathBuf::from("."),
            symbol: None,
            signature: None,
            line_range: None,
            description: "Python project".to_string(),
            risk: RiskLevel::Medium,
        }];

        for function in discover_functions(root)? {
            targets.push(VerificationTarget {
                id: format!("python:{}:{}", function.path, function.symbol),
                language: "python".to_string(),
                kind: TargetKind::Function,
                path: function.path.clone(),
                symbol: Some(function.symbol.clone()),
                signature: Some(function.signature.clone()),
                line_range: Some(function.line_range.clone()),
                description: if let Some(owner) = &function.owner {
                    format!("Python method {owner}.{}", function.name)
                } else {
                    format!("Python function {}", function.name)
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
            .contains(&VerificationStrategy::MutationChecks)
        {
            artifacts.push(python_mutation_manifest_artifact(
                target,
                target.symbol.as_deref(),
                &functions,
            )?);
        }
        if plan
            .strategies
            .contains(&VerificationStrategy::PropertyTests)
        {
            if let Some(artifact) =
                python_hypothesis_property_artifact(target, target.symbol.as_deref(), &functions)?
            {
                artifacts.push(artifact);
            }
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
        let (runner_name, args) = python_test_args(root);
        let command = run_command(
            root,
            "python3",
            args.iter().map(String::as_str),
            self.config.command_timeout_seconds,
        )?;
        let status = command.status.clone();
        let failures = if command.status == RunStatus::Failed {
            vec![Failure {
                id: None,
                message: format!("python {runner_name} failed"),
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
        if artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::PropertyTest)
        {
            let property = run_python_property_artifacts(root, artifacts, &self.config)?;
            if property.status == RunStatus::Failed {
                status = RunStatus::Failed;
            }
            commands.extend(property.commands);
            failures.extend(property.failures);
        }
        let mutation = if artifacts
            .iter()
            .any(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        {
            let mutation = run_python_mutations(root, artifacts, &self.config)?;
            if mutation.status == RunStatus::Failed {
                status = RunStatus::Failed;
            }
            commands.extend(mutation.commands);
            failures.extend(mutation.failures);
            mutation.quality
        } else {
            VerificationQuality::default()
        };

        Ok(TestRunResult {
            language: "python".to_string(),
            status,
            commands,
            failures,
            duration_ms: start.elapsed().as_millis(),
            quality: mutation,
        })
    }

    fn collect_coverage(&self, root: &Path) -> Result<Option<CoverageReport>> {
        if !self.config.coverage_enabled {
            return Ok(Some(CoverageReport {
                tool: "python coverage".to_string(),
                summary: "not collected: disabled by Python plugin config".to_string(),
                files: vec![],
            }));
        }
        if !python_module_available(root, "coverage") {
            return Ok(Some(CoverageReport {
                tool: "python coverage.py".to_string(),
                summary: "not collected: coverage.py is not available".to_string(),
                files: vec![],
            }));
        }

        let veritas_dir = root.join(".veritas");
        fs::create_dir_all(&veritas_dir)
            .with_context(|| format!("failed to create {}", veritas_dir.display()))?;
        let data_file = ".veritas/.coverage";
        let json_file = ".veritas/python_coverage.json";
        let (_, test_args) = python_test_args(root);
        let mut run_args = vec![
            "-m".to_string(),
            "coverage".to_string(),
            "run".to_string(),
            "--data-file".to_string(),
            data_file.to_string(),
        ];
        run_args.extend(test_args);
        let run = run_command(
            root,
            "python3",
            run_args.iter().map(String::as_str),
            self.config.command_timeout_seconds,
        )?;
        if run.status == RunStatus::Failed {
            return Ok(Some(CoverageReport {
                tool: "python coverage.py".to_string(),
                summary: format!("not collected: {}", excerpt(&run.stderr)),
                files: vec![],
            }));
        }
        let json_args = [
            "-m",
            "coverage",
            "json",
            "--data-file",
            data_file,
            "-o",
            json_file,
        ];
        let json = run_command(
            root,
            "python3",
            json_args,
            self.config.command_timeout_seconds,
        )?;
        if json.status == RunStatus::Failed {
            return Ok(Some(CoverageReport {
                tool: "python coverage.py".to_string(),
                summary: format!("not collected: {}", excerpt(&json.stderr)),
                files: vec![],
            }));
        }
        Ok(Some(python_coverage_report(root, &root.join(json_file))?))
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
            .find(|function| python_target_matches_function(&target.id, function))
        else {
            return Ok(None);
        };
        replay_python_function(root, function, case, &self.config).map(Some)
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
            .find(|function| python_target_matches_function(&target.id, function))
        else {
            return Ok(BTreeMap::new());
        };
        replay_python_function_batch(root, function, cases, &self.config)
    }
}

fn discover_functions(root: &Path) -> Result<Vec<PythonFunction>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Python grammar: {error}"))?;

    let mut functions = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry.path(), entry.file_name()))
    {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension() != Some(OsStr::new("py"))
            || is_python_test_file(entry.path())
        {
            continue;
        }
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let tree = parser
            .parse(&contents, None)
            .ok_or_else(|| anyhow!("failed to parse Python source {}", entry.path().display()))?;
        let path = relative_utf8(root, entry.path())?;
        collect_python_functions(tree.root_node(), &contents, &path, &mut functions)?;
    }
    Ok(functions)
}

fn collect_python_functions(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
    functions: &mut Vec<PythonFunction>,
) -> Result<()> {
    if matches!(
        node.kind(),
        "function_definition" | "async_function_definition"
    ) {
        if let Some(function) = parse_python_function(node, source, path)? {
            functions.push(function);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_functions(child, source, path, functions)?;
    }
    Ok(())
}

fn parse_python_function(
    node: Node<'_>,
    source: &str,
    path: &Utf8PathBuf,
) -> Result<Option<PythonFunction>> {
    let Some(name_node) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let name = node_text(name_node, source)?.to_string();
    if name.starts_with('_') {
        return Ok(None);
    }
    let owner = python_function_owner(node, source)?;
    let symbol = owner
        .as_ref()
        .map(|owner| format!("{owner}.{name}"))
        .unwrap_or_else(|| name.clone());
    let signature = signature_text(node, source)?.trim().to_string();
    let params = node
        .child_by_field_name("parameters")
        .map(|parameters| parse_python_params(node_text(parameters, source).unwrap_or_default()))
        .unwrap_or_default();
    Ok(Some(PythonFunction {
        path: path.clone(),
        name,
        symbol,
        owner,
        params,
        signature,
        line_range: LineRange {
            start: node.start_position().row + 1,
            end: node.end_position().row + 1,
        },
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        calls: python_calls_in_function(node, source)?,
    }))
}

fn python_function_owner(node: Node<'_>, source: &str) -> Result<Option<String>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            return Ok(parent
                .child_by_field_name("name")
                .map(|node| node_text(node, source).unwrap_or_default().to_string()));
        }
        current = parent.parent();
    }
    Ok(None)
}

fn parse_python_params(params: &str) -> Vec<String> {
    params
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
        .filter_map(|param| {
            let name = param
                .split([':', '='])
                .next()
                .unwrap_or_default()
                .trim()
                .trim_start_matches('*');
            (!name.is_empty()).then_some(name.to_string())
        })
        .collect()
}

fn python_calls_in_function(node: Node<'_>, source: &str) -> Result<Vec<String>> {
    let mut calls = Vec::new();
    collect_python_calls(node, source, &mut calls)?;
    calls.sort();
    calls.dedup();
    Ok(calls)
}

fn collect_python_calls(node: Node<'_>, source: &str, calls: &mut Vec<String>) -> Result<()> {
    if node.kind() == "call" {
        if let Some(function) = node.child_by_field_name("function") {
            let text = node_text(function, source)?.trim();
            if !text.is_empty() {
                calls.push(text.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_calls(child, source, calls)?;
    }
    Ok(())
}

fn symbol_graph_artifact(
    target_id: &str,
    target_path: &Utf8PathBuf,
    target_symbol: Option<&str>,
    functions: &[PythonFunction],
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
        .map(|function| PythonSymbolNode {
            id: format!("python:{}:{}", function.path, function.symbol),
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
    let contents = serde_json::to_string_pretty(&PythonSymbolGraph { target_id, symbols })?;
    Ok(GeneratedArtifact {
        id: format!("python-symbol-{}", safe_ident(target_id)),
        language: "python".to_string(),
        kind: ArtifactKind::SymbolGraph,
        target_id: target_id.to_string(),
        path: Utf8PathBuf::from(format!(
            ".veritas/symbols/python_{}.json",
            safe_ident(target_id)
        )),
        contents,
        description: "Tree-sitter Python symbol graph for selected target".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn python_mutation_manifest_artifact(
    target: &VerificationTarget,
    target_symbol: Option<&str>,
    functions: &[PythonFunction],
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
                "id": format!("python:{}:{}", function.path, function.symbol),
                "path": &function.path,
                "symbol": &function.symbol,
                "signature": &function.signature,
                "line_range": &function.line_range,
                "risk": infer_risk(&function.symbol),
                "operators": [
                    "comparison_boundary",
                    "boolean_guard",
                    "string_normalization",
                    "exception_path",
                    "numeric_limit"
                ],
            })
        })
        .collect::<Vec<_>>();
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "language": "python",
        "mode": "mutation_manifest",
        "target_id": target.id,
        "status": "planned",
        "targets": selected,
        "next_step": "Python mutation execution uses this manifest as the stable target/operator contract for generated tests and AI repair loops.",
    }))?;
    Ok(GeneratedArtifact {
        id: format!("python-mutation-{}", safe_ident(&target.id)),
        language: "python".to_string(),
        kind: ArtifactKind::MutationCheck,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(format!(
            ".veritas/mutations/python_{}.json",
            safe_ident(&target.id)
        )),
        contents,
        description: "Tree-sitter Python mutation target/operator manifest".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn python_hypothesis_property_artifact(
    target: &VerificationTarget,
    target_symbol: Option<&str>,
    functions: &[PythonFunction],
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
            !function.params.is_empty()
                && function.owner.is_none()
                && function.params.len() <= 3
                && function
                    .params
                    .iter()
                    .all(|param| !matches!(param.as_str(), "self" | "cls"))
        })
        .take(4)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(None);
    }

    let mut contents = String::from(
        "# Generated by veritas. Review before committing.\n\
         # Requires: python3 -m pip install hypothesis\n\
         \n\
         from hypothesis import given, strategies as st\n\
         \n\
         def _veritas_observe(call):\n\
             try:\n\
                 return (\"ok\", call())\n\
             except Exception as exc:\n\
                 return (\"exception\", type(exc).__name__, str(exc))\n\
         \n",
    );
    for function in selected {
        let module = python_module_name(&function.path);
        let name = &function.name;
        contents.push_str(&format!("from {module} import {name}\n"));
        let params = function.params.join(", ");
        let strategies = function
            .params
            .iter()
            .map(|param| format!("{param}={}", hypothesis_strategy_for_param(param)))
            .collect::<Vec<_>>()
            .join(", ");
        contents.push_str(&format!(
            "\n@given({strategies})\n\
             def test_veritas_{name}_does_not_panic({params}):\n\
                 first = _veritas_observe(lambda: {name}({params}))\n\
                 second = _veritas_observe(lambda: {name}({params}))\n\
                 assert first == second  # is_deterministic\n\
                 assert first[0] in (\"ok\", \"exception\")  # prop_assert does_not_panic\n"
        ));
    }

    Ok(Some(GeneratedArtifact {
        id: format!("python-property-{}", safe_ident(&target.id)),
        language: "python".to_string(),
        kind: ArtifactKind::PropertyTest,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(format!(
            ".veritas/properties/python_{}.py",
            safe_ident(&target.id)
        )),
        contents,
        description: "Reviewable Hypothesis property candidates for Python targets".to_string(),
        status: ArtifactStatus::Planned,
    }))
}

fn hypothesis_strategy_for_param(param: &str) -> String {
    let lowered = param.to_ascii_lowercase();
    if lowered.contains("cents")
        || lowered.contains("amount")
        || lowered.contains("total")
        || lowered.contains("count")
        || lowered.contains("limit")
        || lowered.contains("price")
    {
        "st.integers(min_value=-1_000_000, max_value=1_000_000)".to_string()
    } else if lowered.contains("enabled")
        || lowered.starts_with("is_")
        || lowered.starts_with("has_")
        || lowered.starts_with("can_")
    {
        "st.booleans()".to_string()
    } else {
        "st.text(max_size=64)".to_string()
    }
}

fn python_module_name(path: &Utf8PathBuf) -> String {
    path.as_str()
        .trim_end_matches(".py")
        .replace(['/', '\\'], ".")
        .trim_end_matches(".__init__")
        .to_string()
}

fn run_python_property_artifacts(
    root: &Path,
    artifacts: &[GeneratedArtifact],
    config: &PythonPluginConfig,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let property_paths = artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::PropertyTest)
        .map(|artifact| artifact.path.to_string())
        .collect::<Vec<_>>();
    if property_paths.is_empty() {
        return Ok(TestRunResult {
            language: "python".to_string(),
            status: RunStatus::Skipped,
            commands: vec![],
            failures: vec![],
            duration_ms: 0,
            quality: VerificationQuality::default(),
        });
    }
    if !python_module_available(root, "hypothesis") {
        return Ok(TestRunResult {
            language: "python".to_string(),
            status: RunStatus::Skipped,
            commands: vec![skipped_python_command(
                root,
                vec![
                    "-m".to_string(),
                    "pytest".to_string(),
                    "-q".to_string(),
                    ".veritas/properties".to_string(),
                ],
                "skipped: hypothesis is not installed",
            )?],
            failures: vec![],
            duration_ms: start.elapsed().as_millis(),
            quality: VerificationQuality::default(),
        });
    }
    if !python_module_available(root, "pytest") {
        return Ok(TestRunResult {
            language: "python".to_string(),
            status: RunStatus::Skipped,
            commands: vec![skipped_python_command(
                root,
                vec![
                    "-m".to_string(),
                    "pytest".to_string(),
                    "-q".to_string(),
                    ".veritas/properties".to_string(),
                ],
                "skipped: pytest is not installed",
            )?],
            failures: vec![],
            duration_ms: start.elapsed().as_millis(),
            quality: VerificationQuality::default(),
        });
    }

    let mut args = vec!["-m".to_string(), "pytest".to_string(), "-q".to_string()];
    args.extend(property_paths);
    let command = run_command(
        root,
        "python3",
        args.iter().map(String::as_str),
        config.command_timeout_seconds.min(60),
    )?;
    let failures = if command.status == RunStatus::Failed {
        vec![Failure {
            id: None,
            message: "python hypothesis property candidates failed".to_string(),
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
                path: Some(Utf8PathBuf::from(".veritas/properties")),
            }),
        }]
    } else {
        Vec::new()
    };
    let status = command.status.clone();
    Ok(TestRunResult {
        language: "python".to_string(),
        status,
        commands: vec![command],
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality: VerificationQuality::default(),
    })
}

fn skipped_python_command(root: &Path, args: Vec<String>, stderr: &str) -> Result<CommandRecord> {
    Ok(CommandRecord {
        program: "python3".to_string(),
        args,
        cwd: utf8_path(root)?,
        exit_code: None,
        status: RunStatus::Skipped,
        stdout: String::new(),
        stderr: stderr.to_string(),
        duration_ms: 0,
    })
}

fn run_python_mutations(
    root: &Path,
    artifacts: &[GeneratedArtifact],
    config: &PythonPluginConfig,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let functions = discover_functions(root)?;
    let candidates = python_mutation_candidates(root, &functions, artifacts)?
        .into_iter()
        .filter(|candidate| python_mutation_candidate_in_shard(candidate, &config.mutation))
        .filter(|candidate| {
            config.mutation.report_filtered || python_mutation_candidate_allowed(candidate, config)
        })
        .collect::<Vec<_>>();
    let mut quality = VerificationQuality::default();
    quality.mutation.generated = candidates.len();
    quality.mutation.effective_workers = 1;
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut status = RunStatus::Passed;
    let run_dir = start_mutation_run(root, "python")?;

    for candidate in candidates
        .into_iter()
        .take(config.mutation.max_mutants.unwrap_or(8))
    {
        let domain = python_mutation_domain(&candidate);
        let operator = python_mutation_operator(&candidate.label);
        record_mutation_generated(&mut quality.mutation.by_domain, &domain);
        record_mutation_generated(&mut quality.mutation.by_operator, &operator);
        if !python_mutation_candidate_allowed(&candidate, config) {
            let mut record = python_mutation_record(
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
            let mut record = python_mutation_record(
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
                "failed to write Python mutation {} in {}",
                candidate.label,
                path.display()
            )
        })?;
        let (_, args) = python_test_args(root);
        let command = run_command(
            root,
            "python3",
            args.iter().map(String::as_str),
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
            failures.push(python_mutation_failure(
                artifacts,
                &candidate,
                &command,
                &command_text,
            ));
            MutationStatus::Lived
        } else if python_mutation_not_viable(&command) {
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
        let mut record = python_mutation_record(
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
        language: "python".to_string(),
        status,
        commands,
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality,
    })
}

fn python_mutation_candidates(
    root: &Path,
    functions: &[PythonFunction],
    artifacts: &[GeneratedArtifact],
) -> Result<Vec<PythonMutationCandidate>> {
    let mut candidates = Vec::new();
    for function in functions {
        if !python_function_selected_for_mutation(function, artifacts) {
            continue;
        }
        let path = root.join(&function.path);
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if function_has_mutation_skip_annotation(&contents, function.start_byte, function.end_byte)
        {
            continue;
        }
        push_python_mutation(
            &contents,
            function,
            "<=",
            "<",
            "boundary comparison mutation",
            &mut candidates,
        );
        push_python_mutation(
            &contents,
            function,
            " or ",
            " and ",
            "permission boolean connector mutation",
            &mut candidates,
        );
        push_python_mutation(
            &contents,
            function,
            " and ",
            " or ",
            "boolean connector mutation",
            &mut candidates,
        );
        push_python_mutation(
            &contents,
            function,
            "return 0, False",
            "return 1, False",
            "default tuple mutation",
            &mut candidates,
        );
        for (from, to, label) in [
            ("FOR UPDATE", "", "database isolation_lock mutation"),
            ("tenant_id", "1", "database tenant_filter mutation"),
            (
                "idempotency_key",
                "request_id",
                "database idempotency mutation",
            ),
            (
                "asyncio.create_task",
                "await",
                "concurrency_lifecycle task_spawn mutation",
            ),
            (
                ".acquire()",
                ".locked()",
                "synchronization lock_mode mutation",
            ),
            ("retry(", "once(", "retry_resilience retry_attempt mutation"),
            ("time.time()", "0", "testability injected_clock mutation"),
            (
                "random.",
                "deterministic_random.",
                "testability injected_randomness mutation",
            ),
            (
                "sorted(",
                "list(",
                "brittleness equivalent_ordering mutation",
            ),
        ] {
            push_python_mutation(&contents, function, from, to, label, &mut candidates);
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

fn function_has_mutation_skip_annotation(source: &str, start_byte: usize, end_byte: usize) -> bool {
    source
        .get(start_byte..end_byte)
        .is_some_and(|body| body.contains("veritas:skip-mutation"))
}

fn push_python_mutation(
    contents: &str,
    function: &PythonFunction,
    from: &str,
    to: &str,
    label: &str,
    candidates: &mut Vec<PythonMutationCandidate>,
) {
    let Some(source) = contents.get(function.start_byte..function.end_byte) else {
        return;
    };
    let Some(offset) = source.find(from) else {
        return;
    };
    let start_byte = function.start_byte + offset;
    candidates.push(PythonMutationCandidate {
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

fn python_function_selected_for_mutation(
    function: &PythonFunction,
    artifacts: &[GeneratedArtifact],
) -> bool {
    artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        .any(|artifact| {
            artifact.target_id == "python:project"
                || artifact.target_id == format!("python:{}", function.path)
                || artifact.target_id == format!("python:{}:{}", function.path, function.symbol)
        })
}

fn python_mutation_failure(
    artifacts: &[GeneratedArtifact],
    candidate: &PythonMutationCandidate,
    command: &CommandRecord,
    command_text: &str,
) -> Failure {
    Failure {
        id: None,
        message: format!(
            "mutation survived in Python function `{}`: {}",
            candidate.function, candidate.label
        ),
        severity: FailureSeverity::Warning,
        target_id: Some(format!("python:{}:{}", candidate.path, candidate.function)),
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

fn python_mutation_record(
    candidate: &PythonMutationCandidate,
    domain: &str,
    operator: &str,
    status: MutationStatus,
    command: Option<&str>,
    duration_ms: u128,
) -> MutationRecord {
    MutationRecord {
        id: python_mutation_candidate_id(candidate),
        language: "python".to_string(),
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
        diff: Some(python_mutation_diff(candidate)),
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

fn python_mutation_candidate_id(candidate: &PythonMutationCandidate) -> String {
    format!(
        "python:{}:{}:{}:{}",
        candidate.path, candidate.function, candidate.start_byte, candidate.end_byte
    )
}

fn python_mutation_diff(candidate: &PythonMutationCandidate) -> String {
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
        MutationStatus::TimedOut => Some(
            "mutation test command timed out; consider filtering this operator/mutant or adding deterministic test seams for recurring hangs"
                .to_string(),
        ),
        MutationStatus::NotViable => Some("mutation did not compile or could not run".to_string()),
        _ => None,
    }
}

fn python_mutation_domain(candidate: &PythonMutationCandidate) -> String {
    let value = format!("{} {}", candidate.function, candidate.label).to_ascii_lowercase();
    mutation_taxonomy::normalize_domain(&value).to_string()
}

fn python_mutation_operator(label: &str) -> String {
    mutation_taxonomy::normalize_operator(label).to_string()
}

fn python_mutation_candidate_allowed(
    candidate: &PythonMutationCandidate,
    config: &PythonPluginConfig,
) -> bool {
    if !config.mutation.include_paths.is_empty()
        && !config
            .mutation
            .include_paths
            .iter()
            .any(|pattern| text_matches(candidate.path.as_str(), pattern))
    {
        return false;
    }
    if config
        .mutation
        .exclude_paths
        .iter()
        .any(|pattern| text_matches(candidate.path.as_str(), pattern))
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
    let target_id = python_mutation_candidate_target_id(candidate);
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
    let id = python_mutation_candidate_id(candidate);
    if !config.mutation.include_mutant_ids.is_empty()
        && !config
            .mutation
            .include_mutant_ids
            .iter()
            .any(|configured| text_matches(&id, configured))
    {
        return false;
    }
    if config
        .mutation
        .exclude_mutant_ids
        .iter()
        .any(|configured| text_matches(&id, configured))
    {
        return false;
    }
    let domain = python_mutation_domain(candidate);
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
    let operator = python_mutation_operator(&candidate.label);
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

fn python_mutation_candidate_target_id(candidate: &PythonMutationCandidate) -> String {
    format!("python:{}:{}", candidate.path, candidate.function)
}

fn python_mutation_candidate_in_shard(
    candidate: &PythonMutationCandidate,
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
    if let Some(regex) = pattern.strip_prefix("regex:") {
        return regex::RegexBuilder::new(regex)
            .case_insensitive(true)
            .build()
            .is_ok_and(|regex| regex.is_match(text));
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

fn python_mutation_not_viable(command: &CommandRecord) -> bool {
    let output = format!("{}\n{}", command.stdout, command.stderr).to_ascii_lowercase();
    output.contains("syntaxerror")
        || output.contains("indentationerror")
        || output.contains("nameerror")
        || output.contains("typeerror")
}

fn python_coverage_report(root: &Path, path: &Path) -> Result<CoverageReport> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let total = value["totals"]["percent_covered_display"]
        .as_str()
        .map(ToString::to_string)
        .or_else(|| {
            value["totals"]["percent_covered"]
                .as_f64()
                .map(|percent| format!("{percent:.1}"))
        })
        .unwrap_or_else(|| "unknown".to_string());
    let files = value["files"]
        .as_object()
        .into_iter()
        .flat_map(|files| files.iter())
        .map(|(path, file)| CoverageFile {
            path: Utf8PathBuf::from(path),
            line_coverage_percent: file["summary"]["percent_covered"]
                .as_f64()
                .map(|percent| percent.round().clamp(0.0, 100.0) as u8),
            uncovered_ranges: file["missing_lines"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|line| line.as_u64())
                .map(|line| line.to_string())
                .collect(),
        })
        .collect();
    Ok(CoverageReport {
        tool: "python coverage.py".to_string(),
        summary: format!("line coverage {total}% ({})", relative_display(root, path)),
        files,
    })
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn replay_python_function(
    root: &Path,
    function: &PythonFunction,
    case: &BehaviorReplayCase,
    config: &PythonPluginConfig,
) -> Result<BehaviorReplayObservation> {
    if function.owner.is_some() {
        return Ok(unsupported_python_replay(
            "method replay requires receiver construction",
        ));
    }
    if function.params.is_empty() || case.inputs.is_empty() {
        return Ok(unsupported_python_replay(
            "executable replay requires at least one supported argument with seeded inputs",
        ));
    }

    let script = render_python_replay_script(function, case)?;
    let script_path = root.join(".veritas").join("tmp_python_replay.py");
    if let Some(parent) = script_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&script_path, script)
        .with_context(|| format!("failed to write {}", script_path.display()))?;
    let command = run_command(
        root,
        "python3",
        [script_path.to_string_lossy().as_ref()],
        config.command_timeout_seconds.min(30),
    );
    let cleanup = fs::remove_file(&script_path)
        .with_context(|| format!("failed to remove {}", script_path.display()));
    let command = command?;
    cleanup?;

    let outputs = parse_replay_marker_output(&command.stdout);
    let output = if outputs.is_empty() {
        serde_json::json!({
            "observations": [],
            "stderr": excerpt(&command.stderr),
        })
    } else {
        serde_json::json!({ "observations": outputs })
    };
    let status = if command.status == RunStatus::Passed && !outputs.is_empty() {
        BehaviorReplayStatus::Observed
    } else {
        BehaviorReplayStatus::Failed
    };
    Ok(BehaviorReplayObservation {
        status,
        output,
        command: Some(command_line(&command.program, &command.args)),
        stdout_excerpt: Some(excerpt(&command.stdout)),
        stderr_excerpt: Some(excerpt(&command.stderr)),
        duration_ms: Some(command.duration_ms),
    })
}

fn replay_python_function_batch(
    root: &Path,
    function: &PythonFunction,
    cases: &[BehaviorReplayCase],
    config: &PythonPluginConfig,
) -> Result<BTreeMap<String, BehaviorReplayObservation>> {
    let mut observations = BTreeMap::new();
    if cases.is_empty() {
        return Ok(observations);
    }
    if function.owner.is_some() {
        insert_unsupported_python_replay(
            &mut observations,
            cases,
            "method replay requires receiver construction",
        );
        return Ok(observations);
    }
    if function.params.is_empty() {
        insert_unsupported_python_replay(
            &mut observations,
            cases,
            "executable replay requires at least one supported argument",
        );
        return Ok(observations);
    }

    let runnable = cases
        .iter()
        .filter(|case| {
            if case.inputs.is_empty() {
                observations.insert(
                    case.name.clone(),
                    unsupported_python_replay(
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

    let script = render_python_replay_batch_script(function, &runnable)?;
    let script_path = root.join(".veritas").join(format!(
        "tmp_python_replay_{}_{}.py",
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
        "python3",
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

fn render_python_replay_script(
    function: &PythonFunction,
    case: &BehaviorReplayCase,
) -> Result<String> {
    let inputs = serde_json::to_string(&case.inputs)?;
    Ok(format!(
        r#"import importlib.util
import json
import pathlib
import traceback

module_path = pathlib.Path({path:?})
spec = importlib.util.spec_from_file_location("veritas_replay_target", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
target = getattr(module, {name:?})
arity = {arity}

def call_args(value):
    if arity == 1:
        return [value]
    if isinstance(value, list) and len(value) == arity:
        return value
    raise ValueError("replay input does not match target arity")

for value in json.loads({inputs:?}):
    try:
        output = repr(target(*call_args(value)))
        status = "observed"
    except BaseException as exc:
        output = repr(exc)
        status = "exception"
    print("__VERITAS_REPLAY__{{}}\t{{}}\t{{}}".format(repr(value), status, output))
"#,
        path = function.path.as_str(),
        name = function.name,
        arity = function.params.len(),
        inputs = inputs
    ))
}

fn render_python_replay_batch_script(
    function: &PythonFunction,
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
    Ok(format!(
        r#"import importlib.util
import json
import pathlib

module_path = pathlib.Path({path:?})
spec = importlib.util.spec_from_file_location("veritas_replay_target", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
target = getattr(module, {name:?})
arity = {arity}

def call_args(value):
    if arity == 1:
        return [value]
    if isinstance(value, list) and len(value) == arity:
        return value
    raise ValueError("replay input does not match target arity")

for case in json.loads({cases:?}):
    for value in case["inputs"]:
        try:
            output = repr(target(*call_args(value)))
            status = "observed"
        except BaseException as exc:
            output = repr(exc)
            status = "exception"
        print("__VERITAS_REPLAY_CASE__{{}}\t{{}}\t{{}}\t{{}}".format(case["name"], repr(value), status, output))
"#,
        path = function.path.as_str(),
        name = function.name,
        arity = function.params.len(),
        cases = cases
    ))
}

fn unsupported_python_replay(reason: &str) -> BehaviorReplayObservation {
    BehaviorReplayObservation {
        status: BehaviorReplayStatus::Unsupported,
        output: serde_json::json!({ "reason": reason }),
        command: None,
        stdout_excerpt: None,
        stderr_excerpt: None,
        duration_ms: None,
    }
}

fn insert_unsupported_python_replay(
    observations: &mut BTreeMap<String, BehaviorReplayObservation>,
    cases: &[BehaviorReplayCase],
    reason: &str,
) {
    for case in cases {
        observations.insert(case.name.clone(), unsupported_python_replay(reason));
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

fn python_target_matches_function(target_id: &str, function: &PythonFunction) -> bool {
    if target_id == "python:project" {
        return true;
    }
    let Some(rest) = target_id.strip_prefix("python:") else {
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

fn contains_python_file(root: &Path) -> bool {
    WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry.path(), entry.file_name()))
        .filter_map(Result::ok)
        .any(|entry| {
            entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("py"))
        })
}

fn is_ignored(path: &Path, name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    if matches!(
        name.as_ref(),
        ".git"
            | ".hg"
            | ".svn"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".veritas"
    ) {
        return true;
    }
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_string_lossy().as_ref(),
            ".git" | ".venv" | "venv" | "__pycache__" | ".veritas"
        )
    })
}

fn is_python_test_file(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.starts_with("test_") || name.ends_with("_test.py"))
        || path
            .components()
            .any(|component| component.as_os_str() == OsStr::new("tests"))
}

fn python_test_args(root: &Path) -> (&'static str, Vec<String>) {
    python_test_args_with_availability(root, python_module_available(root, "pytest"))
}

fn python_test_args_with_availability(
    root: &Path,
    pytest_available: bool,
) -> (&'static str, Vec<String>) {
    if prefers_pytest(root) && pytest_available {
        (
            "pytest",
            vec!["-m".to_string(), "pytest".to_string(), "-q".to_string()],
        )
    } else {
        (
            "unittest",
            vec![
                "-m".to_string(),
                "unittest".to_string(),
                "discover".to_string(),
            ],
        )
    }
}

fn prefers_pytest(root: &Path) -> bool {
    root.join("pytest.ini").exists()
        || root.join(".pytest.ini").exists()
        || config_contains(root.join("pyproject.toml"), "[tool.pytest")
        || config_contains(root.join("setup.cfg"), "[tool:pytest]")
        || config_contains(root.join("tox.ini"), "[pytest]")
        || tests_import_pytest(root)
}

fn tests_import_pytest(root: &Path) -> bool {
    WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_entry(|entry| !is_ignored(entry.path(), entry.file_name()))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry.path().extension() == Some(OsStr::new("py"))
                && is_python_test_file(entry.path())
        })
        .any(|entry| {
            fs::read_to_string(entry.path()).is_ok_and(|contents| {
                contents.contains("import pytest") || contents.contains("from pytest")
            })
        })
}

fn config_contains(path: impl AsRef<Path>, needle: &str) -> bool {
    fs::read_to_string(path).is_ok_and(|contents| contents.contains(needle))
}

fn python_module_available(root: &Path, module: &str) -> bool {
    Command::new("python3")
        .args(["-m", module, "--version"])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
        "serialize",
        "deserialize",
        "refund",
        "discount",
    ];
    if high_risk_terms.iter().any(|term| lowered.contains(term)) {
        RiskLevel::High
    } else {
        RiskLevel::Medium
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.byte_range())
        .ok_or_else(|| anyhow!("invalid tree-sitter byte range"))
}

fn signature_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    let start = node.start_byte();
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    source
        .get(start..body_start)
        .ok_or_else(|| anyhow!("invalid Python signature byte range"))
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

fn parse_replay_marker_output(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let marker = line.find("__VERITAS_REPLAY__")?;
            let payload = &line[marker + "__VERITAS_REPLAY__".len()..];
            let mut parts = payload.splitn(3, '\t');
            let input = parts.next()?.to_string();
            let status = parts.next()?.to_string();
            let output = parts.next().unwrap_or_default().to_string();
            Some(serde_json::json!({
                "input": input,
                "status": status,
                "output": output,
            }))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn pytest_preference_uses_pytest_when_available() {
        let root = unique_test_root("pytest-available");
        fs::create_dir_all(root.join("tests")).expect("create tests dir");
        fs::write(root.join("pyproject.toml"), "[tool.pytest.ini_options]\n").expect("pyproject");

        let (runner, args) = python_test_args_with_availability(&root, true);

        fs::remove_dir_all(&root).ok();
        assert_eq!(runner, "pytest");
        assert_eq!(args, ["-m", "pytest", "-q"]);
    }

    #[test]
    fn pytest_preference_falls_back_to_unittest_when_unavailable() {
        let root = unique_test_root("pytest-unavailable");
        fs::create_dir_all(root.join("tests")).expect("create tests dir");
        fs::write(root.join("tests/test_invoice.py"), "import pytest\n").expect("test file");

        let (runner, args) = python_test_args_with_availability(&root, false);

        fs::remove_dir_all(&root).ok();
        assert_eq!(runner, "unittest");
        assert_eq!(args, ["-m", "unittest", "discover"]);
    }

    #[test]
    fn python_mutation_skip_annotation_is_function_local() {
        let source =
            "def kept():\n    return 1\n\ndef skipped():\n    # veritas:skip-mutation\n    return 2\n";
        let kept_start = source.find("def kept").unwrap();
        let kept_end = source.find("def skipped").unwrap();
        let skipped_start = kept_end;
        assert!(!function_has_mutation_skip_annotation(
            source, kept_start, kept_end
        ));
        assert!(function_has_mutation_skip_annotation(
            source,
            skipped_start,
            source.len()
        ));
    }

    fn unique_test_root(name: &str) -> PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis();
        std::env::temp_dir().join(format!("veritas-python-{name}-{millis}"))
    }
}
