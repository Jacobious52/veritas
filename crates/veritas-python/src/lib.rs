use std::{
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use serde::Serialize;
use tree_sitter::{Node, Parser};
use veritas_core::config::PythonPluginConfig;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, BehaviorReplayCase, BehaviorReplayObservation,
    BehaviorReplayStatus, CommandRecord, CoverageReport, Failure, FailureSeverity,
    GeneratedArtifact, LanguagePlugin, LineRange, PluginCapability, ProjectInfo, ReproCase,
    RiskLevel, RunStatus, TargetKind, TestRunResult, VerificationPlan, VerificationQuality,
    VerificationTarget,
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
    calls: Vec<String>,
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
        _plan: &VerificationPlan,
    ) -> Result<Vec<GeneratedArtifact>> {
        let root = std::env::current_dir()?;
        let functions = discover_functions(&root).unwrap_or_default();
        Ok(vec![symbol_graph_artifact(
            &target.id,
            &target.path,
            target.symbol.as_deref(),
            &functions,
        )?])
    }

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        _plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        let start = Instant::now();
        let command = run_command(
            root,
            "python3",
            ["-m", "unittest", "discover"],
            self.config.command_timeout_seconds,
        )?;
        let status = command.status.clone();
        let failures = if command.status == RunStatus::Failed {
            vec![Failure {
                id: None,
                message: "python unittest failed".to_string(),
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

        Ok(TestRunResult {
            language: "python".to_string(),
            status,
            commands: vec![command],
            failures,
            duration_ms: start.elapsed().as_millis(),
            quality: VerificationQuality::default(),
        })
    }

    fn collect_coverage(&self, _root: &Path) -> Result<Option<CoverageReport>> {
        Ok(Some(CoverageReport {
            tool: "python coverage".to_string(),
            summary: if self.config.coverage_enabled {
                "not collected: Python coverage integration is not enabled in this spike"
                    .to_string()
            } else {
                "not collected: disabled by Python plugin config".to_string()
            },
            files: vec![],
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
            .find(|function| python_target_matches_function(&target.id, function))
        else {
            return Ok(None);
        };
        replay_python_function(root, function, case, &self.config).map(Some)
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
    if function.params.len() != 1 || case.inputs.is_empty() {
        return Ok(unsupported_python_replay(
            "executable replay currently supports single-argument functions with seeded inputs",
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

for value in json.loads({inputs:?}):
    try:
        output = repr(target(value))
        status = "observed"
    except BaseException as exc:
        output = repr(exc)
        status = "exception"
    print("__VERITAS_REPLAY__{{}}\t{{}}\t{{}}".format(repr(value), status, output))
"#,
        path = function.path.as_str(),
        name = function.name,
        inputs = inputs
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
