use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use tree_sitter::{Node, Parser};
use veritas_core::config::RustPluginConfig;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, CommandRecord, CoverageReport, Failure, FailureSeverity,
    GeneratedArtifact, LanguagePlugin, LineRange, ProjectInfo, ReproCase, RiskLevel, RunStatus,
    TargetKind, TestRunResult, VerificationPlan, VerificationStrategy, VerificationTarget,
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
    path: Utf8PathBuf,
    params: Vec<RustParam>,
    returns_value: bool,
    signature: String,
    line_range: LineRange,
    start_byte: usize,
    end_byte: usize,
    crate_name: String,
    package_root: Utf8PathBuf,
}

#[derive(Debug, Clone)]
struct RustParam {
    name: String,
    type_name: String,
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
                id: format!("rust:{}:{}", function.path, function.name),
                language: "rust".to_string(),
                kind: TargetKind::Function,
                path: function.path.clone(),
                symbol: Some(function.name.clone()),
                signature: Some(function.signature.clone()),
                line_range: Some(function.line_range.clone()),
                description: format!("public Rust function {}", function.name),
                risk: infer_risk(&function.name),
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
            .into_iter()
            .filter(|function| {
                if let Some(symbol) = &target.symbol {
                    function.name == *symbol && function.path == target.path
                } else {
                    function.path == target.path || target.kind == TargetKind::Project
                }
            })
            .filter(supports_proptest)
            .collect();

        let mut artifacts = Vec::new();
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

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        let start = Instant::now();
        let mut commands = Vec::new();
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
            failures_for_failed_commands(&test_commands, artifacts, "cargo test failed");
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
    if node.kind() == "function_item" && is_public_free_function(node, source) {
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
    let params = node
        .child_by_field_name("parameters")
        .map(|parameters| parse_rust_params(node_text(parameters, source).unwrap_or_default()))
        .unwrap_or_default();
    let signature = signature_text(node, source)?.trim().to_string();
    let returns_value = signature.contains("->");

    Ok(Some(RustFunction {
        name,
        path: path.clone(),
        params,
        returns_value,
        signature,
        line_range: LineRange {
            start: node.start_position().row + 1,
            end: node.end_position().row + 1,
        },
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        crate_name: package.crate_name.clone(),
        package_root: package.root.clone(),
    }))
}

fn is_public_free_function(node: Node<'_>, source: &str) -> bool {
    if has_ancestor_kind(node, &["impl_item", "trait_item"]) {
        return false;
    }

    let mut cursor = node.walk();
    let is_public = node.children(&mut cursor).any(|child| {
        child.kind() == "visibility_modifier"
            && node_text(child, source).is_ok_and(|text| text.trim_start().starts_with("pub"))
    });
    is_public
}

fn has_ancestor_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if kinds.contains(&parent.kind()) {
            return true;
        }
        current = parent.parent();
    }
    false
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

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.start_byte()..node.end_byte())
        .ok_or_else(|| anyhow!("tree-sitter node byte range was invalid"))
}

fn supports_proptest(function: &RustFunction) -> bool {
    function.params.len() <= 2
        && function
            .params
            .iter()
            .all(|param| proptest_strategy(&param.type_name).is_some())
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
    }
    out.push_str("}\n");
    out
}

fn render_index(module_name: &str) -> String {
    format!(
        "// Generated by veritas. Review before committing.\n#[path = \"veritas_generated/{module_name}.rs\"]\nmod {module_name};\n"
    )
}

fn render_call_arg(param: &RustParam) -> String {
    let ident = safe_ident(&param.name);
    match param.type_name.as_str() {
        "&str" => format!("{ident}.as_str()"),
        _ => ident,
    }
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
    label: &'static str,
    from: &'static str,
    to: &'static str,
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
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut status = RunStatus::Passed;

    for candidate in candidates.into_iter().take(8) {
        if budget_nearly_spent(run_start, plan.budget_seconds) {
            commands.push(skipped_command(
                root,
                "rust mutation checks",
                "global budget nearly exhausted before remaining mutants",
            )?);
            break;
        }
        let path = root.join(&candidate.path);
        let original = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut mutated = original.clone();
        mutated.replace_range(candidate.start_byte..candidate.end_byte, candidate.to);
        fs::write(&path, mutated).with_context(|| {
            format!(
                "failed to write Rust mutation {} in {}",
                candidate.label,
                path.display()
            )
        })?;

        fs::write(&path, original)
            .with_context(|| format!("failed to restore {}", path.display()))?;
        let mutation_commands = run_cargo_tests(root, package_roots, config)?;
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
        }
    }

    Ok(TestRunResult {
        language: "rust".to_string(),
        status,
        commands,
        failures,
        duration_ms: start.elapsed().as_millis(),
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

    for function in functions {
        if !mutation_targets
            .iter()
            .any(|target_id| rust_target_matches_function(target_id, function))
        {
            continue;
        }
        let contents = fs::read_to_string(root.join(&function.path))?;
        let Some(function_text) = contents.get(function.start_byte..function.end_byte) else {
            continue;
        };
        for (label, from, to) in [
            ("boundary inversion", ".min(", ".max("),
            ("boundary inversion", ".max(", ".min("),
            ("arithmetic direction", "saturating_sub", "saturating_add"),
            ("arithmetic direction", "saturating_add", "saturating_sub"),
            ("default value perturbation", "unwrap_or(0)", "unwrap_or(1)"),
            ("boolean inversion", "true", "false"),
            ("boolean inversion", "false", "true"),
            ("equality inversion", "==", "!="),
            ("inequality inversion", "!=", "=="),
        ] {
            if let Some(offset) = function_text.find(from) {
                candidates.push(MutationCandidate {
                    path: function.path.clone(),
                    function: function.name.clone(),
                    label,
                    from,
                    to,
                    start_byte: function.start_byte + offset,
                    end_byte: function.start_byte + offset + from.len(),
                });
                break;
            }
        }
    }

    Ok(candidates)
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
        return path == function.path.as_str() && symbol == function.name;
    }
    false
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
    commands: &[CommandRecord],
    artifacts: &[GeneratedArtifact],
    message: &str,
) -> Vec<Failure> {
    commands
        .iter()
        .filter(|command| command.status == RunStatus::Failed)
        .map(|command| Failure {
            id: None,
            message: message.to_string(),
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
        })
        .collect()
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
