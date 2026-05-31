use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};
use veritas_core::{config::GoPluginConfig, run_parallel_jobs};
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, CommandRecord, CoverageFile, CoverageReport, Failure,
    FailureSeverity, GeneratedArtifact, LanguagePlugin, LineRange, MutationAttribution,
    PluginCapability, ProjectInfo, ReproCase, RiskLevel, RunStatus, TargetKind, TestRunResult,
    VerificationPlan, VerificationQuality, VerificationReport, VerificationStrategy,
    VerificationTarget,
};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct GoPlugin {
    config: GoPluginConfig,
    state: Arc<Mutex<GoPluginState>>,
}

#[derive(Debug, Default)]
struct GoPluginState {
    coverage_package_args: BTreeMap<Utf8PathBuf, Vec<String>>,
}

#[derive(Debug, Clone)]
struct GoModule {
    module_path: String,
    root: Utf8PathBuf,
}

#[derive(Debug, Clone)]
struct GoFunction {
    package_name: String,
    path: Utf8PathBuf,
    name: String,
    symbol: String,
    receiver: Option<String>,
    params: Vec<GoParam>,
    signature: String,
    line_range: LineRange,
    start_byte: usize,
    end_byte: usize,
    calls: Vec<String>,
}

#[derive(Debug, Clone)]
struct GoParam {
    name: String,
    type_name: String,
}

#[derive(Debug, Clone)]
struct GoPackage {
    import_path: String,
    dir: Utf8PathBuf,
    imports: Vec<String>,
    test_imports: Vec<String>,
    x_test_imports: Vec<String>,
    go_files: Vec<String>,
    test_go_files: Vec<String>,
    x_test_go_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackage {
    import_path: String,
    dir: String,
    imports: Option<Vec<String>>,
    test_imports: Option<Vec<String>>,
    x_test_imports: Option<Vec<String>>,
    go_files: Option<Vec<String>>,
    test_go_files: Option<Vec<String>>,
    x_test_go_files: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct GoSymbolGraph<'a> {
    target_id: &'a str,
    symbols: Vec<GoSymbolNode<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct GoSymbolNode<'a> {
    id: String,
    path: &'a Utf8PathBuf,
    package_name: &'a str,
    symbol: &'a str,
    name: &'a str,
    receiver: Option<&'a str>,
    signature: &'a str,
    line_range: &'a LineRange,
    risk: RiskLevel,
    calls: &'a [String],
}

#[derive(Debug, Clone, Default)]
struct GoFuzzTargets {
    handwritten: BTreeMap<Utf8PathBuf, Vec<String>>,
    generated: BTreeMap<Utf8PathBuf, Vec<String>>,
}

#[derive(Debug, Clone, Default)]
struct GoVerificationContext {
    modules: Vec<GoModule>,
    packages: Vec<GoPackage>,
    functions: Vec<GoFunction>,
    fuzz_targets: GoFuzzTargets,
}

impl GoPlugin {
    pub fn new(config: GoPluginConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(GoPluginState::default())),
        }
    }

    fn remember_coverage_package_args(&self, root: &Path, package_args: Vec<String>) -> Result<()> {
        let root = utf8_path(root)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("Go plugin state lock was poisoned"))?;
        state.coverage_package_args.insert(root, package_args);
        Ok(())
    }

    fn coverage_package_args(&self, root: &Path) -> Result<Vec<String>> {
        let root = utf8_path(root)?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("Go plugin state lock was poisoned"))?;
        Ok(state
            .coverage_package_args
            .get(&root)
            .cloned()
            .unwrap_or_else(|| vec!["./...".to_string()]))
    }
}

impl GoVerificationContext {
    fn discover(root: &Path, config: &GoPluginConfig) -> Result<Self> {
        let modules = discover_go_modules(root)?;
        let mut packages = Vec::new();
        let mut functions = Vec::new();
        let mut fuzz_targets = GoFuzzTargets::default();
        for module in &modules {
            let module_root = root.join(&module.root);
            packages.extend(
                discover_packages(&module_root, config)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut package| {
                        package.dir = prefix_module_path(&module.root, &package.dir);
                        package
                    }),
            );
            functions.extend(
                discover_functions(&module_root)?
                    .into_iter()
                    .map(|mut function| {
                        function.path = prefix_module_path(&module.root, &function.path);
                        function
                    }),
            );
            let module_fuzz = discover_existing_fuzz_targets(&module_root)?;
            merge_prefixed_fuzz_targets(&mut fuzz_targets, &module.root, module_fuzz);
        }
        Ok(Self {
            modules,
            packages,
            functions,
            fuzz_targets,
        })
    }
}

impl LanguagePlugin for GoPlugin {
    fn id(&self) -> &'static str {
        "go"
    }

    fn display_name(&self) -> &'static str {
        "Go"
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::TargetDiscovery,
            PluginCapability::SymbolGraph,
            PluginCapability::GeneratedTests,
            PluginCapability::ExistingTests,
            PluginCapability::Fuzzing,
            PluginCapability::MutationChecks,
            PluginCapability::Coverage,
            PluginCapability::DifferentialReplay,
            PluginCapability::CorpusReplay,
            PluginCapability::RegressionPromotion,
            PluginCapability::ResourceBudgets,
        ]
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectInfo> {
        let modules = discover_go_modules(root)?;
        if modules.is_empty() {
            return Err(anyhow!("go.mod not found"));
        }
        let name = if modules.len() == 1 {
            modules[0].module_path.clone()
        } else {
            format!("{} Go modules", modules.len())
        };
        let manifests = modules
            .iter()
            .map(|module| prefix_module_path(&module.root, &Utf8PathBuf::from("go.mod")))
            .collect();
        Ok(ProjectInfo {
            language: "go".to_string(),
            name,
            root: utf8_path(root)?,
            manifests,
        })
    }

    fn discover_targets(&self, root: &Path) -> Result<Vec<VerificationTarget>> {
        let context = GoVerificationContext::discover(root, &self.config)?;
        let mut targets = vec![VerificationTarget {
            id: "go:project".to_string(),
            language: "go".to_string(),
            kind: TargetKind::Project,
            path: Utf8PathBuf::from("."),
            symbol: None,
            signature: None,
            line_range: None,
            description: if context.modules.len() == 1 {
                format!("Go module {}", context.modules[0].module_path)
            } else {
                format!("{} Go modules", context.modules.len())
            },
            risk: RiskLevel::Medium,
        }];

        let mut packages = BTreeSet::new();
        for package in &context.packages {
            packages.insert(package.dir.clone());
        }
        for function in context.functions {
            packages.insert(package_dir(&function.path));
            targets.push(VerificationTarget {
                id: format!("go:{}:{}", function.path, function.symbol),
                language: "go".to_string(),
                kind: TargetKind::Function,
                path: function.path.clone(),
                symbol: Some(function.symbol.clone()),
                signature: Some(function.signature.clone()),
                line_range: Some(function.line_range.clone()),
                description: if let Some(receiver) = &function.receiver {
                    format!("Go method {receiver}.{}", function.name)
                } else {
                    format!("Go function {}", function.name)
                },
                risk: infer_risk(&function.symbol),
            });
        }

        for package in packages {
            targets.push(VerificationTarget {
                id: format!("go:{package}"),
                language: "go".to_string(),
                kind: TargetKind::Package,
                path: package.clone(),
                symbol: None,
                signature: None,
                line_range: None,
                description: format!("Go package {package}"),
                risk: RiskLevel::Medium,
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
        let context = GoVerificationContext::discover(&root, &self.config)?;
        let selected: Vec<GoFunction> = context
            .functions
            .iter()
            .filter(|function| {
                if let Some(symbol) = &target.symbol {
                    function.symbol == *symbol && function.path == target.path
                } else {
                    package_dir(&function.path) == target.path
                        || function.path == target.path
                        || target.kind == TargetKind::Project
                }
            })
            .cloned()
            .collect();
        let selected_dirs = selected_package_dirs(target, &selected);

        let mut artifacts = Vec::new();
        if let Some(artifact) =
            package_awareness_artifact(&context, &self.config, target, &selected_dirs)
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            package_graph_artifact(&context, &self.config, target, &selected_dirs)?
        {
            artifacts.push(artifact);
        }
        artifacts.push(symbol_graph_artifact(
            &context,
            &target.id,
            &target.path,
            target.symbol.as_deref(),
        )?);

        if plan
            .strategies
            .iter()
            .any(|strategy| matches!(strategy, VerificationStrategy::Fuzzing))
            && !selected.is_empty()
        {
            let mut by_package: BTreeMap<Utf8PathBuf, Vec<GoFunction>> = BTreeMap::new();
            for function in selected.clone() {
                if function.receiver.is_some() || function.params.is_empty() {
                    continue;
                }
                let package = package_dir(&function.path);
                if handwritten_fuzz_exists(&context, &package, &function) {
                    continue;
                }
                by_package.entry(package).or_default().push(function);
            }

            for (package, functions) in by_package {
                if functions.is_empty() {
                    continue;
                }
                let file_path = if package.as_str() == "." {
                    Utf8PathBuf::from("veritas_fuzz_test.go")
                } else {
                    package.join("veritas_fuzz_test.go")
                };
                artifacts.push(GeneratedArtifact {
                    id: format!("go-fuzz-{}", safe_ident(package.as_str())),
                    language: "go".to_string(),
                    kind: ArtifactKind::FuzzHarness,
                    target_id: target.id.clone(),
                    path: file_path,
                    contents: render_fuzz_file(&functions),
                    description: "Generated Go testing.F fuzz harnesses".to_string(),
                    status: ArtifactStatus::Planned,
                });
            }
        }

        if plan
            .strategies
            .iter()
            .any(|strategy| matches!(strategy, VerificationStrategy::MutationChecks))
            && !selected_dirs.is_empty()
        {
            let slug = module_slug(&target.path, target.symbol.as_deref());
            artifacts.push(GeneratedArtifact {
                id: format!("go-mutation-{slug}"),
                language: "go".to_string(),
                kind: ArtifactKind::MutationCheck,
                target_id: target.id.clone(),
                path: Utf8PathBuf::from(format!(".veritas/mutations/go_{slug}.txt")),
                contents: format!(
                    "language=go\ntarget_id={}\npath={}\nsymbol={}\n",
                    target.id,
                    target.path,
                    target.symbol.as_deref().unwrap_or("")
                ),
                description: "Deterministic Go mutation probes for selected functions".to_string(),
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
        promoted_go_regression_artifacts(root, &self.config, report, finding, index)
    }

    fn run_tests(
        &self,
        root: &Path,
        artifacts: &[GeneratedArtifact],
        plan: &VerificationPlan,
    ) -> Result<TestRunResult> {
        let start = Instant::now();
        let context = GoVerificationContext::discover(root, &self.config)?;
        let mut commands = Vec::new();
        let mut quality = VerificationQuality::default();
        let package_args = test_package_args(&context, artifacts, &self.config);
        self.remember_coverage_package_args(root, package_args.clone())?;
        let mut status = RunStatus::Passed;
        for (module_root, module_package_args) in
            module_package_args(&context.modules, &package_args)
        {
            let test_args = go_test_args(&self.config, &module_package_args);
            let existing = run_command(
                &root.join(&module_root),
                "go",
                test_args,
                self.config.command_timeout_seconds,
            )?;
            if existing.status == RunStatus::Failed {
                status = RunStatus::Failed;
            }
            commands.push(existing);
        }

        if status == RunStatus::Passed {
            if budget_nearly_spent(start, plan.budget_seconds) {
                commands.push(skipped_command(
                    root,
                    "go fuzz targets",
                    "global budget nearly exhausted before remaining fuzz targets",
                )?);
            } else {
                let fuzz_commands = run_fuzz_targets(root, &context, &self.config, artifacts)?;
                if fuzz_commands
                    .iter()
                    .any(|command| command.status == RunStatus::Failed)
                {
                    status = RunStatus::Failed;
                }
                quality.fuzz.targets_executed += fuzz_commands
                    .iter()
                    .filter(|command| command.status != RunStatus::Skipped)
                    .count();
                quality.fuzz.failures += fuzz_commands
                    .iter()
                    .filter(|command| command.status == RunStatus::Failed)
                    .count();
                commands.extend(fuzz_commands);
            }
        }

        let mut failures = commands
            .iter()
            .filter(|command| command.status == RunStatus::Failed)
            .map(|command| go_command_failure(command, artifacts))
            .collect::<Vec<_>>();

        if status == RunStatus::Passed
            && artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::MutationCheck)
        {
            if budget_nearly_spent(start, plan.budget_seconds) {
                commands.push(skipped_command(
                    root,
                    "go mutation checks",
                    "global budget nearly exhausted after tests and fuzzing",
                )?);
            } else {
                let mutation = run_mutation_checks(
                    root,
                    artifacts,
                    &context,
                    &self.config,
                    &package_args,
                    start,
                    plan,
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
            language: "go".to_string(),
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
                tool: "go test -coverprofile".to_string(),
                summary: "not collected: disabled by Go plugin config".to_string(),
                files: vec![],
            }));
        }

        let context = GoVerificationContext::discover(root, &self.config)?;
        let report_dir = root.join(".veritas");
        fs::create_dir_all(&report_dir)
            .with_context(|| format!("failed to create {}", report_dir.display()))?;
        let package_args = self.coverage_package_args(root)?;
        let mut summaries = Vec::new();
        let mut files = Vec::new();

        for (module_root, module_package_args) in
            module_package_args(&context.modules, &package_args)
        {
            let coverage_path =
                report_dir.join(format!("go-cover-{}.out", safe_ident(module_root.as_str())));
            if let Some(parent) = coverage_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let coverage_arg = format!("-coverprofile={}", coverage_path.display());
            let mut args = vec!["test".to_string()];
            if let Some(tags) = go_tags_arg(&self.config) {
                args.push(tags);
            }
            args.push(coverage_arg);
            args.extend(module_package_args);
            let command = run_command(
                &root.join(&module_root),
                "go",
                args,
                self.config.command_timeout_seconds,
            );
            let Ok(command) = command else {
                summaries.push(format!(
                    "{}: not collected: failed to run go test",
                    module_root
                ));
                continue;
            };
            if command.status == RunStatus::Failed {
                summaries.push(format!(
                    "{}: not collected: {}",
                    module_root,
                    excerpt(&command.stderr)
                ));
                continue;
            }

            summaries.push(format!(
                "{}: {}",
                module_root,
                go_coverage_summary(&command.stdout)
            ));
            files.extend(parse_go_coverprofile(root, &coverage_path)?);
        }

        if summaries.is_empty() {
            summaries.push("coverage collected".to_string());
        }
        Ok(Some(CoverageReport {
            tool: "go test -coverprofile".to_string(),
            summary: summaries.join("; "),
            files,
        }))
    }
}

fn parse_go_module(root: &Path, module_root: Utf8PathBuf) -> Result<GoModule> {
    let path = root.join("go.mod");
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let module_path = contents
        .lines()
        .find_map(|line| line.strip_prefix("module "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("go.mod is missing a module declaration"))?
        .to_string();
    Ok(GoModule {
        module_path,
        root: module_root,
    })
}

fn discover_go_modules(root: &Path) -> Result<Vec<GoModule>> {
    let mut module_roots = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || !is_ignored(entry.path(), entry.file_name()))
    {
        let entry = entry?;
        if entry.file_type().is_file() && entry.file_name() == "go.mod" {
            let module_root = entry
                .path()
                .parent()
                .map(|path| relative_utf8(root, path))
                .transpose()?
                .unwrap_or_else(|| Utf8PathBuf::from("."));
            module_roots.push(normalize_package_dir(module_root));
        }
    }
    module_roots.sort();
    module_roots.dedup();

    let mut modules = Vec::new();
    for module_root in module_roots {
        modules.push(parse_go_module(&root.join(&module_root), module_root)?);
    }
    Ok(modules)
}

fn discover_packages(root: &Path, config: &GoPluginConfig) -> Result<Vec<GoPackage>> {
    let mut args = vec!["list".to_string(), "-json".to_string()];
    if let Some(tags) = go_tags_arg(config) {
        args.push(tags);
    }
    args.push("./...".to_string());
    let command = run_command(root, "go", args, config.command_timeout_seconds)?;
    if command.status == RunStatus::Failed {
        return Err(anyhow!(
            "go list failed: {}",
            excerpt(&format!("{}\n{}", command.stdout, command.stderr))
        ));
    }

    let stream = serde_json::Deserializer::from_str(&command.stdout).into_iter::<GoListPackage>();
    let mut packages = Vec::new();
    for package in stream {
        let package = package.with_context(|| "failed to parse go list JSON")?;
        packages.push(GoPackage {
            import_path: package.import_path,
            dir: normalize_package_dir(relative_utf8(root, Path::new(&package.dir))?),
            imports: package.imports.unwrap_or_default(),
            test_imports: package.test_imports.unwrap_or_default(),
            x_test_imports: package.x_test_imports.unwrap_or_default(),
            go_files: package.go_files.unwrap_or_default(),
            test_go_files: package.test_go_files.unwrap_or_default(),
            x_test_go_files: package.x_test_go_files.unwrap_or_default(),
        });
    }
    Ok(packages)
}

fn test_package_args(
    context: &GoVerificationContext,
    artifacts: &[GeneratedArtifact],
    config: &GoPluginConfig,
) -> Vec<String> {
    let selected_dirs = package_dirs_from_artifacts(artifacts);
    if selected_dirs.is_empty() {
        return vec!["./...".to_string()];
    }

    if context.packages.is_empty() {
        return selected_dirs.iter().map(package_arg).collect();
    }

    let dirs = scoped_package_dirs(
        &context.packages,
        &selected_dirs,
        config.reverse_dependency_depth,
        config.max_packages,
    );
    dirs.iter().map(package_arg).collect()
}

fn module_package_args(
    modules: &[GoModule],
    package_args: &[String],
) -> BTreeMap<Utf8PathBuf, Vec<String>> {
    let mut by_module: BTreeMap<Utf8PathBuf, Vec<String>> = BTreeMap::new();
    if modules.is_empty() {
        by_module.insert(Utf8PathBuf::from("."), package_args.to_vec());
        return by_module;
    }

    for package_arg in package_args {
        if package_arg == "./..." {
            for module in modules {
                by_module
                    .entry(module.root.clone())
                    .or_default()
                    .push("./...".to_string());
            }
            continue;
        }

        let path = package_arg
            .strip_prefix("./")
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|| Utf8PathBuf::from(package_arg));
        let module = owning_module(modules, &path);
        let relative_arg = module_relative_package_arg(&module.root, &path);
        by_module
            .entry(module.root.clone())
            .or_default()
            .push(relative_arg);
    }

    for args in by_module.values_mut() {
        args.sort();
        args.dedup();
    }
    by_module
}

fn owning_module<'a>(modules: &'a [GoModule], path: &Utf8PathBuf) -> &'a GoModule {
    modules
        .iter()
        .filter(|module| module.root.as_str() == "." || path.starts_with(&module.root))
        .max_by_key(|module| module.root.as_str().len())
        .unwrap_or(&modules[0])
}

fn module_relative_package_arg(module_root: &Utf8PathBuf, path: &Utf8PathBuf) -> String {
    let relative = if module_root.as_str() == "." {
        path.clone()
    } else {
        path.strip_prefix(module_root)
            .map(Utf8PathBuf::from)
            .unwrap_or_else(|_| path.clone())
    };
    package_arg(&normalize_package_dir(relative))
}

#[cfg(test)]
fn scoped_package_args(
    packages: &[GoPackage],
    selected_dirs: &BTreeSet<Utf8PathBuf>,
) -> Vec<String> {
    scoped_package_dirs(packages, selected_dirs, 1, usize::MAX)
        .iter()
        .map(package_arg)
        .collect()
}

fn scoped_package_dirs(
    packages: &[GoPackage],
    selected_dirs: &BTreeSet<Utf8PathBuf>,
    reverse_depth: usize,
    max_packages: usize,
) -> BTreeSet<Utf8PathBuf> {
    let selected_imports = packages
        .iter()
        .filter(|package| selected_dirs.contains(&package.dir))
        .map(|package| package.import_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut dirs = selected_dirs.clone();

    if !selected_imports.is_empty() && reverse_depth > 0 {
        let mut frontier = selected_imports
            .iter()
            .map(|import| (*import).to_string())
            .collect::<BTreeSet<_>>();
        for _ in 0..reverse_depth {
            let mut next_frontier = BTreeSet::new();
            for package in packages {
                if dirs.contains(&package.dir) {
                    continue;
                }
                if package.imports_any(&frontier) {
                    dirs.insert(package.dir.clone());
                    next_frontier.insert(package.import_path.clone());
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }
    }

    limit_package_dirs(selected_dirs, dirs, max_packages)
}

fn limit_package_dirs(
    selected_dirs: &BTreeSet<Utf8PathBuf>,
    dirs: BTreeSet<Utf8PathBuf>,
    max_packages: usize,
) -> BTreeSet<Utf8PathBuf> {
    if max_packages == 0 || dirs.len() <= max_packages {
        return dirs;
    }

    let mut limited = selected_dirs.clone();
    if limited.len() >= max_packages {
        return limited.into_iter().take(max_packages).collect();
    }

    for dir in dirs {
        if limited.len() >= max_packages {
            break;
        }
        limited.insert(dir);
    }

    limited
}

impl GoPackage {
    fn imports_any(&self, imports: &BTreeSet<String>) -> bool {
        self.imports
            .iter()
            .chain(self.test_imports.iter())
            .chain(self.x_test_imports.iter())
            .any(|import| imports.contains(import))
    }

    fn has_tests(&self) -> bool {
        !self.test_go_files.is_empty() || !self.x_test_go_files.is_empty()
    }

    fn test_package_kinds(&self) -> String {
        let mut kinds = Vec::new();
        if !self.test_go_files.is_empty() {
            kinds.push("internal");
        }
        if !self.x_test_go_files.is_empty() {
            kinds.push("external");
        }
        if kinds.is_empty() {
            "none".to_string()
        } else {
            kinds.join("+")
        }
    }
}

fn selected_package_dirs(
    target: &VerificationTarget,
    selected_functions: &[GoFunction],
) -> BTreeSet<Utf8PathBuf> {
    let mut dirs = selected_functions
        .iter()
        .map(|function| package_dir(&function.path))
        .collect::<BTreeSet<_>>();

    if dirs.is_empty() {
        if target.kind == TargetKind::Project {
            return dirs;
        }
        let dir = if target.path.extension() == Some("go") {
            package_dir(&target.path)
        } else {
            target.path.clone()
        };
        dirs.insert(dir);
    }

    dirs
}

fn package_awareness_artifact(
    context: &GoVerificationContext,
    config: &GoPluginConfig,
    target: &VerificationTarget,
    selected_dirs: &BTreeSet<Utf8PathBuf>,
) -> Option<GeneratedArtifact> {
    let dirs = awareness_package_dirs(context, config, target, selected_dirs);
    if dirs.is_empty() {
        return None;
    }

    let mut contents = String::from("# Go Package Awareness\n\n");
    contents.push_str("Generated by veritas. Review before committing.\n\n");
    contents.push_str(&format!("- Target: `{}`\n", target.id));
    contents.push_str(&format!(
        "- Reverse dependency depth: `{}`\n",
        config.reverse_dependency_depth
    ));
    contents.push_str(&format!(
        "- Max fuzz targets per package: `{}`\n",
        config.max_fuzz_targets
    ));
    contents.push_str(&format!(
        "- Command timeout: `{}s`\n\n",
        config.command_timeout_seconds
    ));
    let scoped_dirs = awareness_package_dirs(context, config, target, selected_dirs);
    contents.push_str(
        "| Package | Import path | Run reason | Tests | Handwritten fuzz | Generated fuzz |\n",
    );
    contents.push_str("| --- | --- | --- | --- | --- | --- |\n");

    let mut suggestions = Vec::new();
    for dir in &dirs {
        let package = context.packages.iter().find(|package| &package.dir == dir);
        let import_path = package
            .map(|package| package.import_path.as_str())
            .unwrap_or("unknown");
        let tests = package
            .map(GoPackage::test_package_kinds)
            .unwrap_or_else(|| "unknown".to_string());
        let handwritten = awareness_fuzz_cell(&context.fuzz_targets.handwritten, dir);
        let generated = awareness_fuzz_cell(&context.fuzz_targets.generated, dir);
        let reason = package_run_reason(&scoped_dirs, selected_dirs, dir);
        contents.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
            dir, import_path, reason, tests, handwritten, generated
        ));

        if package.is_some_and(GoPackage::has_tests) && handwritten == "none" {
            suggestions.push(format!(
                "`{dir}` has tests but no handwritten fuzz target around the changed surface."
            ));
        }
        if handwritten != "none" && package.is_some_and(|package| package.go_files.is_empty()) {
            suggestions.push(format!(
                "`{dir}` exposes fuzzing from test-only files; confirm the package under test is still in scope."
            ));
        }
    }

    if !suggestions.is_empty() {
        contents.push_str("\n## Suggestions\n\n");
        for suggestion in suggestions {
            contents.push_str(&format!("- {suggestion}\n"));
        }
    }

    Some(GeneratedArtifact {
        id: format!(
            "go-package-awareness-{}",
            module_slug(&target.path, target.symbol.as_deref())
        ),
        language: "go".to_string(),
        kind: ArtifactKind::PackageAwareness,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(".veritas/feedback/go_packages.md"),
        contents,
        description: "Changed Go package test and fuzz awareness summary".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn package_graph_artifact(
    context: &GoVerificationContext,
    config: &GoPluginConfig,
    target: &VerificationTarget,
    selected_dirs: &BTreeSet<Utf8PathBuf>,
) -> Result<Option<GeneratedArtifact>> {
    if context.packages.is_empty() && context.modules.is_empty() {
        return Ok(None);
    }
    let scoped_dirs = awareness_package_dirs(context, config, target, selected_dirs);
    let modules = context
        .modules
        .iter()
        .map(|module| {
            serde_json::json!({
                "module_path": module.module_path,
                "root": module.root,
            })
        })
        .collect::<Vec<_>>();
    let packages = context
        .packages
        .iter()
        .map(|package| {
            serde_json::json!({
                "dir": package.dir,
                "import_path": package.import_path,
                "imports": package.imports,
                "test_imports": package.test_imports,
                "external_test_imports": package.x_test_imports,
                "has_tests": package.has_tests(),
                "test_package_kinds": package.test_package_kinds(),
                "handwritten_fuzz": context.fuzz_targets.handwritten.get(&package.dir).cloned().unwrap_or_default(),
                "generated_fuzz": context.fuzz_targets.generated.get(&package.dir).cloned().unwrap_or_default(),
                "run_reason": package_run_reason(&scoped_dirs, selected_dirs, &package.dir),
            })
        })
        .collect::<Vec<_>>();
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "target_id": target.id,
        "reverse_dependency_depth": config.reverse_dependency_depth,
        "max_packages": config.max_packages,
        "modules": modules,
        "packages": packages,
    }))?;

    Ok(Some(GeneratedArtifact {
        id: format!(
            "go-package-graph-{}",
            module_slug(&target.path, target.symbol.as_deref())
        ),
        language: "go".to_string(),
        kind: ArtifactKind::PackageGraph,
        target_id: target.id.clone(),
        path: Utf8PathBuf::from(".veritas/package_graph/go.json"),
        contents,
        description: "Machine-readable Go package graph and scoped-run reasons".to_string(),
        status: ArtifactStatus::Planned,
    }))
}

fn symbol_graph_artifact(
    context: &GoVerificationContext,
    target_id: &str,
    target_path: &Utf8PathBuf,
    target_symbol: Option<&str>,
) -> Result<GeneratedArtifact> {
    let symbols = context
        .functions
        .iter()
        .filter(|function| {
            target_symbol
                .map(|symbol| function.symbol == symbol && function.path == *target_path)
                .unwrap_or_else(|| {
                    package_dir(&function.path) == *target_path
                        || function.path == *target_path
                        || target_path.as_str() == "."
                })
        })
        .map(|function| GoSymbolNode {
            id: format!("go:{}:{}", function.path, function.symbol),
            path: &function.path,
            package_name: &function.package_name,
            symbol: &function.symbol,
            name: &function.name,
            receiver: function.receiver.as_deref(),
            signature: &function.signature,
            line_range: &function.line_range,
            risk: infer_risk(&function.symbol),
            calls: &function.calls,
        })
        .collect::<Vec<_>>();
    let graph = GoSymbolGraph { target_id, symbols };
    let contents = serde_json::to_string_pretty(&graph)?;
    let slug = module_slug(target_path, target_symbol);
    Ok(GeneratedArtifact {
        id: format!("go-symbol-graph-{slug}"),
        language: "go".to_string(),
        kind: ArtifactKind::SymbolGraph,
        target_id: target_id.to_string(),
        path: Utf8PathBuf::from(format!(".veritas/symbol_graph/go_{slug}.json")),
        contents,
        description: "Machine-readable Go symbol graph with receiver and call hints".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn package_run_reason(
    scoped_dirs: &BTreeSet<Utf8PathBuf>,
    selected_dirs: &BTreeSet<Utf8PathBuf>,
    dir: &Utf8PathBuf,
) -> &'static str {
    if selected_dirs.contains(dir) {
        "selected target"
    } else if scoped_dirs.contains(dir) {
        "reverse dependency"
    } else {
        "not scheduled"
    }
}

fn awareness_package_dirs(
    context: &GoVerificationContext,
    config: &GoPluginConfig,
    target: &VerificationTarget,
    selected_dirs: &BTreeSet<Utf8PathBuf>,
) -> BTreeSet<Utf8PathBuf> {
    if !selected_dirs.is_empty() && !context.packages.is_empty() {
        return scoped_package_dirs(
            &context.packages,
            selected_dirs,
            config.reverse_dependency_depth,
            config.max_packages,
        );
    }
    if !selected_dirs.is_empty() {
        return selected_dirs.clone();
    }
    if target.kind == TargetKind::Project {
        return context
            .packages
            .iter()
            .map(|package| package.dir.clone())
            .take(config.max_packages)
            .collect();
    }
    BTreeSet::new()
}

fn awareness_fuzz_cell(targets: &BTreeMap<Utf8PathBuf, Vec<String>>, dir: &Utf8PathBuf) -> String {
    let Some(names) = targets.get(dir) else {
        return "none".to_string();
    };
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

fn package_dirs_from_artifacts(artifacts: &[GeneratedArtifact]) -> BTreeSet<Utf8PathBuf> {
    let mut dirs = BTreeSet::new();
    for artifact in artifacts {
        if artifact.kind == ArtifactKind::FuzzHarness {
            dirs.insert(package_dir(&artifact.path));
        }
        if let Some(dir) = package_dir_from_target_id(&artifact.target_id) {
            dirs.insert(dir);
        }
    }
    dirs
}

fn package_dir_from_target_id(target_id: &str) -> Option<Utf8PathBuf> {
    let rest = target_id.strip_prefix("go:")?;
    if rest == "project" {
        return None;
    }
    let path = if let Some((path, _symbol)) = rest.rsplit_once(':') {
        path
    } else {
        rest
    };
    let path = Utf8PathBuf::from(path);
    if path.extension() == Some("go") {
        Some(package_dir(&path))
    } else {
        Some(path)
    }
}

fn package_arg(path: &Utf8PathBuf) -> String {
    if path.as_str() == "." {
        ".".to_string()
    } else {
        format!("./{path}")
    }
}

fn go_test_args(config: &GoPluginConfig, package_args: &[String]) -> Vec<String> {
    let mut args = vec!["test".to_string()];
    if let Some(tags) = go_tags_arg(config) {
        args.push(tags);
    }
    args.extend(package_args.iter().cloned());
    args
}

fn go_tags_arg(config: &GoPluginConfig) -> Option<String> {
    if config.build_tags.is_empty() {
        None
    } else {
        Some(format!("-tags={}", config.build_tags.join(",")))
    }
}

fn normalize_package_dir(path: Utf8PathBuf) -> Utf8PathBuf {
    if path.as_str().is_empty() {
        Utf8PathBuf::from(".")
    } else {
        path
    }
}

fn prefix_module_path(module_root: &Utf8PathBuf, path: &Utf8PathBuf) -> Utf8PathBuf {
    if module_root.as_str() == "." || path.as_str() == "." {
        if module_root.as_str() == "." {
            path.clone()
        } else {
            module_root.clone()
        }
    } else {
        module_root.join(path)
    }
}

fn merge_prefixed_fuzz_targets(
    target: &mut GoFuzzTargets,
    module_root: &Utf8PathBuf,
    source: GoFuzzTargets,
) {
    for (dir, names) in source.handwritten {
        target
            .handwritten
            .entry(prefix_module_path(module_root, &dir))
            .or_default()
            .extend(names);
    }
    for (dir, names) in source.generated {
        target
            .generated
            .entry(prefix_module_path(module_root, &dir))
            .or_default()
            .extend(names);
    }
}

fn discover_functions(root: &Path) -> Result<Vec<GoFunction>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Go grammar: {error}"))?;

    let mut functions = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_entry(|entry| {
        entry.depth() == 0
            || (!is_ignored(entry.path(), entry.file_name())
                && !is_nested_go_module_root(entry.path(), entry.depth()))
    }) {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension() != Some(OsStr::new("go"))
            || entry
                .path()
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with("_test.go"))
        {
            continue;
        }
        let path = relative_utf8(root, entry.path())?;
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let package_name = parse_package_name(&contents).unwrap_or_else(|| "main".to_string());
        let tree = parser
            .parse(&contents, None)
            .ok_or_else(|| anyhow!("failed to parse Go source {}", entry.path().display()))?;
        collect_go_functions(
            tree.root_node(),
            &contents,
            &package_name,
            &path,
            &mut functions,
        )?;
    }
    Ok(functions)
}

fn parse_package_name(contents: &str) -> Option<String> {
    contents
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("package "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn collect_go_functions(
    node: Node<'_>,
    source: &str,
    package_name: &str,
    path: &Utf8PathBuf,
    functions: &mut Vec<GoFunction>,
) -> Result<()> {
    if node.kind() == "function_declaration" || node.kind() == "method_declaration" {
        if let Some(function) = parse_go_function(node, source, package_name, path)? {
            functions.push(function);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_functions(child, source, package_name, path, functions)?;
    }
    Ok(())
}

fn parse_go_function(
    node: Node<'_>,
    source: &str,
    package_name: &str,
    path: &Utf8PathBuf,
) -> Result<Option<GoFunction>> {
    let Some(name_node) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let name = node_text(name_node, source)?;
    if !name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
    {
        return Ok(None);
    }
    let receiver = if node.kind() == "method_declaration" {
        parse_go_receiver(node, source)?
    } else {
        None
    };
    let symbol = receiver
        .as_ref()
        .map(|receiver| format!("{receiver}.{name}"))
        .unwrap_or_else(|| name.to_string());
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Ok(None);
    };
    let params = node_text(parameters, source)?;
    let params = parse_fuzz_params(params).unwrap_or_default();
    let signature = signature_text(node, source)?.trim().to_string();
    Ok(Some(GoFunction {
        package_name: package_name.to_string(),
        path: path.clone(),
        name: name.to_string(),
        symbol,
        receiver,
        params,
        signature,
        line_range: LineRange {
            start: node.start_position().row + 1,
            end: node.end_position().row + 1,
        },
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        calls: go_calls_in_function(node, source)?,
    }))
}

fn parse_go_receiver(node: Node<'_>, source: &str) -> Result<Option<String>> {
    let Some(receiver) = node.child_by_field_name("receiver") else {
        return Ok(None);
    };
    Ok(node_text(receiver, source)?
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split_whitespace()
        .last()
        .map(clean_go_receiver))
}

fn clean_go_receiver(receiver: &str) -> String {
    receiver
        .trim_start_matches('*')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn go_calls_in_function(node: Node<'_>, source: &str) -> Result<Vec<String>> {
    let mut calls = BTreeSet::new();
    collect_go_calls(node, source, &mut calls)?;
    Ok(calls.into_iter().collect())
}

fn collect_go_calls(node: Node<'_>, source: &str, calls: &mut BTreeSet<String>) -> Result<()> {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            let text = normalize_call_text(node_text(function, source)?);
            if !text.is_empty() {
                calls.insert(text);
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_calls(child, source, calls)?;
    }
    Ok(())
}

fn normalize_call_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn signature_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    let function_text = node_text(node, source)?;
    let signature_end = function_text.find('{').unwrap_or(function_text.len());
    Ok(&function_text[..signature_end])
}

fn parse_fuzz_params(params: &str) -> Option<Vec<GoParam>> {
    let params = params.trim().trim_start_matches('(').trim_end_matches(')');
    if params.is_empty() {
        return None;
    }

    let mut parsed = Vec::new();
    let mut pending_names = Vec::new();
    let mut unnamed_index = 0usize;

    for part in params.split(',') {
        let pieces = part.split_whitespace().collect::<Vec<_>>();
        match pieces.as_slice() {
            [type_name] if is_go_fuzz_type(type_name) => {
                parsed.push(GoParam {
                    name: format!("input{unnamed_index}"),
                    type_name: (*type_name).to_string(),
                });
                unnamed_index += 1;
            }
            [name] => {
                pending_names.push((*name).to_string());
            }
            [name, type_name] if is_go_fuzz_type(type_name) => {
                for pending in pending_names.drain(..) {
                    parsed.push(GoParam {
                        name: pending,
                        type_name: (*type_name).to_string(),
                    });
                }
                parsed.push(GoParam {
                    name: (*name).to_string(),
                    type_name: (*type_name).to_string(),
                });
            }
            _ => return None,
        }
    }

    if !pending_names.is_empty() || parsed.is_empty() || parsed.len() > 4 {
        return None;
    }
    Some(parsed)
}

fn is_go_fuzz_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "string"
            | "[]byte"
            | "bool"
            | "byte"
            | "rune"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "float32"
            | "float64"
    )
}

fn render_fuzz_file(functions: &[GoFunction]) -> String {
    let package_name = functions
        .first()
        .map(|function| function.package_name.as_str())
        .unwrap_or("main");
    let mut out = String::new();
    out.push_str("// Generated by veritas. Review before committing.\n");
    out.push_str(&format!("package {package_name}\n\n"));
    out.push_str("import \"testing\"\n\n");
    for function in functions {
        let fuzz_name = format!("Fuzz{}", function.name);
        let params = function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| format!("{} {}", fuzz_param_name(param, index), param.type_name))
            .collect::<Vec<_>>()
            .join(", ");
        let args = function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| fuzz_param_name(param, index))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("func {fuzz_name}(f *testing.F) {{\n"));
        for seeds in fuzz_seed_rows(&function.params) {
            out.push_str(&format!("\tf.Add({seeds})\n"));
        }
        out.push_str(&format!("\tf.Fuzz(func(t *testing.T, {params}) {{\n"));
        out.push_str("\t\tdefer func() {\n");
        out.push_str("\t\t\tif r := recover(); r != nil {\n");
        out.push_str("\t\t\t\tt.Fatalf(\"panic: %v\", r)\n");
        out.push_str("\t\t\t}\n");
        out.push_str("\t\t}()\n");
        out.push_str(&format!("\t\t{}({args})\n", function.name));
        out.push_str("\t})\n");
        out.push_str("}\n\n");
    }
    out
}

fn handwritten_fuzz_exists(
    context: &GoVerificationContext,
    package: &Utf8PathBuf,
    function: &GoFunction,
) -> bool {
    let fuzz_name = format!("Fuzz{}", function.name);
    context
        .fuzz_targets
        .handwritten
        .get(package)
        .is_some_and(|names| names.iter().any(|name| name == &fuzz_name))
}

fn fuzz_param_name(param: &GoParam, index: usize) -> String {
    let candidate = safe_ident(&param.name);
    if candidate == "input" {
        format!("input{index}")
    } else {
        candidate
    }
}

fn fuzz_seed(type_name: &str) -> &'static str {
    match type_name {
        "string" => "\"veritas-seed\"",
        "[]byte" => "[]byte(\"veritas-seed\")",
        "bool" => "true",
        "byte" => "byte(1)",
        "rune" => "rune('v')",
        "float32" => "float32(1.25)",
        "float64" => "float64(1.25)",
        "uint" => "uint(1)",
        "uint8" => "uint8(1)",
        "uint16" => "uint16(1)",
        "uint32" => "uint32(1)",
        "uint64" => "uint64(1)",
        "int8" => "int8(1)",
        "int16" => "int16(1)",
        "int32" => "int32(1)",
        "int64" => "int64(1)",
        _ => "1",
    }
}

fn fuzz_seed_rows(params: &[GoParam]) -> Vec<String> {
    if params.is_empty() {
        return Vec::new();
    }
    let per_param = params
        .iter()
        .map(|param| fuzz_seed_values(&param.type_name))
        .collect::<Vec<_>>();
    let rows = per_param.iter().map(Vec::len).max().unwrap_or(1).min(4);
    (0..rows)
        .map(|row| {
            per_param
                .iter()
                .map(|seeds| seeds.get(row).copied().unwrap_or(seeds[0]))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect()
}

fn fuzz_seed_values(type_name: &str) -> Vec<&'static str> {
    match type_name {
        "string" => vec!["\"veritas-seed\"", "\"\"", "\" 0 \"", "\"not-a-number\""],
        "[]byte" => vec![
            "[]byte(\"veritas-seed\")",
            "[]byte(\"\")",
            "[]byte(\" 0 \")",
            "[]byte(\"not-a-number\")",
        ],
        "bool" => vec!["true", "false"],
        "byte" => vec!["byte(1)", "byte(0)", "byte(255)"],
        "rune" => vec!["rune('v')", "rune(0)", "rune('0')"],
        "float32" => vec!["float32(1.25)", "float32(0)", "float32(-1.25)"],
        "float64" => vec!["float64(1.25)", "float64(0)", "float64(-1.25)"],
        "uint" => vec!["uint(1)", "uint(0)"],
        "uint8" => vec!["uint8(1)", "uint8(0)", "uint8(255)"],
        "uint16" => vec!["uint16(1)", "uint16(0)"],
        "uint32" => vec!["uint32(1)", "uint32(0)"],
        "uint64" => vec!["uint64(1)", "uint64(0)"],
        "int" => vec!["1", "0", "-1"],
        "int8" => vec!["int8(1)", "int8(0)", "int8(-1)"],
        "int16" => vec!["int16(1)", "int16(0)", "int16(-1)"],
        "int32" => vec!["int32(1)", "int32(0)", "int32(-1)"],
        "int64" => vec!["int64(1)", "int64(0)", "int64(-1)"],
        _ => vec![fuzz_seed(type_name)],
    }
}

#[derive(Debug, Clone)]
struct FuzzJob {
    cwd: Utf8PathBuf,
    args: Vec<String>,
    timeout_seconds: u64,
}

fn run_fuzz_targets(
    root: &Path,
    context: &GoVerificationContext,
    config: &GoPluginConfig,
    artifacts: &[GeneratedArtifact],
) -> Result<Vec<CommandRecord>> {
    let mut jobs = Vec::new();
    for (package, fuzz_names) in relevant_fuzz_targets(context, artifacts, config) {
        let module = owning_module(&context.modules, &package);
        let package_arg = module_relative_package_arg(&module.root, &package);
        for fuzz_name in fuzz_names {
            let fuzz_seconds = format!("{}s", config.fuzz_seconds);
            let fuzz_pattern = format!("^{fuzz_name}$");
            let mut args = vec!["test".to_string()];
            if let Some(tags) = go_tags_arg(config) {
                args.push(tags);
            }
            args.extend([
                "-run=^$".to_string(),
                format!("-fuzz={fuzz_pattern}"),
                format!("-fuzztime={fuzz_seconds}"),
                package_arg.clone(),
            ]);
            jobs.push(FuzzJob {
                cwd: utf8_path(&root.join(&module.root))?,
                args,
                timeout_seconds: config.command_timeout_seconds,
            });
        }
    }

    let (results, _summary) = run_parallel_jobs(jobs, config.fuzz_concurrency, |job| {
        run_command(job.cwd.as_std_path(), "go", job.args, job.timeout_seconds)
    });
    results.into_iter().collect()
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
    context: &GoVerificationContext,
    config: &GoPluginConfig,
    package_args: &[String],
    run_start: Instant,
    plan: &VerificationPlan,
) -> Result<TestRunResult> {
    let start = Instant::now();
    let candidates = go_mutation_candidates(&context.functions, root, artifacts)?;
    let generated = candidates.len();
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut status = RunStatus::Passed;
    let mut quality = VerificationQuality::default();
    quality.mutation.generated = generated;

    for candidate in candidates.into_iter().take(config.max_mutants) {
        let domain = mutation_domain_from_label(&candidate.label);
        let operator = mutation_operator_from_label(&candidate.label);
        record_mutation_generated(&mut quality.mutation.by_domain, &domain);
        record_mutation_generated(&mut quality.mutation.by_operator, &operator);
        if budget_nearly_spent(run_start, plan.budget_seconds) {
            commands.push(skipped_command(
                root,
                "go mutation checks",
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
                "failed to write Go mutation {} in {}",
                candidate.label,
                path.display()
            )
        })?;

        let mut mutation_commands = Vec::new();
        for (module_root, module_package_args) in
            module_package_args(&context.modules, package_args)
        {
            let test_args = go_test_args(config, &module_package_args);
            mutation_commands.push(run_command(
                &root.join(&module_root),
                "go",
                test_args,
                config.command_timeout_seconds,
            ));
        }
        fs::write(&path, original)
            .with_context(|| format!("failed to restore {}", path.display()))?;
        let mut mutant_survived = true;
        let mut representative_command = None;
        for command in mutation_commands {
            let command = command?;
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
                "go mutation checks",
                "no package commands were selected for mutant",
            )?);
            status = RunStatus::Failed;
            failures.push(Failure {
                id: None,
                message: format!(
                    "mutation survived in Go function `{}`: {}",
                    candidate.function, candidate.label
                ),
                severity: FailureSeverity::Warning,
                target_id: Some(format!("go:{}:{}", candidate.path, candidate.function)),
                artifact_id: artifacts
                    .iter()
                    .find(|artifact| artifact.kind == ArtifactKind::MutationCheck)
                    .map(|artifact| artifact.id.clone()),
                command: command_line(&command.program, &command.args),
                stdout_excerpt: mutation_stdout_excerpt(&command.stdout, &candidate),
                stderr_excerpt: excerpt(&command.stderr),
                repro: Some(ReproCase {
                    command: format!(
                        "replace `{}` with `{}` in {} and run go test {}",
                        candidate.from,
                        candidate.to,
                        candidate.path,
                        package_args.join(" ")
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
        language: "go".to_string(),
        status,
        commands,
        failures,
        duration_ms: start.elapsed().as_millis(),
        quality,
    })
}

fn go_mutation_candidates(
    functions: &[GoFunction],
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
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Go grammar: {error}"))?;
    let mut functions_by_path: BTreeMap<Utf8PathBuf, Vec<&GoFunction>> = BTreeMap::new();

    for function in functions {
        if !mutation_targets
            .iter()
            .any(|target_id| go_target_matches_function(target_id, function))
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
            .ok_or_else(|| anyhow!("failed to parse Go source {}", path))?;
        for function in path_functions {
            collect_go_mutation_nodes(tree.root_node(), &contents, function, &mut candidates)?;
        }
    }

    Ok(candidates)
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
        "bitwise",
        "assignment",
        "increment",
        "loop",
        "literal",
        "negation",
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

fn collect_go_mutation_nodes(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
    candidates: &mut Vec<MutationCandidate>,
) -> Result<()> {
    if node.end_byte() <= function.start_byte || node.start_byte() >= function.end_byte {
        return Ok(());
    }

    if node.start_byte() >= function.start_byte && node.end_byte() <= function.end_byte {
        match node.kind() {
            "binary_expression" => {
                if let Some(candidate) = mutation_candidate_from_binary(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            "return_statement" => {
                if let Some(candidate) = mutation_candidate_from_return(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            "inc_statement" | "dec_statement" => {
                if let Some(candidate) = mutation_candidate_from_update(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            "assignment_statement" => {
                if let Some(candidate) = mutation_candidate_from_assignment(node, source, function)?
                {
                    candidates.push(candidate);
                }
                if let Some(candidate) =
                    mutation_candidate_from_self_assignment(node, source, function)?
                {
                    candidates.push(candidate);
                }
            }
            "unary_expression" => {
                if let Some(candidate) = mutation_candidate_from_unary(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            "break_statement" | "continue_statement" => {
                if let Some(candidate) = mutation_candidate_from_branch(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            "true" | "false" | "int_literal" => {
                if let Some(candidate) = mutation_candidate_from_literal(node, source, function)? {
                    candidates.push(candidate);
                }
            }
            _ => {}
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_mutation_nodes(child, source, function, candidates)?;
    }
    Ok(())
}

fn mutation_candidate_from_binary(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let Some(operator) = binary_operator_node(node) else {
        return Ok(None);
    };
    let op = operator.kind();
    let Some(to) = binary_operator_replacement(op) else {
        return Ok(None);
    };
    let left = node
        .child_by_field_name("left")
        .map(|node| node_text(node, source).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let right = node
        .child_by_field_name("right")
        .map(|node| node_text(node, source).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let base_label = if is_err_nil_comparison(&left, &right) {
        "error/nil branch inversion"
    } else if matches!(op, "==" | "!=") {
        "equality inversion"
    } else if matches!(op, "&&" | "||") {
        "boolean connector inversion"
    } else if matches!(op, "+" | "-") {
        "arithmetic direction mutation"
    } else if matches!(op, "*" | "/" | "%") {
        "arithmetic operator mutation"
    } else if matches!(op, "&" | "|" | "^" | "&^" | "<<" | ">>") {
        "bitwise operator mutation"
    } else {
        "comparison boundary mutation"
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, base_label),
        from: op.to_string(),
        to: to.to_string(),
        start_byte: operator.start_byte(),
        end_byte: operator.end_byte(),
    }))
}

fn mutation_candidate_from_return(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let statement = node_text(node, source)?;
    let Some(expression) = statement.trim().strip_prefix("return") else {
        return Ok(None);
    };
    let expression = expression.trim();
    let Some((label, to)) = return_replacement(expression) else {
        return Ok(None);
    };
    let Some(offset) = statement.find(expression) else {
        return Ok(None);
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, label),
        from: expression.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte() + offset,
        end_byte: node.start_byte() + offset + expression.len(),
    }))
}

fn mutation_candidate_from_update(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let statement = node_text(node, source)?;
    let Some((from, to, offset)) = statement
        .find("++")
        .map(|offset| ("++", "--", offset))
        .or_else(|| statement.find("--").map(|offset| ("--", "++", offset)))
    else {
        return Ok(None);
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, "increment decrement mutation"),
        from: from.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte() + offset,
        end_byte: node.start_byte() + offset + from.len(),
    }))
}

fn mutation_candidate_from_assignment(
    node: Node<'_>,
    _source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let Some(operator) = assignment_operator_node(node) else {
        return Ok(None);
    };
    let op = operator.kind();
    let Some(to) = assignment_operator_replacement(op) else {
        return Ok(None);
    };
    let base_label = if matches!(op, "&=" | "|=" | "^=" | "&^=" | "<<=" | ">>=") {
        "bitwise assignment mutation"
    } else {
        "arithmetic assignment mutation"
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, base_label),
        from: op.to_string(),
        to: to.to_string(),
        start_byte: operator.start_byte(),
        end_byte: operator.end_byte(),
    }))
}

fn mutation_candidate_from_self_assignment(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let Some(operator) = assignment_operator_node(node) else {
        return Ok(None);
    };
    if operator.kind() != "=" {
        return Ok(None);
    }
    let Some(left) = node.child_by_field_name("left") else {
        return Ok(None);
    };
    let Some(right) = node.child_by_field_name("right") else {
        return Ok(None);
    };
    let left_text = node_text(left, source)?.trim();
    let right_text = node_text(right, source)?.trim();
    if left_text.is_empty() || left_text != right_text {
        return Ok(None);
    }
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, "remove self-assignment mutation"),
        from: node_text(node, source)?.to_string(),
        to: String::new(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn mutation_candidate_from_unary(
    node: Node<'_>,
    _source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let Some(operator) = unary_operator_node(node) else {
        return Ok(None);
    };
    let op = operator.kind();
    let base_label = match op {
        "!" => "boolean negation removal",
        "-" => "invert negative mutation",
        "^" => "bitwise negation removal",
        _ => return Ok(None),
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, base_label),
        from: op.to_string(),
        to: String::new(),
        start_byte: operator.start_byte(),
        end_byte: operator.end_byte(),
    }))
}

fn mutation_candidate_from_branch(
    node: Node<'_>,
    _source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let (from, to) = match node.kind() {
        "break_statement" => ("break", "continue"),
        "continue_statement" => ("continue", "break"),
        _ => return Ok(None),
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, "loop control mutation"),
        from: from.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn mutation_candidate_from_literal(
    node: Node<'_>,
    source: &str,
    function: &GoFunction,
) -> Result<Option<MutationCandidate>> {
    let text = node_text(node, source)?.trim();
    let to = match text {
        "true" => "false",
        "false" => "true",
        "0" => "1",
        "1" => "0",
        _ => return Ok(None),
    };
    Ok(Some(MutationCandidate {
        path: function.path.clone(),
        function: function.symbol.clone(),
        label: domain_mutation_label(function, "literal value mutation"),
        from: text.to_string(),
        to: to.to_string(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }))
}

fn binary_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let operator = node.children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "==" | "!="
                | ">="
                | "<="
                | ">"
                | "<"
                | "&&"
                | "||"
                | "+"
                | "-"
                | "*"
                | "/"
                | "%"
                | "&"
                | "|"
                | "^"
                | "&^"
                | "<<"
                | ">>"
        )
    });
    operator
}

fn binary_operator_replacement(operator: &str) -> Option<&'static str> {
    match operator {
        "==" => Some("!="),
        "!=" => Some("=="),
        ">=" => Some(">"),
        "<=" => Some("<"),
        ">" => Some(">="),
        "<" => Some("<="),
        "&&" => Some("||"),
        "||" => Some("&&"),
        "+" => Some("-"),
        "-" => Some("+"),
        "*" => Some("/"),
        "/" => Some("*"),
        "%" => Some("*"),
        "&" => Some("|"),
        "|" => Some("&"),
        "^" => Some("&"),
        "&^" => Some("|"),
        "<<" => Some(">>"),
        ">>" => Some("<<"),
        _ => None,
    }
}

fn assignment_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let operator = node.children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "&^=" | "<<=" | ">>="
        )
    });
    operator
}

fn assignment_operator_replacement(operator: &str) -> Option<&'static str> {
    match operator {
        "+=" => Some("-="),
        "-=" => Some("+="),
        "*=" => Some("/="),
        "/=" => Some("*="),
        "%=" => Some("*="),
        "&=" => Some("|="),
        "|=" => Some("&="),
        "^=" => Some("&="),
        "&^=" => Some("|="),
        "<<=" => Some(">>="),
        ">>=" => Some("<<="),
        _ => None,
    }
}

fn unary_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let operator = node
        .children(&mut cursor)
        .find(|child| matches!(child.kind(), "!" | "-" | "^"));
    operator
}

fn is_err_nil_comparison(left: &str, right: &str) -> bool {
    matches!((left, right), ("err", "nil") | ("nil", "err"))
        || left.ends_with("Err") && right == "nil"
        || right.ends_with("Err") && left == "nil"
}

fn return_replacement(expression: &str) -> Option<(&'static str, &'static str)> {
    match expression {
        "true" => Some(("boolean default flip", "false")),
        "false" => Some(("boolean default flip", "true")),
        "err" => Some(("error suppression", "nil")),
        "0" => Some(("zero-value perturbation", "1")),
        "1" => Some(("one-value perturbation", "0")),
        "\"\"" => Some(("string-default perturbation", "\"veritas-mutant\"")),
        "\"anonymous\"" => Some(("string-default perturbation", "\"\"")),
        _ if is_simple_string_literal(expression) => Some(("string-default perturbation", "\"\"")),
        _ => None,
    }
}

fn is_simple_string_literal(expression: &str) -> bool {
    expression.starts_with('"') && expression.ends_with('"') && !expression[1..].contains('"')
}

fn domain_mutation_label(function: &GoFunction, base: &str) -> String {
    let lowered = function.symbol.to_ascii_lowercase();
    let domain = if lowered.contains("auth")
        || lowered.contains("permission")
        || lowered.contains("token")
    {
        Some("auth/permission")
    } else if lowered.contains("money")
        || lowered.contains("price")
        || lowered.contains("invoice")
        || lowered.contains("total")
    {
        Some("money")
    } else if lowered.contains("parse")
        || lowered.contains("format")
        || lowered.contains("normalize")
    {
        Some("parsing/normalization")
    } else if lowered.contains("marshal")
        || lowered.contains("unmarshal")
        || lowered.contains("serial")
        || lowered.contains("json")
    {
        Some("serialization")
    } else if lowered.contains("error")
        || lowered.contains("err")
        || lowered.contains("result")
        || lowered.contains("valid")
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

fn mutation_stdout_excerpt(stdout: &str, candidate: &MutationCandidate) -> String {
    let mut out = excerpt(stdout);
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "Suggested assertion: cover `{}` so replacing `{}` with `{}` fails.",
        candidate.function, candidate.from, candidate.to
    ));
    out
}

fn go_target_matches_function(target_id: &str, function: &GoFunction) -> bool {
    if target_id == "go:project" {
        return true;
    }
    let Some(rest) = target_id.strip_prefix("go:") else {
        return false;
    };
    if rest == function.path.as_str() || rest == package_dir(&function.path).as_str() {
        return true;
    }
    if let Some((path, symbol)) = rest.rsplit_once(':') {
        return path == function.path.as_str() && symbol == function.symbol;
    }
    false
}

fn go_command_failure(command: &CommandRecord, artifacts: &[GeneratedArtifact]) -> Failure {
    let fuzz_name = command
        .args
        .iter()
        .find_map(|arg| arg.strip_prefix("-fuzz=^"))
        .and_then(|rest| rest.strip_suffix('$'))
        .map(ToString::to_string);
    let (message, severity) = if let Some(fuzz_name) = fuzz_name {
        (
            format!("go fuzz target `{fuzz_name}` failed"),
            FailureSeverity::Critical,
        )
    } else if command.stderr.contains("timed out after") {
        ("go command timed out".to_string(), FailureSeverity::Error)
    } else {
        ("go test failed".to_string(), FailureSeverity::Error)
    };
    let combined_output = format!("{}\n{}", command.stdout, command.stderr);
    let repro_path = parse_go_fuzz_repro_path(&combined_output);
    Failure {
        id: None,
        message,
        severity,
        target_id: artifacts.first().map(|artifact| artifact.target_id.clone()),
        artifact_id: artifacts.first().map(|artifact| artifact.id.clone()),
        command: command_line(&command.program, &command.args),
        stdout_excerpt: excerpt(&command.stdout),
        stderr_excerpt: excerpt(&command.stderr),
        repro: Some(ReproCase {
            command: command_line(&command.program, &command.args),
            input: repro_path
                .as_ref()
                .map(|path| format!("promote corpus entry `{path}` into a regression test")),
            path: repro_path,
        }),
    }
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

fn parse_go_fuzz_repro_path(output: &str) -> Option<Utf8PathBuf> {
    output.lines().find_map(|line| {
        let start = line.find("testdata/fuzz/")?;
        let candidate = line[start..]
            .split(|ch: char| ch.is_whitespace() || ch == '\'' || ch == '"' || ch == '`')
            .next()?
            .trim_matches(|ch| ch == ':' || ch == ',' || ch == '.');
        if candidate.is_empty() {
            None
        } else {
            Some(Utf8PathBuf::from(candidate))
        }
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
                args: args.iter().map(|arg| arg.to_string()).collect(),
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
            stderr.push_str(&format!(
                "command timed out after {}s: {}",
                timeout.as_secs(),
                command_line(program, &args)
            ));
            return Ok(CommandRecord {
                program: program.to_string(),
                args: args.iter().map(|arg| arg.to_string()).collect(),
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

fn go_coverage_summary(stdout: &str) -> String {
    stdout
        .lines()
        .rev()
        .find(|line| line.contains("coverage:"))
        .map(str::trim)
        .unwrap_or("coverage collected")
        .to_string()
}

fn parse_go_coverprofile(root: &Path, path: &Path) -> Result<Vec<CoverageFile>> {
    let contents = fs::read_to_string(path).unwrap_or_default();
    let mut files: BTreeMap<Utf8PathBuf, Vec<String>> = BTreeMap::new();
    for line in contents.lines().skip(1) {
        let Some((location, rest)) = line.split_once(' ') else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _statements = fields.next();
        let Some(count) = fields.next() else {
            continue;
        };
        if count != "0" {
            continue;
        }
        let Some((file, range)) = location.split_once(':') else {
            continue;
        };
        let file_path = normalize_go_cover_path(root, file);
        files.entry(file_path).or_default().push(range.to_string());
    }

    Ok(files
        .into_iter()
        .map(|(path, uncovered_ranges)| CoverageFile {
            path,
            line_coverage_percent: None,
            uncovered_ranges,
        })
        .collect())
}

fn normalize_go_cover_path(root: &Path, file: &str) -> Utf8PathBuf {
    let path = Path::new(file);
    if let Ok(relative) = path.strip_prefix(root) {
        Utf8PathBuf::from_path_buf(relative.to_path_buf())
            .unwrap_or_else(|_| Utf8PathBuf::from(file))
    } else {
        Utf8PathBuf::from(file)
    }
}

fn relevant_fuzz_targets(
    context: &GoVerificationContext,
    artifacts: &[GeneratedArtifact],
    config: &GoPluginConfig,
) -> BTreeMap<Utf8PathBuf, Vec<String>> {
    let mut targets = fuzz_targets(artifacts);
    if config.fuzz_existing && !artifacts.is_empty() {
        let selected_dirs = package_dirs_from_artifacts(artifacts);
        for (package, fuzz_names) in &context.fuzz_targets.handwritten {
            if selected_dirs.contains(package) {
                targets
                    .entry(package.clone())
                    .or_default()
                    .extend(fuzz_names.clone());
            }
        }
    }

    for fuzz_names in targets.values_mut() {
        fuzz_names.sort();
        fuzz_names.dedup();
        fuzz_names.truncate(config.max_fuzz_targets);
    }
    targets.retain(|_, fuzz_names| !fuzz_names.is_empty());
    targets
}

fn fuzz_targets(artifacts: &[GeneratedArtifact]) -> BTreeMap<Utf8PathBuf, Vec<String>> {
    let mut targets = BTreeMap::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::FuzzHarness)
    {
        let package = artifact
            .path
            .parent()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| Utf8PathBuf::from("."));
        let fuzz_names = artifact
            .contents
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("func Fuzz"))
            .filter_map(|rest| rest.split_once('(').map(|(name, _)| format!("Fuzz{name}")))
            .collect::<Vec<_>>();
        targets.insert(
            if package.as_str().is_empty() {
                Utf8PathBuf::from(".")
            } else {
                package
            },
            if fuzz_names.is_empty() {
                vec!["Fuzz".to_string()]
            } else {
                fuzz_names
            },
        );
    }
    targets
}

fn discover_existing_fuzz_targets(root: &Path) -> Result<GoFuzzTargets> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|error| anyhow!("failed to load tree-sitter Go grammar: {error}"))?;

    let mut targets = GoFuzzTargets::default();
    for entry in WalkDir::new(root).into_iter().filter_entry(|entry| {
        entry.depth() == 0
            || (!is_ignored(entry.path(), entry.file_name())
                && !is_nested_go_module_root(entry.path(), entry.depth()))
    }) {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension() != Some(OsStr::new("go"))
            || !entry
                .path()
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.ends_with("_test.go"))
        {
            continue;
        }

        let path = relative_utf8(root, entry.path())?;
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        let generated = is_generated_fuzz_file(&path, &contents);
        let tree = parser
            .parse(&contents, None)
            .ok_or_else(|| anyhow!("failed to parse Go source {}", entry.path().display()))?;
        let mut fuzz_names = Vec::new();
        collect_existing_fuzz_names(tree.root_node(), &contents, &mut fuzz_names)?;
        if !fuzz_names.is_empty() {
            let bucket = if generated {
                &mut targets.generated
            } else {
                &mut targets.handwritten
            };
            bucket
                .entry(package_dir(&path))
                .or_default()
                .extend(fuzz_names);
        }
    }
    Ok(targets)
}

fn is_generated_fuzz_file(path: &Utf8PathBuf, contents: &str) -> bool {
    path.file_name() == Some("veritas_fuzz_test.go")
        || contents
            .lines()
            .take(3)
            .any(|line| line.contains("Generated by veritas"))
}

fn collect_existing_fuzz_names(
    node: Node<'_>,
    source: &str,
    fuzz_names: &mut Vec<String>,
) -> Result<()> {
    if node.kind() == "function_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = node_text(name_node, source)?;
            if name.starts_with("Fuzz") && name.len() > "Fuzz".len() {
                fuzz_names.push(name.to_string());
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_existing_fuzz_names(child, source, fuzz_names)?;
    }
    Ok(())
}

fn package_dir(path: &Utf8PathBuf) -> Utf8PathBuf {
    let dir = path
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    if dir.as_str().is_empty() {
        Utf8PathBuf::from(".")
    } else {
        dir
    }
}

fn promoted_go_regression_artifacts(
    root: &Path,
    config: &GoPluginConfig,
    report: &VerificationReport,
    finding: &Failure,
    index: usize,
) -> Result<Vec<GeneratedArtifact>> {
    let context = GoVerificationContext::discover(root, config)?;
    let target = finding
        .target_id
        .as_ref()
        .and_then(|target_id| report.targets.iter().find(|target| &target.id == target_id));
    let function = target.and_then(|target| {
        let symbol = target.symbol.as_deref()?;
        context
            .functions
            .iter()
            .find(|function| function.path == target.path && function.symbol == symbol)
    });
    let package = function
        .map(|function| package_dir(&function.path))
        .or_else(|| target.map(|target| package_dir(&target.path)))
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    let package_name = function
        .map(|function| function.package_name.clone())
        .or_else(|| {
            context
                .packages
                .iter()
                .find(|candidate| candidate.dir == package)
                .map(|candidate| package_name_from_import_path(&candidate.import_path))
        });
    let Some(package_name) = package_name else {
        return Ok(generic_go_regression_promotion(finding, index));
    };
    let file_name = format!("veritas_regression_{index}_test.go");
    let path = if package.as_str() == "." {
        Utf8PathBuf::from(file_name)
    } else {
        package.join(file_name)
    };
    let contents = render_go_regression_scaffold(&package_name, finding, target, function, index);

    Ok(vec![GeneratedArtifact {
        id: format!("go-promoted-regression-{index}"),
        language: "go".to_string(),
        kind: ArtifactKind::RegressionTest,
        target_id: finding
            .target_id
            .clone()
            .unwrap_or_else(|| "go:unknown".to_string()),
        path,
        contents,
        description: "Reviewable Go regression test scaffold promoted from a veritas finding"
            .to_string(),
        status: ArtifactStatus::Planned,
    }])
}

fn generic_go_regression_promotion(finding: &Failure, index: usize) -> Vec<GeneratedArtifact> {
    let mut contents = String::from("# Go Regression Promotion\n\n");
    contents.push_str("Generated by veritas. Review before committing.\n\n");
    contents.push_str(&format!("- Finding: {}\n", finding.message));
    contents.push_str(&format!("- Command: `{}`\n", finding.command));
    contents.push_str("\nThe Go plugin could not resolve the target package for this finding. Add a package-owned `*_test.go` regression manually, then rerun `veritas verify`.\n");
    vec![GeneratedArtifact {
        id: format!("go-promoted-regression-{index}"),
        language: "go".to_string(),
        kind: ArtifactKind::RegressionTest,
        target_id: finding
            .target_id
            .clone()
            .unwrap_or_else(|| "go:unknown".to_string()),
        path: Utf8PathBuf::from(format!(".veritas/regressions/promoted/go_{index}.md")),
        contents,
        description: "Go regression promotion guidance".to_string(),
        status: ArtifactStatus::Planned,
    }]
}

fn render_go_regression_scaffold(
    package_name: &str,
    finding: &Failure,
    target: Option<&VerificationTarget>,
    function: Option<&GoFunction>,
    index: usize,
) -> String {
    let name = function
        .map(|function| safe_ident(&function.symbol))
        .or_else(|| target.and_then(|target| target.symbol.as_deref().map(safe_ident)))
        .unwrap_or_else(|| "Target".to_string());
    let mut out = String::new();
    out.push_str("// Generated by veritas. Review before committing.\n");
    out.push_str("// Replace t.Skip with an assertion that fails for the recorded finding.\n");
    push_go_comment(&mut out, &format!("Finding: {}", finding.message));
    push_go_comment(&mut out, &format!("Command: {}", finding.command));
    if let Some(target_id) = &finding.target_id {
        push_go_comment(&mut out, &format!("Target: {target_id}"));
    }
    if let Some(repro) = &finding.repro {
        push_go_comment(&mut out, &format!("Repro: {}", repro.command));
        if let Some(input) = &repro.input {
            push_go_comment(&mut out, &format!("Input: {}", input.trim()));
        }
    }
    out.push('\n');
    out.push_str(&format!("package {package_name}\n\n"));
    out.push_str("import \"testing\"\n\n");
    out.push_str(&format!(
        "func TestVeritasRegression{index}{name}(t *testing.T) {{\n"
    ));
    if let Some(function) = function {
        if function.receiver.is_none() {
            let args = go_regression_seed_args(function).join(", ");
            out.push_str("\t// Candidate assertion seed synthesized by veritas:\n");
            out.push_str(&format!("\t// actual := {}({args})\n", function.name));
            out.push_str("\t// if actual != /* reviewed expected value */ {\n");
            out.push_str("\t// \tt.Fatalf(\"unexpected result: %v\", actual)\n");
            out.push_str("\t// }\n");
        } else {
            out.push_str("\t// Construct the receiver state, call the method, and assert the reviewed expected value.\n");
        }
    }
    out.push_str(
        "\tt.Skip(\"review and replace the veritas placeholder with a real assertion\")\n",
    );
    out.push_str("}\n");
    out
}

fn go_regression_seed_args(function: &GoFunction) -> Vec<String> {
    function
        .params
        .iter()
        .map(|param| match param.type_name.as_str() {
            "string" => "\"veritas-seed\"".to_string(),
            "[]byte" => "[]byte(\"veritas-seed\")".to_string(),
            "bool" => "true".to_string(),
            "int" | "int8" | "int16" | "int32" | "int64" => "1".to_string(),
            "uint" | "uint8" | "uint16" | "uint32" | "uint64" => "1".to_string(),
            "float32" => "float32(1)".to_string(),
            "float64" => "float64(1)".to_string(),
            _ => format!("{}{{}}", param.type_name),
        })
        .collect()
}

fn push_go_comment(out: &mut String, line: &str) {
    for line in line.lines() {
        out.push_str("// ");
        out.push_str(line.trim());
        out.push('\n');
    }
}

fn package_name_from_import_path(import_path: &str) -> String {
    import_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(safe_ident)
        .unwrap_or_else(|| "main".to_string())
}

fn module_slug(path: &Utf8PathBuf, symbol: Option<&str>) -> String {
    let base = format!("{}_{}", path, symbol.unwrap_or("target"));
    safe_ident(&base)
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
        "serialize",
        "network",
        "refund",
        "discount",
    ];
    if high_risk_terms.iter().any(|term| lowered.contains(term)) {
        RiskLevel::High
    } else {
        RiskLevel::Medium
    }
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

fn is_ignored(path: &Path, name: &OsStr) -> bool {
    if name.to_string_lossy().starts_with('.') {
        return true;
    }
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(
            value.as_ref(),
            "vendor" | "node_modules" | "target" | ".git" | ".veritas"
        )
    })
}

fn is_nested_go_module_root(path: &Path, depth: usize) -> bool {
    depth > 0 && path.is_dir() && path.join("go.mod").exists()
}

fn safe_ident(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "input".to_string()
    } else {
        out
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    source
        .get(node.start_byte()..node.end_byte())
        .ok_or_else(|| anyhow!("tree-sitter node byte range was invalid"))
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
    use std::{
        fs,
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn parses_multiple_supported_fuzz_params() {
        let params =
            parse_fuzz_params("(name string, count int, payload []byte)").expect("params parse");

        assert_eq!(params.len(), 3);
        assert_eq!(params[0].name, "name");
        assert_eq!(params[0].type_name, "string");
        assert_eq!(params[1].name, "count");
        assert_eq!(params[1].type_name, "int");
        assert_eq!(params[2].name, "payload");
        assert_eq!(params[2].type_name, "[]byte");
    }

    #[test]
    fn parses_grouped_go_param_names() {
        let params = parse_fuzz_params("(left, right string)").expect("params parse");

        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "left");
        assert_eq!(params[0].type_name, "string");
        assert_eq!(params[1].name, "right");
        assert_eq!(params[1].type_name, "string");
    }

    #[test]
    fn renders_multi_arg_go_fuzz_harness() {
        let function = GoFunction {
            package_name: "invoice".to_string(),
            path: Utf8PathBuf::from("pkg/invoice/invoice.go"),
            name: "ParseTotal".to_string(),
            symbol: "ParseTotal".to_string(),
            receiver: None,
            params: vec![
                GoParam {
                    name: "input".to_string(),
                    type_name: "string".to_string(),
                },
                GoParam {
                    name: "round".to_string(),
                    type_name: "bool".to_string(),
                },
            ],
            signature: "func ParseTotal(input string, round bool)".to_string(),
            line_range: LineRange { start: 1, end: 3 },
            start_byte: 0,
            end_byte: 10,
            calls: vec![],
        };

        let rendered = render_fuzz_file(&[function]);

        assert!(rendered.contains("package invoice"));
        assert!(rendered.contains("f.Add(\"veritas-seed\", true)"));
        assert!(rendered.contains("f.Add(\"\", false)"));
        assert!(rendered.contains("f.Add(\" 0 \", true)"));
        assert!(rendered.contains("func(t *testing.T, input0 string, round bool)"));
        assert!(rendered.contains("ParseTotal(input0, round)"));
    }

    #[test]
    fn handwritten_fuzz_targets_suppress_duplicate_generated_harnesses() {
        let function = GoFunction {
            package_name: "invoice".to_string(),
            path: Utf8PathBuf::from("pkg/invoice/invoice.go"),
            name: "ParseTotal".to_string(),
            symbol: "ParseTotal".to_string(),
            receiver: None,
            params: vec![GoParam {
                name: "input".to_string(),
                type_name: "string".to_string(),
            }],
            signature: "func ParseTotal(input string)".to_string(),
            line_range: LineRange { start: 1, end: 3 },
            start_byte: 0,
            end_byte: 10,
            calls: vec![],
        };
        let mut context = GoVerificationContext::default();
        context.fuzz_targets.handwritten.insert(
            Utf8PathBuf::from("pkg/invoice"),
            vec!["FuzzParseTotal".to_string()],
        );

        assert!(handwritten_fuzz_exists(
            &context,
            &Utf8PathBuf::from("pkg/invoice"),
            &function
        ));
    }

    #[test]
    fn scoped_package_args_include_direct_reverse_dependencies() {
        let packages = vec![
            test_package("example.com/app/pkg/a", "pkg/a", &[], &[], &[]),
            test_package(
                "example.com/app/pkg/b",
                "pkg/b",
                &["example.com/app/pkg/a"],
                &[],
                &[],
            ),
            test_package("example.com/app/pkg/c", "pkg/c", &[], &[], &[]),
        ];
        let selected = BTreeSet::from([Utf8PathBuf::from("pkg/a")]);

        let args = scoped_package_args(&packages, &selected);

        assert_eq!(args, vec!["./pkg/a", "./pkg/b"]);
    }

    #[test]
    fn scoped_package_dirs_respect_transitive_depth_and_test_imports() {
        let packages = vec![
            test_package("example.com/app/pkg/a", "pkg/a", &[], &[], &[]),
            test_package(
                "example.com/app/pkg/b",
                "pkg/b",
                &["example.com/app/pkg/a"],
                &[],
                &[],
            ),
            test_package(
                "example.com/app/pkg/c",
                "pkg/c",
                &["example.com/app/pkg/b"],
                &[],
                &[],
            ),
            test_package(
                "example.com/app/pkg/d",
                "pkg/d",
                &[],
                &[],
                &["example.com/app/pkg/a"],
            ),
        ];
        let selected = BTreeSet::from([Utf8PathBuf::from("pkg/a")]);

        let depth_one = scoped_package_dirs(&packages, &selected, 1, usize::MAX);
        let depth_two = scoped_package_dirs(&packages, &selected, 2, usize::MAX);

        assert_eq!(
            depth_one,
            BTreeSet::from([
                Utf8PathBuf::from("pkg/a"),
                Utf8PathBuf::from("pkg/b"),
                Utf8PathBuf::from("pkg/d")
            ])
        );
        assert!(depth_two.contains(&Utf8PathBuf::from("pkg/c")));
    }

    #[test]
    fn scoped_package_dirs_enforce_package_limit_without_dropping_selected_first() {
        let packages = vec![
            test_package("example.com/app/pkg/a", "pkg/a", &[], &[], &[]),
            test_package(
                "example.com/app/pkg/b",
                "pkg/b",
                &["example.com/app/pkg/a"],
                &[],
                &[],
            ),
            test_package(
                "example.com/app/pkg/c",
                "pkg/c",
                &["example.com/app/pkg/a"],
                &[],
                &[],
            ),
        ];
        let selected = BTreeSet::from([Utf8PathBuf::from("pkg/a")]);

        let dirs = scoped_package_dirs(&packages, &selected, 1, 2);

        assert!(dirs.contains(&Utf8PathBuf::from("pkg/a")));
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn existing_fuzz_targets_are_limited_to_selected_artifact_packages() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "pkg/invoice/invoice_test.go",
            "package invoice\n\nimport \"testing\"\n\nfunc FuzzParseTotal(f *testing.F) {}\n",
        );
        write_file(
            root.path(),
            "pkg/other/other_test.go",
            "package other\n\nimport \"testing\"\n\nfunc FuzzOther(f *testing.F) {}\n",
        );
        let artifact = GeneratedArtifact {
            id: "go-mutation-pkg-invoice".to_string(),
            language: "go".to_string(),
            kind: ArtifactKind::MutationCheck,
            target_id: "go:pkg/invoice".to_string(),
            path: Utf8PathBuf::from(".veritas/mutations/go_pkg_invoice.txt"),
            contents: String::new(),
            description: String::new(),
            status: ArtifactStatus::Planned,
        };

        let context = GoVerificationContext {
            modules: vec![],
            packages: vec![],
            functions: vec![],
            fuzz_targets: discover_existing_fuzz_targets(root.path())
                .expect("fuzz discovery succeeds"),
        };
        let targets = relevant_fuzz_targets(&context, &[artifact], &test_go_config());

        assert_eq!(
            targets.get(&Utf8PathBuf::from("pkg/invoice")),
            Some(&vec!["FuzzParseTotal".to_string()])
        );
        assert!(!targets.contains_key(&Utf8PathBuf::from("pkg/other")));
    }

    #[test]
    fn existing_fuzz_targets_are_capped_per_package() {
        let artifact = GeneratedArtifact {
            id: "go-mutation-pkg-invoice".to_string(),
            language: "go".to_string(),
            kind: ArtifactKind::MutationCheck,
            target_id: "go:pkg/invoice".to_string(),
            path: Utf8PathBuf::from(".veritas/mutations/go_pkg_invoice.txt"),
            contents: String::new(),
            description: String::new(),
            status: ArtifactStatus::Planned,
        };
        let mut context = GoVerificationContext::default();
        context.fuzz_targets.handwritten.insert(
            Utf8PathBuf::from("pkg/invoice"),
            vec!["FuzzB".to_string(), "FuzzA".to_string()],
        );
        let mut config = test_go_config();
        config.max_fuzz_targets = 1;

        let targets = relevant_fuzz_targets(&context, &[artifact], &config);

        assert_eq!(
            targets.get(&Utf8PathBuf::from("pkg/invoice")),
            Some(&vec!["FuzzA".to_string()])
        );
    }

    #[test]
    fn discovers_generated_and_handwritten_fuzz_targets_separately() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "pkg/invoice/invoice_test.go",
            "package invoice\n\nimport \"testing\"\n\nfunc FuzzHandwritten(f *testing.F) {}\n",
        );
        write_file(
            root.path(),
            "pkg/invoice/veritas_fuzz_test.go",
            "// Generated by veritas. Review before committing.\npackage invoice\n\nimport \"testing\"\n\nfunc FuzzGenerated(f *testing.F) {}\n",
        );

        let targets = discover_existing_fuzz_targets(root.path()).expect("discover fuzz targets");

        assert_eq!(
            targets.handwritten.get(&Utf8PathBuf::from("pkg/invoice")),
            Some(&vec!["FuzzHandwritten".to_string()])
        );
        assert_eq!(
            targets.generated.get(&Utf8PathBuf::from("pkg/invoice")),
            Some(&vec!["FuzzGenerated".to_string()])
        );
    }

    #[test]
    fn package_awareness_artifact_reports_tests_and_fuzz_gaps() {
        let mut context = GoVerificationContext::default();
        let mut package = test_package("example.com/app/pkg/a", "pkg/a", &[], &[], &[]);
        package.test_go_files = vec!["a_test.go".to_string()];
        context.packages.push(package);
        let target = VerificationTarget {
            id: "go:pkg/a".to_string(),
            language: "go".to_string(),
            kind: TargetKind::Package,
            path: Utf8PathBuf::from("pkg/a"),
            symbol: None,
            signature: None,
            line_range: None,
            description: "package".to_string(),
            risk: RiskLevel::Medium,
        };
        let selected = BTreeSet::from([Utf8PathBuf::from("pkg/a")]);

        let artifact = package_awareness_artifact(&context, &test_go_config(), &target, &selected)
            .expect("package awareness artifact");

        assert_eq!(artifact.kind, ArtifactKind::PackageAwareness);
        assert!(artifact.contents.contains("| `pkg/a` |"));
        assert!(artifact.contents.contains("internal"));
        assert!(artifact
            .contents
            .contains("has tests but no handwritten fuzz target"));
    }

    #[test]
    fn discovers_exported_functions_even_when_params_are_not_fuzzable() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "invoice.go",
            "package invoice\n\ntype Request struct{}\n\nfunc ValidateInvoice(input Request) bool { return true }\n",
        );

        let functions = discover_functions(root.path()).expect("discover functions");

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "ValidateInvoice");
        assert!(functions[0].params.is_empty());
    }

    #[test]
    fn discovers_exported_methods_with_receiver_symbols_and_calls() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "invoice.go",
            "package invoice\n\ntype Service struct{}\n\nfunc (s *Service) AuthorizeRefund(amount int) bool {\n\treturn s.limit(amount)\n}\n\nfunc (s *Service) limit(amount int) bool { return true }\n",
        );

        let functions = discover_functions(root.path()).expect("discover functions");

        let method = functions
            .iter()
            .find(|function| function.symbol == "Service.AuthorizeRefund")
            .expect("exported method");
        assert_eq!(method.receiver.as_deref(), Some("Service"));
        assert!(method.calls.contains(&"s.limit".to_string()));
        assert!(!functions
            .iter()
            .any(|function| function.symbol == "Service.limit"));
    }

    #[test]
    fn go_symbol_graph_artifact_reports_methods() {
        let mut context = GoVerificationContext::default();
        context.functions.push(GoFunction {
            package_name: "invoice".to_string(),
            path: Utf8PathBuf::from("invoice.go"),
            name: "AuthorizeRefund".to_string(),
            symbol: "Service.AuthorizeRefund".to_string(),
            receiver: Some("Service".to_string()),
            params: vec![],
            signature: "func (s *Service) AuthorizeRefund(amount int) bool".to_string(),
            line_range: LineRange { start: 3, end: 5 },
            start_byte: 0,
            end_byte: 20,
            calls: vec!["s.limit".to_string()],
        });

        let artifact = symbol_graph_artifact(
            &context,
            "go:invoice.go:Service.AuthorizeRefund",
            &Utf8PathBuf::from("invoice.go"),
            Some("Service.AuthorizeRefund"),
        )
        .expect("symbol graph");

        assert_eq!(artifact.kind, ArtifactKind::SymbolGraph);
        assert!(artifact.contents.contains("Service.AuthorizeRefund"));
        assert!(artifact.contents.contains("s.limit"));
    }

    #[test]
    fn mutation_candidates_come_from_ast_nodes_not_string_literals() {
        let root = TempRoot::new();
        write_file(
            root.path(),
            "invoice.go",
            "package invoice\n\nfunc ParseInvoiceTotal(input string) int {\n\t_ = \"err != nil\"\n\ttotal := len(input)+1\n\ttotal += 2\n\tmask := total & 3\n\tmask ^= 1\n\tnegate := -total\n\tfor i := 0; i < 3; i++ {\n\t\tif i == 2 {\n\t\t\tbreak\n\t\t}\n\t\tcontinue\n\t}\n\tif !(input == \"\") || mask<<1 > 10 {\n\t\treturn 0\n\t}\n\ttotal = total\n\treturn total + negate\n}\n",
        );
        let functions = discover_functions(root.path()).expect("discover functions");
        let artifact = GeneratedArtifact {
            id: "go-mutation-invoice".to_string(),
            language: "go".to_string(),
            kind: ArtifactKind::MutationCheck,
            target_id: "go:invoice.go:ParseInvoiceTotal".to_string(),
            path: Utf8PathBuf::from(".veritas/mutations/go_invoice.txt"),
            contents: String::new(),
            description: String::new(),
            status: ArtifactStatus::Planned,
        };

        let candidates =
            go_mutation_candidates(&functions, root.path(), &[artifact]).expect("mutations");

        assert!(candidates.iter().any(|candidate| candidate.from == "=="));
        assert!(candidates.iter().any(|candidate| candidate.from == "||"));
        assert!(candidates.iter().any(|candidate| candidate.from == "+"));
        assert!(candidates.iter().any(|candidate| candidate.from == ">"));
        assert!(candidates.iter().any(|candidate| candidate.from == "&"));
        assert!(candidates.iter().any(|candidate| candidate.from == "<<"));
        assert!(candidates.iter().any(|candidate| candidate.from == "+="));
        assert!(candidates.iter().any(|candidate| candidate.from == "^="));
        assert!(candidates.iter().any(|candidate| candidate.from == "++"));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.from == "break" && candidate.to == "continue"));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.from == "continue" && candidate.to == "break"));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.label.contains("negation")));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.label.contains("literal")));
        assert!(candidates
            .iter()
            .any(|candidate| candidate.label.contains("self-assignment")));
        assert!(!candidates
            .iter()
            .any(|candidate| candidate.from == "err != nil"));
    }

    #[test]
    fn parses_go_fuzz_corpus_repro_paths() {
        let output = "failing input written to testdata/fuzz/FuzzParse/abc123\n";

        let path = parse_go_fuzz_repro_path(output).expect("parse repro path");

        assert_eq!(path, Utf8PathBuf::from("testdata/fuzz/FuzzParse/abc123"));
    }

    #[test]
    fn go_test_args_include_build_tags_before_packages() {
        let mut config = test_go_config();
        config.build_tags = vec!["integration".to_string(), "sqlite".to_string()];

        let args = go_test_args(&config, &["./pkg/a".to_string()]);

        assert_eq!(args, vec!["test", "-tags=integration,sqlite", "./pkg/a"]);
    }

    #[test]
    fn module_package_args_group_repo_paths_by_owning_module() {
        let modules = vec![
            GoModule {
                module_path: "example.com/root".to_string(),
                root: Utf8PathBuf::from("."),
            },
            GoModule {
                module_path: "example.com/service".to_string(),
                root: Utf8PathBuf::from("services/api"),
            },
        ];

        let grouped = module_package_args(
            &modules,
            &[
                "./pkg/root".to_string(),
                "./services/api/pkg/http".to_string(),
            ],
        );

        assert_eq!(
            grouped.get(&Utf8PathBuf::from(".")),
            Some(&vec!["./pkg/root".to_string()])
        );
        assert_eq!(
            grouped.get(&Utf8PathBuf::from("services/api")),
            Some(&vec!["./pkg/http".to_string()])
        );
    }

    fn test_go_config() -> GoPluginConfig {
        GoPluginConfig {
            fuzz_seconds: 1,
            fuzz_existing: true,
            fuzz_concurrency: 2,
            coverage_enabled: true,
            reverse_dependency_depth: 1,
            max_fuzz_targets: 20,
            command_timeout_seconds: 10,
            max_packages: 64,
            max_mutants: 8,
            build_tags: Vec::new(),
        }
    }

    fn test_package(
        import_path: &str,
        dir: &str,
        imports: &[&str],
        test_imports: &[&str],
        x_test_imports: &[&str],
    ) -> GoPackage {
        GoPackage {
            import_path: import_path.to_string(),
            dir: Utf8PathBuf::from(dir),
            imports: imports.iter().map(|value| (*value).to_string()).collect(),
            test_imports: test_imports
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            x_test_imports: x_test_imports
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            go_files: vec![format!("{}.go", dir.rsplit('/').next().unwrap_or("pkg"))],
            test_go_files: vec![],
            x_test_go_files: vec![],
        }
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
            let path =
                std::env::temp_dir().join(format!("veritas-go-test-{}-{nanos}", process::id()));
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
