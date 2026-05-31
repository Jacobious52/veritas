pub mod config;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use tracing::debug;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, Failure, FailureSeverity, GeneratedArtifact, LanguagePlugin,
    LineRange, ProjectInfo, ReproCase, RunStatus, TargetKind, VerificationPlan,
    VerificationPlanner, VerificationReport, VerificationStrategy, VerificationTarget,
};

use crate::config::{PlannerMode, VeritasConfig};

#[derive(Clone)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn LanguagePlugin>>,
}

pub struct CoreEngine {
    registry: PluginRegistry,
    planner: Arc<dyn VerificationPlanner>,
    config: VeritasConfig,
}

pub struct ScanResult {
    pub projects: Vec<ProjectInfo>,
    pub targets: Vec<VerificationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupSummary {
    pub dry_run: bool,
    pub paths: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionSummary {
    pub dry_run: bool,
    pub paths: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineSummary {
    pub path: Utf8PathBuf,
    pub accepted_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct ChangedFile {
    path: Utf8PathBuf,
    ranges: Vec<LineRange>,
}

pub struct DeterministicPlanner {
    config: VeritasConfig,
    strategies: Vec<VerificationStrategy>,
}

pub struct ExternalLlmPlanner {
    command: String,
    fail_on_error: bool,
    fallback: DeterministicPlanner,
}

struct RunBudget {
    start: Instant,
    total: Duration,
}

impl RunBudget {
    fn new(seconds: u64) -> Self {
        Self {
            start: Instant::now(),
            total: Duration::from_secs(seconds.max(1)),
        }
    }

    fn spent(&self) -> bool {
        self.start.elapsed() >= self.total
    }

    fn nearly_spent(&self) -> bool {
        self.start.elapsed() + Duration::from_secs(5) >= self.total
    }
}

#[derive(Debug, Serialize)]
struct PlannerRequest<'a> {
    project: &'a ProjectInfo,
    target: &'a VerificationTarget,
    default_plan: &'a VerificationPlan,
    constraints: PlannerConstraints,
}

#[derive(Debug, Clone, Serialize)]
struct PlannerConstraints {
    max_budget_seconds: u64,
    allowed_strategies: Vec<VerificationStrategy>,
    run_scope: &'static str,
    safety_notes: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct PlannerResponse {
    plan: Option<VerificationPlan>,
}

impl PluginRegistry {
    pub fn new(plugins: Vec<Arc<dyn LanguagePlugin>>) -> Self {
        Self { plugins }
    }

    pub fn plugins(&self) -> &[Arc<dyn LanguagePlugin>] {
        &self.plugins
    }

    pub fn get(&self, language: &str) -> Result<Arc<dyn LanguagePlugin>> {
        self.plugins
            .iter()
            .find(|plugin| plugin.id() == language)
            .cloned()
            .ok_or_else(|| anyhow!("no plugin registered for language `{language}`"))
    }
}

impl CoreEngine {
    pub fn new(registry: PluginRegistry, config: VeritasConfig) -> Self {
        let deterministic = DeterministicPlanner::new(config.clone());
        let planner: Arc<dyn VerificationPlanner> =
            match (&config.planner.mode, config.planner.command.as_ref()) {
                (PlannerMode::ExternalLlm, Some(command)) => Arc::new(ExternalLlmPlanner {
                    command: command.clone(),
                    fail_on_error: config.planner.fail_on_error,
                    fallback: deterministic,
                }),
                _ => Arc::new(deterministic),
            };
        Self {
            registry,
            planner,
            config,
        }
    }

    pub fn config(&self) -> &VeritasConfig {
        &self.config
    }

    pub fn scan(&self, root: &Path) -> Result<ScanResult> {
        let mut projects = Vec::new();
        let mut targets = Vec::new();

        for plugin in self.registry.plugins() {
            match plugin.detect_project(root) {
                Ok(project) => {
                    debug!(language = plugin.id(), "detected project");
                    let mut plugin_targets = plugin.discover_targets(root)?;
                    projects.push(project);
                    targets.append(&mut plugin_targets);
                }
                Err(error) => {
                    debug!(language = plugin.id(), error = %error, "plugin did not detect project");
                }
            }
        }

        Ok(ScanResult { projects, targets })
    }

    pub fn verify(
        &self,
        root: &Path,
        language: &str,
        target_path: Option<&Path>,
        requested_strategies: Vec<VerificationStrategy>,
    ) -> Result<VerificationReport> {
        let budget = RunBudget::new(self.config.budget_seconds);
        let plugin = self.registry.get(language)?;
        let project = plugin.detect_project(root)?;
        let target = self.resolve_target(root, plugin.as_ref(), language, target_path)?;
        let all_targets = plugin.discover_targets(root)?;
        let report_targets = expand_report_targets(&target, &all_targets);
        let mut plan = self.planner.plan(&project, &target)?;
        if !requested_strategies.is_empty() {
            plan.strategies = requested_strategies;
        }

        let mut artifacts = merge_artifacts(plugin.generate_tests(&target, &plan)?);
        if plan.write_generated_tests {
            write_artifacts(root, &mut artifacts)?;
        }

        let run = if plan.run_existing_tests || plan.run_generated_tests {
            plugin.run_tests(root, &artifacts, &plan)?
        } else {
            skipped_run(language)
        };
        let coverage = if budget.nearly_spent() {
            vec![budget_skipped_coverage(language)]
        } else {
            plugin.collect_coverage(root)?.into_iter().collect()
        };
        let findings = run.failures.clone();

        let mut report = VerificationReport {
            project: Some(project),
            targets: report_targets,
            plan: Some(plan.clone()),
            artifacts,
            runs: vec![run],
            coverage,
            findings,
            suggested_next_steps: suggested_next_steps(language),
        };
        self.add_observation_artifacts(
            root,
            language,
            &mut report,
            plan.write_generated_tests,
            plan.strategies
                .iter()
                .any(|strategy| matches!(strategy, VerificationStrategy::DifferentialTests)),
        )?;
        assign_finding_ids(&mut report);
        Ok(report)
    }

    pub fn verify_changed(
        &self,
        root: &Path,
        language: Option<&str>,
        requested_strategies: Vec<VerificationStrategy>,
    ) -> Result<VerificationReport> {
        let budget = RunBudget::new(self.config.budget_seconds);
        let changed_files = changed_files(root)?;
        if changed_files.is_empty() {
            return Ok(VerificationReport {
                project: None,
                targets: vec![],
                plan: None,
                artifacts: vec![],
                runs: vec![],
                coverage: vec![],
                findings: vec![],
                suggested_next_steps: vec![
                    "No changed files were detected from git diff or untracked files.".to_string(),
                ],
            });
        }

        let plugins: Vec<Arc<dyn LanguagePlugin>> = if let Some(language) = language {
            vec![self.registry.get(language)?]
        } else {
            self.registry.plugins().to_vec()
        };

        let mut report = VerificationReport::empty();

        for plugin in plugins {
            if budget.spent() {
                report.suggested_next_steps.push(
                    "Global budget was exhausted before all plugins were verified.".to_string(),
                );
                break;
            }
            let project = match plugin.detect_project(root) {
                Ok(project) => project,
                Err(_) if language.is_none() => continue,
                Err(error) => return Err(error),
            };
            let targets = plugin.discover_targets(root)?;
            let changed_targets = targets_for_changed_files(plugin.id(), &targets, &changed_files);
            if changed_targets.is_empty() {
                continue;
            }

            let mut artifacts = Vec::new();
            let mut plans = Vec::new();
            for target in &changed_targets {
                if budget.nearly_spent() {
                    report.suggested_next_steps.push(format!(
                        "Skipped remaining {} changed targets because the global budget was nearly exhausted.",
                        plugin.id()
                    ));
                    break;
                }
                let mut plan = self.planner.plan(&project, target)?;
                if !requested_strategies.is_empty() {
                    plan.strategies = requested_strategies.clone();
                }
                let mut target_artifacts = plugin.generate_tests(target, &plan)?;
                artifacts.append(&mut target_artifacts);
                plans.push(plan);
            }
            if plans.is_empty() {
                continue;
            }

            let mut artifacts = merge_artifacts(artifacts);
            if plans.first().is_some_and(|plan| plan.write_generated_tests) {
                write_artifacts(root, &mut artifacts)?;
            }

            let run = if plans
                .first()
                .is_some_and(|plan| plan.run_existing_tests || plan.run_generated_tests)
            {
                plugin.run_tests(root, &artifacts, &plans[0])?
            } else {
                skipped_run(plugin.id())
            };
            let coverage = if budget.nearly_spent() {
                vec![budget_skipped_coverage(plugin.id())]
            } else {
                plugin
                    .collect_coverage(root)?
                    .into_iter()
                    .collect::<Vec<_>>()
            };

            report.project.get_or_insert(project);
            if let Some(plan) = plans.first() {
                report.plan.get_or_insert_with(|| plan.clone());
            }
            report.targets.extend(changed_targets);
            report.artifacts.extend(artifacts);
            report.coverage.extend(coverage);
            report.findings.extend(run.failures.clone());
            report.runs.push(run);
        }

        let mut next_steps = suggested_next_steps(language.unwrap_or("changed targets"));
        next_steps.append(&mut report.suggested_next_steps);
        report.suggested_next_steps = next_steps;
        let write_observations = report
            .plan
            .as_ref()
            .is_some_and(|plan| plan.write_generated_tests);
        let differential_enabled = report.plan.as_ref().is_some_and(|plan| {
            plan.strategies
                .iter()
                .any(|strategy| matches!(strategy, VerificationStrategy::DifferentialTests))
        });
        self.add_observation_artifacts(
            root,
            language.unwrap_or("changed"),
            &mut report,
            write_observations,
            differential_enabled,
        )?;
        assign_finding_ids(&mut report);
        Ok(report)
    }

    pub fn generate(
        &self,
        root: &Path,
        language: &str,
        target_path: Option<&Path>,
        strategies: Vec<VerificationStrategy>,
    ) -> Result<VerificationReport> {
        let plugin = self.registry.get(language)?;
        let project = plugin.detect_project(root)?;
        let target = self.resolve_target(root, plugin.as_ref(), language, target_path)?;
        let mut plan = self.planner.plan(&project, &target)?;
        if !strategies.is_empty() {
            plan.strategies = strategies;
        }
        plan.run_existing_tests = false;
        plan.run_generated_tests = false;

        let mut artifacts = merge_artifacts(plugin.generate_tests(&target, &plan)?);
        if plan.write_generated_tests {
            write_artifacts(root, &mut artifacts)?;
        }

        Ok(VerificationReport {
            project: Some(project),
            targets: vec![target],
            plan: Some(plan),
            artifacts,
            runs: vec![],
            coverage: vec![],
            findings: vec![],
            suggested_next_steps: suggested_next_steps(language),
        })
    }

    pub fn run(&self, root: &Path, language: Option<&str>) -> Result<VerificationReport> {
        let plugins: Vec<Arc<dyn LanguagePlugin>> = if let Some(language) = language {
            vec![self.registry.get(language)?]
        } else {
            self.registry.plugins().to_vec()
        };

        let mut report = VerificationReport::empty();

        for plugin in plugins {
            let project = match plugin.detect_project(root) {
                Ok(project) => project,
                Err(_) if language.is_none() => continue,
                Err(error) => return Err(error),
            };
            let targets = plugin.discover_targets(root)?;
            let target = targets
                .iter()
                .find(|target| target.kind != TargetKind::Project)
                .cloned()
                .unwrap_or_else(|| VerificationTarget {
                    id: format!("{}:project", plugin.id()),
                    language: plugin.id().to_string(),
                    kind: TargetKind::Project,
                    path: Utf8PathBuf::from("."),
                    symbol: None,
                    signature: None,
                    line_range: None,
                    description: "whole project".to_string(),
                    risk: veritas_plugin_api::RiskLevel::Medium,
                });
            let plan = self.planner.plan(&project, &target)?;
            let run = plugin.run_tests(root, &[], &plan)?;
            report.project.get_or_insert(project);
            report.targets.extend(targets);
            report.findings.extend(run.failures.clone());
            report.runs.push(run);
        }

        report.suggested_next_steps = suggested_next_steps(language.unwrap_or("detected projects"));
        assign_finding_ids(&mut report);
        Ok(report)
    }

    pub fn review_ai(&self, root: &Path, language: Option<&str>) -> Result<VerificationReport> {
        let changed_files = changed_files(root)?;
        let plugins: Vec<Arc<dyn LanguagePlugin>> = if let Some(language) = language {
            vec![self.registry.get(language)?]
        } else {
            self.registry.plugins().to_vec()
        };

        let mut report = VerificationReport::empty();
        let mut all_changed_targets = Vec::new();

        for plugin in plugins {
            let project = match plugin.detect_project(root) {
                Ok(project) => project,
                Err(_) if language.is_none() => continue,
                Err(error) => return Err(error),
            };
            let targets = plugin.discover_targets(root)?;
            let changed_targets = targets_for_changed_files(plugin.id(), &targets, &changed_files);
            report.project.get_or_insert(project);
            report.targets.extend(changed_targets.clone());
            all_changed_targets.extend(changed_targets);
        }

        let mut artifacts = vec![
            change_digest_artifact(root, &changed_files, &all_changed_targets)?,
            ai_feedback_artifact(&changed_files, &all_changed_targets),
        ];
        if self.config.write_generated_tests {
            write_artifacts(root, &mut artifacts)?;
        }
        report.artifacts = artifacts;
        report.suggested_next_steps = vec![
            "Feed `.veritas/ai/agent_feedback.md` back into the coding agent before asking it to patch tests or code.".to_string(),
            "Run `veritas verify --changed --profile ci` after the agent responds.".to_string(),
        ];
        Ok(report)
    }

    pub fn save_report(&self, root: &Path, report: &VerificationReport) -> Result<PathBuf> {
        let report_dir = root.join(".veritas");
        fs::create_dir_all(&report_dir)
            .with_context(|| format!("failed to create {}", report_dir.display()))?;
        let report_path = report_dir.join("report.json");
        let contents = serde_json::to_string_pretty(report)?;
        fs::write(&report_path, contents)
            .with_context(|| format!("failed to write {}", report_path.display()))?;
        Ok(report_path)
    }

    fn add_observation_artifacts(
        &self,
        root: &Path,
        language: &str,
        report: &mut VerificationReport,
        write_artifacts_flag: bool,
        differential_enabled: bool,
    ) -> Result<()> {
        let mut artifacts = Vec::new();

        if differential_enabled {
            let (baseline, mut failures) = api_baseline_artifact(root, language, &report.targets)?;
            artifacts.push(baseline);
            report.findings.append(&mut failures);
        }

        artifacts.extend(feedback_artifacts(language, report));
        artifacts.extend(repro_artifacts(language, &report.findings));
        artifacts.extend(candidate_patch_artifacts(language, &report.findings));

        if artifacts.is_empty() {
            return Ok(());
        }

        if write_artifacts_flag {
            write_artifacts(root, &mut artifacts)?;
        }
        report.artifacts.extend(artifacts);
        Ok(())
    }

    fn resolve_target(
        &self,
        root: &Path,
        plugin: &dyn LanguagePlugin,
        language: &str,
        target_path: Option<&Path>,
    ) -> Result<VerificationTarget> {
        let targets = plugin.discover_targets(root)?;
        if let Some(path) = target_path {
            let relative = normalize_target_path(root, path)?;
            if relative.as_str() != "." && relative.extension().is_some() {
                return Ok(VerificationTarget {
                    id: format!("{language}:{}", relative),
                    language: language.to_string(),
                    kind: TargetKind::File,
                    path: relative,
                    symbol: None,
                    signature: None,
                    line_range: None,
                    description: "explicit CLI file target".to_string(),
                    risk: veritas_plugin_api::RiskLevel::Medium,
                });
            }
            if let Some(target) = targets
                .iter()
                .find(|target| target.path == relative)
                .cloned()
            {
                return Ok(target);
            }
            if let Some(target) = targets
                .iter()
                .find(|target| {
                    target.path.starts_with(&relative) || relative.starts_with(&target.path)
                })
                .cloned()
            {
                return Ok(target);
            }

            return Ok(VerificationTarget {
                id: format!("{language}:{}", relative),
                language: language.to_string(),
                kind: if relative.extension().is_some() {
                    TargetKind::File
                } else {
                    TargetKind::Package
                },
                path: relative,
                symbol: None,
                signature: None,
                line_range: None,
                description: "explicit CLI target".to_string(),
                risk: veritas_plugin_api::RiskLevel::Medium,
            });
        }

        targets
            .into_iter()
            .find(|target| target.kind != TargetKind::Project)
            .or_else(|| {
                Some(VerificationTarget {
                    id: format!("{language}:project"),
                    language: language.to_string(),
                    kind: TargetKind::Project,
                    path: Utf8PathBuf::from("."),
                    symbol: None,
                    signature: None,
                    line_range: None,
                    description: "whole project".to_string(),
                    risk: veritas_plugin_api::RiskLevel::Medium,
                })
            })
            .ok_or_else(|| anyhow!("no target could be resolved"))
    }
}

impl DeterministicPlanner {
    pub fn new(config: VeritasConfig) -> Self {
        Self {
            config,
            strategies: vec![
                VerificationStrategy::ExistingTests,
                VerificationStrategy::UnitTests,
                VerificationStrategy::PropertyTests,
                VerificationStrategy::Fuzzing,
                VerificationStrategy::DifferentialTests,
                VerificationStrategy::MutationChecks,
                VerificationStrategy::CoverageFeedback,
            ],
        }
    }
}

impl VerificationPlanner for DeterministicPlanner {
    fn plan(
        &self,
        _project: &ProjectInfo,
        target: &VerificationTarget,
    ) -> Result<VerificationPlan> {
        Ok(VerificationPlan {
            target_id: target.id.clone(),
            strategies: self.strategies.clone(),
            budget_seconds: self.config.budget_seconds,
            write_generated_tests: self.config.write_generated_tests,
            run_existing_tests: true,
            run_generated_tests: true,
            fail_on_generated_test_failure: self.config.fail_on_generated_test_failure,
        })
    }
}

impl VerificationPlanner for ExternalLlmPlanner {
    fn plan(&self, project: &ProjectInfo, target: &VerificationTarget) -> Result<VerificationPlan> {
        let default_plan = self.fallback.plan(project, target)?;
        let request = PlannerRequest {
            project,
            target,
            default_plan: &default_plan,
            constraints: PlannerConstraints {
                max_budget_seconds: default_plan.budget_seconds,
                allowed_strategies: self.fallback.strategies.clone(),
                run_scope: "selected_target_only",
                safety_notes: vec![
                    "Do not broaden target scope beyond the provided target.",
                    "Do not request unbounded fuzzing, mutation, or coverage.",
                    "Return JSON only; commands are executed by veritas, not by the planner.",
                ],
            },
        };
        match self.invoke(&request) {
            Ok(Some(plan)) => Ok(self.constrain_plan(default_plan, plan)),
            Ok(None) => Ok(default_plan),
            Err(error) if self.fail_on_error => Err(error),
            Err(error) => {
                debug!(error = %error, "external LLM planner failed; using deterministic plan");
                Ok(default_plan)
            }
        }
    }
}

impl ExternalLlmPlanner {
    fn invoke(&self, request: &PlannerRequest<'_>) -> Result<Option<VerificationPlan>> {
        let mut child = Command::new("sh")
            .args(["-c", self.command.as_str()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start planner command `{}`", self.command))?;

        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("planner command stdin was not available"))?;
        stdin
            .write_all(serde_json::to_string(request)?.as_bytes())
            .with_context(|| "failed to write planner request")?;
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .with_context(|| "failed to wait for planner command")?;
        if !output.status.success() {
            bail!(
                "planner command exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(None);
        }
        if let Ok(plan) = serde_json::from_str::<VerificationPlan>(&stdout) {
            return Ok(Some(plan));
        }
        let response = serde_json::from_str::<PlannerResponse>(&stdout)
            .with_context(|| "planner command returned invalid JSON")?;
        Ok(response.plan)
    }

    fn constrain_plan(
        &self,
        default_plan: VerificationPlan,
        mut plan: VerificationPlan,
    ) -> VerificationPlan {
        let allowed = self
            .fallback
            .strategies
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        plan.target_id = default_plan.target_id.clone();
        plan.budget_seconds = plan.budget_seconds.min(default_plan.budget_seconds);
        plan.strategies
            .retain(|strategy| allowed.contains(strategy));
        if plan.strategies.is_empty() {
            plan.strategies = default_plan.strategies;
        }
        plan.write_generated_tests =
            default_plan.write_generated_tests && plan.write_generated_tests;
        plan.fail_on_generated_test_failure = default_plan.fail_on_generated_test_failure;
        plan
    }
}

pub fn read_saved_report(root: &Path) -> Result<VerificationReport> {
    let report_path = root.join(".veritas").join("report.json");
    let contents = fs::read_to_string(&report_path)
        .with_context(|| format!("failed to read {}", report_path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse {}", report_path.display()))
}

pub fn cleanup_generated_artifacts(root: &Path, dry_run: bool) -> Result<CleanupSummary> {
    let mut paths = generated_artifact_paths(root)?;
    paths.sort();
    paths.dedup();

    if !dry_run {
        for path in &paths {
            remove_generated_path(&root.join(path))?;
        }
    }

    Ok(CleanupSummary { dry_run, paths })
}

pub fn promote_repros(
    root: &Path,
    dry_run: bool,
    index: Option<usize>,
) -> Result<PromotionSummary> {
    let report = read_saved_report(root)?;
    let mut artifacts = Vec::new();
    for (finding_index, finding) in report.findings.iter().enumerate() {
        if index.is_some_and(|selected| selected != finding_index) {
            continue;
        }
        let Some(repro) = &finding.repro else {
            continue;
        };
        let language = finding
            .target_id
            .as_ref()
            .and_then(|target_id| target_id.split_once(':').map(|(language, _)| language))
            .unwrap_or("unknown");
        let path = Utf8PathBuf::from(format!(
            ".veritas/promotions/{}_{}.md",
            language, finding_index
        ));
        let mut contents = String::from("# Repro Promotion\n\n");
        contents.push_str(&format!("- Finding: {}\n", finding.message));
        contents.push_str(&format!("- Severity: {:?}\n", finding.severity));
        contents.push_str(&format!("- Command: `{}`\n", repro.command));
        if let Some(target_id) = &finding.target_id {
            contents.push_str(&format!("- Target: `{target_id}`\n"));
        }
        if let Some(path) = &repro.path {
            contents.push_str(&format!("- Source path: `{path}`\n"));
        }
        if let Some(input) = &repro.input {
            contents.push_str(&format!("- Captured input: `{}`\n", input.trim()));
        }
        contents.push_str("\n## Candidate Regression\n\n");
        if language == "go"
            && repro
                .path
                .as_ref()
                .is_some_and(|path| path.starts_with("testdata/fuzz"))
        {
            contents.push_str("Keep the referenced Go fuzz corpus entry under `testdata/fuzz/<FuzzName>/` and add a focused unit assertion for the behavior it exposes.\n");
        } else if finding.message.contains("mutation survived") {
            contents.push_str("Add or promote a test assertion that fails when the described mutation is applied, then rerun `veritas verify` to confirm the mutant is killed.\n");
        } else {
            contents.push_str("Turn the command and input above into a stable regression test or corpus entry owned by the target package.\n");
        }
        artifacts.push(GeneratedArtifact {
            id: format!("{language}-promotion-{finding_index}"),
            language: language.to_string(),
            kind: ArtifactKind::ReproCase,
            target_id: finding
                .target_id
                .clone()
                .unwrap_or_else(|| format!("{language}:unknown")),
            path,
            contents,
            description: "Reviewable repro promotion guidance".to_string(),
            status: ArtifactStatus::Planned,
        });
    }

    let paths = artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    if !dry_run {
        write_artifacts(root, &mut artifacts)?;
    }
    Ok(PromotionSummary { dry_run, paths })
}

pub fn accept_findings(root: &Path, ids: &[String], accept_all: bool) -> Result<BaselineSummary> {
    let report = read_saved_report(root)?;
    let mut accepted = accepted_finding_ids(root)?;
    for finding in &report.findings {
        let Some(id) = &finding.id else {
            continue;
        };
        if accept_all || ids.iter().any(|requested| requested == id) {
            accepted.insert(id.clone());
        }
    }
    let path = Utf8PathBuf::from(".veritas/baselines/findings.json");
    let full_path = root.join(&path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let accepted_ids = accepted.into_iter().collect::<Vec<_>>();
    fs::write(&full_path, serde_json::to_string_pretty(&accepted_ids)?)
        .with_context(|| format!("failed to write {}", full_path.display()))?;
    Ok(BaselineSummary { path, accepted_ids })
}

pub fn accepted_finding_ids(root: &Path) -> Result<BTreeSet<String>> {
    let path = root.join(".veritas/baselines/findings.json");
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let ids = serde_json::from_str::<Vec<String>>(&contents)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(ids.into_iter().collect())
}

fn changed_files(root: &Path) -> Result<Vec<ChangedFile>> {
    let mut files: BTreeMap<Utf8PathBuf, Vec<LineRange>> = BTreeMap::new();
    let root_arg = root.display().to_string();
    for args in [
        ["diff", "--unified=0", "--diff-filter=ACMR", "HEAD", "--"].as_slice(),
        [
            "diff",
            "--unified=0",
            "--cached",
            "--diff-filter=ACMR",
            "--",
        ]
        .as_slice(),
    ] {
        let output = Command::new("git")
            .args(["-C", root_arg.as_str()])
            .args(args)
            .output()
            .with_context(|| "failed to run git for changed-target discovery")?;
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for changed in parse_unified_diff(&stdout) {
            if should_ignore_changed_path(&changed.path) {
                continue;
            }
            files
                .entry(changed.path)
                .or_default()
                .extend(changed.ranges);
        }
    }

    let output = Command::new("git")
        .args(["-C", root_arg.as_str()])
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()
        .with_context(|| "failed to run git for untracked changed-target discovery")?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let path = Utf8PathBuf::from(line);
            if !should_ignore_changed_path(&path) {
                files.entry(path).or_default();
            }
        }
    }

    Ok(files
        .into_iter()
        .map(|(path, ranges)| ChangedFile { path, ranges })
        .collect())
}

fn targets_for_changed_files(
    language: &str,
    targets: &[VerificationTarget],
    changed_files: &[ChangedFile],
) -> Vec<VerificationTarget> {
    let language_changed_files = changed_files
        .iter()
        .filter(|changed| path_matches_language(language, &changed.path))
        .collect::<Vec<_>>();
    if language_changed_files.is_empty() {
        return vec![];
    }

    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for target in targets {
        if target.kind == TargetKind::Project {
            continue;
        }
        if language_changed_files
            .iter()
            .any(|changed| target_matches_changed_file(target, changed))
            && seen.insert(target.id.clone())
        {
            let mut target = target.clone();
            target.description = format!("changed {}", target.description);
            selected.push(target);
        }
    }

    for changed in language_changed_files {
        let has_symbol_target = selected.iter().any(|target| target.path == changed.path);
        if !has_symbol_target {
            let kind = if changed.path.extension().is_some() {
                TargetKind::File
            } else {
                TargetKind::Package
            };
            let id = format!("{language}:{}", changed.path);
            if seen.insert(id.clone()) {
                selected.push(VerificationTarget {
                    id,
                    language: language.to_string(),
                    kind,
                    path: changed.path.clone(),
                    symbol: None,
                    signature: None,
                    line_range: None,
                    description: "changed file".to_string(),
                    risk: veritas_plugin_api::RiskLevel::Medium,
                });
            }
        }
    }

    selected
}

fn parse_unified_diff(diff: &str) -> Vec<ChangedFile> {
    let mut files: BTreeMap<Utf8PathBuf, Vec<LineRange>> = BTreeMap::new();
    let mut current_path: Option<Utf8PathBuf> = None;

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ b/") {
            current_path = Some(Utf8PathBuf::from(path));
            files.entry(Utf8PathBuf::from(path)).or_default();
            continue;
        }
        if line.starts_with("@@") {
            let Some(path) = current_path.clone() else {
                continue;
            };
            let Some(range) = parse_added_hunk_range(line) else {
                continue;
            };
            files.entry(path).or_default().push(range);
        }
    }

    files
        .into_iter()
        .map(|(path, ranges)| ChangedFile { path, ranges })
        .collect()
}

fn parse_added_hunk_range(line: &str) -> Option<LineRange> {
    let plus = line.split_whitespace().find(|part| part.starts_with('+'))?;
    let value = plus.trim_start_matches('+');
    let (start, len) = value
        .split_once(',')
        .map(|(start, len)| (start, len.parse::<usize>().ok()))
        .unwrap_or((value, Some(1)));
    let start = start.parse::<usize>().ok()?;
    let len = len.unwrap_or(1);
    let end = if len == 0 { start } else { start + len - 1 };
    Some(LineRange { start, end })
}

fn should_ignore_changed_path(path: &Utf8PathBuf) -> bool {
    path.starts_with(".veritas")
        || path.starts_with("target")
        || path.starts_with("tests/veritas_generated")
        || path.as_str().contains("/tests/veritas_generated/")
}

fn path_matches_language(language: &str, path: &Utf8PathBuf) -> bool {
    matches!(
        (language, path.extension()),
        ("rust", Some("rs")) | ("go", Some("go"))
    )
}

fn target_matches_changed_file(target: &VerificationTarget, changed: &ChangedFile) -> bool {
    match target.kind {
        TargetKind::Function => {
            target.path == changed.path
                && (changed.ranges.is_empty()
                    || target.line_range.as_ref().is_none_or(|target_range| {
                        changed
                            .ranges
                            .iter()
                            .any(|changed_range| target_range.overlaps(changed_range))
                    }))
        }
        TargetKind::File => target.path == changed.path,
        TargetKind::Package => {
            target.path.as_str() == "."
                || changed.path.starts_with(&target.path)
                || target.path.starts_with(&changed.path)
        }
        TargetKind::Project => false,
    }
}

fn merge_artifacts(artifacts: Vec<GeneratedArtifact>) -> Vec<GeneratedArtifact> {
    let mut by_path: BTreeMap<Utf8PathBuf, GeneratedArtifact> = BTreeMap::new();
    for artifact in artifacts {
        by_path
            .entry(artifact.path.clone())
            .and_modify(|existing| {
                existing.contents = merge_artifact_contents(&existing.contents, &artifact.contents);
                existing.description =
                    format!("{}; {}", existing.description, artifact.description);
            })
            .or_insert(artifact);
    }
    by_path.into_values().collect()
}

fn merge_artifact_contents(left: &str, right: &str) -> String {
    let mut lines = BTreeSet::new();
    let mut merged = Vec::new();
    for line in left.lines().chain(right.lines()) {
        if lines.insert(line.to_string()) {
            merged.push(line);
        }
    }
    let mut contents = merged.join("\n");
    contents.push('\n');
    contents
}

fn expand_report_targets(
    selected: &VerificationTarget,
    all_targets: &[VerificationTarget],
) -> Vec<VerificationTarget> {
    let mut targets = all_targets
        .iter()
        .filter(|target| match selected.kind {
            TargetKind::Project => target.kind != TargetKind::Project,
            TargetKind::Package => {
                target.path == selected.path || target.path.starts_with(&selected.path)
            }
            TargetKind::File => target.path == selected.path,
            TargetKind::Function => target.id == selected.id,
        })
        .cloned()
        .collect::<Vec<_>>();
    if targets.is_empty() {
        targets.push(selected.clone());
    }
    targets
}

fn api_baseline_artifact(
    root: &Path,
    language: &str,
    targets: &[VerificationTarget],
) -> Result<(GeneratedArtifact, Vec<Failure>)> {
    let signatures = targets
        .iter()
        .filter(|target| target.kind == TargetKind::Function)
        .filter_map(|target| {
            target
                .signature
                .as_ref()
                .map(|signature| (target.id.clone(), signature.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let path = Utf8PathBuf::from(format!(".veritas/baselines/{language}_api.json"));
    let full_path = root.join(&path);
    let previous = fs::read_to_string(&full_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<BTreeMap<String, String>>(&contents).ok())
        .unwrap_or_default();

    let mut failures = Vec::new();
    for (id, signature) in &signatures {
        if let Some(old_signature) = previous.get(id) {
            if old_signature != signature {
                failures.push(Failure {
                    id: None,
                    message: format!("public API signature changed for `{id}`"),
                    severity: FailureSeverity::Error,
                    target_id: Some(id.clone()),
                    artifact_id: Some(format!("{language}-api-baseline")),
                    command: "differential-api-baseline".to_string(),
                    stdout_excerpt: format!("old: {old_signature}\nnew: {signature}"),
                    stderr_excerpt: String::new(),
                    repro: Some(ReproCase {
                        command: "review public API compatibility or accept the new baseline"
                            .to_string(),
                        input: None,
                        path: Some(path.clone()),
                    }),
                });
            }
        }
    }

    let contents = serde_json::to_string_pretty(&signatures)?;
    Ok((
        GeneratedArtifact {
            id: format!("{language}-api-baseline"),
            language: language.to_string(),
            kind: ArtifactKind::DifferentialBaseline,
            target_id: format!("{language}:project"),
            path,
            contents,
            description: "Public API signature baseline for differential verification".to_string(),
            status: ArtifactStatus::Planned,
        },
        failures,
    ))
}

fn feedback_artifacts(language: &str, report: &VerificationReport) -> Vec<GeneratedArtifact> {
    let mut artifacts = Vec::new();
    if report
        .coverage
        .iter()
        .any(|coverage| !coverage.files.is_empty() || coverage.summary.contains("not collected"))
    {
        let mut contents = String::from("# Coverage Feedback\n\n");
        for coverage in &report.coverage {
            contents.push_str(&format!("- `{}`: {}\n", coverage.tool, coverage.summary));
            for file in &coverage.files {
                if !file.uncovered_ranges.is_empty() {
                    contents.push_str(&format!(
                        "  - `{}` uncovered: {}\n",
                        file.path,
                        file.uncovered_ranges.join(", ")
                    ));
                }
            }
        }
        contents.push_str("\nSuggested generation focus: add inputs and assertions for uncovered branches before increasing fuzz time.\n");
        artifacts.push(GeneratedArtifact {
            id: format!("{language}-coverage-feedback"),
            language: language.to_string(),
            kind: ArtifactKind::CoverageFeedback,
            target_id: format!("{language}:coverage"),
            path: Utf8PathBuf::from(format!(".veritas/feedback/{language}_coverage.md")),
            contents,
            description: "Coverage feedback for the next verification loop".to_string(),
            status: ArtifactStatus::Planned,
        });
    }

    let mutation_findings = report
        .findings
        .iter()
        .filter(|failure| failure.message.contains("mutation survived"))
        .collect::<Vec<_>>();
    if !mutation_findings.is_empty() {
        let mut contents = String::from("# Mutation Feedback\n\n");
        for finding in mutation_findings {
            contents.push_str(&format!("- {}\n", finding.message));
            if let Some(repro) = &finding.repro {
                contents.push_str(&format!("  - Repro: `{}`\n", repro.command));
            }
        }
        contents.push_str("\nSuggested generation focus: convert surviving mutants into stronger regression assertions.\n");
        artifacts.push(GeneratedArtifact {
            id: format!("{language}-mutation-feedback"),
            language: language.to_string(),
            kind: ArtifactKind::CoverageFeedback,
            target_id: format!("{language}:mutation"),
            path: Utf8PathBuf::from(format!(".veritas/feedback/{language}_mutation.md")),
            contents,
            description: "Mutation feedback for the next verification loop".to_string(),
            status: ArtifactStatus::Planned,
        });
    }

    artifacts
}

fn repro_artifacts(language: &str, findings: &[Failure]) -> Vec<GeneratedArtifact> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, failure)| {
            let repro = failure.repro.as_ref()?;
            let minimized_input = repro
                .input
                .clone()
                .or_else(|| extract_minimized_input(&failure.stdout_excerpt))
                .or_else(|| extract_minimized_input(&failure.stderr_excerpt));
            let mut contents = String::from("# Repro Case\n\n");
            contents.push_str(&format!("- Finding: {}\n", failure.message));
            contents.push_str(&format!("- Command: `{}`\n", repro.command));
            if let Some(path) = &repro.path {
                contents.push_str(&format!("- Path: `{path}`\n"));
            }
            if let Some(input) = minimized_input {
                contents.push_str(&format!("- Minimized input: `{}`\n", input.trim()));
            } else {
                contents.push_str("- Minimized input: not available from tool output\n");
            }
            Some(GeneratedArtifact {
                id: format!("{language}-repro-{index}"),
                language: language.to_string(),
                kind: ArtifactKind::ReproCase,
                target_id: failure
                    .target_id
                    .clone()
                    .unwrap_or_else(|| format!("{language}:unknown")),
                path: Utf8PathBuf::from(format!(".veritas/repros/{language}_{index}.md")),
                contents,
                description: "Minimized repro summary extracted from verification output"
                    .to_string(),
                status: ArtifactStatus::Planned,
            })
        })
        .collect()
}

fn candidate_patch_artifacts(language: &str, findings: &[Failure]) -> Vec<GeneratedArtifact> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, failure)| {
            let target_id = failure.target_id.as_deref().unwrap_or("unknown");
            let mut contents = String::from("# Candidate Verification Patch\n\n");
            contents.push_str(&format!("- Finding: {}\n", failure.message));
            contents.push_str(&format!("- Target: `{target_id}`\n"));
            if let Some(repro) = &failure.repro {
                contents.push_str(&format!("- Repro command: `{}`\n", repro.command));
            }
            contents.push_str("\n## Suggested Test Shape\n\n");
            if failure.message.contains("mutation survived") {
                contents.push_str("Add a focused assertion that fails under the described mutant. Prefer a small unit test next to existing handwritten tests, then rerun `veritas verify` to confirm the mutant is killed.\n");
            } else if failure.message.contains("fuzz") || failure.message.contains("minimal failing input") {
                contents.push_str("Persist the minimized input as a regression case or fuzz corpus entry, then add an assertion for the expected behavior.\n");
            } else if failure.message.contains("cargo test failed") || failure.message.contains("go test failed") {
                contents.push_str("Promote the failing generated harness input into a stable handwritten regression test owned by the target package.\n");
            } else {
                return None;
            }
            Some(GeneratedArtifact {
                id: format!("{language}-candidate-patch-{index}"),
                language: language.to_string(),
                kind: ArtifactKind::CandidatePatch,
                target_id: failure
                    .target_id
                    .clone()
                    .unwrap_or_else(|| format!("{language}:unknown")),
                path: Utf8PathBuf::from(format!(".veritas/patches/{language}_{index}.md")),
                contents,
                description: "AI-ready candidate verification patch guidance".to_string(),
                status: ArtifactStatus::Planned,
            })
        })
        .collect()
}

fn change_digest_artifact(
    root: &Path,
    changed_files: &[ChangedFile],
    targets: &[VerificationTarget],
) -> Result<GeneratedArtifact> {
    let mut contents = String::from("# AI Change Digest\n\n");
    contents.push_str("Generated by veritas for AI-assisted review.\n\n");
    if changed_files.is_empty() {
        contents.push_str("No changed files were detected.\n");
    } else {
        contents.push_str("## Changed Files\n\n");
        for changed in changed_files {
            let ranges = if changed.ranges.is_empty() {
                "untracked or unknown line range".to_string()
            } else {
                changed
                    .ranges
                    .iter()
                    .map(|range| format!("{}-{}", range.start, range.end))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            contents.push_str(&format!("- `{}`: {ranges}\n", changed.path));
        }
    }

    if !targets.is_empty() {
        contents.push_str("\n## Changed Verification Targets\n\n");
        for target in targets {
            contents.push_str(&format!(
                "- {:?} `{}`{} risk={:?}{}\n",
                target.kind,
                target.path,
                target
                    .symbol
                    .as_ref()
                    .map(|symbol| format!(" `{symbol}`"))
                    .unwrap_or_default(),
                target.risk,
                target
                    .line_range
                    .as_ref()
                    .map(|range| format!(" lines {}-{}", range.start, range.end))
                    .unwrap_or_default()
            ));
        }
    }

    let diff = git_diff_excerpt(root)?;
    if !diff.trim().is_empty() {
        contents.push_str("\n## Diff Excerpt\n\n```diff\n");
        contents.push_str(&diff);
        contents.push_str("\n```\n");
    }

    Ok(GeneratedArtifact {
        id: "ai-change-digest".to_string(),
        language: "changed".to_string(),
        kind: ArtifactKind::ChangeDigest,
        target_id: "changed:review".to_string(),
        path: Utf8PathBuf::from(".veritas/ai/change_digest.md"),
        contents,
        description: "AI-aware digest of changed files, symbols, risks, and diff context"
            .to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn ai_feedback_artifact(
    changed_files: &[ChangedFile],
    targets: &[VerificationTarget],
) -> GeneratedArtifact {
    let high_risk_targets = targets
        .iter()
        .filter(|target| target.risk == veritas_plugin_api::RiskLevel::High)
        .count();
    let mut contents = String::from("# AI Agent Feedback\n\n");
    contents.push_str("Use this as copy-paste context for an AI coding agent.\n\n");
    contents.push_str("## Instructions\n\n");
    contents.push_str(
        "- Focus only on the changed files and targets listed in `.veritas/ai/change_digest.md`.\n",
    );
    contents.push_str("- Add or adjust tests before changing production code unless the digest shows an obvious implementation defect.\n");
    contents.push_str("- Prioritize boundary, invalid-input, auth/permission, money, parsing, serialization, and error-handling assertions.\n");
    contents.push_str("- Do not broaden verification scope beyond the configured budgets.\n");
    contents.push_str("- After edits, run `veritas verify --changed --profile ci`.\n");
    contents.push_str("\n## Summary\n\n");
    contents.push_str(&format!("- Changed files: `{}`\n", changed_files.len()));
    contents.push_str(&format!("- Changed targets: `{}`\n", targets.len()));
    contents.push_str(&format!("- High-risk targets: `{high_risk_targets}`\n"));
    GeneratedArtifact {
        id: "ai-agent-feedback".to_string(),
        language: "changed".to_string(),
        kind: ArtifactKind::AiFeedback,
        target_id: "changed:review".to_string(),
        path: Utf8PathBuf::from(".veritas/ai/agent_feedback.md"),
        contents,
        description: "Copy-paste AI agent instructions based on changed targets".to_string(),
        status: ArtifactStatus::Planned,
    }
}

fn git_diff_excerpt(root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-C",
            root.to_string_lossy().as_ref(),
            "diff",
            "--unified=3",
            "HEAD",
            "--",
        ])
        .output()
        .with_context(|| "failed to run git diff for AI change digest")?;
    if !output.status.success() {
        return Ok(String::new());
    }
    let diff = String::from_utf8_lossy(&output.stdout);
    Ok(diff.chars().take(20_000).collect())
}

fn extract_minimized_input(output: &str) -> Option<String> {
    output
        .lines()
        .find(|line| {
            let lowered = line.to_ascii_lowercase();
            lowered.contains("minimal failing input")
                || lowered.contains("failing input")
                || lowered.contains("failure persistence")
        })
        .map(|line| line.trim().to_string())
}

fn write_artifacts(root: &Path, artifacts: &mut [GeneratedArtifact]) -> Result<()> {
    for artifact in artifacts {
        let path = root.join(&artifact.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&path, &artifact.contents)
            .with_context(|| format!("failed to write generated artifact {}", path.display()))?;
        artifact.status = ArtifactStatus::Written;
    }
    Ok(())
}

fn generated_artifact_paths(root: &Path) -> Result<Vec<Utf8PathBuf>> {
    let mut paths = Vec::new();
    let veritas_dir = root.join(".veritas");
    if veritas_dir.exists() {
        paths.push(Utf8PathBuf::from(".veritas"));
    }
    collect_generated_artifact_paths(root, root, &mut paths)?;
    Ok(paths)
}

fn collect_generated_artifact_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<Utf8PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", directory.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if file_type.is_dir() {
            if should_skip_cleanup_dir(&file_name) {
                continue;
            }
            if file_name == "veritas_generated" && parent_dir_name(&path) == Some("tests") {
                paths.push(relative_utf8(root, &path)?);
                continue;
            }
            collect_generated_artifact_paths(root, &path, paths)?;
        } else if file_name == "veritas_fuzz_test.go"
            || (file_name == "veritas_generated.rs" && parent_dir_name(&path) == Some("tests"))
        {
            paths.push(relative_utf8(root, &path)?);
        }
    }
    Ok(())
}

fn should_skip_cleanup_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".veritas" | "target" | "vendor" | "node_modules"
    )
}

fn parent_dir_name(path: &Path) -> Option<&str> {
    path.parent()?.file_name()?.to_str()
}

fn relative_utf8(root: &Path, path: &Path) -> Result<Utf8PathBuf> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    Utf8PathBuf::from_path_buf(relative.to_path_buf()).map_err(|path| {
        anyhow!(
            "generated artifact path contains non-UTF-8 data and cannot be represented: {}",
            path.display()
        )
    })
}

fn remove_generated_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect generated artifact {}", path.display()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove generated artifact {}", path.display()))?;
    } else {
        fs::remove_file(path)
            .with_context(|| format!("failed to remove generated artifact {}", path.display()))?;
    }
    Ok(())
}

fn normalize_target_path(root: &Path, path: &Path) -> Result<Utf8PathBuf> {
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };

    let relative = full.strip_prefix(root).unwrap_or(&full);
    if relative.as_os_str().is_empty() {
        return Ok(Utf8PathBuf::from("."));
    }
    Utf8PathBuf::from_path_buf(relative.to_path_buf()).map_err(|path| {
        anyhow!(
            "target path contains non-UTF-8 data and cannot be represented: {}",
            path.display()
        )
    })
}

fn skipped_run(language: &str) -> veritas_plugin_api::TestRunResult {
    veritas_plugin_api::TestRunResult {
        language: language.to_string(),
        status: RunStatus::Skipped,
        commands: vec![],
        failures: vec![],
        duration_ms: 0,
    }
}

fn assign_finding_ids(report: &mut VerificationReport) {
    for failure in &mut report.findings {
        if failure.id.is_none() {
            failure.id = Some(stable_finding_id(failure));
        }
    }
}

fn stable_finding_id(failure: &Failure) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(failure.message.as_bytes());
    bytes.push(0);
    if let Some(target_id) = &failure.target_id {
        bytes.extend_from_slice(target_id.as_bytes());
    }
    bytes.push(0);
    if let Some(artifact_id) = &failure.artifact_id {
        bytes.extend_from_slice(artifact_id.as_bytes());
    }
    bytes.push(0);
    if let Some(repro) = &failure.repro {
        bytes.extend_from_slice(repro.command.as_bytes());
        if let Some(path) = &repro.path {
            bytes.extend_from_slice(path.as_str().as_bytes());
        }
    }
    format!("vts-{:016x}", fnv1a64(&bytes))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn budget_skipped_coverage(language: &str) -> veritas_plugin_api::CoverageReport {
    veritas_plugin_api::CoverageReport {
        tool: format!("{language} coverage"),
        summary: "not collected: global budget nearly exhausted".to_string(),
        files: vec![],
    }
}

fn suggested_next_steps(language: &str) -> Vec<String> {
    vec![
        format!("Review generated {language} artifacts before committing them."),
        "Keep generated regression tests that reproduce real defects.".to_string(),
        "Increase the time budget for fuzzing when targeting parsers or input-heavy APIs."
            .to_string(),
    ]
}

pub fn strategy_from_kind(kind: &str) -> Result<VerificationStrategy> {
    match kind {
        "unit" => Ok(VerificationStrategy::UnitTests),
        "property" => Ok(VerificationStrategy::PropertyTests),
        "fuzz" => Ok(VerificationStrategy::Fuzzing),
        "differential" => Ok(VerificationStrategy::DifferentialTests),
        "mutation" => Ok(VerificationStrategy::MutationChecks),
        other => bail!("unsupported generation kind `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use camino::Utf8PathBuf;
    use veritas_plugin_api::{LineRange, RiskLevel};

    use super::{
        api_baseline_artifact, cleanup_generated_artifacts, parse_unified_diff,
        targets_for_changed_files, ChangedFile, TargetKind, VerificationTarget,
    };

    #[test]
    fn parses_added_hunk_ranges_from_zero_context_diff() {
        let diff = "\
diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -10,0 +11,2 @@
+let added = true;
+let second = true;
@@ -30 +32 @@
-old
+new
diff --git a/src/other.rs b/src/other.rs
index 3333333..4444444 100644
--- a/src/other.rs
+++ b/src/other.rs
@@ -5,3 +5,0 @@
-removed
-removed
-removed
";

        let changed = parse_unified_diff(diff);

        assert_eq!(changed.len(), 2);
        let lib = changed
            .iter()
            .find(|changed| changed.path.as_str() == "src/lib.rs")
            .expect("src/lib.rs diff should be parsed");
        assert_eq!(
            lib.ranges,
            vec![
                LineRange { start: 11, end: 12 },
                LineRange { start: 32, end: 32 }
            ]
        );
        let other = changed
            .iter()
            .find(|changed| changed.path.as_str() == "src/other.rs")
            .expect("src/other.rs diff should be parsed");
        assert_eq!(other.ranges, vec![LineRange { start: 5, end: 5 }]);
    }

    #[test]
    fn changed_line_ranges_select_overlapping_function_targets() {
        let targets = vec![
            function_target("rust:src/lib.rs::parse_total", "src/lib.rs", 10, 20),
            function_target("rust:src/lib.rs::format_total", "src/lib.rs", 30, 40),
            VerificationTarget {
                id: "rust:project".to_string(),
                language: "rust".to_string(),
                kind: TargetKind::Project,
                path: Utf8PathBuf::from("."),
                symbol: None,
                signature: None,
                line_range: None,
                description: "project".to_string(),
                risk: RiskLevel::Low,
            },
        ];
        let changed_files = vec![ChangedFile {
            path: Utf8PathBuf::from("src/lib.rs"),
            ranges: vec![LineRange { start: 15, end: 15 }],
        }];

        let selected = targets_for_changed_files("rust", &targets, &changed_files);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "rust:src/lib.rs::parse_total");
        assert_eq!(selected[0].description, "changed function");
    }

    #[test]
    fn changed_untracked_files_select_file_target_when_no_symbol_matches() {
        let targets = vec![function_target(
            "rust:src/lib.rs::parse_total",
            "src/lib.rs",
            10,
            20,
        )];
        let changed_files = vec![ChangedFile {
            path: Utf8PathBuf::from("src/new.rs"),
            ranges: Vec::new(),
        }];

        let selected = targets_for_changed_files("rust", &targets, &changed_files);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "rust:src/new.rs");
        assert_eq!(selected[0].kind, TargetKind::File);
        assert_eq!(selected[0].description, "changed file");
    }

    #[test]
    fn api_baseline_reports_only_changed_existing_signatures() {
        let root = TempRoot::new();
        let baseline_dir = root.path().join(".veritas/baselines");
        fs::create_dir_all(&baseline_dir).expect("create baseline dir");
        fs::write(
            baseline_dir.join("rust_api.json"),
            r#"{
  "rust:src/lib.rs::parse_total": "pub fn parse_total(input: &str) -> i32",
  "rust:src/lib.rs::format_total": "pub fn format_total(cents: u64) -> String"
}"#,
        )
        .expect("write baseline");
        let targets = vec![
            function_target_with_signature(
                "rust:src/lib.rs::parse_total",
                "pub fn parse_total(input: &str) -> u64",
            ),
            function_target_with_signature(
                "rust:src/lib.rs::format_total",
                "pub fn format_total(cents: u64) -> String",
            ),
            function_target_with_signature("rust:src/lib.rs::new_api", "pub fn new_api()"),
        ];

        let (artifact, failures) =
            api_baseline_artifact(root.path(), "rust", &targets).expect("build baseline");

        assert_eq!(failures.len(), 1);
        let failure = &failures[0];
        assert_eq!(
            failure.message,
            "public API signature changed for `rust:src/lib.rs::parse_total`"
        );
        assert_eq!(
            failure.stdout_excerpt,
            "old: pub fn parse_total(input: &str) -> i32\nnew: pub fn parse_total(input: &str) -> u64"
        );
        assert_eq!(failure.artifact_id.as_deref(), Some("rust-api-baseline"));

        let current: BTreeMap<String, String> =
            serde_json::from_str(&artifact.contents).expect("baseline JSON should parse");
        assert_eq!(
            current
                .get("rust:src/lib.rs::parse_total")
                .map(String::as_str),
            Some("pub fn parse_total(input: &str) -> u64")
        );
        assert_eq!(
            current.get("rust:src/lib.rs::new_api").map(String::as_str),
            Some("pub fn new_api()")
        );
    }

    #[test]
    fn cleanup_dry_run_reports_generated_artifacts_without_deleting() {
        let root = TempRoot::new();
        write_cleanup_fixture(root.path());

        let summary =
            cleanup_generated_artifacts(root.path(), true).expect("dry-run cleanup should succeed");

        assert!(summary.dry_run);
        assert_eq!(
            summary.paths,
            vec![
                Utf8PathBuf::from(".veritas"),
                Utf8PathBuf::from("crates/sample/tests/veritas_generated"),
                Utf8PathBuf::from("crates/sample/tests/veritas_generated.rs"),
                Utf8PathBuf::from("pkg/veritas_fuzz_test.go"),
                Utf8PathBuf::from("tests/veritas_generated"),
                Utf8PathBuf::from("tests/veritas_generated.rs"),
            ]
        );
        assert!(root.path().join(".veritas/report.json").exists());
        assert!(root
            .path()
            .join("tests/veritas_generated/generated.rs")
            .exists());
        assert!(root.path().join("pkg/veritas_fuzz_test.go").exists());
    }

    #[test]
    fn cleanup_removes_generated_artifacts_and_leaves_other_files() {
        let root = TempRoot::new();
        write_cleanup_fixture(root.path());

        let summary =
            cleanup_generated_artifacts(root.path(), false).expect("cleanup should succeed");

        assert!(!summary.dry_run);
        assert_eq!(summary.paths.len(), 6);
        assert!(!root.path().join(".veritas").exists());
        assert!(!root.path().join("tests/veritas_generated").exists());
        assert!(!root.path().join("tests/veritas_generated.rs").exists());
        assert!(!root
            .path()
            .join("crates/sample/tests/veritas_generated")
            .exists());
        assert!(!root
            .path()
            .join("crates/sample/tests/veritas_generated.rs")
            .exists());
        assert!(!root.path().join("pkg/veritas_fuzz_test.go").exists());
        assert!(root.path().join("src/lib.rs").exists());
        assert!(root
            .path()
            .join("target/tests/veritas_generated.rs")
            .exists());
        assert!(root.path().join("vendor/veritas_fuzz_test.go").exists());
    }

    fn function_target(id: &str, path: &str, start: usize, end: usize) -> VerificationTarget {
        VerificationTarget {
            id: id.to_string(),
            language: "rust".to_string(),
            kind: TargetKind::Function,
            path: Utf8PathBuf::from(path),
            symbol: id.rsplit("::").next().map(ToString::to_string),
            signature: Some(format!("pub fn {}()", id.rsplit("::").next().unwrap_or(id))),
            line_range: Some(LineRange { start, end }),
            description: "function".to_string(),
            risk: RiskLevel::Medium,
        }
    }

    fn function_target_with_signature(id: &str, signature: &str) -> VerificationTarget {
        VerificationTarget {
            id: id.to_string(),
            language: "rust".to_string(),
            kind: TargetKind::Function,
            path: Utf8PathBuf::from("src/lib.rs"),
            symbol: id.rsplit("::").next().map(ToString::to_string),
            signature: Some(signature.to_string()),
            line_range: Some(LineRange { start: 1, end: 1 }),
            description: "function".to_string(),
            risk: RiskLevel::Medium,
        }
    }

    fn write_cleanup_fixture(root: &Path) {
        write_file(root, ".veritas/report.json");
        write_file(root, ".veritas/baselines/rust_api.json");
        write_file(root, "tests/veritas_generated/generated.rs");
        write_file(root, "tests/veritas_generated.rs");
        write_file(root, "crates/sample/tests/veritas_generated/generated.rs");
        write_file(root, "crates/sample/tests/veritas_generated.rs");
        write_file(root, "pkg/veritas_fuzz_test.go");
        write_file(root, "src/lib.rs");
        write_file(root, "target/tests/veritas_generated.rs");
        write_file(root, "vendor/veritas_fuzz_test.go");
    }

    fn write_file(root: &Path, relative: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("test file should have a parent"))
            .expect("create test parent");
        fs::write(path, "test").expect("write test file");
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
                std::env::temp_dir().join(format!("veritas-core-test-{}-{nanos}", process::id()));
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
