pub mod config;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use tracing::debug;
use veritas_plugin_api::{
    ArtifactKind, ArtifactStatus, AssertionCandidate, AssertionDomain, AssertionSource,
    CommandBudget, CommandRecord, ConfidenceGrade, ConfidenceScore, CorpusEntry, Failure,
    FailureSeverity, GeneratedArtifact, LanguagePlugin, LineRange, MutationAttribution,
    ProjectInfo, QualityBaseline, QualityDelta, ReproCase, RunStatus, TargetKind, TestRunResult,
    VerificationPlan, VerificationPlanner, VerificationQuality, VerificationReport,
    VerificationStrategy, VerificationTarget,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityBaselineSummary {
    pub path: Utf8PathBuf,
    pub confidence: u8,
    pub mutation_score: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusReplaySummary {
    pub dry_run: bool,
    pub report: VerificationReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerSummary {
    pub requested_jobs: usize,
    pub max_concurrency: usize,
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

pub fn run_parallel_jobs<T, R, F>(
    jobs: Vec<T>,
    max_concurrency: usize,
    runner: F,
) -> (Vec<R>, SchedulerSummary)
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> R + Send + Sync + 'static,
{
    let requested_jobs = jobs.len();
    if jobs.is_empty() {
        return (
            Vec::new(),
            SchedulerSummary {
                requested_jobs,
                max_concurrency: 0,
            },
        );
    }

    let max_concurrency = max_concurrency.clamp(1, jobs.len());
    if max_concurrency == 1 {
        let results = jobs.into_iter().map(runner).collect::<Vec<_>>();
        return (
            results,
            SchedulerSummary {
                requested_jobs,
                max_concurrency,
            },
        );
    }

    let queue = Arc::new(Mutex::new(
        jobs.into_iter().enumerate().collect::<VecDeque<_>>(),
    ));
    let results = Arc::new(Mutex::new(Vec::with_capacity(requested_jobs)));
    let runner = Arc::new(runner);
    let mut handles = Vec::new();

    for _ in 0..max_concurrency {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        let runner = Arc::clone(&runner);
        handles.push(std::thread::spawn(move || loop {
            let next = {
                let mut queue = queue.lock().expect("scheduler queue lock poisoned");
                queue.pop_front()
            };
            let Some((index, job)) = next else {
                break;
            };
            let result = runner(job);
            results
                .lock()
                .expect("scheduler results lock poisoned")
                .push((index, result));
        }));
    }

    for handle in handles {
        handle.join().expect("scheduler worker panicked");
    }

    let mut results = match Arc::try_unwrap(results) {
        Ok(results) => results
            .into_inner()
            .expect("scheduler results lock poisoned"),
        Err(_) => panic!("scheduler results still shared"),
    };
    results.sort_by_key(|(index, _)| *index);
    (
        results
            .into_iter()
            .map(|(_, result)| result)
            .collect::<Vec<_>>(),
        SchedulerSummary {
            requested_jobs,
            max_concurrency,
        },
    )
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

    pub fn promote_regressions(
        &self,
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
            let language = finding_language(finding).unwrap_or("unknown");
            let plugin_artifacts = self
                .registry
                .get(language)
                .and_then(|plugin| plugin.promote_regression(root, &report, finding, finding_index))
                .unwrap_or_else(|_| {
                    generic_regression_promotion_artifact(language, finding, finding_index)
                });
            artifacts.extend(plugin_artifacts);
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
            quality: VerificationQuality::default(),
            suggested_next_steps: suggested_next_steps(language),
        };
        assign_finding_ids(&mut report);
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
        refresh_report_quality(&mut report);
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
                quality: VerificationQuality::default(),
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
        assign_finding_ids(&mut report);
        self.add_observation_artifacts(
            root,
            language.unwrap_or("changed"),
            &mut report,
            write_observations,
            differential_enabled,
        )?;
        assign_finding_ids(&mut report);
        refresh_report_quality(&mut report);
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

        let mut report = VerificationReport {
            project: Some(project),
            targets: vec![target],
            plan: Some(plan),
            artifacts,
            runs: vec![],
            coverage: vec![],
            findings: vec![],
            quality: VerificationQuality::default(),
            suggested_next_steps: suggested_next_steps(language),
        };
        refresh_report_quality(&mut report);
        Ok(report)
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
        refresh_report_quality(&mut report);
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
        refresh_report_quality(&mut report);
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
            artifacts.push(differential_replay_artifact(language, &report.targets)?);
            report.findings.append(&mut failures);
        }

        artifacts.extend(feedback_artifacts(language, report));
        artifacts.extend(repro_artifacts(language, &report.findings));
        artifacts.extend(assertion_candidate_artifacts(language, &report.findings)?);
        artifacts.extend(corpus_entry_artifacts(language, &report.findings)?);
        artifacts.extend(candidate_patch_artifacts(language, &report.findings));
        artifacts.extend(regression_artifacts(language, &report.findings));
        artifacts.extend(evolution_artifacts(language, report, &artifacts));
        artifacts.extend(replay_result_artifacts(language, report, &artifacts)?);
        artifacts.extend(budget_plan_artifacts(language, report)?);
        artifacts.extend(mutation_trend_artifacts(root, language, report)?);

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

fn finding_language(finding: &Failure) -> Option<&str> {
    finding
        .target_id
        .as_deref()
        .and_then(|target_id| target_id.split_once(':').map(|(language, _)| language))
}

fn generic_regression_promotion_artifact(
    language: &str,
    finding: &Failure,
    index: usize,
) -> Vec<GeneratedArtifact> {
    let language = if language.is_empty() {
        "unknown"
    } else {
        language
    };
    let mut contents = String::from("# Regression Promotion\n\n");
    contents.push_str("Generated by veritas. Review before committing.\n\n");
    contents.push_str(&format!("- Finding: {}\n", finding.message));
    contents.push_str(&format!("- Severity: {:?}\n", finding.severity));
    contents.push_str(&format!("- Command: `{}`\n", finding.command));
    if let Some(target_id) = &finding.target_id {
        contents.push_str(&format!("- Target: `{target_id}`\n"));
    }
    if let Some(repro) = &finding.repro {
        contents.push_str(&format!("- Repro command: `{}`\n", repro.command));
        if let Some(path) = &repro.path {
            contents.push_str(&format!("- Repro path: `{path}`\n"));
        }
        if let Some(input) = &repro.input {
            contents.push_str(&format!("- Repro input: `{}`\n", input.trim()));
        }
    }
    contents.push_str("\n## Next Step\n\n");
    contents.push_str("No executable regression promoter is registered for this finding language. Add a handwritten test owned by the target package, then rerun `veritas verify`.\n");

    vec![GeneratedArtifact {
        id: format!("{language}-promoted-regression-{index}"),
        language: language.to_string(),
        kind: ArtifactKind::RegressionTest,
        target_id: finding
            .target_id
            .clone()
            .unwrap_or_else(|| format!("{language}:unknown")),
        path: Utf8PathBuf::from(format!(
            ".veritas/regressions/promoted/{language}_{index}.md"
        )),
        contents,
        description: "Generic regression promotion guidance".to_string(),
        status: ArtifactStatus::Planned,
    }]
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

pub fn accept_quality_baseline(root: &Path) -> Result<QualityBaselineSummary> {
    let report = read_saved_report(root)?;
    let score = confidence_score_for_root(root, &report);
    let baseline = QualityBaseline {
        version: 1,
        quality: report.quality.clone(),
        confidence: score.score,
    };
    let path = Utf8PathBuf::from(".veritas/baselines/quality.json");
    let full_path = root.join(&path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&full_path, serde_json::to_string_pretty(&baseline)?)
        .with_context(|| format!("failed to write {}", full_path.display()))?;
    Ok(QualityBaselineSummary {
        path,
        confidence: score.score,
        mutation_score: report.quality.mutation.score_percent,
    })
}

pub fn quality_baseline(root: &Path) -> Result<Option<QualityBaseline>> {
    let path = root.join(".veritas/baselines/quality.json");
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents)
        .map(Some)
        .with_context(|| format!("failed to parse {}", path.display()))
}

pub fn replay_corpus(
    root: &Path,
    dry_run: bool,
    timeout_seconds: u64,
) -> Result<CorpusReplaySummary> {
    let entries = read_corpus_entries(root)?;
    let start = Instant::now();
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut skipped = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;

    for entry in entries {
        if !is_executable_replay_command(&entry.replay_command) {
            skipped += 1;
            commands.push(skipped_command_record(
                root,
                &entry.replay_command,
                "corpus replay command is guidance, not an executable test command",
            )?);
            continue;
        }
        if dry_run {
            skipped += 1;
            commands.push(skipped_command_record(
                root,
                &entry.replay_command,
                "dry run",
            )?);
            continue;
        }
        let command = run_shell_command(root, &entry.replay_command, timeout_seconds)?;
        match command.status {
            RunStatus::Passed => passed += 1,
            RunStatus::Failed => {
                failed += 1;
                failures.push(Failure {
                    id: None,
                    message: format!("corpus replay failed for `{}`", entry.target_id),
                    severity: FailureSeverity::Error,
                    target_id: Some(entry.target_id.clone()),
                    artifact_id: None,
                    command: entry.replay_command.clone(),
                    stdout_excerpt: excerpt_text(&command.stdout),
                    stderr_excerpt: excerpt_text(&command.stderr),
                    repro: Some(ReproCase {
                        command: entry.replay_command.clone(),
                        input: entry.input.clone(),
                        path: entry.path.clone(),
                    }),
                });
            }
            RunStatus::Skipped => skipped += 1,
        }
        commands.push(command);
    }

    let status = if failed > 0 {
        RunStatus::Failed
    } else if passed > 0 {
        RunStatus::Passed
    } else {
        RunStatus::Skipped
    };
    let mut quality = VerificationQuality::default();
    quality.regression.corpus_entries = passed + failed + skipped;
    quality.regression.corpus_replayed = passed + failed;
    quality.regression.corpus_passed = passed;
    quality.regression.corpus_failed = failed;
    quality.regression.corpus_skipped = skipped;
    let run = TestRunResult {
        language: "corpus".to_string(),
        status,
        commands,
        failures: failures.clone(),
        duration_ms: start.elapsed().as_millis(),
        quality,
    };
    let mut report = VerificationReport {
        project: None,
        targets: Vec::new(),
        plan: None,
        artifacts: vec![corpus_replay_artifact(&run)?],
        runs: vec![run],
        coverage: Vec::new(),
        findings: failures,
        quality: VerificationQuality::default(),
        suggested_next_steps: vec![
            "Promote failing corpus entries into package-owned regression tests.".to_string(),
            "Remove stale corpus metadata when replay commands are no longer valid.".to_string(),
        ],
    };
    assign_finding_ids(&mut report);
    refresh_report_quality(&mut report);
    if !dry_run {
        write_artifacts(root, &mut report.artifacts)?;
    }
    Ok(CorpusReplaySummary { dry_run, report })
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

fn read_corpus_entries(root: &Path) -> Result<Vec<CorpusEntry>> {
    let corpus_dir = root.join(".veritas/corpus");
    if !corpus_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&corpus_dir)
        .with_context(|| format!("failed to read {}", corpus_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        entries.push(
            serde_json::from_str(&contents)
                .with_context(|| format!("failed to parse {}", path.display()))?,
        );
    }
    Ok(entries)
}

fn is_executable_replay_command(command: &str) -> bool {
    let trimmed = command.trim_start();
    trimmed.starts_with("cargo ")
        || trimmed.starts_with("go ")
        || trimmed.starts_with("(cd ")
        || trimmed.starts_with("./")
}

fn run_shell_command(root: &Path, command: &str, timeout_seconds: u64) -> Result<CommandRecord> {
    let start = Instant::now();
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start corpus replay command `{command}`"))?;
    let timeout = Duration::from_secs(timeout_seconds.max(1));
    loop {
        if child
            .try_wait()
            .with_context(|| format!("failed to poll corpus replay command `{command}`"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .with_context(|| format!("failed to collect corpus replay command `{command}`"))?;
            return Ok(CommandRecord {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), command.to_string()],
                cwd: utf8_path(root)?,
                exit_code: output.status.code(),
                status: if output.status.success() {
                    RunStatus::Passed
                } else {
                    RunStatus::Failed
                },
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                duration_ms: start.elapsed().as_millis(),
            });
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output().with_context(|| {
                format!("failed to collect timed-out corpus replay `{command}`")
            })?;
            return Ok(CommandRecord {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), command.to_string()],
                cwd: utf8_path(root)?,
                exit_code: output.status.code(),
                status: RunStatus::Failed,
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: format!(
                    "corpus replay command timed out after {}s\n{}",
                    timeout.as_secs(),
                    String::from_utf8_lossy(&output.stderr)
                ),
                duration_ms: start.elapsed().as_millis(),
            });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn skipped_command_record(root: &Path, command: &str, reason: &str) -> Result<CommandRecord> {
    Ok(CommandRecord {
        program: "veritas".to_string(),
        args: vec!["replay-corpus".to_string(), command.to_string()],
        cwd: utf8_path(root)?,
        exit_code: None,
        status: RunStatus::Skipped,
        stdout: String::new(),
        stderr: reason.to_string(),
        duration_ms: 0,
    })
}

fn corpus_replay_artifact(run: &TestRunResult) -> Result<GeneratedArtifact> {
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "mode": "corpus_replay",
        "status": run.status,
        "commands": run.commands.len(),
        "passed": run.quality.regression.corpus_passed,
        "failed": run.quality.regression.corpus_failed,
        "skipped": run.quality.regression.corpus_skipped,
    }))?;
    Ok(GeneratedArtifact {
        id: "corpus-replay".to_string(),
        language: "corpus".to_string(),
        kind: ArtifactKind::CorpusReplay,
        target_id: "corpus:replay".to_string(),
        path: Utf8PathBuf::from(".veritas/corpus/replay_result.json"),
        contents,
        description: "Corpus replay execution summary".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn excerpt_text(text: &str) -> String {
    text.lines().take(40).collect::<Vec<_>>().join("\n")
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

fn differential_replay_artifact(
    language: &str,
    targets: &[VerificationTarget],
) -> Result<GeneratedArtifact> {
    let targets = targets
        .iter()
        .filter(|target| target.kind == TargetKind::Function)
        .filter(|target| target.signature.is_some())
        .map(|target| {
            serde_json::json!({
                "target_id": target.id,
                "path": target.path,
                "symbol": target.symbol,
                "signature": target.signature,
                "line_range": target.line_range,
                "risk": target.risk,
                "cases": replay_cases_for_target(language, target),
            })
        })
        .collect::<Vec<_>>();
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "language": language,
        "mode": "behavioral_replay_manifest",
        "description": "Reviewable old/new replay cases for selected public APIs. Persist this artifact before a risky change, rerun veritas after the change, and compare case intent plus promoted assertions.",
        "targets": targets,
    }))?;

    Ok(GeneratedArtifact {
        id: format!("{language}-differential-replay"),
        language: language.to_string(),
        kind: ArtifactKind::DifferentialReplay,
        target_id: format!("{language}:project"),
        path: Utf8PathBuf::from(format!(".veritas/differential/{language}_replay.json")),
        contents,
        description: "Behavioral replay manifest for selected public APIs".to_string(),
        status: ArtifactStatus::Planned,
    })
}

fn replay_cases_for_target(language: &str, target: &VerificationTarget) -> Vec<serde_json::Value> {
    let signature = target.signature.as_deref().unwrap_or_default();
    let mut cases = Vec::new();
    let lowered_symbol = target
        .symbol
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if signature.contains("&str") || signature.contains("String") || signature.contains("string") {
        cases.push(serde_json::json!({
            "name": "empty_string",
            "inputs": [""],
            "assertion": "replay old/new behavior for empty input and invalid formatting"
        }));
        cases.push(serde_json::json!({
            "name": "trimmed_token",
            "inputs": ["  veritas-seed  "],
            "assertion": "replay old/new behavior for whitespace-normalized input"
        }));
    }
    if signature_contains_numeric(signature) {
        cases.push(serde_json::json!({
            "name": "zero_boundary",
            "inputs": [0],
            "assertion": "replay old/new behavior at zero boundary"
        }));
        cases.push(serde_json::json!({
            "name": "one_boundary",
            "inputs": [1],
            "assertion": "replay old/new behavior at one boundary"
        }));
    }
    if signature.contains("bool") {
        cases.push(serde_json::json!({
            "name": "boolean_edges",
            "inputs": [false, true],
            "assertion": "replay old/new behavior for both boolean branches"
        }));
    }
    if lowered_symbol.contains("auth")
        || lowered_symbol.contains("permission")
        || lowered_symbol.contains("refund")
    {
        cases.push(serde_json::json!({
            "name": "permission_boundary",
            "inputs": ["admin", "support", "guest"],
            "assertion": "assert privileged, delegated, and denied principals keep their old/new behavior"
        }));
    }
    if lowered_symbol.contains("parse")
        || lowered_symbol.contains("invoice")
        || lowered_symbol.contains("total")
    {
        cases.push(serde_json::json!({
            "name": "parser_invalid_input",
            "inputs": ["", "total=0", "not-a-total"],
            "assertion": "assert parser invalid-input behavior is intentional before accepting the replay"
        }));
    }

    if cases.is_empty() {
        cases.push(serde_json::json!({
            "name": "targeted_behavior",
            "inputs": [],
            "assertion": format!("add a promoted {language} assertion for this public API before accepting behavior changes")
        }));
    }
    cases
}

fn signature_contains_numeric(signature: &str) -> bool {
    [
        "i8", "i16", "i32", "i64", "isize", "u8", "u16", "u32", "u64", "usize", "int", "int8",
        "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32",
        "float64",
    ]
    .iter()
    .any(|needle| signature.contains(needle))
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

fn assertion_candidate_artifacts(
    language: &str,
    findings: &[Failure],
) -> Result<Vec<GeneratedArtifact>> {
    findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| should_generate_regression_artifact(finding))
        .map(|(index, finding)| {
            let candidate = assertion_candidate(language, finding);
            let contents = serde_json::to_string_pretty(&candidate)?;
            Ok(GeneratedArtifact {
                id: format!("{language}-assertion-candidate-{index}"),
                language: language.to_string(),
                kind: ArtifactKind::AssertionCandidate,
                target_id: candidate.target_id.clone(),
                path: Utf8PathBuf::from(format!(".veritas/assertions/{language}_{index}.json")),
                contents,
                description: "Structured assertion candidate for AI or human regression promotion"
                    .to_string(),
                status: ArtifactStatus::Planned,
            })
        })
        .collect()
}

fn assertion_candidate(language: &str, finding: &Failure) -> AssertionCandidate {
    let source = assertion_source(finding);
    let domain = assertion_domain(finding);
    let target_id = finding
        .target_id
        .clone()
        .unwrap_or_else(|| format!("{language}:unknown"));
    let seed_inputs = assertion_seed_inputs(finding, &domain);
    let replay_command = finding
        .repro
        .as_ref()
        .map(|repro| repro.command.clone())
        .or_else(|| Some(finding.command.clone()));

    AssertionCandidate {
        language: language.to_string(),
        target_id,
        finding_id: finding.id.clone(),
        source,
        domain,
        title: finding.message.clone(),
        seed_inputs,
        expected_behavior: expected_behavior_text(language, finding, &domain),
        replay_command,
    }
}

fn assertion_source(finding: &Failure) -> AssertionSource {
    if finding.message.contains("mutation survived") {
        AssertionSource::MutationSurvivor
    } else if finding.message.contains("fuzz") || finding.command.contains("-fuzz=") {
        AssertionSource::FuzzRepro
    } else if finding.message.contains("cargo test failed")
        || finding.message.contains("go test failed")
    {
        AssertionSource::GeneratedTestFailure
    } else if finding.message.contains("differential") || finding.message.contains("replay") {
        AssertionSource::DifferentialReplay
    } else {
        AssertionSource::CoverageGap
    }
}

fn assertion_domain(finding: &Failure) -> AssertionDomain {
    let text = format!(
        "{} {} {}",
        finding.message,
        finding.target_id.as_deref().unwrap_or_default(),
        finding.command
    )
    .to_ascii_lowercase();
    if text.contains("auth")
        || text.contains("permission")
        || text.contains("token")
        || text.contains("principal")
    {
        AssertionDomain::AuthPermission
    } else if text.contains("money")
        || text.contains("price")
        || text.contains("invoice")
        || text.contains("total")
        || text.contains("refund")
        || text.contains("discount")
    {
        AssertionDomain::Money
    } else if text.contains("parse")
        || text.contains("format")
        || text.contains("normalize")
        || text.contains("trim")
    {
        AssertionDomain::Parsing
    } else if text.contains("json")
        || text.contains("serial")
        || text.contains("marshal")
        || text.contains("deserialize")
    {
        AssertionDomain::Serialization
    } else if text.contains("error")
        || text.contains("err")
        || text.contains("none")
        || text.contains("nil")
        || text.contains("null")
    {
        AssertionDomain::ErrorHandling
    } else if text.contains("boundary")
        || text.contains("comparison")
        || text.contains("<")
        || text.contains(">")
        || text.contains("zero")
    {
        AssertionDomain::Boundary
    } else {
        AssertionDomain::General
    }
}

fn assertion_seed_inputs(finding: &Failure, domain: &AssertionDomain) -> Vec<String> {
    if let Some(input) = finding
        .repro
        .as_ref()
        .and_then(|repro| repro.input.clone())
        .or_else(|| extract_minimized_input(&finding.stdout_excerpt))
        .or_else(|| extract_minimized_input(&finding.stderr_excerpt))
    {
        return vec![input.trim().to_string()];
    }

    match domain {
        AssertionDomain::AuthPermission => vec![
            "principal=admin".to_string(),
            "principal=support".to_string(),
            "principal=guest".to_string(),
        ],
        AssertionDomain::Money => vec![
            "amount=0".to_string(),
            "amount=1".to_string(),
            "amount=100".to_string(),
            "amount=101".to_string(),
        ],
        AssertionDomain::Parsing => vec![
            "input=".to_string(),
            "input=  veritas-seed  ".to_string(),
            "input=not-a-valid-value".to_string(),
        ],
        AssertionDomain::Serialization => {
            vec!["{}".to_string(), "{\"id\":\"veritas\"}".to_string()]
        }
        AssertionDomain::ErrorHandling => vec!["missing".to_string(), "invalid".to_string()],
        AssertionDomain::Boundary => vec!["0".to_string(), "1".to_string(), "-1".to_string()],
        AssertionDomain::General => vec!["veritas-seed".to_string()],
    }
}

fn expected_behavior_text(language: &str, finding: &Failure, domain: &AssertionDomain) -> String {
    let mutation = finding
        .repro
        .as_ref()
        .and_then(|repro| parse_replacement(&repro.command));
    if let Some((from, to)) = mutation {
        return format!(
            "Assert the intended {language} behavior at the smallest seed that distinguishes `{from}` from `{to}`."
        );
    }

    match domain {
        AssertionDomain::AuthPermission => {
            "Assert allowed, delegated, and denied principals explicitly.".to_string()
        }
        AssertionDomain::Money => {
            "Assert exact cents/rounding/refund behavior at zero and threshold boundaries."
                .to_string()
        }
        AssertionDomain::Parsing => {
            "Assert accepted, trimmed, and invalid input behavior explicitly.".to_string()
        }
        AssertionDomain::Serialization => {
            "Assert stable round-trip and missing-field behavior explicitly.".to_string()
        }
        AssertionDomain::ErrorHandling => {
            "Assert the error/empty/nil path, not only that the call returns.".to_string()
        }
        AssertionDomain::Boundary => {
            "Assert the exact value on both sides of the changed boundary.".to_string()
        }
        AssertionDomain::General => {
            "Assert the expected output or state transition for the recorded repro.".to_string()
        }
    }
}

fn corpus_entry_artifacts(language: &str, findings: &[Failure]) -> Result<Vec<GeneratedArtifact>> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| {
            let repro = finding.repro.as_ref()?;
            let input = repro
                .input
                .clone()
                .or_else(|| extract_minimized_input(&finding.stdout_excerpt))
                .or_else(|| extract_minimized_input(&finding.stderr_excerpt));
            if input.is_none() && repro.path.is_none() {
                return None;
            }
            Some((index, finding, repro, input))
        })
        .map(|(index, finding, repro, input)| {
            let target_id = finding
                .target_id
                .clone()
                .unwrap_or_else(|| format!("{language}:unknown"));
            let entry = CorpusEntry {
                language: language.to_string(),
                target_id: target_id.clone(),
                finding_id: finding.id.clone(),
                source: assertion_source(finding),
                input,
                path: repro.path.clone(),
                replay_command: repro.command.clone(),
            };
            Ok(GeneratedArtifact {
                id: format!("{language}-corpus-entry-{index}"),
                language: language.to_string(),
                kind: ArtifactKind::CorpusEntry,
                target_id,
                path: Utf8PathBuf::from(format!(".veritas/corpus/{language}_{index}.json")),
                contents: serde_json::to_string_pretty(&entry)?,
                description: "Persistent corpus seed metadata for replaying a discovered repro"
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

fn regression_artifacts(language: &str, findings: &[Failure]) -> Vec<GeneratedArtifact> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, failure)| {
            if !should_generate_regression_artifact(failure) {
                return None;
            }
            let target_id = failure.target_id.as_deref().unwrap_or("unknown");
            let repro = failure.repro.as_ref();
            let mut contents = String::from("# Generated Regression Assertion\n\n");
            contents.push_str("Generated by veritas. Review before committing.\n\n");
            contents.push_str(&format!("- Finding: {}\n", failure.message));
            contents.push_str(&format!("- Severity: {:?}\n", failure.severity));
            contents.push_str(&format!("- Target: `{target_id}`\n"));
            contents.push_str(&format!("- Original command: `{}`\n", failure.command));
            if let Some(repro) = repro {
                contents.push_str(&format!("- Repro command: `{}`\n", repro.command));
                if let Some(path) = &repro.path {
                    contents.push_str(&format!("- Repro path: `{path}`\n"));
                }
                if let Some(input) = &repro.input {
                    contents.push_str(&format!("- Repro input: `{}`\n", input.trim()));
                }
            }
            if let Some(input) = extract_minimized_input(&failure.stdout_excerpt)
                .or_else(|| extract_minimized_input(&failure.stderr_excerpt))
            {
                contents.push_str(&format!("- Minimized input: `{}`\n", input.trim()));
            }

            contents.push_str("\n## Assertion To Promote\n\n");
            if failure.message.contains("mutation survived") {
                contents.push_str(&mutation_regression_text(language, failure));
            } else if let Some(repro) = repro.filter(|repro| {
                repro
                    .path
                    .as_ref()
                    .is_some_and(|path| path.starts_with("testdata/fuzz"))
            }) {
                contents.push_str(&format!(
                    "Keep the Go fuzz corpus entry `{}` and add a named unit regression that asserts the intended behavior for that input. Run `{}` after promotion.\n",
                    repro.path.as_ref().expect("checked path"),
                    repro.command
                ));
            } else if failure.message.contains("cargo test failed")
                || failure.message.contains("go test failed")
            {
                contents.push_str("Promote the generated failing harness case into a stable handwritten regression test owned by the target package. The assertion should encode the expected behavior directly, not only `does not panic`.\n");
            } else {
                contents.push_str("Persist the minimized input as a regression case and assert the intended behavior before accepting the finding.\n");
            }

            Some(GeneratedArtifact {
                id: format!("{language}-regression-{index}"),
                language: language.to_string(),
                kind: ArtifactKind::RegressionTest,
                target_id: failure
                    .target_id
                    .clone()
                    .unwrap_or_else(|| format!("{language}:unknown")),
                path: Utf8PathBuf::from(format!(".veritas/regressions/{language}_{index}.md")),
                contents,
                description: "Generated regression assertion to promote from verification feedback"
                    .to_string(),
                status: ArtifactStatus::Planned,
            })
        })
        .collect()
}

fn evolution_artifacts(
    language: &str,
    report: &VerificationReport,
    pending_artifacts: &[GeneratedArtifact],
) -> Vec<GeneratedArtifact> {
    let mutation_findings = report
        .findings
        .iter()
        .filter(|finding| finding.message.contains("mutation survived"))
        .collect::<Vec<_>>();
    let generated_failures = report
        .findings
        .iter()
        .filter(|finding| finding_is_generated_test_failure(report, finding))
        .collect::<Vec<_>>();

    if mutation_findings.is_empty() && generated_failures.is_empty() {
        return Vec::new();
    }

    let mut contents = String::from("# Evolution Plan\n\n");
    contents.push_str("Generated by veritas. Use this as the next candidate-generation loop for AI-assisted verification.\n\n");

    if !mutation_findings.is_empty() {
        contents.push_str("## Surviving Mutants\n\n");
        contents.push_str(
            "Generate or promote assertions that kill these surviving behavioral changes:\n\n",
        );
        for finding in &mutation_findings {
            contents.push_str(&format!("- {}\n", finding.message));
            if let Some(repro) = &finding.repro {
                contents.push_str(&format!("  - Repro: `{}`\n", repro.command));
            }
        }
        contents.push('\n');
    }

    if !generated_failures.is_empty() {
        contents.push_str("## Generated Harness Failures\n\n");
        contents.push_str("Minimize these generated-test or fuzz failures, then promote them into owned regression tests:\n\n");
        for finding in &generated_failures {
            contents.push_str(&format!("- {}\n", finding.message));
            contents.push_str(&format!("  - Command: `{}`\n", finding.command));
        }
        contents.push('\n');
    }

    contents.push_str("## Next Generation\n\n");
    contents.push_str("- Prefer one new assertion per survivor or minimized input.\n");
    contents.push_str("- Re-run `veritas verify` and compare mutation score, generated-test failures, and fuzz repro counts.\n");
    contents.push_str(
        "- Keep candidates that raise score or convert a finding into a stable regression test.\n",
    );

    let mut artifacts = vec![GeneratedArtifact {
        id: format!("{language}-evolution-plan"),
        language: language.to_string(),
        kind: ArtifactKind::EvolutionPlan,
        target_id: format!("{language}:evolution"),
        path: Utf8PathBuf::from(format!(".veritas/evolution/{language}.md")),
        contents,
        description: "Next-generation verification candidate plan from current findings"
            .to_string(),
        status: ArtifactStatus::Planned,
    }];

    let candidates = report
        .artifacts
        .iter()
        .chain(pending_artifacts.iter())
        .filter(|artifact| artifact.kind == ArtifactKind::AssertionCandidate)
        .map(|artifact| {
            serde_json::json!({
                "source_artifact": artifact.path,
                "target_id": artifact.target_id,
                "candidate_kind": "assertion",
                "fitness_signal": "raises mutation score, reduces active findings, or converts a repro into corpus replay",
                "keep_if": "the candidate kills a survivor, replays a corpus entry, or increases veritas score",
            })
        })
        .collect::<Vec<_>>();
    if !candidates.is_empty() {
        artifacts.push(GeneratedArtifact {
            id: format!("{language}-evolution-candidates"),
            language: language.to_string(),
            kind: ArtifactKind::EvolutionCandidate,
            target_id: format!("{language}:evolution"),
            path: Utf8PathBuf::from(format!(".veritas/evolution/{language}_candidates.json")),
            contents: serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "language": language,
                "fitness": [
                    "mutation_score_delta",
                    "surviving_mutants_delta",
                    "corpus_replay_pass_rate",
                    "confidence_score_delta"
                ],
                "candidates": candidates
            }))
            .unwrap_or_else(|_| "{\"version\":1,\"candidates\":[]}".to_string()),
            description: "Structured evolutionary candidate queue for the next verification loop"
                .to_string(),
            status: ArtifactStatus::Planned,
        });
    }

    artifacts
}

fn replay_result_artifacts(
    language: &str,
    report: &VerificationReport,
    pending_artifacts: &[GeneratedArtifact],
) -> Result<Vec<GeneratedArtifact>> {
    let replay_artifacts = report
        .artifacts
        .iter()
        .chain(pending_artifacts.iter())
        .filter(|artifact| artifact.kind == ArtifactKind::DifferentialReplay)
        .collect::<Vec<_>>();
    if replay_artifacts.is_empty() {
        return Ok(Vec::new());
    }

    let mut targets = 0usize;
    let mut cases = 0usize;
    for artifact in &replay_artifacts {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&artifact.contents) else {
            continue;
        };
        let replay_targets = value["targets"].as_array().map(Vec::len).unwrap_or(0);
        targets += replay_targets;
        cases += value["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|target| target["cases"].as_array())
            .map(Vec::len)
            .sum::<usize>();
    }

    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "language": language,
        "mode": "differential_replay_result",
        "manifests": replay_artifacts.len(),
        "targets": targets,
        "cases": cases,
        "status": "planned",
        "next_step": "Persist this result with the pre-change manifest, rerun after the AI change, and promote changed observations into assertion candidates."
    }))?;

    Ok(vec![GeneratedArtifact {
        id: format!("{language}-differential-replay-result"),
        language: language.to_string(),
        kind: ArtifactKind::ReplayResult,
        target_id: format!("{language}:differential"),
        path: Utf8PathBuf::from(format!(".veritas/differential/{language}_result.json")),
        contents,
        description: "Differential replay execution summary for selected public APIs".to_string(),
        status: ArtifactStatus::Planned,
    }])
}

fn budget_plan_artifacts(
    language: &str,
    report: &VerificationReport,
) -> Result<Vec<GeneratedArtifact>> {
    let Some(plan) = &report.plan else {
        return Ok(Vec::new());
    };
    let max_concurrency = report
        .runs
        .iter()
        .flat_map(|run| run.commands.iter())
        .filter(|command| command.status != RunStatus::Skipped)
        .count()
        .max(1);
    let resource_limits = report
        .runs
        .iter()
        .flat_map(|run| run.commands.iter())
        .filter_map(|command| {
            if command.program.contains("systemd-run")
                || command
                    .args
                    .iter()
                    .any(|arg| arg.contains("MemoryMax") || arg.contains("CPUQuota"))
            {
                Some(command_line(&command.program, &command.args))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let budget = CommandBudget {
        language: language.to_string(),
        target_id: plan.target_id.clone(),
        budget_seconds: plan.budget_seconds,
        max_concurrency,
        resource_limits,
    };

    Ok(vec![GeneratedArtifact {
        id: format!("{language}-budget-plan"),
        language: language.to_string(),
        kind: ArtifactKind::BudgetPlan,
        target_id: plan.target_id.clone(),
        path: Utf8PathBuf::from(format!(".veritas/budgets/{language}.json")),
        contents: serde_json::to_string_pretty(&budget)?,
        description: "Command budget and resource-limit metadata for large-repo execution"
            .to_string(),
        status: ArtifactStatus::Planned,
    }])
}

fn mutation_trend_artifacts(
    root: &Path,
    language: &str,
    report: &VerificationReport,
) -> Result<Vec<GeneratedArtifact>> {
    let mut quality = VerificationQuality::default();
    for run in &report.runs {
        quality.mutation.generated += run.quality.mutation.generated;
        quality.mutation.executed += run.quality.mutation.executed;
        quality.mutation.killed += run.quality.mutation.killed;
        quality.mutation.survived += run.quality.mutation.survived;
        quality.mutation.skipped += run.quality.mutation.skipped;
        merge_mutation_attribution(
            &mut quality.mutation.by_domain,
            &run.quality.mutation.by_domain,
        );
        merge_mutation_attribution(
            &mut quality.mutation.by_operator,
            &run.quality.mutation.by_operator,
        );
    }
    quality.mutation.score_percent = (quality.mutation.killed * 100)
        .checked_div(quality.mutation.executed)
        .map(|score| score.try_into().unwrap_or(100));
    if quality.mutation.generated == 0 {
        return Ok(Vec::new());
    }
    let baseline = quality_baseline(root)?;
    let delta = baseline
        .as_ref()
        .map(|baseline| quality_delta(&quality, 0, baseline));
    let contents = serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "language": language,
        "mutation": quality.mutation,
        "baseline_delta": delta,
        "threshold_hints": {
            "minimum_score": quality.mutation.score_percent,
            "maximum_survivors": quality.mutation.survived,
            "gate_on_regression": baseline.is_some()
        }
    }))?;
    Ok(vec![GeneratedArtifact {
        id: format!("{language}-mutation-trend"),
        language: language.to_string(),
        kind: ArtifactKind::MutationTrend,
        target_id: format!("{language}:mutation"),
        path: Utf8PathBuf::from(format!(".veritas/trends/{language}_mutation.json")),
        contents,
        description: "Mutation score attribution and baseline trend data".to_string(),
        status: ArtifactStatus::Planned,
    }])
}

fn should_generate_regression_artifact(failure: &Failure) -> bool {
    failure.message.contains("mutation survived")
        || failure.message.contains("fuzz")
        || failure.message.contains("minimal failing input")
        || failure.message.contains("cargo test failed")
        || failure.message.contains("go test failed")
}

fn mutation_regression_text(language: &str, failure: &Failure) -> String {
    let mut out = String::new();
    let symbol = failure
        .target_id
        .as_deref()
        .and_then(|target_id| target_id.rsplit_once(':').map(|(_, symbol)| symbol))
        .unwrap_or("target");
    let Some(repro) = &failure.repro else {
        out.push_str(
            "Add a focused assertion that fails when the described mutation is applied.\n",
        );
        return out;
    };
    let (from, to) = parse_replacement(&repro.command).unwrap_or(("old", "new"));
    out.push_str(&format!(
        "Create a focused {language} regression for `{symbol}` that fails if `{from}` is replaced with `{to}`.\n\n"
    ));
    match language {
        "rust" => {
            out.push_str("Suggested Rust test shape:\n\n```rust\n#[test]\nfn veritas_mutation_regression() {\n    // Arrange the boundary or branch named by the finding.\n    // Assert the exact expected value so the mutant is killed.\n}\n```\n");
        }
        "go" => {
            out.push_str("Suggested Go test shape:\n\n```go\nfunc TestVeritasMutationRegression(t *testing.T) {\n\t// Arrange the boundary or branch named by the finding.\n\t// Assert the exact expected value so the mutant is killed.\n}\n```\n");
        }
        _ => {
            out.push_str("Suggested test shape: add a named regression that asserts the exact old/new behavior at the mutated boundary.\n");
        }
    }
    out
}

fn parse_replacement(command: &str) -> Option<(&str, &str)> {
    let rest = command.strip_prefix("replace `")?;
    let (from, rest) = rest.split_once("` with `")?;
    let (to, _) = rest.split_once('`')?;
    Some((from, to))
}

fn command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
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
            if matches!(
                file_name.as_ref(),
                "veritas_generated" | "veritas_regressions"
            ) && parent_dir_name(&path) == Some("tests")
            {
                paths.push(relative_utf8(root, &path)?);
                continue;
            }
            collect_generated_artifact_paths(root, &path, paths)?;
        } else if file_name == "veritas_fuzz_test.go"
            || is_generated_regression_file(&file_name, &path)
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

fn is_generated_regression_file(file_name: &str, path: &Path) -> bool {
    if file_name.starts_with("veritas_regression_")
        && file_name.ends_with(".rs")
        && parent_dir_name(path) == Some("tests")
    {
        return true;
    }
    file_name.starts_with("veritas_regression_") && file_name.ends_with("_test.go")
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

fn utf8_path(path: &Path) -> Result<Utf8PathBuf> {
    Utf8PathBuf::from_path_buf(path.to_path_buf()).map_err(|path| {
        anyhow!(
            "path contains non-UTF-8 data and cannot be represented: {}",
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
        quality: VerificationQuality::default(),
    }
}

fn refresh_report_quality(report: &mut VerificationReport) {
    let mut quality = VerificationQuality::default();

    for run in &report.runs {
        quality.mutation.generated += run.quality.mutation.generated;
        quality.mutation.executed += run.quality.mutation.executed;
        quality.mutation.killed += run.quality.mutation.killed;
        quality.mutation.survived += run.quality.mutation.survived;
        quality.mutation.skipped += run.quality.mutation.skipped;
        merge_mutation_attribution(
            &mut quality.mutation.by_domain,
            &run.quality.mutation.by_domain,
        );
        merge_mutation_attribution(
            &mut quality.mutation.by_operator,
            &run.quality.mutation.by_operator,
        );
        quality.fuzz.targets_executed += run.quality.fuzz.targets_executed;
        quality.fuzz.failures += run.quality.fuzz.failures;
        quality.regression.corpus_replayed += run.quality.regression.corpus_replayed;
        quality.regression.corpus_passed += run.quality.regression.corpus_passed;
        quality.regression.corpus_failed += run.quality.regression.corpus_failed;
        quality.regression.corpus_skipped += run.quality.regression.corpus_skipped;
    }

    quality.property.generated_artifacts = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::PropertyTest)
        .count();
    for artifact in report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::PropertyTest)
    {
        quality.property.no_panic_properties += artifact.contents.matches("does_not_panic").count();
        quality.property.deterministic_properties +=
            artifact.contents.matches("is_deterministic").count();
        quality.property.invariant_properties += artifact.contents.matches("prop_assert").count();
    }
    quality.property.strength_score_percent = property_strength_score(&quality.property);
    quality.fuzz.generated_harnesses = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::FuzzHarness)
        .count();
    quality.fuzz.persisted_repros = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::ReproCase)
        .count();
    quality.regression.assertion_candidates = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::AssertionCandidate)
        .count();
    quality.regression.promoted_scaffolds = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::RegressionTest)
        .count();
    quality.regression.corpus_entries = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::CorpusEntry)
        .count();
    if quality.mutation.by_domain.is_empty() && quality.mutation.by_operator.is_empty() {
        for finding in report
            .findings
            .iter()
            .filter(|finding| finding.message.contains("mutation survived"))
        {
            let domain = mutation_domain_label(finding);
            let operator = mutation_operator_label(finding);
            let domain_entry = quality.mutation.by_domain.entry(domain).or_default();
            domain_entry.survived += 1;
            let operator_entry = quality.mutation.by_operator.entry(operator).or_default();
            operator_entry.survived += 1;
        }
    }
    quality.replay.manifests = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::DifferentialReplay)
        .count();
    quality.replay.results = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::ReplayResult)
        .count();
    for artifact in report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::DifferentialReplay)
    {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&artifact.contents) {
            quality.replay.targets += value["targets"].as_array().map(Vec::len).unwrap_or(0);
            quality.replay.cases += value["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|target| target["cases"].as_array())
                .map(Vec::len)
                .sum::<usize>();
        }
    }
    quality.budget.budget_plans = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::BudgetPlan)
        .count();
    quality.budget.skipped_commands = report
        .runs
        .iter()
        .flat_map(|run| run.commands.iter())
        .filter(|command| command.status == RunStatus::Skipped)
        .count();
    quality.budget.timed_out_commands = report
        .runs
        .iter()
        .flat_map(|run| run.commands.iter())
        .filter(|command| {
            command.stderr.contains("timed out") || command.stdout.contains("timed out")
        })
        .count();
    quality.property.failed_generated_tests = report
        .findings
        .iter()
        .filter(|finding| finding_is_generated_test_failure(report, finding))
        .count();

    quality.mutation.score_percent = (quality.mutation.killed * 100)
        .checked_div(quality.mutation.executed)
        .map(|score| score.try_into().unwrap_or(100));

    report.quality = quality;
}

fn merge_mutation_attribution(
    target: &mut BTreeMap<String, MutationAttribution>,
    source: &BTreeMap<String, MutationAttribution>,
) {
    for (key, source) in source {
        let target = target.entry(key.clone()).or_default();
        target.generated += source.generated;
        target.executed += source.executed;
        target.killed += source.killed;
        target.survived += source.survived;
        target.skipped += source.skipped;
    }
}

fn property_strength_score(property: &veritas_plugin_api::PropertyMetrics) -> Option<u8> {
    if property.generated_artifacts == 0 {
        return None;
    }
    let checks = property.no_panic_properties
        + (property.deterministic_properties * 2)
        + (property.invariant_properties * 2);
    Some(((checks * 100) / (property.generated_artifacts * 6)).min(100) as u8)
}

fn mutation_domain_label(finding: &Failure) -> String {
    let text = finding.message.to_ascii_lowercase();
    for domain in [
        "auth/permission",
        "money",
        "parsing/normalization",
        "serialization",
        "error handling",
        "boundary",
    ] {
        if text.contains(domain) {
            return domain.to_string();
        }
    }
    "general".to_string()
}

fn mutation_operator_label(finding: &Failure) -> String {
    let text = finding.message.to_ascii_lowercase();
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
        if text.contains(operator) {
            return operator.to_string();
        }
    }
    "general".to_string()
}

pub fn confidence_score(report: &VerificationReport) -> ConfidenceScore {
    confidence_score_with_baseline(report, None)
}

pub fn confidence_score_for_root(root: &Path, report: &VerificationReport) -> ConfidenceScore {
    let baseline = quality_baseline(root).ok().flatten();
    confidence_score_with_baseline(report, baseline.as_ref())
}

fn confidence_score_with_baseline(
    report: &VerificationReport,
    baseline: Option<&QualityBaseline>,
) -> ConfidenceScore {
    let mut score: i16 = 45;
    let mut positive_signals = Vec::new();
    let mut risks = Vec::new();

    if let Some(mutation_score) = report.quality.mutation.score_percent {
        score += i16::from(mutation_score) / 3;
        positive_signals.push(format!("mutation score is {mutation_score}%"));
    } else {
        risks.push("mutation checks did not execute".to_string());
    }

    if report.quality.mutation.survived > 0 {
        score -= (report.quality.mutation.survived as i16 * 6).min(24);
        risks.push(format!(
            "{} surviving mutant(s) still need assertions",
            report.quality.mutation.survived
        ));
    }
    if report.quality.property.generated_artifacts > 0 {
        score += 8;
        positive_signals.push(format!(
            "{} generated property artifact(s)",
            report.quality.property.generated_artifacts
        ));
    }
    if report.quality.fuzz.targets_executed > 0 {
        score += 8;
        positive_signals.push(format!(
            "{} fuzz target(s) executed",
            report.quality.fuzz.targets_executed
        ));
    }
    if report.quality.regression.assertion_candidates > 0 {
        score += 6;
        positive_signals.push(format!(
            "{} assertion candidate(s) ready for promotion",
            report.quality.regression.assertion_candidates
        ));
    }
    if report.quality.replay.cases > 0 {
        score += 5;
        positive_signals.push(format!(
            "{} differential replay case(s) planned",
            report.quality.replay.cases
        ));
    }
    if report.quality.budget.timed_out_commands > 0 {
        score -= 12;
        risks.push(format!(
            "{} command(s) timed out",
            report.quality.budget.timed_out_commands
        ));
    }
    if report.quality.budget.skipped_commands > 0 {
        score -= 6;
        risks.push(format!(
            "{} command(s) were skipped by budget",
            report.quality.budget.skipped_commands
        ));
    }
    if report.findings.is_empty() {
        score += 10;
        positive_signals.push("no active findings".to_string());
    } else {
        score -= (report.findings.len() as i16 * 2).min(20);
        risks.push(format!("{} active finding(s)", report.findings.len()));
    }

    let score = score.clamp(0, 100) as u8;
    let baseline_delta =
        baseline.map(|baseline| quality_delta(&report.quality, i16::from(score), baseline));
    if let Some(delta) = &baseline_delta {
        if let Some(mutation_delta) = delta.mutation_score_delta {
            if mutation_delta < 0 {
                risks.push(format!(
                    "mutation score regressed by {} point(s) from baseline",
                    mutation_delta.abs()
                ));
            } else if mutation_delta > 0 {
                positive_signals.push(format!(
                    "mutation score improved by {mutation_delta} point(s) from baseline"
                ));
            }
        }
        if delta.surviving_mutants_delta > 0 {
            risks.push(format!(
                "{} more surviving mutant(s) than baseline",
                delta.surviving_mutants_delta
            ));
        }
        if delta.confidence_delta < 0 {
            risks.push(format!(
                "confidence score regressed by {} point(s) from baseline",
                delta.confidence_delta.abs()
            ));
        }
    }
    let grade = if score >= 80 {
        ConfidenceGrade::High
    } else if score >= 55 {
        ConfidenceGrade::Medium
    } else {
        ConfidenceGrade::Low
    };
    let summary = match grade {
        ConfidenceGrade::High => "strong verification signal for the current scope",
        ConfidenceGrade::Medium => "useful signal with remaining promotion or replay work",
        ConfidenceGrade::Low => "limited confidence; close findings or expand verification",
    }
    .to_string();
    let recommended_next_steps = confidence_next_steps(report);

    ConfidenceScore {
        score,
        grade,
        summary,
        positive_signals,
        risks,
        recommended_next_steps,
        baseline_delta,
    }
}

fn quality_delta(
    quality: &VerificationQuality,
    current_confidence_before_findings: i16,
    baseline: &QualityBaseline,
) -> QualityDelta {
    let mutation_score_delta = match (
        quality.mutation.score_percent,
        baseline.quality.mutation.score_percent,
    ) {
        (Some(current), Some(previous)) => Some(i16::from(current) - i16::from(previous)),
        _ => None,
    };
    QualityDelta {
        mutation_score_delta,
        confidence_delta: current_confidence_before_findings - i16::from(baseline.confidence),
        surviving_mutants_delta: quality.mutation.survived as i64
            - baseline.quality.mutation.survived as i64,
        corpus_entries_delta: quality.regression.corpus_entries as i64
            - baseline.quality.regression.corpus_entries as i64,
    }
}

fn confidence_next_steps(report: &VerificationReport) -> Vec<String> {
    let mut steps = Vec::new();
    if report.quality.mutation.survived > 0 {
        steps.push("Promote assertion candidates for surviving mutants.".to_string());
    }
    if report.quality.regression.corpus_entries > 0 {
        steps.push("Replay persisted corpus entries before accepting the AI change.".to_string());
    }
    if report.quality.replay.cases > 0 {
        steps.push("Compare differential replay cases across old/new behavior.".to_string());
    }
    if report.quality.budget.timed_out_commands > 0 || report.quality.budget.skipped_commands > 0 {
        steps.push("Increase budgets or narrow changed-scope verification.".to_string());
    }
    if steps.is_empty() {
        steps.push(
            "Keep the report as a baseline and rerun Veritas after the next AI change.".to_string(),
        );
    }
    steps
}

fn finding_is_generated_test_failure(report: &VerificationReport, finding: &Failure) -> bool {
    if finding.message.contains("fuzz target") || finding.command.contains("-fuzz=") {
        return true;
    }
    if (finding.message.contains("cargo test failed") || finding.message.contains("go test failed"))
        && report.artifacts.iter().any(|artifact| {
            matches!(
                &artifact.kind,
                ArtifactKind::UnitTest
                    | ArtifactKind::PropertyTest
                    | ArtifactKind::FuzzHarness
                    | ArtifactKind::HarnessIndex
            )
        })
    {
        return true;
    }
    let Some(artifact_id) = &finding.artifact_id else {
        return false;
    };
    report
        .artifacts
        .iter()
        .find(|artifact| &artifact.id == artifact_id)
        .is_some_and(|artifact| {
            matches!(
                artifact.kind,
                ArtifactKind::UnitTest
                    | ArtifactKind::PropertyTest
                    | ArtifactKind::FuzzHarness
                    | ArtifactKind::HarnessIndex
                    | ArtifactKind::RegressionTest
            )
        })
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
    use veritas_plugin_api::{
        ArtifactKind, AssertionDomain, Failure, FailureSeverity, LineRange, ReproCase, RiskLevel,
        VerificationReport,
    };

    use super::{
        api_baseline_artifact, assertion_candidate_artifacts, cleanup_generated_artifacts,
        confidence_score, corpus_entry_artifacts, differential_replay_artifact, parse_unified_diff,
        regression_artifacts, run_parallel_jobs, targets_for_changed_files, ChangedFile,
        TargetKind, VerificationTarget,
    };

    #[test]
    fn scheduler_runs_jobs_concurrently_and_preserves_order() {
        let jobs = vec![3_u64, 2, 1];

        let (results, summary) = run_parallel_jobs(jobs, 2, |value| {
            std::thread::sleep(std::time::Duration::from_millis(value * 10));
            value * 2
        });

        assert_eq!(results, vec![6, 4, 2]);
        assert_eq!(summary.requested_jobs, 3);
        assert_eq!(summary.max_concurrency, 2);
    }

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
    fn differential_replay_artifact_includes_seeded_behavior_cases() {
        let targets = vec![function_target_with_signature(
            "rust:src/lib.rs::parse_total",
            "pub fn parse_total(input: &str, cents: u64) -> bool",
        )];

        let artifact =
            differential_replay_artifact("rust", &targets).expect("build replay artifact");

        assert_eq!(artifact.kind, ArtifactKind::DifferentialReplay);
        assert_eq!(
            artifact.path,
            Utf8PathBuf::from(".veritas/differential/rust_replay.json")
        );
        let body: serde_json::Value =
            serde_json::from_str(&artifact.contents).expect("replay JSON should parse");
        let cases = body["targets"][0]["cases"]
            .as_array()
            .expect("cases should be present");
        let names = cases
            .iter()
            .filter_map(|case| case["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"empty_string"));
        assert!(names.contains(&"zero_boundary"));
        assert!(names.contains(&"boolean_edges"));
        assert!(names.contains(&"parser_invalid_input"));
    }

    #[test]
    fn regression_artifacts_promote_mutation_findings() {
        let finding = Failure {
            id: None,
            message: "mutation survived in `authorize_refund`: comparison boundary mutation"
                .to_string(),
            severity: FailureSeverity::Warning,
            target_id: Some("rust:src/lib.rs::authorize_refund".to_string()),
            artifact_id: Some("rust-mutation-src_lib_rs_authorize_refund".to_string()),
            command: "veritas mutation".to_string(),
            stdout_excerpt: String::new(),
            stderr_excerpt: String::new(),
            repro: Some(ReproCase {
                command: "replace `<=` with `<` in src/lib.rs".to_string(),
                input: None,
                path: Some(Utf8PathBuf::from("src/lib.rs")),
            }),
        };

        let artifacts = regression_artifacts("rust", &[finding]);

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, ArtifactKind::RegressionTest);
        assert_eq!(
            artifacts[0].path,
            Utf8PathBuf::from(".veritas/regressions/rust_0.md")
        );
        assert!(artifacts[0]
            .contents
            .contains("fails if `<=` is replaced with `<`"));
        assert!(artifacts[0].contents.contains("Suggested Rust test shape"));
    }

    #[test]
    fn assertion_candidate_artifact_extracts_domain_and_seeds() {
        let finding = Failure {
            id: Some("vts-test".to_string()),
            message: "mutation survived in Rust function `authorize_refund`: auth/permission comparison boundary mutation"
                .to_string(),
            severity: FailureSeverity::Warning,
            target_id: Some("rust:src/lib.rs:authorize_refund".to_string()),
            artifact_id: None,
            command: "cargo test".to_string(),
            stdout_excerpt: String::new(),
            stderr_excerpt: String::new(),
            repro: Some(ReproCase {
                command: "replace `<=` with `<` in src/lib.rs".to_string(),
                input: None,
                path: Some(Utf8PathBuf::from("src/lib.rs")),
            }),
        };

        let artifacts = assertion_candidate_artifacts("rust", &[finding])
            .expect("assertion artifacts should serialize");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, ArtifactKind::AssertionCandidate);
        let candidate: veritas_plugin_api::AssertionCandidate =
            serde_json::from_str(&artifacts[0].contents).expect("candidate JSON should parse");
        assert_eq!(candidate.finding_id.as_deref(), Some("vts-test"));
        assert_eq!(candidate.domain, AssertionDomain::AuthPermission);
        assert!(candidate
            .expected_behavior
            .contains("distinguishes `<=` from `<`"));
        assert!(candidate
            .seed_inputs
            .iter()
            .any(|seed| seed.contains("admin")));
    }

    #[test]
    fn corpus_entry_artifact_persists_replay_metadata() {
        let finding = Failure {
            id: Some("vts-corpus".to_string()),
            message: "fuzz target failed".to_string(),
            severity: FailureSeverity::Error,
            target_id: Some("go:score.go:Parse".to_string()),
            artifact_id: None,
            command: "go test -run FuzzParse".to_string(),
            stdout_excerpt: String::new(),
            stderr_excerpt: String::new(),
            repro: Some(ReproCase {
                command: "go test -run FuzzParse/testdata/fuzz/FuzzParse/abc".to_string(),
                input: Some("abc".to_string()),
                path: Some(Utf8PathBuf::from("testdata/fuzz/FuzzParse/abc")),
            }),
        };

        let artifacts =
            corpus_entry_artifacts("go", &[finding]).expect("corpus artifact should serialize");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, ArtifactKind::CorpusEntry);
        assert_eq!(
            artifacts[0].path,
            Utf8PathBuf::from(".veritas/corpus/go_0.json")
        );
        let entry: veritas_plugin_api::CorpusEntry =
            serde_json::from_str(&artifacts[0].contents).expect("corpus JSON should parse");
        assert_eq!(entry.finding_id.as_deref(), Some("vts-corpus"));
        assert_eq!(entry.input.as_deref(), Some("abc"));
    }

    #[test]
    fn confidence_score_penalizes_survivors_and_rewards_replay() {
        let mut report = VerificationReport::empty();
        report.quality.mutation.generated = 4;
        report.quality.mutation.executed = 4;
        report.quality.mutation.killed = 3;
        report.quality.mutation.survived = 1;
        report.quality.mutation.score_percent = Some(75);
        report.quality.regression.assertion_candidates = 1;
        report.quality.replay.cases = 2;
        report.findings.push(Failure {
            id: Some("vts-score".to_string()),
            message: "mutation survived".to_string(),
            severity: FailureSeverity::Warning,
            target_id: Some("rust:src/lib.rs:target".to_string()),
            artifact_id: None,
            command: "cargo test".to_string(),
            stdout_excerpt: String::new(),
            stderr_excerpt: String::new(),
            repro: None,
        });

        let score = confidence_score(&report);

        assert!(score.score >= 50);
        assert!(score
            .risks
            .iter()
            .any(|risk| risk.contains("surviving mutant")));
        assert!(score
            .positive_signals
            .iter()
            .any(|signal| signal.contains("differential replay")));
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
                Utf8PathBuf::from("crates/sample/tests/veritas_regression_0_target.rs"),
                Utf8PathBuf::from("pkg/veritas_fuzz_test.go"),
                Utf8PathBuf::from("pkg/veritas_regression_0_test.go"),
                Utf8PathBuf::from("tests/veritas_generated"),
                Utf8PathBuf::from("tests/veritas_generated.rs"),
                Utf8PathBuf::from("tests/veritas_regression_0_target.rs"),
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
        assert_eq!(summary.paths.len(), 9);
        assert!(!root.path().join(".veritas").exists());
        assert!(!root.path().join("tests/veritas_generated").exists());
        assert!(!root.path().join("tests/veritas_generated.rs").exists());
        assert!(!root
            .path()
            .join("tests/veritas_regression_0_target.rs")
            .exists());
        assert!(!root
            .path()
            .join("crates/sample/tests/veritas_generated")
            .exists());
        assert!(!root
            .path()
            .join("crates/sample/tests/veritas_generated.rs")
            .exists());
        assert!(!root
            .path()
            .join("crates/sample/tests/veritas_regression_0_target.rs")
            .exists());
        assert!(!root.path().join("pkg/veritas_fuzz_test.go").exists());
        assert!(!root
            .path()
            .join("pkg/veritas_regression_0_test.go")
            .exists());
        assert!(root.path().join("src/lib.rs").exists());
        assert!(root
            .path()
            .join("target/tests/veritas_generated.rs")
            .exists());
        assert!(root.path().join("vendor/veritas_fuzz_test.go").exists());
        assert!(root
            .path()
            .join("target/tests/veritas_regression_0_test.go")
            .exists());
        assert!(root
            .path()
            .join("vendor/veritas_regression_0_test.go")
            .exists());
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
        write_file(root, "tests/veritas_regression_0_target.rs");
        write_file(root, "crates/sample/tests/veritas_generated/generated.rs");
        write_file(root, "crates/sample/tests/veritas_generated.rs");
        write_file(root, "crates/sample/tests/veritas_regression_0_target.rs");
        write_file(root, "pkg/veritas_fuzz_test.go");
        write_file(root, "pkg/veritas_regression_0_test.go");
        write_file(root, "src/lib.rs");
        write_file(root, "target/tests/veritas_generated.rs");
        write_file(root, "target/tests/veritas_regression_0_test.go");
        write_file(root, "vendor/veritas_fuzz_test.go");
        write_file(root, "vendor/veritas_regression_0_test.go");
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
