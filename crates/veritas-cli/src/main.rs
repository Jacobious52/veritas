use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use veritas_core::{
    accept_findings, accept_quality_baseline, accepted_finding_ids, cleanup_generated_artifacts,
    confidence_score_for_root, config::VeritasConfig, promote_repros, read_saved_report,
    replay_corpus, strategy_from_kind, BaselineSummary, CleanupSummary, CoreEngine,
    CorpusReplaySummary, EvolveSummary, PluginRegistry, PromotionSummary, QualityBaselineSummary,
};
use veritas_go::GoPlugin;
use veritas_plugin_api::{
    ArtifactKind, EvolutionCandidateRecord, EvolutionCandidateStatus, EvolutionSuite,
    FailureSeverity, PerformanceMetrics, RiskLevel, TargetKind, VerificationReport,
    VerificationStrategy,
};
use veritas_python::PythonPlugin;
use veritas_report::{render_junit, render_markdown, render_sarif};
use veritas_rust::RustPlugin;

#[derive(Debug, Parser)]
#[command(name = "veritas")]
#[command(about = "Adversarial verification harness for AI-written and AI-modified software")]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    Verify {
        #[arg(long)]
        lang: Option<String>,

        #[arg(long)]
        target: Option<PathBuf>,

        #[arg(long)]
        changed: bool,

        #[arg(long, value_enum)]
        profile: Option<VerifyProfile>,
    },
    Generate {
        #[arg(long)]
        kind: String,

        #[arg(long)]
        target: Option<PathBuf>,

        #[arg(long)]
        lang: Option<String>,
    },
    Run {
        #[arg(long)]
        lang: Option<String>,
    },
    ReviewAi {
        #[arg(long)]
        lang: Option<String>,
    },
    ReviewPacket {
        #[arg(long)]
        dimension: Vec<String>,
    },
    Report {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    Score {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,

        #[arg(long, value_enum, default_value_t = ScoreMode::Current)]
        mode: ScoreMode,
    },
    Badge {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Next {
        #[arg(long, default_value_t = 1)]
        count: usize,

        #[arg(long)]
        explain: bool,

        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    ReplayCorpus {
        #[arg(long)]
        dry_run: bool,

        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,

        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    AcceptQualityBaseline,
    Explain {
        id: String,
    },
    Cleanup {
        #[arg(long)]
        dry_run: bool,
    },
    PromoteRepro {
        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        index: Option<usize>,
    },
    PromoteRegression {
        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        index: Option<usize>,
    },
    Evolve {
        #[arg(long)]
        lang: Option<String>,

        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        index: Option<usize>,

        #[arg(long)]
        all_selected: bool,

        #[arg(long)]
        evaluate: bool,
    },
    AcceptBaseline {
        #[arg(long)]
        id: Vec<String>,

        #[arg(long)]
        all: bool,
    },
    RepairPrompt {
        #[arg(long)]
        github_step_summary: bool,
    },
    AgentInstructions {
        #[arg(long, value_enum, default_value_t = AgentKind::Generic)]
        agent: AgentKind,

        #[arg(long)]
        output: Option<PathBuf>,
    },
    Bench {
        #[arg(long)]
        suite: Option<PathBuf>,

        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    Conformance {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
    Sarif,
    Junit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VerifyProfile {
    Ci,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ScoreMode {
    Current,
    Strict,
    Verified,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AgentKind {
    Generic,
    Codex,
    Claude,
    Copilot,
}

#[derive(Debug, Deserialize)]
struct BenchSuite {
    #[serde(default)]
    profile: BenchProfile,
    #[serde(rename = "case")]
    cases: Vec<BenchCase>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum BenchProfile {
    #[default]
    Seeded,
    LargeRepo,
    Canary,
}

impl BenchProfile {
    fn label(self) -> &'static str {
        match self {
            BenchProfile::Seeded => "seeded",
            BenchProfile::LargeRepo => "large-repo",
            BenchProfile::Canary => "canary",
        }
    }
}

#[derive(Debug, Deserialize)]
struct BenchCase {
    name: String,
    path: PathBuf,
    language: String,
    #[serde(default)]
    profile: Option<BenchProfile>,
    target: Option<PathBuf>,
    #[serde(default)]
    expect_findings: Vec<String>,
    #[serde(default)]
    expect_artifacts: Vec<String>,
    #[serde(default)]
    expect_commands: Vec<String>,
    min_findings: Option<usize>,
    min_commands: Option<usize>,
    min_mutation_findings: Option<usize>,
    min_mutants_executed: Option<usize>,
    min_mutation_score: Option<u8>,
    min_mutation_effective_workers: Option<usize>,
    max_surviving_mutants: Option<usize>,
    min_generated_test_failures: Option<usize>,
    min_assertion_candidates: Option<usize>,
    min_corpus_entries: Option<usize>,
    min_replay_cases: Option<usize>,
    min_evolution_candidates: Option<usize>,
    min_evolution_selected: Option<usize>,
    max_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BenchReport {
    suite: String,
    profile: BenchProfile,
    passed: bool,
    summary: BenchSummary,
    cases: Vec<BenchCaseReport>,
}

#[derive(Debug, Serialize)]
struct BenchSummary {
    total_cases: usize,
    passed_cases: usize,
    large_repo_cases: usize,
    total_duration_ms: u128,
    total_targets: usize,
    high_risk_targets: usize,
    total_commands: usize,
    total_findings: usize,
    total_artifacts: usize,
    total_mutants_executed: usize,
    total_replay_cases: usize,
    total_evolution_selected: usize,
    slowest_case: Option<String>,
}

#[derive(Debug, Serialize)]
struct BenchCaseReport {
    name: String,
    language: String,
    profile: BenchProfile,
    source: String,
    passed: bool,
    metrics: BenchMetrics,
    findings: usize,
    artifacts: usize,
    missing_findings: Vec<String>,
    missing_artifacts: Vec<String>,
    missing_commands: Vec<String>,
    threshold_failures: Vec<String>,
    duration_ms: u128,
}

#[derive(Debug, Serialize)]
struct BenchMetrics {
    target_count: usize,
    function_targets: usize,
    package_targets: usize,
    high_risk_targets: usize,
    coverage_files: usize,
    command_count: usize,
    findings_by_severity: BTreeMap<String, usize>,
    artifacts_by_kind: BTreeMap<String, usize>,
    mutants_generated: usize,
    mutants_executed: usize,
    mutants_killed: usize,
    mutants_survived: usize,
    mutants_skipped: usize,
    mutation_requested_workers: usize,
    mutation_effective_workers: usize,
    mutation_isolation_failures: usize,
    mutation_score_percent: Option<u8>,
    mutation_findings: usize,
    property_artifacts: usize,
    generated_test_failures: usize,
    fuzz_harnesses: usize,
    fuzz_targets_executed: usize,
    fuzz_failures: usize,
    persisted_repros: usize,
    property_no_panic: usize,
    property_deterministic: usize,
    property_strength_score_percent: Option<u8>,
    assertion_candidates: usize,
    corpus_entries: usize,
    corpus_replayed: usize,
    corpus_failed: usize,
    replay_cases: usize,
    budget_skipped_commands: usize,
    budget_timed_out_commands: usize,
    evolution_suites: usize,
    evolution_candidates: usize,
    evolution_selected: usize,
    evolution_average_fitness_percent: Option<u8>,
    phase_timings: PerformanceMetrics,
}

#[derive(Debug, Serialize)]
struct ConformanceReport {
    passed: bool,
    plugins: Vec<ConformancePluginReport>,
}

#[derive(Debug, Serialize)]
struct ConformancePluginReport {
    language: String,
    project: String,
    targets: usize,
    function_targets: usize,
    file_targets: usize,
    package_targets: usize,
    line_ranges: usize,
    failures: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NextQueue {
    source: String,
    total_candidates: usize,
    returned: usize,
    items: Vec<NextItem>,
}

#[derive(Debug, Serialize)]
struct NextItem {
    rank: usize,
    source: String,
    id: String,
    target_id: Option<String>,
    tier: u8,
    estimated_confidence_impact: i16,
    reason_codes: Vec<String>,
    title: String,
    action: String,
    proof_commands: Vec<String>,
    done_when: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    explanation: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReviewPacketSummary {
    query_path: PathBuf,
    prompt_path: PathBuf,
    dimensions: Vec<String>,
    targets: usize,
}

#[derive(Debug, Serialize)]
struct ReviewPacket<'a> {
    version: u8,
    source_report: &'static str,
    instructions: Vec<&'static str>,
    dimensions: Vec<String>,
    targets: Vec<ReviewTarget<'a>>,
}

#[derive(Debug, Serialize)]
struct ReviewTarget<'a> {
    target_id: &'a str,
    language: &'a str,
    path: &'a str,
    symbol: Option<&'a str>,
    risk: &'a RiskLevel,
    line_range: Option<&'a veritas_plugin_api::LineRange>,
    mechanical_signals: ReviewSignals,
}

#[derive(Debug, Default, Serialize)]
struct ReviewSignals {
    active_findings: usize,
    mutation_survivors: usize,
    generated_properties: usize,
    replay_cases: usize,
    corpus_entries: usize,
    budget_risks: usize,
    artifacts_to_read: Vec<String>,
}

#[derive(Debug)]
struct AgentInstructionSummary {
    path: PathBuf,
    agent: AgentKind,
}

#[derive(Debug, Serialize)]
struct ScoreModeReport {
    source: String,
    modes: Vec<ScoreModeView>,
}

#[derive(Debug, Serialize)]
struct ScoreModeView {
    mode: ScoreMode,
    score: u8,
    grade: String,
    delta_from_current: i16,
    summary: String,
    adjustments: Vec<String>,
    risks: Vec<String>,
    positive_signals: Vec<String>,
    recommended_next_steps: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let root = cli
        .root
        .canonicalize()
        .with_context(|| format!("failed to resolve root {}", cli.root.display()))?;
    let mut config = VeritasConfig::load(&root)?;
    if let Command::Verify { profile, .. } = &cli.command {
        apply_verify_profile(&mut config, *profile);
    }
    let engine = engine(config);

    match cli.command {
        Command::Scan { format } => {
            let scan = engine.scan(&root)?;
            let report = VerificationReport {
                project: scan.projects.first().cloned(),
                targets: scan.targets,
                plan: None,
                artifacts: vec![],
                runs: vec![],
                coverage: vec![],
                findings: vec![],
                quality: veritas_plugin_api::VerificationQuality::default(),
                suggested_next_steps: vec![
                    "Run `veritas verify --lang rust --target <path>`, `veritas verify --lang go --target <path>`, or `veritas verify --lang python --target <path>`.".to_string(),
                ],
            };
            print_report(&report, format)?;
        }
        Command::Verify {
            lang,
            target,
            mut changed,
            profile,
        } => {
            if profile == Some(VerifyProfile::Ci) {
                changed = true;
            }
            if changed && target.is_some() {
                bail!("--changed cannot be combined with --target");
            }
            let report = if changed {
                with_current_dir(&root, || {
                    engine.verify_changed(&root, lang.as_deref(), vec![])
                })?
            } else {
                let language = match lang {
                    Some(lang) => lang,
                    None => infer_language(
                        &root,
                        target.as_deref(),
                        &VerificationStrategy::ExistingTests,
                    )?,
                };
                with_current_dir(&root, || {
                    engine.verify(&root, &language, target.as_deref(), vec![])
                })?
            };
            engine.save_report(&root, &report)?;
            print_report(&report, OutputFormat::Markdown)?;
            enforce_failure_policy(engine.config(), &report)?;
        }
        Command::Generate { kind, target, lang } => {
            let strategy = strategy_from_kind(&kind)?;
            let language = match lang {
                Some(lang) => lang,
                None => infer_language(&root, target.as_deref(), &strategy)?,
            };
            let report = with_current_dir(&root, || {
                engine.generate(&root, &language, target.as_deref(), vec![strategy])
            })?;
            engine.save_report(&root, &report)?;
            print_report(&report, OutputFormat::Markdown)?;
            enforce_failure_policy(engine.config(), &report)?;
        }
        Command::Run { lang } => {
            let report = with_current_dir(&root, || engine.run(&root, lang.as_deref()))?;
            engine.save_report(&root, &report)?;
            print_report(&report, OutputFormat::Markdown)?;
            enforce_failure_policy(engine.config(), &report)?;
        }
        Command::ReviewAi { lang } => {
            let report = with_current_dir(&root, || engine.review_ai(&root, lang.as_deref()))?;
            engine.save_report(&root, &report)?;
            print_report(&report, OutputFormat::Markdown)?;
        }
        Command::ReviewPacket { dimension } => {
            let report = read_saved_report(&root)?;
            let summary = write_review_packet(&root, &report, dimension)?;
            print_review_packet_summary(&summary);
        }
        Command::Report { format } => {
            let report = read_saved_report(&root)?;
            print_report(&report, format)?;
        }
        Command::Score { format, mode } => {
            let report = read_saved_report(&root)?;
            print_score(&root, &report, format, mode)?;
        }
        Command::Badge { output } => {
            let report = read_saved_report(&root)?;
            let path = write_score_badge(&root, &report, output.as_deref())?;
            println!("# veritas badge\n\n- Path: `{}`", path.display());
        }
        Command::Next {
            count,
            explain,
            format,
        } => {
            let report = read_saved_report(&root)?;
            let queue = next_queue(&report, count, explain);
            print_next_queue(&queue, format)?;
        }
        Command::ReplayCorpus {
            dry_run,
            timeout_seconds,
            format,
        } => {
            let summary = replay_corpus(&root, dry_run, timeout_seconds)?;
            print_corpus_replay_summary(&summary, format)?;
        }
        Command::AcceptQualityBaseline => {
            let summary = accept_quality_baseline(&root)?;
            print_quality_baseline_summary(&summary);
        }
        Command::Explain { id } => {
            let report = read_saved_report(&root)?;
            print_explanation(&report, &id)?;
        }
        Command::Cleanup { dry_run } => {
            let summary = cleanup_generated_artifacts(&root, dry_run)?;
            print_cleanup_summary(&summary);
        }
        Command::PromoteRepro { dry_run, index } => {
            let summary = promote_repros(&root, dry_run, index)?;
            print_promotion_summary(&summary);
        }
        Command::PromoteRegression { dry_run, index } => {
            let summary = engine.promote_regressions(&root, dry_run, index)?;
            print_named_promotion_summary("promote-regression", &summary);
        }
        Command::Evolve {
            lang,
            dry_run,
            index,
            all_selected,
            evaluate,
        } => {
            let summary = engine.evolve(
                &root,
                lang.as_deref(),
                dry_run,
                index,
                all_selected,
                evaluate,
            )?;
            print_evolve_summary(&summary);
        }
        Command::AcceptBaseline { id, all } => {
            if id.is_empty() && !all {
                bail!("pass --id <finding-id> or --all");
            }
            let summary = accept_findings(&root, &id, all)?;
            print_baseline_summary(&summary);
        }
        Command::RepairPrompt {
            github_step_summary,
        } => {
            let report = read_saved_report(&root)?;
            let prompt = render_ai_repair_prompt(&report);
            if github_step_summary {
                let path = std::env::var("GITHUB_STEP_SUMMARY")
                    .context("GITHUB_STEP_SUMMARY is not set")?;
                use std::io::Write;
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .with_context(|| format!("failed to open {path}"))?;
                writeln!(file, "{prompt}")?;
            }
            println!("{prompt}");
        }
        Command::AgentInstructions { agent, output } => {
            let summary = write_agent_instructions(&root, agent, output.as_deref())?;
            print_agent_instruction_summary(&summary);
        }
        Command::Bench { suite, format } => {
            let report = run_bench_suite(&root, suite.as_deref())?;
            print_bench_report(&report, format)?;
            if !report.passed {
                bail!("benchmark suite did not meet expected detections");
            }
        }
        Command::Conformance { format } => {
            let report = run_plugin_conformance(&engine, &root)?;
            print_conformance_report(&report, format)?;
            if !report.passed {
                bail!("plugin conformance checks failed");
            }
        }
    }

    Ok(())
}

fn run_bench_suite(root: &Path, suite: Option<&Path>) -> Result<BenchReport> {
    let suite_path = suite
        .map(|path| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        })
        .unwrap_or_else(|| root.join("veritas-bench.toml"));
    let suite_path = suite_path
        .canonicalize()
        .with_context(|| format!("failed to resolve benchmark suite {}", suite_path.display()))?;
    let suite_root = suite_path
        .parent()
        .context("benchmark suite path must have a parent")?;
    let contents = fs::read_to_string(&suite_path)
        .with_context(|| format!("failed to read benchmark suite {}", suite_path.display()))?;
    let suite: BenchSuite = toml::from_str(&contents)
        .with_context(|| format!("failed to parse benchmark suite {}", suite_path.display()))?;

    let profile = suite.profile;
    let mut cases = Vec::new();
    for case in suite.cases {
        cases.push(run_bench_case(suite_root, profile, case)?);
    }
    let passed = cases.iter().all(|case| case.passed);
    let summary = bench_summary(&cases);
    Ok(BenchReport {
        suite: suite_path.display().to_string(),
        profile,
        passed,
        summary,
        cases,
    })
}

fn run_plugin_conformance(engine: &CoreEngine, root: &Path) -> Result<ConformanceReport> {
    let scan = engine.scan(root)?;
    let mut plugins = Vec::new();
    for project in &scan.projects {
        let targets = scan
            .targets
            .iter()
            .filter(|target| target.language == project.language)
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        if !targets
            .iter()
            .any(|target| target.kind == TargetKind::Project && target.path.as_str() == ".")
        {
            failures.push("missing project target at `.`".to_string());
        }
        let mut ids = BTreeMap::<String, usize>::new();
        for target in &targets {
            *ids.entry(target.id.clone()).or_default() += 1;
            if target.language != project.language {
                failures.push(format!(
                    "target `{}` has mismatched language `{}`",
                    target.id, target.language
                ));
            }
            if target.id.trim().is_empty() {
                failures.push("target with empty stable id".to_string());
            }
            if matches!(target.kind, TargetKind::File | TargetKind::Function)
                && target.path.as_str() == "."
            {
                failures.push(format!("non-project target `{}` uses root path", target.id));
            }
            if target.kind == TargetKind::Function && target.symbol.is_none() {
                failures.push(format!("function target `{}` has no symbol", target.id));
            }
            if let Some(range) = &target.line_range {
                if range.start == 0 || range.end < range.start {
                    failures.push(format!(
                        "target `{}` has invalid line range {}-{}",
                        target.id, range.start, range.end
                    ));
                }
            } else if target.kind == TargetKind::Function {
                failures.push(format!("function target `{}` has no line range", target.id));
            }
            if target.path.as_str() != "." && !root.join(&target.path).exists() {
                failures.push(format!(
                    "target `{}` path `{}` does not exist",
                    target.id, target.path
                ));
            }
        }
        for (id, count) in ids {
            if count > 1 {
                failures.push(format!("target id `{id}` appears {count} times"));
            }
        }
        plugins.push(ConformancePluginReport {
            language: project.language.clone(),
            project: project.name.clone(),
            targets: targets.len(),
            function_targets: targets
                .iter()
                .filter(|target| target.kind == TargetKind::Function)
                .count(),
            file_targets: targets
                .iter()
                .filter(|target| target.kind == TargetKind::File)
                .count(),
            package_targets: targets
                .iter()
                .filter(|target| target.kind == TargetKind::Package)
                .count(),
            line_ranges: targets
                .iter()
                .filter(|target| target.line_range.is_some())
                .count(),
            failures,
        });
    }
    let passed = !plugins.is_empty() && plugins.iter().all(|plugin| plugin.failures.is_empty());
    Ok(ConformanceReport { passed, plugins })
}

fn render_ai_repair_prompt(report: &VerificationReport) -> String {
    let mut out = String::from("# veritas AI repair prompt\n\n");
    out.push_str("Use this as the next verification repair loop for the current repo.\n\n");
    out.push_str("## Commands\n\n");
    out.push_str("```bash\n");
    out.push_str("veritas verify --changed --profile ci\n");
    out.push_str("veritas next --explain\n");
    out.push_str("veritas score\n");
    out.push_str("veritas replay-corpus --dry-run\n");
    out.push_str("veritas evolve --dry-run\n");
    out.push_str("```\n\n");

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("- No active findings. Focus on improving coverage, replay, and mutation score without broad rewrites.\n");
    } else {
        for finding in report.findings.iter().take(10) {
            out.push_str(&format!(
                "- `{}` {:?}: {}\n",
                finding.id.as_deref().unwrap_or("unassigned"),
                finding.severity,
                finding.message
            ));
            if let Some(target_id) = &finding.target_id {
                out.push_str(&format!("  Target: `{target_id}`\n"));
            }
            out.push_str(&format!("  Command: `{}`\n", finding.command));
            if let Some(repro) = &finding.repro {
                out.push_str(&format!("  Repro: `{}`\n", repro.command));
                if let Some(path) = &repro.path {
                    out.push_str(&format!("  Path: `{path}`\n"));
                }
            }
        }
    }

    let interesting_artifacts = report
        .artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.kind,
                ArtifactKind::AssertionCandidate
                    | ArtifactKind::CorpusEntry
                    | ArtifactKind::CorpusReplay
                    | ArtifactKind::DifferentialReplay
                    | ArtifactKind::ReplayResult
                    | ArtifactKind::EvolutionCandidate
                    | ArtifactKind::EvolutionSuite
                    | ArtifactKind::RegressionTest
                    | ArtifactKind::MutationCampaign
                    | ArtifactKind::BudgetPlan
            )
        })
        .collect::<Vec<_>>();
    out.push_str("\n## Artifacts To Inspect\n\n");
    if interesting_artifacts.is_empty() {
        out.push_str("- No AI-facing verification artifacts were recorded in the latest report.\n");
    } else {
        for artifact in interesting_artifacts.iter().take(16) {
            out.push_str(&format!(
                "- `{:?}` `{}`: {}\n",
                artifact.kind, artifact.path, artifact.description
            ));
        }
    }

    let selected_candidates = selected_evolution_candidates(report);
    out.push_str("\n## Selected Evolution Candidates\n\n");
    if selected_candidates.is_empty() {
        out.push_str("- No selected evolution candidates were recorded. Use `veritas evolve --dry-run` after the next verification run.\n");
    } else {
        for candidate in selected_candidates.iter().take(8) {
            out.push_str(&format!(
                "- `{}` `{:?}` fitness `{}%`: {}\n",
                candidate.id,
                candidate.kind,
                candidate.fitness.score_percent,
                candidate.proposed_action
            ));
            out.push_str(&format!("  Target: `{}`\n", candidate.target_id));
            if !candidate.proof_commands.is_empty() {
                out.push_str("  Proof commands:\n");
                for command in candidate.proof_commands.iter().take(3) {
                    out.push_str(&format!("  - `{command}`\n"));
                }
            }
            if !candidate.done_when.is_empty() {
                out.push_str("  Done when:\n");
                for criterion in candidate.done_when.iter().take(3) {
                    out.push_str(&format!("  - {criterion}\n"));
                }
            } else {
                out.push_str(&format!("  Done when: {}\n", candidate.keep_if));
            }
        }
    }

    out.push_str("\n## Patch Plan\n\n");
    out.push_str("1. Start with the highest-fitness selected evolution candidate or the highest-severity finding.\n");
    out.push_str("2. Add the smallest owned test, property, fuzz seed, replay assertion, or regression scaffold that proves the behavior.\n");
    out.push_str("3. Run the proof command named by the candidate, then `veritas verify --changed --profile ci` and `veritas score`.\n");
    out.push_str("4. Keep the patch only when the done-when criteria pass, the finding disappears, the mutant dies, or the confidence score improves.\n");
    out.push_str("5. Stop if the next step requires broad production rewrites without a failing proof artifact.\n");

    let mutation_trends = mutation_trend_summaries(report);
    out.push_str("\n## Mutation Trend\n\n");
    if mutation_trends.is_empty() {
        out.push_str("- No mutation trend artifact was recorded in the latest report.\n");
    } else {
        for trend in mutation_trends {
            out.push_str(&format!("- {trend}\n"));
        }
    }

    out.push_str("\n## Repair Rules\n\n");
    out.push_str("- Prefer adding the smallest owned regression, property, fuzz seed, or replay assertion before changing production code.\n");
    out.push_str("- Use `.veritas/assertions`, `.veritas/corpus`, `.veritas/differential`, and `.veritas/evolution` as the work queue.\n");
    out.push_str("- Keep a candidate only if the next `veritas score` improves or explains why confidence is unchanged.\n");
    if report.quality.performance.total_ms > 0 {
        out.push_str(&format!(
            "- Current verification runtime was `{}` ms; tune budgets if replay, coverage, or mutation dominates.\n",
            report.quality.performance.total_ms
        ));
    }
    out
}

fn mutation_trend_summaries(report: &VerificationReport) -> Vec<String> {
    report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::MutationTrend)
        .filter_map(|artifact| {
            let value = serde_json::from_str::<serde_json::Value>(&artifact.contents).ok()?;
            let language = value["language"].as_str().unwrap_or(&artifact.language);
            let mutation = &value["mutation"];
            let score = mutation["score_percent"]
                .as_u64()
                .map(|score| format!("{score}%"))
                .unwrap_or_else(|| "n/a".to_string());
            let survived = mutation["survived"].as_u64().unwrap_or_default();
            let executed = mutation["executed"].as_u64().unwrap_or_default();
            let baseline = value["baseline_delta"]["mutation_score_delta"]
                .as_i64()
                .map(|delta| format!(", baseline score delta {delta:+}"))
                .unwrap_or_default();
            Some(format!(
                "`{language}` mutation score `{score}` over `{executed}` executed mutants, survivors `{survived}`{baseline}; artifact `{}`",
                artifact.path
            ))
        })
        .collect()
}

fn selected_evolution_candidates(report: &VerificationReport) -> Vec<EvolutionCandidateRecord> {
    let mut candidates = Vec::new();
    for artifact in &report.artifacts {
        if !matches!(
            artifact.kind,
            ArtifactKind::EvolutionSuite | ArtifactKind::EvolutionCandidate
        ) {
            continue;
        }
        if let Ok(suite) = serde_json::from_str::<EvolutionSuite>(&artifact.contents) {
            candidates.extend(
                suite
                    .candidates
                    .into_iter()
                    .filter(|candidate| candidate.status == EvolutionCandidateStatus::Selected),
            );
        }
    }
    candidates.sort_by(|left, right| {
        right
            .fitness
            .score_percent
            .cmp(&left.fitness.score_percent)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates
}

fn next_queue(report: &VerificationReport, count: usize, explain: bool) -> NextQueue {
    let mut items = Vec::new();
    for finding in &report.findings {
        items.push(next_item_from_finding(report, finding, explain));
    }
    for candidate in selected_evolution_candidates(report) {
        items.push(next_item_from_candidate(candidate, explain));
    }

    items.sort_by(|left, right| {
        right
            .tier
            .cmp(&left.tier)
            .then_with(|| {
                right
                    .estimated_confidence_impact
                    .cmp(&left.estimated_confidence_impact)
            })
            .then_with(|| left.id.cmp(&right.id))
    });
    let total_candidates = items.len();
    let take = count.max(1);
    items.truncate(take);
    for (index, item) in items.iter_mut().enumerate() {
        item.rank = index + 1;
    }
    NextQueue {
        source: ".veritas/report.json".to_string(),
        total_candidates,
        returned: items.len(),
        items,
    }
}

fn next_item_from_finding(
    report: &VerificationReport,
    finding: &veritas_plugin_api::Failure,
    explain: bool,
) -> NextItem {
    let severity = severity_rank(&finding.severity);
    let target_risk = finding_target_risk(report, finding);
    let mut reason_codes = vec![format!("severity:{:?}", finding.severity).to_ascii_lowercase()];
    let mut impact = 4 + i16::from(severity) * 3;
    let message = finding.message.to_ascii_lowercase();
    if message.contains("mutation survived") {
        impact += 14;
        reason_codes.push("mutation_survivor".to_string());
    }
    if message.contains("fuzz") || message.contains("minimal failing input") {
        impact += 10;
        reason_codes.push("replayable_input".to_string());
    }
    if message.contains("test failed") {
        impact += 8;
        reason_codes.push("generated_test_failure".to_string());
    }
    if target_risk == Some(&RiskLevel::High) {
        impact += 6;
        reason_codes.push("high_risk_target".to_string());
    }
    let tier = if finding.severity == FailureSeverity::Critical
        || finding.severity == FailureSeverity::Error
        || target_risk == Some(&RiskLevel::High)
    {
        4
    } else if message.contains("mutation survived") || message.contains("fuzz") {
        3
    } else {
        2
    };
    let proof_commands = finding_proof_commands(finding);
    let done_when = vec![
        "the finding no longer appears in `.veritas/report.json`".to_string(),
        "the proof command passes against production code".to_string(),
        "the next `veritas score` is stable or improved".to_string(),
    ];
    let mut explanation = Vec::new();
    if explain {
        explanation.push(format!(
            "tier {tier} from severity {:?} and target risk {}",
            finding.severity,
            target_risk
                .map(|risk| format!("{risk:?}"))
                .unwrap_or_else(|| "unknown".to_string())
        ));
        explanation.push(format!(
            "estimated confidence impact {impact:+} from {}",
            reason_codes.join(", ")
        ));
    }
    NextItem {
        rank: 0,
        source: "finding".to_string(),
        id: finding
            .id
            .clone()
            .unwrap_or_else(|| "unassigned-finding".to_string()),
        target_id: finding.target_id.clone(),
        tier,
        estimated_confidence_impact: impact,
        reason_codes,
        title: finding.message.clone(),
        action: finding_action(finding),
        proof_commands,
        done_when,
        explanation,
    }
}

fn next_item_from_candidate(candidate: EvolutionCandidateRecord, explain: bool) -> NextItem {
    let impact = candidate.fitness.confidence_delta.max(0)
        + (i16::from(candidate.fitness.score_percent) / 5)
        + candidate.fitness.mutation_delta.max(0) * 3
        + candidate.fitness.replay_delta.max(0) * 2
        - candidate.fitness.finding_delta.max(0) * 2;
    let tier = match candidate.kind {
        veritas_plugin_api::EvolutionCandidateKind::Mutation => 4,
        veritas_plugin_api::EvolutionCandidateKind::Regression => 4,
        veritas_plugin_api::EvolutionCandidateKind::Fuzz => 3,
        veritas_plugin_api::EvolutionCandidateKind::Replay => 3,
        veritas_plugin_api::EvolutionCandidateKind::Property => 3,
        veritas_plugin_api::EvolutionCandidateKind::Budget => 2,
    };
    let mut reason_codes = vec![
        format!("candidate:{:?}", candidate.kind).to_ascii_lowercase(),
        format!("fitness:{}%", candidate.fitness.score_percent),
    ];
    if candidate.fitness.mutation_delta > 0 {
        reason_codes.push("mutation_delta".to_string());
    }
    if candidate.fitness.replay_delta > 0 {
        reason_codes.push("replay_delta".to_string());
    }
    if candidate.fitness.confidence_delta > 0 {
        reason_codes.push("confidence_delta".to_string());
    }
    let mut explanation = Vec::new();
    if explain {
        explanation.push(candidate.fitness.rationale.clone());
        explanation.push(format!(
            "estimated confidence impact {impact:+}; keep if {}",
            candidate.keep_if
        ));
    }
    NextItem {
        rank: 0,
        source: "evolution_candidate".to_string(),
        id: candidate.id,
        target_id: Some(candidate.target_id),
        tier,
        estimated_confidence_impact: impact,
        reason_codes,
        title: format!("{:?} candidate", candidate.kind),
        action: candidate.proposed_action,
        proof_commands: candidate.proof_commands,
        done_when: if candidate.done_when.is_empty() {
            vec![candidate.keep_if]
        } else {
            candidate.done_when
        },
        explanation,
    }
}

fn severity_rank(severity: &FailureSeverity) -> u8 {
    match severity {
        FailureSeverity::Critical => 4,
        FailureSeverity::Error => 3,
        FailureSeverity::Warning => 2,
        FailureSeverity::Info => 1,
    }
}

fn finding_proof_commands(finding: &veritas_plugin_api::Failure) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(repro) = &finding.repro {
        commands.push(repro.command.clone());
    }
    if !finding.command.trim().is_empty()
        && !commands.iter().any(|command| command == &finding.command)
    {
        commands.push(finding.command.clone());
    }
    commands.push("veritas verify --changed --profile ci".to_string());
    commands.push("veritas score".to_string());
    commands
}

fn finding_action(finding: &veritas_plugin_api::Failure) -> String {
    let message = finding.message.to_ascii_lowercase();
    if message.contains("mutation survived") {
        "Add the smallest owned assertion that fails under the mutant, then rerun the mutation campaign.".to_string()
    } else if message.contains("fuzz") || message.contains("minimal failing input") {
        "Persist the failing input as a corpus seed and add a named regression assertion."
            .to_string()
    } else if message.contains("test failed") {
        "Promote the generated failing case into an owned regression test with explicit expected behavior.".to_string()
    } else {
        "Address this verification finding with the smallest behavior-preserving patch and proof command.".to_string()
    }
}

fn write_review_packet(
    root: &Path,
    report: &VerificationReport,
    dimensions: Vec<String>,
) -> Result<ReviewPacketSummary> {
    let dimensions = if dimensions.is_empty() {
        default_review_dimensions()
    } else {
        dimensions
    };
    let packet = ReviewPacket {
        version: 1,
        source_report: ".veritas/report.json",
        instructions: vec![
            "Review from evidence only; do not anchor to current confidence score or desired score.",
            "Return concrete findings with target IDs, dimensions, evidence, confidence, and suggested tests.",
            "Prefer issues that improve verifiability, boundaries, error handling, and testability.",
            "Do not request broad rewrites unless mechanical signals show high risk.",
        ],
        dimensions: dimensions.clone(),
        targets: review_targets(report),
    };
    let review_dir = root.join(".veritas/review");
    fs::create_dir_all(&review_dir)
        .with_context(|| format!("failed to create {}", review_dir.display()))?;
    let query_path = review_dir.join("query.json");
    let prompt_path = review_dir.join("prompt.md");
    fs::write(&query_path, serde_json::to_string_pretty(&packet)?)
        .with_context(|| format!("failed to write {}", query_path.display()))?;
    fs::write(&prompt_path, render_review_prompt(&packet))
        .with_context(|| format!("failed to write {}", prompt_path.display()))?;
    Ok(ReviewPacketSummary {
        query_path,
        prompt_path,
        dimensions,
        targets: packet.targets.len(),
    })
}

fn default_review_dimensions() -> Vec<String> {
    [
        "naming",
        "abstractions",
        "boundaries",
        "error_handling",
        "testability",
        "security",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn review_targets(report: &VerificationReport) -> Vec<ReviewTarget<'_>> {
    report
        .targets
        .iter()
        .filter(|target| target.kind != TargetKind::Project)
        .map(|target| ReviewTarget {
            target_id: &target.id,
            language: &target.language,
            path: target.path.as_str(),
            symbol: target.symbol.as_deref(),
            risk: &target.risk,
            line_range: target.line_range.as_ref(),
            mechanical_signals: review_signals_for_target(report, &target.id),
        })
        .collect()
}

fn review_signals_for_target(report: &VerificationReport, target_id: &str) -> ReviewSignals {
    ReviewSignals {
        active_findings: report
            .findings
            .iter()
            .filter(|finding| finding.target_id.as_deref() == Some(target_id))
            .count(),
        mutation_survivors: report
            .findings
            .iter()
            .filter(|finding| {
                finding.target_id.as_deref() == Some(target_id)
                    && finding.message.contains("mutation survived")
            })
            .count(),
        generated_properties: report
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.target_id == target_id && artifact.kind == ArtifactKind::PropertyTest
            })
            .count(),
        corpus_entries: report
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.target_id == target_id && artifact.kind == ArtifactKind::CorpusEntry
            })
            .count(),
        replay_cases: report
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == ArtifactKind::DifferentialReplay
                    || artifact.kind == ArtifactKind::ReplayResult
            })
            .count(),
        budget_risks: report.quality.budget.skipped_commands
            + report.quality.budget.timed_out_commands,
        artifacts_to_read: report
            .artifacts
            .iter()
            .filter(|artifact| artifact.target_id == target_id)
            .take(8)
            .map(|artifact| artifact.path.to_string())
            .collect(),
    }
}

fn render_review_prompt(packet: &ReviewPacket<'_>) -> String {
    let mut out = String::from("# Veritas Review Packet\n\n");
    out.push_str("Use `.veritas/review/query.json` as the source of truth. Review the code from evidence only; do not infer or optimize toward a hidden score.\n\n");
    out.push_str("## Dimensions\n\n");
    for dimension in &packet.dimensions {
        out.push_str(&format!("- `{dimension}`\n"));
    }
    out.push_str("\n## Targets\n\n");
    for target in packet.targets.iter().take(20) {
        out.push_str(&format!(
            "- `{}` `{}` risk `{:?}` findings `{}` survivors `{}`\n",
            target.target_id,
            target.path,
            target.risk,
            target.mechanical_signals.active_findings,
            target.mechanical_signals.mutation_survivors
        ));
    }
    out.push_str("\n## Required Output\n\nReturn JSON with `findings`, where each finding has `target_id`, `dimension`, `evidence`, `confidence`, `suggested_test`, and `why_it_improves_verifiability`.\n");
    out
}

fn write_agent_instructions(
    root: &Path,
    agent: AgentKind,
    output: Option<&Path>,
) -> Result<AgentInstructionSummary> {
    let relative = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".veritas/ai/veritas_agent_instructions.md"));
    let path = if relative.is_absolute() {
        relative
    } else {
        root.join(relative)
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, render_agent_instructions(agent))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(AgentInstructionSummary { path, agent })
}

fn render_agent_instructions(agent: AgentKind) -> String {
    let agent_label = match agent {
        AgentKind::Generic => "generic AI coding agent",
        AgentKind::Codex => "Codex",
        AgentKind::Claude => "Claude",
        AgentKind::Copilot => "GitHub Copilot",
    };
    format!(
        "# Veritas Agent Instructions\n\n\
         You are using Veritas with a {agent_label}. Your job is to improve verifiability, not to hide findings.\n\n\
         ## Loop\n\n\
         1. Run `veritas verify --changed --profile ci` for changed work or `veritas verify --lang <lang> --target <target>` for focused work.\n\
         2. Run `veritas next --explain` and do the first item unless it requires a broad rewrite without proof.\n\
         3. Prefer adding the smallest owned regression, property, fuzz seed, or replay assertion before production edits.\n\
         4. Run the listed proof commands, then `veritas score`.\n\
         5. Keep changes only when the finding disappears, a mutant dies, replay/corpus improves, or confidence is stable/improved.\n\n\
         ## Anti-Gaming Rules\n\n\
         - Do not delete generated artifacts to improve output.\n\
         - Do not accept baselines for unresolved behavior changes.\n\
         - Do not widen scope or raise budgets before trying a smaller proof.\n\
         - Treat skipped commands and surviving mutants as real risks.\n\n\
         ## Useful Commands\n\n\
         ```bash\n\
         veritas next --explain\n\
         veritas score\n\
         veritas repair-prompt\n\
         veritas replay-corpus --dry-run\n\
         veritas evolve --dry-run\n\
         veritas review-packet\n\
         ```\n"
    )
}

fn write_score_badge(
    root: &Path,
    report: &VerificationReport,
    output: Option<&Path>,
) -> Result<PathBuf> {
    let relative = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".veritas/badge.svg"));
    let path = if relative.is_absolute() {
        relative
    } else {
        root.join(relative)
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, render_score_badge(report))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn render_score_badge(report: &VerificationReport) -> String {
    let score = veritas_core::confidence_score(report);
    let mutation = report
        .quality
        .mutation
        .score_percent
        .map(|score| format!("{score}% mutation"))
        .unwrap_or_else(|| "mutation n/a".to_string());
    let label = format!("veritas {}", score.score);
    let grade = format!("{:?}", score.grade).to_ascii_lowercase();
    let color = match score.grade {
        veritas_plugin_api::ConfidenceGrade::High => "#1f9d55",
        veritas_plugin_api::ConfidenceGrade::Medium => "#b7791f",
        veritas_plugin_api::ConfidenceGrade::Low => "#c53030",
    };
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"420\" height=\"96\" role=\"img\" aria-label=\"{}\">\n\
         <rect width=\"420\" height=\"96\" rx=\"8\" fill=\"#111827\"/>\n\
         <rect x=\"0\" y=\"0\" width=\"132\" height=\"96\" rx=\"8\" fill=\"{}\"/>\n\
         <text x=\"66\" y=\"40\" text-anchor=\"middle\" font-family=\"Verdana, sans-serif\" font-size=\"18\" fill=\"#fff\">{}</text>\n\
         <text x=\"66\" y=\"66\" text-anchor=\"middle\" font-family=\"Verdana, sans-serif\" font-size=\"13\" fill=\"#ecfdf5\">{}</text>\n\
         <text x=\"152\" y=\"38\" font-family=\"Verdana, sans-serif\" font-size=\"17\" fill=\"#f9fafb\">{}</text>\n\
         <text x=\"152\" y=\"65\" font-family=\"Verdana, sans-serif\" font-size=\"13\" fill=\"#d1d5db\">{}</text>\n\
         </svg>\n",
        xml_escape(&format!("{label} {grade} {mutation}")),
        color,
        xml_escape(&score.score.to_string()),
        xml_escape(&grade),
        xml_escape(&label),
        xml_escape(&mutation)
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn run_bench_case(
    suite_root: &Path,
    suite_profile: BenchProfile,
    case: BenchCase,
) -> Result<BenchCaseReport> {
    let start = std::time::Instant::now();
    let profile = case.profile.unwrap_or(suite_profile);
    let source = suite_root.join(&case.path);
    let source = source
        .canonicalize()
        .with_context(|| format!("failed to resolve benchmark case {}", source.display()))?;
    let temp_root = unique_temp_dir(&case.name)?;
    fs::create_dir_all(&temp_root)
        .with_context(|| format!("failed to create {}", temp_root.display()))?;

    let result = (|| {
        copy_project_for_bench(&source, &temp_root)?;
        let mut config = VeritasConfig::load(&temp_root)?;
        apply_verify_profile(&mut config, None);
        let engine = engine(config);
        let report = with_current_dir(&temp_root, || {
            engine.verify(&temp_root, &case.language, case.target.as_deref(), vec![])
        })?;
        engine.save_report(&temp_root, &report)?;

        let missing_findings = case
            .expect_findings
            .iter()
            .filter(|expected| !report_contains_finding(&report, expected))
            .cloned()
            .collect::<Vec<_>>();
        let missing_artifacts = case
            .expect_artifacts
            .iter()
            .filter(|expected| !report_contains_artifact_kind(&report, expected))
            .cloned()
            .collect::<Vec<_>>();
        let missing_commands = case
            .expect_commands
            .iter()
            .filter(|expected| !report_contains_command(&report, expected))
            .cloned()
            .collect::<Vec<_>>();
        let metrics = bench_metrics(&report);
        let duration_ms = start.elapsed().as_millis();
        let threshold_failures = bench_threshold_failures(&case, &metrics, duration_ms);
        let passed = missing_findings.is_empty()
            && missing_artifacts.is_empty()
            && missing_commands.is_empty()
            && threshold_failures.is_empty();
        Ok(BenchCaseReport {
            name: case.name,
            language: case.language,
            profile,
            source: source.display().to_string(),
            passed,
            metrics,
            findings: report.findings.len(),
            artifacts: report.artifacts.len(),
            missing_findings,
            missing_artifacts,
            missing_commands,
            threshold_failures,
            duration_ms,
        })
    })();

    if let Err(error) = fs::remove_dir_all(&temp_root) {
        eprintln!(
            "warning: failed to remove benchmark temp directory {}: {error}",
            temp_root.display()
        );
    }

    result
}

fn unique_temp_dir(name: &str) -> Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time was before unix epoch")?
        .as_millis();
    Ok(std::env::temp_dir().join(format!("veritas-bench-{}-{millis}", safe_path_name(name))))
}

fn copy_project_for_bench(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target).with_context(|| format!("failed to create {}", target.display()))?;
    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        if should_skip_bench_copy_entry(&name) {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(name);
        if source_path.is_dir() {
            copy_project_for_bench(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn should_skip_bench_copy_entry(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_string_lossy().as_ref(),
        ".git"
            | ".veritas"
            | "target"
            | "vendor"
            | "node_modules"
            | "veritas_fuzz_test.go"
            | "veritas_generated"
            | "veritas_generated.rs"
    ) || name.to_string_lossy().starts_with("veritas_regression_")
        || name.to_string_lossy().ends_with(".proptest-regressions")
}

fn report_contains_finding(report: &VerificationReport, expected: &str) -> bool {
    report.findings.iter().any(|finding| {
        finding.message.contains(expected)
            || finding.command.contains(expected)
            || finding.stdout_excerpt.contains(expected)
            || finding.stderr_excerpt.contains(expected)
    })
}

fn report_contains_artifact_kind(report: &VerificationReport, expected: &str) -> bool {
    report
        .artifacts
        .iter()
        .any(|artifact| artifact_kind_label(&artifact.kind) == expected)
}

fn report_contains_command(report: &VerificationReport, expected: &str) -> bool {
    report.runs.iter().any(|run| {
        run.commands.iter().any(|command| {
            bench_command_line(&command.program, &command.args).contains(expected)
                || command.program.contains(expected)
        })
    })
}

fn bench_metrics(report: &VerificationReport) -> BenchMetrics {
    let mut findings_by_severity = BTreeMap::new();
    let mut artifacts_by_kind = BTreeMap::new();
    for finding in &report.findings {
        *findings_by_severity
            .entry(failure_severity_label(&finding.severity))
            .or_insert(0) += 1;
    }
    for artifact in &report.artifacts {
        *artifacts_by_kind
            .entry(artifact_kind_label(&artifact.kind))
            .or_insert(0) += 1;
    }

    BenchMetrics {
        target_count: report.targets.len(),
        function_targets: report
            .targets
            .iter()
            .filter(|target| target.kind == TargetKind::Function)
            .count(),
        package_targets: report
            .targets
            .iter()
            .filter(|target| target.kind == TargetKind::Package)
            .count(),
        high_risk_targets: report
            .targets
            .iter()
            .filter(|target| target.risk == RiskLevel::High)
            .count(),
        coverage_files: report
            .coverage
            .iter()
            .map(|coverage| coverage.files.len())
            .sum(),
        command_count: report
            .runs
            .iter()
            .map(|run| run.commands.len())
            .sum::<usize>(),
        findings_by_severity,
        artifacts_by_kind,
        mutation_findings: report
            .findings
            .iter()
            .filter(|finding| finding.message.contains("mutation survived"))
            .count(),
        mutants_generated: report.quality.mutation.generated,
        mutants_executed: report.quality.mutation.executed,
        mutants_killed: report.quality.mutation.killed,
        mutants_survived: report.quality.mutation.survived,
        mutants_skipped: report.quality.mutation.skipped,
        mutation_requested_workers: report.quality.mutation.requested_workers,
        mutation_effective_workers: report.quality.mutation.effective_workers,
        mutation_isolation_failures: report.quality.mutation.isolation_failures,
        mutation_score_percent: report.quality.mutation.score_percent,
        property_artifacts: report.quality.property.generated_artifacts,
        generated_test_failures: report.quality.property.failed_generated_tests,
        fuzz_harnesses: report.quality.fuzz.generated_harnesses,
        fuzz_targets_executed: report.quality.fuzz.targets_executed,
        fuzz_failures: report.quality.fuzz.failures,
        persisted_repros: report.quality.fuzz.persisted_repros,
        property_no_panic: report.quality.property.no_panic_properties,
        property_deterministic: report.quality.property.deterministic_properties,
        property_strength_score_percent: report.quality.property.strength_score_percent,
        assertion_candidates: report.quality.regression.assertion_candidates,
        corpus_entries: report.quality.regression.corpus_entries,
        corpus_replayed: report.quality.regression.corpus_replayed,
        corpus_failed: report.quality.regression.corpus_failed,
        replay_cases: report.quality.replay.cases,
        budget_skipped_commands: report.quality.budget.skipped_commands,
        budget_timed_out_commands: report.quality.budget.timed_out_commands,
        evolution_suites: report.quality.evolution.suites,
        evolution_candidates: report.quality.evolution.candidates,
        evolution_selected: report.quality.evolution.selected,
        evolution_average_fitness_percent: report.quality.evolution.average_fitness_percent,
        phase_timings: report.quality.performance.clone(),
    }
}

fn bench_threshold_failures(
    case: &BenchCase,
    metrics: &BenchMetrics,
    duration_ms: u128,
) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(min_findings) = case.min_findings {
        let actual = metrics.findings_by_severity.values().sum::<usize>();
        if actual < min_findings {
            failures.push(format!("findings {actual} < min_findings {min_findings}"));
        }
    }
    if let Some(min_commands) = case.min_commands {
        if metrics.command_count < min_commands {
            failures.push(format!(
                "commands {} < min_commands {min_commands}",
                metrics.command_count
            ));
        }
    }
    if let Some(min_mutation_findings) = case.min_mutation_findings {
        if metrics.mutation_findings < min_mutation_findings {
            failures.push(format!(
                "mutation_findings {} < min_mutation_findings {min_mutation_findings}",
                metrics.mutation_findings
            ));
        }
    }
    if let Some(min_mutants_executed) = case.min_mutants_executed {
        if metrics.mutants_executed < min_mutants_executed {
            failures.push(format!(
                "mutants_executed {} < min_mutants_executed {min_mutants_executed}",
                metrics.mutants_executed
            ));
        }
    }
    if let Some(min_mutation_score) = case.min_mutation_score {
        let actual = metrics.mutation_score_percent.unwrap_or(0);
        if actual < min_mutation_score {
            failures.push(format!(
                "mutation_score_percent {actual} < min_mutation_score {min_mutation_score}"
            ));
        }
    }
    if let Some(min_mutation_effective_workers) = case.min_mutation_effective_workers {
        if metrics.mutation_effective_workers < min_mutation_effective_workers {
            failures.push(format!(
                "mutation_effective_workers {} < min_mutation_effective_workers {min_mutation_effective_workers}",
                metrics.mutation_effective_workers
            ));
        }
    }
    if let Some(max_surviving_mutants) = case.max_surviving_mutants {
        if metrics.mutants_survived > max_surviving_mutants {
            failures.push(format!(
                "mutants_survived {} > max_surviving_mutants {max_surviving_mutants}",
                metrics.mutants_survived
            ));
        }
    }
    if let Some(min_generated_test_failures) = case.min_generated_test_failures {
        if metrics.generated_test_failures < min_generated_test_failures {
            failures.push(format!(
                "generated_test_failures {} < min_generated_test_failures {min_generated_test_failures}",
                metrics.generated_test_failures
            ));
        }
    }
    if let Some(min_assertion_candidates) = case.min_assertion_candidates {
        if metrics.assertion_candidates < min_assertion_candidates {
            failures.push(format!(
                "assertion_candidates {} < min_assertion_candidates {min_assertion_candidates}",
                metrics.assertion_candidates
            ));
        }
    }
    if let Some(min_corpus_entries) = case.min_corpus_entries {
        if metrics.corpus_entries < min_corpus_entries {
            failures.push(format!(
                "corpus_entries {} < min_corpus_entries {min_corpus_entries}",
                metrics.corpus_entries
            ));
        }
    }
    if let Some(min_replay_cases) = case.min_replay_cases {
        if metrics.replay_cases < min_replay_cases {
            failures.push(format!(
                "replay_cases {} < min_replay_cases {min_replay_cases}",
                metrics.replay_cases
            ));
        }
    }
    if let Some(min_evolution_candidates) = case.min_evolution_candidates {
        if metrics.evolution_candidates < min_evolution_candidates {
            failures.push(format!(
                "evolution_candidates {} < min_evolution_candidates {min_evolution_candidates}",
                metrics.evolution_candidates
            ));
        }
    }
    if let Some(min_evolution_selected) = case.min_evolution_selected {
        if metrics.evolution_selected < min_evolution_selected {
            failures.push(format!(
                "evolution_selected {} < min_evolution_selected {min_evolution_selected}",
                metrics.evolution_selected
            ));
        }
    }
    if let Some(max_duration_ms) = case.max_duration_ms {
        if duration_ms > u128::from(max_duration_ms) {
            failures.push(format!(
                "duration_ms {duration_ms} > max_duration_ms {max_duration_ms}"
            ));
        }
    }
    failures
}

fn bench_summary(cases: &[BenchCaseReport]) -> BenchSummary {
    let slowest_case = cases
        .iter()
        .max_by_key(|case| case.duration_ms)
        .map(|case| case.name.clone());
    BenchSummary {
        total_cases: cases.len(),
        passed_cases: cases.iter().filter(|case| case.passed).count(),
        large_repo_cases: cases
            .iter()
            .filter(|case| case.profile == BenchProfile::LargeRepo)
            .count(),
        total_duration_ms: cases.iter().map(|case| case.duration_ms).sum(),
        total_targets: cases.iter().map(|case| case.metrics.target_count).sum(),
        high_risk_targets: cases
            .iter()
            .map(|case| case.metrics.high_risk_targets)
            .sum(),
        total_commands: cases.iter().map(|case| case.metrics.command_count).sum(),
        total_findings: cases.iter().map(|case| case.findings).sum(),
        total_artifacts: cases.iter().map(|case| case.artifacts).sum(),
        total_mutants_executed: cases.iter().map(|case| case.metrics.mutants_executed).sum(),
        total_replay_cases: cases.iter().map(|case| case.metrics.replay_cases).sum(),
        total_evolution_selected: cases
            .iter()
            .map(|case| case.metrics.evolution_selected)
            .sum(),
        slowest_case,
    }
}

fn bench_command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_bench_report(report: &BenchReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => {
            let passed = report.cases.iter().filter(|case| case.passed).count();
            println!("# veritas bench\n");
            println!("- Suite: `{}`", report.suite);
            println!("- Profile: `{}`", report.profile.label());
            println!("- Cases: `{passed}/{}` passed", report.cases.len());
            println!(
                "- Status: `{}`",
                if report.passed { "passed" } else { "failed" }
            );
            println!("\n## Summary\n");
            println!(
                "- Totals: cases `{}`, targets `{}`, high-risk targets `{}`, commands `{}`, findings `{}`, artifacts `{}`",
                report.summary.total_cases,
                report.summary.total_targets,
                report.summary.high_risk_targets,
                report.summary.total_commands,
                report.summary.total_findings,
                report.summary.total_artifacts
            );
            println!(
                "- Verification signal: mutants executed `{}`, replay cases `{}`, selected evolution candidates `{}`",
                report.summary.total_mutants_executed,
                report.summary.total_replay_cases,
                report.summary.total_evolution_selected
            );
            println!("- Large-repo cases: `{}`", report.summary.large_repo_cases);
            if let Some(slowest_case) = &report.summary.slowest_case {
                println!("- Slowest case: `{slowest_case}`");
            }
            println!("- Total duration: `{}ms`", report.summary.total_duration_ms);
            for case in &report.cases {
                println!("\n## {}", case.name);
                println!("- Language: `{}`", case.language);
                println!("- Profile: `{}`", case.profile.label());
                println!(
                    "- Targets: `{}` (functions `{}`, packages `{}`, high-risk `{}`)",
                    case.metrics.target_count,
                    case.metrics.function_targets,
                    case.metrics.package_targets,
                    case.metrics.high_risk_targets
                );
                println!("- Findings: `{}`", case.findings);
                println!("- Artifacts: `{}`", case.artifacts);
                println!("- Coverage files: `{}`", case.metrics.coverage_files);
                println!("- Commands: `{}`", case.metrics.command_count);
                if case.metrics.phase_timings.total_ms > 0 {
                    println!(
                        "- Phase timings: total `{}` ms, discovery `{}`, generation `{}`, tests `{}`, coverage `{}`, replay `{}`, synthesis `{}`",
                        case.metrics.phase_timings.total_ms,
                        case.metrics.phase_timings.discovery_ms,
                        case.metrics.phase_timings.generation_ms,
                        case.metrics.phase_timings.test_execution_ms,
                        case.metrics.phase_timings.coverage_ms,
                        case.metrics.phase_timings.replay_ms,
                        case.metrics.phase_timings.artifact_synthesis_ms,
                    );
                }
                println!(
                    "- Mutation score: `{}`",
                    case.metrics
                        .mutation_score_percent
                        .map(|score| format!("{score}%"))
                        .unwrap_or_else(|| "n/a".to_string())
                );
                println!(
                    "- Mutants: generated `{}`, executed `{}`, killed `{}`, survived `{}`, skipped `{}`",
                    case.metrics.mutants_generated,
                    case.metrics.mutants_executed,
                    case.metrics.mutants_killed,
                    case.metrics.mutants_survived,
                    case.metrics.mutants_skipped
                );
                if case.metrics.mutation_requested_workers > 0
                    || case.metrics.mutation_effective_workers > 0
                    || case.metrics.mutation_isolation_failures > 0
                {
                    println!(
                        "- Mutation workers: requested `{}`, effective `{}`, isolation failures `{}`",
                        case.metrics.mutation_requested_workers,
                        case.metrics.mutation_effective_workers,
                        case.metrics.mutation_isolation_failures
                    );
                }
                println!("- Mutation findings: `{}`", case.metrics.mutation_findings);
                println!(
                    "- Property artifacts: `{}`",
                    case.metrics.property_artifacts
                );
                println!(
                    "- Property strength: `{}` (no-panic `{}`, deterministic `{}`)",
                    case.metrics
                        .property_strength_score_percent
                        .map(|score| format!("{score}%"))
                        .unwrap_or_else(|| "n/a".to_string()),
                    case.metrics.property_no_panic,
                    case.metrics.property_deterministic
                );
                println!(
                    "- Generated test failures: `{}`",
                    case.metrics.generated_test_failures
                );
                println!("- Fuzz harnesses: `{}`", case.metrics.fuzz_harnesses);
                println!(
                    "- Fuzz targets executed: `{}`",
                    case.metrics.fuzz_targets_executed
                );
                println!("- Fuzz failures: `{}`", case.metrics.fuzz_failures);
                println!("- Persisted repros: `{}`", case.metrics.persisted_repros);
                println!(
                    "- Assertion candidates: `{}`",
                    case.metrics.assertion_candidates
                );
                println!("- Corpus entries: `{}`", case.metrics.corpus_entries);
                println!(
                    "- Corpus replayed/failed: `{}/{}`",
                    case.metrics.corpus_replayed, case.metrics.corpus_failed
                );
                println!("- Replay cases: `{}`", case.metrics.replay_cases);
                println!(
                    "- Budget skips/timeouts: `{}/{}`",
                    case.metrics.budget_skipped_commands, case.metrics.budget_timed_out_commands
                );
                println!(
                    "- Evolution: suites `{}`, candidates `{}`, selected `{}`, average fitness `{}`",
                    case.metrics.evolution_suites,
                    case.metrics.evolution_candidates,
                    case.metrics.evolution_selected,
                    case.metrics
                        .evolution_average_fitness_percent
                        .map(|score| format!("{score}%"))
                        .unwrap_or_else(|| "n/a".to_string())
                );
                if !case.metrics.findings_by_severity.is_empty() {
                    println!(
                        "- Findings by severity: `{}`",
                        format_counts(&case.metrics.findings_by_severity)
                    );
                }
                if !case.metrics.artifacts_by_kind.is_empty() {
                    println!(
                        "- Artifacts by kind: `{}`",
                        format_counts(&case.metrics.artifacts_by_kind)
                    );
                }
                println!("- Duration: `{}ms`", case.duration_ms);
                println!(
                    "- Status: `{}`",
                    if case.passed { "passed" } else { "failed" }
                );
                for missing in &case.missing_findings {
                    println!("- Missing finding: `{missing}`");
                }
                for missing in &case.missing_artifacts {
                    println!("- Missing artifact: `{missing}`");
                }
                for missing in &case.missing_commands {
                    println!("- Missing command: `{missing}`");
                }
                for failure in &case.threshold_failures {
                    println!("- Threshold failure: `{failure}`");
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("bench supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn print_conformance_report(report: &ConformanceReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => {
            println!("# veritas conformance\n");
            println!("- Passed: `{}`", report.passed);
            println!("- Plugins: `{}`", report.plugins.len());
            println!();
            println!("| Language | Project | Targets | Functions | Line ranges | Failures |");
            println!("| --- | --- | ---: | ---: | ---: | ---: |");
            for plugin in &report.plugins {
                println!(
                    "| {} | {} | {} | {} | {} | {} |",
                    plugin.language,
                    plugin.project,
                    plugin.targets,
                    plugin.function_targets,
                    plugin.line_ranges,
                    plugin.failures.len()
                );
            }
            for plugin in &report.plugins {
                if plugin.failures.is_empty() {
                    continue;
                }
                println!("\n## {}", plugin.language);
                for failure in &plugin.failures {
                    println!("- {failure}");
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("conformance supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn format_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn failure_severity_label(severity: &FailureSeverity) -> String {
    serde_json::to_value(severity)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("{severity:?}").to_ascii_lowercase())
}

fn safe_path_name(name: &str) -> String {
    let safe = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    safe.trim_matches('-').to_string()
}

fn print_promotion_summary(summary: &PromotionSummary) {
    print_named_promotion_summary("promote-repro", summary);
}

fn print_named_promotion_summary(command: &str, summary: &PromotionSummary) {
    if summary.dry_run {
        println!("# veritas {command} (dry run)\n");
    } else {
        println!("# veritas {command}\n");
    }

    if summary.paths.is_empty() {
        println!("No saved findings were available to promote.");
        return;
    }

    if summary.dry_run {
        println!("Would write promotion artifacts:");
    } else {
        println!("Wrote promotion artifacts:");
    }
    for path in &summary.paths {
        println!("- `{path}`");
    }
}

fn print_evolve_summary(summary: &EvolveSummary) {
    if summary.dry_run {
        println!("# veritas evolve (dry run)\n");
    } else {
        println!("# veritas evolve\n");
    }
    println!("- Language: `{}`", summary.language);
    println!("- Suite: `{}`", summary.suite_path);
    println!("- Candidates: `{}`", summary.candidates.len());
    if !summary.written_paths.is_empty() {
        println!("- Written artifacts: `{}`", summary.written_paths.len());
    }
    if let Some(evaluation) = &summary.evaluation {
        println!("- Evaluation: `{:?}`", evaluation.outcome);
        println!(
            "- Confidence delta: `{}` -> `{}` (`{:+}`)",
            evaluation.before_confidence,
            evaluation.after_confidence,
            evaluation.delta.confidence_delta
        );
        if let Some(score_delta) = evaluation.delta.mutation_score_delta {
            println!("- Mutation score delta: `{score_delta:+}`");
        }
        println!(
            "- Survivor/findings delta: `{:+}` / `{:+}`",
            evaluation.delta.surviving_mutants_delta, evaluation.delta.findings_delta
        );
        if let Some(error) = &evaluation.error {
            println!("- Evaluation error: {error}");
        }
    }
    println!();

    for candidate in &summary.candidates {
        println!(
            "## [{}] {} ({:?}, {:?})",
            candidate.index, candidate.id, candidate.kind, candidate.status
        );
        println!("- Target: `{}`", candidate.target_id);
        println!("- Fitness: `{}%`", candidate.fitness_percent);
        println!("- Action: {}", candidate.proposed_action);
        println!("- Keep if: {}", candidate.keep_if);
        if !candidate.proof_commands.is_empty() {
            println!("- Proof commands:");
            for command in &candidate.proof_commands {
                println!("  - `{command}`");
            }
        }
        if !candidate.done_when.is_empty() {
            println!("- Done when:");
            for criterion in &candidate.done_when {
                println!("  - {criterion}");
            }
        }
        if candidate.applied {
            println!("- Result: `applied`");
        } else if let Some(reason) = &candidate.skipped_reason {
            println!("- Result: `skipped` - {reason}");
        } else if summary.dry_run {
            println!("- Result: `would apply or inspect`");
        }
        if !candidate.written_paths.is_empty() {
            println!("- Wrote:");
            for path in &candidate.written_paths {
                println!("  - `{path}`");
            }
        }
        println!();
    }
}

fn print_baseline_summary(summary: &BaselineSummary) {
    println!("# veritas accept-baseline\n");
    println!("- Baseline: `{}`", summary.path);
    println!("- Accepted findings: `{}`", summary.accepted_ids.len());
}

fn print_quality_baseline_summary(summary: &QualityBaselineSummary) {
    println!("# veritas accept-quality-baseline\n");
    println!("- Baseline: `{}`", summary.path);
    println!("- Confidence: `{}`", summary.confidence);
    println!(
        "- Mutation score: `{}`",
        summary
            .mutation_score
            .map(|score| format!("{score}%"))
            .unwrap_or_else(|| "n/a".to_string())
    );
}

fn print_explanation(report: &VerificationReport, id: &str) -> Result<()> {
    let Some(finding) = report
        .findings
        .iter()
        .find(|finding| finding.id.as_deref() == Some(id))
    else {
        bail!("finding `{id}` was not found in the saved report");
    };
    println!("# veritas finding `{id}`\n");
    println!("- Message: {}", finding.message);
    println!("- Severity: {:?}", finding.severity);
    if let Some(target_id) = &finding.target_id {
        println!("- Target: `{target_id}`");
    }
    println!("- Command: `{}`", finding.command);
    if let Some(repro) = &finding.repro {
        println!("- Repro: `{}`", repro.command);
    }
    let patches = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ArtifactKind::CandidatePatch)
        .filter(|artifact| {
            finding
                .target_id
                .as_ref()
                .is_some_and(|target_id| &artifact.target_id == target_id)
        })
        .collect::<Vec<_>>();
    if !patches.is_empty() {
        println!("\nCandidate verification patch artifacts:");
        for patch in patches {
            println!("- `{}`", patch.path);
        }
    }
    Ok(())
}

fn apply_verify_profile(config: &mut VeritasConfig, profile: Option<VerifyProfile>) {
    let Some(VerifyProfile::Ci) = profile else {
        return;
    };

    config.budget_seconds = config.budget_seconds.min(120);
    config.fail_on_findings = true;
    if config.policy.fail_on_severity < FailureSeverity::Error {
        config.policy.fail_on_severity = FailureSeverity::Error;
    }

    config.plugins.rust.coverage_enabled = false;
    config.plugins.rust.command_timeout_seconds =
        config.plugins.rust.command_timeout_seconds.min(120);
    config.plugins.rust.coverage_timeout_seconds =
        config.plugins.rust.coverage_timeout_seconds.min(60);
    config.plugins.rust.cargo_jobs = config.plugins.rust.cargo_jobs.clamp(1, 2);
    config.plugins.rust.test_threads = config.plugins.rust.test_threads.clamp(1, 2);

    config.plugins.go.coverage_enabled = false;
    config.plugins.go.fuzz_seconds = config.plugins.go.fuzz_seconds.min(5);
    config.plugins.go.fuzz_concurrency = config.plugins.go.fuzz_concurrency.clamp(1, 2);
    config.plugins.go.reverse_dependency_depth = config.plugins.go.reverse_dependency_depth.min(1);
    config.plugins.go.max_fuzz_targets = config.plugins.go.max_fuzz_targets.min(5);
    config.plugins.go.command_timeout_seconds = config.plugins.go.command_timeout_seconds.min(90);
    config.plugins.go.max_packages = config.plugins.go.max_packages.min(16);
    config.plugins.go.max_mutants = config.plugins.go.max_mutants.min(4);
}

fn engine(config: VeritasConfig) -> CoreEngine {
    let registry = PluginRegistry::new(vec![
        Arc::new(RustPlugin::new(config.plugins.rust.clone())),
        Arc::new(GoPlugin::new(config.plugins.go.clone())),
        Arc::new(PythonPlugin::new(config.plugins.python.clone())),
    ]);
    CoreEngine::new(registry, config)
}

fn print_report(report: &VerificationReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Markdown => {
            println!("{}", render_markdown(report));
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        OutputFormat::Sarif => {
            println!("{}", render_sarif(report));
        }
        OutputFormat::Junit => {
            println!("{}", render_junit(report));
        }
    }
    Ok(())
}

fn print_score(
    root: &Path,
    report: &VerificationReport,
    format: OutputFormat,
    mode: ScoreMode,
) -> Result<()> {
    let score = confidence_score_for_root(root, report);
    if mode != ScoreMode::Current {
        let mode_report = score_mode_report(root, report, &score, mode);
        return print_score_mode_report(&mode_report, format);
    }
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&score)?),
        OutputFormat::Markdown => {
            println!("# veritas score\n");
            println!("- Score: `{}`", score.score);
            println!("- Grade: `{:?}`", score.grade);
            println!("- Summary: {}", score.summary);
            if let Some(delta) = &score.baseline_delta {
                println!("\n## Baseline Delta\n");
                println!(
                    "- Mutation score delta: `{}`",
                    delta
                        .mutation_score_delta
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "n/a".to_string())
                );
                println!("- Confidence delta: `{}`", delta.confidence_delta);
                println!(
                    "- Surviving mutants delta: `{}`",
                    delta.surviving_mutants_delta
                );
                println!("- Corpus entries delta: `{}`", delta.corpus_entries_delta);
            }
            if !score.positive_signals.is_empty() {
                println!("\n## Positive Signals\n");
                for signal in &score.positive_signals {
                    println!("- {signal}");
                }
            }
            if !score.risks.is_empty() {
                println!("\n## Risks\n");
                for risk in &score.risks {
                    println!("- {risk}");
                }
            }
            println!("\n## Next Steps\n");
            for step in &score.recommended_next_steps {
                println!("- {step}");
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("score supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn score_mode_report(
    root: &Path,
    report: &VerificationReport,
    current: &veritas_plugin_api::ConfidenceScore,
    mode: ScoreMode,
) -> ScoreModeReport {
    let accepted_count = accepted_finding_ids(root).map(|ids| ids.len()).unwrap_or(0);
    let modes = match mode {
        ScoreMode::Current => vec![ScoreMode::Current],
        ScoreMode::Strict => vec![ScoreMode::Strict],
        ScoreMode::Verified => vec![ScoreMode::Verified],
        ScoreMode::All => vec![ScoreMode::Current, ScoreMode::Strict, ScoreMode::Verified],
    }
    .into_iter()
    .map(|mode| score_mode_view(report, current, accepted_count, mode))
    .collect();
    ScoreModeReport {
        source: ".veritas/report.json".to_string(),
        modes,
    }
}

fn score_mode_view(
    report: &VerificationReport,
    current: &veritas_plugin_api::ConfidenceScore,
    accepted_count: usize,
    mode: ScoreMode,
) -> ScoreModeView {
    let mut score = i16::from(current.score);
    let mut adjustments = Vec::new();
    if matches!(mode, ScoreMode::Strict | ScoreMode::Verified) {
        if accepted_count > 0 {
            let penalty = (accepted_count as i16 * 3).min(15);
            score -= penalty;
            adjustments.push(format!("accepted findings remain score debt: -{penalty}"));
        }
        if report.quality.budget.skipped_commands > 0 {
            let penalty = (report.quality.budget.skipped_commands as i16 * 2).min(10);
            score -= penalty;
            adjustments.push(format!("skipped verification commands: -{penalty}"));
        }
    }
    if mode == ScoreMode::Verified {
        if report.quality.regression.promoted_scaffolds > 0 {
            let penalty = (report.quality.regression.promoted_scaffolds as i16 * 2).min(12);
            score -= penalty;
            adjustments.push(format!(
                "unreviewed generated regression scaffolds need proof: -{penalty}"
            ));
        }
        if report.quality.regression.assertion_candidates > 0 {
            let penalty = (report.quality.regression.assertion_candidates as i16).min(10);
            score -= penalty;
            adjustments.push(format!(
                "assertion candidates are not owned tests yet: -{penalty}"
            ));
        }
        if report.quality.mutation.survived > 0 {
            let penalty = (report.quality.mutation.survived as i16 * 2).min(12);
            score -= penalty;
            adjustments.push(format!(
                "surviving mutants remain verified debt: -{penalty}"
            ));
        }
    }
    if adjustments.is_empty() {
        adjustments.push("no additional anti-gaming adjustment for this mode".to_string());
    }
    let score = score.clamp(0, 100) as u8;
    ScoreModeView {
        mode,
        score,
        grade: score_grade_label(score).to_string(),
        delta_from_current: i16::from(score) - i16::from(current.score),
        summary: score_mode_summary(mode).to_string(),
        adjustments,
        risks: current.risks.clone(),
        positive_signals: current.positive_signals.clone(),
        recommended_next_steps: current.recommended_next_steps.clone(),
    }
}

fn score_grade_label(score: u8) -> &'static str {
    if score >= 80 {
        "high"
    } else if score >= 55 {
        "medium"
    } else {
        "low"
    }
}

fn score_mode_summary(mode: ScoreMode) -> &'static str {
    match mode {
        ScoreMode::Current => "current confidence from the latest report",
        ScoreMode::Strict => "current confidence plus accepted-finding and skipped-command debt",
        ScoreMode::Verified => {
            "strict confidence plus unpromoted candidate and surviving-mutant proof debt"
        }
        ScoreMode::All => "all score modes",
    }
}

fn print_score_mode_report(report: &ScoreModeReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => {
            println!("# veritas score modes\n");
            println!("- Source: `{}`", report.source);
            for mode in &report.modes {
                println!("\n## {:?}\n", mode.mode);
                println!("- Score: `{}`", mode.score);
                println!("- Grade: `{}`", mode.grade);
                println!("- Delta from current: `{:+}`", mode.delta_from_current);
                println!("- Summary: {}", mode.summary);
                println!("- Adjustments:");
                for adjustment in &mode.adjustments {
                    println!("  - {adjustment}");
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("score supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn print_next_queue(queue: &NextQueue, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(queue)?),
        OutputFormat::Markdown => {
            println!("# veritas next\n");
            println!("- Source: `{}`", queue.source);
            println!("- Queue size: `{}`", queue.total_candidates);
            println!("- Returned: `{}`", queue.returned);
            if queue.items.is_empty() {
                println!("\nNo active findings or selected evolution candidates. Run `veritas verify` or keep this report as the current baseline.");
                return Ok(());
            }
            for item in &queue.items {
                println!("\n## [{}] {}", item.rank, item.title);
                println!("- Source: `{}`", item.source);
                println!("- ID: `{}`", item.id);
                if let Some(target_id) = &item.target_id {
                    println!("- Target: `{target_id}`");
                }
                println!("- Tier: `T{}`", item.tier);
                println!(
                    "- Estimated confidence impact: `{:+}`",
                    item.estimated_confidence_impact
                );
                println!("- Reason codes: `{}`", item.reason_codes.join(", "));
                println!("- Action: {}", item.action);
                if !item.proof_commands.is_empty() {
                    println!("- Proof commands:");
                    for command in &item.proof_commands {
                        println!("  - `{command}`");
                    }
                }
                if !item.done_when.is_empty() {
                    println!("- Done when:");
                    for criterion in &item.done_when {
                        println!("  - {criterion}");
                    }
                }
                if !item.explanation.is_empty() {
                    println!("- Why this is next:");
                    for line in &item.explanation {
                        println!("  - {line}");
                    }
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("next supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn print_review_packet_summary(summary: &ReviewPacketSummary) {
    println!("# veritas review-packet\n");
    println!("- Query: `{}`", summary.query_path.display());
    println!("- Prompt: `{}`", summary.prompt_path.display());
    println!("- Targets: `{}`", summary.targets);
    println!("- Dimensions: `{}`", summary.dimensions.join(", "));
}

fn print_agent_instruction_summary(summary: &AgentInstructionSummary) {
    println!("# veritas agent-instructions\n");
    println!("- Agent: `{:?}`", summary.agent);
    println!("- Path: `{}`", summary.path.display());
}

fn print_corpus_replay_summary(summary: &CorpusReplaySummary, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary.report)?),
        OutputFormat::Markdown => {
            println!(
                "# veritas replay-corpus{}\n",
                if summary.dry_run { " (dry run)" } else { "" }
            );
            println!(
                "- Replayed: `{}`",
                summary.report.quality.regression.corpus_replayed
            );
            println!(
                "- Passed: `{}`",
                summary.report.quality.regression.corpus_passed
            );
            println!(
                "- Failed: `{}`",
                summary.report.quality.regression.corpus_failed
            );
            println!(
                "- Skipped: `{}`",
                summary.report.quality.regression.corpus_skipped
            );
            for run in &summary.report.runs {
                for command in &run.commands {
                    println!(
                        "- `{} {}` -> {:?}",
                        command.program,
                        command.args.join(" "),
                        command.status
                    );
                }
            }
        }
        OutputFormat::Sarif | OutputFormat::Junit => {
            bail!("replay-corpus supports --format markdown or --format json")
        }
    }
    Ok(())
}

fn print_cleanup_summary(summary: &CleanupSummary) {
    if summary.dry_run {
        println!("# veritas cleanup (dry run)\n");
    } else {
        println!("# veritas cleanup\n");
    }

    if summary.paths.is_empty() {
        println!("No generated veritas artifacts found.");
        return;
    }

    if summary.dry_run {
        println!("Would remove generated artifacts:");
    } else {
        println!("Removed generated artifacts:");
    }
    for path in &summary.paths {
        println!("- `{path}`");
    }
}

fn enforce_failure_policy(config: &VeritasConfig, report: &VerificationReport) -> Result<()> {
    if let Some(min_score) = config.policy.min_mutation_score {
        match report.quality.mutation.score_percent {
            Some(score) if score < min_score => {
                bail!("mutation score {score}% is below policy minimum {min_score}%");
            }
            None => {
                bail!("mutation score was unavailable but policy minimum is {min_score}%");
            }
            _ => {}
        }
    }
    if let Some(min_efficacy) = config.policy.min_mutation_efficacy {
        match report.quality.mutation.efficacy_percent {
            Some(score) if score < min_efficacy => {
                bail!("mutation efficacy {score}% is below policy minimum {min_efficacy}%");
            }
            None => {
                bail!("mutation efficacy was unavailable but policy minimum is {min_efficacy}%");
            }
            _ => {}
        }
    }
    if let Some(min_coverage) = config.policy.min_mutant_coverage {
        match report.quality.mutation.mutant_coverage_percent {
            Some(score) if score < min_coverage => {
                bail!("mutant coverage {score}% is below policy minimum {min_coverage}%");
            }
            None => {
                bail!("mutant coverage was unavailable but policy minimum is {min_coverage}%");
            }
            _ => {}
        }
    }

    if config.fail_on_findings {
        let accepted = report
            .project
            .as_ref()
            .and_then(|project| accepted_finding_ids(project.root.as_std_path()).ok())
            .unwrap_or_default();
        let policy_failures = report
            .findings
            .iter()
            .filter(|finding| !finding.id.as_ref().is_some_and(|id| accepted.contains(id)))
            .filter(|finding| finding_matches_policy(config, report, finding))
            .count();
        if policy_failures > 0 {
            bail!("verification produced {policy_failures} policy-failing finding(s)");
        }
    }
    Ok(())
}

fn finding_matches_policy(
    config: &VeritasConfig,
    report: &VerificationReport,
    finding: &veritas_plugin_api::Failure,
) -> bool {
    if finding.severity < config.policy.fail_on_severity {
        return false;
    }

    if !config.policy.fail_on_languages.is_empty() {
        let language = finding_language(report, finding);
        if !language.is_some_and(|language| {
            config
                .policy
                .fail_on_languages
                .iter()
                .any(|configured| configured == &language)
        }) {
            return false;
        }
    }

    if !config.policy.fail_on_artifact_kinds.is_empty() {
        let artifact_kind = finding_artifact_kind(report, finding);
        if !artifact_kind.is_some_and(|kind| {
            config
                .policy
                .fail_on_artifact_kinds
                .iter()
                .any(|configured| configured == &artifact_kind_label(kind))
        }) {
            return false;
        }
    }

    if !config.policy.fail_on_target_risks.is_empty() {
        let target_risk = finding_target_risk(report, finding);
        if !target_risk.is_some_and(|risk| {
            config
                .policy
                .fail_on_target_risks
                .iter()
                .any(|configured| configured == risk)
        }) {
            return false;
        }
    }

    true
}

fn finding_language(
    report: &VerificationReport,
    finding: &veritas_plugin_api::Failure,
) -> Option<String> {
    if let Some(target_id) = &finding.target_id {
        if let Some((language, _)) = target_id.split_once(':') {
            return Some(language.to_string());
        }
    }
    let artifact_id = finding.artifact_id.as_ref()?;
    report
        .artifacts
        .iter()
        .find(|artifact| &artifact.id == artifact_id)
        .map(|artifact| artifact.language.clone())
}

fn finding_artifact_kind<'a>(
    report: &'a VerificationReport,
    finding: &veritas_plugin_api::Failure,
) -> Option<&'a ArtifactKind> {
    let artifact_id = finding.artifact_id.as_ref()?;
    report
        .artifacts
        .iter()
        .find(|artifact| &artifact.id == artifact_id)
        .map(|artifact| &artifact.kind)
}

fn finding_target_risk<'a>(
    report: &'a VerificationReport,
    finding: &veritas_plugin_api::Failure,
) -> Option<&'a RiskLevel> {
    let target_id = finding.target_id.as_ref()?;
    report
        .targets
        .iter()
        .find(|target| &target.id == target_id)
        .map(|target| &target.risk)
}

fn artifact_kind_label(kind: &ArtifactKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("{kind:?}").to_ascii_lowercase())
}

fn infer_language(
    root: &std::path::Path,
    target: Option<&std::path::Path>,
    strategy: &VerificationStrategy,
) -> Result<String> {
    if let Some(target) = target {
        if target.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            return Ok("rust".to_string());
        }
        if target.extension().and_then(|ext| ext.to_str()) == Some("go") {
            return Ok("go".to_string());
        }
        if target.extension().and_then(|ext| ext.to_str()) == Some("py") {
            return Ok("python".to_string());
        }
    }
    if matches!(strategy, VerificationStrategy::Fuzzing) && root.join("go.mod").exists() {
        return Ok("go".to_string());
    }
    if root.join("Cargo.toml").exists() {
        return Ok("rust".to_string());
    }
    if root.join("go.mod").exists() {
        return Ok("go".to_string());
    }
    if root.join("pyproject.toml").exists()
        || root.join("setup.py").exists()
        || root.join("setup.cfg").exists()
    {
        return Ok("python".to_string());
    }
    bail!("could not infer language; pass --lang rust, --lang go, or --lang python")
}

fn with_current_dir<T>(root: &std::path::Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let previous = std::env::current_dir()?;
    std::env::set_current_dir(root)
        .with_context(|| format!("failed to set current directory to {}", root.display()))?;
    let result = f();
    std::env::set_current_dir(&previous).with_context(|| {
        format!(
            "failed to restore current directory to {}",
            previous.display()
        )
    })?;
    result
}
