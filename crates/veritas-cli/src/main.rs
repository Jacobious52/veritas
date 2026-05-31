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
    CorpusReplaySummary, PluginRegistry, PromotionSummary, QualityBaselineSummary,
};
use veritas_go::GoPlugin;
use veritas_plugin_api::{
    ArtifactKind, FailureSeverity, RiskLevel, VerificationReport, VerificationStrategy,
};
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
    Report {
        #[arg(long, value_enum, default_value_t = OutputFormat::Markdown)]
        format: OutputFormat,
    },
    Score {
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
    AcceptBaseline {
        #[arg(long)]
        id: Vec<String>,

        #[arg(long)]
        all: bool,
    },
    Bench {
        #[arg(long)]
        suite: Option<PathBuf>,

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

#[derive(Debug, Deserialize)]
struct BenchSuite {
    #[serde(rename = "case")]
    cases: Vec<BenchCase>,
}

#[derive(Debug, Deserialize)]
struct BenchCase {
    name: String,
    path: PathBuf,
    language: String,
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
    max_surviving_mutants: Option<usize>,
    min_generated_test_failures: Option<usize>,
    min_assertion_candidates: Option<usize>,
    min_corpus_entries: Option<usize>,
    min_replay_cases: Option<usize>,
    max_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BenchReport {
    suite: String,
    passed: bool,
    cases: Vec<BenchCaseReport>,
}

#[derive(Debug, Serialize)]
struct BenchCaseReport {
    name: String,
    language: String,
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
    command_count: usize,
    findings_by_severity: BTreeMap<String, usize>,
    artifacts_by_kind: BTreeMap<String, usize>,
    mutants_generated: usize,
    mutants_executed: usize,
    mutants_killed: usize,
    mutants_survived: usize,
    mutants_skipped: usize,
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
                    "Run `veritas verify --lang rust --target <path>` or `veritas verify --lang go --target <path>`.".to_string(),
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
        Command::Report { format } => {
            let report = read_saved_report(&root)?;
            print_report(&report, format)?;
        }
        Command::Score { format } => {
            let report = read_saved_report(&root)?;
            print_score(&root, &report, format)?;
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
        Command::AcceptBaseline { id, all } => {
            if id.is_empty() && !all {
                bail!("pass --id <finding-id> or --all");
            }
            let summary = accept_findings(&root, &id, all)?;
            print_baseline_summary(&summary);
        }
        Command::Bench { suite, format } => {
            let report = run_bench_suite(&root, suite.as_deref())?;
            print_bench_report(&report, format)?;
            if !report.passed {
                bail!("benchmark suite did not meet expected detections");
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

    let mut cases = Vec::new();
    for case in suite.cases {
        cases.push(run_bench_case(suite_root, case)?);
    }
    let passed = cases.iter().all(|case| case.passed);
    Ok(BenchReport {
        suite: suite_path.display().to_string(),
        passed,
        cases,
    })
}

fn run_bench_case(suite_root: &Path, case: BenchCase) -> Result<BenchCaseReport> {
    let start = std::time::Instant::now();
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
    if let Some(max_duration_ms) = case.max_duration_ms {
        if duration_ms > u128::from(max_duration_ms) {
            failures.push(format!(
                "duration_ms {duration_ms} > max_duration_ms {max_duration_ms}"
            ));
        }
    }
    failures
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
            println!("- Cases: `{passed}/{}` passed", report.cases.len());
            println!(
                "- Status: `{}`",
                if report.passed { "passed" } else { "failed" }
            );
            for case in &report.cases {
                println!("\n## {}", case.name);
                println!("- Language: `{}`", case.language);
                println!("- Findings: `{}`", case.findings);
                println!("- Artifacts: `{}`", case.artifacts);
                println!("- Commands: `{}`", case.metrics.command_count);
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

fn print_score(root: &Path, report: &VerificationReport, format: OutputFormat) -> Result<()> {
    let score = confidence_score_for_root(root, report);
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
    bail!("could not infer language; pass --lang rust or --lang go")
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
