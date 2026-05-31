use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use veritas_core::{
    accept_findings, accepted_finding_ids, cleanup_generated_artifacts, config::VeritasConfig,
    promote_repros, read_saved_report, strategy_from_kind, BaselineSummary, CleanupSummary,
    CoreEngine, PluginRegistry, PromotionSummary,
};
use veritas_go::GoPlugin;
use veritas_plugin_api::{
    ArtifactKind, FailureSeverity, RiskLevel, VerificationReport, VerificationStrategy,
};
use veritas_report::{render_junit, render_markdown, render_sarif};
use veritas_rust::RustPlugin;

#[derive(Debug, Parser)]
#[command(name = "veritas")]
#[command(about = "AI-native verification engine for vibe-coded software")]
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
    AcceptBaseline {
        #[arg(long)]
        id: Vec<String>,

        #[arg(long)]
        all: bool,
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
        Command::AcceptBaseline { id, all } => {
            if id.is_empty() && !all {
                bail!("pass --id <finding-id> or --all");
            }
            let summary = accept_findings(&root, &id, all)?;
            print_baseline_summary(&summary);
        }
    }

    Ok(())
}

fn print_promotion_summary(summary: &PromotionSummary) {
    if summary.dry_run {
        println!("# veritas promote-repro (dry run)\n");
    } else {
        println!("# veritas promote-repro\n");
    }

    if summary.paths.is_empty() {
        println!("No saved repro findings were available to promote.");
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
