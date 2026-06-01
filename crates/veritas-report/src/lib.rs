use veritas_plugin_api::{
    ArtifactKind, Failure, FailureSeverity, GeneratedArtifact, RiskLevel, VerificationReport,
    VerificationTarget,
};

pub fn render_markdown(report: &VerificationReport) -> String {
    let mut out = String::new();
    out.push_str("# veritas verification report\n\n");

    if let Some(project) = &report.project {
        out.push_str("## Project\n\n");
        out.push_str(&format!("- Language: `{}`\n", project.language));
        out.push_str(&format!("- Name: `{}`\n", project.name));
        out.push_str(&format!("- Root: `{}`\n", project.root));
        if !project.manifests.is_empty() {
            out.push_str("- Manifests:\n");
            for manifest in &project.manifests {
                out.push_str(&format!("  - `{manifest}`\n"));
            }
        }
        out.push('\n');
    }

    if !report.targets.is_empty() {
        out.push_str("## Targets\n\n");
        for target in &report.targets {
            let symbol = target
                .symbol
                .as_ref()
                .map(|symbol| format!(" `{symbol}`"))
                .unwrap_or_default();
            out.push_str(&format!(
                "- {:?}: `{}`{} - risk: **{}**{}\n",
                target.kind,
                target.path,
                symbol,
                risk_label(&target.risk),
                target
                    .line_range
                    .as_ref()
                    .map(|range| format!(" (lines {}-{})", range.start, range.end))
                    .unwrap_or_default()
            ));
        }
        out.push('\n');
    }

    if let Some(plan) = &report.plan {
        out.push_str("## Plan\n\n");
        out.push_str(&format!("- Budget: {} seconds\n", plan.budget_seconds));
        out.push_str(&format!(
            "- Write generated tests: `{}`\n",
            plan.write_generated_tests
        ));
        out.push_str("- Strategies:\n");
        for strategy in &plan.strategies {
            out.push_str(&format!("  - `{:?}`\n", strategy));
        }
        out.push('\n');
    }

    if !report.artifacts.is_empty() {
        out.push_str("## Generated Artifacts\n\n");
        for artifact in &report.artifacts {
            out.push_str(&format!(
                "- {} `{}` ({:?}, {:?})\n",
                artifact_icon(artifact),
                artifact.path,
                artifact.kind,
                artifact.status
            ));
        }
        out.push('\n');
    }

    if !report.runs.is_empty() {
        out.push_str("## Commands Run\n\n");
        for run in &report.runs {
            out.push_str(&format!(
                "- `{}` run: **{:?}** ({} ms)\n",
                run.language, run.status, run.duration_ms
            ));
            for command in &run.commands {
                out.push_str(&format!(
                    "  - `{}` -> {:?} ({} ms)\n",
                    command_line(&command.program, &command.args),
                    command.status,
                    command.duration_ms
                ));
            }
        }
        out.push('\n');
    }

    if report.quality.mutation.generated > 0
        || report.quality.property.generated_artifacts > 0
        || report.quality.fuzz.generated_harnesses > 0
        || report.quality.fuzz.targets_executed > 0
        || report.quality.regression.assertion_candidates > 0
        || report.quality.replay.cases > 0
        || report.quality.budget.budget_plans > 0
        || report.quality.evolution.candidates > 0
    {
        out.push_str("## Quality Metrics\n\n");
        if report.quality.performance.total_ms > 0 {
            out.push_str(&format!(
                "- Performance: total `{}` ms (discovery `{}`, generation `{}`, tests `{}`, coverage `{}`, replay `{}`, synthesis `{}`)\n",
                report.quality.performance.total_ms,
                report.quality.performance.discovery_ms,
                report.quality.performance.generation_ms,
                report.quality.performance.test_execution_ms,
                report.quality.performance.coverage_ms,
                report.quality.performance.replay_ms,
                report.quality.performance.artifact_synthesis_ms,
            ));
        }
        if report.quality.mutation.generated > 0 {
            out.push_str(&format!(
                "- Mutation score: `{}` (generated: `{}`, runnable: `{}`, executed: `{}`, killed: `{}`, survived: `{}`, not covered: `{}`, timed out: `{}`, not viable: `{}`, skipped: `{}`)\n",
                report
                    .quality
                    .mutation
                    .score_percent
                    .map(|score| format!("{score}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                report.quality.mutation.generated,
                report.quality.mutation.runnable,
                report.quality.mutation.executed,
                report.quality.mutation.killed,
                report.quality.mutation.survived,
                report.quality.mutation.not_covered,
                report.quality.mutation.timed_out,
                report.quality.mutation.not_viable,
                report.quality.mutation.skipped,
            ));
            if report.quality.mutation.efficacy_percent.is_some()
                || report.quality.mutation.mutant_coverage_percent.is_some()
            {
                out.push_str(&format!(
                    "  - Efficacy: `{}`, mutant coverage: `{}`\n",
                    report
                        .quality
                        .mutation
                        .efficacy_percent
                        .map(|score| format!("{score}%"))
                        .unwrap_or_else(|| "n/a".to_string()),
                    report
                        .quality
                        .mutation
                        .mutant_coverage_percent
                        .map(|score| format!("{score}%"))
                        .unwrap_or_else(|| "n/a".to_string())
                ));
            }
            if report.quality.mutation.requested_workers > 0
                || report.quality.mutation.effective_workers > 0
                || report.quality.mutation.isolation_failures > 0
            {
                out.push_str(&format!(
                    "  - Mutation workers: requested `{}`, effective `{}`, isolation failures `{}`\n",
                    report.quality.mutation.requested_workers,
                    report.quality.mutation.effective_workers,
                    report.quality.mutation.isolation_failures,
                ));
            }
            if report.quality.mutation.computed_timeout_seconds.is_some()
                || report.quality.mutation.baseline_duration_ms.is_some()
            {
                out.push_str(&format!(
                    "  - Mutation timeout: baseline `{}`, computed `{}`, source `{}`\n",
                    report
                        .quality
                        .mutation
                        .baseline_duration_ms
                        .map(|duration| format!("{duration}ms"))
                        .unwrap_or_else(|| "n/a".to_string()),
                    report
                        .quality
                        .mutation
                        .computed_timeout_seconds
                        .map(|timeout| format!("{timeout}s"))
                        .unwrap_or_else(|| "n/a".to_string()),
                    report
                        .quality
                        .mutation
                        .timeout_source
                        .as_deref()
                        .unwrap_or("n/a")
                ));
            }
            if !report.quality.mutation.by_domain.is_empty() {
                out.push_str(&format!(
                    "  - Domains: `{}`\n",
                    attribution_counts(&report.quality.mutation.by_domain)
                ));
            }
            if !report.quality.mutation.by_operator.is_empty() {
                out.push_str(&format!(
                    "  - Operators: `{}`\n",
                    attribution_counts(&report.quality.mutation.by_operator)
                ));
            }
        }
        if report.quality.property.generated_artifacts > 0
            || report.quality.property.failed_generated_tests > 0
        {
            out.push_str(&format!(
                "- Property tests: generated artifacts `{}`, no-panic `{}`, deterministic `{}`, strength `{}`, generated-test failures `{}`\n",
                report.quality.property.generated_artifacts,
                report.quality.property.no_panic_properties,
                report.quality.property.deterministic_properties,
                report
                    .quality
                    .property
                    .strength_score_percent
                    .map(|score| format!("{score}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                report.quality.property.failed_generated_tests
            ));
        }
        if report.quality.fuzz.generated_harnesses > 0 || report.quality.fuzz.targets_executed > 0 {
            out.push_str(&format!(
                "- Fuzzing: generated harnesses `{}`, targets executed `{}`, failures `{}`, persisted repros `{}`\n",
                report.quality.fuzz.generated_harnesses,
                report.quality.fuzz.targets_executed,
                report.quality.fuzz.failures,
                report.quality.fuzz.persisted_repros
            ));
        }
        if report.quality.regression.assertion_candidates > 0
            || report.quality.regression.corpus_entries > 0
        {
            out.push_str(&format!(
                "- Regression loop: assertion candidates `{}`, promoted scaffolds `{}`, corpus entries `{}`, corpus replayed `{}`, corpus failed `{}`\n",
                report.quality.regression.assertion_candidates,
                report.quality.regression.promoted_scaffolds,
                report.quality.regression.corpus_entries,
                report.quality.regression.corpus_replayed,
                report.quality.regression.corpus_failed
            ));
        }
        if report.quality.replay.cases > 0 {
            out.push_str(&format!(
                "- Differential replay: manifests `{}`, targets `{}`, cases `{}`, result artifacts `{}`\n",
                report.quality.replay.manifests,
                report.quality.replay.targets,
                report.quality.replay.cases,
                report.quality.replay.results
            ));
        }
        if report.quality.budget.budget_plans > 0
            || report.quality.budget.skipped_commands > 0
            || report.quality.budget.timed_out_commands > 0
        {
            out.push_str(&format!(
                "- Budgets: plans `{}`, skipped commands `{}`, timed-out commands `{}`\n",
                report.quality.budget.budget_plans,
                report.quality.budget.skipped_commands,
                report.quality.budget.timed_out_commands
            ));
        }
        if report.quality.evolution.candidates > 0 {
            out.push_str(&format!(
                "- Evolution: suites `{}`, candidates `{}`, selected `{}`, average fitness `{}` (mutation `{}`, property `{}`, fuzz `{}`, regression `{}`, replay `{}`)\n",
                report.quality.evolution.suites,
                report.quality.evolution.candidates,
                report.quality.evolution.selected,
                report
                    .quality
                    .evolution
                    .average_fitness_percent
                    .map(|score| format!("{score}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                report.quality.evolution.mutation_candidates,
                report.quality.evolution.property_candidates,
                report.quality.evolution.fuzz_candidates,
                report.quality.evolution.regression_candidates,
                report.quality.evolution.replay_candidates,
            ));
        }
        out.push('\n');
    }

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No failing verification findings were detected in this run.\n\n");
    } else {
        for failure in &report.findings {
            out.push_str(&format!("- **{}**\n", failure.message));
            if let Some(id) = &failure.id {
                out.push_str(&format!("  - ID: `{id}`\n"));
            }
            out.push_str(&format!(
                "  - Severity: `{}`\n",
                severity_label(&failure.severity)
            ));
            out.push_str(&format!("  - Command: `{}`\n", failure.command));
            if let Some(target_id) = &failure.target_id {
                out.push_str(&format!("  - Target: `{target_id}`\n"));
            }
            if let Some(artifact_id) = &failure.artifact_id {
                out.push_str(&format!("  - Artifact: `{artifact_id}`\n"));
            }
            if let Some(repro) = &failure.repro {
                out.push_str(&format!("  - Repro: `{}`\n", repro.command));
            }
        }
        out.push('\n');
    }

    if !report.coverage.is_empty() {
        out.push_str("## Coverage\n\n");
        for coverage in &report.coverage {
            out.push_str(&format!("- `{}`: {}\n", coverage.tool, coverage.summary));
        }
        out.push('\n');
    }

    if !report.suggested_next_steps.is_empty() {
        out.push_str("## Suggested Next Steps\n\n");
        for step in &report.suggested_next_steps {
            out.push_str(&format!("- {step}\n"));
        }
    }

    out
}

pub fn render_junit(report: &VerificationReport) -> String {
    let tests = report.findings.len().max(1);
    let failures = report.findings.len();
    let mut out = String::new();
    out.push_str(&format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"veritas\" tests=\"{tests}\" failures=\"{failures}\">\n"
    ));
    if report.findings.is_empty() {
        out.push_str("  <testcase classname=\"veritas\" name=\"verification\" />\n");
    } else {
        for (index, finding) in report.findings.iter().enumerate() {
            out.push_str(&format!(
                "  <testcase classname=\"veritas\" name=\"finding-{index}\">\n    <failure message=\"{}\">{}</failure>\n  </testcase>\n",
                xml_escape(&finding.message),
                xml_escape(&trim_junit_body(finding))
            ));
        }
    }
    out.push_str("</testsuite>\n");
    out
}

pub fn render_sarif(report: &VerificationReport) -> String {
    let results = report
        .findings
        .iter()
        .map(|finding| {
            let target = finding_target(report, finding);
            let uri = target
                .map(|target| target.path.to_string())
                .or_else(|| {
                    finding
                        .repro
                        .as_ref()
                        .and_then(|repro| repro.path.as_ref())
                        .map(ToString::to_string)
                })
                .unwrap_or_else(|| "veritas".to_string());
            let region = target
                .and_then(|target| target.line_range.as_ref())
                .map(|range| {
                    format!(
                        r#", "region": {{ "startLine": {}, "endLine": {} }}"#,
                        range.start, range.end
                    )
                })
                .unwrap_or_default();
            format!(
                r#"{{
          "ruleId": "veritas.finding",
          "level": "{}",
          "message": {{ "text": "{}" }},
          "locations": [{{ "physicalLocation": {{ "artifactLocation": {{ "uri": "{}" }}{} }} }}]
        }}"#,
                sarif_level(&finding.severity),
                json_escape(&finding.message),
                json_escape(&uri),
                region
            )
        })
        .collect::<Vec<_>>()
        .join(",\n        ");
    format!(
        r#"{{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {{
      "tool": {{
        "driver": {{
          "name": "veritas",
          "informationUri": "https://github.com/Jacobious52/veritas",
          "rules": [
            {{
              "id": "veritas.finding",
              "name": "Verification finding",
              "shortDescription": {{ "text": "veritas verification finding" }}
            }}
          ]
        }}
      }},
      "results": [
        {results}
      ]
    }}
  ]
}}
"#
    )
}

fn artifact_icon(artifact: &GeneratedArtifact) -> &'static str {
    match artifact.kind {
        ArtifactKind::PropertyTest => "[property]",
        ArtifactKind::FuzzHarness => "[fuzz]",
        ArtifactKind::UnitTest => "[unit]",
        ArtifactKind::HarnessIndex => "[index]",
        ArtifactKind::MutationCheck => "[mutation]",
        ArtifactKind::CoverageFeedback => "[feedback]",
        ArtifactKind::DifferentialBaseline => "[baseline]",
        ArtifactKind::ReproCase => "[repro]",
        ArtifactKind::PackageAwareness => "[packages]",
        ArtifactKind::PackageGraph => "[graph]",
        ArtifactKind::SymbolGraph => "[symbols]",
        ArtifactKind::ChangeDigest => "[digest]",
        ArtifactKind::AiFeedback => "[ai]",
        ArtifactKind::CandidatePatch => "[patch]",
        ArtifactKind::FindingBaseline => "[baseline]",
        ArtifactKind::RegressionTest => "[regression]",
        ArtifactKind::DifferentialReplay => "[replay]",
        ArtifactKind::EvolutionPlan => "[evolution]",
        ArtifactKind::AssertionCandidate => "[assertion]",
        ArtifactKind::CorpusEntry => "[corpus]",
        ArtifactKind::ReplayResult => "[replay-result]",
        ArtifactKind::BudgetPlan => "[budget]",
        ArtifactKind::ConfidenceScore => "[score]",
        ArtifactKind::MutationTrend => "[trend]",
        ArtifactKind::MutationCampaign => "[campaign]",
        ArtifactKind::EvolutionCandidate => "[candidate]",
        ArtifactKind::EvolutionSuite => "[evolution-suite]",
        ArtifactKind::CorpusReplay => "[corpus-replay]",
        ArtifactKind::TargetCache => "[cache]",
        ArtifactKind::SiteAsset => "[site]",
    }
}

fn attribution_counts(
    counts: &std::collections::BTreeMap<String, veritas_plugin_api::MutationAttribution>,
) -> String {
    counts
        .iter()
        .map(|(label, value)| {
            format!(
                "{label}=generated:{}, killed:{}, survived:{}",
                value.generated, value.killed, value.survived
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn risk_label(risk: &RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    }
}

fn severity_label(severity: &FailureSeverity) -> &'static str {
    match severity {
        FailureSeverity::Info => "info",
        FailureSeverity::Warning => "warning",
        FailureSeverity::Error => "error",
        FailureSeverity::Critical => "critical",
    }
}

fn sarif_level(severity: &FailureSeverity) -> &'static str {
    match severity {
        FailureSeverity::Info => "note",
        FailureSeverity::Warning => "warning",
        FailureSeverity::Error | FailureSeverity::Critical => "error",
    }
}

fn finding_target<'a>(
    report: &'a VerificationReport,
    finding: &Failure,
) -> Option<&'a VerificationTarget> {
    let target_id = finding.target_id.as_ref()?;
    report.targets.iter().find(|target| &target.id == target_id)
}

fn trim_junit_body(finding: &Failure) -> String {
    let body = if finding.stdout_excerpt.trim().is_empty() {
        finding.stderr_excerpt.as_str()
    } else {
        finding.stdout_excerpt.as_str()
    };
    const LIMIT: usize = 1200;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut trimmed = body.chars().take(LIMIT).collect::<String>();
    trimmed.push_str("\n... truncated by veritas ...");
    trimmed
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn command_line(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use veritas_plugin_api::{
        Failure, FailureSeverity, LineRange, ReproCase, RiskLevel, TargetKind, VerificationReport,
        VerificationTarget,
    };

    use super::{render_junit, render_sarif};

    #[test]
    fn junit_reports_one_testcase_for_empty_reports() {
        let output = render_junit(&VerificationReport::empty());

        assert!(output.contains("tests=\"1\""));
        assert!(output.contains("failures=\"0\""));
        assert!(output.contains("<testcase classname=\"veritas\" name=\"verification\" />"));
    }

    #[test]
    fn junit_escapes_finding_messages_and_failure_body() {
        let output = render_junit(&report_with_finding(
            "bad <tag> & \"quote\" 'tick'",
            "stdout <xml> & \"quote\" 'tick'",
        ));

        assert!(output.contains("tests=\"1\""));
        assert!(output.contains("failures=\"1\""));
        assert!(
            output.contains("message=\"bad &lt;tag&gt; &amp; &quot;quote&quot; &apos;tick&apos;\"")
        );
        assert!(output.contains("stdout &lt;xml&gt; &amp; &quot;quote&quot; &apos;tick&apos;"));
    }

    #[test]
    fn sarif_renders_valid_empty_top_level_shape() {
        let output = render_sarif(&VerificationReport::empty());
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF output should be valid JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "veritas");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "veritas.finding"
        );
        assert_eq!(
            parsed["runs"][0]["results"]
                .as_array()
                .expect("results should be an array")
                .len(),
            0
        );
    }

    #[test]
    fn sarif_escapes_finding_message_and_repro_uri() {
        let report = report_with_finding(
            "bad \"quote\" and slash \\ with\nnewline",
            "stdout is not rendered in SARIF",
        );
        let output = render_sarif(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF output should be valid JSON");
        let result = &parsed["runs"][0]["results"][0];

        assert_eq!(
            result["message"]["text"],
            "bad \"quote\" and slash \\ with\nnewline"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "repros/failing \"case\".md"
        );
    }

    #[test]
    fn sarif_prefers_target_location_and_region_when_available() {
        let mut report = report_with_finding("bad target", "stdout");
        report.targets.push(VerificationTarget {
            id: "rust:src/lib.rs::parse_total".to_string(),
            language: "rust".to_string(),
            kind: TargetKind::Function,
            path: "src/lib.rs".into(),
            symbol: Some("parse_total".to_string()),
            signature: None,
            line_range: Some(LineRange { start: 10, end: 12 }),
            description: "function".to_string(),
            risk: RiskLevel::High,
        });

        let output = render_sarif(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF output should be valid JSON");
        let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];

        assert_eq!(location["artifactLocation"]["uri"], "src/lib.rs");
        assert_eq!(location["region"]["startLine"], 10);
        assert_eq!(location["region"]["endLine"], 12);
    }

    #[test]
    fn junit_trims_large_failure_bodies() {
        let output = render_junit(&report_with_finding("big", &"x".repeat(1_500)));

        assert!(output.contains("truncated by veritas"));
        assert!(output.len() < 1_500);
    }

    fn report_with_finding(message: &str, stdout_excerpt: &str) -> VerificationReport {
        let mut report = VerificationReport::empty();
        report.findings.push(Failure {
            id: None,
            message: message.to_string(),
            severity: FailureSeverity::Error,
            target_id: Some("rust:src/lib.rs::parse_total".to_string()),
            artifact_id: Some("rust-generated-test".to_string()),
            command: "cargo test".to_string(),
            stdout_excerpt: stdout_excerpt.to_string(),
            stderr_excerpt: String::new(),
            repro: Some(ReproCase {
                command: "cargo test parse_total".to_string(),
                input: None,
                path: Some("repros/failing \"case\".md".into()),
            }),
        });
        report
    }
}
