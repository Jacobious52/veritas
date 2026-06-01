use std::{
    fs,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

#[test]
fn scans_rust_fixture() {
    let fixture = copy_fixture("sample-rust");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).arg("scan");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("sample-rust"))
        .stdout(predicate::str::contains("parse_invoice_total"));
}

#[test]
fn verifies_rust_fixture_and_writes_property_test() {
    let fixture = copy_fixture("sample-rust");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "rust", "--target", "src/lib.rs"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Generated Artifacts"))
        .stdout(predicate::str::contains("SymbolGraph"))
        .stdout(predicate::str::contains(
            "No failing verification findings were detected",
        ));

    assert!(fixture
        .path()
        .join("tests/veritas_generated/src_lib_rs_target.rs")
        .exists());
    assert!(fixture
        .path()
        .join(".veritas/symbol_graph/rust_src_lib_rs_target.json")
        .exists());
    assert!(fixture.path().join(".veritas/report.json").exists());
}

#[test]
fn verifies_rust_workspace_fixture_with_package_local_artifacts() {
    let fixture = copy_fixture("rust-workspace");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "rust", "--target", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Policy.authorize_refund"))
        .stdout(predicate::str::contains(
            "crates/auth/tests/veritas_generated",
        ))
        .stdout(predicate::str::contains(
            "crates/invoice/tests/veritas_generated",
        ))
        .stdout(predicate::str::contains("mutation survived"));

    assert!(fixture
        .path()
        .join("crates/auth/tests/veritas_generated/target.rs")
        .exists());
    assert!(fixture
        .path()
        .join("crates/invoice/tests/veritas_generated/target.rs")
        .exists());
    assert!(fixture
        .path()
        .join(".veritas/symbol_graph/rust_target.json")
        .exists());

    let report = read_report(fixture.path());
    assert!(report["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .any(|target| target["symbol"] == "Policy.authorize_refund"));
    assert!(report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("mutation survived"))));
}

#[test]
fn verifies_changed_rust_targets() {
    if !git_available() {
        return;
    }

    let fixture = copy_fixture("sample-rust");
    run_git(fixture.path(), &["init"]);
    run_git(
        fixture.path(),
        &["config", "user.email", "veritas@example.test"],
    );
    run_git(fixture.path(), &["config", "user.name", "veritas"]);
    run_git(fixture.path(), &["add", "."]);
    run_git(fixture.path(), &["commit", "-m", "initial"]);

    let lib = fixture.path().join("src/lib.rs");
    let contents = fs::read_to_string(&lib).expect("read lib");
    fs::write(
        &lib,
        contents.replace(
            "    input\n        .trim()",
            "    let input = input;\n    input\n        .trim()",
        ),
    )
    .expect("write changed lib");

    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--changed"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("parse_invoice_total"))
        .stdout(predicate::str::contains("Generated Artifacts"));
}

#[test]
fn scans_go_fixture() {
    let fixture = copy_fixture("sample-go");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).arg("scan");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("example.com/veritas-sample-go"))
        .stdout(predicate::str::contains("ParseInvoiceTotal"));
}

#[test]
fn plugin_sdk_scan_contract_is_stable_across_language_fixtures() {
    let rust = scan_fixture_json("sample-rust");
    assert_eq!(rust["project"]["language"], "rust");
    assert_target_contract(
        &rust,
        "rust:src/lib.rs:parse_invoice_total",
        "src/lib.rs",
        "parse_invoice_total",
    );

    let go = scan_fixture_json("sample-go");
    assert_eq!(go["project"]["language"], "go");
    assert_target_contract(
        &go,
        "go:invoice.go:ParseInvoiceTotal",
        "invoice.go",
        "ParseInvoiceTotal",
    );

    let python = scan_fixture_json("sample-python");
    assert_eq!(python["project"]["language"], "python");
    assert_target_contract(
        &python,
        "python:invoice.py:parse_invoice_total",
        "invoice.py",
        "parse_invoice_total",
    );
    assert_target_contract(
        &python,
        "python:sample_python/pricing.py:normalize_discount_code",
        "sample_python/pricing.py",
        "normalize_discount_code",
    );
    assert!(!python["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .any(|target| target["id"]
            .as_str()
            .is_some_and(|id| id.contains("test_invoice") || id.contains("PricingTests"))));
}

#[test]
fn conformance_command_validates_fixture_plugin_contracts() {
    let rust = copy_fixture("sample-rust");
    let mut rust_cmd = veritas();
    rust_cmd
        .current_dir(rust.path())
        .args(["conformance", "--format", "json"]);
    rust_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"language\": \"rust\""));

    let python = copy_fixture("sample-python");
    let mut python_cmd = veritas();
    python_cmd
        .current_dir(python.path())
        .args(["conformance", "--format", "json"]);
    python_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"language\": \"python\""));
}

#[test]
fn verifies_python_fixture_and_writes_sdk_artifacts() {
    let fixture = copy_fixture("sample-python");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "python", "--target", "invoice.py"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Generated Artifacts"))
        .stdout(predicate::str::contains("SymbolGraph"))
        .stdout(predicate::str::contains("MutationCheck"))
        .stdout(predicate::str::contains("PropertyTest"));

    let report = read_report(fixture.path());
    assert!(report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|artifact| artifact["kind"] == "mutation_check"));
    assert!(report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|artifact| artifact["kind"] == "symbol_graph"));
    assert!(report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|artifact| artifact["kind"] == "target_cache"));
    assert!(report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|artifact| {
            artifact["kind"] == "property_test"
                && artifact["contents"]
                    .as_str()
                    .is_some_and(|contents| contents.contains("from hypothesis import given"))
        }));
    assert!(fixture
        .path()
        .join(".veritas/properties/python_python_invoice_py.py")
        .exists());
    let mutation = &report["quality"]["mutation"];
    assert!(mutation["executed"].as_u64().unwrap_or_default() > 0);
    assert!(mutation["killed"].as_u64().unwrap_or_default() > 0);
    assert!(mutation["survived"].as_u64().unwrap_or_default() > 0);
    assert!(
        report["quality"]["performance"]["total_ms"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(
        report["quality"]["property"]["generated_artifacts"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    let python_command = report["runs"]
        .as_array()
        .expect("runs array")
        .iter()
        .flat_map(|run| run["commands"].as_array().into_iter().flatten())
        .find(|command| command["program"] == "python3")
        .expect("python command");
    let args = python_command["args"]
        .as_array()
        .expect("python command args")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        args.contains(&"unittest") || args.contains(&"pytest"),
        "Python plugin should run a known test runner, got {args:?}"
    );
    let replay_result = report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .find(|artifact| artifact["kind"] == "replay_result")
        .and_then(|artifact| artifact["contents"].as_str())
        .and_then(|contents| serde_json::from_str::<Value>(contents).ok())
        .expect("python replay result artifact");
    assert!(replay_result["comparisons"]
        .as_array()
        .expect("comparisons array")
        .iter()
        .any(
            |comparison| comparison["target_id"] == "python:invoice.py:authorize_refund"
                && comparison["case"]["argument_tuple"] == true
                && comparison["current"]["status"] == "observed"
        ));
}

#[test]
fn verifies_go_fixture_and_writes_fuzz_test() {
    if !go_available() {
        return;
    }

    let fixture = copy_fixture("sample-go");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "go", "--target", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Generated Artifacts"))
        .stdout(predicate::str::contains("mutation survived"));

    assert!(fixture.path().join("veritas_fuzz_test.go").exists());
    assert!(fixture.path().join(".veritas/report.json").exists());

    let report = read_report(fixture.path());
    let records = report["quality"]["mutation"]["records"]
        .as_array()
        .expect("mutation records");
    let survivor = records
        .iter()
        .find(|record| record["status"] == "lived" && record["stdout_log_path"].as_str().is_some())
        .expect("surviving mutant with command logs");
    for key in [
        "diff_path",
        "outcome_path",
        "command_log_path",
        "stdout_log_path",
        "stderr_log_path",
    ] {
        let path = survivor[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing {key}"));
        assert!(
            fixture.path().join(path).exists(),
            "expected mutation artifact {key} at {path}"
        );
    }

    let campaign: Value = serde_json::from_str(
        &fs::read_to_string(fixture.path().join(".veritas/mutations/go_campaign.json"))
            .expect("read go mutation campaign"),
    )
    .expect("parse go mutation campaign");
    assert_eq!(
        campaign["layout"]["run_outputs"]["records"],
        "records/{mutant}.json"
    );
    assert_eq!(
        campaign["layout"]["run_outputs"]["logs"],
        "logs/{mutant}.{command,stdout,stderr}.log"
    );
    assert!(fixture
        .path()
        .join(".veritas/mutations/go_progress.live.md")
        .exists());
    let progress = fs::read_to_string(fixture.path().join(".veritas/mutations/go_progress.md"))
        .expect("read go progress");
    assert!(progress.contains("Artifacts: outcome"));

    let mut markdown = veritas();
    markdown
        .current_dir(fixture.path())
        .args(["report", "--format", "markdown"]);
    markdown
        .assert()
        .success()
        .stdout(predicate::str::contains("Mutation artifacts:"))
        .stdout(predicate::str::contains(".stdout.log"));

    let mut sarif = veritas();
    sarif
        .current_dir(fixture.path())
        .args(["report", "--format", "sarif"]);
    sarif
        .assert()
        .success()
        .stdout(predicate::str::contains(".stdout.log"));

    let mut junit = veritas();
    junit
        .current_dir(fixture.path())
        .args(["report", "--format", "junit"]);
    junit
        .assert()
        .success()
        .stdout(predicate::str::contains("Mutation artifacts:"))
        .stdout(predicate::str::contains(".stderr.log"));
}

#[test]
fn go_mutation_score_policy_can_gate_ci() {
    if !go_available() {
        return;
    }

    let fixture = copy_fixture("sample-go");
    fs::write(
        fixture.path().join("veritas.toml"),
        r#"
[policy]
min_mutation_score = 100

[plugins.go]
coverage_enabled = false
fuzz_existing = false
max_mutants = 4
command_timeout_seconds = 20
"#,
    )
    .expect("write veritas config");

    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "go", "--target", "."]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("mutation score"));
}

#[test]
fn mutants_list_previews_advanced_records_without_executing_tests() {
    let fixture = copy_example("rust-concurrency-db");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).args([
        "mutants",
        "list",
        "--lang",
        "rust",
        "--target",
        "src/lib.rs",
        "--format",
        "json",
        "--domain",
        "synchronization",
    ]);
    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).expect("mutants list json");
    assert!(json["count"].as_u64().expect("count") > 0);
    let records = json["records"].as_array().expect("records");
    assert!(records.iter().any(|record| {
        record["operator"] == "atomic_ordering"
            && record["status"] == "runnable"
            && record["diff"]
                .as_str()
                .is_some_and(|diff| diff.contains("@@ bytes"))
    }));

    let mut conformance = veritas();
    conformance
        .current_dir(fixture.path())
        .args(["conformance", "--format", "json"]);
    let output = conformance.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).expect("conformance json");
    assert_eq!(json["passed"], true);
    assert!(json["plugins"][0]["mutation_records"]
        .as_u64()
        .is_some_and(|count| count > 0));
    assert_eq!(json["plugins"][0]["invalid_mutation_records"], 0);
}

#[test]
fn verifies_go_multimodule_fixture_and_scopes_reverse_dependencies() {
    if !go_available() {
        return;
    }

    let fixture = copy_fixture("go-multimodule");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).args([
        "verify",
        "--lang",
        "go",
        "--target",
        "services/billing/pkg/invoice",
    ]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("2 Go modules"))
        .stdout(predicate::str::contains("go test ./pkg/invoice"))
        .stdout(predicate::str::contains("go test ./pkg/api"))
        .stdout(predicate::str::contains("FuzzApplyDiscountCents"))
        .stdout(predicate::str::contains("mutation survived"));

    let generated = fs::read_to_string(
        fixture
            .path()
            .join("services/billing/pkg/invoice/veritas_fuzz_test.go"),
    )
    .expect("read generated go fuzz");
    assert!(generated.contains("FuzzApplyDiscountCents"));
    assert!(generated.contains("FuzzNormalizeToken"));
    assert!(
        !generated.contains("FuzzParseInvoiceTotal"),
        "handwritten fuzz targets should suppress duplicate generated names"
    );

    let graph = fs::read_to_string(fixture.path().join(".veritas/package_graph/go.json"))
        .expect("read package graph");
    assert!(graph.contains("\"root\": \"services/billing\""));
    assert!(graph.contains("\"root\": \"services/gateway\""));
    assert!(graph.contains("\"run_reason\": \"reverse dependency\""));

    let report =
        fs::read_to_string(fixture.path().join(".veritas/report.json")).expect("read report");
    let report: Value = serde_json::from_str(&report).expect("report json");
    let records = report["quality"]["mutation"]["records"]
        .as_array()
        .expect("mutation records");
    assert!(records.iter().any(|record| {
        record["status"] == "killed"
            && record["selected_test_command"]
                .as_str()
                .is_some_and(|command| {
                    command.contains("go test ./pkg/invoice") && !command.contains("./...")
                })
            && record["test_selection_hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("reverse dependencies"))
    }));
}

#[test]
fn go_timeout_fixture_records_adaptive_mutation_timeout_and_continues() {
    if !go_available() {
        return;
    }

    let fixture = copy_fixture("go-timeout");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "go", "--target", "."]);
    cmd.assert().success();

    let report = fs::read_to_string(fixture.path().join(".veritas/report.json"))
        .expect("read timeout report");
    let report: Value = serde_json::from_str(&report).expect("timeout report json");
    let mutation = &report["quality"]["mutation"];
    assert!(mutation["baseline_duration_ms"]
        .as_u64()
        .is_some_and(|duration| duration > 0));
    assert_eq!(mutation["computed_timeout_seconds"], 1);
    assert!(mutation["timeout_source"]
        .as_str()
        .is_some_and(|source| source.contains("baseline duration")));
    assert_eq!(mutation["timed_out"], 1);
    assert!(mutation["killed"]
        .as_u64()
        .is_some_and(|killed| killed >= 1));

    let records = mutation["records"].as_array().expect("mutation records");
    assert!(records.iter().any(|record| {
        record["status"] == "timed_out"
            && record["skip_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("deterministic test seams"))
    }));
}

#[test]
fn review_ai_writes_changed_digest_and_agent_feedback() {
    if !git_available() {
        return;
    }

    let fixture = copy_fixture("rust-workspace");
    init_git_repo(fixture.path());

    let auth = fixture.path().join("crates/auth/src/lib.rs");
    let contents = fs::read_to_string(&auth).expect("read auth");
    fs::write(
        &auth,
        contents.replace(
            "token != \"anonymous\" && token.len() >= 8",
            "token != \"anonymous\" && token.len() >= 8 && !token.starts_with(\"test\")",
        ),
    )
    .expect("write changed auth");

    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).arg("review-ai");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ChangeDigest"))
        .stdout(predicate::str::contains("AiFeedback"));

    let digest = fs::read_to_string(fixture.path().join(".veritas/ai/change_digest.md"))
        .expect("read change digest");
    let feedback = fs::read_to_string(fixture.path().join(".veritas/ai/agent_feedback.md"))
        .expect("read agent feedback");
    assert!(digest.contains("crates/auth/src/lib.rs"));
    assert!(digest.contains("validate_token"));
    assert!(feedback.contains("veritas verify --changed --profile ci"));
}

#[test]
fn repair_prompt_summarizes_saved_report_for_agents() {
    let fixture = copy_fixture("sample-rust");
    write_evolution_state(
        fixture.path(),
        "rust",
        "rust:src/lib.rs:parse_invoice_total",
        "src/lib.rs",
        "parse_invoice_total",
    );

    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).arg("repair-prompt");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("# veritas AI repair prompt"))
        .stdout(predicate::str::contains(
            "mutation survived in rust function",
        ))
        .stdout(predicate::str::contains("Selected Evolution Candidates"))
        .stdout(predicate::str::contains("Done when"))
        .stdout(predicate::str::contains(
            "veritas verify --changed --profile ci",
        ))
        .stdout(predicate::str::contains("veritas next --explain"))
        .stdout(predicate::str::contains("veritas evolve --dry-run"));
}

#[test]
fn next_command_ranks_findings_and_evolution_candidates() {
    let fixture = copy_fixture("sample-rust");
    write_evolution_state(
        fixture.path(),
        "rust",
        "rust:src/lib.rs:parse_invoice_total",
        "src/lib.rs",
        "parse_invoice_total",
    );

    let mut markdown = veritas();
    markdown
        .current_dir(fixture.path())
        .args(["next", "--explain", "--count", "2"]);
    markdown
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas next"))
        .stdout(predicate::str::contains("Estimated confidence impact"))
        .stdout(predicate::str::contains("evolve-mutant-rust"))
        .stdout(predicate::str::contains("mutation_survivor"));

    let mut json = veritas();
    json.current_dir(fixture.path())
        .args(["next", "--format", "json", "--count", "1"]);
    json.assert()
        .success()
        .stdout(predicate::str::contains("\"returned\": 1"))
        .stdout(predicate::str::contains("\"reason_codes\""));

    let mut score_modes = veritas();
    score_modes
        .current_dir(fixture.path())
        .args(["score", "--mode", "all", "--format", "json"]);
    score_modes
        .assert()
        .success()
        .stdout(predicate::str::contains("\"mode\": \"current\""))
        .stdout(predicate::str::contains("\"mode\": \"strict\""))
        .stdout(predicate::str::contains("\"mode\": \"verified\""))
        .stdout(predicate::str::contains("\"delta_from_current\""));
}

#[test]
fn review_packet_and_agent_instructions_write_ai_artifacts() {
    let fixture = copy_fixture("sample-rust");
    write_evolution_state(
        fixture.path(),
        "rust",
        "rust:src/lib.rs:parse_invoice_total",
        "src/lib.rs",
        "parse_invoice_total",
    );

    let mut packet = veritas();
    packet
        .current_dir(fixture.path())
        .args(["review-packet", "--dimension", "testability"]);
    packet
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas review-packet"))
        .stdout(predicate::str::contains("testability"));
    let query = fs::read_to_string(fixture.path().join(".veritas/review/query.json"))
        .expect("read review query");
    assert!(query.contains("\"dimensions\""));
    assert!(query.contains("rust:src/lib.rs:parse_invoice_total"));
    assert!(query.contains("mutation_survivors"));

    let mut instructions = veritas();
    instructions
        .current_dir(fixture.path())
        .args(["agent-instructions", "--agent", "codex"]);
    instructions
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas agent-instructions"));
    let contents = fs::read_to_string(
        fixture
            .path()
            .join(".veritas/ai/veritas_agent_instructions.md"),
    )
    .expect("read agent instructions");
    assert!(contents.contains("veritas next --explain"));
    assert!(contents.contains("Anti-Gaming Rules"));

    let mut badge = veritas();
    badge.current_dir(fixture.path()).arg("badge");
    badge
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas badge"));
    let badge_svg =
        fs::read_to_string(fixture.path().join(".veritas/badge.svg")).expect("read badge svg");
    assert!(badge_svg.contains("<svg"));
    assert!(badge_svg.contains("veritas"));
}

#[test]
fn seeded_rust_example_supports_explain_baseline_promotion_and_reports() {
    let fixture = copy_example("rust-invoice");
    let mut verify = veritas();
    verify
        .current_dir(fixture.path())
        .args(["verify", "--lang", "rust", "--target", "src/lib.rs"]);
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("cargo test failed"))
        .stdout(predicate::str::contains("rust-property-src_lib_rs_target"));

    let report = read_report(fixture.path());
    let finding_id = first_finding_id_containing(&report, "cargo test failed");

    let mut explain = veritas();
    explain
        .current_dir(fixture.path())
        .args(["explain", &finding_id]);
    explain.assert().success().stdout(predicate::str::contains(
        "Candidate verification patch artifacts",
    ));

    let mut sarif = veritas();
    sarif
        .current_dir(fixture.path())
        .args(["report", "--format", "sarif"]);
    sarif
        .assert()
        .success()
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""));

    let mut junit = veritas();
    junit
        .current_dir(fixture.path())
        .args(["report", "--format", "junit"]);
    junit
        .assert()
        .success()
        .stdout(predicate::str::contains("<testsuite name=\"veritas\""));

    let mut promote = veritas();
    promote.current_dir(fixture.path()).arg("promote-repro");
    promote
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote promotion artifacts"));

    let mut promote_regression = veritas();
    promote_regression
        .current_dir(fixture.path())
        .args(["promote-regression", "--index", "0"]);
    promote_regression
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote promotion artifacts"))
        .stdout(predicate::str::contains("veritas_regression_0"));

    let mut accept = veritas();
    accept
        .current_dir(fixture.path())
        .args(["accept-baseline", "--id", &finding_id]);
    accept
        .assert()
        .success()
        .stdout(predicate::str::contains("Accepted findings: `1`"));

    assert!(fixture
        .path()
        .join(".veritas/promotions/rust_0.md")
        .exists());
    assert!(has_file_with_prefix(
        &fixture.path().join("tests"),
        "veritas_regression_0"
    ));
    assert!(fixture
        .path()
        .join(".veritas/baselines/findings.json")
        .exists());
}

#[test]
fn seeded_go_example_fuzzes_parser_panic() {
    if !go_available() {
        return;
    }

    let fixture = copy_example("go-invoice");
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["verify", "--lang", "go", "--target", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("go test failed"))
        .stdout(predicate::str::contains("veritas_fuzz_test.go"));

    let generated =
        fs::read_to_string(fixture.path().join("veritas_fuzz_test.go")).expect("read go fuzz");
    assert!(generated.contains("FuzzParseInvoiceTotal"));

    let report = read_report(fixture.path());
    assert!(report["artifacts"]
        .as_array()
        .expect("artifacts array")
        .iter()
        .any(|artifact| artifact["kind"] == "candidate_patch"));
    assert!(fixture.path().join(".veritas/repros/go_0.md").exists());
}

#[test]
fn benchmark_suite_scores_seeded_examples() {
    if !go_available() {
        return;
    }

    let mut json = veritas();
    json.current_dir(workspace_root())
        .args(["--root", "examples", "bench", "--format", "json"]);
    json.assert()
        .success()
        .stdout(predicate::str::contains("\"total_cases\": 12"))
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"profile\": \"seeded\""))
        .stdout(predicate::str::contains("\"summary\""))
        .stdout(predicate::str::contains("\"total_targets\""))
        .stdout(predicate::str::contains("\"high_risk_targets\""))
        .stdout(predicate::str::contains("\"target_count\""))
        .stdout(predicate::str::contains("\"large_repo_cases\""))
        .stdout(predicate::str::contains("\"rust-commerce\""))
        .stdout(predicate::str::contains("\"go-api-service\""))
        .stdout(predicate::str::contains("\"rust-evolution-loop\""))
        .stdout(predicate::str::contains("\"go-evolution-loop\""))
        .stdout(predicate::str::contains("\"rust-concurrency-db\""))
        .stdout(predicate::str::contains("\"go-concurrency-db\""))
        .stdout(predicate::str::contains("\"command_count\""))
        .stdout(predicate::str::contains("\"mutation_score_percent\""))
        .stdout(predicate::str::contains(
            "\"property_strength_score_percent\"",
        ))
        .stdout(predicate::str::contains("\"corpus_entries\""))
        .stdout(predicate::str::contains("\"evolution_candidates\""))
        .stdout(predicate::str::contains("\"evolution_selected\""))
        .stdout(predicate::str::contains("\"generated_test_failures\""))
        .stdout(predicate::str::contains("\"threshold_failures\": []"));
}

#[test]
fn cleanup_removes_generated_artifacts() {
    let fixture = copy_fixture("sample-rust");
    write_fixture_file(fixture.path(), ".veritas/report.json");
    write_fixture_file(
        fixture.path(),
        "tests/veritas_generated/src_lib_rs_target.rs",
    );
    write_fixture_file(fixture.path(), "tests/veritas_generated.rs");
    write_fixture_file(fixture.path(), "pkg/veritas_fuzz_test.go");
    write_fixture_file(fixture.path(), "target/tests/veritas_generated.rs");

    let mut cmd = veritas();
    cmd.current_dir(fixture.path()).arg("cleanup");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Removed generated artifacts"))
        .stdout(predicate::str::contains("tests/veritas_generated"))
        .stdout(predicate::str::contains("pkg/veritas_fuzz_test.go"));

    assert!(!fixture.path().join(".veritas").exists());
    assert!(!fixture.path().join("tests/veritas_generated").exists());
    assert!(!fixture.path().join("tests/veritas_generated.rs").exists());
    assert!(!fixture.path().join("pkg/veritas_fuzz_test.go").exists());
    assert!(fixture.path().join("src/lib.rs").exists());
    assert!(fixture
        .path()
        .join("target/tests/veritas_generated.rs")
        .exists());
}

#[test]
fn evolve_dry_run_and_apply_rust_candidate() {
    let fixture = copy_fixture("sample-rust");
    write_evolution_state(
        fixture.path(),
        "rust",
        "rust:src/lib.rs:parse_invoice_total",
        "src/lib.rs",
        "parse_invoice_total",
    );

    let mut dry_run = veritas();
    dry_run
        .current_dir(fixture.path())
        .args(["evolve", "--lang", "rust", "--dry-run"]);
    dry_run
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas evolve (dry run)"))
        .stdout(predicate::str::contains("evolve-mutant-rust"))
        .stdout(predicate::str::contains("Fitness: `95%`"));

    let mut apply = veritas();
    apply.current_dir(fixture.path()).args([
        "evolve",
        "--lang",
        "rust",
        "--index",
        "0",
        "--evaluate",
    ]);
    apply
        .assert()
        .success()
        .stdout(predicate::str::contains("Result: `applied`"))
        .stdout(predicate::str::contains("Evaluation: `Improved`"))
        .stdout(predicate::str::contains("veritas_regression_0"));

    assert!(has_file_with_prefix(
        &fixture.path().join("tests"),
        "veritas_regression_0"
    ));
    assert!(fixture
        .path()
        .join(".veritas/evolution/rust_generation_1.json")
        .exists());

    let mut second = veritas();
    second
        .current_dir(fixture.path())
        .args(["evolve", "--lang", "rust", "--index", "0"]);
    second.assert().success();
    assert!(fixture
        .path()
        .join(".veritas/evolution/rust_generation_2.json")
        .exists());

    let mut score = veritas();
    score.current_dir(fixture.path()).arg("score");
    score
        .assert()
        .success()
        .stdout(predicate::str::contains("latest evolution generation"));
}

#[test]
fn evolve_dry_run_and_apply_go_candidate() {
    if !go_available() {
        return;
    }
    let fixture = copy_fixture("sample-go");
    write_evolution_state(
        fixture.path(),
        "go",
        "go:invoice.go:ParseInvoiceTotal",
        "invoice.go",
        "ParseInvoiceTotal",
    );

    let mut dry_run = veritas();
    dry_run
        .current_dir(fixture.path())
        .args(["evolve", "--lang", "go", "--dry-run"]);
    dry_run
        .assert()
        .success()
        .stdout(predicate::str::contains("# veritas evolve (dry run)"))
        .stdout(predicate::str::contains("evolve-mutant-go"))
        .stdout(predicate::str::contains(
            "mutant moves from lived to killed",
        ));

    let mut apply = veritas();
    apply
        .current_dir(fixture.path())
        .args(["evolve", "--lang", "go", "--index", "0"]);
    apply
        .assert()
        .success()
        .stdout(predicate::str::contains("Result: `applied`"))
        .stdout(predicate::str::contains("veritas_regression_0_test.go"));

    assert!(fixture.path().join("veritas_regression_0_test.go").exists());
}

fn veritas() -> Command {
    Command::cargo_bin("veritas").expect("veritas binary should build")
}

fn go_available() -> bool {
    std::process::Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_git(root: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_git_repo(root: &Path) {
    run_git(root, &["init"]);
    run_git(root, &["config", "user.email", "veritas@example.test"]);
    run_git(root, &["config", "user.name", "veritas"]);
    run_git(root, &["add", "."]);
    run_git(root, &["commit", "-m", "initial"]);
}

fn copy_fixture(name: &str) -> TempDir {
    copy_project(&fixture_root().join(name))
}

fn copy_example(name: &str) -> TempDir {
    copy_project(&workspace_root().join("examples").join(name))
}

fn copy_project(source: &Path) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    copy_dir(source, temp.path()).expect("copy project");
    temp
}

fn read_report(root: &Path) -> Value {
    let report = fs::read_to_string(root.join(".veritas/report.json")).expect("read report");
    serde_json::from_str(&report).expect("parse report json")
}

fn scan_fixture_json(name: &str) -> Value {
    let fixture = copy_fixture(name);
    let mut cmd = veritas();
    cmd.current_dir(fixture.path())
        .args(["scan", "--format", "json"]);
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("parse scan json")
}

fn assert_target_contract(scan: &Value, id: &str, path: &str, symbol: &str) {
    let target = scan["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|target| target["id"] == id)
        .unwrap_or_else(|| panic!("missing target {id}"));
    assert_eq!(target["path"], path);
    assert_eq!(target["symbol"], symbol);
    assert!(target["signature"]
        .as_str()
        .is_some_and(|signature| signature.contains(symbol)));
    let line_range = &target["line_range"];
    assert!(line_range["start"].as_u64().unwrap_or_default() > 0);
    assert!(
        line_range["end"].as_u64().unwrap_or_default()
            >= line_range["start"].as_u64().unwrap_or_default()
    );
}

fn first_finding_id_containing(report: &Value, needle: &str) -> String {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|finding| {
            finding["message"]
                .as_str()
                .is_some_and(|message| message.contains(needle))
        })
        .and_then(|finding| finding["id"].as_str())
        .expect("finding id")
        .to_string()
}

fn write_fixture_file(root: &Path, relative: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture file should have a parent"))
        .expect("create fixture parent");
    fs::write(path, "generated").expect("write fixture file");
}

fn write_evolution_state(root: &Path, language: &str, target_id: &str, path: &str, symbol: &str) {
    let veritas = root.join(".veritas");
    fs::create_dir_all(veritas.join("evolution")).expect("create evolution dir");
    let suite = serde_json::json!({
        "version": 1,
        "language": language,
        "generation": 1,
        "selection_budget": 1,
        "fitness_signals": ["mutation_score_delta", "confidence_score_delta"],
        "candidates": [{
            "id": format!("evolve-mutant-{language}"),
            "language": language,
            "target_id": target_id,
            "kind": "mutation",
            "strategy": "add_assertion",
            "status": "selected",
            "source_finding_id": "vts-test-finding",
            "domain": "boundary",
            "fitness": {
                "score_percent": 95,
                "mutation_delta": 1,
                "finding_delta": 0,
                "replay_delta": 0,
                "confidence_delta": 20,
                "rationale": "surviving mutant should become an assertion"
            },
            "proposed_action": "Add the smallest assertion that fails under this surviving mutant.",
            "keep_if": "mutant moves from lived to killed",
            "proof_commands": [
                format!("veritas verify --lang {language} --target <target>"),
                "veritas score"
            ],
            "done_when": [
                "the mutant moves from lived to killed in the next campaign",
                "the confidence score improves or explains why it is unchanged"
            ]
        }]
    });
    let suite_contents = serde_json::to_string_pretty(&suite).expect("suite json");
    let report = serde_json::json!({
        "project": null,
        "targets": [{
            "id": target_id,
            "language": language,
            "kind": "function",
            "path": path,
            "symbol": symbol,
            "signature": null,
            "line_range": {"start": 1, "end": 12},
            "description": "test target",
            "risk": "medium"
        }],
        "plan": null,
        "artifacts": [{
            "id": format!("{language}-evolution-suite"),
            "language": language,
            "kind": "evolution_suite",
            "target_id": format!("{language}:evolution"),
            "path": format!(".veritas/evolution/{language}_suite.json"),
            "contents": suite_contents,
            "description": "Evolution suite for repair prompt tests",
            "status": "written"
        }],
        "runs": [],
        "coverage": [],
        "findings": [{
            "id": "vts-test-finding",
            "message": format!("mutation survived in {language} function `{symbol}`: comparison boundary mutation"),
            "severity": "warning",
            "target_id": target_id,
            "artifact_id": null,
            "command": "test command",
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "repro": {
                "command": "replace boundary and run tests",
                "input": null,
                "path": path
            }
        }],
        "suggested_next_steps": []
    });
    fs::write(
        veritas.join("report.json"),
        serde_json::to_string_pretty(&report).expect("report json"),
    )
    .expect("write report");
    fs::write(
        veritas.join(format!("evolution/{language}_suite.json")),
        serde_json::to_string_pretty(&suite).expect("suite json"),
    )
    .expect("write suite");
}

fn fixture_root() -> PathBuf {
    workspace_root().join("fixtures")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn copy_dir(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if should_skip_copy_entry(&entry.file_name()) {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

fn should_skip_copy_entry(name: &std::ffi::OsStr) -> bool {
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
    ) || name.to_string_lossy().ends_with(".proptest-regressions")
        || name.to_string_lossy().starts_with("veritas_regression_")
}

fn has_file_with_prefix(directory: &Path, prefix: &str) -> bool {
    fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
}
