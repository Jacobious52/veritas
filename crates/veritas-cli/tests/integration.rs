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

    let mut cmd = veritas();
    cmd.current_dir(workspace_root())
        .args(["--root", "examples", "bench"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("# veritas bench"))
        .stdout(predicate::str::contains("rust-commerce"))
        .stdout(predicate::str::contains("go-api-service"))
        .stdout(predicate::str::contains("rust-mutation-score"))
        .stdout(predicate::str::contains("rust-risk-suite"))
        .stdout(predicate::str::contains("go-risk-suite"))
        .stdout(predicate::str::contains("Mutation score:"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("Generated test failures:"))
        .stdout(predicate::str::contains("Cases: `8/8` passed"));

    let mut json = veritas();
    json.current_dir(workspace_root())
        .args(["--root", "examples", "bench", "--format", "json"]);
    json.assert()
        .success()
        .stdout(predicate::str::contains("\"passed\": true"))
        .stdout(predicate::str::contains("\"command_count\""))
        .stdout(predicate::str::contains("\"mutation_score_percent\""))
        .stdout(predicate::str::contains(
            "\"property_strength_score_percent\"",
        ))
        .stdout(predicate::str::contains("\"corpus_entries\""))
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
