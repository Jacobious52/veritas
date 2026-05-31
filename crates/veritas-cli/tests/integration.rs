use std::{
    fs,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use predicates::prelude::*;
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
        .stdout(predicate::str::contains("mutation survived"));

    assert!(fixture
        .path()
        .join("tests/veritas_generated/src_lib_rs_target.rs")
        .exists());
    assert!(fixture.path().join(".veritas/report.json").exists());
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

fn copy_fixture(name: &str) -> TempDir {
    let temp = TempDir::new().expect("tempdir");
    let source = fixture_root().join(name);
    copy_dir(&source, temp.path()).expect("copy fixture");
    temp
}

fn write_fixture_file(root: &Path, relative: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("fixture file should have a parent"))
        .expect("create fixture parent");
    fs::write(path, "generated").expect("write fixture file");
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
}

fn copy_dir(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
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
