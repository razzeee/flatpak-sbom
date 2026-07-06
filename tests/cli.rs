use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_generate_scan_and_report() {
    let mut command = Command::cargo_bin("flatpak-sbom").unwrap();

    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("generate"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("report"));
}

#[test]
fn generate_help_documents_default_output() {
    let mut command = Command::cargo_bin("flatpak-sbom").unwrap();

    command
        .args(["generate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<app-id>.cdx.json"))
        .stdout(predicate::str::contains("use '-' for stdout"));
}
