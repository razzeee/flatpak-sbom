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

#[test]
fn generates_sbom_from_real_app_and_runtime_refs() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let tree = temp.path().join("tree");
    std::fs::create_dir_all(tree.join("files")).unwrap();
    let ostree = |args: &[&str]| {
        let output = std::process::Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .args(args)
            .output()
            .expect("install ostree to run integration tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };
    ostree(&["init", "--mode=archive"]);
    let app_ref = "app/org.example.App/x86_64/stable";
    let runtime_ref = "runtime/org.example.Platform/x86_64/1";
    std::fs::write(
        tree.join("metadata"),
        "[Application]\nruntime=org.example.Platform/x86_64/1\n",
    )
    .unwrap();
    std::fs::write(tree.join("files/manifest.json"), r#"{"id":"org.example.App","modules":[{"name":"example","sources":[{"type":"git","url":"https://github.com/example/example.git","tag":"v1.0"}]}]}"#).unwrap();
    let app_commit = ostree(&[
        "commit",
        "--branch",
        app_ref,
        "--subject",
        "app",
        &format!("--tree=dir={}", tree.display()),
    ]);
    std::fs::write(
        tree.join("metadata"),
        "[Runtime]\nname=org.example.Platform\n",
    )
    .unwrap();
    std::fs::remove_file(tree.join("files/manifest.json")).unwrap();
    std::fs::create_dir_all(tree.join("usr")).unwrap();
    std::fs::write(tree.join("usr/manifest.json"), r#"{"modules":[]}"#).unwrap();
    let runtime_commit = ostree(&[
        "commit",
        "--branch",
        runtime_ref,
        "--subject",
        "runtime",
        &format!("--tree=dir={}", tree.display()),
    ]);
    let output = Command::cargo_bin("flatpak-sbom")
        .unwrap()
        .args([
            "generate",
            app_ref,
            "--repo",
            &format!("file://{}", repo.display()),
            "--output",
            "-",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let bom: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(bom["specVersion"], "1.7");
    assert_eq!(bom["compositions"][0]["aggregate"], "incomplete");
    let properties = |scope: &str| {
        bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["properties"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "flatpak:scope" && p["value"] == scope)
            })
            .unwrap()["properties"]
            .as_array()
            .unwrap()
    };
    assert!(properties("app")
        .iter()
        .any(|p| p["name"] == "flatpak:commit" && p["value"] == app_commit));
    assert!(properties("runtime")
        .iter()
        .any(|p| p["name"] == "flatpak:commit" && p["value"] == runtime_commit));
    assert!(properties("runtime")
        .iter()
        .any(|p| p["name"] == "flatpak:manifest-path" && p["value"] == "usr/manifest.json"));
}

#[test]
fn report_rejects_unrecognized_json() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "{}").unwrap();
    Command::cargo_bin("flatpak-sbom")
        .unwrap()
        .arg("report")
        .arg(file.path())
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("matches array"));
}
