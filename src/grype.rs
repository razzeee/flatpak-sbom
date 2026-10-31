use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

/// Own the scanner projection and temporary file while retaining the original
/// inventory for coverage, identity review and OSV reporting.
pub fn scan(document: &crate::cyclonedx::Bom, format: &str) -> Result<String> {
    scan_with_command(document, format, &mut Command::new("grype"))
}

fn scan_with_command(
    document: &crate::cyclonedx::Bom,
    format: &str,
    command: &mut Command,
) -> Result<String> {
    let input = scanner_input(document)?;
    let tempdir = tempfile::tempdir().context("create temporary scan directory")?;
    let sbom_path = tempdir.path().join("flatpak-sbom.cdx.json");
    std::fs::write(&sbom_path, serde_json::to_vec(&input)?)
        .context("write temporary CycloneDX document")?;
    let output = command
        .arg(format!("sbom:{}", sbom_path.display()))
        .arg("-o")
        .arg(format)
        .output()
        .context("run grype")?;

    if output.status.success() {
        String::from_utf8(output.stdout).context("grype output is not UTF-8")
    } else {
        bail!(
            "grype failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

fn scanner_input(document: &crate::cyclonedx::Bom) -> Result<Value> {
    let rejected: std::collections::BTreeSet<_> = document
        .components
        .iter()
        .filter(|c| crate::content::is_quarantined(c))
        .map(|c| c.bom_ref.as_str())
        .collect();
    let mut input = serde_json::to_value(document)?;
    input["$schema"] = Value::String("https://cyclonedx.org/schema/bom-1.6.schema.json".into());
    input["specVersion"] = Value::String("1.6".into());
    // Grype can infer CPEs from names: exclude quarantined identities and all
    // graph references to them, without changing the original inventory.
    let keep = |v: &Value| !rejected.contains(v.as_str().unwrap_or_default());
    input["components"]
        .as_array_mut()
        .unwrap()
        .retain(|c| keep(&c["bom-ref"]));
    if let Some(dependencies) = input.get_mut("dependencies").and_then(Value::as_array_mut) {
        dependencies.retain(|d| keep(&d["ref"]));
        for dependency in dependencies {
            if let Some(refs) = dependency
                .get_mut("dependsOn")
                .and_then(Value::as_array_mut)
            {
                refs.retain(&keep);
            }
        }
    }
    if let Some(compositions) = input.get_mut("compositions").and_then(Value::as_array_mut) {
        for composition in compositions {
            if let Some(refs) = composition["assemblies"].as_array_mut() {
                refs.retain(&keep);
            }
        }
    }
    Ok(input)
}

#[derive(Debug, Serialize)]
pub struct ScopedReport {
    pub findings: Vec<ScopedFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit_scan: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_scan: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_reviews: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ScopedFinding {
    pub vulnerability: Option<String>,
    pub package: Option<String>,
    pub package_version: Option<String>,
    pub severity: Option<String>,
    pub fixed_versions: Vec<String>,
    pub match_types: Vec<String>,
    pub data_source: Option<String>,
    pub scope: Option<String>,
    pub flatpak_ref: Option<String>,
    pub commit: Option<String>,
    pub bom_ref: Option<String>,
    pub inventory_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
}

pub fn map_report(path: &Path) -> Result<ScopedReport> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&data).context("parse Grype JSON")?;
    let findings = value
        .get("matches")
        .and_then(Value::as_array)
        .context("Grype report must contain a matches array")?
        .iter()
        .map(|entry| {
            if entry
                .pointer("/vulnerability/id")
                .and_then(Value::as_str)
                .is_none()
                || entry
                    .pointer("/artifact/id")
                    .and_then(Value::as_str)
                    .is_none()
                || entry
                    .pointer("/artifact/name")
                    .and_then(Value::as_str)
                    .is_none()
            {
                bail!("Grype match must contain vulnerability.id, artifact.id and artifact.name");
            }
            Ok(map_match(entry))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ScopedReport {
        findings,
        coverage: value.get("flatpakCoverage").cloned(),
        source_commit_scan: value.get("flatpakOsv").cloned(),
        package_scan: value.get("flatpakOsvPackages").cloned(),
        identity_reviews: value.get("flatpakIdentityReviews").cloned(),
    })
}

fn map_match(value: &Value) -> ScopedFinding {
    let artifact = value.get("artifact").unwrap_or(&Value::Null);
    let properties = artifact
        .get("metadata")
        .and_then(|metadata| metadata.get("properties"))
        .and_then(Value::as_array);
    // Grype preserves CycloneDX bom-ref as artifact.id, but drops arbitrary
    // component properties. Recover provenance from our immutable identifier.
    let provenance = artifact.get("id").and_then(Value::as_str).and_then(|id| {
        let identity = id.strip_prefix("flatpak:")?.split('#').next()?;
        let (identity, extension) = match identity.strip_prefix("extension/") {
            Some(identity) => (identity, true),
            None => (identity, false),
        };
        let (reference, commit) = identity.rsplit_once('@')?;
        let parsed = crate::refname::FlatpakRef::parse(reference).ok()?;
        if !matches!(parsed.kind(), "app" | "runtime")
            || commit.len() != 64
            || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        Some((
            if extension {
                "extension".into()
            } else {
                parsed.kind().to_string()
            },
            reference.to_string(),
            commit.to_string(),
        ))
    });

    ScopedFinding {
        vulnerability: value
            .pointer("/vulnerability/id")
            .and_then(Value::as_str)
            .map(str::to_string),
        package: artifact
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        package_version: artifact
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        severity: value
            .pointer("/vulnerability/severity")
            .and_then(Value::as_str)
            .map(str::to_string),
        fixed_versions: value
            .pointer("/vulnerability/fix/versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        match_types: value
            .get("matchDetails")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|details| details["type"].as_str())
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        data_source: value
            .pointer("/vulnerability/dataSource")
            .and_then(Value::as_str)
            .map(str::to_string),
        scope: property(properties, "flatpak:scope")
            .or_else(|| provenance.as_ref().map(|p| p.0.clone())),
        flatpak_ref: property(properties, "flatpak:ref")
            .or_else(|| provenance.as_ref().map(|p| p.1.clone())),
        commit: property(properties, "flatpak:commit")
            .or_else(|| provenance.as_ref().map(|p| p.2.clone())),
        bom_ref: artifact
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string),
        inventory_kind: property(properties, "flatpak:inventory-kind").or_else(|| {
            provenance.as_ref()?;
            let id = artifact.get("id")?.as_str()?;
            if id.contains("#content=extra-") {
                Some("extra-data-content".into())
            } else if id.contains("#content=") {
                Some("content-detected".into())
            } else if id.contains("#module=") && id.contains(":source=") {
                Some("manifest-source".into())
            } else {
                None
            }
        }),
        payload_sha256: artifact
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| id.split_once("#content=extra-").map(|(_, tail)| tail))
            .and_then(|tail| tail.split_once('-').map(|(sha, _)| sha))
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_owned),
    }
}

fn property(properties: Option<&Vec<Value>>, name: &str) -> Option<String> {
    properties?.iter().find_map(|property| {
        if property.get("name").and_then(Value::as_str) == Some(name) {
            property
                .get("value")
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> crate::cyclonedx::Bom {
        use crate::cyclonedx::*;
        Bom {
            schema: "https://cyclonedx.org/schema/bom-1.7.schema.json".into(),
            bom_format: "CycloneDX".into(),
            spec_version: "1.7".into(),
            serial_number: "urn:uuid:00000000-0000-0000-0000-000000000000".into(),
            version: 1,
            metadata: Metadata {
                timestamp: None,
                lifecycles: vec![],
                tools: None,
                component: Component {
                    component_type: "application".into(),
                    name: "test".into(),
                    bom_ref: "test".into(),
                    version: None,
                    purl: None,
                    cpe: None,
                    external_references: vec![],
                    hashes: vec![],
                    licenses: vec![],
                    evidence: None,
                    properties: vec![],
                },
            },
            components: vec![],
            dependencies: vec![],
            compositions: vec![],
        }
    }

    #[test]
    fn scan_owns_compatibility_quarantine_and_temporary_file_lifetime() {
        use crate::cyclonedx::{property, Composition, Dependency};
        let mut document = document();
        let mut rejected = document.metadata.component.clone();
        rejected.bom_ref = "quarantined".into();
        rejected
            .properties
            .push(property("flatpak:identity-status", "quarantined"));
        document.components.push(rejected);
        document.dependencies = vec![
            Dependency {
                bom_ref: "test".into(),
                depends_on: vec!["quarantined".into()],
            },
            Dependency {
                bom_ref: "quarantined".into(),
                depends_on: vec![],
            },
        ];
        document.compositions.push(Composition {
            aggregate: "incomplete".into(),
            assemblies: vec!["test".into(), "quarantined".into()],
        });
        let mut command = Command::new("sh");
        command.args([
            "-c",
            r#"
            test "$2" = '-o' && test "$3" = 'json' || exit 2
            path="${1#sbom:}"
            printf '%s\n' "$path"
            cat "$path"
        "#,
            "scanner",
        ]);
        let output = scan_with_command(&document, "json", &mut command).unwrap();
        let (path, json) = output.split_once('\n').unwrap();
        let input: Value = serde_json::from_str(json).unwrap();
        assert_eq!(input["specVersion"], "1.6");
        assert_eq!(
            input["$schema"],
            "https://cyclonedx.org/schema/bom-1.6.schema.json"
        );
        assert_eq!(input["components"], serde_json::json!([]));
        assert_eq!(
            input["dependencies"],
            serde_json::json!([{"ref":"test", "dependsOn":[]}])
        );
        assert_eq!(
            input["compositions"][0]["assemblies"],
            serde_json::json!(["test"])
        );
        assert!(!Path::new(path).exists());
        assert_eq!(document.spec_version, "1.7");
        assert_eq!(
            document.components.len(),
            1,
            "original inventory evidence is retained"
        );
    }

    #[test]
    fn scanner_failure_preserves_diagnostics_and_cleans_up() {
        let mut command = Command::new("sh");
        command.args(["-c", r#"printf '%s' "${1#sbom:}" >&2; exit 1"#, "scanner"]);
        let error = scan_with_command(&document(), "json", &mut command)
            .unwrap_err()
            .to_string();
        let path = error.strip_prefix("grype failed: ").unwrap();
        assert!(path.ends_with("flatpak-sbom.cdx.json"));
        assert!(!Path::new(path).exists());
    }

    #[test]
    fn rejects_invalid_reports_instead_of_reporting_no_findings() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for input in [
            "{}",
            "null",
            r#"{"matches":null}"#,
            r#"{"matches":{}}"#,
            r#"{"matches":[{}]}"#,
            r#"{"matches":[{"vulnerability":{"id":"CVE-1"},"artifact":{"name":"test"}}]}"#,
        ] {
            std::fs::write(file.path(), input).unwrap();
            assert!(map_report(file.path()).is_err(), "accepted {input}");
        }
        std::fs::write(file.path(), r#"{"matches":[],"flatpakCoverage":{"incomplete":true},"flatpakOsv":{"queries":[]},"flatpakOsvPackages":{"queries":[]},"flatpakIdentityReviews":[]}"#).unwrap();
        let report = map_report(file.path()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.coverage.unwrap()["incomplete"], true);
        assert!(report.source_commit_scan.is_some());
        assert!(report.package_scan.is_some());
        assert!(report.identity_reviews.is_some());
    }

    #[test]
    fn maps_scoped_finding() {
        let value: Value = serde_json::from_str(r#"{"vulnerability":{"id":"CVE-1"},"artifact":{"id":"bom","name":"openssl","metadata":{"properties":[{"name":"flatpak:scope","value":"runtime"},{"name":"flatpak:ref","value":"runtime/org.gnome.Platform/x86_64/46"},{"name":"flatpak:commit","value":"abc"}]}}}"#).unwrap();
        let finding = map_match(&value);
        assert_eq!(finding.scope.as_deref(), Some("runtime"));
        assert_eq!(finding.commit.as_deref(), Some("abc"));
    }
}
