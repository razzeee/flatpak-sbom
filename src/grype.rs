use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

pub fn run_grype(sbom_path: &Path, format: &str) -> Result<String> {
    let output = Command::new("grype")
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
                    .pointer("/artifact/name")
                    .and_then(Value::as_str)
                    .is_none()
            {
                bail!("Grype match must contain vulnerability.id and artifact.name");
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
        if !matches!(parsed.kind.as_str(), "app" | "runtime")
            || commit.len() != 64
            || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        Some((
            if extension {
                "extension".into()
            } else {
                parsed.kind
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

    #[test]
    fn maps_scoped_finding() {
        let value: Value = serde_json::from_str(r#"{"vulnerability":{"id":"CVE-1"},"artifact":{"id":"bom","name":"openssl","metadata":{"properties":[{"name":"flatpak:scope","value":"runtime"},{"name":"flatpak:ref","value":"runtime/org.gnome.Platform/x86_64/46"},{"name":"flatpak:commit","value":"abc"}]}}}"#).unwrap();
        let finding = map_match(&value);
        assert_eq!(finding.scope.as_deref(), Some("runtime"));
        assert_eq!(finding.commit.as_deref(), Some("abc"));
    }
}
