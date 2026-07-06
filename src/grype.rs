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
}

#[derive(Debug, Serialize)]
pub struct ScopedFinding {
    pub vulnerability: Option<String>,
    pub package: Option<String>,
    pub scope: Option<String>,
    pub flatpak_ref: Option<String>,
    pub commit: Option<String>,
    pub bom_ref: Option<String>,
}

pub fn map_report(path: &Path) -> Result<ScopedReport> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&data).context("parse Grype JSON")?;
    let findings = value
        .get("matches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(map_match)
        .collect();

    Ok(ScopedReport { findings })
}

fn map_match(value: &Value) -> ScopedFinding {
    let artifact = value.get("artifact").unwrap_or(&Value::Null);
    let properties = artifact
        .get("metadata")
        .and_then(|metadata| metadata.get("properties"))
        .and_then(Value::as_array);

    ScopedFinding {
        vulnerability: value
            .pointer("/vulnerability/id")
            .and_then(Value::as_str)
            .map(str::to_string),
        package: artifact
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        scope: property(properties, "flatpak:scope"),
        flatpak_ref: property(properties, "flatpak:ref"),
        commit: property(properties, "flatpak:commit"),
        bom_ref: artifact
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string),
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
