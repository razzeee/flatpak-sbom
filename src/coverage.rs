use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

#[derive(Default, Serialize)]
pub struct ScopeCoverage {
    declared_package_sources: usize,
    ecosystem_identities_with_release_version: usize,
    repository_identities_with_release_version: usize,
    filename_version_candidates: usize,
    content_packages: usize,
    content_packages_with_identity_and_version: usize,
    cpe_identities_with_release_version: usize,
    content_scan: String,
    content_origin: String,
    extension_declarations: Vec<ExtensionDeclaration>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    extension_inventories: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    extra_data_acquisitions: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    content_observations: Vec<Value>,
    gaps: Vec<Gap>,
}

#[derive(Deserialize, Serialize)]
struct ExtensionDeclaration {
    name: String,
    parent_ref: String,
    parent_commit: String,
    metadata: BTreeMap<String, String>,
    status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selected_refs: Vec<String>,
}

#[derive(Serialize)]
struct Gap {
    bom_ref: String,
    name: String,
    reasons: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct Coverage {
    inventory_complete: bool,
    acquisition_complete: bool,
    completeness_limitations: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_extension_discovery: Option<Value>,
    note: &'static str,
    scopes: BTreeMap<String, ScopeCoverage>,
}

fn prop<'a>(component: &'a Value, name: &str) -> Option<&'a str> {
    component
        .get("properties")?
        .as_array()?
        .iter()
        .find_map(|p| {
            (p["name"].as_str() == Some(name))
                .then(|| p["value"].as_str())
                .flatten()
        })
}

pub fn read(path: &Path) -> Result<Coverage> {
    summarize(
        &serde_json::from_slice(&std::fs::read(path).context("read SBOM")?)
            .context("parse SBOM")?,
    )
}

pub fn summarize(bom: &Value) -> Result<Coverage> {
    if bom["bomFormat"] != "CycloneDX" {
        bail!("coverage expects a CycloneDX SBOM");
    }
    let components = bom["components"]
        .as_array()
        .context("SBOM has no components array")?;
    let mut scopes = BTreeMap::new();
    let mut scope_names = vec!["app", "runtime"];
    if components
        .iter()
        .any(|c| prop(c, "flatpak:scope") == Some("extension"))
    {
        scope_names.push("extension");
    }
    for scope in scope_names {
        let mut summary = ScopeCoverage {
            content_scan: prop(
                &bom["metadata"]["component"],
                &format!("flatpak:content-scan:{scope}"),
            )
            .unwrap_or("not-performed")
            .to_string(),
            content_origin: prop(
                &bom["metadata"]["component"],
                &format!("flatpak:content-origin:{scope}"),
            )
            .unwrap_or("not-performed")
            .to_string(),
            extension_declarations: prop(
                &bom["metadata"]["component"],
                &format!("flatpak:extension-declarations:{scope}"),
            )
            .map(serde_json::from_str)
            .transpose()
            .context("parse extension declarations")?
            .unwrap_or_default(),
            extension_inventories: if scope == "extension" {
                prop(
                    &bom["metadata"]["component"],
                    "flatpak:extension-inventories",
                )
                .map(serde_json::from_str)
                .transpose()
                .context("parse extension inventories")?
                .unwrap_or_default()
            } else {
                vec![]
            },
            extra_data_acquisitions: prop(
                &bom["metadata"]["component"],
                &format!("flatpak:extra-data-acquisitions:{scope}"),
            )
            .map(serde_json::from_str)
            .transpose()
            .context("parse extra-data acquisition evidence")?
            .unwrap_or_default(),
            content_observations: prop(
                &bom["metadata"]["component"],
                &format!("flatpak:content-observations:{scope}"),
            )
            .map(serde_json::from_str)
            .transpose()
            .context("parse content observations")?
            .unwrap_or_default(),
            ..Default::default()
        };
        for c in components
            .iter()
            .filter(|c| prop(c, "flatpak:scope") == Some(scope))
        {
            let content = matches!(
                prop(c, "flatpak:inventory-kind"),
                Some("content-detected" | "extra-data-content")
            );
            if (prop(c, "flatpak:extra-data-declared") == Some("true")
                || prop(c, "flatpak:metadata:Extra_Data:uri").is_some())
                && summary.content_origin == "ostree-checkout"
                && !summary.extra_data_acquisitions.iter().any(|a| {
                    a["ref"].as_str() == prop(c, "flatpak:ref")
                        && a["status"] == "archive-inspected"
                })
            {
                summary.gaps.push(Gap {
                    bom_ref: c["bom-ref"].as_str().unwrap_or_default().into(),
                    name: c["name"].as_str().unwrap_or_default().into(),
                    reasons: vec!["extra-data-not-acquired-from-remote"],
                });
            }
            let source_type = prop(c, "flatpak:source-type");
            let candidate = matches!(source_type, Some("archive" | "git" | "extra-data"))
                || (source_type == Some("file")
                    && (c.get("purl").is_some()
                        || prop(c, "flatpak:filename-version-candidate").is_some()));
            if !content && !candidate {
                continue;
            }
            let mut reasons = Vec::new();
            if prop(c, "flatpak:identity-status") == Some("quarantined") {
                reasons.push("quarantined-scanner-identity");
            }
            if let Some(status) = prop(c, "flatpak:cpe-mapping-status") {
                if !matches!(status, "mapped" | "existing-cpe-preserved") {
                    reasons.push("cpe-mapping-needs-review");
                }
            }
            let version = c["version"]
                .as_str()
                .filter(|v| !v.is_empty() && !matches!(*v, "UNKNOWN" | "unknown"));
            let purl = c["purl"]
                .as_str()
                .and_then(|p| p.parse::<packageurl::PackageUrl>().ok());
            let version_kind = prop(c, "flatpak:version-kind");
            let commit_version = version.is_some() && version == prop(c, "flatpak:source-commit");
            let release = version.is_some()
                && !commit_version
                && !matches!(version_kind, Some("git-commit" | "filename"));
            let cpe = c["cpe"]
                .as_str()
                .is_some_and(|cpe| cpe.starts_with("cpe:2.3:") || cpe.starts_with("cpe:/"));
            if cpe && release {
                summary.cpe_identities_with_release_version += 1;
            }
            if content {
                summary.content_packages += 1;
                if purl.is_some() && release {
                    summary.content_packages_with_identity_and_version += 1;
                }
            } else {
                summary.declared_package_sources += 1;
                if version_kind == Some("filename") {
                    summary.filename_version_candidates += 1;
                }
            }
            if let Some(purl) = &purl {
                if release {
                    match purl.ty() {
                        "github" | "gitlab" | "bitbucket" => {
                            summary.repository_identities_with_release_version += 1
                        }
                        "npm" | "pypi" | "cargo" | "golang" | "nuget" | "maven" | "gem" | "deb"
                        | "rpm" | "apk" => summary.ecosystem_identities_with_release_version += 1,
                        _ if !cpe => reasons.push("unverified-advisory-ecosystem"),
                        _ => {}
                    }
                }
            } else if !cpe {
                reasons.push("missing-package-identity");
            }
            if !release {
                reasons.push("missing-confirmed-release-version");
            }
            if !content && matches!(source_type, Some("archive" | "extra-data")) {
                reasons.push("payload-dependencies-not-enumerated-from-manifest");
            }
            if source_type == Some("extra-data")
                && summary.content_origin == "ostree-checkout"
                && prop(c, "flatpak:extra-data-acquisition") != Some("archive-inspected")
            {
                reasons.push("extra-data-not-acquired-from-remote");
            }
            if !reasons.is_empty() {
                summary.gaps.push(Gap {
                    bom_ref: c["bom-ref"].as_str().unwrap_or_default().into(),
                    name: c["name"].as_str().unwrap_or_default().into(),
                    reasons,
                });
            }
        }
        scopes.insert(scope.to_string(), summary);
    }
    let discovery: Option<Value> = prop(
        &bom["metadata"]["component"],
        "flatpak:active-extension-discovery",
    )
    .map(serde_json::from_str)
    .transpose()
    .context("parse active extension discovery")?;
    let mut limitations = vec!["static-and-vendored-dependencies-not-proven-complete"];
    if scopes.values().any(|s| {
        s.content_observations.iter().any(|o| {
            o["scanner_unknowns"]
                .as_array()
                .is_some_and(|u| !u.is_empty())
        })
    }) {
        limitations.push("scanner-partial-analysis");
    }
    if scopes.values().any(|s| {
        s.content_observations.iter().any(|o| {
            o["unattributed_elf_paths"]
                .as_array()
                .is_some_and(|p| !p.is_empty())
        })
    }) {
        limitations.push("unattributed-native-binaries");
    }
    if scopes.values().any(|s| s.content_scan == "not-performed") {
        limitations.push("content-scan-not-performed");
    }
    if discovery.is_none()
        && scopes
            .values()
            .any(|s| !s.extension_declarations.is_empty())
    {
        limitations.push("active-extension-discovery-not-performed");
    }
    if scopes.values().any(|s| {
        s.gaps
            .iter()
            .any(|g| g.reasons.contains(&"extra-data-not-acquired-from-remote"))
    }) {
        limitations.push("extra-data-acquisition-incomplete");
    }
    if scopes.values().any(|s| {
        s.extra_data_acquisitions
            .iter()
            .any(|a| a["status"] == "opaque-payload")
    }) {
        limitations.push("opaque-extra-data-container");
    }
    if scopes
        .values()
        .any(|s| !s.extra_data_acquisitions.is_empty())
    {
        limitations.push("extra-data-installation-transform-not-evaluated");
    }
    if scopes.values().any(|s| {
        s.extra_data_acquisitions
            .iter()
            .any(|a| a["skipped_links"].as_u64().unwrap_or(0) > 0)
    }) {
        limitations.push("archive-links-not-materialized");
    }
    let acquisition_complete = !limitations.iter().any(|s| {
        matches!(
            *s,
            "content-scan-not-performed"
                | "active-extension-discovery-not-performed"
                | "extra-data-acquisition-incomplete"
                | "opaque-extra-data-container"
        )
    });
    Ok(Coverage { inventory_complete: false, acquisition_complete, completeness_limitations: limitations, active_extension_discovery: discovery,
        note: "Identity counts are not vulnerability-detection recall. Content scans may miss stripped binaries, vendored code, and extensions. Manifest sources may be build-only or removed during cleanup.", scopes })
}

#[cfg(test)]
mod tests {
    #[test]
    fn generic_native_records_need_a_separate_advisory_identity() {
        let bom = serde_json::json!({"bomFormat":"CycloneDX", "components":[
            {"name":"vlc", "bom-ref":"vlc", "version":"3.0.11", "purl":"pkg:generic/vlc@3.0.11",
             "cpe":"cpe:2.3:a:videolan:vlc_media_player:3.0.11:*:*:*:*:*:*:*",
             "properties":[{"name":"flatpak:scope","value":"app"},{"name":"flatpak:inventory-kind","value":"content-detected"}]},
            {"name":"libavcodec", "bom-ref":"codec", "version":"58.134.100", "purl":"pkg:generic/libavcodec@58.134.100",
             "properties":[{"name":"flatpak:scope","value":"app"},{"name":"flatpak:inventory-kind","value":"content-detected"}]}
        ]});
        let report = super::summarize(&bom).unwrap();
        let app = &report.scopes["app"];
        assert_eq!(app.cpe_identities_with_release_version, 1);
        assert_eq!(app.ecosystem_identities_with_release_version, 0);
        assert_eq!(app.gaps.len(), 1);
        assert_eq!(app.gaps[0].name, "libavcodec");
        assert_eq!(app.gaps[0].reasons, ["unverified-advisory-ecosystem"]);
    }
    #[test]
    fn rejects_non_sbom_input() {
        assert!(super::summarize(&serde_json::json!({})).is_err());
    }
}
