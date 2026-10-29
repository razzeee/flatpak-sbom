//! Offline, exact repository-PURL lookups; no package-name guessing.
use crate::cyclonedx::{property, Bom, Component};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Index {
    source: String,
    revision: String,
    mappings: BTreeMap<String, Vec<String>>,
    unsupported_purls: BTreeSet<String>,
}

pub fn enrich(bom: &mut Bom) -> Result<()> {
    let index: Index = serde_json::from_str(include_str!("../data/purl2cpe.json"))
        .context("parse bundled purl2cpe index")?;
    bom.metadata.component.properties.push(property(
        "flatpak:cpe-mapping-source",
        format!("{}@{}", index.source, index.revision),
    ));
    for component in &mut bom.components {
        if let Some(key) = component.purl.as_deref().and_then(repository_key) {
            if let Some(candidates) = index.mappings.get(&key) {
                apply(
                    component,
                    &key,
                    candidates,
                    &index.revision,
                    index.unsupported_purls.contains(&key),
                )?;
            }
        }
    }
    Ok(())
}

fn repository_key(value: &str) -> Option<String> {
    let purl = value.parse::<packageurl::PackageUrl>().ok()?;
    if !matches!(purl.ty(), "github" | "gitlab" | "bitbucket")
        || !purl.qualifiers().is_empty()
        || purl.subpath().is_some()
    {
        return None;
    }
    let mut key = packageurl::PackageUrl::new(purl.ty(), purl.name()).ok()?;
    key.with_namespace(purl.namespace()?).ok()?;
    Some(key.to_string())
}

fn apply(
    component: &mut Component,
    key: &str,
    candidates: &[String],
    revision: &str,
    unsupported: bool,
) -> Result<()> {
    component
        .properties
        .push(property("flatpak:cpe-mapping-purl", key));
    component
        .properties
        .push(property("flatpak:cpe-mapping-revision", revision));
    component.properties.push(property(
        "flatpak:cpe-mapping-candidates",
        serde_json::to_string(candidates)?,
    ));
    let kind = component
        .properties
        .iter()
        .find(|p| p.name == "flatpak:version-kind")
        .map(|p| p.value.as_str());
    let status = if component.cpe.is_some() {
        "existing-cpe-preserved"
    } else if unsupported || candidates.len() != 1 {
        "ambiguous-or-unsupported-binding"
    } else if kind != Some("release") {
        "missing-release-evidence"
    } else if let Some(cpe) = component
        .version
        .as_deref()
        .and_then(|version| instantiate(&candidates[0], version))
    {
        component.cpe = Some(cpe);
        "mapped"
    } else {
        "constrained-binding-or-unsupported-version"
    };
    component
        .properties
        .push(property("flatpak:cpe-mapping-status", status));
    Ok(())
}

fn instantiate(template: &str, version: &str) -> Option<String> {
    // Only plain numeric releases: don't guess how tags/prereleases map to CPE
    // version/update fields or turn a Git hash into a release version.
    let version = version.strip_prefix('v').unwrap_or(version);
    if version.len() > 64
        || !version.contains('.')
        || version
            .split('.')
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let mut fields: Vec<_> = template.split(':').collect();
    if fields.len() != 13
        || fields[..3] != ["cpe", "2.3", "a"]
        || fields[3..5].iter().any(|field| {
            *field == "-"
                || field.is_empty()
                || !field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
        || fields[5..].iter().any(|field| *field != "*")
    {
        return None;
    }
    fields[5] = version;
    Some(fields.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_bindings_and_commit_versions_never_become_release_cpes() {
        let mut component = Component {
            component_type: "library".into(),
            name: "example".into(),
            bom_ref: "example".into(),
            version: Some("1.2.3".into()),
            purl: None,
            cpe: None,
            external_references: vec![],
            hashes: vec![],
            licenses: vec![],
            evidence: None,
            properties: vec![property("flatpak:version-kind", "git-commit")],
        };
        let candidates = vec!["cpe:2.3:a:example:library:*:*:*:*:*:*:*:*".into()];
        apply(
            &mut component,
            "pkg:github/example/library",
            &candidates,
            "revision",
            false,
        )
        .unwrap();
        assert!(component.cpe.is_none());
        component.properties = vec![property("flatpak:version-kind", "release")];
        let mut ambiguous = candidates.clone();
        ambiguous.push("cpe:2.3:a:other:library:*:*:*:*:*:*:*:*".into());
        apply(
            &mut component,
            "pkg:github/example/library",
            &ambiguous,
            "revision",
            false,
        )
        .unwrap();
        assert!(component.cpe.is_none());
        apply(
            &mut component,
            "pkg:github/example/library",
            &candidates,
            "revision",
            false,
        )
        .unwrap();
        assert_eq!(
            component.cpe.as_deref(),
            Some("cpe:2.3:a:example:library:1.2.3:*:*:*:*:*:*:*")
        );
        component.cpe = None;
        apply(
            &mut component,
            "pkg:github/example/library",
            &candidates,
            "revision",
            true,
        )
        .unwrap();
        assert!(component.cpe.is_none());
        component.cpe = Some("cpe:2.3:a:example:library:1.2.3:*:*:*:*:*:*:*".into());
        apply(
            &mut component,
            "pkg:github/example/library",
            &ambiguous,
            "revision",
            false,
        )
        .unwrap();
        assert_eq!(
            component.cpe.as_deref(),
            Some("cpe:2.3:a:example:library:1.2.3:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn exact_repository_identity_does_not_broaden_subpackages_or_forks() {
        assert_eq!(
            repository_key("pkg:github/LibSSH2/libssh2@1.11.1"),
            Some("pkg:github/libssh2/libssh2".into())
        );
        assert_eq!(repository_key("pkg:generic/libssh2@1.11.1"), None);
        assert_eq!(
            repository_key("pkg:github/libssh2/libssh2@1.11.1#subdir"),
            None
        );
        assert_eq!(
            repository_key("pkg:github/libssh2/libssh2?arch=x86_64"),
            None
        );
        let index: Index = serde_json::from_str(include_str!("../data/purl2cpe.json")).unwrap();
        assert_eq!(
            index.mappings["pkg:github/libssh2/libssh2"],
            ["cpe:2.3:a:libssh2:libssh2:*:*:*:*:*:*:*:*"]
        );
        assert!(!index
            .mappings
            .contains_key("pkg:github/unrelated-fork/libssh2"));
        assert!(index.mappings["pkg:github/ffmpeg/ffmpeg"].len() > 1);
    }

    #[test]
    fn cpe_version_mapping_preserves_constraints() {
        let template = "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*";
        assert_eq!(
            instantiate(template, "1.2.3"),
            Some("cpe:2.3:a:example:library:1.2.3:*:*:*:*:*:*:*".into())
        );
        assert_eq!(
            instantiate(template, "v1.2.3"),
            instantiate(template, "1.2.3")
        );
        for version in ["1.2.3-rc1", "library-1.2.3", "1.2:*", "deadbeef", "1..2"] {
            assert_eq!(instantiate(template, version), None);
        }
        assert_eq!(
            instantiate("cpe:2.3:a:example:library:*:*:*:*:*:windows:*:*", "1.2.3"),
            None
        );
    }
}
