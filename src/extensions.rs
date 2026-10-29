//! Explicitly selected extension contents, not an assertion of active mounts.
use crate::{
    cyclonedx::{property, Bom, Component, Dependency},
    metadata::FlatpakMetadata,
    ostree::OstreeFileReader,
    refname::FlatpakRef,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::process::Command;

pub fn include(
    bom: &mut Bom,
    reader: &impl OstreeFileReader,
    repo: &str,
    selected: &[String],
) -> Result<()> {
    let mut seen: BTreeSet<String> = bom
        .components
        .iter()
        .filter(|c| {
            c.properties
                .iter()
                .any(|p| p.name == "flatpak:scope" && p.value == "extension")
        })
        .filter_map(|c| {
            c.properties
                .iter()
                .find(|p| p.name == "flatpak:ref")
                .map(|p| p.value.clone())
        })
        .collect();
    let mut inventories: Vec<Value> = bom
        .metadata
        .component
        .properties
        .iter()
        .find(|p| p.name == "flatpak:extension-inventories")
        .map(|p| serde_json::from_str(&p.value))
        .transpose()?
        .unwrap_or_default();
    for reference in selected {
        if !seen.insert(reference.clone()) {
            continue;
        }
        let extension = FlatpakRef::parse(reference)?;
        if extension.kind != "runtime" {
            bail!("extension must be a runtime ref: {reference}");
        }
        let mut parents = Vec::new();
        for scope in ["app", "runtime"] {
            let declarations = bom
                .metadata
                .component
                .properties
                .iter()
                .find(|p| p.name == format!("flatpak:extension-declarations:{scope}"))
                .context("missing extension declarations")?;
            for mut declaration in serde_json::from_str::<Vec<Value>>(&declarations.value)? {
                if matches_declaration(&extension, &declaration)? {
                    if let Some(fields) = declaration.as_object_mut() {
                        fields.remove("status");
                        fields.remove("selected_refs");
                    }
                    parents.push(declaration);
                }
            }
        }
        if parents.is_empty() {
            bail!("selected extension {reference} does not match an app/runtime declaration (name, architecture and branch)");
        }
        let commit = reader
            .resolve_ref(repo, reference)
            .with_context(|| format!("resolve extension {reference}"))?;
        let metadata = reader
            .read_file_from_ref(repo, reference, "metadata")?
            .context("selected extension has no metadata")?;
        let metadata = FlatpakMetadata::parse(std::str::from_utf8(&metadata)?)?;
        // Derived runtimes (e.g. GNOME) can declare extensions built for their
        // Freedesktop base. Preserve ExtensionOf as build provenance; it does
        // not replace the consuming runtime's extension declaration.
        let built_for = metadata.get("ExtensionOf", "ref");
        if let Some(parent) = built_for {
            FlatpakRef::parse(parent).context("invalid extension build-parent ref")?;
        }
        let bom_ref = format!("flatpak:extension/{reference}@{commit}");
        let extra_data = metadata.groups().any(|(name, _)| name == "Extra Data");
        let selection = json!({"ref":reference, "commit":commit, "selection":"explicit",
            "activation":"not-evaluated", "inventory":"content-only", "built_for_ref":built_for,
            "extra_data_declared":extra_data, "parents":parents});
        let mut properties = vec![
            property("flatpak:scope", "extension"),
            property("flatpak:ref", reference),
            property("flatpak:commit", &commit),
            property("flatpak:repo-url", repo),
            property("flatpak:inventory-kind", "extension-artifact"),
            property("flatpak:extra-data-declared", extra_data.to_string()),
            property(
                "flatpak:extension-selection",
                serde_json::to_string(&selection)?,
            ),
        ];
        crate::sbom::push_metadata_properties(&mut properties, &metadata);
        bom.components.push(Component {
            component_type: "framework".into(),
            name: extension.id,
            bom_ref: bom_ref.clone(),
            version: Some(extension.branch),
            purl: None,
            cpe: None,
            external_references: vec![],
            hashes: vec![],
            licenses: vec![],
            evidence: None,
            properties,
        });
        for parent in &parents {
            let id = format!(
                "flatpak:{}@{}",
                parent["parent_ref"].as_str().unwrap(),
                parent["parent_commit"].as_str().unwrap()
            );
            let dependency = bom
                .dependencies
                .iter_mut()
                .find(|d| d.bom_ref == id)
                .context("missing extension parent graph node")?;
            if !dependency.depends_on.contains(&bom_ref) {
                dependency.depends_on.push(bom_ref.clone());
            }
        }
        bom.dependencies.push(Dependency {
            bom_ref: bom_ref.clone(),
            depends_on: vec![],
        });
        if let Some(composition) = bom.compositions.first_mut() {
            composition.assemblies.push(bom_ref);
        }
        for property in &mut bom.metadata.component.properties {
            if !property.name.starts_with("flatpak:extension-declarations:") {
                continue;
            }
            let mut declarations: Vec<Value> = serde_json::from_str(&property.value)?;
            for declaration in &mut declarations {
                if parents.iter().any(|p| {
                    p["parent_ref"] == declaration["parent_ref"] && p["name"] == declaration["name"]
                }) {
                    declaration["status"] = json!("partially-inventoried");
                    let object = declaration
                        .as_object_mut()
                        .context("invalid extension declaration")?;
                    object
                        .entry("selected_refs")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .context("invalid selected extension refs")?
                        .push(json!(reference));
                }
            }
            property.value = serde_json::to_string(&declarations)?;
        }
        inventories.push(selection);
    }
    if !inventories.is_empty() {
        bom.metadata
            .component
            .properties
            .retain(|p| p.name != "flatpak:extension-inventories");
        bom.metadata.component.properties.push(property(
            "flatpak:extension-inventories",
            serde_json::to_string(&inventories)?,
        ));
    }
    Ok(())
}

/// Delegate enable-if, GL-driver, theme and full-vs-subdirectory precedence to
/// Flatpak's own flatpak_list_extensions implementation, without launching apps.
pub fn discover_active(bom: &mut Bom, reader: &crate::installed::InstalledReader) -> Result<()> {
    let parents: Vec<_> = bom
        .components
        .iter()
        .filter(|c| !c.bom_ref.contains('#'))
        .filter(|c| {
            c.properties
                .iter()
                .any(|p| p.name == "flatpak:scope" && matches!(p.value.as_str(), "app" | "runtime"))
        })
        .map(|c| {
            let get = |name| {
                c.properties
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| p.value.clone())
                    .context("missing parent identity")
            };
            Ok((get("flatpak:ref")?, get("flatpak:commit")?))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut selections = Vec::new();
    let mut evaluations = Vec::new();
    for (parent, commit) in parents {
        let output = Command::new("flatpak")
            .args([
                "info",
                "--show-ref",
                "--show-commit",
                "--show-extensions",
                &parent,
            ])
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("COLUMNS", "4096")
            .env("TERM", "dumb")
            .output()
            .context("discover enabled Flatpak extensions")?;
        if !output.status.success() {
            bail!(
                "Flatpak extension discovery failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let discovered = parse_discovery(std::str::from_utf8(&output.stdout)?, &parent, &commit)?;
        for extension in &discovered {
            reader.pin_discovered(
                &extension.reference,
                &extension.commit,
                &extension.installation,
            )?;
            selections.push(extension.reference.clone());
        }
        evaluations
            .push(json!({"parent_ref":parent, "parent_commit":commit, "extensions":discovered}));
    }
    include(bom, reader, "urn:flatpak:installed", &selections)?;
    for component in &mut bom.components {
        if let Some(selection) = component
            .properties
            .iter_mut()
            .find(|p| p.name == "flatpak:extension-selection")
        {
            let mut value: Value = serde_json::from_str(&selection.value)?;
            if selections.iter().any(|s| value["ref"] == *s) {
                value["activation"] = json!("enabled-by-flatpak-on-host");
                value["selection"] = json!("flatpak-discovery");
                selection.value = serde_json::to_string(&value)?;
            }
        }
    }
    if let Some(property) = bom
        .metadata
        .component
        .properties
        .iter_mut()
        .find(|p| p.name == "flatpak:extension-inventories")
    {
        let mut inventories: Vec<Value> = serde_json::from_str(&property.value)?;
        for value in &mut inventories {
            if selections.iter().any(|s| value["ref"] == *s) {
                value["activation"] = json!("enabled-by-flatpak-on-host");
                value["selection"] = json!("flatpak-discovery");
            }
        }
        property.value = serde_json::to_string(&inventories)?;
    }
    bom.metadata.component.properties.push(property(
        "flatpak:active-extension-discovery",
        serde_json::to_string(&evaluations)?,
    ));
    Ok(())
}

#[derive(Default, serde::Serialize)]
struct DiscoveredExtension {
    reference: String,
    commit: String,
    installation: String,
    subpaths: Option<String>,
}

fn parse_discovery(text: &str, parent: &str, commit: &str) -> Result<Vec<DiscoveredExtension>> {
    let mut lines = text.lines();
    let header: Vec<_> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if header != [parent, commit] {
        bail!("Flatpak parent changed or discovery header is invalid for {parent}");
    }
    let mut extensions: Vec<DiscoveredExtension> = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .context("malformed Flatpak extension discovery")?;
        let value = value.trim();
        if key == "Extension" {
            if FlatpakRef::parse(value)?.kind != "runtime" {
                bail!("discovered extension is not a runtime ref");
            }
            extensions.push(DiscoveredExtension {
                reference: value.into(),
                ..Default::default()
            });
        } else {
            let extension = extensions
                .last_mut()
                .context("extension fields precede extension ref")?;
            match key {
                "Commit" => extension.commit = value.into(),
                "Installation" => extension.installation = value.into(),
                "Subpaths" => extension.subpaths = Some(value.into()),
                "ID" | "Origin" | "Installed Size" => {}
                _ => bail!("unexpected Flatpak extension discovery field {key}"),
            }
        }
    }
    for extension in &extensions {
        if extension.commit.len() != 64
            || !extension.commit.bytes().all(|b| b.is_ascii_hexdigit())
            || extension.installation.is_empty()
            || extension.installation == "unknown"
        {
            bail!(
                "extension {} has no pinnable deployment (unmaintained or incomplete discovery)",
                extension.reference
            );
        }
    }
    Ok(extensions)
}

fn matches_declaration(extension: &FlatpakRef, declaration: &Value) -> Result<bool> {
    let parent = FlatpakRef::parse(
        declaration["parent_ref"]
            .as_str()
            .context("missing extension parent ref")?,
    )?;
    let name = declaration["name"]
        .as_str()
        .context("missing extension declaration name")?;
    let name = name.split('@').next().unwrap();
    let fields = &declaration["metadata"];
    let name_matches = extension.id == name
        || (fields["subdirectories"] == "true"
            && extension
                .id
                .strip_prefix(name)
                .is_some_and(|suffix| suffix.starts_with('.') && suffix.len() > 1));
    let versions = fields["versions"]
        .as_str()
        .or_else(|| fields["version"].as_str())
        .unwrap_or(&parent.branch);
    Ok(name_matches
        && extension.arch == parent.arch
        && versions.split(';').any(|v| v == extension.branch))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_rejects_changed_parents_and_unpinned_extensions() {
        let parent = "runtime/org.example.Platform/x86_64/stable";
        let commit = "a".repeat(64);
        let text = format!("{parent} {commit}\n Extension: runtime/org.example.Locale/x86_64/stable\n Commit: {}\n Installation: user\n Subpaths: /en\n", "b".repeat(64));
        let records = parse_discovery(&text, parent, &commit).unwrap();
        assert_eq!(records[0].subpaths.as_deref(), Some("/en"));
        assert!(parse_discovery(&text, parent, &"c".repeat(64)).is_err());
        assert!(parse_discovery(
            &text.replace(&"b".repeat(64), "unmaintained"),
            parent,
            &commit
        )
        .is_err());
        assert!(parse_discovery(
            &text.replace("Installation: user", "Installation: unknown"),
            parent,
            &commit
        )
        .is_err());
        assert!(parse_discovery("", parent, &commit).is_err());
        assert!(
            parse_discovery(&format!("{parent} {commit}\n"), parent, &commit)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn explicit_selection_requires_matching_name_architecture_and_branch() {
        let declaration = json!({"name":"org.example.GL", "parent_ref":"runtime/org.example.Platform/x86_64/stable",
            "metadata":{"versions":"24.08;25.08;", "subdirectories":"true"}});
        for (reference, expected) in [
            ("runtime/org.example.GL.default/x86_64/24.08", true),
            ("runtime/org.example.GL/x86_64/25.08", true),
            ("runtime/org.example.GLExtra/x86_64/24.08", false),
            ("runtime/org.example.GL.default/aarch64/24.08", false),
            ("runtime/org.example.GL.default/x86_64/stable", false),
        ] {
            assert_eq!(
                matches_declaration(&FlatpakRef::parse(reference).unwrap(), &declaration).unwrap(),
                expected
            );
        }
        let declaration = json!({"name":"org.example.Codecs", "parent_ref":"app/org.example.App/x86_64/stable", "metadata":{}});
        assert!(matches_declaration(
            &FlatpakRef::parse("runtime/org.example.Codecs/x86_64/stable").unwrap(),
            &declaration
        )
        .unwrap());
        assert!(!matches_declaration(
            &FlatpakRef::parse("runtime/org.example.Codecs.child/x86_64/stable").unwrap(),
            &declaration
        )
        .unwrap());
    }
}
