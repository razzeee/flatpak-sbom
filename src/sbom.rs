use crate::cyclonedx::{
    property, Bom, Component, Composition, Dependency, Evidence, EvidenceIdentity,
    ExternalReference, Hash, LicenseChoice, Lifecycle, Metadata, Tools,
};
use crate::manifest::{FlatpakManifest, Source};
use crate::metadata::FlatpakMetadata;
use crate::ostree::{OstreeFileReader, RepositorySnapshot};
use crate::refname::FlatpakRef;
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

pub fn generate_for_app(
    reader: &impl OstreeFileReader,
    repo_url: &str,
    app_ref: &str,
) -> Result<Bom> {
    let app_ref = FlatpakRef::parse(app_ref)?;
    if app_ref.kind() != "app" {
        return Err(anyhow!(
            "generate expects an app ref, got '{}'",
            app_ref.as_str()
        ));
    }

    let app_snapshot = reader
        .read_snapshot(
            repo_url,
            &app_ref.as_str(),
            &["metadata", "files/manifest.json"],
        )
        .context("read app snapshot")?;
    let app_commit = app_snapshot.commit.clone();
    let app_metadata = read_metadata(&app_snapshot).context("read app metadata")?;
    let (app_manifest, _) = read_manifest_from_paths(&app_snapshot, &["files/manifest.json"])
        .context("read app manifest")?;

    let runtime_ref = FlatpakRef::runtime(
        app_metadata.runtime(),
        app_manifest.runtime.as_deref(),
        app_manifest.runtime_version.as_deref(),
        app_ref.arch(),
    )
    .context("determine runtime ref")?;
    let runtime_snapshot = reader
        .read_snapshot(
            repo_url,
            &runtime_ref.as_str(),
            &["metadata", "files/manifest.json", "usr/manifest.json"],
        )
        .context("read runtime snapshot")?;
    let runtime_commit = runtime_snapshot.commit.clone();
    let runtime_metadata = read_metadata(&runtime_snapshot).context("read runtime metadata")?;
    let (runtime_manifest, runtime_manifest_path) = read_manifest_from_paths(
        &runtime_snapshot,
        &["files/manifest.json", "usr/manifest.json"],
    )
    .context("read runtime manifest")?;
    let extension_group_count =
        app_metadata.extension_groups().count() + runtime_metadata.extension_groups().count();

    let root_ref = format!(
        "flatpak:{}@{}+runtime@{}",
        app_ref.as_str(),
        app_commit,
        runtime_commit
    );
    let mut root_properties = vec![
        property("flatpak:scope", "app"),
        property("flatpak:repo-url", repo_url),
        property("flatpak:ref", app_ref.as_str()),
        property("flatpak:commit", app_commit.clone()),
        property("flatpak:inventory-kind", "manifest-derived"),
        property("flatpak:composition-reason", "Manifest-derived metadata does not enumerate package contents inside source archives, vendored trees, or binary extra-data payloads"),
        property("flatpak:composition-coverage", "app-and-runtime-manifests"),
        property("flatpak:composition-runtime-ref", runtime_ref.as_str()),
    ];
    push_optional(
        &mut root_properties,
        "flatpak:manifest-id",
        app_manifest.id.as_deref(),
    );
    push_optional(
        &mut root_properties,
        "flatpak:manifest-app-id",
        app_manifest.app_id.as_deref(),
    );
    push_optional(
        &mut root_properties,
        "flatpak:manifest-command",
        app_manifest.command.as_deref(),
    );
    push_optional(
        &mut root_properties,
        "flatpak:manifest-runtime",
        app_manifest.runtime.as_deref(),
    );
    push_optional(
        &mut root_properties,
        "flatpak:manifest-runtime-version",
        app_manifest.runtime_version.as_deref(),
    );
    push_optional(
        &mut root_properties,
        "flatpak:manifest-sdk",
        app_manifest.sdk.as_deref(),
    );
    push_string_list(
        &mut root_properties,
        "flatpak:manifest-finish-args",
        app_manifest.finish_args.as_deref(),
    );
    push_string_list(
        &mut root_properties,
        "flatpak:manifest-cleanup",
        app_manifest.cleanup.as_deref(),
    );
    push_string_list(
        &mut root_properties,
        "flatpak:manifest-cleanup-commands",
        app_manifest.cleanup_commands.as_deref(),
    );
    push_extra_properties(
        &mut root_properties,
        "flatpak:manifest-extra",
        &app_manifest.extra,
    );
    if extension_group_count > 0 {
        root_properties.push(property(
            "flatpak:unresolved-extension-groups",
            extension_group_count.to_string(),
        ));
    }

    for (scope, metadata, reference, commit) in [
        ("app", &app_metadata, app_ref.as_str(), &app_commit),
        (
            "runtime",
            &runtime_metadata,
            runtime_ref.as_str(),
            &runtime_commit,
        ),
    ] {
        let declarations: Vec<_> = metadata
            .extension_groups()
            .map(|(group, fields)| {
                serde_json::json!({"name":group.strip_prefix("Extension ").unwrap(),
                "parent_ref":reference, "parent_commit":commit,
                "metadata":fields, "status":"not-inventoried"})
            })
            .collect();
        root_properties.push(property(
            format!("flatpak:extension-declarations:{scope}"),
            serde_json::to_string(&declarations)?,
        ));
    }
    let root = Component {
        cpe: None,
        component_type: "application".to_string(),
        name: app_ref.id().to_string(),
        bom_ref: root_ref.clone(),
        version: Some(app_ref.branch().to_string()),
        purl: Some(app_ref.purl()),
        external_references: vec![ExternalReference {
            reference_type: "distribution".to_string(),
            url: repo_url.to_string(),
        }],
        hashes: vec![],
        licenses: licenses_from_expression(app_manifest.license.as_deref()),
        evidence: Some(component_evidence("purl", app_ref.purl())),
        properties: root_properties,
    };

    let app_context = ComponentContext {
        repo_url,
        scope: "app",
        flatpak_ref: &app_ref,
        commit: &app_commit,
        manifest_path: "files/manifest.json",
    };
    let runtime_context = ComponentContext {
        repo_url,
        scope: "runtime",
        flatpak_ref: &runtime_ref,
        commit: &runtime_commit,
        manifest_path: &runtime_manifest_path,
    };
    let app_artifact = artifact_component(
        app_context,
        app_manifest.license.as_deref(),
        Some(&app_metadata),
    );
    let runtime_artifact = artifact_component(
        runtime_context,
        runtime_manifest.license.as_deref(),
        Some(&runtime_metadata),
    );
    let app_artifact_ref = app_artifact.bom_ref.clone();
    let runtime_artifact_ref = runtime_artifact.bom_ref.clone();
    let mut components = vec![app_artifact, runtime_artifact];
    let app_manifest_components = manifest_components(app_context, &app_manifest);
    let runtime_manifest_components = manifest_components(runtime_context, &runtime_manifest);
    components.extend(app_manifest_components.components);
    components.extend(runtime_manifest_components.components);

    let assemblies = components
        .iter()
        .map(|component| component.bom_ref.clone())
        .collect::<Vec<_>>();
    let mut dependencies = vec![Dependency {
        bom_ref: root_ref.clone(),
        depends_on: vec![app_artifact_ref.clone(), runtime_artifact_ref.clone()],
    }];
    dependencies.push(Dependency {
        bom_ref: app_artifact_ref,
        depends_on: app_manifest_components.module_refs,
    });
    dependencies.push(Dependency {
        bom_ref: runtime_artifact_ref,
        depends_on: runtime_manifest_components.module_refs,
    });
    dependencies.extend(app_manifest_components.dependencies);
    dependencies.extend(runtime_manifest_components.dependencies);

    Ok(Bom {
        schema: "https://cyclonedx.org/schema/bom-1.7.schema.json".to_string(),
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.7".to_string(),
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp: Some(
                OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .context("format CycloneDX timestamp")?,
            ),
            lifecycles: vec![Lifecycle {
                phase: "build".to_string(),
            }],
            tools: Some(Tools {
                components: vec![Component {
                    cpe: None,
                    component_type: "application".to_string(),
                    name: "flatpak-sbom".to_string(),
                    bom_ref: format!("pkg:cargo/flatpak-sbom@{}", env!("CARGO_PKG_VERSION")),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    purl: Some(format!(
                        "pkg:cargo/flatpak-sbom@{}",
                        env!("CARGO_PKG_VERSION")
                    )),
                    external_references: vec![],
                    hashes: vec![],
                    licenses: vec![],
                    evidence: None,
                    properties: vec![],
                }],
            }),
            component: root,
        },
        components,
        dependencies,
        compositions: vec![Composition {
            aggregate: "incomplete".to_string(),
            assemblies,
        }],
    })
}

fn read_metadata(snapshot: &RepositorySnapshot) -> Result<FlatpakMetadata> {
    let bytes = snapshot
        .files
        .get("metadata")
        .ok_or_else(|| anyhow!("metadata not found for {}", snapshot.commit))?;
    let text = std::str::from_utf8(bytes).context("metadata is not UTF-8")?;
    FlatpakMetadata::parse(text)
}

fn read_manifest_from_paths(
    snapshot: &RepositorySnapshot,
    paths: &[&str],
) -> Result<(FlatpakManifest, String)> {
    let mut missing_paths = Vec::new();
    for path in paths {
        match snapshot.files.get(*path) {
            Some(bytes) => {
                let manifest = serde_json::from_slice(bytes)
                    .with_context(|| format!("parse {path} for {}", snapshot.commit))?;
                return Ok((manifest, (*path).to_string()));
            }
            None => missing_paths.push(*path),
        }
    }

    Err(anyhow!(
        "none of {} found for {}",
        missing_paths.join(", "),
        snapshot.commit
    ))
}

#[derive(Clone, Copy)]
struct ComponentContext<'a> {
    repo_url: &'a str,
    scope: &'a str,
    flatpak_ref: &'a FlatpakRef,
    commit: &'a str,
    manifest_path: &'a str,
}

fn artifact_component(
    context: ComponentContext<'_>,
    license: Option<&str>,
    flatpak_metadata: Option<&FlatpakMetadata>,
) -> Component {
    let mut properties = base_properties(context);
    if let Some(flatpak_metadata) = flatpak_metadata {
        push_metadata_properties(&mut properties, flatpak_metadata);
    }
    let purl = context.flatpak_ref.purl();

    Component {
        cpe: None,
        component_type: if context.scope == "app" {
            "application"
        } else {
            "framework"
        }
        .to_string(),
        name: context.flatpak_ref.id().to_string(),
        bom_ref: format!(
            "flatpak:{}@{}",
            context.flatpak_ref.as_str(),
            context.commit
        ),
        version: Some(context.flatpak_ref.branch().to_string()),
        purl: Some(purl.clone()),
        external_references: vec![ExternalReference {
            reference_type: "distribution".to_string(),
            url: context.repo_url.to_string(),
        }],
        hashes: vec![],
        licenses: licenses_from_expression(license),
        evidence: Some(component_evidence("purl", purl)),
        properties,
    }
}

struct ManifestComponents {
    components: Vec<Component>,
    module_refs: Vec<String>,
    dependencies: Vec<Dependency>,
}

fn manifest_components(
    context: ComponentContext<'_>,
    manifest: &FlatpakManifest,
) -> ManifestComponents {
    let mut components = Vec::new();
    let mut module_refs = Vec::new();
    let mut dependencies = Vec::new();
    for (index, module) in manifest.modules.iter().enumerate() {
        if !module.applies_to_arch(context.flatpak_ref.arch()) {
            continue;
        }

        let module_ref = collect_module_components(
            context,
            module,
            &[module.name().to_string()],
            &format!("/modules/{index}"),
            &mut components,
            &mut dependencies,
        );
        module_refs.push(module_ref);
    }
    ManifestComponents {
        components,
        module_refs,
        dependencies,
    }
}

fn collect_module_components(
    context: ComponentContext<'_>,
    module: &crate::manifest::Module,
    module_path: &[String],
    module_pointer: &str,
    components: &mut Vec<Component>,
    dependencies: &mut Vec<Dependency>,
) -> String {
    let module_name = module.name();
    let object = module.object();
    let module_path_string = module_path.join("/");
    let mut module_properties = with_module(base_properties(context), module_name);
    module_properties.push(property(
        "flatpak:manifest-module-path",
        &module_path_string,
    ));
    module_properties.push(property("flatpak:manifest-module-pointer", module_pointer));
    push_optional(
        &mut module_properties,
        "flatpak:module-buildsystem",
        object.and_then(|module| module.buildsystem.as_deref()),
    );
    push_optional_value(
        &mut module_properties,
        "flatpak:module-builddir",
        object.and_then(|module| module.builddir.as_ref()),
    );
    push_optional(
        &mut module_properties,
        "flatpak:module-subdir",
        object.and_then(|module| module.subdir.as_deref()),
    );
    if let Some(config_opts) = object.and_then(|module| module.config_opts.as_deref()) {
        module_properties.push(property(
            "flatpak:module-config-opts",
            config_opts.join(" "),
        ));
    }
    push_string_list(
        &mut module_properties,
        "flatpak:module-cleanup",
        object.and_then(|module| module.cleanup.as_deref()),
    );
    push_string_list(
        &mut module_properties,
        "flatpak:module-cleanup-commands",
        object.and_then(|module| module.cleanup_commands.as_deref()),
    );
    push_string_list(
        &mut module_properties,
        "flatpak:module-post-install",
        object.and_then(|module| module.post_install.as_deref()),
    );
    if let Some(object) = object {
        push_extra_properties(
            &mut module_properties,
            "flatpak:module-extra",
            &object.extra,
        );
    }

    let module_component = Component {
        cpe: None,
        component_type: "library".to_string(),
        name: module_name.to_string(),
        bom_ref: module_bom_ref(context, module_pointer),
        version: None,
        purl: None,
        external_references: vec![],
        hashes: vec![],
        licenses: licenses_from_expression(object.and_then(|module| module.license.as_deref())),
        evidence: Some(component_evidence("name", module_name.to_string())),
        properties: module_properties,
    };
    let module_ref = module_component.bom_ref.clone();
    components.push(module_component);

    let mut depends_on = Vec::new();
    for (index, child) in object
        .map_or(&[][..], |module| module.modules.as_slice())
        .iter()
        .enumerate()
    {
        if !child.applies_to_arch(context.flatpak_ref.arch()) {
            continue;
        }
        let mut child_path = module_path.to_vec();
        child_path.push(child.name().to_string());
        let child_ref = collect_module_components(
            context,
            child,
            &child_path,
            &format!("{module_pointer}/modules/{index}"),
            components,
            dependencies,
        );
        depends_on.push(child_ref);
    }

    for (index, source) in object
        .map_or(&[][..], |module| module.sources.as_slice())
        .iter()
        .enumerate()
        .filter(|(_, source)| source.applies_to_arch(context.flatpak_ref.arch()))
    {
        let source_component =
            source_component(context, module_name, module_pointer, index, source);
        depends_on.push(source_component.bom_ref.clone());
        dependencies.push(Dependency {
            bom_ref: source_component.bom_ref.clone(),
            depends_on: vec![],
        });
        components.push(source_component);
    }

    dependencies.push(Dependency {
        bom_ref: module_ref.clone(),
        depends_on,
    });
    module_ref
}

fn source_component(
    context: ComponentContext<'_>,
    module_name: &str,
    module_pointer: &str,
    index: usize,
    source: &Source,
) -> Component {
    let source_type = source.source_type.as_deref().unwrap_or("unknown");
    let name = source
        .dest_filename
        .as_deref()
        .or(source.path.as_deref())
        .or_else(|| source.url.as_deref().and_then(last_url_segment))
        .unwrap_or(source_type);
    let mut properties = with_module(base_properties(context), module_name);
    properties.push(property("flatpak:source-type", source_type));
    push_optional(&mut properties, "flatpak:source-url", source.url.as_deref());
    push_optional(
        &mut properties,
        "flatpak:source-sha512",
        source.sha512.as_deref(),
    );
    push_optional(
        &mut properties,
        "flatpak:source-sha256",
        source.sha256.as_deref(),
    );
    push_optional(
        &mut properties,
        "flatpak:source-sha1",
        source.sha1.as_deref(),
    );
    push_optional(&mut properties, "flatpak:source-md5", source.md5.as_deref());
    push_optional(
        &mut properties,
        "flatpak:source-commit",
        source.commit.as_deref(),
    );
    push_optional(&mut properties, "flatpak:source-tag", source.tag.as_deref());
    push_optional(
        &mut properties,
        "flatpak:source-branch",
        source.branch.as_deref(),
    );
    push_optional(
        &mut properties,
        "flatpak:source-filename",
        source.dest_filename.as_deref(),
    );
    push_optional(
        &mut properties,
        "flatpak:source-dest",
        source.dest.as_deref(),
    );
    push_optional(
        &mut properties,
        "flatpak:source-path",
        source.path.as_deref(),
    );
    if let Some(size) = source.size {
        properties.push(property("flatpak:source-size", size.to_string()));
    }
    if let Some(strip_components) = source.strip_components {
        properties.push(property(
            "flatpak:source-strip-components",
            strip_components.to_string(),
        ));
    }
    push_bool(
        &mut properties,
        "flatpak:source-git-submodules",
        source.git_submodules,
    );
    push_bool(
        &mut properties,
        "flatpak:source-disable-shallow-clone",
        source.disable_shallow_clone,
    );
    push_string_list(
        &mut properties,
        "flatpak:source-urls",
        source.urls.as_deref(),
    );
    push_string_list(
        &mut properties,
        "flatpak:source-mirror-urls",
        source.mirror_urls.as_deref(),
    );
    if let Some(arches) = &source.only_arches {
        properties.push(property("flatpak:only-arches", arches.join(",")));
    }
    if let Some(arches) = &source.skip_arches {
        properties.push(property("flatpak:skip-arches", arches.join(",")));
    }
    push_extra_properties(&mut properties, "flatpak:source-extra", &source.extra);

    let purl = crate::package_identity::infer(source);
    let archive_identity = source
        .url
        .as_deref()
        .and_then(crate::package_identity::archive_candidate);
    let version_kind =
        if purl.as_deref().is_some_and(|purl| purl.contains('@')) || source.tag.is_some() {
            "release"
        } else if source.commit.is_some() {
            "git-commit"
        } else if archive_identity.is_some() {
            "filename"
        } else {
            "unknown"
        };
    properties.push(property("flatpak:version-kind", version_kind));
    if let Some((_, version)) = &archive_identity {
        properties.push(property("flatpak:filename-version-candidate", version));
    }
    let package = purl
        .as_deref()
        .and_then(|value| value.parse::<packageurl::PackageUrl>().ok());
    let hashes = source_hashes(source);
    let evidence = source_evidence(source, purl.as_deref(), name);

    Component {
        cpe: None,
        component_type: if purl.is_some() || archive_identity.is_some() {
            "library"
        } else {
            "file"
        }
        .to_string(),
        name: package
            .as_ref()
            .map(|package| package.name())
            .or_else(|| archive_identity.as_ref().map(|(name, _)| name.as_str()))
            .unwrap_or(name)
            .to_string(),
        bom_ref: format!("{}:source={index}", module_bom_ref(context, module_pointer)),
        version: package
            .as_ref()
            .and_then(|package| package.version())
            .map(str::to_string)
            .or_else(|| {
                source.tag.clone().or_else(|| {
                    archive_identity
                        .as_ref()
                        .map(|(_, version)| version.clone())
                })
            }),
        purl,
        external_references: source_external_references(source),
        hashes,
        licenses: vec![],
        evidence,
        properties,
    }
}

fn module_bom_ref(context: ComponentContext<'_>, module_pointer: &str) -> String {
    format!(
        "flatpak:{}@{}#module={}",
        context.flatpak_ref.as_str(),
        context.commit,
        module_pointer
    )
}

fn base_properties(context: ComponentContext<'_>) -> Vec<crate::cyclonedx::Property> {
    vec![
        property("flatpak:scope", context.scope),
        property("flatpak:repo-url", context.repo_url),
        property("flatpak:ref", context.flatpak_ref.as_str()),
        property("flatpak:commit", context.commit),
        property("flatpak:manifest-path", context.manifest_path),
        property("flatpak:inventory-kind", "manifest-derived"),
    ]
}

fn with_module(
    mut properties: Vec<crate::cyclonedx::Property>,
    module_name: &str,
) -> Vec<crate::cyclonedx::Property> {
    properties.push(property("flatpak:manifest-module", module_name));
    properties
}

fn push_optional(
    properties: &mut Vec<crate::cyclonedx::Property>,
    name: &str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        properties.push(property(name, value));
    }
}

fn push_optional_value(
    properties: &mut Vec<crate::cyclonedx::Property>,
    name: &str,
    value: Option<&Value>,
) {
    if let Some(value) = value {
        properties.push(property(name, json_property_value(value)));
    }
}

fn push_string_list(
    properties: &mut Vec<crate::cyclonedx::Property>,
    name: &str,
    value: Option<&[String]>,
) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        properties.push(property(name, value.join(" ")));
    }
}

fn push_bool(properties: &mut Vec<crate::cyclonedx::Property>, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        properties.push(property(name, value.to_string()));
    }
}

fn push_extra_properties(
    properties: &mut Vec<crate::cyclonedx::Property>,
    prefix: &str,
    extra: &BTreeMap<String, Value>,
) {
    for (key, value) in extra {
        properties.push(property(
            format!("{prefix}:{key}"),
            json_property_value(value),
        ));
    }
}

pub(crate) fn push_metadata_properties(
    properties: &mut Vec<crate::cyclonedx::Property>,
    metadata: &FlatpakMetadata,
) {
    for (group, values) in metadata.groups() {
        for (key, value) in values {
            properties.push(property(
                format!(
                    "flatpak:metadata:{}:{}",
                    property_segment(group),
                    property_segment(key)
                ),
                value,
            ));
        }
    }
}

fn property_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn json_property_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn source_external_references(source: &Source) -> Vec<ExternalReference> {
    let mut urls = Vec::new();
    push_url(&mut urls, source.url.as_deref());
    if let Some(source_urls) = &source.urls {
        for url in source_urls {
            push_url(&mut urls, Some(url));
        }
    }
    if let Some(mirror_urls) = &source.mirror_urls {
        for url in mirror_urls {
            push_url(&mut urls, Some(url));
        }
    }

    urls.into_iter()
        .map(|url| ExternalReference {
            reference_type: "distribution".to_string(),
            url,
        })
        .collect()
}

fn push_url(urls: &mut Vec<String>, url: Option<&str>) {
    let Some(url) = url.filter(|url| !url.is_empty()) else {
        return;
    };
    if !urls.iter().any(|existing| existing == url) {
        urls.push(url.to_string());
    }
}

fn source_hashes(source: &Source) -> Vec<Hash> {
    let mut hashes = Vec::new();
    push_hash(&mut hashes, "SHA-512", source.sha512.as_deref());
    push_hash(&mut hashes, "SHA-256", source.sha256.as_deref());
    push_hash(&mut hashes, "SHA-1", source.sha1.as_deref());
    push_hash(&mut hashes, "MD5", source.md5.as_deref());
    hashes
}

fn push_hash(hashes: &mut Vec<Hash>, alg: &str, content: Option<&str>) {
    if let Some(content) = content {
        hashes.push(Hash {
            alg: alg.to_string(),
            content: content.to_string(),
        });
    }
}

fn licenses_from_expression(expression: Option<&str>) -> Vec<LicenseChoice> {
    expression
        .filter(|expression| !expression.trim().is_empty())
        .map(|expression| LicenseChoice {
            expression: expression.to_string(),
        })
        .into_iter()
        .collect()
}

fn source_evidence(source: &Source, purl: Option<&str>, fallback_name: &str) -> Option<Evidence> {
    if let Some(purl) = purl {
        return Some(component_evidence("purl", purl.to_string()));
    }
    if let Some(sha256) = source.sha256.as_deref() {
        return Some(component_evidence("hash", sha256.to_string()));
    }
    Some(component_evidence("name", fallback_name.to_string()))
}

fn component_evidence(field: &str, value: String) -> Evidence {
    Evidence {
        identity: Some(EvidenceIdentity {
            field: field.to_string(),
            concluded_value: value,
        }),
    }
}

fn last_url_segment(url: &str) -> Option<&str> {
    url.split(['?', '#'])
        .next()?
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct FixtureReader {
        files: BTreeMap<(String, String), Vec<u8>>,
        commits: BTreeMap<String, String>,
    }

    fn has_property(component: &Component, name: &str, value: &str) -> bool {
        component
            .properties
            .iter()
            .any(|property| property.name == name && property.value == value)
    }

    impl OstreeFileReader for FixtureReader {
        fn read_snapshot(
            &self,
            _repo_url: &str,
            ref_name: &str,
            paths: &[&str],
        ) -> Result<RepositorySnapshot> {
            let commit = self
                .commits
                .get(ref_name)
                .cloned()
                .ok_or_else(|| anyhow!("missing commit"))?;
            let files = paths
                .iter()
                .filter_map(|path| {
                    self.files
                        .get(&(ref_name.to_string(), path.to_string()))
                        .map(|bytes| (path.to_string(), bytes.clone()))
                })
                .collect();
            Ok(RepositorySnapshot { commit, files })
        }
    }

    #[test]
    fn generates_flattened_cyclonedx() {
        let app_ref = "app/org.example.App/x86_64/stable";
        let runtime_ref = "runtime/org.gnome.Platform/x86_64/46";
        let reader = FixtureReader {
            files: BTreeMap::from([
                ((app_ref.to_string(), "metadata".to_string()), b"[Application]\nruntime=org.gnome.Platform/x86_64/46\ncommand=example-app\n[Context]\nshared=network;ipc;\n[Session Bus Policy]\norg.example.Service=talk\n[Environment]\nFOO=bar\n[Extension org.example.Codecs]\ndirectory=lib/codecs\n".to_vec()),
                ((app_ref.to_string(), "files/manifest.json".to_string()), br#"{"id":"org.example.App","license":"GPL-3.0-or-later","command":"example-app","runtime":"org.gnome.Platform","runtime-version":"46","sdk":"org.gnome.Sdk","finish-args":["--share=network"],"cleanup":["/include"],"rename-icon":"org.example.App","modules":[{"name":"zlib","license":"Zlib","buildsystem":"cmake-ninja","config-opts":["-DBUILD_SHARED_LIBS=ON"],"cleanup":["*.la"],"post-install":["install -Dm644 COPYING /app/share/licenses/zlib/COPYING"],"custom-module-key":"module-extra","sources":[{"type":"git","url":"https://github.com/madler/zlib.git","tag":"v1.3.1"}],"modules":[{"name":"zlib-helper","sources":[{"type":"file","path":"helper.patch"}]}]}]}"#.to_vec()),
                ((runtime_ref.to_string(), "metadata".to_string()), b"[Runtime]\nruntime=org.gnome.Platform\n[Extension org.example.Locale]\ndirectory=share/runtime/locale\n".to_vec()),
                ((runtime_ref.to_string(), "files/manifest.json".to_string()), br#"{"modules":[{"name":"openssl","sources":[{"type":"archive","url":"https://example.test/openssl.tar.gz","urls":["https://mirror1.example.test/openssl.tar.gz"],"mirror-urls":["https://mirror2.example.test/openssl.tar.gz"],"sha512":"abc","sha256":"def","sha1":"123","md5":"456","dest":"openssl-src","strip-components":1,"git-submodules":true,"disable-shallow-clone":true,"x-checker-data":"checker-extra"}]}]}"#.to_vec()),
            ]),
            commits: BTreeMap::from([(app_ref.to_string(), "appcommit".to_string()), (runtime_ref.to_string(), "runtimecommit".to_string())]),
        };

        let bom = generate_for_app(&reader, "https://example.test/repo", app_ref).unwrap();
        assert_eq!(
            bom.schema,
            "https://cyclonedx.org/schema/bom-1.7.schema.json"
        );
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.7");
        assert!(bom.serial_number.starts_with("urn:uuid:"));
        assert!(bom.metadata.timestamp.is_some());
        assert!(bom
            .metadata
            .lifecycles
            .iter()
            .any(|lifecycle| lifecycle.phase == "build"));
        assert_eq!(
            bom.metadata
                .component
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.identity.as_ref())
                .map(|identity| identity.field.as_str()),
            Some("purl")
        );
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:repo-url",
            "https://example.test/repo"
        ));
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:manifest-id",
            "org.example.App"
        ));
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:manifest-command",
            "example-app"
        ));
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:manifest-finish-args",
            "--share=network"
        ));
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:manifest-cleanup",
            "/include"
        ));
        assert!(has_property(
            &bom.metadata.component,
            "flatpak:manifest-extra:rename-icon",
            "org.example.App"
        ));
        assert!(bom
            .metadata
            .component
            .licenses
            .iter()
            .any(|license| license.expression == "GPL-3.0-or-later"));
        assert_eq!(
            bom.metadata
                .tools
                .as_ref()
                .unwrap()
                .components
                .first()
                .unwrap()
                .name,
            "flatpak-sbom"
        );
        assert!(bom
            .components
            .iter()
            .any(|component| component.name == "openssl"));
        assert!(bom.components.iter().any(|component| {
            component.bom_ref == "flatpak:app/org.example.App/x86_64/stable@appcommit"
                && component
                    .evidence
                    .as_ref()
                    .and_then(|evidence| evidence.identity.as_ref())
                    .is_some_and(|identity| identity.field == "purl")
                && has_property(
                    component,
                    "flatpak:metadata:Application:command",
                    "example-app",
                )
                && has_property(component, "flatpak:metadata:Context:shared", "network;ipc;")
                && has_property(
                    component,
                    "flatpak:metadata:Session_Bus_Policy:org.example.Service",
                    "talk",
                )
                && has_property(component, "flatpak:metadata:Environment:FOO", "bar")
                && has_property(
                    component,
                    "flatpak:metadata:Extension_org.example.Codecs:directory",
                    "lib/codecs",
                )
        }));
        assert!(bom.components.iter().any(|component| {
            component.bom_ref == "flatpak:runtime/org.gnome.Platform/x86_64/46@runtimecommit"
                && has_property(
                    component,
                    "flatpak:metadata:Runtime:runtime",
                    "org.gnome.Platform",
                )
                && has_property(
                    component,
                    "flatpak:metadata:Extension_org.example.Locale:directory",
                    "share/runtime/locale",
                )
        }));
        assert!(bom
            .components
            .iter()
            .any(|component| component.purl.as_deref() == Some("pkg:github/madler/zlib@v1.3.1")));
        assert!(bom.components.iter().any(|component| {
            component.purl.as_deref() == Some("pkg:github/madler/zlib@v1.3.1")
                && component.component_type == "library"
                && component
                    .evidence
                    .as_ref()
                    .and_then(|evidence| evidence.identity.as_ref())
                    .is_some_and(|identity| identity.field == "purl")
        }));
        assert!(bom.components.iter().any(|component| {
            component.name == "zlib"
                && has_property(component, "flatpak:module-buildsystem", "cmake-ninja")
                && has_property(
                    component,
                    "flatpak:module-config-opts",
                    "-DBUILD_SHARED_LIBS=ON",
                )
                && has_property(component, "flatpak:module-cleanup", "*.la")
                && has_property(
                    component,
                    "flatpak:module-post-install",
                    "install -Dm644 COPYING /app/share/licenses/zlib/COPYING",
                )
                && has_property(
                    component,
                    "flatpak:module-extra:custom-module-key",
                    "module-extra",
                )
                && component
                    .licenses
                    .iter()
                    .any(|license| license.expression == "Zlib")
        }));
        assert!(bom.components.iter().any(|component| {
            component.name == "zlib-helper"
                && component.bom_ref
                    == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=/modules/0/modules/0"
                && has_property(component, "flatpak:manifest-module", "zlib-helper")
                && has_property(
                    component,
                    "flatpak:manifest-module-path",
                    "zlib/zlib-helper",
                )
        }));
        assert!(bom.components.iter().any(|component| {
            component.name == "helper.patch"
                && component.bom_ref
                    == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=/modules/0/modules/0:source=0"
        }));
        assert!(bom.dependencies.iter().any(|dependency| {
            dependency.bom_ref == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=/modules/0"
                && dependency.depends_on.iter().any(|dependency_ref| {
                    dependency_ref
                        == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=/modules/0/modules/0"
                })
        }));
        assert!(bom.components.iter().any(|component| {
            component.name == "openssl.tar.gz"
                && component
                    .hashes
                    .iter()
                    .any(|hash| hash.alg == "SHA-256" && hash.content == "def")
                && component
                    .hashes
                    .iter()
                    .any(|hash| hash.alg == "SHA-512" && hash.content == "abc")
                && component
                    .hashes
                    .iter()
                    .any(|hash| hash.alg == "SHA-1" && hash.content == "123")
                && component
                    .hashes
                    .iter()
                    .any(|hash| hash.alg == "MD5" && hash.content == "456")
                && has_property(component, "flatpak:source-dest", "openssl-src")
                && has_property(component, "flatpak:source-strip-components", "1")
                && has_property(component, "flatpak:source-git-submodules", "true")
                && has_property(component, "flatpak:source-disable-shallow-clone", "true")
                && has_property(
                    component,
                    "flatpak:source-urls",
                    "https://mirror1.example.test/openssl.tar.gz",
                )
                && has_property(
                    component,
                    "flatpak:source-mirror-urls",
                    "https://mirror2.example.test/openssl.tar.gz",
                )
                && has_property(
                    component,
                    "flatpak:source-extra:x-checker-data",
                    "checker-extra",
                )
                && component
                    .external_references
                    .iter()
                    .any(|reference| reference.url == "https://mirror1.example.test/openssl.tar.gz")
                && component
                    .external_references
                    .iter()
                    .any(|reference| reference.url == "https://mirror2.example.test/openssl.tar.gz")
        }));

        let json = serde_json::to_value(&bom).unwrap();
        let refs = bom
            .components
            .iter()
            .map(|component| &component.bom_ref)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(refs.len(), bom.components.len());
        for dependency in &bom.dependencies {
            for target in &dependency.depends_on {
                assert!(refs.contains(target), "missing dependency target {target}");
            }
        }
        for component in json["components"].as_array().unwrap() {
            if let Some(identity) = component.pointer("/evidence/identity") {
                assert!(identity.get("confidence").is_none());
                assert!(identity.get("methods").is_none());
                assert!(identity["concludedValue"].is_string());
            }
        }
        assert_eq!(json["metadata"]["lifecycles"][0]["phase"], "build");
        assert!(json["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component.get("evidence").is_some()));
        assert_eq!(json["compositions"][0]["aggregate"], "incomplete");
        assert!(json["metadata"]["component"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| property["name"] == "flatpak:composition-reason"));
        assert!(json["dependencies"][0].get("dependsOn").is_some());
        assert!(json["dependencies"][0].get("depends_on").is_none());
        assert_eq!(
            json["dependencies"][0]["dependsOn"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn manifest_fallback_and_structural_references_survive_colliding_names() {
        let app_ref = "app/org.example.App/x86_64/stable";
        let runtime_ref = "runtime/org.example.Platform/x86_64/1";
        let manifest = serde_json::json!({
            "runtime": "org.example.Platform", "runtime-version": "1",
            "modules": [
                {"name": "a_b"}, {"name": "a b"}, {"name": "a/b"},
                {"name": "a", "modules": [{"name": "b"}, {"name": "b"}]},
                {"name": "a_b"}, {}, {},
                {"name": "skipped", "only-arches": ["aarch64"]},
                {"name": "last", "sources": [
                    {"type": "file", "path": "skipped", "only-arches": ["aarch64"]},
                    {"type": "file", "path": "same"}, {"type": "file", "path": "same"}
                ]}
            ]
        });
        let reader = FixtureReader {
            files: BTreeMap::from([
                (
                    (app_ref.into(), "metadata".into()),
                    b"[Application]\n".to_vec(),
                ),
                (
                    (app_ref.into(), "files/manifest.json".into()),
                    serde_json::to_vec(&manifest).unwrap(),
                ),
                (
                    (runtime_ref.into(), "metadata".into()),
                    b"[Runtime]\n".to_vec(),
                ),
                (
                    (runtime_ref.into(), "files/manifest.json".into()),
                    br#"{"modules":[]}"#.to_vec(),
                ),
            ]),
            commits: BTreeMap::from([
                (app_ref.into(), "appcommit".into()),
                (runtime_ref.into(), "runtimecommit".into()),
            ]),
        };
        let bom = generate_for_app(&reader, "https://repo.test", app_ref).unwrap();
        let refs = bom
            .components
            .iter()
            .map(|c| c.bom_ref.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(refs.len(), bom.components.len());
        assert_eq!(bom.components.len(), 14); // Two artifacts, ten modules, two sources.
        for dependency in &bom.dependencies {
            for target in &dependency.depends_on {
                assert!(refs.contains(target.as_str()));
            }
        }
        let prefix = format!("flatpak:{app_ref}@appcommit#module=");
        let parent = bom
            .dependencies
            .iter()
            .find(|d| d.bom_ref == format!("{prefix}/modules/3"))
            .unwrap();
        assert_eq!(
            parent.depends_on,
            [
                format!("{prefix}/modules/3/modules/0"),
                format!("{prefix}/modules/3/modules/1")
            ]
        );
        assert!(refs.contains(format!("{prefix}/modules/8:source=1").as_str()));
        assert!(refs.contains(format!("{prefix}/modules/8:source=2").as_str()));
        assert!(!refs.contains(format!("{prefix}/modules/7").as_str()));
        for module in &bom.components {
            if let Some(pointer) = module
                .properties
                .iter()
                .find(|p| p.name == "flatpak:manifest-module-pointer")
            {
                let original = manifest.pointer(&pointer.value).unwrap();
                assert_eq!(
                    module.name,
                    original["name"].as_str().unwrap_or("unnamed-module")
                );
            }
        }
        let repeated = generate_for_app(&reader, "https://repo.test", app_ref).unwrap();
        assert_eq!(
            refs,
            repeated
                .components
                .iter()
                .map(|c| c.bom_ref.as_str())
                .collect()
        );
    }

    #[test]
    fn omits_sources_for_other_arches() {
        let app_ref = "app/org.example.App/aarch64/stable";
        let runtime_ref = "runtime/org.gnome.Platform/aarch64/46";
        let reader = FixtureReader {
            files: BTreeMap::from([
                ((app_ref.to_string(), "metadata".to_string()), b"[Application]\nruntime=org.gnome.Platform/aarch64/46\n".to_vec()),
                ((app_ref.to_string(), "files/manifest.json".to_string()), br#"{"modules":[{"name":"app","sources":[{"type":"archive","url":"https://example.test/aarch64.tar.gz"},{"type":"archive","url":"https://example.test/x86_64.tar.gz","only-arches":["x86_64"]}]}]}"#.to_vec()),
                ((runtime_ref.to_string(), "metadata".to_string()), b"[Runtime]\n".to_vec()),
                ((runtime_ref.to_string(), "files/manifest.json".to_string()), br#"{"modules":[]}"#.to_vec()),
            ]),
            commits: BTreeMap::from([(app_ref.to_string(), "appcommit".to_string()), (runtime_ref.to_string(), "runtimecommit".to_string())]),
        };

        let bom = generate_for_app(&reader, "https://example.test/repo", app_ref).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.name == "aarch64.tar.gz"));
        assert!(!bom
            .components
            .iter()
            .any(|component| component.name == "x86_64.tar.gz"));
    }
}
