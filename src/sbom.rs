use crate::cyclonedx::{
    property, Bom, Component, Composition, Dependency, Evidence, EvidenceIdentity,
    EvidenceIdentityMethod, ExternalReference, Hash, LicenseChoice, Lifecycle, Metadata, Tools,
};
use crate::manifest::{FlatpakManifest, Source};
use crate::metadata::FlatpakMetadata;
use crate::ostree::OstreeFileReader;
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
    if app_ref.kind != "app" {
        return Err(anyhow!(
            "generate expects an app ref, got '{}'",
            app_ref.as_str()
        ));
    }

    let app_commit = reader
        .resolve_ref(repo_url, &app_ref.as_str())
        .context("resolve app ref")?;
    let app_metadata =
        read_metadata(reader, repo_url, &app_ref.as_str()).context("read app metadata")?;
    let app_manifest = read_manifest(reader, repo_url, &app_ref.as_str(), "files/manifest.json")
        .context("read app manifest")?;

    let runtime_value = app_metadata
        .runtime()
        .or(app_manifest.runtime.as_deref())
        .ok_or_else(|| anyhow!("app metadata and manifest do not declare a runtime"))?;
    let runtime_ref = FlatpakRef::runtime_from_metadata(runtime_value, &app_ref.arch)?;
    let runtime_commit = reader
        .resolve_ref(repo_url, &runtime_ref.as_str())
        .context("resolve runtime ref")?;
    let runtime_metadata =
        read_metadata(reader, repo_url, &runtime_ref.as_str()).context("read runtime metadata")?;
    let (runtime_manifest, runtime_manifest_path) = read_manifest_from_paths(
        reader,
        repo_url,
        &runtime_ref.as_str(),
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

    let root = Component {
        component_type: "application".to_string(),
        name: app_ref.id.clone(),
        bom_ref: root_ref.clone(),
        version: Some(app_ref.branch.clone()),
        purl: Some(format!(
            "pkg:flatpak/{}?arch={}&branch={}",
            app_ref.id, app_ref.arch, app_ref.branch
        )),
        external_references: vec![ExternalReference {
            reference_type: "distribution".to_string(),
            url: repo_url.to_string(),
        }],
        hashes: vec![],
        licenses: licenses_from_expression(app_manifest.license.as_deref()),
        evidence: Some(component_evidence(
            "purl",
            format!(
                "pkg:flatpak/{}?arch={}&branch={}",
                app_ref.id, app_ref.arch, app_ref.branch
            ),
            "Flatpak ref and manifest identity",
            0.9,
        )),
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
    let app_module_refs = app_manifest_components
        .modules
        .iter()
        .map(|module| module.bom_ref.clone())
        .collect::<Vec<_>>();
    let runtime_module_refs = runtime_manifest_components
        .modules
        .iter()
        .map(|module| module.bom_ref.clone())
        .collect::<Vec<_>>();
    components.extend(app_manifest_components.components.iter().cloned());
    components.extend(runtime_manifest_components.components.iter().cloned());

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
        depends_on: app_module_refs,
    });
    dependencies.push(Dependency {
        bom_ref: runtime_artifact_ref,
        depends_on: runtime_module_refs,
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
                description: Some(
                    "Manifest-derived SBOM generated from Flatpak OSTree metadata and manifests"
                        .to_string(),
                ),
            }],
            tools: Some(Tools {
                components: vec![Component {
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
            properties: vec![
                property(
                    "flatpak:composition-reason",
                    "Manifest-derived metadata does not enumerate package contents inside source archives, vendored trees, or binary extra-data payloads",
                ),
                property("flatpak:composition-coverage", "app-and-runtime-manifests"),
                property("flatpak:composition-runtime-ref", runtime_ref.as_str()),
            ],
        }],
    })
}

fn read_metadata(
    reader: &impl OstreeFileReader,
    repo_url: &str,
    ref_name: &str,
) -> Result<FlatpakMetadata> {
    let bytes = reader
        .read_file_from_ref(repo_url, ref_name, "metadata")?
        .ok_or_else(|| anyhow!("metadata not found for {ref_name}"))?;
    let text = String::from_utf8(bytes).context("metadata is not UTF-8")?;
    FlatpakMetadata::parse(&text)
}

fn read_manifest(
    reader: &impl OstreeFileReader,
    repo_url: &str,
    ref_name: &str,
    path: &str,
) -> Result<FlatpakManifest> {
    let bytes = reader
        .read_file_from_ref(repo_url, ref_name, path)?
        .ok_or_else(|| anyhow!("{path} not found for {ref_name}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {path} for {ref_name}"))
}

fn read_manifest_from_paths(
    reader: &impl OstreeFileReader,
    repo_url: &str,
    ref_name: &str,
    paths: &[&str],
) -> Result<(FlatpakManifest, String)> {
    let mut missing_paths = Vec::new();
    for path in paths {
        match reader.read_file_from_ref(repo_url, ref_name, path)? {
            Some(bytes) => {
                let manifest = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {path} for {ref_name}"))?;
                return Ok((manifest, (*path).to_string()));
            }
            None => missing_paths.push(*path),
        }
    }

    Err(anyhow!(
        "none of {} found for {ref_name}",
        missing_paths.join(", ")
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
    let purl = format!(
        "pkg:flatpak/{}?arch={}&branch={}",
        context.flatpak_ref.id, context.flatpak_ref.arch, context.flatpak_ref.branch
    );

    Component {
        component_type: if context.scope == "app" {
            "application"
        } else {
            "framework"
        }
        .to_string(),
        name: context.flatpak_ref.id.clone(),
        bom_ref: format!(
            "flatpak:{}@{}",
            context.flatpak_ref.as_str(),
            context.commit
        ),
        version: Some(context.flatpak_ref.branch.clone()),
        purl: Some(purl.clone()),
        external_references: vec![ExternalReference {
            reference_type: "distribution".to_string(),
            url: context.repo_url.to_string(),
        }],
        hashes: vec![],
        licenses: licenses_from_expression(license),
        evidence: Some(component_evidence(
            "purl",
            purl,
            "Resolved Flatpak ref",
            1.0,
        )),
        properties,
    }
}

struct ManifestComponents {
    components: Vec<Component>,
    modules: Vec<Component>,
    dependencies: Vec<Dependency>,
}

fn manifest_components(
    context: ComponentContext<'_>,
    manifest: &FlatpakManifest,
) -> ManifestComponents {
    let mut components = Vec::new();
    let mut modules = Vec::new();
    let mut dependencies = Vec::new();
    for module in &manifest.modules {
        if !module.applies_to_arch(&context.flatpak_ref.arch) {
            continue;
        }

        let module_component = collect_module_components(
            context,
            module,
            &[module.name().to_string()],
            &mut components,
            &mut dependencies,
        );
        modules.push(module_component);
    }
    ManifestComponents {
        components,
        modules,
        dependencies,
    }
}

fn collect_module_components(
    context: ComponentContext<'_>,
    module: &crate::manifest::Module,
    module_path: &[String],
    components: &mut Vec<Component>,
    dependencies: &mut Vec<Dependency>,
) -> Component {
    let module_name = module.name();
    let module_path_string = module_path.join("/");
    let mut module_properties = with_module(base_properties(context), module_name);
    module_properties.push(property(
        "flatpak:manifest-module-path",
        &module_path_string,
    ));
    push_optional(
        &mut module_properties,
        "flatpak:module-buildsystem",
        module.buildsystem(),
    );
    push_optional(
        &mut module_properties,
        "flatpak:module-builddir",
        module.builddir(),
    );
    push_optional(
        &mut module_properties,
        "flatpak:module-subdir",
        module.subdir(),
    );
    if let Some(config_opts) = module.config_opts() {
        module_properties.push(property(
            "flatpak:module-config-opts",
            config_opts.join(" "),
        ));
    }
    push_string_list(
        &mut module_properties,
        "flatpak:module-cleanup",
        module.cleanup(),
    );
    push_string_list(
        &mut module_properties,
        "flatpak:module-cleanup-commands",
        module.cleanup_commands(),
    );
    push_string_list(
        &mut module_properties,
        "flatpak:module-post-install",
        module.post_install(),
    );
    if let Some(extra) = module.extra() {
        push_extra_properties(&mut module_properties, "flatpak:module-extra", extra);
    }

    let module_component = Component {
        component_type: "library".to_string(),
        name: module_name.to_string(),
        bom_ref: module_bom_ref(context, &module_path_string),
        version: None,
        purl: None,
        external_references: vec![],
        hashes: vec![],
        licenses: licenses_from_expression(module.license()),
        evidence: Some(component_evidence(
            "name",
            module_name.to_string(),
            "Flatpak manifest module name",
            0.7,
        )),
        properties: module_properties,
    };
    let module_ref = module_component.bom_ref.clone();
    components.push(module_component.clone());

    let mut depends_on = Vec::new();
    for child in module.modules() {
        if !child.applies_to_arch(&context.flatpak_ref.arch) {
            continue;
        }
        let mut child_path = module_path.to_vec();
        child_path.push(child.name().to_string());
        let child_component =
            collect_module_components(context, child, &child_path, components, dependencies);
        depends_on.push(child_component.bom_ref);
    }

    for (index, source) in module
        .sources()
        .iter()
        .enumerate()
        .filter(|(_, source)| source.applies_to_arch(&context.flatpak_ref.arch))
    {
        let source_component =
            source_component(context, module_name, &module_path_string, index, source);
        depends_on.push(source_component.bom_ref.clone());
        dependencies.push(Dependency {
            bom_ref: source_component.bom_ref.clone(),
            depends_on: vec![],
        });
        components.push(source_component);
    }

    dependencies.push(Dependency {
        bom_ref: module_ref,
        depends_on,
    });
    module_component
}

fn source_component(
    context: ComponentContext<'_>,
    module_name: &str,
    module_path: &str,
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

    let purl = infer_purl(source);
    let hashes = source_hashes(source);
    let evidence = source_evidence(source, purl.as_deref(), name);

    Component {
        component_type: if purl.is_some() { "library" } else { "file" }.to_string(),
        name: name.to_string(),
        bom_ref: format!(
            "flatpak:{}@{}#module={}:source={}",
            context.flatpak_ref.as_str(),
            context.commit,
            escape_ref(module_path),
            index
        ),
        version: source
            .tag
            .clone()
            .or_else(|| source.commit.clone())
            .or_else(|| source.branch.clone()),
        purl,
        external_references: source_external_references(source),
        hashes,
        licenses: vec![],
        evidence,
        properties,
    }
}

fn module_bom_ref(context: ComponentContext<'_>, module_path: &str) -> String {
    format!(
        "flatpak:{}@{}#module={}",
        context.flatpak_ref.as_str(),
        context.commit,
        escape_ref(module_path)
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

fn push_metadata_properties(
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
        return Some(component_evidence(
            "purl",
            purl.to_string(),
            "Inferred package URL from Flatpak source declaration",
            0.8,
        ));
    }
    if let Some(sha256) = source.sha256.as_deref() {
        return Some(component_evidence(
            "hash",
            sha256.to_string(),
            "Flatpak manifest SHA-256 source checksum",
            0.9,
        ));
    }
    if let Some(url) = source.url.as_deref() {
        return Some(component_evidence(
            "url",
            url.to_string(),
            "Flatpak manifest source URL",
            0.6,
        ));
    }
    if let Some(path) = source.path.as_deref() {
        return Some(component_evidence(
            "path",
            path.to_string(),
            "Flatpak manifest local source path",
            0.6,
        ));
    }
    Some(component_evidence(
        "name",
        fallback_name.to_string(),
        "Derived from Flatpak source declaration",
        0.4,
    ))
}

fn component_evidence(field: &str, value: String, technique: &str, confidence: f32) -> Evidence {
    Evidence {
        identity: Some(EvidenceIdentity {
            field: field.to_string(),
            confidence,
            methods: vec![EvidenceIdentityMethod {
                technique: technique.to_string(),
                confidence,
                value,
            }],
        }),
    }
}

fn infer_purl(source: &Source) -> Option<String> {
    let url = source.url.as_deref()?;
    if source.source_type.as_deref() == Some("git") && url.starts_with("https://github.com/") {
        let path = url
            .trim_start_matches("https://github.com/")
            .trim_end_matches(".git");
        if path.split('/').count() == 2 {
            if let Some(version) = source
                .tag
                .as_deref()
                .or(source.commit.as_deref())
                .and_then(normalize_git_version)
            {
                return Some(format!("pkg:github/{path}@{version}"));
            }
            return Some(format!("pkg:github/{}", path));
        }
    }

    if url.starts_with("https://github.com/") || url.starts_with("https://codeload.github.com/") {
        if let Some(purl) = infer_github_release_purl(url) {
            return Some(purl);
        }
    }

    if url.starts_with("https://files.pythonhosted.org/") {
        return infer_pypi_wheel_purl(url);
    }

    if url.starts_with("https://static.crates.io/crates/") || url.contains("/crates/") {
        if let Some(purl) = infer_cargo_crate_purl(url) {
            return Some(purl);
        }
    }

    if url.starts_with("https://api.nuget.org/v3-flatcontainer/") {
        return infer_nuget_purl(url);
    }

    if url.starts_with("https://proxy.golang.org/") && url.ends_with(".zip") {
        return infer_go_proxy_purl(url);
    }

    None
}

fn infer_github_release_purl(url: &str) -> Option<String> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("https://codeload.github.com/"))?;
    let parts = path.split('/').collect::<Vec<_>>();
    let [owner, repo, rest @ ..] = parts.as_slice() else {
        return None;
    };
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    let version = match rest {
        ["archive", "refs", "tags", tag_file, ..] => strip_archive_extension(tag_file),
        ["releases", "download", tag, ..] => Some((*tag).to_string()),
        ["tar.gz", "refs", "tags", tag, ..] => Some((*tag).to_string()),
        ["zip", "refs", "tags", tag, ..] => Some((*tag).to_string()),
        _ => None,
    }?;

    if version.is_empty() {
        return None;
    }

    Some(format!("pkg:github/{owner}/{repo}@{version}"))
}

fn normalize_git_version(value: &str) -> Option<String> {
    if value.is_empty() || value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    if let Some((tag, _commit)) = value.split_once("-0-g") {
        if !tag.is_empty() {
            return Some(tag.to_string());
        }
    }

    Some(value.to_string())
}

fn strip_archive_extension(filename: &str) -> Option<String> {
    [".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".zip"]
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))
        .map(str::to_string)
}

fn infer_pypi_wheel_purl(url: &str) -> Option<String> {
    let filename = last_url_segment(url)?.strip_suffix(".whl")?;
    let mut parts = filename.split('-');
    let package = parts.next()?;
    let version = parts.next()?;

    if package.is_empty() || version.is_empty() || parts.count() < 3 {
        return None;
    }

    Some(format!(
        "pkg:pypi/{}@{}",
        package.replace('_', "-").to_ascii_lowercase(),
        version
    ))
}

fn infer_cargo_crate_purl(url: &str) -> Option<String> {
    let filename = last_url_segment(url)?.strip_suffix(".crate")?;
    let (name, version) = filename.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    Some(format!("pkg:cargo/{name}@{version}"))
}

fn infer_nuget_purl(url: &str) -> Option<String> {
    let path = url.trim_start_matches("https://api.nuget.org/v3-flatcontainer/");
    let mut parts = path.split('/');
    let package = parts.next()?;
    let version = parts.next()?;
    let filename = parts.next()?;

    if package.is_empty() || version.is_empty() || !filename.ends_with(".nupkg") {
        return None;
    }

    Some(format!("pkg:nuget/{package}@{version}"))
}

fn infer_go_proxy_purl(url: &str) -> Option<String> {
    let path = url.trim_start_matches("https://proxy.golang.org/");
    let (module, version_file) = path.split_once("/@v/")?;
    let version = version_file.strip_suffix(".zip")?;
    if module.is_empty() || version.is_empty() {
        return None;
    }

    Some(format!(
        "pkg:golang/{}@{}",
        decode_go_proxy_module(module),
        version
    ))
}

fn decode_go_proxy_module(module: &str) -> String {
    let mut decoded = String::with_capacity(module.len());
    let mut chars = module.chars();
    while let Some(ch) = chars.next() {
        if ch == '!' {
            if let Some(next) = chars.next() {
                decoded.push(next.to_ascii_uppercase());
            }
        } else {
            decoded.push(ch);
        }
    }
    decoded
}

fn last_url_segment(url: &str) -> Option<&str> {
    url.rsplit('/').next().filter(|segment| !segment.is_empty())
}

fn escape_ref(value: &str) -> String {
    value.replace([' ', '/'], "_")
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
        fn read_file_from_ref(
            &self,
            _repo_url: &str,
            ref_name: &str,
            path: &str,
        ) -> Result<Option<Vec<u8>>> {
            Ok(self
                .files
                .get(&(ref_name.to_string(), path.to_string()))
                .cloned())
        }

        fn resolve_ref(&self, _repo_url: &str, ref_name: &str) -> Result<String> {
            self.commits
                .get(ref_name)
                .cloned()
                .ok_or_else(|| anyhow!("missing commit"))
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
        assert!(bom.metadata.lifecycles.iter().any(|lifecycle| {
            lifecycle.phase == "build"
                && lifecycle
                    .description
                    .as_deref()
                    .is_some_and(|description| description.contains("Manifest-derived SBOM"))
        }));
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
                    .is_some_and(|identity| identity.confidence == 1.0)
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
                    == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=zlib_zlib-helper"
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
                    == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=zlib_zlib-helper:source=0"
        }));
        assert!(bom.dependencies.iter().any(|dependency| {
            dependency.bom_ref == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=zlib"
                && dependency.depends_on.iter().any(|dependency_ref| {
                    dependency_ref
                        == "flatpak:app/org.example.App/x86_64/stable@appcommit#module=zlib_zlib-helper"
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
        assert_eq!(json["metadata"]["lifecycles"][0]["phase"], "build");
        assert!(json["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component.get("evidence").is_some()));
        assert_eq!(json["compositions"][0]["aggregate"], "incomplete");
        assert!(json["compositions"][0]["properties"]
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

    #[test]
    fn infers_pypi_purl_from_pythonhosted_wheel() {
        let source = Source {
            source_type: Some("file".to_string()),
            url: Some("https://files.pythonhosted.org/packages/d4/8d/5e43d9584b3b3591a6f9b68f755a4da879a59712981ef5ad2a0ac1379f7a/bcrypt-5.0.0-cp39-abi3-manylinux_2_34_x86_64.whl".to_string()),
            ..Default::default()
        };

        assert_eq!(
            infer_purl(&source).as_deref(),
            Some("pkg:pypi/bcrypt@5.0.0")
        );
    }

    #[test]
    fn normalizes_pypi_wheel_package_name() {
        assert_eq!(
            infer_pypi_wheel_purl(
                "https://files.pythonhosted.org/packages/example/My_Package-1.2.3-py3-none-any.whl"
            )
            .as_deref(),
            Some("pkg:pypi/my-package@1.2.3")
        );
    }

    #[test]
    fn infers_github_purl_from_tag_archive() {
        assert_eq!(
            infer_github_release_purl(
                "https://github.com/owner/project/archive/refs/tags/v1.2.3.tar.gz"
            )
            .as_deref(),
            Some("pkg:github/owner/project@v1.2.3")
        );
    }

    #[test]
    fn infers_github_purl_from_release_asset() {
        assert_eq!(
            infer_github_release_purl(
                "https://github.com/owner/project/releases/download/v1.2.3/project-linux.tar.gz"
            )
            .as_deref(),
            Some("pkg:github/owner/project@v1.2.3")
        );
    }

    #[test]
    fn infers_github_purl_from_codeload_archive() {
        assert_eq!(
            infer_github_release_purl(
                "https://codeload.github.com/owner/project/tar.gz/refs/tags/v1.2.3"
            )
            .as_deref(),
            Some("pkg:github/owner/project@v1.2.3")
        );
    }

    #[test]
    fn infers_versioned_github_git_purl_from_tag() {
        let source = Source {
            source_type: Some("git".to_string()),
            url: Some("https://github.com/madler/zlib.git".to_string()),
            tag: Some("v1.3.1".to_string()),
            ..Default::default()
        };

        assert_eq!(
            infer_purl(&source).as_deref(),
            Some("pkg:github/madler/zlib@v1.3.1")
        );
    }

    #[test]
    fn normalizes_exact_git_describe_version() {
        assert_eq!(
            normalize_git_version("v1.3.1-0-g51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf").as_deref(),
            Some("v1.3.1")
        );
    }

    #[test]
    fn infers_cargo_purl_from_crate_archive() {
        assert_eq!(
            infer_cargo_crate_purl(
                "https://static.crates.io/crates/aho-corasick/aho-corasick-1.1.4.crate"
            )
            .as_deref(),
            Some("pkg:cargo/aho-corasick@1.1.4")
        );
    }

    #[test]
    fn infers_nuget_purl_from_flat_container_url() {
        assert_eq!(
            infer_nuget_purl(
                "https://api.nuget.org/v3-flatcontainer/avalonia/12.0.4/avalonia.12.0.4.nupkg"
            )
            .as_deref(),
            Some("pkg:nuget/avalonia@12.0.4")
        );
    }

    #[test]
    fn infers_go_purl_from_proxy_zip_url() {
        assert_eq!(
            infer_go_proxy_purl(
                "https://proxy.golang.org/github.com/!karpeles!lab/weak/@v/v0.1.1.zip"
            )
            .as_deref(),
            Some("pkg:golang/github.com/KarpelesLab/weak@v0.1.1")
        );
    }
}
