use crate::cyclonedx::{
    property, Bom, Component, Composition, Dependency, ExternalReference, Metadata,
};
use crate::manifest::{FlatpakManifest, Source};
use crate::metadata::FlatpakMetadata;
use crate::ostree::OstreeFileReader;
use crate::refname::FlatpakRef;
use anyhow::{anyhow, Context, Result};

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
        property("flatpak:ref", app_ref.as_str()),
        property("flatpak:commit", app_commit.clone()),
        property("flatpak:inventory-kind", "manifest-derived"),
    ];
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
        external_references: vec![],
        properties: root_properties,
    };

    let mut components = vec![artifact_component(
        "app",
        &app_ref,
        &app_commit,
        "files/manifest.json",
    )];
    components.push(artifact_component(
        "runtime",
        &runtime_ref,
        &runtime_commit,
        &runtime_manifest_path,
    ));
    components.extend(manifest_components(
        "app",
        &app_ref,
        &app_commit,
        "files/manifest.json",
        &app_manifest,
    ));
    components.extend(manifest_components(
        "runtime",
        &runtime_ref,
        &runtime_commit,
        &runtime_manifest_path,
        &runtime_manifest,
    ));

    let assemblies = components
        .iter()
        .map(|component| component.bom_ref.clone())
        .collect::<Vec<_>>();
    let mut dependencies = vec![Dependency {
        bom_ref: root_ref.clone(),
        depends_on: assemblies.clone(),
    }];
    dependencies.extend(components.iter().map(|component| Dependency {
        bom_ref: component.bom_ref.clone(),
        depends_on: vec![],
    }));

    Ok(Bom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.7".to_string(),
        version: 1,
        metadata: Metadata { component: root },
        components,
        dependencies,
        compositions: vec![Composition {
            aggregate: "incomplete".to_string(),
            assemblies,
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

fn artifact_component(
    scope: &str,
    flatpak_ref: &FlatpakRef,
    commit: &str,
    manifest_path: &str,
) -> Component {
    Component {
        component_type: if scope == "app" {
            "application"
        } else {
            "framework"
        }
        .to_string(),
        name: flatpak_ref.id.clone(),
        bom_ref: format!("flatpak:{}@{}", flatpak_ref.as_str(), commit),
        version: Some(flatpak_ref.branch.clone()),
        purl: Some(format!(
            "pkg:flatpak/{}?arch={}&branch={}",
            flatpak_ref.id, flatpak_ref.arch, flatpak_ref.branch
        )),
        external_references: vec![],
        properties: base_properties(scope, flatpak_ref, commit, manifest_path),
    }
}

fn manifest_components(
    scope: &str,
    flatpak_ref: &FlatpakRef,
    commit: &str,
    manifest_path: &str,
    manifest: &FlatpakManifest,
) -> Vec<Component> {
    let mut components = Vec::new();
    for module in &manifest.modules {
        if !module.applies_to_arch(&flatpak_ref.arch) {
            continue;
        }

        let module_name = module.name();
        components.push(Component {
            component_type: "library".to_string(),
            name: module_name.to_string(),
            bom_ref: format!(
                "flatpak:{}@{}#module={}",
                flatpak_ref.as_str(),
                commit,
                escape_ref(module_name)
            ),
            version: None,
            purl: None,
            external_references: vec![],
            properties: with_module(
                base_properties(scope, flatpak_ref, commit, manifest_path),
                module_name,
            ),
        });

        for (index, source) in module
            .sources()
            .iter()
            .enumerate()
            .filter(|(_, source)| source.applies_to_arch(&flatpak_ref.arch))
        {
            components.push(source_component(
                scope,
                flatpak_ref,
                commit,
                manifest_path,
                module_name,
                index,
                source,
            ));
        }
    }
    components
}

fn source_component(
    scope: &str,
    flatpak_ref: &FlatpakRef,
    commit: &str,
    manifest_path: &str,
    module_name: &str,
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
    let mut properties = with_module(
        base_properties(scope, flatpak_ref, commit, manifest_path),
        module_name,
    );
    properties.push(property("flatpak:source-type", source_type));
    push_optional(
        &mut properties,
        "flatpak:source-sha256",
        source.sha256.as_deref(),
    );
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
        "flatpak:source-path",
        source.path.as_deref(),
    );
    if let Some(size) = source.size {
        properties.push(property("flatpak:source-size", size.to_string()));
    }
    if let Some(arches) = &source.only_arches {
        properties.push(property("flatpak:only-arches", arches.join(",")));
    }
    if let Some(arches) = &source.skip_arches {
        properties.push(property("flatpak:skip-arches", arches.join(",")));
    }

    let purl = infer_purl(source);

    Component {
        component_type: if purl.is_some() { "library" } else { "file" }.to_string(),
        name: name.to_string(),
        bom_ref: format!(
            "flatpak:{}@{}#module={}:source={}",
            flatpak_ref.as_str(),
            commit,
            escape_ref(module_name),
            index
        ),
        version: source
            .tag
            .clone()
            .or_else(|| source.commit.clone())
            .or_else(|| source.branch.clone()),
        purl,
        external_references: source
            .url
            .as_ref()
            .map(|url| ExternalReference {
                reference_type: "distribution".to_string(),
                url: url.clone(),
            })
            .into_iter()
            .collect(),
        properties,
    }
}

fn base_properties(
    scope: &str,
    flatpak_ref: &FlatpakRef,
    commit: &str,
    manifest_path: &str,
) -> Vec<crate::cyclonedx::Property> {
    vec![
        property("flatpak:scope", scope),
        property("flatpak:ref", flatpak_ref.as_str()),
        property("flatpak:commit", commit),
        property("flatpak:manifest-path", manifest_path),
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
                ((app_ref.to_string(), "metadata".to_string()), b"[Application]\nruntime=org.gnome.Platform/x86_64/46\n".to_vec()),
                ((app_ref.to_string(), "files/manifest.json".to_string()), br#"{"modules":[{"name":"zlib","sources":[{"type":"git","url":"https://github.com/madler/zlib.git","tag":"v1.3.1"}]}]}"#.to_vec()),
                ((runtime_ref.to_string(), "metadata".to_string()), b"[Runtime]\n".to_vec()),
                ((runtime_ref.to_string(), "files/manifest.json".to_string()), br#"{"modules":[{"name":"openssl","sources":[{"type":"archive","url":"https://example.test/openssl.tar.gz","sha256":"def"}]}]}"#.to_vec()),
            ]),
            commits: BTreeMap::from([(app_ref.to_string(), "appcommit".to_string()), (runtime_ref.to_string(), "runtimecommit".to_string())]),
        };

        let bom = generate_for_app(&reader, "https://example.test/repo", app_ref).unwrap();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.7");
        assert!(bom
            .components
            .iter()
            .any(|component| component.name == "openssl"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.purl.as_deref() == Some("pkg:github/madler/zlib@v1.3.1")));
        assert!(bom.components.iter().any(|component| {
            component.purl.as_deref() == Some("pkg:github/madler/zlib@v1.3.1")
                && component.component_type == "library"
        }));

        let json = serde_json::to_value(&bom).unwrap();
        assert!(json["dependencies"][0].get("dependsOn").is_some());
        assert!(json["dependencies"][0].get("depends_on").is_none());
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
