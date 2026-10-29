//! Catalog deployed files without running application code or extra-data scripts.
use crate::cyclonedx::{property, Bom, Component, Dependency};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
};

pub struct ContentTree {
    pub path: PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

impl ContentTree {
    pub fn installed(path: PathBuf) -> Self {
        Self {
            path,
            _temporary: None,
        }
    }
    pub fn checkout(directory: tempfile::TempDir) -> Self {
        Self {
            path: directory.path().join("files"),
            _temporary: Some(directory),
        }
    }
}

pub trait ContentSource {
    fn content_tree(&self, repo: &str, reference: &str, commit: &str) -> Result<ContentTree>;
    fn content_origin(&self) -> &'static str;
}

pub fn enrich(bom: &mut Bom, reader: &impl ContentSource, acquire_extra_data: bool) -> Result<()> {
    bom.metadata.lifecycles.push(crate::cyclonedx::Lifecycle {
        phase: "operations".into(),
    });
    let artifacts: Vec<_> = bom
        .components
        .iter()
        .filter(|c| {
            !c.bom_ref.contains('#') && c.properties.iter().any(|p| p.name == "flatpak:ref")
        })
        .cloned()
        .collect();
    for artifact in artifacts {
        let value = |name: &str| {
            artifact
                .properties
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.value.as_str())
        };
        let reference = value("flatpak:ref").context("missing artifact ref")?;
        let scope = value("flatpak:scope").context("missing artifact scope")?;
        let commit = value("flatpak:commit").context("missing artifact commit")?;
        let repo = value("flatpak:repo-url").context("missing artifact repository")?;
        let tree = reader.content_tree(repo, reference, commit)?;
        let mut trees = vec![(tree, None)];
        if acquire_extra_data {
            for payload in crate::extra_data::acquire(&artifact, &bom.components)? {
                trees.push((payload.tree, Some(payload.evidence)));
            }
        }
        for (acquisition_index, (tree, payload)) in trees.into_iter().enumerate() {
            let files = &tree.path;
            let output = Command::new("syft")
                .args([
                    "scan",
                    &format!("dir:{}", files.display()),
                    "--base-path",
                    files.to_str().context("non-UTF8 deployment path")?,
                    "--override-default-catalogers",
                    if payload.is_some() {
                        "image,deb-archive-cataloger"
                    } else {
                        "image"
                    },
                    "--source-name",
                    reference,
                    "--source-version",
                    commit,
                    "-o",
                    "syft-json",
                ])
                .output()
                .context("run Syft content scanner")?;
            if !output.status.success() {
                bail!("Syft failed: {}", String::from_utf8_lossy(&output.stderr));
            }
            let document: Value =
                serde_json::from_slice(&output.stdout).context("parse Syft output")?;
            let mut packages = document["artifacts"]
                .as_array()
                .context("Syft output has no artifacts array")?
                .clone();
            let mut installed_files = Vec::new();
            collect_files(files, &mut installed_files)?;
            installed_files.sort();
            for package in &mut packages {
                if unconfirmed_ffmpeg_identity(package, files, &installed_files)? {
                    let original = package.clone();
                    package["identityReview"] = serde_json::json!({
                        "reason": "ffmpeg-library-release-not-corroborated",
                        "original": original,
                    });
                    // ABI evidence is not a release identity. Keep it available for
                    // review without letting downstream scanners match on it.
                    for field in ["version", "purl", "cpes"] {
                        package.as_object_mut().unwrap().remove(field);
                    }
                }
            }
            packages.extend(crate::native::packages(
                files,
                &installed_files,
                reference,
                &bom.components,
            )?);
            for archive in installed_files
                .iter()
                .filter(|path| path.extension().is_some_and(|ext| ext == "asar"))
            {
                packages.extend(asar_packages(
                    archive,
                    archive
                        .strip_prefix(files)?
                        .to_str()
                        .context("non-UTF8 ASAR path")?,
                )?);
            }
            let attributed: BTreeSet<_> = packages
                .iter()
                .filter(|p| p.get("identityReview").is_none())
                .flat_map(|p| p["locations"].as_array().into_iter().flatten())
                .filter_map(|l| l["path"].as_str())
                .map(|p| {
                    p.trim_start_matches('/')
                        .trim_start_matches("./")
                        .to_string()
                })
                .collect();
            let mut elf_files = 0usize;
            let mut unattributed = Vec::new();
            for path in &installed_files {
                let mut magic = [0; 4];
                if File::open(path)?.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF" {
                    elf_files += 1;
                    let relative = path.strip_prefix(files)?.to_string_lossy().into_owned();
                    if !attributed.contains(&relative) {
                        unattributed.push(relative);
                    }
                }
            }
            let observation_key = format!("flatpak:content-observations:{scope}");
            let mut observations: Vec<Value> = bom
                .metadata
                .component
                .properties
                .iter()
                .find(|p| p.name == observation_key)
                .map(|p| serde_json::from_str(&p.value))
                .transpose()?
                .unwrap_or_default();
            observations.push(serde_json::json!({"ref":reference,"commit":commit,
                "origin":if payload.is_some() { "checksum-verified-extra-data" } else { reader.content_origin() },
                "payload_sha256":payload.as_ref().map(|p| &p["sha256"]), "regular_files":installed_files.len(),
                "elf_files":elf_files,"elf_files_with_package_evidence":elf_files-unattributed.len(),
                "unattributed_elf_paths":unattributed,
                "scanner_unknowns": document["files"].as_array().into_iter().flatten()
                    .filter(|f| f["unknowns"].as_array().is_some_and(|u| !u.is_empty()))
                    .map(|f| serde_json::json!({"location":f["location"],"reasons":f["unknowns"]})).collect::<Vec<_>>() }));
            bom.metadata
                .component
                .properties
                .retain(|p| p.name != observation_key);
            bom.metadata.component.properties.push(property(
                observation_key,
                serde_json::to_string(&observations)?,
            ));
            let mut refs = Vec::new();
            let mut seen = BTreeSet::new();
            for (index, package) in packages.iter().enumerate() {
                let name = package["name"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .context("content package missing name")?;
                let version = package["version"]
                    .as_str()
                    .filter(|v| !v.is_empty() && !matches!(*v, "UNKNOWN" | "unknown"));
                let purl = package["purl"].as_str().filter(|v| !v.is_empty());
                // Different locations are retained as evidence even for identical packages.
                let key = (
                    name.to_string(),
                    version.map(str::to_string),
                    purl.map(str::to_string),
                    package["locations"].to_string(),
                    package.get("identityReview").map(Value::to_string),
                );
                if !seen.insert(key) {
                    continue;
                }
                let bom_ref = if let Some(payload) = &payload {
                    format!(
                        "{}#content=extra-{}-{acquisition_index}-{index}",
                        artifact.bom_ref,
                        payload["sha256"].as_str().unwrap()
                    )
                } else {
                    format!("{}#content={index}", artifact.bom_ref)
                };
                let mut properties = vec![
                    property("flatpak:scope", scope),
                    property("flatpak:ref", reference),
                    property("flatpak:commit", commit),
                    property(
                        "flatpak:inventory-kind",
                        if payload.is_some() {
                            "extra-data-content"
                        } else {
                            "content-detected"
                        },
                    ),
                    property(
                        "flatpak:content-origin",
                        if payload.is_some() {
                            "checksum-verified-extra-data"
                        } else {
                            reader.content_origin()
                        },
                    ),
                    property(
                        "flatpak:content-cataloger",
                        package["foundBy"].as_str().unwrap_or("syft"),
                    ),
                    property(
                        "flatpak:content-package-type",
                        package["type"].as_str().unwrap_or("unknown"),
                    ),
                ];
                if let Some(payload) = &payload {
                    properties.push(property(
                        "flatpak:extra-data-sha256",
                        payload["sha256"].as_str().unwrap(),
                    ));
                    properties.push(property(
                        "flatpak:extra-data-url",
                        payload["url"].as_str().unwrap(),
                    ));
                    properties.push(property(
                        "flatpak:extra-data-deployment-equivalence",
                        "not-established",
                    ));
                }
                if let Some(review) = package.get("identityReview") {
                    properties.push(property("flatpak:identity-status", "quarantined"));
                    properties.push(property(
                        "flatpak:identity-review-reason",
                        review["reason"].as_str().unwrap(),
                    ));
                    properties.push(property(
                        "flatpak:scanner-original-artifact",
                        serde_json::to_string(&review["original"])?,
                    ));
                }
                for location in package["locations"].as_array().into_iter().flatten() {
                    if let Some(path) = location["path"].as_str() {
                        properties.push(property("flatpak:content-path", path));
                    }
                }
                if let Some(kind) = package["evidenceKind"].as_str() {
                    properties.push(property("flatpak:content-evidence-kind", kind));
                }
                if let Some(url) = package["upstreamUrl"].as_str() {
                    properties.push(property("flatpak:content-upstream-url", url));
                }
                if let Some(cpes) = package["cpes"].as_array().filter(|cpes| !cpes.is_empty()) {
                    properties.push(property(
                        "flatpak:content-cpe-evidence",
                        serde_json::to_string(cpes)?,
                    ));
                }
                // Preserve binary identifiers used by vulnerability matching. Syft JSON
                // represents CPEs as objects in current releases and strings in older ones.
                let cpe = package["cpes"]
                    .as_array()
                    .and_then(|cpes| cpes.first())
                    .and_then(|v| v.as_str().or_else(|| v["cpe"].as_str()))
                    .map(str::to_string);
                bom.components.push(Component {
                    component_type: "library".into(),
                    name: name.into(),
                    bom_ref: bom_ref.clone(),
                    version: version.map(str::to_string),
                    purl: purl.map(str::to_string),
                    cpe,
                    external_references: vec![],
                    hashes: vec![],
                    licenses: vec![],
                    evidence: None,
                    properties,
                });
                refs.push(bom_ref.clone());
                bom.dependencies.push(Dependency {
                    bom_ref,
                    depends_on: vec![],
                });
            }
            if let Some(dependency) = bom
                .dependencies
                .iter_mut()
                .find(|d| d.bom_ref == artifact.bom_ref)
            {
                dependency.depends_on.extend(refs.iter().cloned());
            }
            if let Some(composition) = bom.compositions.first_mut() {
                composition.assemblies.extend(refs);
            }
            bom.metadata.component.properties.push(property(
                format!("flatpak:content-origin:{scope}"),
                reader.content_origin(),
            ));
            bom.metadata.component.properties.push(property(
                format!("flatpak:content-scan:{scope}"),
                "syft-asar-and-native-metadata",
            ));
            bom.metadata.component.properties.push(property(
                format!("flatpak:content-scanner-version:{scope}"),
                document
                    .pointer("/descriptor/version")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ));
            if let Some(mut payload) = payload {
                payload["ref"] = serde_json::json!(reference);
                payload["commit"] = serde_json::json!(commit);
                let key = format!("flatpak:extra-data-acquisitions:{scope}");
                let mut acquisitions: Vec<Value> = bom
                    .metadata
                    .component
                    .properties
                    .iter()
                    .find(|p| p.name == key)
                    .map(|p| serde_json::from_str(&p.value))
                    .transpose()?
                    .unwrap_or_default();
                for c in &mut bom.components {
                    let get = |name| {
                        c.properties
                            .iter()
                            .find(|p| p.name == name)
                            .map(|p| p.value.as_str())
                    };
                    if get("flatpak:ref") == Some(reference)
                        && get("flatpak:source-type") == Some("extra-data")
                        && get("flatpak:source-url") == payload["url"].as_str()
                        && get("flatpak:source-sha256").is_some_and(|s| {
                            Some(s.to_ascii_lowercase().as_str()) == payload["sha256"].as_str()
                        })
                    {
                        c.properties.push(property(
                            "flatpak:extra-data-acquisition",
                            payload["status"].as_str().unwrap(),
                        ));
                    }
                }
                acquisitions.push(payload);
                bom.metadata.component.properties.retain(|p| p.name != key);
                bom.metadata
                    .component
                    .properties
                    .push(property(key, serde_json::to_string(&acquisitions)?));
            }
        }
    }
    for p in &mut bom.metadata.component.properties {
        if p.name == "flatpak:inventory-kind" {
            p.value = "manifest-and-content".into();
        }
        if p.name == "flatpak:composition-coverage" {
            p.value = if bom.components.iter().any(|c| {
                c.properties
                    .iter()
                    .any(|p| p.name == "flatpak:scope" && p.value == "extension")
            }) {
                "app-runtime-and-selected-extension-content"
            } else {
                "app-and-runtime-manifests-and-content"
            }
            .into();
        }
        if p.name == "flatpak:composition-reason" {
            p.value = if reader.content_origin() == "ostree-checkout" {
                if acquire_extra_data {
                    "Commit-pinned OSTree and checksum-verified extra-data archive inventory; payload inspection does not establish installed contents. Stripped/vendored code and unselected extensions may remain unidentified."
                } else {
                    "Manifest and commit-pinned OSTree content inventory; extra-data payloads are not acquired. Stripped binaries, vendored code, and extension contents may remain unidentified."
                }
            } else {
                "Manifest and installed-content inventory; stripped binaries, vendored code, and extension contents may remain unidentified. Extra-data is observed after installation, not authenticated by the OSTree commit alone."
            }.into();
        }
    }
    Ok(())
}

pub fn is_quarantined(component: &Component) -> bool {
    component
        .properties
        .iter()
        .any(|p| p.name == "flatpak:identity-status" && p.value == "quarantined")
}

// Syft 1.55.0's ffmpeg-library classifier accepts Lavc/Lavf ABI banners
// as FFmpeg release versions. Verify its release claim at each match location;
// never infer a replacement release from ABI numbering or another file.
fn unconfirmed_ffmpeg_identity(package: &Value, root: &Path, files: &[PathBuf]) -> Result<bool> {
    if package["name"] != "ffmpeg" || package["foundBy"] != "binary-classifier-cataloger" {
        return Ok(false);
    }
    let Some(matches) = package
        .pointer("/metadata/matches")
        .and_then(Value::as_array)
        .filter(|m| !m.is_empty())
    else {
        return Ok(true);
    };
    for evidence in matches {
        if evidence["classifier"] == "ffmpeg-binary" {
            continue;
        }
        let Some(version) = package["version"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 256)
        else {
            return Ok(true);
        };
        let Some(location) = evidence.pointer("/location/path").and_then(Value::as_str) else {
            return Ok(true);
        };
        let relative = Path::new(location.trim_start_matches('/'));
        if !relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            return Ok(true);
        }
        let path = root.join(relative);
        // Only use files already collected without following symlinks.
        if files.binary_search(&path).is_err()
            || !contains_release_banner(&path, &format!("FFmpeg version {version}"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn contains_release_banner(path: &Path, banner: &str) -> Result<bool> {
    let needle = banner.as_bytes();
    let mut file = File::open(path).context("open scanner identity evidence")?;
    let mut buffer = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            return Ok(false);
        }
        buffer.extend_from_slice(&chunk[..count]);
        if buffer.windows(needle.len() + 1).any(|window| {
            &window[..needle.len()] == needle
                && matches!(window[needle.len()], 0 | b' ' | b'\n' | b'\r')
        }) {
            return Ok(true);
        }
        let keep = buffer.len().saturating_sub(needle.len());
        buffer.drain(..keep);
    }
}

fn collect_files(root: &Path, paths: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_files(&entry.path(), paths)?;
        } else if kind.is_file() {
            paths.push(entry.path());
        }
    }
    Ok(())
}

fn asar_packages(path: &Path, display_path: &str) -> Result<Vec<Value>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix).context("read ASAR header")?;
    let word = |index| u32::from_le_bytes(prefix[index..index + 4].try_into().unwrap()) as u64;
    let header_size = word(4);
    let json_size = word(12);
    if word(0) != 4
        || header_size < 8
        || json_size > 16 * 1024 * 1024
        || json_size + 8 > header_size
        || header_size + 8 > length
    {
        bail!("invalid or oversized ASAR header in {}", path.display());
    }
    let mut json = vec![0; json_size as usize];
    file.read_exact(&mut json)?;
    let header: Value = serde_json::from_slice(&json).context("parse ASAR header")?;
    let mut entries = Vec::new();
    asar_entries(&header, "", 0, &mut entries)?;
    let mut packages = Vec::new();
    for (name, offset, size) in entries {
        let start = (header_size + 8)
            .checked_add(offset)
            .context("ASAR offset overflow")?;
        if size > 4 * 1024 * 1024 || start.checked_add(size).is_none_or(|end| end > length) {
            bail!("invalid package metadata extent in {}", path.display());
        }
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = vec![0; size as usize];
        file.read_exact(&mut bytes)?;
        // Indexed package metadata is part of the requested inventory. Invalid
        // JSON fails the scan rather than silently omitting a dependency.
        let package: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse {display_path}!/{name}"))?;
        let (Some(package_name), Some(version)) =
            (package["name"].as_str(), package["version"].as_str())
        else {
            continue;
        };
        if package_name.is_empty() || version.is_empty() {
            continue;
        }
        let (namespace, short_name) = if let Some(scoped) = package_name.strip_prefix('@') {
            let (namespace, name) = scoped
                .split_once('/')
                .context("invalid scoped npm package name")?;
            (Some(format!("@{namespace}")), name)
        } else {
            (None, package_name)
        };
        let mut purl = packageurl::PackageUrl::new("npm", short_name)?;
        if let Some(namespace) = namespace {
            purl.with_namespace(namespace)?;
        }
        purl.with_version(version)?;
        packages.push(serde_json::json!({"name":package_name,"version":version,"purl":purl.to_string(),
            "type":"npm","foundBy":"flatpak-asar-package-json", "locations":[{"path":format!("{display_path}!/{name}")}]}));
    }
    Ok(packages)
}

fn asar_entries(
    node: &Value,
    parent: &str,
    depth: usize,
    entries: &mut Vec<(String, u64, u64)>,
) -> Result<()> {
    if depth > 128 {
        bail!("ASAR directory nesting exceeds limit");
    }
    let files = node["files"]
        .as_object()
        .context("ASAR directory missing files")?;
    for (name, value) in files {
        let path = if parent.is_empty() {
            name.clone()
        } else {
            format!("{parent}/{name}")
        };
        if value.get("files").is_some() {
            asar_entries(value, &path, depth + 1, entries)?;
        } else if name == "package.json" && value.get("link").is_none() && value["unpacked"] != true
        {
            let offset = value["offset"]
                .as_str()
                .context("ASAR file missing offset")?
                .parse()?;
            let size = value["size"].as_u64().context("ASAR file missing size")?;
            entries.push((path, offset, size));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn validates_scanner_release_at_its_own_location() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libavcodec.so");
        let files = vec![path.clone()];
        let mut package = serde_json::json!({"name":"ffmpeg", "version":"4.3",
            "foundBy":"binary-classifier-cataloger", "metadata":{"matches":[{
                "classifier":"ffmpeg-library", "location":{"path":"/libavcodec.so"}}]}});
        for banner in [
            "Lavc4.3\0",
            "FFmpeg version 4.30\0",
            "FFmpeg version 4.3.1\0",
            "FFmpeg version 4.3-dev\0",
        ] {
            std::fs::write(&path, banner).unwrap();
            assert!(unconfirmed_ffmpeg_identity(&package, dir.path(), &files).unwrap());
        }
        // A genuine release banner straddling the read boundary still works.
        let mut bytes = vec![0; 65530];
        bytes.extend_from_slice(b"FFmpeg version 4.3\0Lavc58.134.100\0");
        std::fs::write(&path, bytes).unwrap();
        assert!(!unconfirmed_ffmpeg_identity(&package, dir.path(), &files).unwrap());
        for location in ["/missing.so", "../libavcodec.so", "/lib/../libavcodec.so"] {
            package["metadata"]["matches"][0]["location"]["path"] = serde_json::json!(location);
            assert!(unconfirmed_ffmpeg_identity(&package, dir.path(), &files).unwrap());
        }
        package["metadata"] = serde_json::json!({});
        assert!(unconfirmed_ffmpeg_identity(&package, dir.path(), &files).unwrap());
        package["foundBy"] = serde_json::json!("flatpak-native-metadata");
        assert!(!unconfirmed_ffmpeg_identity(&package, dir.path(), &files).unwrap());
    }

    use super::*;

    #[test]
    fn rejects_asar_metadata_extents_outside_archive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad.asar");
        let header = serde_json::to_vec(&serde_json::json!({"files": {
            "package.json": {"size": 1, "offset": u64::MAX.to_string()}
        }}))
        .unwrap();
        let padding = (4 - header.len() % 4) % 4;
        let header_size = header.len() as u32 + padding as u32 + 8;
        let mut bytes = Vec::new();
        for word in [4u32, header_size, header_size - 4, header.len() as u32] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(header);
        bytes.extend(vec![0; padding]);
        std::fs::write(&path, bytes).unwrap();
        let error = asar_packages(&path, "bad.asar").unwrap_err();
        assert!(error.to_string().contains("offset overflow"));
    }

    #[test]
    fn skips_asar_links_and_unpacked_entries() {
        let mut entries = Vec::new();
        asar_entries(
            &serde_json::json!({"files": {
                "package.json": {"link": "../../outside"},
                "node_modules": {"files": {"package.json": {"unpacked": true}}}
            }}),
            "",
            0,
            &mut entries,
        )
        .unwrap();
        assert!(entries.is_empty());
    }
}
