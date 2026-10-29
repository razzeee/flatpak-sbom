//! Native identities backed by installed metadata and shipped binary evidence.
use crate::cyclonedx::Component;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

pub fn packages(
    root: &Path,
    files: &[PathBuf],
    reference: &str,
    sources: &[Component],
) -> Result<Vec<Value>> {
    let mut packages = Vec::new();
    let collected_elf = |relative: &str| -> Result<bool> {
        let path = root.join(relative);
        Ok(files.contains(&path) && is_elf(&path)?)
    };
    for path in files.iter().filter(|path| {
        path.extension().is_some_and(|ext| ext == "pc")
            && path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|name| name == "pkgconfig")
    }) {
        // Bound metadata reads and never run pkg-config (which could read host data).
        let mut text = String::new();
        File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)?;
        if text.len() > 1024 * 1024 {
            continue;
        }
        let fields = pkg_config(&text);
        let Some(version) = fields.get("Version").filter(|v| valid_version(v)) else {
            continue;
        };
        let Some(name) = path.file_stem().and_then(|v| v.to_str()) else {
            continue;
        };
        let libraries: Vec<_> = fields
            .get("Libs")
            .into_iter()
            .flat_map(|v| v.split_whitespace())
            .filter_map(|word| word.strip_prefix("-l"))
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .collect();
        let search_paths: Vec<_> = fields
            .get("Libs")
            .into_iter()
            .flat_map(|v| v.split_whitespace())
            .filter_map(|word| word.strip_prefix("-L"))
            .collect();
        let prefix = if reference.starts_with("app/") {
            "/app/"
        } else {
            "/usr/"
        };
        let library_dirs: Vec<_> = if search_paths.is_empty() {
            path.parent()
                .and_then(|p| p.parent())
                .map(Path::to_path_buf)
                .into_iter()
                .collect()
        } else {
            search_paths
                .iter()
                .filter_map(|path| path.strip_prefix(prefix))
                .filter(|path| {
                    Path::new(path)
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
                })
                .map(|path| root.join(path))
                .collect()
        };
        let candidates = files.iter().filter(|file| {
            let filename = file
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            library_dirs
                .iter()
                .any(|dir| file.parent() == Some(dir.as_path()))
                && libraries.iter().any(|library| {
                    filename == format!("lib{library}.a")
                        || filename == format!("lib{library}.so")
                        || filename.starts_with(&format!("lib{library}.so."))
                })
        });
        let mut matching = Vec::new();
        for file in candidates {
            let mut magic = [0; 8];
            let mut library = File::open(file)?;
            if library.read_exact(&mut magic).is_ok()
                && (&magic[..4] == b"\x7fELF" || &magic == b"!<arch>\n")
            {
                matching.push(file);
            }
        }
        if matching.is_empty() {
            continue;
        }
        let mut locations = vec![json!({"path":path.strip_prefix(root)?.to_string_lossy()})];
        locations.extend(
            matching
                .iter()
                .map(|file| json!({"path":file.strip_prefix(root).unwrap().to_string_lossy()})),
        );
        let mut purl = packageurl::PackageUrl::new("generic", name)?;
        purl.with_version(version)?;
        packages.push(json!({"name":name,"version":version,"purl":purl.to_string(),"type":"native-library",
            "foundBy":"flatpak-linked-pkg-config","locations":locations,"evidenceKind":"installed-metadata-and-library",
            "upstreamUrl":fields.get("URL")}));
        // Build headers can supply upstream releases that pkg-config deliberately
        // does not (e.g. libavutil's API version versus the FFmpeg release).
        let build_identity = match name {
            "libavutil" => Some((
                "ffmpeg",
                "ffmpeg:ffmpeg",
                "include/libavutil/ffversion.h",
                "FFMPEG_VERSION",
            )),
            "libssh2" => Some((
                "libssh2",
                "libssh2:libssh2",
                "include/libssh2.h",
                "LIBSSH2_VERSION",
            )),
            _ => None,
        };
        if let Some((package, cpe_product, header, define)) = build_identity {
            let header_path = root.join(header);
            if !files.contains(&header_path) {
                continue;
            }
            if let Some(release) = quoted_define(&header_path, define)? {
                let consistent = package != "libssh2" || release == *version;
                let binary_value = if package == "libssh2" {
                    format!("SSH-2.0-libssh2_{release}")
                } else {
                    release.clone()
                };
                if consistent {
                    for library in &matching {
                        if contains_c_strings(library, &[&binary_value])? {
                            packages.push(json!({"name":package,"version":release,
                                "purl":format!("pkg:generic/{package}@{release}"), "type":"native-library",
                                "foundBy":"flatpak-native-build-version", "evidenceKind":"build-header-corroborated-in-library",
                                "locations":[{"path":header},{"path":library.strip_prefix(root)?.to_string_lossy()},
                                    {"path":path.strip_prefix(root)?.to_string_lossy()}],
                                "cpes":[format!("cpe:2.3:a:{cpe_product}:{release}:*:*:*:*:*:*:*")]}));
                            break;
                        }
                    }
                }
            }
        }
        // libavcodec's Version is an ABI/library version, not FFmpeg's release
        // version. Only explicitly supported app metadata gets an app CPE.
        if reference.starts_with("app/org.videolan.VLC/") && name == "libvlc" {
            let executable = if collected_elf("bin/vlc")? {
                "bin/vlc"
            } else if collected_elf("bin/vlc.bin")? {
                "bin/vlc.bin"
            } else {
                continue;
            };
            packages.push(
                json!({"name":"vlc","version":version,"purl":format!("pkg:generic/vlc@{version}"),
                "type":"native-application","foundBy":"flatpak-vlc-pkg-config",
                "evidenceKind":"installed-metadata-and-executable", "locations":[
                    {"path":path.strip_prefix(root)?.to_string_lossy()},{"path":executable}],
                "cpes":[format!("cpe:2.3:a:videolan:vlc_media_player:{version}:*:*:*:*:*:*:*")]}),
            );
        }
    }
    if reference.starts_with("app/com.google.Chrome/") {
        let binary = root.join("extra/chrome");
        if collected_elf("extra/chrome")? {
            let mut versions = Vec::new();
            for component in sources.iter().filter(|component| {
                component.name == "google-chrome-stable"
                    && component
                        .properties
                        .iter()
                        .any(|p| p.name == "flatpak:ref" && p.value == reference)
            }) {
                if let Some(candidate) = component.version.as_deref() {
                    let version = candidate.split('-').next().unwrap_or_default();
                    let parts: Vec<_> = version.split('.').collect();
                    if parts.len() == 4
                        && parts
                            .iter()
                            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                    {
                        versions.push(version.to_string());
                    }
                }
            }
            versions.sort();
            versions.dedup();
            if versions.len() == 1 && contains_c_strings(&binary, &[&versions[0], "Google Chrome"])?
            {
                let version = &versions[0];
                packages.push(json!({"name":"google-chrome","version":version,
                    "purl":format!("pkg:generic/google-chrome@{version}"),"type":"native-application",
                    "foundBy":"flatpak-chrome-binary-version", "evidenceKind":"manifest-version-corroborated-in-binary",
                    "locations":[{"path":"extra/chrome"},{"path":"manifest.json"}],
                    "cpes":[format!("cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*")]}));
            }
        }
    }
    for path in files.iter().filter(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "libcrypto.so" || name.starts_with("libcrypto.so."))
    }) {
        if !is_elf(path)? {
            continue;
        }
        if let Some(version) = openssl_release(path)? {
            packages.push(json!({"name":"openssl", "version":version,
                "purl":format!("pkg:generic/openssl@{version}"), "type":"native-library",
                "foundBy":"flatpak-openssl-binary-version",
                "evidenceKind":"binary-release-banner-and-version-api-strings",
                "locations":[{"path":path.strip_prefix(root)?.to_string_lossy()}],
                "cpes":[format!("cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*")]}));
        }
    }
    Ok(packages)
}

// Restrict this detector to stable OpenSSL 3 releases. Older letter-suffixed
// releases and forks need their own version/CPE normalization rules.
fn openssl_banner_version(banner: &str) -> Option<&str> {
    let words: Vec<_> = banner.split_ascii_whitespace().collect();
    if words.len() != 5 || words[0] != "OpenSSL" {
        return None;
    }
    let parts: Vec<_> = words[1].split('.').collect();
    if parts.len() != 3
        || parts[0] != "3"
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return None;
    }
    if !words[2]
        .parse::<u8>()
        .is_ok_and(|day| (1..=31).contains(&day))
        || ![
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        .contains(&words[3])
        || words[4].len() != 4
        || !words[4].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some(words[1])
}

fn openssl_release(path: &Path) -> Result<Option<String>> {
    let mut release = None;
    let mut api = [false; 2];
    let mut ambiguous = false;
    visit_c_strings(path, 256, |bytes| {
        api[0] |= bytes == b"OpenSSL_version";
        api[1] |= bytes == b"OpenSSL_version_num";
        if let Ok(text) = std::str::from_utf8(bytes) {
            if text.starts_with("LibreSSL ") || text.starts_with("BoringSSL") {
                ambiguous = true;
            }
            if text
                .strip_prefix("OpenSSL ")
                .is_some_and(|s| s.starts_with(|c: char| c.is_ascii_digit()))
            {
                match openssl_banner_version(text) {
                    Some(version) if release.as_deref().is_none_or(|old| old == version) => {
                        release = Some(version.to_string())
                    }
                    _ => ambiguous = true,
                }
            }
        }
        ambiguous
    })?;
    Ok(if !ambiguous && api.iter().all(|found| *found) {
        release
    } else {
        None
    })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-~".contains(&c))
}

fn quoted_define(path: &Path, name: &str) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= 1024 * 1024 => {}
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let text = std::fs::read_to_string(path)?;
    let mut versions = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("#define") || words.next() != Some(name) {
            continue;
        }
        if let Some(version) = words
            .next()
            .and_then(|word| word.strip_prefix('"'))
            .and_then(|word| word.strip_suffix('"'))
        {
            if valid_version(version) {
                versions.insert(version.to_string());
            }
        }
    }
    Ok(if versions.len() == 1 {
        versions.into_iter().next()
    } else {
        None
    })
}

fn pkg_config(text: &str) -> BTreeMap<String, String> {
    let text = text.replace("\\\n", "");
    let mut vars = BTreeMap::new();
    let mut fields = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if let Some((key, value)) = line.split_once(':').filter(|(key, _)| !key.contains('=')) {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        } else if let Some((key, value)) = line.split_once('=') {
            vars.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    for value in fields.values_mut() {
        for _ in 0..16 {
            let Some(start) = value.find("${") else {
                break;
            };
            let Some(end) = value[start..].find('}').map(|end| start + end) else {
                break;
            };
            let Some(replacement) = vars.get(&value[start + 2..end]) else {
                break;
            };
            if replacement.len() + value.len() > 1024 * 1024 {
                break;
            }
            value.replace_range(start..=end, replacement);
        }
    }
    fields
}

fn is_elf(path: &Path) -> Result<bool> {
    // Do not follow links out of the deployment.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let mut bytes = [0; 4];
    Ok(File::open(path)?.read_exact(&mut bytes).is_ok() && bytes == *b"\x7fELF")
}

// Stream large binaries with bounded memory. Require complete NUL-delimited
// strings; a filename substring or a longer version must not corroborate a claim.
fn contains_c_strings(path: &Path, expected: &[&str]) -> Result<bool> {
    let mut found = vec![false; expected.len()];
    let max = expected.iter().map(|value| value.len()).max().unwrap_or(0);
    visit_c_strings(path, max, |bytes| {
        for (i, expected) in expected.iter().enumerate() {
            if bytes == expected.as_bytes() {
                found[i] = true;
            }
        }
        found.iter().all(|found| *found)
    })?;
    Ok(found.iter().all(|found| *found))
}

fn visit_c_strings(path: &Path, max: usize, mut visit: impl FnMut(&[u8]) -> bool) -> Result<()> {
    let mut reader = BufReader::new(File::open(path).context("open native binary")?);
    let mut current = Vec::with_capacity(max);
    let mut overflow = false;
    let mut chunk = [0; 65536];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        for &byte in &chunk[..count] {
            if byte == 0 {
                if !overflow && visit(&current) {
                    return Ok(());
                }
                current.clear();
                overflow = false;
            } else if current.len() < max {
                current.push(byte);
            } else {
                overflow = true;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_binary_requires_unambiguous_stable_release_and_api_strings() {
        let dir = tempfile::tempdir().unwrap();
        let library = dir.path().join("libcrypto.so.3");
        let prefix = b"\x7fELF\x02\x01\x01\x00OpenSSL_version\0OpenSSL_version_num\0";
        for (banners, expected) in [
            ("OpenSSL 3.0.0 7 Sep 2021\0", Some("3.0.0")),
            ("OpenSSL 3.5.9 29 Sep 2026\0", Some("3.5.9")),
            (
                "OpenSSL 3.0.0 7 Sep 2021\0OpenSSL 3.0.0 7 Sep 2021\0",
                Some("3.0.0"),
            ),
            (
                "OpenSSL 3.0.0 7 Sep 2021\0OpenSSL 3.0.1 14 Dec 2021\0",
                None,
            ),
            ("OpenSSL 3.0.0-dev 7 Sep 2021\0", None),
            ("OpenSSL 1.1.1w 11 Sep 2023\0", None),
            ("OpenSSL 3.0.0\0", None),
            ("prefix OpenSSL 3.0.0 7 Sep 2021\0", None),
            ("OpenSSL 3.0.0 7 Sep 2021", None),
            ("OpenSSL 3.0.0 7 Sep 2021\0LibreSSL 3.9.0\0", None),
        ] {
            std::fs::write(&library, [prefix.as_slice(), banners.as_bytes()].concat()).unwrap();
            assert_eq!(
                openssl_release(&library).unwrap().as_deref(),
                expected,
                "{banners:?}"
            );
        }
        std::fs::write(&library, b"\x7fELF\0OpenSSL 3.0.0 7 Sep 2021\0").unwrap();
        assert_eq!(openssl_release(&library).unwrap(), None);
    }

    #[test]
    fn openssl_records_keep_each_library_location_and_version() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (subdir, version) in [("lib", "3.0.0"), ("vendored/lib", "3.0.8")] {
            let parent = dir.path().join(subdir);
            std::fs::create_dir_all(&parent).unwrap();
            let path = parent.join("libcrypto.so.3");
            std::fs::write(
                &path,
                format!(
                    "\x7fELF\0OpenSSL_version\0OpenSSL_version_num\0OpenSSL {version} 7 Sep 2021\0"
                ),
            )
            .unwrap();
            files.push(path);
        }
        let detected = packages(dir.path(), &files, "runtime/example/x86_64/stable", &[]).unwrap();
        assert_eq!(detected.len(), 2);
        assert_eq!(detected[0]["version"], "3.0.0");
        assert_eq!(detected[1]["version"], "3.0.8");
        assert_eq!(
            detected[1]["locations"][0]["path"],
            "vendored/lib/libcrypto.so.3"
        );
        std::fs::write(
            &files[0],
            b"not ELF\0OpenSSL_version\0OpenSSL_version_num\0OpenSSL 3.0.0 7 Sep 2021\0",
        )
        .unwrap();
        assert!(packages(
            dir.path(),
            &files[..1],
            "runtime/example/x86_64/stable",
            &[]
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn ambiguous_build_headers_do_not_supply_release_versions() {
        let dir = tempfile::tempdir().unwrap();
        let header = dir.path().join("version.h");
        std::fs::write(
            &header,
            "#define FFMPEG_VERSION \"4.3\"\n#define FFMPEG_VERSION \"4.4\"\n",
        )
        .unwrap();
        assert_eq!(quoted_define(&header, "FFMPEG_VERSION").unwrap(), None);
        std::fs::write(&header, "#define FFMPEG_VERSION \"4.3\"\n").unwrap();
        assert_eq!(
            quoted_define(&header, "FFMPEG_VERSION").unwrap(),
            Some("4.3".into())
        );
    }

    #[test]
    #[cfg(unix)]
    fn build_headers_outside_the_collected_tree_are_not_evidence() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("lib/pkgconfig")).unwrap();
        std::fs::create_dir_all(outside.path().join("libavutil")).unwrap();
        std::fs::write(
            outside.path().join("libavutil/ffversion.h"),
            "#define FFMPEG_VERSION \"4.3\"\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("include")).unwrap();
        let pc = root.path().join("lib/pkgconfig/libavutil.pc");
        let so = root.path().join("lib/libavutil.so.56");
        std::fs::write(&pc, "Version: 56.51.100\nLibs: -L/app/lib -lavutil\n").unwrap();
        std::fs::write(&so, b"\x7fELF\x02\x01\x01\x00\x004.3\x00").unwrap();
        let detected = packages(root.path(), &[pc, so], "app/example/x86_64/stable", &[]).unwrap();
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0]["name"], "libavutil");
        assert!(detected[0].get("cpes").is_none());
    }
    #[test]
    fn expands_metadata_variables_without_shell_evaluation() {
        let fields = pkg_config("release=3.0.11\nv=${release}\nVersion: ${v}\nLibs: -lvlc\n");
        assert_eq!(fields["Version"], "3.0.11");
        assert!(!valid_version("$(echo 1.2.3)"));
        assert!(!valid_version(
            &pkg_config("v=${v}\nVersion: ${v}")["Version"]
        ));
    }

    #[test]
    fn metadata_without_a_shipped_library_is_not_a_detected_package() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pkgconfig")).unwrap();
        let pc = dir.path().join("pkgconfig/unused.pc");
        std::fs::write(&pc, "Name: unused\nVersion: 1.2.3\nLibs: -lunused\n").unwrap();
        assert!(
            packages(dir.path(), &[pc], "app/example/x86_64/stable", &[])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn version_matching_is_exact_and_handles_chunk_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("binary");
        let mut data = vec![0; 65530];
        data.extend(b"80.0.3987.87\0Google Chrome\0");
        std::fs::write(&binary, &data).unwrap();
        assert!(contains_c_strings(&binary, &["80.0.3987.87", "Google Chrome"]).unwrap());
        assert!(!contains_c_strings(&binary, &["80.0.3987.8", "Google Chrome"]).unwrap());
        assert!(!contains_c_strings(&binary, &["81.0.3987.87", "Google Chrome"]).unwrap());
    }

    #[test]
    fn native_metadata_does_not_borrow_a_runtime_library_or_relabel_abi_versions() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("lib");
        std::fs::create_dir_all(lib.join("pkgconfig")).unwrap();
        let pc = lib.join("pkgconfig/libavcodec.pc");
        let so = lib.join("libavcodec.so.58");
        std::fs::write(&so, b"\x7fELF\x02\x01\x01\x00").unwrap();
        std::fs::write(&pc, "Version: 58.134.100\nLibs: -L/usr/lib -lavcodec\n").unwrap();
        let files = [pc.clone(), so];
        assert!(
            packages(dir.path(), &files, "app/example/x86_64/stable", &[])
                .unwrap()
                .is_empty()
        );
        std::fs::write(&pc, "Version: 58.134.100\nLibs: -L/app/lib -lavcodec\n").unwrap();
        let detected = packages(dir.path(), &files, "app/example/x86_64/stable", &[]).unwrap();
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0]["name"], "libavcodec");
        assert_eq!(detected[0]["version"], "58.134.100");
        assert!(detected[0].get("cpes").is_none());
        std::fs::write(&files[1], "not a library").unwrap();
        assert!(
            packages(dir.path(), &files, "app/example/x86_64/stable", &[])
                .unwrap()
                .is_empty()
        );
    }
}
