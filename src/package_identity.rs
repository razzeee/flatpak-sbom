//! Conservative package identity inference from recognized source declarations.
//! Unknown hosts and ambiguous paths have no inferred identity.
use crate::manifest::Source;
use packageurl::PackageUrl;
use percent_encoding::percent_decode_str;
use url::Url;

pub fn infer(source: &Source) -> Option<String> {
    let url = Url::parse(source.url.as_deref()?).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return None;
    }
    let parts = url
        .path_segments()?
        .map(|part| {
            percent_decode_str(part)
                .decode_utf8()
                .ok()
                .map(|part| part.into_owned())
        })
        .collect::<Option<Vec<_>>>()?;
    let parts = parts.iter().map(String::as_str).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    match url.host_str()? {
        "github.com" | "codeload.github.com" => github(source, url.host_str()?, &parts),
        "files.pythonhosted.org" => wheel(parts.last()?).or_else(|| {
            let (name, version) = archive_candidate(url.as_str())?;
            purl("pypi", None, &normalize_pypi_name(&name), Some(&version))
        }),
        "static.crates.io" => match parts.as_slice() {
            ["crates", name, filename] => {
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                {
                    return None;
                }
                let version = filename
                    .strip_prefix(&format!("{name}-"))?
                    .strip_suffix(".crate")?;
                semver::Version::parse(version).ok()?;
                purl("cargo", None, name, Some(version))
            }
            _ => None,
        },
        "api.nuget.org" => match parts.as_slice() {
            ["v3-flatcontainer", name, version, filename]
                if *filename == format!("{name}.{version}.nupkg") =>
            {
                purl("nuget", None, name, Some(version))
            }
            _ => None,
        },
        "proxy.golang.org" => {
            let (version_file, prefix) = parts.split_last()?;
            let (marker, module) = prefix.split_last()?;
            if *marker != "@v" || module.is_empty() {
                return None;
            }
            let module = decode_go_module(&module.join("/"))?;
            let (namespace, name) = module
                .rsplit_once('/')
                .map_or((None, module.as_str()), |(ns, name)| (Some(ns), name));
            purl(
                "golang",
                namespace,
                name,
                Some(version_file.strip_suffix(".zip")?),
            )
        }
        _ => None,
    }
}

fn purl(kind: &str, namespace: Option<&str>, name: &str, version: Option<&str>) -> Option<String> {
    if name.is_empty() || name.contains('/') || version.is_some_and(str::is_empty) {
        return None;
    }
    let mut purl = PackageUrl::new(kind, name).ok()?;
    if let Some(namespace) = namespace {
        purl.with_namespace(namespace).ok()?;
    }
    if let Some(version) = version {
        purl.with_version(version).ok()?;
    }
    Some(purl.to_string())
}

fn github(source: &Source, host: &str, parts: &[&str]) -> Option<String> {
    let [owner, repo, rest @ ..] = parts else {
        return None;
    };
    if owner.contains('/') || repo.contains('/') {
        return None;
    }
    if host == "github.com" && rest.is_empty() && source.source_type.as_deref() == Some("git") {
        let version = source
            .tag
            .as_deref()
            .or(source.commit.as_deref())
            .and_then(git_version);
        return purl(
            "github",
            Some(owner),
            repo.strip_suffix(".git").unwrap_or(repo),
            version,
        );
    }
    let version = match (host, rest) {
        ("github.com", ["archive", "refs", "tags", filename]) => strip_archive_extension(filename),
        ("github.com", ["releases", "download", tag, _asset]) => Some(*tag),
        ("codeload.github.com", ["tar.gz" | "zip", "refs", "tags", tag]) => Some(*tag),
        _ => None,
    }?;
    purl("github", Some(owner), repo, Some(version))
}

fn git_version(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() == 40 && value.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    if let Some((tag, commit)) = value.rsplit_once("-0-g") {
        if !tag.is_empty() && !commit.is_empty() && commit.bytes().all(|ch| ch.is_ascii_hexdigit())
        {
            return Some(tag);
        }
    }
    Some(value)
}

fn wheel(filename: &str) -> Option<String> {
    let parts = filename
        .strip_suffix(".whl")?
        .split('-')
        .collect::<Vec<_>>();
    if !(parts.len() == 5 || parts.len() == 6) || parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    purl("pypi", None, &normalize_pypi_name(parts[0]), Some(parts[1]))
}

fn normalize_pypi_name(name: &str) -> String {
    name.split(['_', '.', '-'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .to_ascii_lowercase()
}

fn strip_archive_extension(filename: &str) -> Option<&str> {
    [
        ".tar.gz",
        ".tar.xz",
        ".tar.bz2",
        ".tar.zst",
        ".tar.lz",
        ".tar.lzma",
        ".tgz",
        ".zip",
    ]
    .iter()
    .find_map(|suffix| filename.strip_suffix(suffix))
}

/// Filename evidence is only a candidate, never an invented ecosystem identity.
pub fn archive_candidate(url: &str) -> Option<(String, String)> {
    let filename = url.split(['?', '#']).next()?.rsplit('/').next()?;
    if let Some(stem) = filename.strip_suffix(".deb") {
        let parts: Vec<_> = stem.split('_').collect();
        if let [name, version, arch] = parts.as_slice() {
            if !name.is_empty()
                && !arch.is_empty()
                && version.starts_with(|c: char| c.is_ascii_digit())
                && version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".+:~-".contains(&c))
            {
                return Some((name.to_string(), version.to_string()));
            }
        }
        return None;
    }
    let stem = strip_archive_extension(filename)?;
    for (index, _) in stem.match_indices('-') {
        let name = &stem[..index];
        let version = &stem[index + 1..];
        let numeric = version.split(['-', '_']).next()?;
        if numeric != version
            && !["-rc", "-alpha", "-beta", "-pre"]
                .iter()
                .any(|prefix| version[numeric.len()..].starts_with(prefix))
        {
            continue;
        }
        let parts: Vec<_> = numeric.split('.').collect();
        if !name.is_empty()
            && parts.len() >= 2
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
        {
            return Some((name.to_string(), version.to_string()));
        }
    }
    None
}

fn decode_go_module(module: &str) -> Option<String> {
    let mut decoded = String::with_capacity(module.len());
    let mut chars = module.chars();
    while let Some(ch) = chars.next() {
        if ch == '!' {
            let next = chars.next()?;
            if !next.is_ascii_lowercase() {
                return None;
            }
            decoded.push(next.to_ascii_uppercase());
        } else {
            decoded.push(ch);
        }
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_source_archive_and_semver_identity_rules() {
        let source = Source {
            url: Some(
                "https://files.pythonhosted.org/packages/example/My.Package-1.2.3.tar.gz".into(),
            ),
            ..Default::default()
        };
        assert_eq!(infer(&source).as_deref(), Some("pkg:pypi/my-package@1.2.3"));
        for (name, version) in [
            ("sha-1", "0.10.1"),
            ("foo-2-bar", "1.2.3-rc.1"),
            ("foo", "1.2.3+build.2"),
        ] {
            let source = Source {
                url: Some(format!(
                    "https://static.crates.io/crates/{name}/{name}-{version}.crate?download=1"
                )),
                ..Default::default()
            };
            let value = infer(&source).unwrap();
            let parsed = value.parse::<PackageUrl>().unwrap();
            assert_eq!(parsed.name(), name);
            assert_eq!(parsed.version(), Some(version));
        }
        for path in [
            "sha-1/sha-2-0.10.1.crate",
            "foo/foo-1.crate",
            "foo/foo-01.2.3.crate",
            "foo/foo-1.2.3-rc..1.crate",
            "foo/sub/foo-1.2.3.crate",
        ] {
            let source = Source {
                url: Some(format!("https://static.crates.io/crates/{path}")),
                ..Default::default()
            };
            assert!(infer(&source).is_none());
        }
    }

    #[test]
    fn archive_versions_remain_candidates_not_invented_ecosystems() {
        for (url, expected) in [
            (
                "https://www.lua.org/ftp/lua-5.3.5.tar.gz",
                Some(("lua".into(), "5.3.5".into())),
            ),
            (
                "https://example.org/lib-thing-1.2.3.tar.xz?download=1",
                Some(("lib-thing".into(), "1.2.3".into())),
            ),
            ("https://example.org/snapshot-deadbeef.tar.gz", None),
            ("https://example.org/patch-123.tar.gz", None),
        ] {
            assert_eq!(archive_candidate(url), expected);
            assert!(infer(&Source {
                url: Some(url.into()),
                ..Default::default()
            })
            .is_none());
        }
    }

    #[test]
    fn recognizes_supported_ecosystems_through_one_interface() {
        for (url, expected) in [
            ("https://files.pythonhosted.org/packages/bcrypt-5.0.0-cp39-abi3-manylinux_2_34_x86_64.whl", "pkg:pypi/bcrypt@5.0.0"),
            ("https://files.pythonhosted.org/packages/My__Package-1.2.3-py3-none-any.whl?download=1", "pkg:pypi/my-package@1.2.3"),
            ("https://github.com/owner/project/archive/refs/tags/v1.2.3.tar.gz", "pkg:github/owner/project@v1.2.3"),
            ("https://github.com/owner/project/releases/download/v1.2.3/project-linux.tar.gz", "pkg:github/owner/project@v1.2.3"),
            ("https://codeload.github.com/owner/project/tar.gz/refs/tags/v1.2.3", "pkg:github/owner/project@v1.2.3"),
            ("https://static.crates.io/crates/aho-corasick/aho-corasick-1.1.4.crate", "pkg:cargo/aho-corasick@1.1.4"),
            ("https://api.nuget.org/v3-flatcontainer/avalonia/12.0.4/avalonia.12.0.4.nupkg", "pkg:nuget/avalonia@12.0.4"),
            ("https://proxy.golang.org/github.com/!karpeles!lab/weak/@v/v0.1.1.zip", "pkg:golang/github.com/karpeleslab/weak@v0.1.1"),
        ] {
            let source = Source { url: Some(url.into()), ..Default::default() };
            assert_eq!(infer(&source).as_deref(), Some(expected), "{url}");
        }
    }

    #[test]
    fn normalizes_git_versions_and_encodes_reserved_characters() {
        for (tag, expected) in [
            ("v1.3.1", "pkg:github/madler/zlib@v1.3.1"),
            ("v1.3.1-0-g51b7f2ab", "pkg:github/madler/zlib@v1.3.1"),
            ("release/1#2", "pkg:github/madler/zlib@release/1%232"),
            (
                "0123456789012345678901234567890123456789",
                "pkg:github/madler/zlib",
            ),
        ] {
            let source = Source {
                source_type: Some("git".into()),
                url: Some("https://github.com/madler/zlib.git".into()),
                tag: Some(tag.into()),
                ..Default::default()
            };
            assert_eq!(infer(&source).as_deref(), Some(expected));
        }
        let source = Source {
            url: Some(
                "https://github.com/owner/project/archive/refs/tags/release%2F1%232.tar.gz".into(),
            ),
            ..Default::default()
        };
        assert_eq!(
            infer(&source).as_deref(),
            Some("pkg:github/owner/project@release/1%232")
        );
    }

    #[test]
    fn leaves_ambiguous_or_unrecognized_sources_unidentified() {
        for url in [
            "not a URL",
            "https://example.test/crates/foo-1.0.crate",
            "https://github.com.evil.test/owner/repo/archive/refs/tags/v1.zip",
            "https://github.com@evil.test/owner/repo/archive/refs/tags/v1.zip",
            "https://static.crates.io/crates/foo/bar-1.0.crate",
            "https://api.nuget.org/v3-flatcontainer/foo/1.0/bar.nupkg",
            "https://github.com/owner/repo/archive/refs/tags/v1.zip/extra",
            "https://proxy.golang.org/example.com/foo!/@v/v1.zip",
            "https://files.pythonhosted.org/foo-1.0.whl",
        ] {
            assert!(
                infer(&Source {
                    url: Some(url.into()),
                    ..Default::default()
                })
                .is_none(),
                "{url}"
            );
        }
    }
}
