use anyhow::{bail, Result};
use packageurl::PackageUrl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatpakRef {
    kind: String,
    id: String,
    arch: String,
    branch: String,
}

impl FlatpakRef {
    pub fn parse(input: &str) -> Result<Self> {
        let parts = input.split('/').collect::<Vec<_>>();
        if parts.len() != 4 || parts.iter().any(|part| part.is_empty()) {
            bail!("invalid Flatpak ref '{input}', expected kind/id/arch/branch");
        }
        if !matches!(parts[0], "app" | "runtime") {
            bail!("invalid Flatpak ref kind '{}'", parts[0]);
        }
        // Match Flatpak's name, architecture and branch grammar without limiting
        // architectures or branches to the ones this tool currently knows about.
        let segments = parts[1].split('.').collect::<Vec<_>>();
        if parts[1].len() > 255
            || segments.len() < 3
            || segments.iter().enumerate().any(|(index, segment)| {
                let initial = |ch: u8| {
                    ch.is_ascii_alphabetic()
                        || ch == b'_'
                        || (index == segments.len() - 1 && ch == b'-')
                };
                !segment.bytes().next().is_some_and(initial)
                    || !segment.bytes().all(|ch| initial(ch) || ch.is_ascii_digit())
            })
        {
            bail!("invalid Flatpak ID '{}'", parts[1]);
        }
        if !parts[2]
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        {
            bail!("invalid Flatpak architecture '{}'", parts[2]);
        }
        if parts[3].starts_with('.')
            || !parts[3]
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.'))
        {
            bail!("invalid Flatpak branch '{}'", parts[3]);
        }
        Ok(Self {
            kind: parts[0].to_string(),
            id: parts[1].to_string(),
            arch: parts[2].to_string(),
            branch: parts[3].to_string(),
        })
    }

    /// Published metadata takes precedence. A manifest fallback needs both its
    /// runtime ID and runtime-version; it uses the app's architecture.
    pub fn runtime(
        metadata: Option<&str>,
        manifest_id: Option<&str>,
        manifest_version: Option<&str>,
        arch: &str,
    ) -> Result<Self> {
        if let Some(value) = metadata {
            return Self::runtime_from_metadata(value, arch);
        }
        let (Some(id), Some(version)) = (manifest_id, manifest_version) else {
            bail!("runtime metadata is absent; manifest must declare runtime and runtime-version");
        };
        Self::parse(&format!("runtime/{id}/{arch}/{version}"))
    }

    fn runtime_from_metadata(value: &str, fallback_arch: &str) -> Result<Self> {
        if value.starts_with("runtime/") {
            return Self::parse(value);
        }

        let parts = value.split('/').collect::<Vec<_>>();
        match parts.as_slice() {
            [id, arch, branch] => Self::parse(&format!("runtime/{id}/{arch}/{branch}")),
            [id, branch] => Self::parse(&format!("runtime/{id}/{fallback_arch}/{branch}")),
            _ => bail!("invalid runtime metadata value '{value}'"),
        }
    }

    pub fn as_str(&self) -> String {
        format!("{}/{}/{}/{}", self.kind, self.id, self.arch, self.branch)
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn arch(&self) -> &str {
        &self.arch
    }
    pub fn branch(&self) -> &str {
        &self.branch
    }

    pub fn purl(&self) -> String {
        let mut purl = PackageUrl::new("flatpak", self.id()).expect("validated Flatpak ID");
        purl.add_qualifier("arch", self.arch())
            .expect("valid qualifier");
        purl.add_qualifier("branch", self.branch())
            .expect("valid qualifier");
        purl.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flatpak_ref() {
        let parsed = FlatpakRef::parse("app/org.example.App/x86_64/stable").unwrap();
        assert_eq!(parsed.id(), "org.example.App");
        assert_eq!(parsed.as_str(), "app/org.example.App/x86_64/stable");
    }

    #[test]
    fn parses_runtime_metadata_ref() {
        let parsed =
            FlatpakRef::runtime(Some("org.gnome.Platform/x86_64/46"), None, None, "aarch64")
                .unwrap();
        assert_eq!(parsed.as_str(), "runtime/org.gnome.Platform/x86_64/46");
    }

    #[test]
    fn validates_all_ref_construction_paths() {
        for value in [
            "app/org.example.App/x86_64/stable/extra",
            "unknown/org.example.App/x86_64/stable",
            "app/org.example/x86_64/stable",
            "app/org..App/x86_64/stable",
            "app/org.1example.App/x86_64/stable",
            "app/org.ex-ample.App/x86_64/stable",
            "app/org.example.App/x86-64/stable",
            "app/org.example.App//stable",
            "app/org.example.App/x86_64/.hidden",
            "app/org.example.App/x86_64/stable?other=value",
            "app/org.example.App/x86_64/",
        ] {
            assert!(FlatpakRef::parse(value).is_err(), "accepted {value}");
        }
        assert!(FlatpakRef::parse(&format!(
            "app/org.example.{}/x86_64/stable",
            "a".repeat(255)
        ))
        .is_err());
        for value in [
            "org.example.Platform//46",
            "org.example.Platform/x86_64/",
            "app/org.example.Platform/x86_64/46",
        ] {
            assert!(FlatpakRef::runtime(
                Some(value),
                Some("org.example.Platform"),
                Some("46"),
                "x86_64"
            )
            .is_err());
        }
    }

    #[test]
    fn constructs_canonical_purls_without_restricting_architectures() {
        let reference = FlatpakRef::parse("app/org.example.App-beta/riscv64/1.2-beta").unwrap();
        assert_eq!(
            reference.purl(),
            "pkg:flatpak/org.example.App-beta?arch=riscv64&branch=1.2-beta"
        );
    }

    #[test]
    fn runtime_uses_metadata_first_and_manifest_version_as_fallback() {
        for metadata in [
            "org.gnome.Platform/x86_64/46",
            "runtime/org.gnome.Platform/x86_64/46",
        ] {
            let runtime = FlatpakRef::runtime(
                Some(metadata),
                Some("org.example.Platform"),
                Some("1"),
                "aarch64",
            )
            .unwrap();
            assert_eq!(runtime.as_str(), "runtime/org.gnome.Platform/x86_64/46");
        }
        let runtime =
            FlatpakRef::runtime(None, Some("org.example.Platform"), Some("1"), "aarch64").unwrap();
        assert_eq!(runtime.as_str(), "runtime/org.example.Platform/aarch64/1");
        let short =
            FlatpakRef::runtime(Some("org.example.Platform/1"), None, None, "aarch64").unwrap();
        assert_eq!(short, runtime);
        assert!(FlatpakRef::runtime(None, Some("org.example.Platform"), None, "aarch64").is_err());
        assert!(FlatpakRef::runtime(None, None, Some("1"), "aarch64").is_err());
        assert!(
            FlatpakRef::runtime(None, Some("org.example.Platform"), Some(""), "aarch64").is_err()
        );
    }
}
