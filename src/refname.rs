use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatpakRef {
    pub kind: String,
    pub id: String,
    pub arch: String,
    pub branch: String,
}

impl FlatpakRef {
    pub fn parse(input: &str) -> Result<Self> {
        let parts = input.split('/').collect::<Vec<_>>();
        if parts.len() != 4 || parts.iter().any(|part| part.is_empty()) {
            bail!("invalid Flatpak ref '{input}', expected kind/id/arch/branch");
        }
        Ok(Self {
            kind: parts[0].to_string(),
            id: parts[1].to_string(),
            arch: parts[2].to_string(),
            branch: parts[3].to_string(),
        })
    }

    pub fn runtime_from_metadata(value: &str, fallback_arch: &str) -> Result<Self> {
        if value.starts_with("runtime/") {
            return Self::parse(value);
        }

        let parts = value.split('/').collect::<Vec<_>>();
        match parts.as_slice() {
            [id, arch, branch] => Ok(Self {
                kind: "runtime".to_string(),
                id: (*id).to_string(),
                arch: (*arch).to_string(),
                branch: (*branch).to_string(),
            }),
            [id, branch] => Ok(Self {
                kind: "runtime".to_string(),
                id: (*id).to_string(),
                arch: fallback_arch.to_string(),
                branch: (*branch).to_string(),
            }),
            _ => bail!("invalid runtime metadata value '{value}'"),
        }
    }

    pub fn as_str(&self) -> String {
        format!("{}/{}/{}/{}", self.kind, self.id, self.arch, self.branch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flatpak_ref() {
        let parsed = FlatpakRef::parse("app/org.example.App/x86_64/stable").unwrap();
        assert_eq!(parsed.id, "org.example.App");
        assert_eq!(parsed.as_str(), "app/org.example.App/x86_64/stable");
    }

    #[test]
    fn parses_runtime_metadata_ref() {
        let parsed =
            FlatpakRef::runtime_from_metadata("org.gnome.Platform/x86_64/46", "aarch64").unwrap();
        assert_eq!(parsed.as_str(), "runtime/org.gnome.Platform/x86_64/46");
    }
}
