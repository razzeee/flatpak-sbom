use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlatpakManifest {
    pub id: Option<String>,
    pub app_id: Option<String>,
    pub license: Option<String>,
    pub command: Option<String>,
    pub runtime: Option<String>,
    pub runtime_version: Option<String>,
    pub sdk: Option<String>,
    pub finish_args: Option<Vec<String>>,
    pub cleanup: Option<Vec<String>>,
    pub cleanup_commands: Option<Vec<String>>,
    #[serde(default)]
    pub modules: Vec<Module>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Module {
    Object(Box<ModuleObject>),
    Name(String),
}

impl Module {
    pub fn name(&self) -> &str {
        match self {
            Self::Object(module) => module.name.as_deref().unwrap_or("unnamed-module"),
            Self::Name(name) => name,
        }
    }

    pub fn sources(&self) -> &[Source] {
        match self {
            Self::Object(module) => &module.sources,
            Self::Name(_) => &[],
        }
    }

    pub fn modules(&self) -> &[Module] {
        match self {
            Self::Object(module) => &module.modules,
            Self::Name(_) => &[],
        }
    }

    pub fn license(&self) -> Option<&str> {
        match self {
            Self::Object(module) => module.license.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn buildsystem(&self) -> Option<&str> {
        match self {
            Self::Object(module) => module.buildsystem.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn builddir(&self) -> Option<&str> {
        match self {
            Self::Object(module) => module.builddir.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn subdir(&self) -> Option<&str> {
        match self {
            Self::Object(module) => module.subdir.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn config_opts(&self) -> Option<&[String]> {
        match self {
            Self::Object(module) => module.config_opts.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn cleanup(&self) -> Option<&[String]> {
        match self {
            Self::Object(module) => module.cleanup.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn cleanup_commands(&self) -> Option<&[String]> {
        match self {
            Self::Object(module) => module.cleanup_commands.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn post_install(&self) -> Option<&[String]> {
        match self {
            Self::Object(module) => module.post_install.as_deref(),
            Self::Name(_) => None,
        }
    }

    pub fn extra(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Object(module) => Some(&module.extra),
            Self::Name(_) => None,
        }
    }

    pub fn applies_to_arch(&self, arch: &str) -> bool {
        match self {
            Self::Object(module) => arch_filter_allows(
                module.only_arches.as_deref(),
                module.skip_arches.as_deref(),
                arch,
            ),
            Self::Name(_) => true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ModuleObject {
    pub name: Option<String>,
    pub license: Option<String>,
    pub buildsystem: Option<String>,
    pub builddir: Option<String>,
    pub subdir: Option<String>,
    pub config_opts: Option<Vec<String>>,
    pub cleanup: Option<Vec<String>>,
    pub cleanup_commands: Option<Vec<String>>,
    pub post_install: Option<Vec<String>>,
    pub only_arches: Option<Vec<String>>,
    pub skip_arches: Option<Vec<String>>,
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub modules: Vec<Module>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Source {
    #[serde(rename = "type")]
    pub source_type: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub urls: Option<Vec<String>>,
    pub mirror_urls: Option<Vec<String>>,
    pub sha512: Option<String>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub size: Option<u64>,
    pub dest: Option<String>,
    pub dest_filename: Option<String>,
    pub strip_components: Option<u64>,
    pub git_submodules: Option<bool>,
    pub disable_shallow_clone: Option<bool>,
    pub only_arches: Option<Vec<String>>,
    pub skip_arches: Option<Vec<String>>,
    pub commit: Option<String>,
    pub tag: Option<String>,
    pub branch: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Source {
    pub fn applies_to_arch(&self, arch: &str) -> bool {
        arch_filter_allows(
            self.only_arches.as_deref(),
            self.skip_arches.as_deref(),
            arch,
        )
    }
}

fn arch_filter_allows(
    only_arches: Option<&[String]>,
    skip_arches: Option<&[String]>,
    arch: &str,
) -> bool {
    if only_arches.is_some_and(|arches| !arches.iter().any(|candidate| candidate == arch)) {
        return false;
    }

    if skip_arches.is_some_and(|arches| arches.iter().any(|candidate| candidate == arch)) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extra_data_source() {
        let manifest: FlatpakManifest = serde_json::from_str(
            r#"{"modules":[{"name":"geekbench","sources":[{"type":"extra-data","url":"https://example.test/a","sha256":"abc","size":12,"dest-filename":"a.bin","only-arches":["x86_64"]}]}]}"#,
        )
        .unwrap();

        let source = &manifest.modules[0].sources()[0];
        assert_eq!(source.source_type.as_deref(), Some("extra-data"));
        assert_eq!(source.size, Some(12));
        assert_eq!(source.dest_filename.as_deref(), Some("a.bin"));
    }

    #[test]
    fn parses_file_source_path() {
        let manifest: FlatpakManifest = serde_json::from_str(
            r#"{"modules":[{"name":"app","sources":[{"type":"file","path":"appdata.xml"}]}]}"#,
        )
        .unwrap();

        assert_eq!(
            manifest.modules[0].sources()[0].path.as_deref(),
            Some("appdata.xml")
        );
    }

    #[test]
    fn applies_arch_filters() {
        let manifest: FlatpakManifest = serde_json::from_str(
            r#"{"modules":[{"name":"x86-only","only-arches":["x86_64"],"sources":[{"type":"archive","skip-arches":["aarch64"]}]}]}"#,
        )
        .unwrap();

        assert!(manifest.modules[0].applies_to_arch("x86_64"));
        assert!(!manifest.modules[0].applies_to_arch("aarch64"));
        assert!(manifest.modules[0].sources()[0].applies_to_arch("x86_64"));
        assert!(!manifest.modules[0].sources()[0].applies_to_arch("aarch64"));
    }

    #[test]
    fn parses_nested_modules() {
        let manifest: FlatpakManifest =
            serde_json::from_str(r#"{"modules":[{"name":"parent","modules":[{"name":"child"}]}]}"#)
                .unwrap();

        assert_eq!(manifest.modules[0].modules()[0].name(), "child");
    }
}
