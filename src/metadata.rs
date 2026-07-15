use anyhow::{anyhow, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlatpakMetadata {
    groups: BTreeMap<String, BTreeMap<String, String>>,
}

impl FlatpakMetadata {
    pub fn parse(input: &str) -> Result<Self> {
        let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current = String::new();

        for (idx, raw_line) in input.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                current = line[1..line.len() - 1].trim().to_string();
                groups.entry(current.clone()).or_default();
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(anyhow!("invalid metadata line {}: {}", idx + 1, raw_line));
            };
            groups
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }

        Ok(Self { groups })
    }

    pub fn get(&self, group: &str, key: &str) -> Option<&str> {
        self.groups.get(group)?.get(key).map(String::as_str)
    }

    pub fn runtime(&self) -> Option<&str> {
        self.get("Application", "runtime")
    }

    pub fn groups(&self) -> impl Iterator<Item = (&str, &BTreeMap<String, String>)> {
        self.groups
            .iter()
            .map(|(name, values)| (name.as_str(), values))
    }

    pub fn extension_groups(&self) -> impl Iterator<Item = (&str, &BTreeMap<String, String>)> {
        self.groups.iter().filter_map(|(name, values)| {
            if name.starts_with("Extension ") || name.starts_with("ExtensionOf ") {
                Some((name.as_str(), values))
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_application_runtime() {
        let metadata =
            FlatpakMetadata::parse("[Application]\nruntime=org.gnome.Platform/x86_64/46\n")
                .unwrap();
        assert_eq!(metadata.runtime(), Some("org.gnome.Platform/x86_64/46"));
    }

    #[test]
    fn finds_extension_groups() {
        let metadata =
            FlatpakMetadata::parse("[Extension org.example.Codecs]\ndirectory=lib/codecs\n")
                .unwrap();
        assert_eq!(metadata.extension_groups().count(), 1);
    }

    #[test]
    fn exposes_groups_in_sorted_order() {
        let metadata = FlatpakMetadata::parse("[B]\ny=2\n[A]\nx=1\n").unwrap();
        let groups = metadata.groups().map(|(name, _)| name).collect::<Vec<_>>();

        assert_eq!(groups, vec!["A", "B"]);
    }
}
