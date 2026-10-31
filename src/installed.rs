//! Pin installed deployment directories before reading manifests or contents.
use crate::ostree::{OstreeFileReader, RepositorySnapshot};
use anyhow::{bail, Context, Result};
use std::{cell::RefCell, collections::BTreeMap, path::PathBuf, process::Command};

#[derive(Default)]
pub struct InstalledReader {
    deployments: RefCell<BTreeMap<String, PathBuf>>,
}

impl InstalledReader {
    pub fn deployment(&self, reference: &str) -> Result<PathBuf> {
        self.locate(reference, None)
    }

    pub fn pin_discovered(&self, reference: &str, commit: &str, installation: &str) -> Result<()> {
        let path = self.locate(reference, Some(installation))?;
        if deployment_commit(&path)? != commit {
            bail!("extension deployment changed during discovery: {reference}");
        }
        Ok(())
    }

    fn locate(&self, reference: &str, installation: Option<&str>) -> Result<PathBuf> {
        if let Some(path) = self.deployments.borrow().get(reference) {
            return Ok(path.clone());
        }
        crate::refname::FlatpakRef::parse(reference)?;
        let mut command = Command::new("flatpak");
        command.args(["info", "--show-location"]);
        if let Some(installation) = installation {
            command.arg(match installation {
                "user" => "--user".to_string(),
                "system" => "--system".to_string(),
                name => format!("--installation={name}"),
            });
        }
        let output = command
            .arg(reference)
            .output()
            .context("run flatpak info")?;
        if !output.status.success() {
            bail!(
                "locate installed {reference}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let path = PathBuf::from(String::from_utf8(output.stdout)?.trim())
            .canonicalize()
            .context("resolve installed deployment directory")?;
        deployment_commit(&path)?;
        self.deployments
            .borrow_mut()
            .insert(reference.to_string(), path.clone());
        Ok(path)
    }
}

impl OstreeFileReader for InstalledReader {
    fn read_snapshot(
        &self,
        _repo: &str,
        reference: &str,
        paths: &[&str],
    ) -> Result<RepositorySnapshot> {
        let deployment = self.deployment(reference)?;
        let commit = deployment_commit(&deployment)?.to_owned();
        let mut files = BTreeMap::new();
        for path in paths {
            // Callers request only these fixed paths; do not allow escaping a deployment.
            if !matches!(
                *path,
                "metadata" | "files/manifest.json" | "usr/manifest.json"
            ) {
                bail!("unsupported deployment metadata path {path}");
            }
            match std::fs::read(deployment.join(path)) {
                Ok(bytes) => {
                    files.insert((*path).to_string(), bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("read installed deployment metadata"),
            }
        }
        Ok(RepositorySnapshot { commit, files })
    }
}

impl crate::content::ContentSource for InstalledReader {
    fn content_tree(
        &self,
        _repo: &str,
        reference: &str,
        commit: &str,
    ) -> Result<crate::content::ContentTree> {
        let deployment = self.deployment(reference)?;
        if deployment_commit(&deployment)? != commit {
            bail!("installed content commit disagrees with SBOM provenance");
        }
        Ok(crate::content::ContentTree::installed(
            deployment.join("files"),
        ))
    }
    fn content_origin(&self) -> &'static str {
        "installed-deployment"
    }
}

fn deployment_commit(path: &std::path::Path) -> Result<&str> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid deployment directory")?;
    // Flatpak adds a subpath suffix for partial deployments (e.g. Locale -en).
    let commit = name
        .get(..64)
        .context("deployment directory has no full checksum")?;
    if !commit.bytes().all(|b| b.is_ascii_hexdigit())
        || (name.len() > 64 && name.as_bytes()[64] != b'-')
    {
        bail!("installed deployment path does not start with a commit checksum");
    }
    Ok(commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_deployments_preserve_full_commit_identity() {
        let checksum = "a".repeat(64);
        assert_eq!(
            deployment_commit(&PathBuf::from(format!("/runtime/{checksum}-en"))).unwrap(),
            checksum
        );
        assert!(deployment_commit(&PathBuf::from(format!("/runtime/{checksum}bad"))).is_err());
        assert!(deployment_commit(std::path::Path::new("/runtime/short-en")).is_err());
    }
}
