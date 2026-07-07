use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use tempfile::TempDir;

pub trait OstreeFileReader {
    fn read_file_from_ref(
        &self,
        repo_url: &str,
        ref_name: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>>;
    fn resolve_ref(&self, repo_url: &str, ref_name: &str) -> Result<String>;
}

#[derive(Debug, Default)]
pub struct CliOstreeFileReader {
    repo: Mutex<Option<CachedRepo>>,
}

#[derive(Debug)]
struct CachedRepo {
    _tempdir: TempDir,
    repo_url: String,
    path: PathBuf,
}

impl CliOstreeFileReader {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_repo(&self, repo_url: &str) -> Result<PathBuf> {
        let mut cached = self.repo.lock().expect("OSTree repo cache poisoned");
        if let Some(cached_repo) = cached.as_ref() {
            if cached_repo.repo_url == repo_url {
                return Ok(cached_repo.path.clone());
            }
        }

        let tempdir = tempfile::tempdir().context("create temporary OSTree repository")?;
        let repo = tempdir.path().to_path_buf();
        run(Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .arg("init")
            .arg("--mode=archive"))?;
        run(Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .arg("remote")
            .arg("add")
            .arg("--no-gpg-verify")
            .arg("origin")
            .arg(repo_url))?;

        *cached = Some(CachedRepo {
            _tempdir: tempdir,
            repo_url: repo_url.to_string(),
            path: repo.clone(),
        });

        Ok(repo)
    }

    fn pull_ref(&self, repo_url: &str, ref_name: &str, subpath: Option<&str>) -> Result<PathBuf> {
        let repo = self.ensure_repo(repo_url)?;
        let mut pull = Command::new("ostree");
        pull.arg(format!("--repo={}", repo.display()))
            .arg("pull")
            .arg("--depth=0");
        if let Some(subpath) = subpath {
            pull.arg(format!("--subpath=/{}", subpath.trim_start_matches('/')));
        }
        pull.arg("origin").arg(ref_name);
        run(&mut pull)?;

        Ok(repo)
    }
}

impl OstreeFileReader for CliOstreeFileReader {
    fn read_file_from_ref(
        &self,
        repo_url: &str,
        ref_name: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let repo = self.pull_ref(repo_url, ref_name, Some(path))?;
        let normalized = path.trim_start_matches('/');
        let output = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .arg("cat")
            .arg(format!("origin:{ref_name}"))
            .arg(format!("/{normalized}"))
            .output()
            .context("run ostree cat")?;

        if output.status.success() {
            Ok(Some(output.stdout))
        } else if String::from_utf8_lossy(&output.stderr).contains("No such file") {
            Ok(None)
        } else {
            bail!(
                "ostree cat failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }

    fn resolve_ref(&self, repo_url: &str, ref_name: &str) -> Result<String> {
        let repo = self.pull_ref(repo_url, ref_name, None)?;
        let output = Command::new("ostree")
            .arg(format!("--repo={}", repo.display()))
            .arg("rev-parse")
            .arg(format!("origin:{ref_name}"))
            .output()
            .context("run ostree rev-parse")?;

        if !output.status.success() {
            bail!(
                "ostree rev-parse failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        String::from_utf8(output.stdout)
            .map(|value| value.trim().to_string())
            .map_err(|err| anyhow!(err))
    }
}

fn run(command: &mut Command) -> Result<()> {
    let output = command.output().context("run ostree command")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "ostree command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
