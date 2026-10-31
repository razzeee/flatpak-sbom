use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

pub trait OstreeFileReader {
    /// Resolve once and read only the requested paths from that immutable commit.
    /// Missing paths are omitted; transport and repository failures are errors.
    fn read_snapshot(
        &self,
        repo_url: &str,
        ref_name: &str,
        paths: &[&str],
    ) -> Result<RepositorySnapshot>;
}

pub struct RepositorySnapshot {
    pub commit: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct CliOstreeFileReader {
    session: RepositorySession,
}

#[derive(Debug)]
struct RepositorySession {
    repo: Mutex<Option<CachedRepo>>,
    commands: Arc<dyn OstreeCommands>,
}

#[derive(Debug)]
struct CachedRepo {
    _tempdir: TempDir,
    repo_url: String,
    path: PathBuf,
}

#[derive(Debug)]
struct OstreeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait OstreeCommands: Send + Sync + std::fmt::Debug {
    fn output(&self, args: &[String]) -> Result<OstreeOutput>;
}

#[derive(Debug, Default)]
struct ProcessOstreeCommands;

impl OstreeCommands for ProcessOstreeCommands {
    fn output(&self, args: &[String]) -> Result<OstreeOutput> {
        let output = Command::new("ostree")
            .env("LC_ALL", "C")
            .args(args)
            .output()
            .context("run ostree command")?;

        Ok(OstreeOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

impl Default for RepositorySession {
    fn default() -> Self {
        Self::new(Arc::new(ProcessOstreeCommands))
    }
}

impl RepositorySession {
    fn new(commands: Arc<dyn OstreeCommands>) -> Self {
        Self {
            repo: Mutex::new(None),
            commands,
        }
    }

    fn run(&self, args: Vec<String>) -> Result<()> {
        let output = self.commands.output(&args)?;
        if output.success {
            Ok(())
        } else {
            bail!(
                "ostree command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
    }

    fn output(&self, args: Vec<String>, context: &str) -> Result<OstreeOutput> {
        self.commands
            .output(&args)
            .with_context(|| context.to_string())
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
        self.run(vec![
            format!("--repo={}", repo.display()),
            "init".to_string(),
            "--mode=archive".to_string(),
        ])?;
        self.run(vec![
            format!("--repo={}", repo.display()),
            "remote".to_string(),
            "add".to_string(),
            "--no-gpg-verify".to_string(),
            "origin".to_string(),
            repo_url.to_string(),
        ])?;

        *cached = Some(CachedRepo {
            _tempdir: tempdir,
            repo_url: repo_url.to_string(),
            path: repo.clone(),
        });

        Ok(repo)
    }

    fn pull_ref(&self, repo_url: &str, ref_name: &str, subpath: Option<&str>) -> Result<PathBuf> {
        let repo = self.ensure_repo(repo_url)?;
        let mut args = vec![
            format!("--repo={}", repo.display()),
            "pull".to_string(),
            "--depth=0".to_string(),
            format!(
                "--http-header=User-Agent=flatpak-sbom/{}",
                env!("CARGO_PKG_VERSION")
            ),
        ];
        if let Some(subpath) = subpath {
            args.push(format!("--subpath=/{}", subpath.trim_start_matches('/')));
        } else {
            args.push("--commit-metadata-only".to_string());
        }
        args.push("--disable-static-deltas".to_string());
        args.push("origin".to_string());
        args.push(ref_name.to_string());
        self.run(args)?;

        Ok(repo)
    }

    fn read_file_from_ref(
        &self,
        repo_url: &str,
        ref_name: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let repo = self.pull_ref(repo_url, ref_name, Some(path))?;
        let normalized = path.trim_start_matches('/');
        let output = self.output(
            vec![
                format!("--repo={}", repo.display()),
                "cat".to_string(),
                ref_name.to_string(),
                format!("/{normalized}"),
            ],
            "run ostree cat",
        )?;

        if output.success {
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
        let output = self.output(
            vec![
                format!("--repo={}", repo.display()),
                "rev-parse".to_string(),
                format!("origin:{ref_name}"),
            ],
            "run ostree rev-parse",
        )?;

        if !output.success {
            bail!(
                "ostree rev-parse failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let commit = String::from_utf8(output.stdout)
            .map(|value| value.trim().to_string())
            .map_err(|err| anyhow!(err))?;
        if commit.len() != 64 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("ostree returned an invalid commit checksum");
        }
        Ok(commit)
    }
}

impl CliOstreeFileReader {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_commands(commands: Arc<dyn OstreeCommands>) -> Self {
        Self {
            session: RepositorySession::new(commands),
        }
    }
}

impl OstreeFileReader for CliOstreeFileReader {
    fn read_snapshot(
        &self,
        repo_url: &str,
        ref_name: &str,
        paths: &[&str],
    ) -> Result<RepositorySnapshot> {
        let commit = self.session.resolve_ref(repo_url, ref_name)?;
        let mut files = BTreeMap::new();
        for path in paths {
            if let Some(bytes) = self.session.read_file_from_ref(repo_url, &commit, path)? {
                files.insert((*path).to_string(), bytes);
            }
        }
        Ok(RepositorySnapshot { commit, files })
    }
}

impl crate::content::ContentSource for CliOstreeFileReader {
    fn content_tree(
        &self,
        repo_url: &str,
        _reference: &str,
        commit: &str,
    ) -> Result<crate::content::ContentTree> {
        if commit.len() != 64 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid content checkout commit checksum");
        }
        let repo = self.session.pull_ref(repo_url, commit, Some("files"))?;
        let directory = tempfile::tempdir().context("create content checkout directory")?;
        let tree = crate::content::ContentTree::checkout(directory);
        self.session.run(vec![
            format!("--repo={}", repo.display()),
            "checkout".into(),
            "--user-mode".into(),
            "--force-copy".into(),
            "--subpath=/files".into(),
            commit.to_string(),
            tree.path.to_string_lossy().into_owned(),
        ])?;
        Ok(tree)
    }
    fn content_origin(&self) -> &'static str {
        "ostree-checkout"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Debug, Default)]
    struct RecordingCommands {
        calls: Mutex<Vec<Vec<String>>>,
        outputs: Mutex<VecDeque<OstreeOutput>>,
    }

    impl RecordingCommands {
        fn with_outputs(outputs: Vec<OstreeOutput>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs.into()),
            })
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl OstreeCommands for RecordingCommands {
        fn output(&self, args: &[String]) -> Result<OstreeOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("missing test command output"))
        }
    }

    fn success(stdout: impl Into<Vec<u8>>) -> OstreeOutput {
        OstreeOutput {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn failure(stderr: impl Into<Vec<u8>>) -> OstreeOutput {
        OstreeOutput {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn switches_repo_when_remote_changes() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success("a".repeat(64).into_bytes()),
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success("b".repeat(64).into_bytes()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());

        reader
            .read_snapshot(
                "https://repo-one.test",
                "app/org.example.App/x86_64/stable",
                &[],
            )
            .unwrap();
        reader
            .read_snapshot(
                "https://repo-two.test",
                "app/org.example.App/x86_64/stable",
                &[],
            )
            .unwrap();

        let calls = commands.calls();
        assert_eq!(calls.iter().filter(|call| call[1] == "init").count(), 2);
        assert!(calls.iter().any(
            |call| call.ends_with(&["origin".to_string(), "https://repo-one.test".to_string()])
        ));
        assert!(calls.iter().any(
            |call| call.ends_with(&["origin".to_string(), "https://repo-two.test".to_string()])
        ));
    }

    #[test]
    fn includes_failed_command_stderr_in_error() {
        let commands =
            RecordingCommands::with_outputs(vec![failure(b"network unavailable".to_vec())]);
        let reader = CliOstreeFileReader::with_commands(commands);

        let err = reader
            .read_snapshot(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                &["metadata"],
            )
            .err()
            .unwrap();

        assert!(err.to_string().contains("network unavailable"));
    }

    #[test]
    fn snapshot_reads_stay_on_resolved_commit() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(format!("{}\n", "a".repeat(64)).into_bytes()),
            success(vec![]),
            success(b"metadata".to_vec()),
            success(vec![]),
            success(b"manifest".to_vec()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());
        let snapshot = reader
            .read_snapshot(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                &["metadata", "files/manifest.json"],
            )
            .unwrap();
        assert_eq!(snapshot.commit, "a".repeat(64));
        assert_eq!(snapshot.files["metadata"], b"metadata");
        let calls = commands.calls();
        let pulls: Vec<_> = calls.iter().filter(|call| call[1] == "pull").collect();
        assert!(pulls[0].contains(&"--commit-metadata-only".to_string()));
        for pull in &pulls[1..] {
            assert_eq!(pull.last().unwrap(), &snapshot.commit);
            assert!(pull.iter().any(|arg| arg.starts_with("--subpath=")));
            assert!(pull.contains(&"--disable-static-deltas".to_string()));
        }
        for cat in calls.iter().filter(|call| call[1] == "cat") {
            assert_eq!(cat[2], snapshot.commit);
        }
    }

    #[test]
    fn reads_real_repository_without_fetching_unrequested_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote");
        let tree = temp.path().join("tree");
        std::fs::create_dir_all(tree.join("files")).unwrap();
        std::fs::write(tree.join("metadata"), b"old metadata").unwrap();
        std::fs::write(tree.join("files/manifest.json"), b"{}").unwrap();
        std::fs::write(tree.join("files/payload"), b"unrequested payload").unwrap();
        let run = |args: &[&str]| {
            let output = Command::new("ostree")
                .arg(format!("--repo={}", remote.display()))
                .args(args)
                .output()
                .expect("install ostree to run repository tests");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        run(&["init", "--mode=archive"]);
        let ref_name = "app/org.example.App/x86_64/stable";
        let commit = run(&[
            "commit",
            "--branch",
            ref_name,
            "--subject",
            "initial",
            &format!("--tree=dir={}", tree.display()),
        ]);
        let repo_url = format!("file://{}", remote.display());
        let reader = CliOstreeFileReader::new();
        let snapshot = reader
            .read_snapshot(
                &repo_url,
                ref_name,
                &["metadata", "files/manifest.json", "usr/manifest.json"],
            )
            .unwrap();
        assert_eq!(snapshot.commit, commit);
        assert_eq!(snapshot.files["metadata"], b"old metadata");
        assert_eq!(snapshot.files["files/manifest.json"], b"{}");
        assert!(!snapshot.files.contains_key("usr/manifest.json"));
        // Inspect the real destination repository: the payload object must not be present.
        let cache = reader.session.repo.lock().unwrap();
        let output = Command::new("ostree")
            .arg(format!("--repo={}", cache.as_ref().unwrap().path.display()))
            .args(["cat", &commit, "/files/payload"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        drop(cache);

        std::fs::write(tree.join("metadata"), b"new metadata").unwrap();
        std::fs::write(tree.join("files/payload"), b"new payload").unwrap();
        let new_commit = run(&[
            "commit",
            "--branch",
            ref_name,
            "--subject",
            "updated",
            &format!("--tree=dir={}", tree.display()),
        ]);
        let updated = reader
            .read_snapshot(&repo_url, ref_name, &["metadata"])
            .unwrap();
        assert_eq!(updated.commit, new_commit);
        assert_eq!(updated.files["metadata"], b"new metadata");
        assert_eq!(snapshot.files["metadata"], b"old metadata");
        use crate::content::ContentSource;
        let checkout = reader
            .content_tree(&repo_url, ref_name, &snapshot.commit)
            .unwrap();
        assert_eq!(
            std::fs::read(checkout.path.join("payload")).unwrap(),
            b"unrequested payload"
        );
        let checkout_path = checkout.path.clone();
        drop(checkout);
        assert!(!checkout_path.exists());
    }
}
