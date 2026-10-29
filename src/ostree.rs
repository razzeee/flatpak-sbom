use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
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
    commits: BTreeMap<String, String>,
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
            commits: BTreeMap::new(),
        });

        Ok(repo)
    }

    fn pull_ref(&self, repo_url: &str, ref_name: &str, subpath: Option<&str>) -> Result<PathBuf> {
        let repo = self.ensure_repo(repo_url)?;
        let mut args = vec![
            format!("--repo={}", repo.display()),
            "pull".to_string(),
            "--depth=0".to_string(),
            // Identify the application consistently for discovery, metadata,
            // and content. Some repositories reject libostree's generic UA.
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
        self.ensure_repo(repo_url)?;
        let pinned = self
            .repo
            .lock()
            .expect("OSTree repo cache poisoned")
            .as_ref()
            .and_then(|repo| repo.commits.get(ref_name))
            .cloned();
        let revision = pinned.as_deref().unwrap_or(ref_name);
        let repo = self.pull_ref(repo_url, revision, Some(path))?;
        let normalized = path.trim_start_matches('/');
        let output = self.output(
            vec![
                format!("--repo={}", repo.display()),
                "cat".to_string(),
                pinned.unwrap_or_else(|| format!("origin:{ref_name}")),
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
        self.repo
            .lock()
            .expect("OSTree repo cache poisoned")
            .as_mut()
            .expect("repository initialized")
            .commits
            .insert(ref_name.to_string(), commit.clone());
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
        // Pull and check out the recorded checksum, never a moving ref. Keep
        // ownership local and copy files so scanners cannot modify repo objects.
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

impl OstreeFileReader for CliOstreeFileReader {
    fn read_file_from_ref(
        &self,
        repo_url: &str,
        ref_name: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.session.read_file_from_ref(repo_url, ref_name, path)
    }

    fn resolve_ref(&self, repo_url: &str, ref_name: &str) -> Result<String> {
        self.session.resolve_ref(repo_url, ref_name)
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
    fn reuses_cached_repo_for_same_remote() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(b"first".to_vec()),
            success(vec![]),
            success(b"second".to_vec()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());

        reader
            .read_file_from_ref(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                "metadata",
            )
            .unwrap();
        reader
            .read_file_from_ref(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                "files/manifest.json",
            )
            .unwrap();

        let calls = commands.calls();
        assert_eq!(calls.iter().filter(|call| call[1] == "init").count(), 1);
        assert_eq!(calls.iter().filter(|call| call[1] == "remote").count(), 1);
        assert_eq!(calls.iter().filter(|call| call[1] == "pull").count(), 2);
    }

    #[test]
    fn switches_repo_when_remote_changes() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(b"one".to_vec()),
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(b"two".to_vec()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());

        reader
            .read_file_from_ref(
                "https://repo-one.test",
                "app/org.example.App/x86_64/stable",
                "metadata",
            )
            .unwrap();
        reader
            .read_file_from_ref(
                "https://repo-two.test",
                "app/org.example.App/x86_64/stable",
                "metadata",
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
    fn pulls_requested_file_subpath_before_cat() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(b"contents".to_vec()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());

        reader
            .read_file_from_ref(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                "/files/manifest.json",
            )
            .unwrap();

        let calls = commands.calls();
        let pull = calls.iter().find(|call| call[1] == "pull").unwrap();
        assert!(pull.contains(&"--subpath=/files/manifest.json".to_string()));
        let cat = calls.iter().find(|call| call[1] == "cat").unwrap();
        assert_eq!(cat.last().map(String::as_str), Some("/files/manifest.json"));
    }

    #[test]
    fn maps_missing_file_stderr_to_none() {
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            failure(b"error: No such file or directory".to_vec()),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands);

        let data = reader
            .read_file_from_ref(
                "https://repo.test",
                "app/org.example.App/x86_64/stable",
                "metadata",
            )
            .unwrap();

        assert!(data.is_none());
    }

    #[test]
    fn includes_failed_command_stderr_in_error() {
        let commands =
            RecordingCommands::with_outputs(vec![failure(b"network unavailable".to_vec())]);
        let reader = CliOstreeFileReader::with_commands(commands);

        let err = reader
            .resolve_ref("https://repo.test", "app/org.example.App/x86_64/stable")
            .unwrap_err();

        assert!(err.to_string().contains("network unavailable"));
    }

    #[test]
    fn reads_pinned_commit_after_resolution_without_pulling_full_tree() {
        let commit = "a".repeat(64);
        let commands = RecordingCommands::with_outputs(vec![
            success(vec![]),
            success(vec![]),
            success(vec![]),
            success(commit.as_bytes()),
            success(vec![]),
            success(b"old manifest"),
        ]);
        let reader = CliOstreeFileReader::with_commands(commands.clone());
        let reference = "app/org.example.App/x86_64/stable";
        assert_eq!(
            reader.resolve_ref("https://repo.test", reference).unwrap(),
            commit
        );
        reader
            .read_file_from_ref("https://repo.test", reference, "files/manifest.json")
            .unwrap();
        let calls = commands.calls();
        assert!(calls[2].contains(&"--commit-metadata-only".to_string()));
        assert_eq!(calls[4].last(), Some(&commit));
        assert_eq!(calls[5][2], commit);
    }

    #[test]
    #[ignore = "requires ostree; run in acceptance CI"]
    fn real_repository_update_does_not_change_pinned_contents() {
        use crate::content::ContentSource;
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("remote");
        let tree = temp.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        let run = |args: &[&str]| {
            let output = Command::new("ostree")
                .arg(format!("--repo={}", repo.display()))
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["init", "--mode=archive"]);
        let reference = "app/org.example.App/x86_64/stable";
        let commit = || {
            run(&[
                "commit",
                &format!("--branch={reference}"),
                &format!("--tree=dir={}", tree.display()),
                "--subject=fixture",
            ])
        };
        std::fs::write(tree.join("metadata"), "old").unwrap();
        std::fs::create_dir(tree.join("files")).unwrap();
        std::fs::write(tree.join("files/dependency.txt"), "old package").unwrap();
        commit();
        let reader = CliOstreeFileReader::new();
        let url = format!("file://{}", repo.display());
        let checksum = reader.resolve_ref(&url, reference).unwrap();
        std::fs::write(tree.join("metadata"), "new").unwrap();
        std::fs::write(tree.join("files/dependency.txt"), "new package").unwrap();
        commit();
        assert_eq!(
            reader
                .read_file_from_ref(&url, reference, "metadata")
                .unwrap(),
            Some(b"old".to_vec())
        );
        assert_eq!(
            reader
                .read_file_from_ref(&url, reference, "absent")
                .unwrap(),
            None
        );
        let checkout = reader.content_tree(&url, reference, &checksum).unwrap();
        assert_eq!(
            std::fs::read(checkout.path.join("dependency.txt")).unwrap(),
            b"old package"
        );
        let checkout_path = checkout.path.clone();
        drop(checkout);
        assert!(
            !checkout_path.exists(),
            "temporary content must be removed after scanning"
        );
    }
}
