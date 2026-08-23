use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use semver::Version;

use crate::error::{ErrorCategory, GitveilError, Result};
use crate::path::ManagedPath;

const MINIMUM_GIT_VERSION: Version = Version::new(2, 20, 0);

pub(crate) enum RepositoryDiscoveryError {
    NotRepository,
    Failure(GitveilError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IgnoreRule {
    source: String,
    line: usize,
    pattern: String,
    ignored: bool,
}

impl IgnoreRule {
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) const fn line(&self) -> usize {
        self.line
    }

    pub(crate) fn pattern(&self) -> &str {
        &self.pattern
    }

    pub(crate) const fn is_ignored(&self) -> bool {
        self.ignored
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IgnoreMatch {
    Unmatched,
    Rule(IgnoreRule),
}

impl IgnoreMatch {
    pub(crate) fn is_ignored(&self) -> bool {
        matches!(self, Self::Rule(rule) if rule.is_ignored())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Repository {
    root: PathBuf,
    runtime_path: PathBuf,
}

impl Repository {
    pub(crate) fn discover(start: &Path) -> std::result::Result<Self, RepositoryDiscoveryError> {
        let output = git_text(
            start,
            ["rev-parse", "--show-toplevel", "--git-path", "gitveil"],
        )?;
        let paths = output.lines().collect::<Vec<_>>();
        if paths.len() != 2 {
            return Err(RepositoryDiscoveryError::Failure(protocol_error(
                "invalid Git repository discovery output",
            )));
        }
        let root = PathBuf::from(paths[0]);
        if !root.is_absolute() {
            return Err(RepositoryDiscoveryError::Failure(GitveilError::new(
                ErrorCategory::Path,
                "Git repository root is not absolute",
            )));
        }
        // Git renders relative repository paths against the command's current
        // directory, which may be below the repository root.
        let runtime_path = resolve_git_path(start, paths[1]);
        Ok(Self { root, runtime_path })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    pub(crate) fn ensure_supported_version(&self) -> Result<()> {
        let version = git_version(&self.root)?;
        if version < MINIMUM_GIT_VERSION {
            return Err(GitveilError::dependency(format!(
                "unsupported Git version {version}; required >= {MINIMUM_GIT_VERSION}"
            )));
        }
        Ok(())
    }

    /// Returns selected plaintext paths currently present in the Git index.
    pub(crate) fn tracked_paths(&self, paths: &[ManagedPath]) -> Result<HashSet<ManagedPath>> {
        if paths.is_empty() {
            return Ok(HashSet::new());
        }
        let requested = paths
            .iter()
            .map(|path| (path.as_str().as_bytes(), path))
            .collect::<HashMap<_, _>>();
        let mut arguments = vec![
            OsString::from("ls-files"),
            OsString::from("--cached"),
            OsString::from("-z"),
            OsString::from("--"),
        ];
        arguments.extend(paths.iter().map(|path| OsString::from(path.as_str())));
        let output = self.git_output_with_environment(arguments, None, true, &[], &[])?;
        let mut tracked = HashSet::new();
        for path in output
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let requested_path = requested
                .get(path)
                .ok_or_else(|| protocol_error("git ls-files returned an unrequested path"))?;
            tracked.insert((*requested_path).clone());
        }
        Ok(tracked)
    }

    /// Evaluates the effective ignore rule for every requested path.
    pub(crate) fn ignore_matches(
        &self,
        paths: &[ManagedPath],
    ) -> Result<HashMap<ManagedPath, IgnoreMatch>> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let requested = paths
            .iter()
            .map(|path| (path.as_str().as_bytes(), path))
            .collect::<HashMap<_, _>>();
        let mut input = Vec::new();
        for path in paths {
            input.extend_from_slice(path.as_str().as_bytes());
            input.push(0);
        }
        let output = self.git_output_with_environment(
            [
                "check-ignore",
                "--no-index",
                "--verbose",
                "--non-matching",
                "-z",
                "--stdin",
            ],
            Some(&input),
            false,
            &[],
            &[1],
        )?;
        parse_ignore_matches(&output, &requested)
    }

    /// Returns the selected paths that have unmerged index stages using one
    /// index query, independent of the number of managed paths.
    pub(crate) fn unmerged_paths(&self, paths: &[ManagedPath]) -> Result<HashSet<ManagedPath>> {
        if paths.is_empty() {
            return Ok(HashSet::new());
        }
        let requested = paths
            .iter()
            .map(|path| (path.as_str().as_bytes(), path))
            .collect::<HashMap<_, _>>();
        let output = self.git_output(
            [
                OsString::from("ls-files"),
                OsString::from("--unmerged"),
                OsString::from("--stage"),
                OsString::from("-z"),
            ],
            None,
        )?;
        let mut unmerged = HashSet::new();
        for entry in output
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
                return Err(protocol_error("invalid git ls-files output"));
            };
            let metadata = std::str::from_utf8(&entry[..tab])
                .map_err(|_| protocol_error("non-UTF-8 git ls-files metadata"))?;
            let stage = metadata
                .split_whitespace()
                .nth(2)
                .ok_or_else(|| protocol_error("missing index stage"))?
                .parse::<u8>()
                .map_err(|_| protocol_error("invalid index stage"))?;
            if !(1..=3).contains(&stage) {
                return Err(protocol_error("invalid unmerged index stage"));
            }
            if let Some(path) = requested.get(&entry[tab + 1..]) {
                unmerged.insert((*path).clone());
            }
        }
        Ok(unmerged)
    }

    pub(crate) fn index_blob(&self, path: &ManagedPath, stage: u8) -> Result<Option<Vec<u8>>> {
        let output = self.run_git_literal_path(["ls-files", "--stage", "-z"], path)?;
        for entry in output
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
                return Err(protocol_error("invalid git ls-files output"));
            };
            let metadata = std::str::from_utf8(&entry[..tab])
                .map_err(|_| protocol_error("non-UTF-8 git ls-files metadata"))?;
            let mut fields = metadata.split_whitespace();
            let _mode = fields.next();
            let oid = fields
                .next()
                .ok_or_else(|| protocol_error("missing index object id"))?;
            let entry_stage = fields
                .next()
                .ok_or_else(|| protocol_error("missing index stage"))?
                .parse::<u8>()
                .map_err(|_| protocol_error("invalid index stage"))?;
            if entry_stage == stage {
                return self.cat_blob(oid).map(Some);
            }
        }
        Ok(None)
    }

    pub(crate) fn revision_blob(
        &self,
        revision: &str,
        path: &ManagedPath,
    ) -> Result<Option<Vec<u8>>> {
        if revision != "HEAD"
            && (revision.len() > 64
                || revision.is_empty()
                || !revision
                    .chars()
                    .all(|character| character.is_ascii_hexdigit()))
        {
            return Err(GitveilError::configuration("invalid revision object id"));
        }
        // A Git failure must propagate: `verify` reads an absent blob as "this
        // commit removed the path", so mapping failures to absence would make
        // the history scan fail open.
        let output = self.run_git_literal_path(["ls-tree", "-z", revision], path)?;
        let Some(entry) = output
            .split(|byte| *byte == 0)
            .find(|entry| !entry.is_empty())
        else {
            return Ok(None);
        };
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(protocol_error("invalid git ls-tree output"));
        };
        let metadata = std::str::from_utf8(&entry[..tab])
            .map_err(|_| protocol_error("non-UTF-8 git ls-tree metadata"))?;
        let oid = metadata
            .split_whitespace()
            .nth(2)
            .ok_or_else(|| protocol_error("missing tree object id"))?;
        self.cat_blob(oid).map(Some)
    }

    fn cat_blob(&self, oid: &str) -> Result<Vec<u8>> {
        if !oid.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err(protocol_error("invalid Git object id"));
        }
        self.git_output(
            [
                OsString::from("cat-file"),
                OsString::from("blob"),
                OsString::from(oid),
            ],
            None,
        )
    }

    pub(crate) fn run_git_literal_path<I, S>(&self, args: I, path: &ManagedPath) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut arguments = args
            .into_iter()
            .map(|value| value.as_ref().to_os_string())
            .collect::<Vec<_>>();
        arguments.push(OsString::from("--"));
        arguments.push(OsString::from(path.as_str()));
        self.git_output_with_environment(arguments, None, true, &[], &[])
    }

    fn git_output<I, S>(&self, args: I, input: Option<&[u8]>) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.git_output_with_environment(args, input, false, &[], &[])
    }

    fn git_output_with_environment<I, S>(
        &self,
        args: I,
        input: Option<&[u8]>,
        literal_paths: bool,
        environment: &[(OsString, OsString)],
        accepted_nonzero_codes: &[i32],
    ) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new("git");
        command
            .current_dir(&self.root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);
        if literal_paths {
            command.env("GIT_LITERAL_PATHSPECS", "1");
        }
        let mut child = command.spawn().map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not start Git process: {}", error.kind()),
            )
        })?;
        // Git interleaves reading stdin with writing stdout (for example
        // `check-ignore --stdin`), so stdin must be written concurrently or
        // both processes deadlock once the pipes fill.
        let stdin_writer = if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| protocol_error("Git stdin unavailable"))?;
            let input = input.to_vec();
            Some(std::thread::spawn(move || stdin.write_all(&input)))
        } else {
            None
        };
        let output = child.wait_with_output().map_err(|error| {
            GitveilError::new(
                ErrorCategory::Process,
                format!("could not wait for Git process: {}", error.kind()),
            )
        })?;
        let stdin_result = stdin_writer
            .map(|writer| {
                writer
                    .join()
                    .map_err(|_| protocol_error("Git stdin writer failed"))?
                    .map_err(|error| {
                        GitveilError::new(
                            ErrorCategory::Process,
                            format!("could not write Git input: {}", error.kind()),
                        )
                    })
            })
            .transpose();
        if output.status.success()
            || output
                .status
                .code()
                .is_some_and(|code| accepted_nonzero_codes.contains(&code))
        {
            // A failed Git command already reports the more specific error; a
            // short stdin write only matters when Git claims success.
            stdin_result?;
            Ok(output.stdout)
        } else {
            Err(git_failure(output.status.code(), &output.stderr))
        }
    }
}

fn parse_ignore_matches(
    output: &[u8],
    requested: &HashMap<&[u8], &ManagedPath>,
) -> Result<HashMap<ManagedPath, IgnoreMatch>> {
    let mut fields = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    if fields.len() % 4 != 0 {
        return Err(protocol_error("invalid git check-ignore verbose output"));
    }

    let mut matches = HashMap::with_capacity(requested.len());
    for &[source, line, pattern, path] in fields.as_chunks::<4>().0 {
        let requested_path = requested
            .get(path)
            .ok_or_else(|| protocol_error("git check-ignore returned an unrequested path"))?;
        let outcome = if source.is_empty() && line.is_empty() && pattern.is_empty() {
            IgnoreMatch::Unmatched
        } else {
            if source.is_empty() || line.is_empty() || pattern.is_empty() {
                return Err(protocol_error("incomplete git check-ignore rule evidence"));
            }
            let source = std::str::from_utf8(source)
                .map_err(|_| protocol_error("non-UTF-8 git check-ignore rule source"))?;
            let line = std::str::from_utf8(line)
                .map_err(|_| protocol_error("non-UTF-8 git check-ignore line"))?
                .parse::<usize>()
                .map_err(|_| protocol_error("invalid git check-ignore line"))?;
            let pattern = std::str::from_utf8(pattern)
                .map_err(|_| protocol_error("non-UTF-8 git check-ignore pattern"))?;
            IgnoreMatch::Rule(IgnoreRule {
                source: source.to_owned(),
                line,
                pattern: pattern.to_owned(),
                ignored: !pattern.starts_with('!'),
            })
        };
        if matches.insert((*requested_path).clone(), outcome).is_some() {
            return Err(protocol_error("git check-ignore returned a duplicate path"));
        }
    }
    if matches.len() != requested.len() {
        return Err(protocol_error("git check-ignore omitted a requested path"));
    }
    Ok(matches)
}

fn git_version(start: &Path) -> Result<Version> {
    let output = Command::new("git")
        .current_dir(start)
        .arg("version")
        .output()
        .map_err(|error| {
            GitveilError::dependency(format!("Git executable unavailable: {}", error.kind()))
        })?;
    if !output.status.success() {
        return Err(GitveilError::dependency("Git version check failed"));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| GitveilError::dependency("Git version output is not UTF-8"))?;
    let token = text
        .split_whitespace()
        .find(|value| {
            value
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
        })
        .ok_or_else(|| GitveilError::dependency("Git version output is unrecognized"))?;
    let normalized = token.split('.').take(3).collect::<Vec<_>>().join(".");
    Version::parse(&normalized)
        .map_err(|_| GitveilError::dependency("Git version output is unrecognized"))
}

fn git_text<const N: usize>(
    start: &Path,
    args: [&str; N],
) -> std::result::Result<String, RepositoryDiscoveryError> {
    let output = Command::new("git")
        .current_dir(start)
        .args(args)
        .output()
        .map_err(|error| {
            RepositoryDiscoveryError::Failure(GitveilError::new(
                ErrorCategory::Process,
                format!("could not execute Git: {}", error.kind()),
            ))
        })?;
    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code == 128 {
            return Err(RepositoryDiscoveryError::NotRepository);
        }
        return Err(RepositoryDiscoveryError::Failure(GitveilError::new(
            ErrorCategory::Process,
            format!("Git repository discovery failed with exit code {code}"),
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| {
            RepositoryDiscoveryError::Failure(protocol_error("non-UTF-8 Git repository path"))
        })
}

fn resolve_git_path(root: &Path, value: &str) -> PathBuf {
    let value = PathBuf::from(value);
    if value.is_absolute() {
        value
    } else {
        root.join(value)
    }
}

fn git_failure(code: Option<i32>, stderr: &[u8]) -> GitveilError {
    let detail = std::str::from_utf8(stderr).ok().and_then(|text| {
        text.lines().find_map(|line| {
            let index = line.find("gitveil: ")?;
            let value = &line[index..];
            (value.len() <= 512).then_some(value)
        })
    });
    let detail = detail.map(|value| format!(": {value}")).unwrap_or_default();
    GitveilError::new(
        ErrorCategory::Process,
        format!(
            "Git operation failed with exit code {}{detail}",
            code.unwrap_or(-1)
        ),
    )
}

fn protocol_error(message: &str) -> GitveilError {
    GitveilError::new(ErrorCategory::Protocol, message)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::Command;

    use super::{IgnoreMatch, Repository, parse_ignore_matches};
    use crate::path::ManagedPath;

    /// Initializes a real empty Git repository and discovers it.
    fn ephemeral_repository() -> (tempfile::TempDir, Repository) {
        let root = tempfile::tempdir().expect("repository fixture");
        let init = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .current_dir(root.path())
            .output()
            .expect("git init");
        assert!(init.status.success(), "git init failed");
        let Ok(repository) = Repository::discover(root.path()) else {
            panic!("repository discovery failed");
        };
        (root, repository)
    }

    // `verify` treats an absent blob as "this commit removed the path"; a Git
    // failure must therefore surface as an error, never as absence, or the
    // history scan fails open.
    #[test]
    fn revision_blob_propagates_git_failures_instead_of_reporting_absence() {
        let (_root, repository) = ephemeral_repository();
        let path = ManagedPath::new(".env.gitveil").expect("path");
        let missing_commit = "d".repeat(40);
        assert!(
            repository.revision_blob(&missing_commit, &path).is_err(),
            "a failing git ls-tree must propagate as an error"
        );
    }

    // `git check-ignore --stdin` interleaves reading requests with writing
    // results; a request set larger than the pipe capacity in both
    // directions deadlocks unless stdin is written concurrently.
    #[test]
    fn ignore_matches_streams_large_path_sets_without_deadlock() {
        let (_root, repository) = ephemeral_repository();
        let directory = "d".repeat(120);
        let paths = (0..2000)
            .map(|index| ManagedPath::new(format!("{directory}/p{index:04}.env")).expect("path"))
            .collect::<Vec<_>>();
        let matches = repository.ignore_matches(&paths).expect("ignore matches");
        assert_eq!(matches.len(), paths.len());
        assert!(
            matches
                .values()
                .all(|outcome| *outcome == IgnoreMatch::Unmatched),
            "no ignore rules exist in the fixture"
        );
    }

    #[test]
    fn verbose_ignore_protocol_preserves_rule_evidence_and_non_matches() {
        let plaintext = ManagedPath::new(".env").expect("plaintext path");
        let ciphertext = ManagedPath::new(".env.gitveil").expect("ciphertext path");
        let requested = HashMap::from([
            (plaintext.as_str().as_bytes(), &plaintext),
            (ciphertext.as_str().as_bytes(), &ciphertext),
        ]);
        let output = b".gitignore\x001\x00/.env\x00.env\x00\x00\x00\x00.env.gitveil\x00";
        let matches = parse_ignore_matches(output, &requested).expect("ignore protocol");
        let IgnoreMatch::Rule(rule) = &matches[&plaintext] else {
            panic!("plaintext rule")
        };
        assert_eq!(rule.source(), ".gitignore");
        assert_eq!(rule.line(), 1);
        assert_eq!(rule.pattern(), "/.env");
        assert!(rule.is_ignored());
        assert_eq!(matches[&ciphertext], IgnoreMatch::Unmatched);
    }

    #[test]
    fn verbose_ignore_protocol_rejects_missing_or_unrequested_records() {
        let path = ManagedPath::new(".env").expect("path");
        let requested = HashMap::from([(path.as_str().as_bytes(), &path)]);
        assert!(parse_ignore_matches(b"", &requested).is_err());
        assert!(parse_ignore_matches(b"\0\0\0other.env\0", &requested).is_err());
    }
}
