use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::configure::{AddOutcomeKind, add, initialize};
use crate::error::{ErrorCategory, GitveilError, Result};
use crate::open::{OpenOutcome, open};
use crate::resolve::{ResolveOutcome, resolve};
use crate::runtime::{read_editor_token, run_internal_editor};
use crate::seal::{SealOutcome, seal};
use crate::status::status;
use crate::verify::verify;
use crate::workspace::Workspace;

const AFTER_HELP: &str = "\
Examples:
  gitveil init --recipient age1...
  gitveil add .env --format dotenv
  gitveil open
  gitveil seal --profile dev
  gitveil seal packages/service/.env
  gitveil status --profile prod
  gitveil verify --range origin/main..HEAD

Exit codes:
  0  success
  1  runtime failure, unresolved conflict, or drift requiring attention
  2  usage error
  3  ciphertext verification or integrity failure

Support: https://github.com/Sukitly/gitveil";

#[derive(Debug, Parser)]
#[command(name = "gitveil", version, about, after_help = AFTER_HELP)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize Gitveil configuration at the Git repository root
    Init {
        /// Name of the initial recipient policy
        #[arg(long, default_value = "default", value_name = "POLICY")]
        policy: String,
        /// Public age X25519 recipient authorized to decrypt (repeatable)
        #[arg(long, required = true, action = clap::ArgAction::Append, value_name = "AGE_RECIPIENT")]
        recipient: Vec<String>,
    },
    /// Register plaintext paths and install their Gitignore protection
    Add {
        /// Source format shared by every requested path
        #[arg(long, required = true, value_name = "FORMAT")]
        format: String,
        /// Profile assigned to every requested path
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Named recipient policy (inferred only when exactly one exists)
        #[arg(long, value_name = "POLICY")]
        recipient_policy: Option<String>,
        /// Repository-root-relative plaintext paths to register
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<String>,
    },
    /// Decrypt managed files into their plaintext siblings (key-wise merge)
    Open {
        /// Select only managed files in this profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Manifest paths to open (defaults to every managed file)
        paths: Vec<String>,
    },
    /// Encrypt plaintext changes into the tracked ciphertext siblings
    Seal {
        /// Select only managed files in this profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Manifest paths to seal (defaults to every managed file)
        paths: Vec<String>,
    },
    /// Report drift between plaintext and ciphertext for each managed pair
    Status {
        /// Select only managed files in this profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// Manifest paths to report (defaults to every managed file)
        paths: Vec<String>,
    },
    /// Scan Git history for leaked plaintext or invalid ciphertext
    Verify {
        /// Restrict the scan to a revision range (defaults to all refs)
        #[arg(long, value_name = "BASE..HEAD")]
        range: Option<String>,
    },
    /// Merge conflicted ciphertext files key-wise from the Git index stages
    Resolve {
        /// Manifest paths to resolve (defaults to every conflicted file)
        paths: Vec<String>,
    },
    #[command(hide = true)]
    SopsEditor {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        runtime: PathBuf,
        target: PathBuf,
    },
}

/// Severity tone for one report line; rendered as color on a TTY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tone {
    Good,
    Quiet,
    Attention,
    Bad,
}

fn paint(text: &str, tone: Tone, enabled: bool) -> String {
    if !enabled {
        return text.to_owned();
    }
    let code = match tone {
        Tone::Good => "32",
        Tone::Quiet => "2",
        Tone::Attention => "33",
        Tone::Bad => "31",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

/// Colors are a TTY affordance only, and the `NO_COLOR` convention wins.
fn stdout_styled() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn stderr_styled() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

fn status_tone(state: &crate::status::PairStatus) -> Tone {
    if state.is_bad() {
        Tone::Bad
    } else if state.is_clean() {
        Tone::Good
    } else {
        Tone::Attention
    }
}

fn report_error(path: &crate::path::ManagedPath, error: &GitveilError) {
    let line = format!("gitveil: {path}: {error}");
    eprintln!("{}", paint(&line, Tone::Bad, stderr_styled()));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Success,
    Attention,
}

impl RunOutcome {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Attention => 1,
        }
    }
}

/// Maps an error category to the documented CLI exit code.
///
/// The mapping is part of the public interface: `3` means repository content
/// failed ciphertext or integrity verification, and every other runtime
/// failure exits `1`. Usage errors exit `2` through clap.
pub const fn error_exit_code(category: ErrorCategory) -> u8 {
    match category {
        ErrorCategory::Integrity | ErrorCategory::Ciphertext => 3,
        _ => 1,
    }
}

pub fn run(cli: Cli) -> Result<RunOutcome> {
    let current = std::env::current_dir()
        .map_err(|error| GitveilError::io("read current directory", None, &error))?;
    let gitveil_binary = std::env::current_exe()
        .map_err(|error| GitveilError::io("resolve current executable", None, &error))?;
    match cli.command {
        Command::Init { policy, recipient } => run_initialize(&current, &policy, &recipient),
        Command::Add {
            format,
            profile,
            recipient_policy,
            paths,
        } => run_add(
            &current,
            &paths,
            &format,
            profile.as_deref(),
            recipient_policy.as_deref(),
        ),
        Command::Open { profile, paths } => {
            run_open(&current, &gitveil_binary, &paths, profile.as_deref())
        }
        Command::Seal { profile, paths } => {
            run_seal(&current, &gitveil_binary, &paths, profile.as_deref())
        }
        Command::Status { profile, paths } => {
            run_status(&current, &gitveil_binary, &paths, profile.as_deref())
        }
        Command::Verify { range } => run_verify(&current, &gitveil_binary, range.as_deref()),
        Command::Resolve { paths } => run_resolve(&current, &gitveil_binary, &paths),
        Command::SopsEditor {
            endpoint,
            token_file,
            runtime,
            target,
        } => {
            let token = read_editor_token(&token_file)?;
            run_internal_editor(&endpoint, &token, &runtime, &target)?;
            Ok(RunOutcome::Success)
        }
    }
}

fn run_initialize(current: &Path, policy: &str, recipients: &[String]) -> Result<RunOutcome> {
    let outcome = initialize(current, policy, recipients)?;
    println!(
        "initialized .gitveilrc.json with recipient policy {} ({} recipient{})",
        outcome.policy(),
        outcome.recipient_count(),
        if outcome.recipient_count() == 1 {
            ""
        } else {
            "s"
        }
    );
    Ok(RunOutcome::Success)
}

fn run_add(
    current: &Path,
    paths: &[String],
    format: &str,
    profile: Option<&str>,
    recipient_policy: Option<&str>,
) -> Result<RunOutcome> {
    let outcomes = add(current, paths, format, profile, recipient_policy)?;
    for outcome in &outcomes {
        match outcome.kind() {
            AddOutcomeKind::AddedExisting => {
                println!("{}: added; existing plaintext protected", outcome.path());
            }
            AddOutcomeKind::AddedMissing => {
                println!(
                    "{}: added; create the plaintext before sealing",
                    outcome.path()
                );
            }
            AddOutcomeKind::AlreadyManaged if outcome.plaintext_exists() => {
                println!(
                    "{}: already managed; existing plaintext protected",
                    outcome.path()
                );
            }
            AddOutcomeKind::AlreadyManaged => {
                println!(
                    "{}: already managed; create the plaintext before sealing",
                    outcome.path()
                );
            }
        }
    }
    println!("next: gitveil verify");
    let sealable = outcomes
        .iter()
        .filter(|outcome| outcome.plaintext_exists())
        .map(|outcome| shell_quote(outcome.path().as_str()))
        .collect::<Vec<_>>();
    if !sealable.is_empty() {
        println!("next: gitveil seal -- {}", sealable.join(" "));
    }
    Ok(RunOutcome::Success)
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_open(
    current: &Path,
    gitveil_binary: &Path,
    paths: &[String],
    profile: Option<&str>,
) -> Result<RunOutcome> {
    let workspace = Workspace::discover(current, gitveil_binary)?;
    let styled = stdout_styled();
    let mut outcome = RunOutcome::Success;
    for report in open(&workspace, paths, profile)? {
        match report.result {
            Ok(OpenOutcome::Opened) => {
                println!("{}: {}", report.path, paint("opened", Tone::Good, styled));
            }
            Ok(OpenOutcome::UpToDate) => {
                println!(
                    "{}: {}",
                    report.path,
                    paint("up to date", Tone::Quiet, styled)
                );
            }
            Ok(OpenOutcome::Conflicts(conflicts)) => {
                outcome = RunOutcome::Attention;
                println!(
                    "{}: {}",
                    report.path,
                    paint("conflicts; edit and run gitveil seal", Tone::Bad, styled)
                );
                for conflict in conflicts {
                    println!("  {}", conflict.describe());
                }
            }
            Err(error) => {
                outcome = RunOutcome::Attention;
                report_error(&report.path, &error);
            }
        }
    }
    Ok(outcome)
}

fn run_seal(
    current: &Path,
    gitveil_binary: &Path,
    paths: &[String],
    profile: Option<&str>,
) -> Result<RunOutcome> {
    let workspace = Workspace::discover(current, gitveil_binary)?;
    let styled = stdout_styled();
    let mut outcome = RunOutcome::Success;
    for report in seal(&workspace, paths, profile)? {
        match report.result {
            Ok(SealOutcome::Sealed { data_key_rotated }) => {
                let label = if data_key_rotated {
                    "sealed; data key rotated"
                } else {
                    "sealed"
                };
                println!("{}: {}", report.path, paint(label, Tone::Good, styled));
            }
            Ok(SealOutcome::Unchanged) => {
                println!(
                    "{}: {}",
                    report.path,
                    paint("unchanged", Tone::Quiet, styled)
                );
            }
            Err(error) => {
                outcome = RunOutcome::Attention;
                report_error(&report.path, &error);
            }
        }
    }
    Ok(outcome)
}

fn run_status(
    current: &Path,
    gitveil_binary: &Path,
    paths: &[String],
    profile: Option<&str>,
) -> Result<RunOutcome> {
    let workspace = Workspace::discover(current, gitveil_binary)?;
    let styled = stdout_styled();
    let mut outcome = RunOutcome::Success;
    for report in status(&workspace, paths, profile)? {
        match report.result {
            Ok(state) => {
                if !state.is_clean() {
                    outcome = RunOutcome::Attention;
                }
                let tone = status_tone(&state);
                println!(
                    "{}: {}",
                    report.path,
                    paint(&state.to_string(), tone, styled)
                );
            }
            Err(error) => {
                outcome = RunOutcome::Attention;
                report_error(&report.path, &error);
            }
        }
    }
    Ok(outcome)
}

fn run_verify(current: &Path, gitveil_binary: &Path, range: Option<&str>) -> Result<RunOutcome> {
    let workspace = Workspace::discover(current, gitveil_binary)?;
    let styled = stdout_styled();
    let report = verify(&workspace, range)?;
    for violation in &report.violations {
        println!("{}", paint(&violation.to_string(), Tone::Bad, styled));
    }
    if report.violations.is_empty() {
        Ok(RunOutcome::Success)
    } else {
        Err(GitveilError::new(
            ErrorCategory::Integrity,
            format!("{} history violation(s) found", report.violations.len()),
        ))
    }
}

fn run_resolve(current: &Path, gitveil_binary: &Path, paths: &[String]) -> Result<RunOutcome> {
    let workspace = Workspace::discover(current, gitveil_binary)?;
    let styled = stdout_styled();
    let mut outcome = RunOutcome::Success;
    for report in resolve(&workspace, paths)? {
        match report.result {
            Ok(ResolveOutcome::Resolved { data_key_rotated }) => {
                let label = if data_key_rotated {
                    "resolved; data key rotated; review and git add"
                } else {
                    "resolved; review and git add"
                };
                println!("{}: {}", report.path, paint(label, Tone::Good, styled));
            }
            Ok(ResolveOutcome::ConflictWritten(node)) => {
                outcome = RunOutcome::Attention;
                println!(
                    "{}: {}",
                    report.path,
                    paint(
                        &format!("conflict at {node}; edit the plaintext and run gitveil seal"),
                        Tone::Bad,
                        styled
                    )
                );
            }
            Err(error) => {
                outcome = RunOutcome::Attention;
                report_error(&report.path, &error);
            }
        }
    }
    Ok(outcome)
}

pub fn parse() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::{Tone, error_exit_code, paint, shell_quote, status_tone};
    use crate::baseline::BaselineDiff;
    use crate::error::ErrorCategory;
    use crate::status::{PairDataStatus, PairStatus, RecipientStatus};

    #[test]
    fn paint_wraps_text_only_when_styling_is_enabled() {
        assert_eq!(paint("clean", Tone::Good, false), "clean");
        assert_eq!(paint("clean", Tone::Good, true), "\x1b[32mclean\x1b[0m");
        assert_eq!(
            paint("up to date", Tone::Quiet, true),
            "\x1b[2mup to date\x1b[0m"
        );
        assert_eq!(
            paint("local edits", Tone::Attention, true),
            "\x1b[33mlocal edits\x1b[0m"
        );
        assert_eq!(
            paint("conflict", Tone::Bad, true),
            "\x1b[31mconflict\x1b[0m"
        );
    }

    #[test]
    fn status_states_map_to_their_severity_tone() {
        assert_eq!(
            status_tone(&PairStatus::new(
                PairDataStatus::Clean,
                RecipientStatus::Aligned
            )),
            Tone::Good
        );
        for attention in [
            PairDataStatus::LocalEdits(BaselineDiff::default()),
            PairDataStatus::Behind(BaselineDiff::default()),
            PairDataStatus::Diverged {
                local: BaselineDiff::default(),
                remote: BaselineDiff::default(),
            },
            PairDataStatus::Differs { keys: Vec::new() },
            PairDataStatus::Unknown,
            PairDataStatus::PlaintextMissing,
            PairDataStatus::CiphertextMissing,
            PairDataStatus::Missing,
        ] {
            assert_eq!(
                status_tone(&PairStatus::new(attention, RecipientStatus::Aligned)),
                Tone::Attention
            );
        }
        assert_eq!(
            status_tone(&PairStatus::new(
                PairDataStatus::Conflicted,
                RecipientStatus::NotApplicable
            )),
            Tone::Bad
        );
        assert_eq!(
            status_tone(&PairStatus::new(
                PairDataStatus::Corrupt(String::new()),
                RecipientStatus::NotApplicable
            )),
            Tone::Bad
        );
    }

    #[test]
    fn next_action_paths_are_shell_quoted_without_interpolation() {
        assert_eq!(shell_quote("packages/api/.env"), "packages/api/.env");
        assert_eq!(shell_quote("secret $HOME.env"), "'secret $HOME.env'");
        assert_eq!(shell_quote("secret'file.env"), "'secret'\"'\"'file.env'");
    }

    #[test]
    fn content_verification_failures_use_exit_three() {
        assert_eq!(error_exit_code(ErrorCategory::Integrity), 3);
        assert_eq!(error_exit_code(ErrorCategory::Ciphertext), 3);
    }

    #[test]
    fn other_runtime_failures_use_exit_one() {
        for category in [
            ErrorCategory::Configuration,
            ErrorCategory::Dependency,
            ErrorCategory::IdentityUnavailable,
            ErrorCategory::Source,
            ErrorCategory::Path,
            ErrorCategory::Concurrency,
            ErrorCategory::Process,
            ErrorCategory::Protocol,
            ErrorCategory::Conflict,
            ErrorCategory::Io,
        ] {
            assert_eq!(error_exit_code(category), 1);
        }
    }
}
