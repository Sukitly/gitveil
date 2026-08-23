//! Baseline persistence: per-pair salted digest records under the private
//! `.git/gitveil/state/` directory.
//!
//! The store is a correctness-optional cache. A missing or unreadable record
//! degrades `open`/`status` to conservative arbitration; it never fails a
//! command.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::{GitveilError, Result};
use crate::path::ManagedPath;

mod record;

pub(crate) use record::residual_layout;
pub use record::{BaselineDiff, BaselineError, BaselineRecord, CipherSummary, UnitView, unit_view};

pub(crate) struct BaselineStore {
    directory: PathBuf,
}

impl BaselineStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Loads the record for a managed pair.
    ///
    /// A missing, unreadable, or corrupt record yields `None`: the baseline
    /// is an arbitration cache, not a correctness dependency.
    pub(crate) fn load(&self, path: &ManagedPath) -> Option<BaselineRecord> {
        let bytes = fs::read(self.record_path(path)).ok()?;
        BaselineRecord::from_json(&bytes).ok()
    }

    /// Atomically persists the record for a managed pair with owner-only
    /// permissions.
    pub(crate) fn save(&self, path: &ManagedPath, record: &BaselineRecord) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(&self.directory).map_err(|error| {
            GitveilError::io(
                "create baseline directory",
                Some(self.directory.clone()),
                &error,
            )
        })?;
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                GitveilError::io(
                    "secure baseline directory",
                    Some(self.directory.clone()),
                    &error,
                )
            },
        )?;
        let bytes = record
            .to_json()
            .map_err(|error| GitveilError::configuration(error.to_string()))?;
        let target = self.record_path(path);
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory).map_err(|error| {
            GitveilError::io(
                "create baseline record",
                Some(self.directory.clone()),
                &error,
            )
        })?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| temporary.write_all(&bytes))
            .and_then(|()| temporary.as_file_mut().sync_all())
            .map_err(|error| {
                GitveilError::io("write baseline record", Some(target.clone()), &error)
            })?;
        temporary.persist(&target).map_err(|error| {
            GitveilError::io("replace baseline record", Some(target), &error.error)
        })?;
        Ok(())
    }

    pub(crate) fn fresh_salt() -> [u8; 32] {
        let mut salt = [0_u8; 32];
        rand::rng().fill_bytes(&mut salt);
        salt
    }

    fn record_path(&self, path: &ManagedPath) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(path.as_str().as_bytes());
        self.directory
            .join(format!("{}.json", hex::encode(hasher.finalize())))
    }
}
