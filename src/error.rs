use std::fmt;
use std::io;
use std::path::PathBuf;

use thiserror::Error;
use zeroize::Zeroize;

use crate::config::SourceFormat;
use crate::path::ManagedPath;

pub type Result<T> = std::result::Result<T, GitveilError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    Configuration,
    Dependency,
    IdentityUnavailable,
    Integrity,
    Ciphertext,
    Source,
    Path,
    Concurrency,
    Process,
    Protocol,
    Conflict,
    Io,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct GitveilError {
    category: ErrorCategory,
    message: String,
}

impl GitveilError {
    pub(crate) fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }

    pub const fn category(&self) -> ErrorCategory {
        self.category
    }

    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Configuration, message)
    }

    pub(crate) fn dependency(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Dependency, message)
    }

    pub(crate) fn path(path: &ManagedPath, reason: &str) -> Self {
        Self::new(
            ErrorCategory::Path,
            format!("unsafe managed path {path}: {reason}"),
        )
    }

    pub(crate) fn source(path: &ManagedPath, format: SourceFormat, reason: &str) -> Self {
        Self::new(
            ErrorCategory::Source,
            format!("invalid {format} source at {path}: {reason}"),
        )
    }

    pub(crate) fn ciphertext(path: &ManagedPath, reason: &str) -> Self {
        Self::new(
            ErrorCategory::Ciphertext,
            format!("invalid ciphertext envelope at {path}: {reason}"),
        )
    }

    pub(crate) fn io(operation: &'static str, path: Option<PathBuf>, error: &io::Error) -> Self {
        let target = path.map_or_else(String::new, |path| format!(" at {}", path.display()));
        Self::new(
            ErrorCategory::Io,
            format!("{operation} failed{target}: {}", error.kind()),
        )
    }
}

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn copy_out(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}
