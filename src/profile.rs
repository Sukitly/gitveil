//! Managed-file profile names used to scope pair-oriented commands.
//!

use std::fmt;

use thiserror::Error;

/// A validated manifest profile name.
///
/// Profiles are selection labels only. They do not alter ciphertext,
/// recipients, baselines, or plaintext paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProfileName(String);

impl ProfileName {
    pub(crate) const DEFAULT: &str = "default";
    const MAX_LENGTH: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self, ProfileError> {
        let value = value.into();
        let valid = (1..=Self::MAX_LENGTH).contains(&value.len())
            && value
                .bytes()
                .enumerate()
                .all(|(index, byte)| match (index, byte) {
                    (0, b'a'..=b'z') => true,
                    (0, _) => false,
                    (_, b'a'..=b'z' | b'0'..=b'9' | b'-') => true,
                    _ => false,
                });
        if !valid {
            return Err(ProfileError::InvalidName(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ProfileName {
    fn default() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("invalid profile name {0:?}; expected ^[a-z][a-z0-9-]{{0,63}}$")]
    InvalidName(String),
}
