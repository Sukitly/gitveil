use std::fmt;
use std::path::{Path, PathBuf};

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ManagedPath(Utf8PathBuf);

impl ManagedPath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, PathError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(PathError::Empty);
        }
        if value.starts_with(':') {
            return Err(PathError::GitPathspecMagic);
        }
        if value.starts_with('/')
            || value.starts_with('\\')
            || value.starts_with('!')
            || value.contains('\\')
        {
            return Err(PathError::NotRepositoryRelative);
        }
        if value.ends_with('/') || value.contains("//") {
            return Err(PathError::NotNormalized);
        }
        if value.chars().any(char::is_control) {
            return Err(PathError::ControlCharacter);
        }

        for component in value.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(PathError::NotNormalized);
            }
            if component.eq_ignore_ascii_case(".git") {
                return Err(PathError::GitMetadata);
            }
            if component.contains(['*', '?', '[', ']']) {
                return Err(PathError::AttributePattern);
            }
        }

        Ok(Self(Utf8PathBuf::from(value)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn as_path(&self) -> &Path {
        self.0.as_std_path()
    }

    pub(crate) fn join_to(&self, root: &Path) -> PathBuf {
        root.join(self.as_path())
    }

    /// Canonical comparison key for platforms where case and Unicode
    /// normalization do not distinguish filesystem identities.
    pub(crate) fn case_collision_key(&self) -> String {
        self.as_str().nfc().collect::<String>().to_lowercase()
    }
}

impl fmt::Debug for ManagedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ManagedPath")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for ManagedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for ManagedPath {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ManagedPath> for String {
    fn from(value: ManagedPath) -> Self {
        value.0.into_string()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathError {
    #[error("managed path is empty")]
    Empty,
    #[error("managed path must not begin with Git pathspec magic ':'")]
    GitPathspecMagic,
    #[error("managed path must be repository-relative and use '/' separators")]
    NotRepositoryRelative,
    #[error("managed path is not normalized")]
    NotNormalized,
    #[error("managed path may not reference Git metadata")]
    GitMetadata,
    #[error("managed path contains Git attribute pattern metacharacters")]
    AttributePattern,
    #[error("managed path contains a control character")]
    ControlCharacter,
}

#[cfg(test)]
mod tests {
    use super::{ManagedPath, PathError};

    #[test]
    fn leading_colon_is_rejected_before_git_can_apply_pathspec_magic() {
        assert_eq!(
            ManagedPath::new(":secret.env"),
            Err(PathError::GitPathspecMagic)
        );
    }

    #[test]
    fn case_collision_key_unifies_case_and_unicode_normalization() {
        let composed = ManagedPath::new("CAFÉ.env").expect("composed path");
        let decomposed = ManagedPath::new("cafe\u{301}.env").expect("decomposed path");
        assert_eq!(
            composed.case_collision_key(),
            decomposed.case_collision_key()
        );
    }
}
