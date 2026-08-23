use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Dotenv,
    Json,
    Yaml,
    Toml,
}

impl SourceFormat {
    pub(crate) const ALL: [Self; 4] = [Self::Dotenv, Self::Json, Self::Yaml, Self::Toml];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Dotenv => "dotenv",
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Toml => "toml",
        }
    }
}

impl std::str::FromStr for SourceFormat {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dotenv" => Ok(Self::Dotenv),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            "toml" => Ok(Self::Toml),
            _ => Err(ConfigError::UnsupportedFormat(value.to_owned())),
        }
    }
}

impl fmt::Display for SourceFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("unsupported source format {0:?}")]
    UnsupportedFormat(String),
}
