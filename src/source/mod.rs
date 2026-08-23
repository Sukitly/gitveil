mod document;
mod dotenv;
mod json;
mod strict;
mod toml;
mod yaml;

pub use document::{
    DotenvLayout, Layout, LineEnding, Node, NodePath, PathSegment, Placeholder, QuoteStyle, Scalar,
    SourceDocument, SourceError, Template,
};

use crate::config::SourceFormat;

pub fn parse(format: SourceFormat, input: &[u8]) -> Result<SourceDocument, SourceError> {
    let text = std::str::from_utf8(input).map_err(|_| SourceError::NonUtf8 { format })?;
    if has_conflict_markers(text) {
        return Err(SourceError::ConflictMarkers { format });
    }
    match format {
        SourceFormat::Dotenv => dotenv::parse(text),
        SourceFormat::Json => json::parse(text),
        SourceFormat::Yaml => yaml::parse(text),
        SourceFormat::Toml => toml::parse(text),
    }
}

fn generate(document: &SourceDocument) -> Result<Vec<u8>, SourceError> {
    match document.format() {
        SourceFormat::Dotenv => dotenv::generate(document),
        SourceFormat::Json => json::generate(document),
        SourceFormat::Yaml => yaml::generate(document),
        SourceFormat::Toml => toml::generate(document),
    }
}

fn has_conflict_markers(input: &str) -> bool {
    input.lines().any(|line| {
        let line = line.trim_start_matches([' ', '\t', '#', '/', ';']);
        line.starts_with("<<<<<<< ") || line == "=======" || line.starts_with(">>>>>>> ")
    })
}
