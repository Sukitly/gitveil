use serde::de::DeserializeSeed;

use super::strict::NodeSeed;
use super::{Layout, LineEnding, Node, Scalar, SourceDocument, SourceError};
use crate::config::SourceFormat;

pub(super) fn parse(input: &str) -> Result<SourceDocument, SourceError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let root = NodeSeed::root(SourceFormat::Json)
        .deserialize(&mut deserializer)
        .map_err(|error| SourceError::Parse {
            format: SourceFormat::Json,
            reason: error.to_string(),
        })?;
    deserializer.end().map_err(|error| SourceError::Parse {
        format: SourceFormat::Json,
        reason: error.to_string(),
    })?;
    Ok(SourceDocument::new(
        SourceFormat::Json,
        root,
        Layout::new(LineEnding::detect(input), input.ends_with('\n')),
    ))
}

pub(super) fn generate(document: &SourceDocument) -> Result<Vec<u8>, SourceError> {
    let value = to_value(document.root())?;
    let mut output =
        serde_json::to_string_pretty(&value).map_err(|error| SourceError::Generate {
            format: SourceFormat::Json,
            reason: error.to_string(),
        })?;
    if document.layout().trailing_newline() {
        output.push('\n');
    }
    Ok(document.layout().line_ending().apply(&output).into_bytes())
}

fn to_value(node: &Node) -> Result<serde_json::Value, SourceError> {
    match node {
        Node::Mapping(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), to_value(value)?)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object),
        Node::Sequence(values) => values
            .iter()
            .map(to_value)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        Node::Scalar(Scalar::String(value)) => Ok(serde_json::Value::String(value.clone())),
        Node::Scalar(Scalar::Integer(value) | Scalar::Float(value)) => value
            .parse::<serde_json::Number>()
            .map(serde_json::Value::Number)
            .map_err(|error| SourceError::Generate {
                format: SourceFormat::Json,
                reason: error.to_string(),
            }),
        Node::Scalar(Scalar::Bool(value)) => Ok(serde_json::Value::Bool(*value)),
        Node::Scalar(Scalar::Null) => Ok(serde_json::Value::Null),
        Node::Scalar(Scalar::DateTime(_)) | Node::Tagged { .. } => Err(SourceError::Generate {
            format: SourceFormat::Json,
            reason: "unsupported JSON node type".to_owned(),
        }),
    }
}
