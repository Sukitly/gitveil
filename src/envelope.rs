use base64::Engine as _;

use thiserror::Error;

use crate::config::SourceFormat;
use crate::recipient::AgeRecipient;
use crate::source::{Layout, Node, NodePath, PathSegment, Scalar, SourceDocument};

const DISCRIMINATOR_PREFIX: &str = "gitveil_v1_";
const FORBIDDEN_SELECTORS: &[&str] = &[
    "unencrypted_suffix",
    "encrypted_suffix",
    "unencrypted_regex",
    "unencrypted_comment_regex",
    "encrypted_comment_regex",
];

#[derive(Clone)]
pub struct DecryptedEnvelope {
    format: SourceFormat,
    data: Node,
    layout: Layout,
}

impl DecryptedEnvelope {
    pub fn from_source(source: &SourceDocument) -> Result<Self, EnvelopeError> {
        Ok(Self {
            format: source.format(),
            data: source.root().clone(),
            layout: source.layout().clone(),
        })
    }

    pub fn from_yaml(input: &[u8], expected_format: SourceFormat) -> Result<Self, EnvelopeError> {
        let text = std::str::from_utf8(input).map_err(|_| EnvelopeError::NonUtf8)?;
        let value: yaml_serde::Value =
            yaml_serde::from_str(text).map_err(|error| EnvelopeError::Yaml(error.to_string()))?;
        let mapping = value
            .as_mapping()
            .ok_or(EnvelopeError::InvalidStructure("root must be a mapping"))?;
        if mapping.len() != 1 {
            return Err(EnvelopeError::InvalidStructure(
                "decrypted envelope must contain one discriminator",
            ));
        }
        let discriminator = discriminator(expected_format);
        let body = mapping
            .get(yaml_serde::Value::String(discriminator))
            .and_then(yaml_serde::Value::as_mapping)
            .ok_or(EnvelopeError::FormatMismatch)?;
        let data = body
            .get(yaml_serde::Value::String("data".to_owned()))
            .ok_or(EnvelopeError::MissingField("data"))?;
        let layout = body
            .get(yaml_serde::Value::String("layout".to_owned()))
            .and_then(yaml_serde::Value::as_str)
            .ok_or(EnvelopeError::MissingField("layout"))?;
        let layout = serde_json::from_str::<Layout>(layout)
            .map_err(|error| EnvelopeError::Layout(error.to_string()))?;
        let type_paths = body
            .get(yaml_serde::Value::String("types".to_owned()))
            .map(parse_type_paths)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            format: expected_format,
            data: node_from_yaml(data, &NodePath::root(), &type_paths)?,
            layout,
        })
    }

    pub fn to_yaml(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut body = yaml_serde::Mapping::new();
        body.insert(
            yaml_serde::Value::String("data".to_owned()),
            node_to_yaml(&self.data)?,
        );
        body.insert(
            yaml_serde::Value::String("layout".to_owned()),
            yaml_serde::Value::String(
                serde_json::to_string(&self.layout)
                    .map_err(|error| EnvelopeError::Layout(error.to_string()))?,
            ),
        );
        let type_paths = collect_type_paths(&self.data);
        if !type_paths.is_empty() {
            let mut types = yaml_serde::Mapping::new();
            for (path, scalar_type) in type_paths {
                let mut marker = yaml_serde::Mapping::new();
                marker.insert(
                    yaml_serde::Value::String(scalar_type.as_str().to_owned()),
                    yaml_serde::Value::Mapping(yaml_serde::Mapping::new()),
                );
                types.insert(
                    yaml_serde::Value::String(path),
                    yaml_serde::Value::Mapping(marker),
                );
            }
            body.insert(
                yaml_serde::Value::String("types".to_owned()),
                yaml_serde::Value::Mapping(types),
            );
        }
        let mut root = yaml_serde::Mapping::new();
        root.insert(
            yaml_serde::Value::String(discriminator(self.format)),
            yaml_serde::Value::Mapping(body),
        );
        yaml_serde::to_string(&yaml_serde::Value::Mapping(root))
            .map(String::into_bytes)
            .map_err(|error| EnvelopeError::Yaml(error.to_string()))
    }

    pub fn into_source(self) -> Result<SourceDocument, EnvelopeError> {
        Ok(SourceDocument::new(self.format, self.data, self.layout))
    }
}

pub struct CiphertextEnvelope {
    format: SourceFormat,
    key_paths: Vec<String>,
    leaves: indexmap::IndexMap<String, String>,
    layout_ciphertext: String,
    age_recipients: Vec<AgeRecipient>,
}

impl CiphertextEnvelope {
    /// Detects the source format carried by an envelope's discriminator.
    ///
    /// Ciphertext files are self-describing: the `gitveil_v1_<format>` root
    /// key names the source format, so read paths never depend on external
    /// declarations.
    pub fn detect_format(input: &[u8]) -> Result<SourceFormat, EnvelopeError> {
        let text = std::str::from_utf8(input).map_err(|_| EnvelopeError::NonUtf8)?;
        let value: yaml_serde::Value =
            yaml_serde::from_str(text).map_err(|error| EnvelopeError::Yaml(error.to_string()))?;
        let root = value
            .as_mapping()
            .ok_or(EnvelopeError::InvalidStructure("root must be a mapping"))?;
        for format in SourceFormat::ALL {
            if root.contains_key(yaml_serde::Value::String(discriminator(format))) {
                return Ok(format);
            }
        }
        Err(EnvelopeError::FormatMismatch)
    }

    pub fn parse(input: &[u8], expected_format: SourceFormat) -> Result<Self, EnvelopeError> {
        let text = std::str::from_utf8(input).map_err(|_| EnvelopeError::NonUtf8)?;
        let value: yaml_serde::Value =
            yaml_serde::from_str(text).map_err(|error| EnvelopeError::Yaml(error.to_string()))?;
        let root = value
            .as_mapping()
            .ok_or(EnvelopeError::InvalidStructure("root must be a mapping"))?;
        if root.len() != 2 {
            return Err(EnvelopeError::InvalidStructure(
                "ciphertext envelope must contain discriminator and sops metadata",
            ));
        }
        let body = root
            .get(yaml_serde::Value::String(discriminator(expected_format)))
            .and_then(yaml_serde::Value::as_mapping)
            .ok_or(EnvelopeError::FormatMismatch)?;
        if !(2..=3).contains(&body.len()) {
            return Err(EnvelopeError::InvalidStructure(
                "envelope body must contain data, layout, and optional types",
            ));
        }
        for key in body.keys() {
            let Some(key) = key.as_str() else {
                return Err(EnvelopeError::InvalidStructure(
                    "envelope body key must be a string",
                ));
            };
            if !matches!(key, "data" | "layout" | "types") {
                return Err(EnvelopeError::InvalidStructure(
                    "envelope body contains an unknown field",
                ));
            }
        }
        let data = body
            .get(yaml_serde::Value::String("data".to_owned()))
            .ok_or(EnvelopeError::MissingField("data"))?;
        let layout = body
            .get(yaml_serde::Value::String("layout".to_owned()))
            .and_then(yaml_serde::Value::as_str)
            .ok_or(EnvelopeError::MissingField("layout"))?;
        if !is_encrypted_scalar(layout) {
            return Err(EnvelopeError::PlaintextLeaf(
                NodePath::root().child_key("layout"),
            ));
        }
        if let Some(types) = body.get(yaml_serde::Value::String("types".to_owned())) {
            parse_type_paths(types)?;
        }
        let mut key_paths = Vec::new();
        let mut leaves = indexmap::IndexMap::new();
        validate_encrypted_tree(data, &NodePath::root(), &mut key_paths, &mut leaves)?;

        let metadata = root
            .get(yaml_serde::Value::String("sops".to_owned()))
            .and_then(yaml_serde::Value::as_mapping)
            .ok_or(EnvelopeError::MissingField("sops"))?;
        let age_recipients = validate_metadata(metadata)?;
        for key in root.keys() {
            let Some(key) = key.as_str() else {
                return Err(EnvelopeError::InvalidStructure("root key must be a string"));
            };
            if key != "sops" && key != discriminator(expected_format) {
                return Err(EnvelopeError::UnsupportedVersion);
            }
        }

        Ok(Self {
            format: expected_format,
            key_paths,
            leaves,
            layout_ciphertext: layout.to_owned(),
            age_recipients,
        })
    }

    pub const fn format(&self) -> SourceFormat {
        self.format
    }

    pub fn key_paths(&self) -> &[String] {
        &self.key_paths
    }

    pub(crate) fn leaf_ciphertexts(&self) -> &indexmap::IndexMap<String, String> {
        &self.leaves
    }

    pub(crate) fn layout_ciphertext(&self) -> &str {
        &self.layout_ciphertext
    }

    pub fn age_recipients(&self) -> &[AgeRecipient] {
        &self.age_recipients
    }
}

fn validate_metadata(metadata: &yaml_serde::Mapping) -> Result<Vec<AgeRecipient>, EnvelopeError> {
    for required in ["mac", "version", "lastmodified", "encrypted_regex"] {
        if !metadata.contains_key(yaml_serde::Value::String(required.to_owned())) {
            return Err(EnvelopeError::MissingField(required));
        }
    }
    let mac = metadata
        .get(yaml_serde::Value::String("mac".to_owned()))
        .and_then(yaml_serde::Value::as_str)
        .ok_or(EnvelopeError::MissingField("mac"))?;
    if !is_encrypted_scalar(mac) {
        return Err(EnvelopeError::InvalidMetadata("mac is not encrypted"));
    }
    let encrypted_regex = metadata
        .get(yaml_serde::Value::String("encrypted_regex".to_owned()))
        .and_then(yaml_serde::Value::as_str)
        .ok_or(EnvelopeError::MissingField("encrypted_regex"))?;
    if encrypted_regex != ".*" {
        return Err(EnvelopeError::SelectorDrift);
    }
    for selector in FORBIDDEN_SELECTORS {
        if metadata.contains_key(yaml_serde::Value::String((*selector).to_owned())) {
            return Err(EnvelopeError::SelectorDrift);
        }
    }
    for unsupported in [
        "pgp",
        "kms",
        "gcp_kms",
        "azure_kv",
        "hc_vault",
        "key_groups",
    ] {
        if metadata.contains_key(yaml_serde::Value::String(unsupported.to_owned())) {
            return Err(EnvelopeError::InvalidMetadata(
                "only age recipient metadata is supported",
            ));
        }
    }
    let entries = metadata
        .get(yaml_serde::Value::String("age".to_owned()))
        .and_then(yaml_serde::Value::as_sequence)
        .ok_or(EnvelopeError::InvalidMetadata(
            "age recipient metadata is missing",
        ))?;
    if entries.is_empty() {
        return Err(EnvelopeError::InvalidMetadata(
            "age recipient metadata is empty",
        ));
    }
    let mut recipients = Vec::with_capacity(entries.len());
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.as_mapping().ok_or(EnvelopeError::InvalidMetadata(
            "age recipient entry is invalid",
        ))?;
        let recipient = entry
            .get(yaml_serde::Value::String("recipient".to_owned()))
            .and_then(yaml_serde::Value::as_str)
            .ok_or(EnvelopeError::InvalidMetadata(
                "age recipient entry is missing recipient",
            ))?;
        let encrypted_key = entry
            .get(yaml_serde::Value::String("enc".to_owned()))
            .and_then(yaml_serde::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(EnvelopeError::InvalidMetadata(
                "age recipient entry is missing encrypted data key",
            ))?;
        let _ = encrypted_key;
        let recipient = AgeRecipient::new(recipient)
            .map_err(|_| EnvelopeError::InvalidMetadata("age recipient is invalid"))?;
        if !seen.insert(recipient.clone()) {
            return Err(EnvelopeError::InvalidMetadata(
                "age recipient metadata contains a duplicate",
            ));
        }
        recipients.push(recipient);
    }
    Ok(recipients)
}

fn validate_encrypted_tree(
    value: &yaml_serde::Value,
    path: &NodePath,
    key_paths: &mut Vec<String>,
    leaves: &mut indexmap::IndexMap<String, String>,
) -> Result<(), EnvelopeError> {
    match value {
        yaml_serde::Value::Mapping(mapping) => {
            for (key, value) in mapping {
                let Some(key) = key.as_str() else {
                    return Err(EnvelopeError::InvalidStructure(
                        "data mapping key must be a string",
                    ));
                };
                let child = path.child_key(key);
                key_paths.push(child.to_string());
                validate_encrypted_tree(value, &child, key_paths, leaves)?;
            }
            Ok(())
        }
        yaml_serde::Value::Sequence(sequence) => {
            for (index, value) in sequence.iter().enumerate() {
                validate_encrypted_tree(value, &path.child_index(index), key_paths, leaves)?;
            }
            Ok(())
        }
        yaml_serde::Value::String(value) if is_encrypted_scalar(value) => {
            leaves.insert(path.to_string(), value.clone());
            Ok(())
        }
        yaml_serde::Value::Tagged(tagged) => {
            validate_encrypted_tree(&tagged.value, path, key_paths, leaves)
        }
        _ => Err(EnvelopeError::PlaintextLeaf(path.clone())),
    }
}

fn is_encrypted_scalar(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("ENC[AES256_GCM,")
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    let fields = inner.split(',').collect::<Vec<_>>();
    fields.len() == 4
        && fields[0]
            .strip_prefix("data:")
            .is_some_and(|value| !value.is_empty())
        && fields[1]
            .strip_prefix("iv:")
            .is_some_and(|value| !value.is_empty())
        && fields[2]
            .strip_prefix("tag:")
            .is_some_and(|value| !value.is_empty())
        && fields[3].strip_prefix("type:").is_some_and(|value| {
            matches!(
                value,
                "str" | "int" | "float" | "bool" | "bytes" | "comment" | "null"
            )
        })
}

fn discriminator(format: SourceFormat) -> String {
    format!("{DISCRIMINATOR_PREFIX}{}", format.as_str())
}

fn node_to_yaml(node: &Node) -> Result<yaml_serde::Value, EnvelopeError> {
    match node {
        Node::Mapping(values) => {
            let mut mapping = yaml_serde::Mapping::new();
            for (key, value) in values {
                mapping.insert(yaml_serde::Value::String(key.clone()), node_to_yaml(value)?);
            }
            Ok(yaml_serde::Value::Mapping(mapping))
        }
        Node::Sequence(values) => values
            .iter()
            .map(node_to_yaml)
            .collect::<Result<Vec<_>, _>>()
            .map(yaml_serde::Value::Sequence),
        Node::Scalar(Scalar::String(value)) => Ok(yaml_serde::Value::String(value.clone())),
        Node::Scalar(Scalar::DateTime(value)) => Ok(yaml_serde::Value::String(format!(
            "gitveil:datetime:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
        ))),
        Node::Scalar(Scalar::Integer(value)) => Ok(yaml_serde::Value::String(format!(
            "gitveil:integer:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
        ))),
        Node::Scalar(Scalar::Float(value)) => Ok(yaml_serde::Value::String(format!(
            "gitveil:float:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
        ))),
        Node::Scalar(Scalar::Bool(value)) => Ok(yaml_serde::Value::Bool(*value)),
        Node::Scalar(Scalar::Null) => Ok(yaml_serde::Value::String("gitveil:null".to_owned())),
        Node::Tagged { tag, value } => Ok(yaml_serde::Value::Tagged(Box::new(
            yaml_serde::value::TaggedValue {
                tag: yaml_serde::value::Tag::new(tag),
                value: node_to_yaml(value)?,
            },
        ))),
    }
}

fn node_from_yaml(
    value: &yaml_serde::Value,
    path: &NodePath,
    type_paths: &std::collections::HashMap<String, InternalScalarType>,
) -> Result<Node, EnvelopeError> {
    match value {
        yaml_serde::Value::Mapping(mapping) => {
            let mut values = indexmap::IndexMap::with_capacity(mapping.len());
            for (key, value) in mapping {
                let key = key
                    .as_str()
                    .ok_or_else(|| EnvelopeError::UnsupportedKey(path.clone()))?;
                if values.contains_key(key) {
                    return Err(EnvelopeError::DuplicateKey(path.child_key(key)));
                }
                values.insert(
                    key.to_owned(),
                    node_from_yaml(value, &path.child_key(key), type_paths)?,
                );
            }
            Ok(Node::Mapping(values))
        }
        yaml_serde::Value::Sequence(sequence) => sequence
            .iter()
            .enumerate()
            .map(|(index, value)| node_from_yaml(value, &path.child_index(index), type_paths))
            .collect::<Result<Vec<_>, _>>()
            .map(Node::Sequence),
        yaml_serde::Value::String(value)
            if type_paths.get(&encode_path(path)) == Some(&InternalScalarType::DateTime) =>
        {
            let encoded = value
                .strip_prefix("gitveil:datetime:")
                .ok_or(EnvelopeError::InvalidScalar)?;
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| EnvelopeError::InvalidScalar)?;
            let decoded = String::from_utf8(decoded).map_err(|_| EnvelopeError::InvalidScalar)?;
            Ok(Node::Scalar(Scalar::DateTime(decoded)))
        }
        yaml_serde::Value::String(value)
            if type_paths.get(&encode_path(path)) == Some(&InternalScalarType::Null) =>
        {
            if value != "gitveil:null" {
                return Err(EnvelopeError::InvalidScalar);
            }
            Ok(Node::Scalar(Scalar::Null))
        }
        yaml_serde::Value::String(value)
            if type_paths.get(&encode_path(path)) == Some(&InternalScalarType::Integer) =>
        {
            decode_typed_number(value, "gitveil:integer:")
                .map(Scalar::Integer)
                .map(Node::Scalar)
        }
        yaml_serde::Value::String(value)
            if type_paths.get(&encode_path(path)) == Some(&InternalScalarType::Float) =>
        {
            decode_typed_number(value, "gitveil:float:")
                .map(Scalar::Float)
                .map(Node::Scalar)
        }
        yaml_serde::Value::String(value) => Ok(Node::Scalar(Scalar::String(value.clone()))),
        yaml_serde::Value::Number(value) => {
            let value = value.to_string();
            if value.contains(['.', 'e', 'E']) {
                Ok(Node::Scalar(Scalar::Float(value)))
            } else {
                Ok(Node::Scalar(Scalar::Integer(value)))
            }
        }
        yaml_serde::Value::Bool(value) => Ok(Node::Scalar(Scalar::Bool(*value))),
        yaml_serde::Value::Null => Ok(Node::Scalar(Scalar::Null)),
        yaml_serde::Value::Tagged(tagged) => Ok(Node::Tagged {
            tag: tagged.tag.to_string(),
            value: Box::new(node_from_yaml(&tagged.value, path, type_paths)?),
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InternalScalarType {
    DateTime,
    Integer,
    Float,
    Null,
}

impl InternalScalarType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DateTime => "datetime",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Null => "null",
        }
    }
}

fn decode_typed_number(value: &str, prefix: &str) -> Result<String, EnvelopeError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or(EnvelopeError::InvalidScalar)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| EnvelopeError::InvalidScalar)?;
    String::from_utf8(decoded).map_err(|_| EnvelopeError::InvalidScalar)
}

fn collect_type_paths(node: &Node) -> Vec<(String, InternalScalarType)> {
    fn collect(node: &Node, path: &NodePath, output: &mut Vec<(String, InternalScalarType)>) {
        match node {
            Node::Mapping(values) => {
                for (key, value) in values {
                    collect(value, &path.child_key(key), output);
                }
            }
            Node::Sequence(values) => {
                for (index, value) in values.iter().enumerate() {
                    collect(value, &path.child_index(index), output);
                }
            }
            Node::Scalar(Scalar::DateTime(_)) => {
                output.push((encode_path(path), InternalScalarType::DateTime));
            }
            Node::Scalar(Scalar::Integer(_)) => {
                output.push((encode_path(path), InternalScalarType::Integer));
            }
            Node::Scalar(Scalar::Float(_)) => {
                output.push((encode_path(path), InternalScalarType::Float));
            }
            Node::Scalar(Scalar::Null) => {
                output.push((encode_path(path), InternalScalarType::Null));
            }
            Node::Tagged { value, .. } => collect(value, path, output),
            Node::Scalar(_) => {}
        }
    }

    let mut output = Vec::new();
    collect(node, &NodePath::root(), &mut output);
    output
}

fn encode_path(path: &NodePath) -> String {
    let mut encoded = String::from("$");
    for segment in path.segments() {
        encoded.push('/');
        match segment {
            PathSegment::Key(key) => {
                encoded.push_str("k:");
                encoded.push_str(&key.replace('~', "~0").replace('/', "~1"));
            }
            PathSegment::Index(index) => {
                encoded.push_str("i:");
                encoded.push_str(&index.to_string());
            }
        }
    }
    encoded
}

fn parse_type_paths(
    value: &yaml_serde::Value,
) -> Result<std::collections::HashMap<String, InternalScalarType>, EnvelopeError> {
    let mapping = value
        .as_mapping()
        .ok_or(EnvelopeError::InvalidStructure("types must be a mapping"))?;
    let mut paths = std::collections::HashMap::with_capacity(mapping.len());
    for (path, marker) in mapping {
        let path = path.as_str().ok_or(EnvelopeError::InvalidStructure(
            "type path must be a string",
        ))?;
        if !path.starts_with('$')
            || !path
                .split('/')
                .skip(1)
                .all(|segment| segment.starts_with("k:") || segment.starts_with("i:"))
        {
            return Err(EnvelopeError::InvalidStructure("invalid type path"));
        }
        let marker = marker.as_mapping().ok_or(EnvelopeError::InvalidStructure(
            "type marker must be a mapping",
        ))?;
        if marker.len() != 1 {
            return Err(EnvelopeError::InvalidStructure("invalid type marker"));
        }
        let (scalar_type, value) = marker
            .iter()
            .next()
            .ok_or(EnvelopeError::InvalidStructure("invalid type marker"))?;
        let scalar_type = match scalar_type.as_str() {
            Some("datetime") => InternalScalarType::DateTime,
            Some("integer") => InternalScalarType::Integer,
            Some("float") => InternalScalarType::Float,
            Some("null") => InternalScalarType::Null,
            _ => return Err(EnvelopeError::InvalidStructure("unknown type marker")),
        };
        if !value
            .as_mapping()
            .is_some_and(yaml_serde::Mapping::is_empty)
            || paths.insert(path.to_owned(), scalar_type).is_some()
        {
            return Err(EnvelopeError::InvalidStructure(
                "invalid duplicate type marker",
            ));
        }
    }
    Ok(paths)
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope is not UTF-8")]
    NonUtf8,
    #[error("invalid envelope YAML: {0}")]
    Yaml(String),
    #[error("invalid envelope layout: {0}")]
    Layout(String),
    #[error("invalid envelope structure: {0}")]
    InvalidStructure(&'static str),
    #[error("missing envelope field {0}")]
    MissingField(&'static str),
    #[error("envelope format does not match managed path")]
    FormatMismatch,
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    #[error("plaintext leaf at {0}")]
    PlaintextLeaf(NodePath),
    #[error("invalid SOPS metadata: {0}")]
    InvalidMetadata(&'static str),
    #[error("SOPS encryption selector does not enforce all-scalar encryption")]
    SelectorDrift,
    #[error("unsupported mapping key at {0}")]
    UnsupportedKey(NodePath),
    #[error("duplicate key at {0}")]
    DuplicateKey(NodePath),
    #[error("invalid typed scalar")]
    InvalidScalar,
}
