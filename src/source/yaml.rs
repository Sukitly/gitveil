use serde::de::DeserializeSeed;

use super::strict::NodeSeed;
use super::{
    Layout, LineEnding, Node, NodePath, Placeholder, Scalar, SourceDocument, SourceError, Template,
};
use crate::config::SourceFormat;

pub(super) fn parse(input: &str) -> Result<SourceDocument, SourceError> {
    let syntax = validate_lossless_syntax(input)?;
    let mut documents = Vec::new();
    for deserializer in yaml_serde::Deserializer::from_str(input) {
        documents.push(
            NodeSeed::root(SourceFormat::Yaml)
                .deserialize(deserializer)
                .map_err(|error| SourceError::Parse {
                    format: SourceFormat::Yaml,
                    reason: error.to_string(),
                })?,
        );
    }
    let document_count = documents.len();
    let root = match document_count {
        0 => Node::Scalar(Scalar::Null),
        1 => documents.remove(0),
        _ => Node::Sequence(documents),
    };
    let mut root = strip_tags(root);
    let mut layout = Layout::new(LineEnding::detect(input), input.ends_with('\n'));
    layout.set_preamble_comments(
        input
            .replace("\r\n", "\n")
            .lines()
            .filter(|line| line.trim_start().starts_with('#'))
            .map(ToOwned::to_owned)
            .collect(),
    );
    let (template, aliases) = scrub_lossless_template(&syntax, input, document_count)?;
    for path in aliases {
        if !root.remove_at_path(&path) {
            return Err(SourceError::LayoutMismatch(path));
        }
    }
    layout.set_template(template);
    Ok(SourceDocument::new(SourceFormat::Yaml, root, layout))
}

pub(super) fn generate(document: &SourceDocument) -> Result<Vec<u8>, SourceError> {
    // Every product path (parse, envelope restore, three-way layout merge)
    // carries a template; fail closed instead of falling back to a lossy
    // serializer, mirroring the TOML adapter.
    let Some(template) = document.layout().template() else {
        return Err(SourceError::Generate {
            format: SourceFormat::Yaml,
            reason: "YAML layout template is missing".to_owned(),
        });
    };
    let mut output = template.body().to_owned();
    for placeholder in template.placeholders() {
        let node = document
            .root()
            .at_path(placeholder.path())
            .ok_or_else(|| SourceError::LayoutMismatch(placeholder.path().clone()))?;
        let rendered = render_scalar(node)?;
        output = output.replace(placeholder.token(), &rendered);
    }
    Ok(document.layout().line_ending().apply(&output).into_bytes())
}

fn strip_tags(node: Node) -> Node {
    match node {
        Node::Mapping(values) => Node::Mapping(
            values
                .into_iter()
                .map(|(key, value)| (key, strip_tags(value)))
                .collect(),
        ),
        Node::Sequence(values) => Node::Sequence(values.into_iter().map(strip_tags).collect()),
        Node::Tagged { value, .. } => strip_tags(*value),
        Node::Scalar(_) => node,
    }
}

fn validate_lossless_syntax(input: &str) -> Result<yaml_edit::YamlFile, SourceError> {
    let file = input
        .parse::<yaml_edit::YamlFile>()
        .map_err(|error| SourceError::Parse {
            format: SourceFormat::Yaml,
            reason: error.to_string(),
        })?;
    if file.to_string() != input {
        return Err(SourceError::Parse {
            format: SourceFormat::Yaml,
            reason: "YAML syntax could not be represented losslessly".to_owned(),
        });
    }
    Ok(file)
}

#[derive(Debug)]
struct YamlReplacement {
    start: usize,
    end: usize,
    token: String,
    path: NodePath,
}

fn scrub_lossless_template(
    file: &yaml_edit::YamlFile,
    input: &str,
    document_count: usize,
) -> Result<(Template, Vec<NodePath>), SourceError> {
    let mut replacements = Vec::new();
    let mut references = Vec::new();
    for (index, document) in file.documents().enumerate() {
        let path = if document_count > 1 {
            NodePath::root().child_index(index)
        } else {
            NodePath::root()
        };
        if let Some(mapping) = document.as_mapping() {
            walk_yaml_mapping(&mapping, &path, &mut replacements, &mut references)?;
        } else if let Some(sequence) = document.as_sequence() {
            walk_yaml_sequence(&sequence, &path, &mut replacements, &mut references)?;
        } else if let Some(scalar) = document.as_scalar() {
            add_yaml_scalar(&scalar, path, &mut replacements);
        }
    }
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.start));
    let mut body = input.to_owned();
    for replacement in &replacements {
        if replacement.start > replacement.end
            || replacement.end > body.len()
            || !body.is_char_boundary(replacement.start)
            || !body.is_char_boundary(replacement.end)
        {
            return Err(SourceError::Parse {
                format: SourceFormat::Yaml,
                reason: "invalid YAML scalar range".to_owned(),
            });
        }
        let original = &input[replacement.start..replacement.end];
        let suffix = if original.ends_with("\r\n") {
            "\r\n"
        } else if original.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        body.replace_range(
            replacement.start..replacement.end,
            &format!("{}{suffix}", replacement.token),
        );
    }
    replacements.reverse();
    let placeholders = replacements
        .into_iter()
        .map(|replacement| Placeholder::new(replacement.token, replacement.path))
        .collect();
    Ok((Template::new(body, placeholders), references))
}

fn walk_yaml_mapping(
    mapping: &yaml_edit::Mapping,
    path: &NodePath,
    replacements: &mut Vec<YamlReplacement>,
    references: &mut Vec<NodePath>,
) -> Result<(), SourceError> {
    for entry in mapping.entries() {
        let key = entry
            .key_node()
            .and_then(|node| node.as_scalar().cloned())
            .ok_or_else(|| SourceError::UnsupportedKey {
                format: SourceFormat::Yaml,
                path: path.clone(),
            })?;
        if key.as_i64().is_some()
            || key.as_f64().is_some()
            || key.as_bool().is_some()
            || key.is_null()
        {
            return Err(SourceError::UnsupportedKey {
                format: SourceFormat::Yaml,
                path: path.clone(),
            });
        }
        let key = key.as_string();
        let child_path = path.child_key(key);
        if let Some(value) = entry.value_node() {
            walk_yaml_node(&value, &child_path, replacements, references)?;
        }
    }
    Ok(())
}

fn walk_yaml_sequence(
    sequence: &yaml_edit::Sequence,
    path: &NodePath,
    replacements: &mut Vec<YamlReplacement>,
    references: &mut Vec<NodePath>,
) -> Result<(), SourceError> {
    let mut semantic_index = 0;
    for value in sequence.values() {
        let child_path = path.child_index(semantic_index);
        if value.as_alias().is_some() {
            references.push(child_path);
        } else {
            walk_yaml_node(&value, &child_path, replacements, references)?;
            semantic_index += 1;
        }
    }
    Ok(())
}

fn walk_yaml_node(
    node: &yaml_edit::YamlNode,
    path: &NodePath,
    replacements: &mut Vec<YamlReplacement>,
    references: &mut Vec<NodePath>,
) -> Result<(), SourceError> {
    if node.as_alias().is_some() {
        references.push(path.clone());
    } else if let Some(scalar) = node.as_scalar() {
        add_yaml_scalar(scalar, path.clone(), replacements);
    } else if let Some(mapping) = node.as_mapping() {
        walk_yaml_mapping(mapping, path, replacements, references)?;
    } else if let Some(sequence) = node.as_sequence() {
        walk_yaml_sequence(sequence, path, replacements, references)?;
    } else if let Some(tagged) = node.as_tagged() {
        let scalar = tagged.value().ok_or_else(|| SourceError::Parse {
            format: SourceFormat::Yaml,
            reason: "tagged non-scalar values are unsupported".to_owned(),
        })?;
        add_yaml_scalar(&scalar, path.clone(), replacements);
    }
    Ok(())
}

fn add_yaml_scalar(
    scalar: &yaml_edit::Scalar,
    path: NodePath,
    replacements: &mut Vec<YamlReplacement>,
) {
    let range = scalar.byte_range();
    let token = format!("\u{001f}GITVEIL_VALUE_{:04}\u{001f}", replacements.len());
    replacements.push(YamlReplacement {
        start: range.start as usize,
        end: range.end as usize,
        token,
        path,
    });
}

fn render_scalar(node: &Node) -> Result<String, SourceError> {
    let value = to_yaml_value(node)?;
    let rendered = yaml_serde::to_string(&value).map_err(|error| SourceError::Generate {
        format: SourceFormat::Yaml,
        reason: error.to_string(),
    })?;
    Ok(rendered.trim_end_matches('\n').to_owned())
}

fn to_yaml_value(node: &Node) -> Result<yaml_serde::Value, SourceError> {
    match node {
        Node::Mapping(values) => {
            let mut mapping = yaml_serde::Mapping::new();
            for (key, value) in values {
                mapping.insert(
                    yaml_serde::Value::String(key.clone()),
                    to_yaml_value(value)?,
                );
            }
            Ok(yaml_serde::Value::Mapping(mapping))
        }
        Node::Sequence(values) => values
            .iter()
            .map(to_yaml_value)
            .collect::<Result<Vec<_>, _>>()
            .map(yaml_serde::Value::Sequence),
        Node::Scalar(Scalar::String(value) | Scalar::DateTime(value)) => {
            Ok(yaml_serde::Value::String(value.clone()))
        }
        Node::Scalar(Scalar::Integer(value)) => value
            .parse::<i64>()
            .map(yaml_serde::Number::from)
            .map(yaml_serde::Value::Number)
            .map_err(|error| generate_error(error.to_string())),
        Node::Scalar(Scalar::Float(value)) => value
            .parse::<f64>()
            .map(yaml_serde::Number::from)
            .map(yaml_serde::Value::Number)
            .map_err(|error| generate_error(error.to_string())),
        Node::Scalar(Scalar::Bool(value)) => Ok(yaml_serde::Value::Bool(*value)),
        Node::Scalar(Scalar::Null) => Ok(yaml_serde::Value::Null),
        Node::Tagged { tag, value } => Ok(yaml_serde::Value::Tagged(Box::new(
            yaml_serde::value::TaggedValue {
                tag: yaml_serde::value::Tag::new(tag),
                value: to_yaml_value(value)?,
            },
        ))),
    }
}

fn generate_error(reason: impl Into<String>) -> SourceError {
    SourceError::Generate {
        format: SourceFormat::Yaml,
        reason: reason.into(),
    }
}
