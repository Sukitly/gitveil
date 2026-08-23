use indexmap::IndexMap;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use super::{
    Layout, LineEnding, Node, NodePath, Placeholder, Scalar, SourceDocument, SourceError, Template,
};
use crate::config::SourceFormat;

pub(super) fn parse(input: &str) -> Result<SourceDocument, SourceError> {
    let value = toml::from_str::<toml::Value>(input).map_err(|error| SourceError::Parse {
        format: SourceFormat::Toml,
        reason: error.to_string(),
    })?;
    let root = from_value(value);
    let mut syntax = input
        .parse::<DocumentMut>()
        .map_err(|error| SourceError::Parse {
            format: SourceFormat::Toml,
            reason: error.to_string(),
        })?;
    let mut placeholders = Vec::new();
    scrub_table(syntax.as_table_mut(), &NodePath::root(), &mut placeholders);
    let mut layout = Layout::new(LineEnding::detect(input), input.ends_with('\n'));
    layout.set_template(Template::new(syntax.to_string(), placeholders));
    Ok(SourceDocument::new(SourceFormat::Toml, root, layout))
}

pub(super) fn generate(document: &SourceDocument) -> Result<Vec<u8>, SourceError> {
    let Some(template) = document.layout().template() else {
        return Err(generate_error("TOML layout template is missing"));
    };
    let mut syntax = template
        .body()
        .parse::<DocumentMut>()
        .map_err(|error| generate_error(error.to_string()))?;
    restore_table(syntax.as_table_mut(), document.root(), &NodePath::root())?;
    let mut output = syntax.to_string();
    if !document.layout().trailing_newline() {
        while output.ends_with('\n') {
            output.pop();
        }
    }
    Ok(document.layout().line_ending().apply(&output).into_bytes())
}

fn scrub_table(table: &mut Table, path: &NodePath, placeholders: &mut Vec<Placeholder>) {
    for (key, item) in table.iter_mut() {
        let child = path.child_key(key.get());
        scrub_item(item, &child, placeholders);
    }
}

fn scrub_item(item: &mut Item, path: &NodePath, placeholders: &mut Vec<Placeholder>) {
    match item {
        Item::None => {}
        Item::Value(value) => scrub_value(value, path, placeholders),
        Item::Table(table) => scrub_table(table, path, placeholders),
        Item::ArrayOfTables(tables) => scrub_array_of_tables(tables, path, placeholders),
    }
}

fn scrub_array_of_tables(
    tables: &mut ArrayOfTables,
    path: &NodePath,
    placeholders: &mut Vec<Placeholder>,
) {
    for (index, table) in tables.iter_mut().enumerate() {
        scrub_table(table, &path.child_index(index), placeholders);
    }
}

fn scrub_value(value: &mut Value, path: &NodePath, placeholders: &mut Vec<Placeholder>) {
    match value {
        Value::Array(array) => {
            for (index, value) in array.iter_mut().enumerate() {
                scrub_value(value, &path.child_index(index), placeholders);
            }
        }
        Value::InlineTable(table) => {
            for (key, value) in table.iter_mut() {
                scrub_value(value, &path.child_key(key.get()), placeholders);
            }
        }
        Value::String(formatted) => {
            let token = format!(
                "__GITVEIL_VALUE_{:04}__@{}",
                placeholders.len(),
                toml_string_style(formatted.display_repr().as_ref())
            );
            let decor = value.decor().clone();
            *value = Value::from(token.clone());
            *value.decor_mut() = decor;
            placeholders.push(Placeholder::new(token, path.clone()));
        }
        Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_) => {
            let token = format!("__GITVEIL_VALUE_{:04}__", placeholders.len());
            let decor = value.decor().clone();
            *value = Value::from(token.clone());
            *value.decor_mut() = decor;
            placeholders.push(Placeholder::new(token, path.clone()));
        }
    }
}

fn restore_table(table: &mut Table, node: &Node, path: &NodePath) -> Result<(), SourceError> {
    let Node::Mapping(values) = node else {
        return Err(SourceError::LayoutMismatch(path.clone()));
    };
    if table.len() != values.len() {
        return Err(SourceError::LayoutMismatch(path.clone()));
    }
    for (key, item) in table.iter_mut() {
        let child_path = path.child_key(key.get());
        let child = values
            .get(key.get())
            .ok_or_else(|| SourceError::LayoutMismatch(child_path.clone()))?;
        restore_item(item, child, &child_path)?;
    }
    Ok(())
}

fn restore_item(item: &mut Item, node: &Node, path: &NodePath) -> Result<(), SourceError> {
    match item {
        Item::None => Err(SourceError::LayoutMismatch(path.clone())),
        Item::Value(value) => restore_value(value, node, path),
        Item::Table(table) => restore_table(table, node, path),
        Item::ArrayOfTables(tables) => {
            let Node::Sequence(values) = node else {
                return Err(SourceError::LayoutMismatch(path.clone()));
            };
            if tables.len() != values.len() {
                return Err(SourceError::LayoutMismatch(path.clone()));
            }
            for (index, (table, value)) in tables.iter_mut().zip(values).enumerate() {
                restore_table(table, value, &path.child_index(index))?;
            }
            Ok(())
        }
    }
}

fn restore_value(value: &mut Value, node: &Node, path: &NodePath) -> Result<(), SourceError> {
    match value {
        Value::Array(array) => {
            let Node::Sequence(values) = node else {
                return Err(SourceError::LayoutMismatch(path.clone()));
            };
            if array.len() != values.len() {
                return Err(SourceError::LayoutMismatch(path.clone()));
            }
            for (index, (value, node)) in array.iter_mut().zip(values).enumerate() {
                restore_value(value, node, &path.child_index(index))?;
            }
            Ok(())
        }
        Value::InlineTable(table) => {
            let Node::Mapping(values) = node else {
                return Err(SourceError::LayoutMismatch(path.clone()));
            };
            if table.len() != values.len() {
                return Err(SourceError::LayoutMismatch(path.clone()));
            }
            for (key, value) in table.iter_mut() {
                let child_path = path.child_key(key.get());
                let child = values
                    .get(key.get())
                    .ok_or_else(|| SourceError::LayoutMismatch(child_path.clone()))?;
                restore_value(value, child, &child_path)?;
            }
            Ok(())
        }
        Value::String(token) if token.value().starts_with("__GITVEIL_VALUE_") => {
            let style = token
                .value()
                .split_once("__@")
                .map(|(_, style)| style.to_owned());
            let decor = value.decor().clone();
            *value = match (node, style.as_deref()) {
                (Node::Scalar(Scalar::String(value)), Some(style)) => {
                    styled_toml_string(value, style)?
                }
                _ => node_to_edit_value(node, path)?,
            };
            *value.decor_mut() = decor;
            Ok(())
        }
        _ => Err(SourceError::LayoutMismatch(path.clone())),
    }
}

fn toml_string_style(repr: &str) -> &'static str {
    let repr = repr.trim();
    if repr.starts_with("\"\"\"") {
        "mb"
    } else if repr.starts_with("'''") {
        "ml"
    } else if repr.starts_with('\'') {
        "sl"
    } else {
        "sb"
    }
}

fn styled_toml_string(value: &str, style: &str) -> Result<Value, SourceError> {
    let literal = match style {
        "sl" if !value.contains('\'') && !value.contains(['\n', '\r']) => format!("'{value}'"),
        "ml" if !value.contains("'''") && !value.starts_with(['\n', '\r']) => {
            format!("'''{value}'''")
        }
        "mb" => {
            let escaped = value
                .replace('\\', "\\\\")
                .replace("\"\"\"", "\\\"\\\"\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\u{0008}', "\\b")
                .replace('\u{000c}', "\\f");
            format!("\"\"\"{escaped}\"\"\"")
        }
        _ => serde_json::to_string(value).map_err(|error| generate_error(error.to_string()))?,
    };
    let document = format!("value = {literal}\n")
        .parse::<DocumentMut>()
        .map_err(|error| generate_error(error.to_string()))?;
    document
        .get("value")
        .and_then(Item::as_value)
        .cloned()
        .ok_or_else(|| generate_error("could not preserve TOML string style"))
}

fn node_to_edit_value(node: &Node, path: &NodePath) -> Result<Value, SourceError> {
    match node {
        Node::Scalar(Scalar::String(value)) => Ok(Value::from(value.clone())),
        Node::Scalar(Scalar::Integer(value)) => value
            .parse::<i64>()
            .map(Value::from)
            .map_err(|error| generate_error(error.to_string())),
        Node::Scalar(Scalar::Float(value)) => value
            .parse::<f64>()
            .map(Value::from)
            .map_err(|error| generate_error(error.to_string())),
        Node::Scalar(Scalar::Bool(value)) => Ok(Value::from(*value)),
        Node::Scalar(Scalar::DateTime(value)) => value
            .parse::<toml_edit::Datetime>()
            .map(Value::from)
            .map_err(|error| generate_error(error.to_string())),
        Node::Sequence(values) => {
            let mut array = Array::new();
            for (index, value) in values.iter().enumerate() {
                array.push(node_to_edit_value(value, &path.child_index(index))?);
            }
            Ok(Value::Array(array))
        }
        Node::Mapping(values) => {
            let mut table = InlineTable::new();
            for (key, value) in values {
                table.insert(key, node_to_edit_value(value, &path.child_key(key))?);
            }
            Ok(Value::InlineTable(table))
        }
        Node::Scalar(Scalar::Null) | Node::Tagged { .. } => {
            Err(SourceError::LayoutMismatch(path.clone()))
        }
    }
}

fn from_value(value: toml::Value) -> Node {
    match value {
        toml::Value::String(value) => Node::Scalar(Scalar::String(value)),
        toml::Value::Integer(value) => Node::Scalar(Scalar::Integer(value.to_string())),
        toml::Value::Float(value) => Node::Scalar(Scalar::Float(value.to_string())),
        toml::Value::Boolean(value) => Node::Scalar(Scalar::Bool(value)),
        toml::Value::Datetime(value) => Node::Scalar(Scalar::DateTime(value.to_string())),
        toml::Value::Array(values) => Node::Sequence(values.into_iter().map(from_value).collect()),
        toml::Value::Table(values) => Node::Mapping(
            values
                .into_iter()
                .map(|(key, value)| (key, from_value(value)))
                .collect::<IndexMap<_, _>>(),
        ),
    }
}

fn generate_error(reason: impl Into<String>) -> SourceError {
    SourceError::Generate {
        format: SourceFormat::Toml,
        reason: reason.into(),
    }
}
