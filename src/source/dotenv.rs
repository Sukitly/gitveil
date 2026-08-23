use indexmap::IndexMap;

use super::{
    DotenvLayout, Layout, LineEnding, Node, QuoteStyle, Scalar, SourceDocument, SourceError,
};
use crate::config::SourceFormat;

pub(super) fn parse(input: &str) -> Result<SourceDocument, SourceError> {
    let line_ending = LineEnding::detect(input);
    let normalized = input.replace("\r\n", "\n");
    let trailing_newline = normalized.ends_with('\n');
    let lines = normalized.split('\n').collect::<Vec<_>>();
    let mut values = IndexMap::new();
    let mut layouts = Vec::new();
    let mut pending = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        index += 1;
        if index == lines.len() && line.is_empty() && trailing_newline {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            pending.push(line.to_owned());
            continue;
        }

        let (exported, assignment) = if let Some(rest) = trimmed.strip_prefix("export ") {
            (true, rest.trim_start())
        } else {
            (false, trimmed)
        };
        let Some((key, raw_value)) = assignment.split_once('=') else {
            return Err(parse_error("expected KEY=VALUE assignment"));
        };
        if !valid_key(key) {
            return Err(parse_error("invalid dotenv key"));
        }
        if values.contains_key(key) {
            return Err(SourceError::DuplicateKey {
                format: SourceFormat::Dotenv,
                path: super::NodePath::root().child_key(key),
            });
        }

        let (value, quote, consumed, inline_comment) = parse_value(raw_value, &lines[index..])?;
        index += consumed;
        values.insert(key.to_owned(), Node::Scalar(Scalar::String(value)));
        layouts.push(DotenvLayout {
            key: key.to_owned(),
            exported,
            quote,
            leading: std::mem::take(&mut pending),
            inline_comment,
        });
    }

    let mut layout = Layout::new(line_ending, trailing_newline);
    layout.set_dotenv(layouts);
    layout.set_preamble_comments(pending);
    Ok(SourceDocument::new(
        SourceFormat::Dotenv,
        Node::Mapping(values),
        layout,
    ))
}

pub(super) fn generate(document: &SourceDocument) -> Result<Vec<u8>, SourceError> {
    let Node::Mapping(values) = document.root() else {
        return Err(generate_error("dotenv root must be a mapping"));
    };
    let mut output = String::new();
    for (key, node) in values {
        let Some(Scalar::String(value)) = node.scalar() else {
            return Err(generate_error("dotenv values must be strings"));
        };
        let style = document
            .layout()
            .dotenv()
            .iter()
            .find(|entry| entry.key == *key);
        if let Some(style) = style {
            for line in &style.leading {
                output.push_str(line);
                output.push('\n');
            }
            if style.exported {
                output.push_str("export ");
            }
            output.push_str(key);
            output.push('=');
            output.push_str(&render_value(value, style.quote));
            if let Some(comment) = &style.inline_comment {
                output.push(' ');
                output.push_str(comment);
            }
        } else {
            output.push_str(key);
            output.push('=');
            output.push_str(&render_value(value, QuoteStyle::Double));
        }
        output.push('\n');
    }
    for line in document.layout().preamble_comments() {
        output.push_str(line);
        output.push('\n');
    }
    if !document.layout().trailing_newline() {
        output.pop();
    }
    Ok(document.layout().line_ending().apply(&output).into_bytes())
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn parse_value(
    raw: &str,
    remaining: &[&str],
) -> Result<(String, QuoteStyle, usize, Option<String>), SourceError> {
    let raw = raw.trim_start();
    if let Some(value) = raw.strip_prefix('\'') {
        parse_quoted(value, remaining, '\'', QuoteStyle::Single)
    } else if let Some(value) = raw.strip_prefix('"') {
        parse_quoted(value, remaining, '"', QuoteStyle::Double)
    } else {
        let comment_index = raw.find(" #");
        let value = comment_index
            .map_or(raw, |index| &raw[..index])
            .trim_end()
            .to_owned();
        let comment = comment_index.map(|index| raw[index..].trim_start().to_owned());
        Ok((value, QuoteStyle::Unquoted, 0, comment))
    }
}

fn parse_quoted(
    first: &str,
    remaining: &[&str],
    quote: char,
    style: QuoteStyle,
) -> Result<(String, QuoteStyle, usize, Option<String>), SourceError> {
    let mut joined = first.to_owned();
    let mut consumed = 0;
    loop {
        if let Some(end) = find_unescaped(&joined, quote) {
            let suffix = joined[end + quote.len_utf8()..].trim();
            if !suffix.is_empty() && !suffix.starts_with('#') {
                return Err(parse_error("unexpected content after quoted value"));
            }
            let encoded = &joined[..end];
            let value = match style {
                QuoteStyle::Double => decode_double(encoded)?,
                QuoteStyle::Single | QuoteStyle::Unquoted => encoded.to_owned(),
            };
            let comment = (!suffix.is_empty()).then(|| suffix.to_owned());
            return Ok((value, style, consumed, comment));
        }
        let Some(next) = remaining.get(consumed) else {
            return Err(parse_error("unterminated quoted value"));
        };
        joined.push('\n');
        joined.push_str(next);
        consumed += 1;
    }
}

fn find_unescaped(value: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if character == quote && !escaped {
            return Some(index);
        }
        if character == '\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    None
}

fn decode_double(value: &str) -> Result<String, SourceError> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(parse_error("trailing escape in double-quoted value"));
        };
        decoded.push(match escaped {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '\\' => '\\',
            '"' => '"',
            other => other,
        });
    }
    Ok(decoded)
}

/// Renders a value in its preferred quote style when that rendering is a
/// parse fixed point, otherwise falls back to double quoting.
///
/// The candidate is verified against the real parser instead of an
/// approximated character allowlist: an unquoted value may legitimately
/// contain quote characters, commas, or equals signs, and inventing
/// escaping for such values changes what third-party dotenv loaders read.
fn render_value(value: &str, preferred: QuoteStyle) -> String {
    let candidate = match preferred {
        QuoteStyle::Unquoted => (!value.is_empty()).then(|| value.to_owned()),
        QuoteStyle::Single => Some(format!("'{value}'")),
        QuoteStyle::Double => None,
    };
    if let Some(candidate) = candidate
        && renders_back(&candidate, value, preferred)
    {
        return candidate;
    }
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\r', "\\r")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    )
}

/// Verifies that a rendered candidate parses back to exactly the same value
/// in the same style, with no line continuation or comment capture.
fn renders_back(candidate: &str, value: &str, style: QuoteStyle) -> bool {
    parse_value(candidate, &[]).is_ok_and(|(parsed, parsed_style, consumed, comment)| {
        parsed == value && parsed_style == style && consumed == 0 && comment.is_none()
    })
}

fn parse_error(reason: &str) -> SourceError {
    SourceError::Parse {
        format: SourceFormat::Dotenv,
        reason: reason.to_owned(),
    }
}

fn generate_error(reason: &str) -> SourceError {
    SourceError::Generate {
        format: SourceFormat::Dotenv,
        reason: reason.to_owned(),
    }
}
