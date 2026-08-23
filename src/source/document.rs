use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use similar::{DiffTag, TextDiff};
use thiserror::Error;
use zeroize::Zeroize;

use crate::config::SourceFormat;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Scalar {
    String(String),
    Integer(String),
    Float(String),
    Bool(bool),
    Null,
    DateTime(String),
}

impl Drop for Scalar {
    fn drop(&mut self) {
        match self {
            Self::String(value)
            | Self::Integer(value)
            | Self::Float(value)
            | Self::DateTime(value) => value.zeroize(),
            Self::Bool(value) => *value = false,
            Self::Null => {}
        }
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::String(_) => "string",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
            Self::Null => "null",
            Self::DateTime(_) => "datetime",
        };
        formatter.write_str("<redacted:")?;
        formatter.write_str(kind)?;
        formatter.write_str(">")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "node", content = "value", rename_all = "snake_case")]
pub enum Node {
    Mapping(IndexMap<String, Node>),
    Sequence(Vec<Node>),
    Scalar(Scalar),
    Tagged { tag: String, value: Box<Node> },
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Mapping(left), Self::Mapping(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(
                        |((left_key, left_value), (right_key, right_value))| {
                            left_key == right_key && left_value == right_value
                        },
                    )
            }
            (Self::Sequence(left), Self::Sequence(right)) => left == right,
            (Self::Scalar(left), Self::Scalar(right)) => left == right,
            (
                Self::Tagged {
                    tag: left_tag,
                    value: left_value,
                },
                Self::Tagged {
                    tag: right_tag,
                    value: right_value,
                },
            ) => left_tag == right_tag && left_value == right_value,
            _ => false,
        }
    }
}

impl Eq for Node {}

impl fmt::Debug for Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(values) => formatter.debug_map().entries(values.iter()).finish(),
            Self::Sequence(values) => formatter.debug_list().entries(values).finish(),
            Self::Scalar(value) => value.fmt(formatter),
            Self::Tagged { tag, value } => formatter
                .debug_struct("Tagged")
                .field("tag", tag)
                .field("value", value)
                .finish(),
        }
    }
}

impl Node {
    pub(crate) fn remove_at_path(&mut self, path: &NodePath) -> bool {
        self.remove_at_segments(path.segments())
    }

    fn remove_at_segments(&mut self, segments: &[PathSegment]) -> bool {
        let Some((head, tail)) = segments.split_first() else {
            return false;
        };
        if tail.is_empty() {
            return match (self, head) {
                (Self::Mapping(values), PathSegment::Key(key)) => {
                    values.shift_remove(key).is_some()
                }
                (Self::Sequence(values), PathSegment::Index(index)) if *index < values.len() => {
                    values.remove(*index);
                    true
                }
                _ => false,
            };
        }
        match (self, head) {
            (Self::Mapping(values), PathSegment::Key(key)) => values
                .get_mut(key)
                .is_some_and(|value| value.remove_at_segments(tail)),
            (Self::Sequence(values), PathSegment::Index(index)) => values
                .get_mut(*index)
                .is_some_and(|value| value.remove_at_segments(tail)),
            (Self::Tagged { value, .. }, _) => value.remove_at_segments(segments),
            _ => false,
        }
    }

    pub fn mapping_keys(&self) -> Option<Vec<&str>> {
        let Self::Mapping(values) = self else {
            return None;
        };
        Some(values.keys().map(String::as_str).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Self> {
        let Self::Mapping(values) = self else {
            return None;
        };
        values.get(key)
    }

    pub fn at_path(&self, path: &NodePath) -> Option<&Self> {
        let mut current = self;
        for segment in path.segments() {
            while let Self::Tagged { value, .. } = current {
                current = value;
            }
            current = match (segment, current) {
                (PathSegment::Key(key), Self::Mapping(values)) => values.get(key)?,
                (PathSegment::Index(index), Self::Sequence(values)) => values.get(*index)?,
                _ => return None,
            };
        }
        Some(current)
    }

    pub(crate) fn scalar(&self) -> Option<&Scalar> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::Tagged { value, .. } => value.scalar(),
            Self::Mapping(_) | Self::Sequence(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PathSegment {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodePath(Vec<PathSegment>);

impl NodePath {
    pub fn root() -> Self {
        Self::default()
    }

    pub fn child_key(&self, key: impl Into<String>) -> Self {
        let mut segments = self.0.clone();
        segments.push(PathSegment::Key(key.into()));
        Self(segments)
    }

    pub fn child_index(&self, index: usize) -> Self {
        let mut segments = self.0.clone();
        segments.push(PathSegment::Index(index));
        Self(segments)
    }

    pub(crate) fn segments(&self) -> &[PathSegment] {
        &self.0
    }
}

impl fmt::Display for NodePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("$");
        }
        for (index, segment) in self.0.iter().enumerate() {
            match segment {
                PathSegment::Key(key) => {
                    if index > 0 {
                        formatter.write_str(".")?;
                    }
                    formatter.write_str(key)?;
                }
                PathSegment::Index(value) => write!(formatter, "[{value}]")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineEnding {
    Lf,
    CrLf,
}

impl LineEnding {
    pub(crate) fn detect(input: &str) -> Self {
        if input.contains("\r\n") {
            Self::CrLf
        } else {
            Self::Lf
        }
    }

    pub(crate) fn apply(self, value: &str) -> String {
        match self {
            Self::Lf => value.replace("\r\n", "\n"),
            Self::CrLf => value.replace("\r\n", "\n").replace('\n', "\r\n"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placeholder {
    token: String,
    path: NodePath,
}

impl Placeholder {
    pub(crate) fn new(token: String, path: NodePath) -> Self {
        Self { token, path }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn path(&self) -> &NodePath {
        &self.path
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    body: String,
    placeholders: Vec<Placeholder>,
}

impl Template {
    pub(crate) fn new(body: String, placeholders: Vec<Placeholder>) -> Self {
        Self { body, placeholders }
    }

    pub(crate) fn body(&self) -> &str {
        &self.body
    }

    pub(crate) fn placeholders(&self) -> &[Placeholder] {
        &self.placeholders
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DotenvLayout {
    pub key: String,
    pub(crate) exported: bool,
    pub(crate) quote: QuoteStyle,
    pub(crate) leading: Vec<String>,
    pub(crate) inline_comment: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStyle {
    Unquoted,
    Single,
    Double,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    line_ending: LineEnding,
    trailing_newline: bool,
    #[serde(default)]
    preamble_comments: Vec<String>,
    #[serde(default)]
    dotenv: Vec<DotenvLayout>,
    template: Option<Template>,
}

impl Drop for Layout {
    fn drop(&mut self) {
        for comment in &mut self.preamble_comments {
            comment.zeroize();
        }
        for entry in &mut self.dotenv {
            for line in &mut entry.leading {
                line.zeroize();
            }
            if let Some(comment) = &mut entry.inline_comment {
                comment.zeroize();
            }
        }
        if let Some(template) = &mut self.template {
            template.body.zeroize();
        }
    }
}

impl Layout {
    pub fn new(line_ending: LineEnding, trailing_newline: bool) -> Self {
        Self {
            line_ending,
            trailing_newline,
            preamble_comments: Vec::new(),
            dotenv: Vec::new(),
            template: None,
        }
    }

    pub(crate) fn line_ending(&self) -> LineEnding {
        self.line_ending
    }

    pub(crate) fn trailing_newline(&self) -> bool {
        self.trailing_newline
    }

    pub(crate) fn set_preamble_comments(&mut self, comments: Vec<String>) {
        self.preamble_comments = comments;
    }

    pub(crate) fn preamble_comments(&self) -> &[String] {
        &self.preamble_comments
    }

    pub(crate) fn set_dotenv(&mut self, entries: Vec<DotenvLayout>) {
        self.dotenv = entries;
    }

    pub fn dotenv(&self) -> &[DotenvLayout] {
        &self.dotenv
    }

    pub(crate) fn set_template(&mut self, template: Template) {
        self.template = Some(template);
    }

    pub(crate) fn template(&self) -> Option<&Template> {
        self.template.as_ref()
    }

    pub fn merge_three_way(base: &Self, ours: &Self, theirs: &Self) -> Option<Self> {
        if ours == theirs {
            return Some(ours.clone());
        }
        if ours == base {
            return Some(theirs.clone());
        }
        if theirs == base {
            return Some(ours.clone());
        }
        Some(Self {
            line_ending: merge_field(&base.line_ending, &ours.line_ending, &theirs.line_ending)?,
            trailing_newline: merge_field(
                &base.trailing_newline,
                &ours.trailing_newline,
                &theirs.trailing_newline,
            )?,
            preamble_comments: merge_field(
                &base.preamble_comments,
                &ours.preamble_comments,
                &theirs.preamble_comments,
            )?,
            dotenv: merge_dotenv(&base.dotenv, &ours.dotenv, &theirs.dotenv)?,
            template: merge_template(
                base.template.as_ref(),
                ours.template.as_ref(),
                theirs.template.as_ref(),
            )
            .ok()?,
        })
    }
}

fn merge_field<T: Clone + PartialEq>(base: &T, ours: &T, theirs: &T) -> Option<T> {
    if ours == theirs {
        Some(ours.clone())
    } else if ours == base {
        Some(theirs.clone())
    } else if theirs == base {
        Some(ours.clone())
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LineHunk {
    start: usize,
    end: usize,
    replacement: String,
}

fn merge_template(
    base: Option<&Template>,
    ours: Option<&Template>,
    theirs: Option<&Template>,
) -> std::result::Result<Option<Template>, ()> {
    if ours == theirs {
        return Ok(ours.cloned());
    }
    if ours == base {
        return Ok(theirs.cloned());
    }
    if theirs == base {
        return Ok(ours.cloned());
    }
    let (Some(base), Some(ours), Some(theirs)) = (base, ours, theirs) else {
        return Err(());
    };
    if base.placeholders != ours.placeholders || base.placeholders != theirs.placeholders {
        return Err(());
    }
    let body = merge_text_lines(&base.body, &ours.body, &theirs.body).ok_or(())?;
    Ok(Some(Template::new(body, base.placeholders.clone())))
}

fn merge_text_lines(base: &str, ours: &str, theirs: &str) -> Option<String> {
    let mut hunks = line_hunks(base, ours);
    for their_hunk in line_hunks(base, theirs) {
        if let Some(our_hunk) = hunks
            .iter()
            .find(|hunk| line_hunks_overlap(hunk, &their_hunk))
        {
            if our_hunk != &their_hunk {
                return None;
            }
        } else {
            hunks.push(their_hunk);
        }
    }
    hunks.sort_by_key(|hunk| (hunk.start, hunk.end));
    let lines = base.split_inclusive('\n').collect::<Vec<_>>();
    let mut merged = String::with_capacity(base.len());
    let mut cursor = 0;
    for hunk in hunks {
        if hunk.start < cursor || hunk.end > lines.len() {
            return None;
        }
        merged.push_str(&lines[cursor..hunk.start].concat());
        merged.push_str(&hunk.replacement);
        cursor = hunk.end;
    }
    merged.push_str(&lines[cursor..].concat());
    Some(merged)
}

fn line_hunks(base: &str, side: &str) -> Vec<LineHunk> {
    let side_lines = side.split_inclusive('\n').collect::<Vec<_>>();
    TextDiff::from_lines(base, side)
        .ops()
        .iter()
        .filter(|operation| operation.tag() != DiffTag::Equal)
        .map(|operation| LineHunk {
            start: operation.old_range().start,
            end: operation.old_range().end,
            replacement: side_lines[operation.new_range()].concat(),
        })
        .collect()
}

fn line_hunks_overlap(left: &LineHunk, right: &LineHunk) -> bool {
    if left.start == left.end && right.start == right.end {
        return left.start == right.start;
    }
    left.start < right.end && right.start < left.end
        || left.start == right.start
        || left.end == right.end && left.start != left.end && right.start != right.end
}

fn merge_dotenv(
    base: &[DotenvLayout],
    ours: &[DotenvLayout],
    theirs: &[DotenvLayout],
) -> Option<Vec<DotenvLayout>> {
    let shared = base
        .iter()
        .filter(|entry| {
            ours.iter().any(|other| other.key == entry.key)
                && theirs.iter().any(|other| other.key == entry.key)
        })
        .map(|entry| entry.key.clone())
        .collect::<Vec<_>>();
    let shared_order = |entries: &[DotenvLayout]| {
        entries
            .iter()
            .filter(|entry| shared.contains(&entry.key))
            .map(|entry| entry.key.clone())
            .collect::<Vec<_>>()
    };
    let base_shared = shared_order(base);
    let ours_shared = shared_order(ours);
    let theirs_shared = shared_order(theirs);
    let (primary, secondary) = if ours_shared == theirs_shared {
        (ours, theirs)
    } else if ours_shared == base_shared {
        (theirs, ours)
    } else if theirs_shared == base_shared {
        (ours, theirs)
    } else {
        return None;
    };
    let mut order = Vec::with_capacity(base.len().max(ours.len()).max(theirs.len()));
    for entries in [primary, secondary, base] {
        for entry in entries {
            if !order.contains(&entry.key) {
                order.push(entry.key.clone());
            }
        }
    }
    let mut merged = Vec::with_capacity(order.len());
    for key in order {
        let base_entry = base.iter().find(|entry| entry.key == key);
        let our_entry = ours.iter().find(|entry| entry.key == key);
        let their_entry = theirs.iter().find(|entry| entry.key == key);
        let entry = merge_field(&base_entry, &our_entry, &their_entry)?;
        if let Some(entry) = entry {
            merged.push(entry.clone());
        }
    }
    Some(merged)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDocument {
    format: SourceFormat,
    root: Node,
    layout: Layout,
}

impl fmt::Debug for SourceDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceDocument")
            .field("format", &self.format)
            .field("root", &self.root)
            .field("layout", &self.layout)
            .finish()
    }
}

impl SourceDocument {
    pub fn new(format: SourceFormat, root: Node, layout: Layout) -> Self {
        Self {
            format,
            root,
            layout,
        }
    }

    pub(crate) fn format(&self) -> SourceFormat {
        self.format
    }

    pub fn root(&self) -> &Node {
        &self.root
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn semantic_eq(&self, other: &Self) -> bool {
        self.format == other.format && self.root == other.root && self.layout == other.layout
    }

    pub fn generate(&self) -> Result<Vec<u8>, SourceError> {
        super::generate(self)
    }
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("{format} input is not UTF-8")]
    NonUtf8 { format: SourceFormat },
    #[error("invalid {format} document")]
    Parse {
        format: SourceFormat,
        reason: String,
    },
    #[error("duplicate key {path} in {format} document")]
    DuplicateKey {
        format: SourceFormat,
        path: NodePath,
    },
    #[error("unsupported key at {path} in {format} document")]
    UnsupportedKey {
        format: SourceFormat,
        path: NodePath,
    },
    #[error("unresolved conflict markers in {format} document")]
    ConflictMarkers { format: SourceFormat },
    #[error("could not generate {format} document")]
    Generate {
        format: SourceFormat,
        reason: String,
    },
    #[error("layout does not match semantic node at {0}")]
    LayoutMismatch(NodePath),
}
