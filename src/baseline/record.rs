//!
//! A baseline record captures the state of a managed pair at the last
//! successful `open`/`seal`/`resolve` as salted digests: one digest per
//! sync unit plus one digest for the residual layout. Digests answer only
//! "changed or not"; no plaintext value is stored.
//!
//! A sync unit is a top-level key together with the layout that travels
//! with it (its dotenv entry: leading comments, quoting, inline comment).
//! The residual layout holds only what no key owns: line ending, trailing
//! newline, and trailing file comments. A non-mapping root is one unit
//! covering the whole document including its layout.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::SourceFormat;
use crate::envelope::CiphertextEnvelope;
use crate::source::{DotenvLayout, Layout, Node, SourceDocument};

const VERSION: u32 = 1;
const SALT_BYTES: usize = 32;
const KEY_DOMAIN: &[u8] = b"gitveil-baseline-key-v1";
const LAYOUT_DOMAIN: &[u8] = b"gitveil-baseline-layout-v1";
const CIPHER_DOMAIN: &[u8] = b"gitveil-baseline-cipher-v1";
const CIPHER_LAYOUT_DOMAIN: &[u8] = b"gitveil-baseline-cipher-layout-v1";

/// One side's view of a sync unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitView<'a> {
    pub(crate) node: &'a Node,
    entry: Option<&'a DotenvLayout>,
    layout: Option<&'a Layout>,
}

/// Returns the view of one sync unit of a document, when present.
pub fn unit_view<'a>(document: &'a SourceDocument, key: &str) -> Option<UnitView<'a>> {
    match document.root() {
        Node::Mapping(values) => values.get(key).map(|node| UnitView {
            node,
            entry: document
                .layout()
                .dotenv()
                .iter()
                .find(|entry| entry.key == key),
            layout: None,
        }),
        root if key == BaselineRecord::ROOT_UNIT => Some(UnitView {
            node: root,
            entry: None,
            layout: Some(document.layout()),
        }),
        _ => None,
    }
}

/// Enumerates every sync unit of a document.
fn units_of(document: &SourceDocument) -> Vec<(String, UnitView<'_>)> {
    match document.root() {
        Node::Mapping(values) => values
            .keys()
            .filter_map(|key| unit_view(document, key).map(|view| (key.clone(), view)))
            .collect(),
        _ => unit_view(document, BaselineRecord::ROOT_UNIT)
            .map(|view| vec![(BaselineRecord::ROOT_UNIT.to_owned(), view)])
            .into_iter()
            .flatten()
            .collect(),
    }
}

/// The layout no key owns: line ending, trailing newline, and trailing file
/// comments. For non-dotenv formats the whole layout is residual.
pub(crate) fn residual_layout(document: &SourceDocument) -> Layout {
    let layout = document.layout();
    if document.format() == SourceFormat::Dotenv {
        let mut residual = Layout::new(layout.line_ending(), layout.trailing_newline());
        residual.set_preamble_comments(layout.preamble_comments().to_vec());
        residual
    } else {
        layout.clone()
    }
}

fn unit_bytes(view: &UnitView<'_>) -> Vec<u8> {
    // `Node`, `DotenvLayout`, and `Layout` serialize infallibly: every
    // mapping key is a string and numbers travel as strings. A panic here is
    // preferable to collapsing different units onto the digest of empty
    // bytes, which would silently corrupt arbitration.
    let mut bytes = serde_json::to_vec(view.node).expect("baseline unit node serializes");
    bytes.push(0);
    if let Some(entry) = view.entry {
        bytes.extend(serde_json::to_vec(entry).expect("baseline dotenv entry serializes"));
    }
    bytes.push(0);
    if let Some(layout) = view.layout {
        bytes.extend(serde_json::to_vec(layout).expect("baseline layout serializes"));
    }
    bytes
}

/// Per-unit fingerprints of a ciphertext envelope.
///
/// Thanks to per-leaf ciphertext stability, comparing the raw `ENC[...]`
/// strings answers "did this unit change" without any decryption, which is
/// what keeps `status` keyless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherSummary {
    units: BTreeMap<String, String>,
    layout: String,
}

impl CipherSummary {
    pub fn from_envelope(envelope: &CiphertextEnvelope) -> Self {
        let mut units: BTreeMap<String, String> = BTreeMap::new();
        for (path, leaf) in envelope.leaf_ciphertexts() {
            let unit = unit_of(path);
            let entry = units.entry(unit.to_owned()).or_default();
            entry.push_str(path);
            entry.push('=');
            entry.push_str(leaf);
            entry.push('\n');
        }
        Self {
            units,
            layout: envelope.layout_ciphertext().to_owned(),
        }
    }

    pub(crate) fn unit_names(&self) -> impl Iterator<Item = &str> {
        self.units.keys().map(String::as_str)
    }

    /// Empty summary for pure plan tests that do not involve ciphertext.
    #[cfg(test)]
    pub(crate) fn empty_for_tests() -> Self {
        Self {
            units: BTreeMap::new(),
            layout: String::new(),
        }
    }
}

/// Maps a leaf path rendered by `NodePath::Display` onto its top-level unit.
///
/// Keys containing `.` in nested formats may be attributed to a parent unit;
/// that only widens change detection, never narrows it.
fn unit_of(path: &str) -> &str {
    if path.starts_with('[') || path == "$" {
        return BaselineRecord::ROOT_UNIT;
    }
    let end = path.find(['.', '[']).unwrap_or(path.len());
    &path[..end]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineRecord {
    version: u32,
    salt: String,
    keys: BTreeMap<String, String>,
    layout: String,
    cipher_units: BTreeMap<String, String>,
    cipher_layout: String,
}

/// Directionless difference sets against the recorded baseline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BaselineDiff {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub layout_changed: bool,
}

impl BaselineDiff {
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
            && self.added.is_empty()
            && self.removed.is_empty()
            && !self.layout_changed
    }
}

impl BaselineRecord {
    /// Unit name used when the document root is not a mapping and the whole
    /// document is treated as a single unit.
    pub const ROOT_UNIT: &'static str = "$";

    pub fn capture(document: &SourceDocument, cipher: &CipherSummary, salt: [u8; 32]) -> Self {
        let keys = units_of(document)
            .into_iter()
            .map(|(key, view)| {
                (
                    key.clone(),
                    digest(KEY_DOMAIN, &salt, key.as_bytes(), &unit_bytes(&view)),
                )
            })
            .collect();
        let cipher_units = cipher
            .units
            .iter()
            .map(|(unit, body)| {
                (
                    unit.clone(),
                    digest(CIPHER_DOMAIN, &salt, unit.as_bytes(), body.as_bytes()),
                )
            })
            .collect();
        Self {
            version: VERSION,
            salt: hex::encode(salt),
            keys,
            layout: digest(
                LAYOUT_DOMAIN,
                &salt,
                b"",
                &layout_bytes(&residual_layout(document)),
            ),
            cipher_units,
            cipher_layout: digest(CIPHER_LAYOUT_DOMAIN, &salt, b"", cipher.layout.as_bytes()),
        }
    }

    /// Answers whether `view` matches the recorded digest for `key`.
    ///
    /// Returns `None` when the key was not recorded, so callers can
    /// distinguish additions from modifications.
    pub fn unit_matches(&self, key: &str, view: Option<&UnitView<'_>>) -> Option<bool> {
        let recorded = self.keys.get(key)?;
        let salt = self.salt_bytes();
        Some(view.is_some_and(|view| {
            &digest(KEY_DOMAIN, &salt, key.as_bytes(), &unit_bytes(view)) == recorded
        }))
    }

    pub fn has_key(&self, key: &str) -> bool {
        self.keys.contains_key(key)
    }

    /// Answers whether the document's residual layout matches the record.
    pub fn residual_layout_matches(&self, document: &SourceDocument) -> bool {
        digest(
            LAYOUT_DOMAIN,
            &self.salt_bytes(),
            b"",
            &layout_bytes(&residual_layout(document)),
        ) == self.layout
    }

    /// Diffs the current plaintext document against the recorded plain-side
    /// digests.
    pub fn diff_plain(&self, document: &SourceDocument) -> BaselineDiff {
        let salt = self.salt_bytes();
        let current: BTreeMap<String, String> = units_of(document)
            .into_iter()
            .map(|(key, view)| {
                (
                    key.clone(),
                    digest(KEY_DOMAIN, &salt, key.as_bytes(), &unit_bytes(&view)),
                )
            })
            .collect();
        diff_maps(
            &self.keys,
            &current,
            !self.residual_layout_matches(document),
        )
    }

    /// Diffs the current ciphertext summary against the recorded cipher-side
    /// digests; needs no decryption.
    pub fn diff_cipher(&self, cipher: &CipherSummary) -> BaselineDiff {
        let salt = self.salt_bytes();
        let current = cipher
            .units
            .iter()
            .map(|(unit, body)| {
                (
                    unit.clone(),
                    digest(CIPHER_DOMAIN, &salt, unit.as_bytes(), body.as_bytes()),
                )
            })
            .collect();
        let layout_changed = digest(CIPHER_LAYOUT_DOMAIN, &salt, b"", cipher.layout.as_bytes())
            != self.cipher_layout;
        diff_maps(&self.cipher_units, &current, layout_changed)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, BaselineError> {
        serde_json::to_vec(self).map_err(|error| BaselineError::Serialize(error.to_string()))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, BaselineError> {
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| BaselineError::Deserialize(error.to_string()))?;
        if record.version != VERSION {
            return Err(BaselineError::UnsupportedVersion(record.version));
        }
        // Every digest in the record was computed with a 32-byte salt; a
        // record that does not carry one cannot arbitrate anything.
        match hex::decode(&record.salt) {
            Ok(salt) if salt.len() == SALT_BYTES => Ok(record),
            _ => Err(BaselineError::Deserialize(
                "baseline salt is not 32 hexadecimal bytes".to_owned(),
            )),
        }
    }

    fn salt_bytes(&self) -> Vec<u8> {
        // Both constructors guarantee the encoding: `capture` hex-encodes a
        // 32-byte salt and `from_json` rejects records without one.
        hex::decode(&self.salt).expect("baseline salt is validated at construction")
    }
}

fn layout_bytes(layout: &Layout) -> Vec<u8> {
    // See `unit_bytes`: layout serialization is infallible, and a panic is
    // preferable to digesting empty bytes.
    serde_json::to_vec(layout).expect("baseline layout serializes")
}

fn diff_maps(
    recorded: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    layout_changed: bool,
) -> BaselineDiff {
    let mut diff = BaselineDiff {
        layout_changed,
        ..BaselineDiff::default()
    };
    for (key, digest) in current {
        match recorded.get(key) {
            None => diff.added.push(key.clone()),
            Some(recorded) if recorded != digest => diff.changed.push(key.clone()),
            Some(_) => {}
        }
    }
    for key in recorded.keys() {
        if !current.contains_key(key) {
            diff.removed.push(key.clone());
        }
    }
    diff
}

fn digest(domain: &[u8], salt: &[u8], name: &[u8], body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((salt.len() as u64).to_be_bytes());
    hasher.update(salt);
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("could not serialize baseline record: {0}")]
    Serialize(String),
    #[error("could not deserialize baseline record: {0}")]
    Deserialize(String),
    #[error("unsupported baseline record version {0}")]
    UnsupportedVersion(u32),
}
