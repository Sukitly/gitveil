//!
//! Pure key-wise `open` arbitration: merges the decrypted remote document
//! into the local plaintext using the baseline record as the three-way
//! referee. Sync units carry a key's value together with its attached
//! layout (dotenv entry); the residual layout (line ending, trailing
//! newline, trailing comments) is arbitrated as one extra unit. Without a
//! baseline the plan degrades to conservative mode: disagreements become
//! reported conflicts and local-only units are always preserved.

use indexmap::IndexMap;

use crate::baseline::{BaselineRecord, UnitView, residual_layout, unit_view};
use crate::source::{DotenvLayout, Layout, Node, SourceDocument};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OpenConflict {
    /// Both sides changed the key to different values; the local value wins.
    Key(String),
    /// The local value changed while the remote side deleted the key; the
    /// local value wins.
    DeletedRemotely(String),
    /// The local side deleted the key while the remote value changed; the
    /// local deletion wins.
    DeletedLocally(String),
    /// Both sides changed the residual layout; the local layout wins.
    Layout,
    /// The structural merge cannot be rendered for this format; the local
    /// file is left untouched and must be reconciled manually.
    Structural,
}

impl OpenConflict {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Key(key) => format!("key {key}: changed locally and remotely; local value kept"),
            Self::DeletedRemotely(key) => {
                format!("key {key}: changed locally but deleted remotely; local value kept")
            }
            Self::DeletedLocally(key) => {
                format!("key {key}: deleted locally but changed remotely; local deletion kept")
            }
            Self::Layout => "layout: changed locally and remotely; local layout kept".to_owned(),
            Self::Structural => {
                "structural changes on both sides cannot be merged for this format; \
                 file left unchanged"
                    .to_owned()
            }
        }
    }
}

pub(super) struct OpenPlan {
    /// Document to write to the plaintext file; `None` leaves the file as is.
    pub document: Option<SourceDocument>,
    pub conflicts: Vec<OpenConflict>,
}

pub(super) fn plan_open(
    local: Option<&SourceDocument>,
    remote: &SourceDocument,
    baseline: Option<&BaselineRecord>,
) -> OpenPlan {
    let Some(local) = local else {
        return OpenPlan {
            document: Some(remote.clone()),
            conflicts: Vec::new(),
        };
    };
    let mut conflicts = Vec::new();
    let document = match (local.root(), remote.root()) {
        (Node::Mapping(_), Node::Mapping(_)) => {
            merge_documents(local, remote, baseline, &mut conflicts)
        }
        _ => merge_whole_document(local, remote, baseline, &mut conflicts),
    };
    if document.semantic_eq(local) {
        return OpenPlan {
            document: None,
            conflicts,
        };
    }
    if document.generate().is_err() {
        conflicts.push(OpenConflict::Structural);
        return OpenPlan {
            document: None,
            conflicts,
        };
    }
    OpenPlan {
        document: Some(document),
        conflicts,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Local,
    Remote,
}

fn merge_documents(
    local: &SourceDocument,
    remote: &SourceDocument,
    baseline: Option<&BaselineRecord>,
    conflicts: &mut Vec<OpenConflict>,
) -> SourceDocument {
    let local_keys: Vec<String> = local
        .root()
        .mapping_keys()
        .map(|keys| keys.into_iter().map(str::to_owned).collect())
        .unwrap_or_default();
    let remote_keys: Vec<String> = remote
        .root()
        .mapping_keys()
        .map(|keys| keys.into_iter().map(str::to_owned).collect())
        .unwrap_or_default();

    let mut merged: IndexMap<String, (Node, Side)> = IndexMap::new();

    // Local keys first, preserving local order; per-unit arbitration.
    for key in &local_keys {
        let local_view = unit_view(local, key);
        let remote_view = unit_view(remote, key);
        match (&local_view, &remote_view) {
            (Some(local_view), Some(remote_view)) => {
                if local_view == remote_view {
                    merged.insert(key.clone(), (local_view.node.clone(), Side::Local));
                    continue;
                }
                match arbitrate(baseline, key, Some(local_view), Some(remote_view)) {
                    Arbitration::TakeRemote => {
                        merged.insert(key.clone(), (remote_view.node.clone(), Side::Remote));
                    }
                    Arbitration::KeepLocal => {
                        merged.insert(key.clone(), (local_view.node.clone(), Side::Local));
                    }
                    Arbitration::Conflict => {
                        conflicts.push(OpenConflict::Key(key.clone()));
                        merged.insert(key.clone(), (local_view.node.clone(), Side::Local));
                    }
                }
            }
            (Some(local_view), None) => {
                match arbitrate(baseline, key, Some(local_view), None) {
                    // Remote deleted an unchanged local key: propagate.
                    Arbitration::TakeRemote => {}
                    Arbitration::KeepLocal => {
                        merged.insert(key.clone(), (local_view.node.clone(), Side::Local));
                    }
                    Arbitration::Conflict => {
                        conflicts.push(OpenConflict::DeletedRemotely(key.clone()));
                        merged.insert(key.clone(), (local_view.node.clone(), Side::Local));
                    }
                }
            }
            _ => {}
        }
    }

    // Remote-only keys: insert after their nearest preceding remote key that
    // exists in the merged result, otherwise append at the end.
    for (index, key) in remote_keys.iter().enumerate() {
        if local_keys.contains(key) {
            continue;
        }
        let Some(remote_view) = unit_view(remote, key) else {
            continue;
        };
        match arbitrate(baseline, key, None, Some(&remote_view)) {
            Arbitration::TakeRemote => {
                let anchor = remote_keys[..index]
                    .iter()
                    .rev()
                    .find_map(|candidate| merged.get_index_of(candidate));
                let value = (remote_view.node.clone(), Side::Remote);
                match anchor {
                    Some(anchor) => {
                        merged.shift_insert(anchor + 1, key.clone(), value);
                    }
                    None => {
                        merged.insert(key.clone(), value);
                    }
                }
            }
            // Local deletion of an unchanged remote key stands.
            Arbitration::KeepLocal => {}
            Arbitration::Conflict => {
                conflicts.push(OpenConflict::DeletedLocally(key.clone()));
            }
        }
    }

    let residual = choose_residual_layout(local, remote, baseline, conflicts);
    let layout = assemble_layout(&merged, residual, local, remote);
    let root = Node::Mapping(
        merged
            .into_iter()
            .map(|(key, (node, _))| (key, node))
            .collect(),
    );
    SourceDocument::new(local.format(), root, layout)
}

enum Arbitration {
    TakeRemote,
    KeepLocal,
    Conflict,
}

fn arbitrate(
    baseline: Option<&BaselineRecord>,
    key: &str,
    local: Option<&UnitView<'_>>,
    remote: Option<&UnitView<'_>>,
) -> Arbitration {
    let Some(baseline) = baseline else {
        // Conservative mode: keep everything local; only remote additions
        // (no local counterpart) sync down.
        return match (local, remote) {
            (None, Some(_)) => Arbitration::TakeRemote,
            (Some(_), None) => Arbitration::KeepLocal,
            _ => Arbitration::Conflict,
        };
    };
    let local_matches = baseline.unit_matches(key, local);
    let remote_matches = baseline.unit_matches(key, remote);
    match (local_matches, remote_matches) {
        // Unit was never recorded: both sides introduced it independently.
        (None, None) => match (local, remote) {
            (None, Some(_)) => Arbitration::TakeRemote,
            (Some(_), None) => Arbitration::KeepLocal,
            _ => Arbitration::Conflict,
        },
        (Some(true), _) => Arbitration::TakeRemote,
        (_, Some(true)) => Arbitration::KeepLocal,
        _ => Arbitration::Conflict,
    }
}

fn merge_whole_document(
    local: &SourceDocument,
    remote: &SourceDocument,
    baseline: Option<&BaselineRecord>,
    conflicts: &mut Vec<OpenConflict>,
) -> SourceDocument {
    let local_view = unit_view(local, BaselineRecord::ROOT_UNIT);
    let remote_view = unit_view(remote, BaselineRecord::ROOT_UNIT);
    if local_view == remote_view {
        return local.clone();
    }
    match arbitrate(
        baseline,
        BaselineRecord::ROOT_UNIT,
        local_view.as_ref(),
        remote_view.as_ref(),
    ) {
        Arbitration::TakeRemote => remote.clone(),
        Arbitration::KeepLocal => local.clone(),
        Arbitration::Conflict => {
            conflicts.push(OpenConflict::Key(BaselineRecord::ROOT_UNIT.to_owned()));
            local.clone()
        }
    }
}

/// Chooses the residual-layout winner via the same three-way arbitration.
fn choose_residual_layout(
    local: &SourceDocument,
    remote: &SourceDocument,
    baseline: Option<&BaselineRecord>,
    conflicts: &mut Vec<OpenConflict>,
) -> Layout {
    let local_residual = residual_layout(local);
    let remote_residual = residual_layout(remote);
    if local_residual == remote_residual {
        return local_residual;
    }
    let Some(baseline) = baseline else {
        return local_residual;
    };
    if baseline.residual_layout_matches(local) {
        return remote_residual;
    }
    if baseline.residual_layout_matches(remote) {
        return local_residual;
    }
    conflicts.push(OpenConflict::Layout);
    local_residual
}

/// Builds the final layout: the residual winner plus each merged key's entry
/// from its chosen side (falling back to the other side's entry).
fn assemble_layout(
    merged: &IndexMap<String, (Node, Side)>,
    residual: Layout,
    local: &SourceDocument,
    remote: &SourceDocument,
) -> Layout {
    let entry_of = |document: &SourceDocument, key: &str| -> Option<DotenvLayout> {
        document
            .layout()
            .dotenv()
            .iter()
            .find(|entry| entry.key == key)
            .cloned()
    };
    let mut entries = Vec::with_capacity(merged.len());
    for (key, (_, side)) in merged {
        let (primary, secondary) = match side {
            Side::Local => (local, remote),
            Side::Remote => (remote, local),
        };
        if let Some(entry) = entry_of(primary, key).or_else(|| entry_of(secondary, key)) {
            entries.push(entry);
        }
    }
    let mut layout = residual;
    layout.set_dotenv(entries);
    // Template layouts (non-dotenv formats) travel whole; the residual
    // already carries the winning template.
    layout
}

#[cfg(test)]
mod tests {
    use crate::baseline::BaselineRecord;
    use crate::config::SourceFormat;
    use crate::source::parse;

    use super::{OpenConflict, plan_open};

    const SALT: [u8; 32] = [3; 32];

    fn capture(document: &crate::source::SourceDocument) -> BaselineRecord {
        BaselineRecord::capture(
            document,
            &crate::baseline::CipherSummary::empty_for_tests(),
            SALT,
        )
    }

    fn document(body: &str) -> crate::source::SourceDocument {
        parse(SourceFormat::Dotenv, body.as_bytes()).expect("document")
    }

    fn rendered(plan: &super::OpenPlan) -> String {
        String::from_utf8(
            plan.document
                .as_ref()
                .expect("plan document")
                .generate()
                .expect("generate"),
        )
        .expect("utf-8")
    }

    #[test]
    fn missing_local_file_materializes_the_remote_document() {
        let remote = document("# hello\nA=1\n");
        let plan = plan_open(None, &remote, None);
        assert!(plan.conflicts.is_empty());
        assert_eq!(rendered(&plan), "# hello\nA=1\n");
    }

    #[test]
    fn local_unsealed_edit_survives_when_remote_is_unchanged() {
        let base = document("A=1\nB=2\n");
        let baseline = capture(&base);
        let local = document("A=local\nB=2\n");
        let remote = document("A=1\nB=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert!(
            plan.document.is_none(),
            "nothing to write when the local file already holds the result"
        );
    }

    #[test]
    fn stale_local_value_is_updated_from_the_remote_side() {
        let base = document("A=1\nB=2\n");
        let baseline = capture(&base);
        let local = document("A=1\nB=2\n");
        let remote = document("A=remote\nB=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert_eq!(rendered(&plan), "A=remote\nB=2\n");
    }

    #[test]
    fn both_sides_changed_reports_a_conflict_and_keeps_local() {
        let base = document("A=1\n");
        let baseline = capture(&base);
        let local = document("A=local\n");
        let remote = document("A=remote\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(plan.conflicts, vec![OpenConflict::Key("A".to_owned())]);
        assert!(plan.document.is_none());
    }

    #[test]
    fn remote_deletion_propagates_only_when_local_is_unchanged() {
        let base = document("A=1\nB=2\n");
        let baseline = capture(&base);

        // Local unchanged: deletion propagates.
        let local = document("A=1\nB=2\n");
        let remote = document("B=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert_eq!(rendered(&plan), "B=2\n");

        // Local modified: deletion is a conflict and the value survives.
        let local = document("A=local\nB=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(
            plan.conflicts,
            vec![OpenConflict::DeletedRemotely("A".to_owned())]
        );
        assert!(plan.document.is_none());
    }

    #[test]
    fn local_deletion_survives_and_conflicts_with_remote_modification() {
        let base = document("A=1\nB=2\n");
        let baseline = capture(&base);

        // Remote unchanged: local deletion stands, nothing to write.
        let local = document("B=2\n");
        let remote = document("A=1\nB=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert!(plan.document.is_none());

        // Remote modified the deleted key: conflict, deletion kept.
        let remote = document("A=remote\nB=2\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(
            plan.conflicts,
            vec![OpenConflict::DeletedLocally("A".to_owned())]
        );
        assert!(plan.document.is_none());
    }

    #[test]
    fn remote_additions_are_inserted_after_their_remote_predecessor() {
        let base = document("A=1\nC=3\n");
        let baseline = capture(&base);
        let local = document("A=1\nC=3\nLOCAL=x\n");
        let remote = document("A=1\n# for B\nB=2\nC=3\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
        assert_eq!(rendered(&plan), "A=1\n# for B\nB=2\nC=3\nLOCAL=x\n");
    }

    #[test]
    fn remote_addition_without_a_present_predecessor_lands_deterministically() {
        let base = document("A=1\n");
        let baseline = capture(&base);
        let local = document("A=1\n");
        let remote = document("NEW=first\nA=1\nTAIL=last\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        // NEW has no preceding remote key, so it lands at the end; TAIL's
        // predecessor A exists, so it follows A.
        assert_eq!(rendered(&plan), "A=1\nTAIL=last\nNEW=first\n");
    }

    #[test]
    fn remote_comment_change_travels_with_its_key() {
        let base = document("A=1\n");
        let baseline = capture(&base);
        let local = document("A=1\n");
        let remote = document("# production, do not touch\nA=1\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert_eq!(rendered(&plan), "# production, do not touch\nA=1\n");
    }

    #[test]
    fn comment_changed_on_both_sides_conflicts_on_that_key() {
        let base = document("A=1\n");
        let baseline = capture(&base);
        let local = document("# local comment\nA=1\n");
        let remote = document("# remote comment\nA=1\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(plan.conflicts, vec![OpenConflict::Key("A".to_owned())]);
        assert!(plan.document.is_none());
    }

    #[test]
    fn concurrent_additions_of_different_keys_merge_without_conflict() {
        let base = document("A=1\n");
        let baseline = capture(&base);
        let local = document("A=1\n# mine\nMINE=x\n");
        let remote = document("A=1\n# theirs\nTHEIRS=y\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
        assert_eq!(rendered(&plan), "A=1\n# theirs\nTHEIRS=y\n# mine\nMINE=x\n");
    }

    #[test]
    fn residual_layout_changed_on_both_sides_keeps_local_and_reports() {
        let base = document("A=1\n# tail base\n");
        let baseline = capture(&base);
        let local = document("A=1\n# tail local\n");
        let remote = document("A=1\n# tail remote\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(plan.conflicts, vec![OpenConflict::Layout]);
        assert!(plan.document.is_none());
    }

    #[test]
    fn conservative_mode_without_baseline_keeps_local_and_reports_disagreements() {
        let local = document("A=local\nONLY_LOCAL=x\n");
        let remote = document("A=remote\nNEW=y\n");
        let plan = plan_open(Some(&local), &remote, None);
        assert_eq!(plan.conflicts, vec![OpenConflict::Key("A".to_owned())]);
        // NEW still syncs down after its remote predecessor A; ONLY_LOCAL
        // survives; A keeps the local value.
        assert_eq!(rendered(&plan), "A=local\nNEW=y\nONLY_LOCAL=x\n");
    }

    #[test]
    fn partial_conflict_still_applies_every_arbitrable_change() {
        let base = document("A=1\nB=2\nC=3\n");
        let baseline = capture(&base);
        let local = document("A=local\nB=2\nC=3\n");
        let remote = document("A=remote\nB=remote\nC=3\nD=4\n");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert_eq!(plan.conflicts, vec![OpenConflict::Key("A".to_owned())]);
        assert_eq!(rendered(&plan), "A=local\nB=remote\nC=3\nD=4\n");
    }

    #[test]
    fn non_mapping_roots_use_whole_document_arbitration() {
        let base = parse(SourceFormat::Json, b"[1, 2]").expect("base");
        let baseline = capture(&base);
        let local = parse(SourceFormat::Json, b"[1, 2]").expect("local");
        let remote = parse(SourceFormat::Json, b"[1, 2, 3]").expect("remote");
        let plan = plan_open(Some(&local), &remote, Some(&baseline));
        assert!(plan.conflicts.is_empty());
        assert_eq!(
            String::from_utf8(
                plan.document
                    .expect("document")
                    .generate()
                    .expect("generate")
            )
            .expect("utf-8"),
            // The JSON generator normalizes sequence roots; what matters is
            // that the remote document (data and layout) won wholesale.
            "[\n  1,\n  2,\n  3\n]"
        );
    }
}
