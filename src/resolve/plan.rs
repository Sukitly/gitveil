use crate::error::SecretBytes;
use crate::semantic::{MergeResult, merge};
use crate::source::{Layout, NodePath, SourceDocument, SourceError};

pub(super) enum MergePlan {
    Merged(SourceDocument),
    Conflict {
        path: NodePath,
        document: SecretBytes,
    },
}

pub(super) fn plan_merge(
    base: &SourceDocument,
    ours: &SourceDocument,
    theirs: &SourceDocument,
    marker_size: usize,
) -> Result<MergePlan, SourceError> {
    let merged_root = merge(base.root(), ours.root(), theirs.root());
    let merged_layout = Layout::merge_three_way(base.layout(), ours.layout(), theirs.layout());
    match (merged_root, merged_layout) {
        (MergeResult::Merged(root), Some(layout)) => Ok(MergePlan::Merged(SourceDocument::new(
            ours.format(),
            root,
            layout,
        ))),
        (MergeResult::Conflict(conflicts), _) => {
            let path = conflicts
                .first()
                .map_or_else(NodePath::root, |conflict| conflict.path().clone());
            Ok(MergePlan::Conflict {
                path,
                document: build_conflict(ours, theirs, marker_size)?,
            })
        }
        (MergeResult::Merged(_), None) => Ok(MergePlan::Conflict {
            path: NodePath::root(),
            document: build_conflict(ours, theirs, marker_size)?,
        }),
    }
}

fn build_conflict(
    ours: &SourceDocument,
    theirs: &SourceDocument,
    marker_size: usize,
) -> Result<SecretBytes, SourceError> {
    let ours = SecretBytes::new(ours.generate()?);
    let theirs = SecretBytes::new(theirs.generate()?);
    let marker = "<".repeat(marker_size);
    let divider = "=".repeat(marker_size);
    let end = ">".repeat(marker_size);
    let mut output =
        Vec::with_capacity(ours.as_slice().len() + theirs.as_slice().len() + marker.len() * 3 + 32);
    output.extend_from_slice(marker.as_bytes());
    output.extend_from_slice(b" ours\n");
    output.extend_from_slice(ours.as_slice());
    if !ours.as_slice().ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(divider.as_bytes());
    output.push(b'\n');
    output.extend_from_slice(theirs.as_slice());
    if !theirs.as_slice().ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(end.as_bytes());
    output.extend_from_slice(b" theirs\n");
    Ok(SecretBytes::new(output))
}

#[cfg(test)]
mod tests {
    use crate::config::SourceFormat;
    use crate::source::parse;

    use super::{MergePlan, plan_merge};

    fn document(input: &[u8]) -> crate::source::SourceDocument {
        parse(SourceFormat::Dotenv, input).expect("document")
    }

    #[test]
    fn different_data_and_layout_changes_produce_one_merged_document() {
        let base = document(b"# a base\nA=base-a\n# b base\nB=base-b\n");
        let ours = document(b"# a ours\nA=ours-a\n# b base\nB=base-b\n");
        let theirs = document(b"# a base\nA=base-a\n# b theirs\nB=theirs-b\n");

        let MergePlan::Merged(merged) = plan_merge(&base, &ours, &theirs, 7).expect("merge plan")
        else {
            panic!("different nodes should merge");
        };
        let generated = String::from_utf8(merged.generate().expect("generate")).expect("UTF-8");
        assert!(generated.contains("A=ours-a"));
        assert!(generated.contains("B=theirs-b"));
        assert!(generated.contains("# a ours"));
        assert!(generated.contains("# b theirs"));
    }

    #[test]
    fn root_conflict_reports_path_and_builds_redacted_secret_document() {
        let base = document(b"A=base\n");
        let ours = document(b"A=ours-secret\n");
        let theirs = document(b"A=theirs-secret\n");

        let MergePlan::Conflict { path, document } =
            plan_merge(&base, &ours, &theirs, 5).expect("merge plan")
        else {
            panic!("same node should conflict");
        };
        assert_eq!(path.to_string(), "A");
        let text = String::from_utf8(document.copy_out()).expect("conflict UTF-8");
        assert!(text.contains("<<<<< ours"));
        assert!(text.contains("====="));
        assert!(text.contains(">>>>> theirs"));
        assert_eq!(format!("{document:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn incompatible_layout_changes_conflict_at_root() {
        let base = document(b"# base\nA=value\n");
        let ours = document(b"# ours\nA=value\n");
        let theirs = document(b"# theirs\nA=value\n");

        let MergePlan::Conflict { path, .. } =
            plan_merge(&base, &ours, &theirs, 7).expect("merge plan")
        else {
            panic!("layout changes should conflict");
        };
        assert_eq!(path.to_string(), "$");
    }

    #[test]
    fn marker_size_is_applied_without_entering_diagnostics() {
        let base = document(b"A=base\n");
        let ours = document(b"A=ours\n");
        let theirs = document(b"A=theirs\n");
        let MergePlan::Conflict { document, .. } =
            plan_merge(&base, &ours, &theirs, 3).expect("merge plan")
        else {
            panic!("conflict");
        };
        let text = String::from_utf8(document.copy_out()).expect("UTF-8");
        assert!(text.starts_with("<<< ours\n"));
        assert!(text.contains("\n===\n"));
        assert!(text.ends_with(">>> theirs\n"));
    }
}
