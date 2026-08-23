use gitveil::semantic::{ChangeKind, MergeResult, diff, merge};
use gitveil::source::{Node, Scalar};
use indexmap::IndexMap;

fn map(entries: &[(&str, &str)]) -> Node {
    Node::Mapping(
        entries
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_owned(),
                    Node::Scalar(Scalar::String((*value).to_owned())),
                )
            })
            .collect::<IndexMap<_, _>>(),
    )
}

#[test]
fn diff_reports_paths_and_kinds_without_values() {
    let before = map(&[("A", "one"), ("B", "two")]);
    let after = map(&[("A", "changed"), ("C", "three")]);

    let changes = diff(&before, &after);
    assert!(
        changes
            .iter()
            .any(|c| c.path().to_string() == "A" && c.kind() == ChangeKind::Modified)
    );
    assert!(
        changes
            .iter()
            .any(|c| c.path().to_string() == "B" && c.kind() == ChangeKind::Deleted)
    );
    assert!(
        changes
            .iter()
            .any(|c| c.path().to_string() == "C" && c.kind() == ChangeKind::Added)
    );

    let rendered = changes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!rendered.contains("one"));
    assert!(!rendered.contains("changed"));
    assert!(!rendered.contains("three"));
}

#[test]
fn merge_combines_different_keys() {
    let base = map(&[("A", "base-a"), ("B", "base-b")]);
    let ours = map(&[("A", "ours-a"), ("B", "base-b")]);
    let theirs = map(&[("A", "base-a"), ("B", "theirs-b")]);

    let MergeResult::Merged(merged) = merge(&base, &ours, &theirs) else {
        panic!("different keys must merge");
    };
    assert_eq!(merged, map(&[("A", "ours-a"), ("B", "theirs-b")]));
}

#[test]
fn merge_combines_one_sided_order_change_with_other_side_addition() {
    let base = map(&[("A", "a"), ("B", "b")]);
    let ours = map(&[("B", "b"), ("A", "a")]);
    let theirs = map(&[("A", "a"), ("B", "b"), ("C", "c")]);
    let MergeResult::Merged(merged) = merge(&base, &ours, &theirs) else {
        panic!("order change and addition should merge");
    };
    assert_eq!(merged.mapping_keys().expect("mapping"), vec!["B", "A", "C"]);
}

#[test]
fn merge_conflicts_on_incompatible_order_changes() {
    let base = map(&[("A", "a"), ("B", "b"), ("C", "c")]);
    let ours = map(&[("B", "b"), ("A", "a"), ("C", "c")]);
    let theirs = map(&[("A", "a"), ("C", "c"), ("B", "b")]);
    assert!(matches!(
        merge(&base, &ours, &theirs),
        MergeResult::Conflict(_)
    ));
}

#[test]
fn merge_conflicts_on_same_key_delete_modify_and_changed_array() {
    let base = map(&[("A", "base")]);
    let ours = map(&[("A", "ours")]);
    let theirs = map(&[("A", "theirs")]);
    let MergeResult::Conflict(conflicts) = merge(&base, &ours, &theirs) else {
        panic!("same key must conflict");
    };
    assert_eq!(conflicts[0].path().to_string(), "A");

    let deleted = Node::Mapping(IndexMap::new());
    assert!(matches!(
        merge(&base, &deleted, &theirs),
        MergeResult::Conflict(_)
    ));

    let base_array = Node::Sequence(vec![Node::Scalar(Scalar::String("base".into()))]);
    let ours_array = Node::Sequence(vec![Node::Scalar(Scalar::String("ours".into()))]);
    let theirs_array = Node::Sequence(vec![Node::Scalar(Scalar::String("theirs".into()))]);
    assert!(matches!(
        merge(&base_array, &ours_array, &theirs_array),
        MergeResult::Conflict(_)
    ));
}
