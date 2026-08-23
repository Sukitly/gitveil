use std::fmt;

use indexmap::IndexMap;

use crate::source::{Node, NodePath};

pub enum MergeResult {
    Merged(Node),
    Conflict(Vec<Conflict>),
}

impl fmt::Debug for MergeResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Merged(node) => formatter.debug_tuple("Merged").field(node).finish(),
            Self::Conflict(conflicts) => formatter
                .debug_tuple("Conflict")
                .field(&conflicts.iter().map(Conflict::path).collect::<Vec<_>>())
                .finish(),
        }
    }
}

pub struct Conflict {
    path: NodePath,
}

impl Conflict {
    pub fn path(&self) -> &NodePath {
        &self.path
    }
}

impl fmt::Debug for Conflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Conflict")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

pub fn merge(base: &Node, ours: &Node, theirs: &Node) -> MergeResult {
    let mut conflicts = Vec::new();
    let merged = merge_at(
        &NodePath::root(),
        Some(base),
        Some(ours),
        Some(theirs),
        &mut conflicts,
    );
    if conflicts.is_empty() {
        match merged {
            Some(node) => MergeResult::Merged(node),
            None => MergeResult::Merged(Node::Mapping(IndexMap::new())),
        }
    } else {
        MergeResult::Conflict(conflicts)
    }
}

fn merge_at(
    path: &NodePath,
    base: Option<&Node>,
    ours: Option<&Node>,
    theirs: Option<&Node>,
    conflicts: &mut Vec<Conflict>,
) -> Option<Node> {
    if ours == theirs {
        return ours.cloned();
    }
    if ours == base {
        return theirs.cloned();
    }
    if theirs == base {
        return ours.cloned();
    }

    match (base, ours, theirs) {
        (
            Some(Node::Mapping(base_values)),
            Some(Node::Mapping(our_values)),
            Some(Node::Mapping(their_values)),
        ) => {
            let (order, order_conflict) = merged_order(base_values, our_values, their_values);
            if order_conflict {
                conflicts.push(Conflict { path: path.clone() });
            }
            let mut merged = IndexMap::new();
            for key in order {
                if let Some(value) = merge_at(
                    &path.child_key(&key),
                    base_values.get(&key),
                    our_values.get(&key),
                    their_values.get(&key),
                    conflicts,
                ) {
                    merged.insert(key, value);
                }
            }
            Some(Node::Mapping(merged))
        }
        (
            Some(Node::Tagged {
                tag: base_tag,
                value: base,
            }),
            Some(Node::Tagged {
                tag: our_tag,
                value: ours,
            }),
            Some(Node::Tagged {
                tag: their_tag,
                value: theirs,
            }),
        ) if base_tag == our_tag && base_tag == their_tag => {
            merge_at(path, Some(base), Some(ours), Some(theirs), conflicts).map(|value| {
                Node::Tagged {
                    tag: base_tag.clone(),
                    value: Box::new(value),
                }
            })
        }
        _ => {
            conflicts.push(Conflict { path: path.clone() });
            ours.cloned()
        }
    }
}

fn merged_order(
    base: &IndexMap<String, Node>,
    ours: &IndexMap<String, Node>,
    theirs: &IndexMap<String, Node>,
) -> (Vec<String>, bool) {
    let shared = base
        .keys()
        .filter(|key| ours.contains_key(*key) && theirs.contains_key(*key))
        .collect::<Vec<_>>();
    let base_shared = base
        .keys()
        .filter(|key| shared.contains(key))
        .collect::<Vec<_>>();
    let ours_shared = ours
        .keys()
        .filter(|key| shared.contains(key))
        .collect::<Vec<_>>();
    let theirs_shared = theirs
        .keys()
        .filter(|key| shared.contains(key))
        .collect::<Vec<_>>();
    let (primary, secondary, conflict) = if ours_shared == theirs_shared {
        (ours, theirs, false)
    } else if ours_shared == base_shared {
        (theirs, ours, false)
    } else if theirs_shared == base_shared {
        (ours, theirs, false)
    } else {
        (ours, theirs, true)
    };
    let mut keys = Vec::with_capacity(base.len().max(ours.len()).max(theirs.len()));
    for mapping in [primary, secondary, base] {
        for key in mapping.keys() {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
    }
    (keys, conflict)
}
