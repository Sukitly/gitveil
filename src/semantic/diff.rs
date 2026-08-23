use std::fmt;

use crate::source::{Node, NodePath};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Deleted,
    Modified,
    OrderChanged,
}

impl ChangeKind {
    const fn symbol(self) -> char {
        match self {
            Self::Added => '+',
            Self::Deleted => '-',
            Self::Modified | Self::OrderChanged => '~',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    path: NodePath,
    kind: ChangeKind,
}

impl Change {
    pub fn path(&self) -> &NodePath {
        &self.path
    }

    pub const fn kind(&self) -> ChangeKind {
        self.kind
    }
}

impl fmt::Display for Change {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.kind.symbol(), self.path)?;
        if self.kind == ChangeKind::OrderChanged {
            formatter.write_str(" [order]")?;
        }
        Ok(())
    }
}

pub fn diff(before: &Node, after: &Node) -> Vec<Change> {
    let mut changes = Vec::new();
    diff_at(&NodePath::root(), Some(before), Some(after), &mut changes);
    changes
}

fn diff_at(
    path: &NodePath,
    before: Option<&Node>,
    after: Option<&Node>,
    changes: &mut Vec<Change>,
) {
    match (before, after) {
        (None, Some(_)) => changes.push(Change {
            path: path.clone(),
            kind: ChangeKind::Added,
        }),
        (Some(_), None) => changes.push(Change {
            path: path.clone(),
            kind: ChangeKind::Deleted,
        }),
        (Some(before), Some(after)) if before == after => {}
        (Some(Node::Mapping(before)), Some(Node::Mapping(after))) => {
            let before_order = before.keys().collect::<Vec<_>>();
            let after_order = after.keys().collect::<Vec<_>>();
            let common_before = before_order
                .iter()
                .filter(|key| after.contains_key(**key))
                .copied()
                .collect::<Vec<_>>();
            let common_after = after_order
                .iter()
                .filter(|key| before.contains_key(**key))
                .copied()
                .collect::<Vec<_>>();
            if common_before != common_after {
                changes.push(Change {
                    path: path.clone(),
                    kind: ChangeKind::OrderChanged,
                });
            }
            for (key, value) in before {
                diff_at(&path.child_key(key), Some(value), after.get(key), changes);
            }
            for (key, value) in after {
                if !before.contains_key(key) {
                    diff_at(&path.child_key(key), None, Some(value), changes);
                }
            }
        }
        (
            Some(Node::Tagged {
                tag: before_tag,
                value: before,
            }),
            Some(Node::Tagged {
                tag: after_tag,
                value: after,
            }),
        ) if before_tag == after_tag => {
            diff_at(path, Some(before), Some(after), changes);
        }
        (Some(_), Some(_)) => changes.push(Change {
            path: path.clone(),
            kind: ChangeKind::Modified,
        }),
        (None, None) => {}
    }
}
