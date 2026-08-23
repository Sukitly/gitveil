mod diff;
mod merge;

pub use diff::{Change, ChangeKind, diff};
pub use merge::{Conflict, MergeResult, merge};
