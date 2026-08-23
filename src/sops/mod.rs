mod classify;
mod client;
mod process;

pub(crate) use classify::SopsFailure;
pub use client::SOPS_VERSION;
pub(crate) use client::{SopsClient, SopsPaths};
pub(crate) use process::SopsBinary;
