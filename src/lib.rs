#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Gitveil v1 supports macOS and Linux only");

pub mod baseline;
pub mod cli;
pub mod config;
pub(crate) mod configure;
pub(crate) mod confine;
pub mod envelope;
pub mod error;
pub(crate) mod git;
pub mod manifest;
pub(crate) mod open;
pub mod path;
pub mod profile;
pub mod recipient;
pub(crate) mod resolve;
pub mod runtime;
pub(crate) mod seal;
pub mod semantic;
pub mod sops;
pub mod source;
pub(crate) mod status;
pub(crate) mod verify;
pub(crate) mod workspace;
