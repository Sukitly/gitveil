use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, Listener, ListenerNonblockingMode, ListenerOptions, Name,
    Stream, ToFsName, ToNsName, prelude::*,
};
use rand::random;
use zeroize::Zeroize;

use super::PrivateRuntime;
use crate::error::{ErrorCategory, GitveilError, Result, SecretBytes};

const MAX_EDITOR_PAYLOAD: u64 = 64 * 1024 * 1024;
const EDITOR_IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct EditorEndpoint {
    listener: Listener,
    printable: String,
    token: String,
    socket_path: Option<PathBuf>,
}

impl EditorEndpoint {
    pub fn bind(runtime: &PrivateRuntime) -> Result<Self> {
        let nonce = hex::encode(random::<[u8; 16]>());
        let token = hex::encode(random::<[u8; 32]>());
        let (name, printable, socket_path) = endpoint_name(runtime, &nonce)?;
        let listener = ListenerOptions::new()
            .name(name)
            .try_overwrite(false)
            .nonblocking(ListenerNonblockingMode::Accept)
            .create_sync()
            .map_err(|error| {
                GitveilError::io("create editor IPC endpoint", socket_path.clone(), &error)
            })?;
        Ok(Self {
            listener,
            printable,
            token,
            socket_path,
        })
    }

    pub fn printable(&self) -> &str {
        &self.printable
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for EditorEndpoint {
    fn drop(&mut self) {
        self.token.zeroize();
        if let Some(path) = &self.socket_path {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn receive_editor_payload(endpoint: &EditorEndpoint, payload: &SecretBytes) -> Result<bool> {
    let stream = match endpoint.listener.accept() {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => {
            return Err(GitveilError::io(
                "accept editor IPC",
                endpoint.socket_path.clone(),
                &error,
            ));
        }
    };
    stream
        .set_recv_timeout(Some(Duration::from_secs(1)))
        .and_then(|()| stream.set_send_timeout(Some(Duration::from_secs(1))))
        .map_err(|error| GitveilError::io("bound editor IPC", None, &error))?;
    let mut reader = BufReader::new(stream);
    let mut token = String::new();
    reader
        .read_line(&mut token)
        .map_err(|error| GitveilError::io("authenticate editor IPC", None, &error))?;
    if token.trim_end() != endpoint.token {
        // The endpoint may be reachable beyond the runtime directory (Linux
        // uses an abstract-namespace socket). Fail closed on the first bad
        // token instead of leaving the payload available for further
        // attempts, mirroring `reject_editor_reuse`.
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "editor IPC authentication failed",
        ));
    }
    let length = u64::try_from(payload.as_slice().len())
        .map_err(|_| GitveilError::new(ErrorCategory::Protocol, "editor payload is too large"))?;
    if length > MAX_EDITOR_PAYLOAD {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "editor payload is too large",
        ));
    }
    let stream = reader.get_mut();
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(payload.as_slice()))
        .and_then(|()| stream.flush())
        .map_err(|error| GitveilError::io("send editor payload", None, &error))?;
    Ok(true)
}

pub fn reject_editor_reuse(endpoint: &EditorEndpoint) -> Result<bool> {
    match endpoint.listener.accept() {
        Ok(stream) => {
            drop(stream);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(GitveilError::io(
            "reject repeated editor IPC",
            endpoint.socket_path.clone(),
            &error,
        )),
    }
}

const MAX_EDITOR_TOKEN: u64 = 4096;

pub(crate) fn read_editor_token(path: &Path) -> Result<zeroize::Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        GitveilError::io(
            "inspect editor token file",
            Some(path.to_path_buf()),
            &error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GitveilError::new(
            ErrorCategory::Path,
            "editor token file is not a regular file",
        ));
    }
    if metadata.len() > MAX_EDITOR_TOKEN {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "editor token file is too large",
        ));
    }
    let mut bytes = fs::read(path).map_err(|error| {
        GitveilError::io("read editor token file", Some(path.to_path_buf()), &error)
    })?;
    let token = std::str::from_utf8(&bytes)
        .map(|text| zeroize::Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_owned()))
        .map_err(|_| GitveilError::new(ErrorCategory::Protocol, "editor token file is not UTF-8"));
    bytes.zeroize();
    token
}

pub fn run_internal_editor(
    endpoint: &str,
    token: &str,
    runtime: &Path,
    target: &Path,
) -> Result<()> {
    validate_editor_target(runtime, target)?;
    let name = parse_endpoint(endpoint)?;
    let mut stream = Stream::connect(name)
        .map_err(|error| GitveilError::io("connect editor IPC", None, &error))?;
    stream
        .set_recv_timeout(Some(EDITOR_IO_TIMEOUT))
        .and_then(|()| stream.set_send_timeout(Some(EDITOR_IO_TIMEOUT)))
        .map_err(|error| GitveilError::io("bound editor IPC", None, &error))?;
    stream
        .write_all(token.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .and_then(|()| stream.flush())
        .map_err(|error| GitveilError::io("authenticate editor IPC", None, &error))?;
    let mut length = [0_u8; 8];
    stream
        .read_exact(&mut length)
        .map_err(|error| GitveilError::io("read editor payload length", None, &error))?;
    let length = u64::from_be_bytes(length);
    if length > MAX_EDITOR_PAYLOAD {
        return Err(GitveilError::new(
            ErrorCategory::Protocol,
            "editor payload is too large",
        ));
    }
    let mut payload = SecretBytes::new(vec![
        0;
        usize::try_from(length).map_err(|_| {
            GitveilError::new(ErrorCategory::Protocol, "editor payload is too large")
        })?
    ]);
    stream
        .read_exact(payload.as_mut_slice())
        .map_err(|error| GitveilError::io("read editor payload", None, &error))?;
    let parent = target.parent().ok_or_else(|| {
        GitveilError::new(ErrorCategory::Path, "SOPS editor target has no parent")
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        GitveilError::io(
            "create editor replacement",
            Some(parent.to_path_buf()),
            &error,
        )
    })?;
    temporary
        .write_all(payload.as_slice())
        .and_then(|()| temporary.as_file_mut().sync_all())
        .map_err(|error| {
            GitveilError::io(
                "write editor replacement",
                Some(target.to_path_buf()),
                &error,
            )
        })?;
    temporary.persist(target).map_err(|error| {
        GitveilError::io(
            "replace SOPS editor target",
            Some(target.to_path_buf()),
            &error.error,
        )
    })?;
    Ok(())
}

fn validate_editor_target(runtime: &Path, target: &Path) -> Result<()> {
    let runtime = fs::canonicalize(runtime).map_err(|error| {
        GitveilError::io(
            "resolve editor runtime",
            Some(runtime.to_path_buf()),
            &error,
        )
    })?;
    let parent = target.parent().ok_or_else(|| {
        GitveilError::new(ErrorCategory::Path, "SOPS editor target has no parent")
    })?;
    let parent = fs::canonicalize(parent).map_err(|error| {
        GitveilError::io(
            "resolve editor target parent",
            Some(parent.to_path_buf()),
            &error,
        )
    })?;
    if !parent.starts_with(&runtime) {
        return Err(GitveilError::new(
            ErrorCategory::Path,
            "SOPS editor target is outside Gitveil runtime",
        ));
    }
    let metadata = fs::symlink_metadata(target).map_err(|error| {
        GitveilError::io("inspect editor target", Some(target.to_path_buf()), &error)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GitveilError::new(
            ErrorCategory::Path,
            "SOPS editor target is not a regular file",
        ));
    }
    Ok(())
}

fn endpoint_name(
    runtime: &PrivateRuntime,
    nonce: &str,
) -> Result<(Name<'static>, String, Option<PathBuf>)> {
    if GenericNamespaced::is_supported() {
        let printable = format!("gitveil-{nonce}");
        let name = printable
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .map_err(|error| GitveilError::io("name editor IPC endpoint", None, &error))?;
        Ok((name, format!("ns:{printable}"), None))
    } else {
        let path = runtime.create_named_path(&format!("editor-{nonce}.sock"))?;
        let printable = path.to_string_lossy().into_owned();
        let name = printable
            .clone()
            .to_fs_name::<GenericFilePath>()
            .map_err(|error| {
                GitveilError::io("name editor IPC endpoint", Some(path.clone()), &error)
            })?;
        Ok((name, format!("fs:{printable}"), Some(path)))
    }
}

fn parse_endpoint(endpoint: &str) -> Result<Name<'static>> {
    if let Some(name) = endpoint.strip_prefix("ns:") {
        name.to_owned()
            .to_ns_name::<GenericNamespaced>()
            .map_err(|error| GitveilError::io("parse editor IPC endpoint", None, &error))
    } else if let Some(path) = endpoint.strip_prefix("fs:") {
        path.to_owned()
            .to_fs_name::<GenericFilePath>()
            .map_err(|error| GitveilError::io("parse editor IPC endpoint", None, &error))
    } else {
        Err(GitveilError::new(
            ErrorCategory::Protocol,
            "invalid editor IPC endpoint",
        ))
    }
}
