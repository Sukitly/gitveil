use std::fs::{File, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::temp::{PrivateRuntime, open_lock_file};
use crate::error::{ErrorCategory, GitveilError, Result};

pub struct OperationLock {
    file: File,
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub fn acquire_lock(runtime: &PrivateRuntime, timeout: Duration) -> Result<OperationLock> {
    let path = runtime.create_named_path("operation.lock")?;
    let file = open_lock_file(&path)?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => {
                runtime.cleanup_orphans()?;
                return Ok(OperationLock { file });
            }
            Err(TryLockError::WouldBlock) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(GitveilError::new(
                    ErrorCategory::Concurrency,
                    "Gitveil operation.lock timed out",
                ));
            }
            Err(TryLockError::Error(error)) => {
                return Err(GitveilError::io("acquire Gitveil lock", Some(path), &error));
            }
        }
    }
}
