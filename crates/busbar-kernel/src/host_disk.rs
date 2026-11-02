// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::io::Write as _;
use std::path::Path;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

use busbar_contract::abi::host::service::{
    DISK_APPEND_FAILED, DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED,
    DISK_SHIFT_FAILED,
};
use busbar_contract::services::{DiskDest, DiskReport, DiskRotate, Later};

pub const LANE_BOUND: usize = 4096;

pub const MAX_KEEP: u32 = 64;

pub const LANE_FULL: &str = "the host's disk lane is full";

pub const LANE_GONE: &str = "the host's disk lane is not running";

struct Append {
    dest: DiskDest,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    later: Later,
}

type SecretJob = Box<dyn FnOnce() + Send>;

/// The FIFO append executor and an isolated config-time secret executor, each lazy and bounded.
/// A filesystem read cannot be interrupted by a caller deadline. It may occupy the secret thread
/// until it returns, but can never occupy the append thread or reserve append queue space.
#[derive(Debug, Default)]
pub struct DiskLane {
    tx: OnceLock<Option<SyncSender<Append>>>,
    secrets: OnceLock<Option<SyncSender<SecretJob>>>,
}

impl DiskLane {
    pub fn submit(&self, dest: DiskDest, bytes: Vec<u8>, later: Later) -> Result<(), DiskReport> {
        let bytes = zeroize::Zeroizing::new(bytes);
        let Some(tx) = self.tx.get_or_init(start) else {
            return Err(refused(LANE_GONE));
        };
        match tx.try_send(Append { dest, bytes, later }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(refused(LANE_FULL)),
            Err(TrySendError::Disconnected(_)) => Err(refused(LANE_GONE)),
        }
    }

    pub fn run(&self, job: Box<dyn FnOnce() + Send>) -> Result<(), &'static str> {
        let Some(tx) = self.secrets.get_or_init(start_secrets) else {
            return Err(LANE_GONE);
        };
        match tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(LANE_FULL),
            Err(TrySendError::Disconnected(_)) => Err(LANE_GONE),
        }
    }
}

pub const LANE_THREAD: &str = "busbar-disk-lane";

const fn refused(why: &'static str) -> DiskReport {
    DiskReport {
        step: DISK_OPEN_FAILED,
        rotated: false,
        faults: 0,
        error: why,
    }
}

fn start() -> Option<SyncSender<Append>> {
    let (tx, rx) = sync_channel::<Append>(LANE_BOUND);
    std::thread::Builder::new()
        .name(LANE_THREAD.into())
        .spawn(move || {
            for Append { dest, bytes, later } in rx {
                let report = append(&dest, &bytes);

                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    later(report.stored());
                }));
            }
        })
        .ok()
        .map(|_| tx)
}

fn start_secrets() -> Option<SyncSender<SecretJob>> {
    let (tx, rx) = sync_channel::<SecretJob>(LANE_BOUND);
    std::thread::Builder::new()
        .name("busbar-disk-secrets".into())
        .spawn(move || {
            for job in rx {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            }
        })
        .ok()
        .map(|_| tx)
}

#[must_use]
pub fn append(dest: &DiskDest, bytes: &[u8]) -> DiskReport {
    let due = dest
        .rotate_at
        .is_some_and(|limit| std::fs::metadata(&dest.path).is_ok_and(|m| m.len() >= limit));

    let truncate = due && dest.rotate == DiskRotate::Truncate;
    let (renamed, faults) = match dest.rotate {
        DiskRotate::Rename { keep } if due => rotate(&dest.path, keep),
        _ => (false, 0),
    };
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(&dest.path);
    let rotated = renamed;
    let report = |step, error| DiskReport {
        step,
        rotated,
        faults,
        error,
    };
    match opened {
        Ok(mut file) => match file.write_all(bytes) {
            Ok(()) => report(0, ""),
            Err(e) => report(DISK_APPEND_FAILED, os_words(&e)),
        },
        Err(e) => report(DISK_OPEN_FAILED, os_words(&e)),
    }
}

#[must_use]
pub fn rotate(path: &str, keep: u32) -> (bool, u8) {
    let keep = keep.clamp(1, MAX_KEEP);
    let mut faults = 0;
    let oldest = format!("{path}.{keep}");
    if Path::new(&oldest).exists() && std::fs::remove_file(&oldest).is_err() {
        faults |= DISK_RETENTION_FAILED;
    }
    for i in (1..keep).rev() {
        let from = format!("{path}.{i}");
        if Path::new(&from).exists() && std::fs::rename(&from, format!("{path}.{}", i + 1)).is_err()
        {
            faults |= DISK_SHIFT_FAILED;
        }
    }
    let renamed = std::fs::rename(path, format!("{path}.1")).is_ok();
    if !renamed {
        faults |= DISK_RENAME_FAILED;
    }
    (renamed, faults)
}

const MAX_WORDS: usize = 256;

pub const OS_REFUSED: &str = "the operating system refused the write";

fn os_words(e: &std::io::Error) -> &'static str {
    static WORDS: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let text = e.to_string();
    let mut words = WORDS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(held) = words.get(text.as_str()) {
        return held;
    }
    if words.len() >= MAX_WORDS {
        return OS_REFUSED;
    }
    let held: &'static str = Box::leak(text.into_boxed_str());
    words.insert(held);
    held
}

#[cfg(test)]
#[path = "tests/host_disk_tests.rs"]
mod tests;
