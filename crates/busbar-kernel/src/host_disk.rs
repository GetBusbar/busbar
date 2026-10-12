// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S BOUNDED DISK LANE (`BUSBAR-1.6.0.md` THE DESIGN §11.11 R4, Q-DISK; §11.12
//! `disk.append`): the ONE exception to "no blocking", scoped to the file export sink and the SQLite
//! store. A plugin never blocks on a file and never opens a path: it names a destination key, the
//! loader maps it to the file the operator configured, and the append runs HERE, on one lane
//! thread, off every dispatcher worker. The call pends until the append is done.
//!
//! * **One thread, in order.** Appends run one at a time in the order they were submitted, so the
//!   lines one sink hands over land in that order and two instances writing one file never
//!   interleave inside a write.
//! * **Bounded.** At most [`LANE_BOUND`] appends are held; past it an append is answered FAILED at
//!   once ([`LANE_FULL`]), never queued without bound.
//! * **1.5.5's write.** Each append opens the file for append (created if absent) and writes the
//!   bytes whole: a file an external rotator moved aside is never written through a stale handle,
//!   and an unopenable path is a per-append failure the plugin reports, never a refused boot.
//! * **Rotation is the host's.** When the destination states a threshold and the file already holds
//!   at least that many bytes, the file is rotated BY RENAME before the append: the oldest archive
//!   is dropped, the rest shift up one slot, the live file becomes `<path>.1`. Each failed step is
//!   reported and the rest still run; a failed final rename leaves the live file to keep growing,
//!   never truncated.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::Path;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

use busbar_contract::abi::host::service::{
    DISK_APPEND_FAILED, DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED,
    DISK_SHIFT_FAILED,
};
use busbar_contract::services::{DiskDest, DiskReport, Later};

/// The most appends the lane holds, queued or running.
pub const LANE_BOUND: usize = 4096;

/// The most archives one rotation may keep: a bound on the renames one append can cost.
pub const MAX_KEEP: u32 = 64;

/// A FAILED append's text when the lane holds [`LANE_BOUND`] appends already.
pub const LANE_FULL: &str = "the host's disk lane is full";

/// A FAILED append's text when the lane thread could not be started or has gone.
pub const LANE_GONE: &str = "the host's disk lane is not running";

/// One append the lane owes.
struct Job {
    dest: DiskDest,
    bytes: Vec<u8>,
    later: Later,
}

/// THE LANE: one thread, started on the first append, fed through a bounded queue.
#[derive(Debug, Default)]
pub struct DiskLane {
    tx: OnceLock<Option<SyncSender<Job>>>,
}

impl DiskLane {
    /// Submit one append of `bytes` to `dest`; its [`DiskReport`] goes to `later` when it is done.
    ///
    /// # Errors
    ///
    /// The lane is full or not running: the report to answer at once (FAILED, nothing written).
    pub fn submit(&self, dest: DiskDest, bytes: Vec<u8>, later: Later) -> Result<(), DiskReport> {
        let Some(tx) = self.tx.get_or_init(start) else {
            return Err(refused(LANE_GONE));
        };
        match tx.try_send(Job { dest, bytes, later }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(refused(LANE_FULL)),
            Err(TrySendError::Disconnected(_)) => Err(refused(LANE_GONE)),
        }
    }
}

/// A FAILED report for an append that never reached the file.
const fn refused(why: &'static str) -> DiskReport {
    DiskReport {
        step: DISK_OPEN_FAILED,
        rotated: false,
        faults: 0,
        error: why,
    }
}

/// Start the lane thread; `None` when the operating system will not give one.
fn start() -> Option<SyncSender<Job>> {
    let (tx, rx) = sync_channel::<Job>(LANE_BOUND);
    std::thread::Builder::new()
        .name("busbar-disk-lane".into())
        .spawn(move || {
            for job in rx {
                let report = append(&job.dest, &job.bytes);
                (job.later)(report.stored());
            }
        })
        .ok()
        .map(|_| tx)
}

/// THE APPEND, as the lane runs it: rotate first when `dest` is due, then open for append (created
/// if absent) and write `bytes` whole.
#[must_use]
pub fn append(dest: &DiskDest, bytes: &[u8]) -> DiskReport {
    let due = dest
        .rotate_at
        .is_some_and(|limit| std::fs::metadata(&dest.path).is_ok_and(|m| m.len() >= limit));
    let (rotated, faults) = if due {
        rotate(&dest.path, dest.keep)
    } else {
        (false, 0)
    };
    let report = |step, error| DiskReport {
        step,
        rotated,
        faults,
        error,
    };
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&dest.path);
    match opened {
        Ok(mut file) => match file.write_all(bytes) {
            Ok(()) => report(0, ""),
            Err(e) => report(DISK_APPEND_FAILED, os_words(&e)),
        },
        Err(e) => report(DISK_OPEN_FAILED, os_words(&e)),
    }
}

/// Rotate `path` by rename, keeping `keep` archives: drop the oldest, shift the rest up, rename the
/// live file to `<path>.1`. Whether the live file was renamed, and the steps that failed.
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

/// The most distinct failure texts the lane keeps; past it a failure is told in [`OS_REFUSED`].
const MAX_WORDS: usize = 256;

/// A failure's text once [`MAX_WORDS`] distinct ones are held.
pub const OS_REFUSED: &str = "the operating system refused the write";

/// The operating system's words for `e`, held for the process's life (a service's error text is
/// `'static`): each distinct text is kept once, at most [`MAX_WORDS`] of them.
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
