// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::Path;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use busbar_contract::abi::host::service::{
    DISK_APPEND_FAILED, DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED,
    DISK_SHIFT_FAILED,
};
use busbar_contract::services::{DiskDest, DiskReport, DiskRotate, Later};

pub const LANE_BOUND: usize = 4096;

// A blocked destination can occupy one worker and its own bounded queue, never the
// entire backlog. Exhausting all workers/destinations still imposes backpressure.
const APPEND_WORKERS: usize = 16;
const DESTINATION_LIMIT: usize = 64;
const DESTINATION_BOUND: usize = LANE_BOUND / DESTINATION_LIMIT;

pub const MAX_KEEP: u32 = 64;

pub const LANE_FULL: &str = "the host's disk lane is full";

pub const LANE_GONE: &str = "the host's disk lane is not running";

struct Append {
    dest: DiskDest,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    later: Later,
}

type SecretJob = Box<dyn FnOnce() + Send>;

// Two bounded workers let unrelated resolves proceed while one filesystem read is stuck.
const SECRET_WORKERS: usize = 2;

/// Bounded, destination-ordered appends and an isolated config-time secret executor.
/// Filesystem operations cannot be interrupted by cancellation. A destination retains
/// its worker and FIFO ownership until append and completion return; other destinations
/// can use the remaining workers. Accepted writes drain when this executor is dropped.
/// Destination identity is the configured path string (not the manifest key). Operators
/// must not configure overlapping files/archives or filesystem aliases as separate sinks:
/// resolving aliases here could itself block admission on a stalled filesystem.
#[derive(Debug, Default)]
pub struct DiskLane {
    appends: OnceLock<Option<AppendExecutor>>,
    // Existing custody tests inject a held queue; production always uses the scheduler.
    #[cfg(test)]
    tx: OnceLock<Option<SyncSender<Append>>>,
    secrets: OnceLock<Option<SyncSender<SecretJob>>>,
}

impl DiskLane {
    pub fn submit(&self, dest: DiskDest, bytes: Vec<u8>, later: Later) -> Result<(), DiskReport> {
        let job = Append {
            dest,
            bytes: zeroize::Zeroizing::new(bytes),
            later,
        };
        #[cfg(test)]
        if let Some(tx) = self.tx.get() {
            return match tx {
                Some(tx) => match tx.try_send(job) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(_)) => Err(refused(LANE_FULL)),
                    Err(TrySendError::Disconnected(_)) => Err(refused(LANE_GONE)),
                },
                None => Err(refused(LANE_GONE)),
            };
        }
        let Some(executor) = self.appends.get_or_init(start) else {
            return Err(refused(LANE_GONE));
        };
        executor.submit(job)
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

#[derive(Default)]
struct Destination {
    queued: VecDeque<Append>,
    busy: bool,
}

#[derive(Default)]
struct AppendState {
    destinations: HashMap<String, Destination>,
    ready: VecDeque<String>,
    queued: usize,
    closing: bool,
}

#[derive(Default)]
struct AppendShared {
    state: Mutex<AppendState>,
    changed: Condvar,
}

struct AppendExecutor {
    shared: Arc<AppendShared>,
}

impl std::fmt::Debug for AppendExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppendExecutor").finish_non_exhaustive()
    }
}

impl AppendExecutor {
    fn submit(&self, job: Append) -> Result<(), DiskReport> {
        // `job` is declared before the guard: refusal drops callback custody only
        // after unlocking, including callbacks whose Drop re-enters admission.
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closing {
            return Err(refused(LANE_GONE));
        }
        let existing = state.destinations.get(&job.dest.path);
        if state.queued >= LANE_BOUND
            || existing.is_some_and(|lane| lane.queued.len() >= DESTINATION_BOUND)
            || (existing.is_none() && state.destinations.len() >= DESTINATION_LIMIT)
        {
            return Err(refused(LANE_FULL));
        }
        let path = job.dest.path.clone();
        let lane = state.destinations.entry(path.clone()).or_default();
        let ready = !lane.busy && lane.queued.is_empty();
        lane.queued.push_back(job);
        state.queued += 1;
        if ready {
            state.ready.push_back(path);
            self.shared.changed.notify_one();
        }
        Ok(())
    }
}

impl Drop for AppendExecutor {
    fn drop(&mut self) {
        // Do not join: an OS write may never return. Workers retain accepted
        // custody, drain what they can, and exit without retaining this executor.
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closing = true;
        self.shared.changed.notify_all();
    }
}

fn start() -> Option<AppendExecutor> {
    let executor = AppendExecutor {
        shared: Arc::default(),
    };
    for _ in 0..APPEND_WORKERS {
        let shared = Arc::clone(&executor.shared);
        std::thread::Builder::new()
            .name(LANE_THREAD.into())
            .spawn(move || append_worker(&shared))
            .ok()?;
    }
    Some(executor)
}

fn append_worker(shared: &AppendShared) {
    loop {
        let (path, Append { dest, bytes, later }) = {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(path) = state.ready.pop_front() {
                    let lane = state
                        .destinations
                        .get_mut(&path)
                        .expect("ready destination");
                    lane.busy = true;
                    let job = lane.queued.pop_front().expect("ready append");
                    state.queued -= 1;
                    break (path, job);
                }
                if state.closing {
                    return;
                }
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let report = append(&dest, &bytes);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            later(report.stored());
        }));
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lane = state
            .destinations
            .get_mut(&path)
            .expect("active destination");
        lane.busy = false;
        if lane.queued.is_empty() {
            state.destinations.remove(&path);
        } else {
            state.ready.push_back(path);
            shared.changed.notify_one();
        }
    }
}

fn start_secrets() -> Option<SyncSender<SecretJob>> {
    let (tx, rx) = sync_channel::<SecretJob>(LANE_BOUND);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..SECRET_WORKERS {
        let rx = Arc::clone(&rx);
        std::thread::Builder::new()
            .name("busbar-disk-secrets".into())
            .spawn(move || loop {
                let job = rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv();
                let Ok(job) = job else { break };
                // Queue ownership is released before running any plugin or filesystem code.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            })
            .ok()?;
    }
    Some(tx)
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
            // Lower archives cannot move into an occupied slot without losing data.
            // Keep the live file in place and let append continue without truncation.
            return (false, faults | DISK_SHIFT_FAILED | DISK_RENAME_FAILED);
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

#[cfg(test)]
#[path = "tests/host_disk_lane_tests.rs"]
mod lane_tests;
