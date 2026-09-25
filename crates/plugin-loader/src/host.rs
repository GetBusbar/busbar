// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S ACTS FOR A COLD SINK (K9a S4) — the host side of [`HostOp`].
//!
//! A cold plugin has no host-callback vtable; it cannot be handed a file descriptor, and it must not
//! open a path or dial a socket itself (the host owns the destination and the egress chokepoint —
//! BUSBAR-1.6.0 18b(c), Part 4 Axis 3). So a sink ASKS: a delivery answers
//! [`ExportResponse::Host`](busbar_plugin::cold::export::ExportResponse::Host) with the acts it
//! needs, the host performs them here under its own rules, and hands the outcomes back on
//! `resume`.
//!
//! **The destination handle.** A sink's manifest declares which of its SETTINGS keys name a
//! destination (`declares.destinations`). At open the host resolves each declared key against the
//! OPERATOR's settings for the instance and binds the handle — the path the operator wrote, under a
//! per-destination lock. An op names the handle by its key, never a path: a sink can write only
//! where the operator's configuration pointed a declared destination.
//!
//! **The egress carrier.** An [`HostOp::Http`] is carried by the [`EgressCarrier`] the composition
//! root installs — the host's own egress — never dialled by the plugin.
//!
//! **Why each write opens the path.** A destination is appended to by opening it for append (created
//! if absent) per write, which is what the host's request-log file sink has always done: a file an
//! external rotator moved aside is not written through a stale descriptor, and an unopenable path is
//! a per-write failure the sink reports rather than a boot it refuses.

use busbar_plugin::cold::export::{HostOp, HostResult, HttpRequest, Rotation, RotationFault};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

/// The most archives a rotation may keep — a bound on the renames one op can cost.
const MAX_KEEP: u32 = 64;

/// One bound destination: the operator's path, and the lock every act on it takes.
#[derive(Debug)]
struct Destination {
    path: String,
    lock: Mutex<()>,
}

/// The destinations a sink was granted at open — its declared keys, resolved against the settings.
#[derive(Debug, Default)]
pub struct Destinations(BTreeMap<String, Destination>);

impl Destinations {
    /// Bind each `declared` settings key the instance's `settings` (JSON text) set to a non-empty
    /// string path. A declared key the operator did not set is simply not a destination; a value
    /// that is not a usable path (empty, or carrying a NUL) is refused naming the key.
    pub fn bind(declared: &[String], settings: &str) -> Result<Destinations, String> {
        let settings: serde_json::Value = serde_json::from_str(settings).unwrap_or_default();
        let mut bound = BTreeMap::new();
        for key in declared {
            let Some(value) = settings.get(key) else {
                continue;
            };
            match value.as_str() {
                Some(path) if !path.is_empty() && !path.contains('\0') => {
                    let lock = Mutex::new(());
                    let path = path.to_string();
                    bound.insert(key.clone(), Destination { path, lock });
                }
                _ => return Err(format!("settings.{key}: a destination must be a path")),
            }
        }
        Ok(Destinations(bound))
    }

    /// Perform `op` against the destination it names and say what happened. Never fails the
    /// delivery: every failure — including a destination this sink was not granted — is an
    /// outcome the sink is told about.
    pub fn perform(&self, op: &HostOp) -> HostResult {
        let destination = match op {
            HostOp::Write { destination, .. }
            | HostOp::Rotate { destination, .. }
            | HostOp::Flush { destination } => destination,
            HostOp::Http(request) => return carry(request),
        };
        let Some(d) = self.0.get(destination) else {
            let error = format!("no destination '{destination}' was granted to this sink");
            return failed("destination", error, None);
        };
        let _held = d.lock.lock().unwrap_or_else(|e| e.into_inner());
        match op {
            HostOp::Write {
                data,
                rotate_at,
                keep,
                ..
            } => write(d, data, *rotate_at, *keep),
            HostOp::Rotate { keep, .. } => HostResult::Done {
                rotation: Some(rotate(&d.path, *keep)),
            },
            HostOp::Flush { .. } => flush(d),
            HostOp::Http(request) => carry(request),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE EGRESS CARRIER (K9a S5). The host ALWAYS owns the outbound chokepoint (Part 4 Axis 3): a
// sink's HTTP request is carried by what the composition root installs — the host's egress, with
// its URL policy, TLS and deadlines — and a host that installs none carries nothing.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The host's egress, as the loader drives it for a cold sink.
pub trait EgressCarrier: Send + Sync {
    /// Carry `request` under the host's egress policy: the far end's answer, or a
    /// [`HostResult::Failed`] (`refused` when the policy refuses it, `request` when it fails in
    /// flight). Called on the delivery's blocking thread.
    fn carry(&self, request: &HttpRequest) -> HostResult;
}

static CARRIER: std::sync::OnceLock<&'static dyn EgressCarrier> = std::sync::OnceLock::new();

/// Install the host's egress carrier — the composition root's one write. The first install wins;
/// a later one returns `false`.
pub fn install_egress_carrier(carrier: &'static dyn EgressCarrier) -> bool {
    CARRIER.set(carrier).is_ok()
}

/// Carry one sink request through the installed carrier; with none installed, refuse it.
fn carry(request: &HttpRequest) -> HostResult {
    match CARRIER.get() {
        Some(carrier) => carrier.carry(request),
        None => failed("refused", "this host carries no plugin egress", None),
    }
}

fn failed(step: &str, error: impl ToString, rotation: Option<Rotation>) -> HostResult {
    HostResult::Failed {
        step: step.to_string(),
        error: error.to_string(),
        rotation,
    }
}

/// Append `data`, rotating first when the file already holds `rotate_at` bytes.
fn write(d: &Destination, data: &str, rotate_at: Option<u64>, keep: u32) -> HostResult {
    let due =
        rotate_at.is_some_and(|limit| std::fs::metadata(&d.path).is_ok_and(|m| m.len() >= limit));
    let rotation = due.then(|| rotate(&d.path, keep));
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&d.path);
    match opened {
        Ok(mut file) => match file.write_all(data.as_bytes()) {
            Ok(()) => HostResult::Done { rotation },
            Err(e) => failed("append", e, rotation),
        },
        Err(e) => failed("open", e, rotation),
    }
}

/// Flush the destination to stable storage (it is written unbuffered, so this is the fsync).
fn flush(d: &Destination) -> HostResult {
    let synced = std::fs::OpenOptions::new()
        .append(true)
        .open(&d.path)
        .and_then(|f| f.sync_all());
    match synced {
        Ok(()) => HostResult::Done { rotation: None },
        Err(e) => failed("flush", e, None),
    }
}

/// Rotate `path` by rename, keeping `keep` archives: drop the oldest, shift the rest up, rename the
/// live file to `<path>.1`. Each failed step is recorded and the rest still run; a failed final
/// rename leaves the live file in place to keep being appended to, never truncated.
fn rotate(path: &str, keep: u32) -> Rotation {
    let keep = keep.clamp(1, MAX_KEEP);
    let mut faults = Vec::new();
    let fault = |step: &str, from: &str, to: Option<&str>, e: std::io::Error| RotationFault {
        step: step.to_string(),
        from: from.to_string(),
        to: to.map(str::to_string),
        error: e.to_string(),
    };
    let oldest = format!("{path}.{keep}");
    if Path::new(&oldest).exists() {
        if let Err(e) = std::fs::remove_file(&oldest) {
            faults.push(fault("retention", &oldest, None, e));
        }
    }
    for i in (1..keep).rev() {
        let (from, to) = (format!("{path}.{i}"), format!("{path}.{}", i + 1));
        if Path::new(&from).exists() {
            if let Err(e) = std::fs::rename(&from, &to) {
                faults.push(fault("shift", &from, Some(&to), e));
            }
        }
    }
    let archive = format!("{path}.1");
    let renamed = match std::fs::rename(path, &archive) {
        Ok(()) => true,
        Err(e) => {
            faults.push(fault("rename", path, Some(&archive), e));
            false
        }
    };
    Rotation {
        archive,
        renamed,
        faults,
    }
}

#[cfg(test)]
#[path = "tests/host_tests.rs"]
mod tests;
