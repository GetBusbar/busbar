// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-file** exporter (PUSH).
//!
//! Appends each built request-log line to a JSONL file. Like the webhook exporter it is a DISTRIBUTION
//! sink: the projection is built in core, this module only ships it. Configured from
//! `export.request-log-file`; absent ⇒ no file sink.

use crate::config::ExportCfg;
use crate::export::projection::Projection;
use crate::export::PayloadCache;
use crate::limits::admission::AdmissionGate;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// How many blocking append tasks ONE file sink may have in flight at once. Every append is a
/// `spawn_blocking` holding an owned `String`, and they SERIALIZE on the sink's `Mutex` — so on a
/// slow or stalled filesystem (a full disk, a hung NFS/EBS mount) an unbounded fan-out accumulates
/// one blocked blocking-pool thread and one owned line per request, without limit. Bounded the same
/// way the sibling webhook exporter is bounded (an [`AdmissionGate`]: shed the log, count the shed,
/// never block the request path). Deliberately a compiled-in constant rather than a new setting: the
/// file exporter's config surface is frozen for 1.5.3, and this is a resource FLOOR that no
/// deployment has a reason to tune (the value matches the webhook exporter's default cap).
const MAX_INFLIGHT_FILE_APPENDS: usize = 64;

/// How many rotated archives ONE sink keeps (`<path>.1` .. `<path>.{ROTATE_ARCHIVE_LIMIT}`) before
/// the oldest is dropped to make room for a new rotation. This is a RETENTION policy, not a
/// truncation one: every rotation preserves the just-completed file in full by renaming it — nothing
/// written to disk is ever discarded except an archive that has already aged past this many
/// rotations. Deliberately a compiled-in constant like [`MAX_INFLIGHT_FILE_APPENDS`]: the file
/// exporter's config surface is frozen for 1.5.3.
const ROTATE_ARCHIVE_LIMIT: usize = 9;

/// One configured JSONL sink (path + optional rotate size in MiB). The `Mutex` serializes concurrent
/// appends so two request-finish tasks never interleave a line.
struct FileSink {
    path: String,
    rotate_bytes: Option<u64>,
    lock: Mutex<()>,
    /// This sink's OWN in-flight append cap — one gate PER named instance, exactly as each named
    /// webhook instance owns its own (a stalled audit-mount sink must not shed the local tail file's
    /// lines, or vice versa).
    gate: AdmissionGate,
    /// This instance's PROJECTION — see the sibling webhook sink: the line this sink is handed is
    /// built to exactly this, so an ungranted field is never written to disk.
    projection: Projection,
}

/// Every configured `module: request-log-file` instance, in config order, set once at boot. Unset ⇒
/// no file sink at all. 1.5.3: a `Vec` because `export:` is a NAMED map — two named file instances
/// (e.g. a local tail file and an audit-mount file) are a legitimate configuration.
static SINKS: OnceLock<Vec<FileSink>> = OnceLock::new();

/// Configure the request-log file sinks from the resolved `export:` block — one per named
/// `module: request-log-file` instance. No-op when none is configured.
pub(crate) fn configure(cfg: &ExportCfg) {
    if cfg.request_log_files.is_empty() {
        return;
    }
    let _ = SINKS.set(
        cfg.request_log_files
            .iter()
            .map(|f| FileSink {
                path: f.path.clone(),
                rotate_bytes: f.rotate_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
                lock: Mutex::new(()),
                gate: AdmissionGate::new(MAX_INFLIGHT_FILE_APPENDS, "request-log-file"),
                projection: f.projection,
            })
            .collect(),
    );
}

/// Append one request-log line to the JSONL file. No-op when unconfigured. Fire-and-forget: the blocking
/// filesystem write is offloaded to the blocking pool so it never stalls the async request-finish path,
/// and any I/O error is logged (once) rather than propagated — telemetry must not affect serving.
/// BOUNDED per sink by [`MAX_INFLIGHT_FILE_APPENDS`]: a stalled filesystem sheds logs (counted on
/// `busbar_file_logs_dropped_total` + `busbar_admission_denied_total{gate="request-log-file"}`)
/// rather than accumulating tasks and owned lines without limit.
pub(crate) fn deliver(cache: &mut PayloadCache<'_>) {
    let Some(sinks) = SINKS.get() else {
        return;
    };
    for sink in sinks {
        // Built to THIS sink's projection (shared with any sibling holding the identical one).
        append_one(sink, cache.get(sink.projection).to_string());
    }
}

/// Append one already-serialized line to ONE sink, off the async path. Split out of [`deliver`] so
/// the fan-out over named instances stays a plain loop.
fn append_one(sink: &'static FileSink, line: String) {
    // Take an append slot WITHOUT waiting; drop this log (counted) rather than block the request
    // path or pile up an unbounded backlog of blocked blocking-pool tasks when the sink is saturated.
    // Same posture — and the same mechanic — as the webhook exporter's shed.
    let Some(permit) = sink.gate.try_enter() else {
        metrics::counter!(crate::metrics::FILE_LOGS_DROPPED_TOTAL).increment(1);
        return;
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit; // slot releases on task end via the owned permit's Drop.
        let _guard = sink.lock.lock().unwrap_or_else(|e| e.into_inner());
        // Best-effort size bound (`rotate_mb`): when the file exceeds the configured size, roll it
        // over by RENAME to a numbered archive, never by truncation — this sink can be an audit
        // trail, and destroying recorded history on a size threshold is not an acceptable "rotation".
        let needs_rotate = sink
            .rotate_bytes
            .and_then(|limit| std::fs::metadata(&sink.path).ok().map(|m| m.len() >= limit))
            .unwrap_or(false);
        if needs_rotate {
            rotate(&sink.path);
        }
        // ALWAYS append, never truncate: even on a failed rotation (see `rotate`) the correct
        // fallback is to keep growing the current file, not to void it.
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&sink.path);
        match opened {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{line}") {
                    crate::diagnostics::diag_warn!(crate::diagnostics::FILE_LOG_APPEND_FAILED, path = %sink.path, error = %e, "request-log file append failed; this log was dropped");
                }
            }
            Err(e) => {
                crate::diagnostics::diag_warn!(crate::diagnostics::FILE_LOG_OPEN_FAILED, path = %sink.path, error = %e, "request-log file open failed; this log was dropped");
            }
        }
    });
}

/// Roll `path` over to a numbered archive series (`path.1` is the newest archive, `path.N` the
/// oldest retained one) and free up `path` for a fresh file. Called with the sink's append `Mutex`
/// already held, so this never races a concurrent append or a concurrent rotation on the same sink.
///
/// Never truncates. On any rename failure this returns having changed nothing observable about
/// `path` itself — the caller then reopens it in append mode, so the file keeps growing past
/// `rotate_mb` rather than losing what's already on disk. A stuck rename (permissions, cross-device
/// archive dir, a racing external process) degrades to "rotation isn't happening", never to
/// "history is gone."
///
/// ## Why this hand-rolls `fs::rename` instead of routing through `crate::durable::write`
///
/// `crate::durable::write` owns "publish freshly computed bytes so a reader never observes a torn
/// write" — a fsync-the-content-before-rename dance built to protect a WRITE. This function does no
/// write: it renames a file whose bytes are already fully on disk. There was never a torn-write
/// contract to preserve here either — this sink's own appends (see [`append_one`]) are
/// fire-and-forget and unfsynced by design ("telemetry must not affect serving"), so a concurrent
/// tailer already has no atomicity guarantee across lines; rotation weakens nothing that existed
/// before it. And `fs::rename` only repoints a directory entry — it never touches the bytes it
/// names — so a crash mid-rotation can leave content under its PRIOR name but can never lose it or
/// leave it torn, which is exactly the property [`FileSink`]'s truncate-free contract needs.
/// Reusing `durable::write` here would mean reading the whole log — sized by the operator via
/// `rotate_mb` and legitimately hundreds of MB — into memory just to re-emit it as "new" bytes, to
/// buy a dance designed for small state/config artifacts. This is a LEDGERED exemption in
/// `scripts/structure-lint.sh`'s choke-point registry (row A-persistence), not a silent bypass.
fn rotate(path: &str) {
    // Free the oldest archive slot first so the shift below never collides with a still-occupied
    // name. Retention is a deliberate, documented bound (`ROTATE_ARCHIVE_LIMIT`) chosen by this
    // sink's default, not a side effect of the rotation mechanism.
    let oldest = format!("{path}.{ROTATE_ARCHIVE_LIMIT}");
    if std::path::Path::new(&oldest).exists() {
        if let Err(e) = std::fs::remove_file(&oldest) {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::FILE_LOG_RETENTION_FAILED,
                archive = %oldest, error = %e,
                "request-log archive retention cleanup failed; the archive series may exceed ROTATE_ARCHIVE_LIMIT"
            );
        }
    }
    // Shift path.{i} -> path.{i+1}, oldest first, so no archive is ever renamed onto one that still
    // holds unshifted data.
    for i in (1..ROTATE_ARCHIVE_LIMIT).rev() {
        let from = format!("{path}.{i}");
        if std::path::Path::new(&from).exists() {
            let to = format!("{path}.{}", i + 1);
            if let Err(e) = std::fs::rename(&from, &to) {
                crate::diagnostics::diag_warn!(
                    crate::diagnostics::FILE_LOG_SHIFT_FAILED,
                    from = %from, to = %to, error = %e,
                    "request-log archive shift failed; older archive left in place rather than lost"
                );
            }
        }
    }
    // The rotation that matters: the just-completed, still-un-archived current file becomes `.1`.
    let archive = format!("{path}.1");
    match std::fs::rename(path, &archive) {
        Ok(()) => {
            tracing::info!(path = %path, archive = %archive, "request-log file rotated by rename");
            metrics::counter!(crate::metrics::FILE_LOGS_ROTATED_TOTAL).increment(1);
        }
        Err(e) => {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::FILE_LOG_ROTATE_RENAME_FAILED,
                path = %path, error = %e,
                "request-log file rotation rename failed; continuing to APPEND to the current file \
                 rather than truncate it, so no recorded data is lost — the file will exceed rotate_mb \
                 until this is resolved"
            );
            metrics::counter!(crate::metrics::FILE_LOGS_ROTATE_FAILED_TOTAL).increment(1);
        }
    }
}

#[cfg(test)]
#[path = "tests/file_tests.rs"]
mod tests;
