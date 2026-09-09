// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-file** exporter (PUSH) — its CONFIGURATION and its FAN-OUT.
//!
//! Appends each built request-log line to a JSONL file. Like the webhook exporter it is a DISTRIBUTION
//! sink: the projection is built in core, this module only ships it. Configured from
//! `export.request-log-file`; absent ⇒ no file sink.
//!
//! **The bytes-to-disk half is NOT here.** What happens to a file that has already been written —
//! append-never-truncate, rollover by rename, a retention-bounded archive series — is a claim about
//! recorded history, so it belongs to the unit that answers for recorded history and lives in
//! [`busbar_unit_audit::export`]. This module owns only what is offered to it: the projection each
//! named instance carries, its own in-flight admission cap, getting the blocking write off the
//! request path, the two rotation counters, and the coded words — the writer hands a failure back as
//! a [`Fault`] and [`report`] renders it under the code operators already grep for.

use crate::config::ExportCfg;
use crate::export::projection::Projection;
use crate::export::PayloadCache;
use crate::limits::admission::AdmissionGate;
use busbar_unit_audit::export::{append_line, Fault, Rotation};
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
        // The unit owns the RULE — append, never truncate; roll over by rename; a retention-bounded
        // archive series — and hands back the two things it cannot speak for: whether a rollover
        // happened, because the counters are this side's, and anything it could not do, because the
        // coded words for those are this side's too and an operator greps for exactly these codes.
        let rotation = append_line(&sink.path, sink.rotate_bytes, &line, &mut |fault| {
            report(fault)
        });
        match rotation {
            Rotation::Renamed => {
                tracing::info!(path = %sink.path, archive = %format!("{}.1", sink.path), "request-log file rotated by rename");
                metrics::counter!(crate::metrics::FILE_LOGS_ROTATED_TOTAL).increment(1);
            }
            Rotation::RenameFailed => {
                metrics::counter!(crate::metrics::FILE_LOGS_ROTATE_FAILED_TOTAL).increment(1);
            }
            Rotation::NotNeeded => {}
        }
    });
}

/// Render one thing the writer could not do under the code an operator already greps for.
///
/// One arm per [`Fault`] variant and nothing else: the CODE, the fields and the words are exactly
/// the ones this module published before the writer moved, because a diagnostic that changed its
/// code is a diagnostic somebody's alert no longer matches. What each failure MEANS for recorded
/// history is the unit's doc; what it is CALLED is the catalog's, and the catalog is here.
fn report(fault: Fault<'_>) {
    match fault {
        Fault::Append { path, error } => {
            crate::diagnostics::diag_warn!(crate::diagnostics::FILE_LOG_APPEND_FAILED, path = %path, error = %error, "request-log file append failed; this log was dropped");
        }
        Fault::Open { path, error } => {
            crate::diagnostics::diag_warn!(crate::diagnostics::FILE_LOG_OPEN_FAILED, path = %path, error = %error, "request-log file open failed; this log was dropped");
        }
        Fault::RetentionCleanup { archive, error } => {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::FILE_LOG_RETENTION_FAILED,
                archive = %archive, error = %error,
                "request-log archive retention cleanup failed; the archive series may exceed ROTATE_ARCHIVE_LIMIT"
            );
        }
        Fault::ArchiveShift { from, to, error } => {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::FILE_LOG_SHIFT_FAILED,
                from = %from, to = %to, error = %error,
                "request-log archive shift failed; older archive left in place rather than lost"
            );
        }
        Fault::RotateRename { path, error } => {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::FILE_LOG_ROTATE_RENAME_FAILED,
                path = %path, error = %error,
                "request-log file rotation rename failed; continuing to APPEND to the current file \
                 rather than truncate it, so no recorded data is lost — the file will exceed rotate_mb \
                 until this is resolved"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/file_tests.rs"]
mod tests;
