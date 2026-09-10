// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this process does with what the file sink REPORTS.
//!
//! `busbar-export-file` is a crate of kind `export`: it may name neither a metrics recorder nor a
//! diagnostics registry, because both are properties of the process it was loaded into rather than
//! of the sink. So it reports, and the composer decides what a report means. Here that means the
//! same five diagnostics and three counters the in-engine sink emitted — byte-identical ids,
//! byte-identical field names, byte-identical metric series — so nothing an operator's dashboard or
//! log pipeline matches on moved when the sink did.

// THE COUNTER NAMES THROUGH THE PARENT, THE DIAGNOSTIC MACRO OFF THE SUBSTRATE. The `legacy-reach`
// ratchet counts DISTINCT symbols the root spells through a RETIRING crate's prefix and may only go
// down, so `metrics` is the one the parent module already spells and `diag_warn!` is taken from the
// substrate's own cross-crate twin — a byte-identical expansion, emitting the same `diag =` field
// on the same coded ids, without teaching the root one more name through a crate that is leaving.
use busbar_substrate_values::{diag_warn, diagnostics};

use super::metrics;
use busbar_export_file::{Event, Report};

/// The [`Report`] every composed file sink is built with.
pub(crate) struct EngineReport;

impl Report for EngineReport {
    fn report(&self, event: Event<'_>) {
        match event {
            Event::Rotated { path, archive } => {
                tracing::info!(path = %path, archive = %archive, "request-log file rotated by rename");
                ::metrics::counter!(metrics::FILE_LOGS_ROTATED_TOTAL).increment(1);
            }
            Event::RotateFailed { path, error } => {
                diag_warn!(
                    diagnostics::FILE_LOG_ROTATE_RENAME_FAILED,
                    path = %path, error = %error,
                    "request-log file rotation rename failed; continuing to APPEND to the current file \
                     rather than truncate it, so no recorded data is lost — the file will exceed rotate_mb \
                     until this is resolved"
                );
                ::metrics::counter!(metrics::FILE_LOGS_ROTATE_FAILED_TOTAL).increment(1);
            }
            Event::ArchiveShiftFailed { from, to, error } => diag_warn!(
                diagnostics::FILE_LOG_SHIFT_FAILED,
                from = %from, to = %to, error = %error,
                "request-log archive shift failed; older archive left in place rather than lost"
            ),
            Event::RetentionCleanupFailed { archive, error } => diag_warn!(
                diagnostics::FILE_LOG_RETENTION_FAILED,
                archive = %archive, error = %error,
                "request-log archive retention cleanup failed; the archive series may exceed ROTATE_ARCHIVE_LIMIT"
            ),
            Event::AppendFailed { path, error } => diag_warn!(
                diagnostics::FILE_LOG_APPEND_FAILED,
                path = %path, error = %error,
                "request-log file append failed; this log was dropped"
            ),
            Event::OpenFailed { path, error } => diag_warn!(
                diagnostics::FILE_LOG_OPEN_FAILED,
                path = %path, error = %error,
                "request-log file open failed; this log was dropped"
            ),
        }
    }
}
