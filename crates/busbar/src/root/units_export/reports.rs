// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this process does with what the composed sinks REPORT.
//!
//! A crate of kind `export` may name neither a metrics recorder nor a diagnostics registry, because
//! both are properties of the process it was loaded into rather than of the sink. So the sinks
//! report, and the composer decides what a report means. Here that means the same seven diagnostics
//! and three counters the in-engine sinks emitted — byte-identical ids, byte-identical field names,
//! byte-identical metric series — so nothing an operator's dashboard or log pipeline matches on
//! moved when the sinks did.
//!
//! BOTH IMPLS ARE IN ONE FILE and that is deliberate: the substrate's diagnostic twin is spelled
//! ONCE for the whole fan-out. The `legacy-reach` ratchet counts what the root spells through a
//! retiring crate's prefix and may only go down, so a second composed sink must not cost a second
//! import of the same macro.
//!
//! THE WEBHOOK'S MASKING IS ALREADY DONE, and deliberately not here. The `url` on every webhook
//! event is the masked spelling the config layer produced once when it validated the target,
//! carried by the sink from construction. Neither this file nor the crate it serves holds the raw
//! target's credentials in a form it could log by accident.

// THE COUNTER NAMES THROUGH THE PARENT, THE DIAGNOSTIC MACRO OFF THE SUBSTRATE. The `legacy-reach`
// ratchet counts DISTINCT symbols the root spells through a RETIRING crate's prefix and may only go
// down, so `metrics` is the one the parent module already spells and `diag_warn!` is taken from the
// substrate's own cross-crate twin — a byte-identical expansion, emitting the same `diag =` field
// on the same coded ids, without teaching the root one more name through a crate that is leaving.
use busbar_substrate_values::{diag_debug, diag_warn, diagnostics};

use super::metrics;
use busbar_export_file::{Event, Report};
use busbar_export_otlp::{Event as OtlpEvent, Report as OtlpReport};
use busbar_export_webhook::{Event as WebhookEvent, Report as WebhookReport};

/// The [`Report`] every composed file sink is built with.
pub(crate) struct EngineFileReport;

impl Report for EngineFileReport {
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

/// The [`WebhookReport`] every composed webhook sink is built with.
pub(crate) struct EngineWebhookReport;

impl WebhookReport for EngineWebhookReport {
    fn report(&self, event: WebhookEvent<'_>) {
        match event {
            WebhookEvent::Non2xx { url, status } => diag_debug!(
                diagnostics::WEBHOOK_DELIVERY_NON_2XX,
                webhook_url = url,
                status = status,
                "request-log webhook delivery returned a non-2xx status; this log was dropped"
            ),
            WebhookEvent::TransportError { url, error } => diag_debug!(
                diagnostics::WEBHOOK_DELIVERY_TRANSPORT_ERROR,
                webhook_url = url,
                error_kind = %error,
                "request-log webhook delivery failed (transport error); this log was dropped"
            ),
        }
    }
}

/// The [`OtlpReport`] the composed OTLP sink is built with.
///
/// NO CODED DIAGNOSTIC ID, and that is a measurement rather than an omission: the pipeline this
/// replaces raised NONE — an `eprintln!` on a failed exporter build and whatever the SDK chose to
/// say about a delivery, neither of which an operator could match on. These four lines are what
/// this process can honestly say about an export it now owns, and none of them can carry the
/// operator's credential because no event of this sink names the target at all.
pub(crate) struct EngineOtlpReport;

impl OtlpReport for EngineOtlpReport {
    fn report(&self, event: OtlpEvent<'_>) {
        match event {
            OtlpEvent::Refused { status } => tracing::warn!(
                status,
                "OTLP trace export was REFUSED; this batch was dropped and every following one will \
                 be too until the endpoint, the credential or the payload the collector rejects is \
                 corrected"
            ),
            OtlpEvent::Unavailable { status } => tracing::debug!(
                status,
                "OTLP trace export could not be accepted right now; this batch was dropped"
            ),
            OtlpEvent::TransportError { error } => tracing::debug!(
                error_kind = %error,
                "OTLP trace export failed (transport error); this batch was dropped"
            ),
            OtlpEvent::MalformedBatch { error } => tracing::warn!(
                error_kind = %error,
                "OTLP trace export was handed bytes that are not a span batch; this batch was dropped"
            ),
        }
    }
}
