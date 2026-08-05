// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **request-log-file** exporter (PUSH) — design §2.3, §8.
//!
//! Appends each built request-log line to a JSONL file. Like the webhook exporter it is a DISTRIBUTION
//! sink: the projection is built in core, this module only ships it. Configured from
//! `export.request-log-file`; absent ⇒ no file sink.

use crate::config::ExportCfg;
use serde_json::Value;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// The configured JSONL sink (path + optional rotate size in MiB), set once at boot. Unset ⇒ no file
/// sink. The `Mutex` serializes concurrent appends so two request-finish tasks never interleave a line.
struct FileSink {
    path: String,
    rotate_bytes: Option<u64>,
    lock: Mutex<()>,
}

static SINK: OnceLock<FileSink> = OnceLock::new();

/// Configure the request-log file sink from the `export:` block. No-op when `export.request-log-file`
/// is absent.
pub(crate) fn configure(cfg: &ExportCfg) {
    if let Some(f) = &cfg.request_log_file {
        let _ = SINK.set(FileSink {
            path: f.settings.path.clone(),
            rotate_bytes: f
                .settings
                .rotate_mb
                .map(|mb| mb.saturating_mul(1024 * 1024)),
            lock: Mutex::new(()),
        });
    }
}

/// True when the file sink is configured.
#[inline]
pub(crate) fn configured() -> bool {
    SINK.get().is_some()
}

/// Append one request-log line to the JSONL file. No-op when unconfigured. Fire-and-forget: the blocking
/// filesystem write is offloaded to the blocking pool so it never stalls the async request-finish path,
/// and any I/O error is logged (once) rather than propagated — telemetry must not affect serving.
pub(crate) fn deliver(payload: &Value) {
    let Some(sink) = SINK.get() else {
        return;
    };
    let line = payload.to_string();
    tokio::task::spawn_blocking(move || {
        let _guard = sink.lock.lock().unwrap_or_else(|e| e.into_inner());
        // Best-effort size bound (design §8 `rotate_mb`): when the file exceeds the configured size,
        // roll over by truncation rather than a rename (which would bypass the durable-write choke
        // point) — a bounded on-disk footprint without a second durable-write path.
        let truncate = sink
            .rotate_bytes
            .and_then(|limit| std::fs::metadata(&sink.path).ok().map(|m| m.len() >= limit))
            .unwrap_or(false);
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(!truncate)
            .write(true)
            .truncate(truncate)
            .open(&sink.path);
        match opened {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{line}") {
                    tracing::warn!(path = %sink.path, error = %e, "request-log file append failed; this log was dropped");
                }
            }
            Err(e) => {
                tracing::warn!(path = %sink.path, error = %e, "request-log file open failed; this log was dropped");
            }
        }
    });
}
