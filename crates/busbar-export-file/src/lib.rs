// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **request-log FILE sink** (`module: request-log-file`, PUSH): each request-log line the host
//! builds for this instance is appended to a JSONL file, rotated by RENAME at `rotate_mb`.
//!
//! A real export sink over the COLD export ABI, served through either door by one registration
//! (DECISIONS #2 rule (1)): LINKED into the binary ([`linked::EXPORT`]) or DROPPED IN as a signed
//! tarball whose manifest carries [`DECLARES`] (`busbar-plugin-pack --declares-file declares.json`).
//!
//! **The sink never opens a path.** Its manifest declares `path` a DESTINATION (K9a S4): the host
//! binds the operator's configured path at open, and every append, every rotation (drop the oldest
//! of [`ROTATE_ARCHIVE_LIMIT`] archives, shift the rest up, rename the live file to `<path>.1`) and
//! every open is a host act on that handle. The sink says WHAT to write and when to rotate; the host
//! says what happened, and the sink reports it:
//!
//! - its series — `busbar_file_logs_{rotated,rotate_failed}_total` from its own drain, and
//!   `busbar_file_logs_dropped_total`, the SHED counter the host counts a delivery it sheds on — are
//!   declared first-party (K9a S1, K9b) and render as they always did;
//! - its five `BUSBAR-707x` codes are declared (K9a S3) and join the host's catalogue, and each line
//!   is raised with the catalogue's `diag` banner field, in the order and words it always was.
//!
//! Settings are validated by the sink itself while the host validates the configuration (K9a S2),
//! with the same serde shape ([`config::FileSettings`]) and so the same words.

#![deny(unsafe_code)]

pub mod config;

use busbar_plugin_sdk::{
    ExportHandler, ExportStream, HostOp, HostResult, HostStep, Observations, PluginMetric, Rotation,
};
use config::FileSettings;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// The row's canonical name.
pub const NAME: &str = "busbar-export-file";

/// The `module:` an operator writes — the frozen 1.5.x module name.
pub const ALIAS: &str = "request-log-file";

/// What this sink DECLARES to the host (the manifest's `declares` section): its three series, its
/// five catalogue codes and its one destination. ONE file, stated by both doors — the linked row
/// reads it here, the packer embeds it (`--declares-file`).
pub const DECLARES: &str = include_str!("../declares.json");

/// How many rotated archives ONE sink keeps (`<path>.1` .. `<path>.{ROTATE_ARCHIVE_LIMIT}`) before the
/// oldest is dropped to make room for a new rotation. A RETENTION policy, not a truncation one: every
/// rotation preserves the just-completed file in full by renaming it. A compiled-in constant: the
/// file exporter's config surface is frozen for 1.5.3.
pub const ROTATE_ARCHIVE_LIMIT: u32 = 9;

/// The declared destination: the settings key naming the file.
const DESTINATION: &str = "path";

/// The sink's series, exactly as they render.
pub const ROTATED_TOTAL: &str = "busbar_file_logs_rotated_total";
/// See [`ROTATED_TOTAL`].
pub const ROTATE_FAILED_TOTAL: &str = "busbar_file_logs_rotate_failed_total";
/// The shed counter — counted by the HOST (the sink never sees a shed delivery).
pub const DROPPED_TOTAL: &str = "busbar_file_logs_dropped_total";

/// The five catalogue codes this sink raises (declared in [`DECLARES`]).
pub const APPEND_FAILED: &str = "BUSBAR-7073";
/// See [`APPEND_FAILED`].
pub const OPEN_FAILED: &str = "BUSBAR-7074";
/// See [`APPEND_FAILED`].
pub const RETENTION_FAILED: &str = "BUSBAR-7075";
/// See [`APPEND_FAILED`].
pub const SHIFT_FAILED: &str = "BUSBAR-7076";
/// See [`APPEND_FAILED`].
pub const ROTATE_RENAME_FAILED: &str = "BUSBAR-7077";

/// One opened instance.
struct FileSink {
    /// The instance's settings; `None` when they do not parse (validation already refused them, so
    /// an instance that got this far is never configured that way — it simply writes nothing).
    settings: Option<FileSettings>,
    /// Rotations the host performed since the last drain.
    rotated: AtomicU64,
    /// Rotations whose final rename failed since the last drain.
    rotate_failed: AtomicU64,
}

impl ExportHandler for FileSink {
    /// `logs`: the request-log line.
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Logs]
    }

    /// Have the host append the line to the destination — rotating first when the file already
    /// holds `rotate_mb` MiB.
    fn deliver_via_host(&self, _stream: ExportStream, payload: &serde_json::Value) -> HostStep {
        let Some(settings) = &self.settings else {
            return HostStep::Done;
        };
        let rotate_at = settings.rotate_mb.map(|mb| mb.saturating_mul(1024 * 1024));
        let write = HostOp::Write {
            destination: DESTINATION.to_string(),
            data: format!("{payload}\n"),
            rotate_at,
            keep: ROTATE_ARCHIVE_LIMIT,
        };
        HostStep::Host {
            token: 0,
            ops: vec![write],
        }
    }

    /// Report what the host did, in the order it did it: the rotation's steps, then the append.
    fn resume(&self, _token: u64, results: Vec<HostResult>) -> HostStep {
        let path = self.settings.as_ref().map_or("", |s| s.path.as_str());
        for result in results {
            match result {
                HostResult::Done { rotation } => self.rotation(path, rotation),
                HostResult::Failed {
                    step,
                    error,
                    rotation,
                } => {
                    self.rotation(path, rotation);
                    match step.as_str() {
                        "append" => {
                            tracing::warn!(diag = %APPEND_FAILED, path = %path, error = %error, "request-log file append failed; this log was dropped")
                        }
                        _ => {
                            tracing::warn!(diag = %OPEN_FAILED, path = %path, error = %error, "request-log file open failed; this log was dropped")
                        }
                    }
                }
                _ => {}
            }
        }
        HostStep::Done
    }

    /// The instance's settings, parsed as the configuration grammar parses them — the error, when
    /// there is one, is the line the host has always reported.
    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match serde_json::from_value::<FileSettings>(settings.clone()) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("export.{instance}.settings: {e}")],
        }
    }

    /// Hand over the rotations since the last drain and reset (a counter is folded as a delta).
    fn drain_observations(&self) -> Observations {
        let mut observed = Observations::none();
        for (series, counter) in [
            (ROTATED_TOTAL, &self.rotated),
            (ROTATE_FAILED_TOTAL, &self.rotate_failed),
        ] {
            let n = counter.swap(0, Relaxed);
            if n > 0 {
                observed = observed.metric(PluginMetric::counter(series, n as f64));
            }
        }
        observed
    }
}

impl FileSink {
    /// The lines and counts one rotation the host ran is owed: each failed step as it failed —
    /// retention, then each shift, then the final rename — and then, when the live file WAS
    /// renamed, the rotation itself.
    fn rotation(&self, path: &str, rotation: Option<Rotation>) {
        let Some(r) = rotation else {
            return;
        };
        for f in &r.faults {
            let (from, to, error) = (&f.from, f.to.as_deref().unwrap_or(""), &f.error);
            match f.step.as_str() {
                "retention" => tracing::warn!(
                    diag = %RETENTION_FAILED,
                    archive = %from, error = %error,
                    "request-log archive retention cleanup failed; the archive series may exceed ROTATE_ARCHIVE_LIMIT"
                ),
                "shift" => tracing::warn!(
                    diag = %SHIFT_FAILED,
                    from = %from, to = %to, error = %error,
                    "request-log archive shift failed; older archive left in place rather than lost"
                ),
                _ => {
                    tracing::warn!(
                        diag = %ROTATE_RENAME_FAILED,
                        path = %from, error = %error,
                        "request-log file rotation rename failed; continuing to APPEND to the current file \
                         rather than truncate it, so no recorded data is lost — the file will exceed rotate_mb \
                         until this is resolved"
                    );
                    self.rotate_failed.fetch_add(1, Relaxed);
                }
            }
        }
        if r.renamed {
            tracing::info!(path = %path, archive = %r.archive, "request-log file rotated by rename");
            self.rotated.fetch_add(1, Relaxed);
        }
    }
}

/// Open one instance over its settings (JSON text). Never refuses: the settings were validated with
/// the configuration, and an instance whose settings do not parse writes nothing.
///
/// `pub` so a test can drive exactly the handler the `cdylib`'s `busbar_open` constructs.
pub fn open(cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(FileSink {
        settings: serde_json::from_str(cfg).ok(),
        rotated: AtomicU64::new(0),
        rotate_failed: AtomicU64::new(0),
    }))
}

busbar_plugin_sdk::export_export_plugin!(open);

/// THE COMPILED-IN ENTRY POINT — the same op-dispatch `busbar_call` runs, envelope included.
pub fn dispatch_compiled_in(
    handler: &dyn ExportHandler,
    req: busbar_plugin_sdk::ExportRequest,
) -> busbar_plugin_sdk::Envelope<busbar_plugin_sdk::ExportResponse> {
    busbar_plugin_sdk::dispatch_export_enveloped(handler, req)
}

/// THE LINKED DOOR's entry: what the composition root's `exports` axis reads for this crate.
pub mod linked {
    /// `(name, alias, declares, boundary)` — the row's statement and the boundary the one cold
    /// load runs over, exactly what the dropped-in tarball states and exports.
    pub const EXPORT: (&str, &str, &str, &busbar_plugin_sdk::ColdEntry) = (
        super::NAME,
        super::ALIAS,
        super::DECLARES,
        &super::BUSBAR_COLD_ENTRY,
    );
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
