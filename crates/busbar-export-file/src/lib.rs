// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

//! The built-in **`request-log-file`** export sink: append one JSONL line per delivery, and roll the
//! file over BY RENAME when it outgrows its configured size.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It is a sink of kind `export`. It takes an item and writes it. It does not decide whether there
//! is room for the delivery (its composer sheds for it, against the capacity this crate STATES in
//! [`MAX_INFLIGHT_APPENDS`]), it does not decide which thread the write runs on, and it does not
//! build the payload — the projection that bounds what may be in the line is resolved from the
//! operator's config long before it gets here, and by the time a delivery reaches [`FileSink::append`]
//! an ungranted field is already absent.
//!
//! It also does not EMIT. A recorder and a diagnostics registry are properties of the process this
//! sink was loaded into, not of the sink — and a crate of kind `export` may name neither. What the
//! sink cannot say for itself it REPORTS ([`Event`], [`Report`]), and its composer turns a report
//! into whatever that process spells a warning with. Nothing is swallowed: every arm of the old
//! in-engine sink's five diagnostics and three counters is an [`Event`] here.
//!
//! # Why the rotation is a rename, and never a truncation
//!
//! This sink can be an audit trail. Destroying recorded history on a size threshold is not an
//! acceptable "rotation", so [`FileSink::append`] rolls the completed file over to a numbered
//! archive series (`<path>.1` newest .. `<path>.9` oldest) and always reopens in APPEND mode. On any
//! rename failure it changes nothing observable about the current file, which then keeps growing
//! past `rotate_mb` — a stuck rename degrades to "rotation isn't happening", never to "history is
//! gone."

use std::io::Write;
use std::sync::{Arc, Mutex};

/// The operator's `module:` token for this sink, and the label its composer's capacity gate is named
/// with on the shared admission-denial series. Stated by the sink so the label is never a string the
/// fan-out invented about an instance it is shedding for.
pub const MODULE: &str = "request-log-file";

/// How many appends of ONE sink may be in flight at once. Every append holds an owned line and they
/// SERIALIZE on the sink's `Mutex`, so on a slow or stalled filesystem (a full disk, a hung NFS/EBS
/// mount) an unbounded fan-out accumulates one blocked thread and one owned line per request,
/// without limit. THE SINK STATES the bound; whoever composed it ENFORCES it, because capacity is a
/// property of the composition and not of a sink that knows nothing about what runs beside it.
///
/// Deliberately a compiled-in constant rather than a setting: this sink's config surface is frozen,
/// and this is a resource FLOOR no deployment has a reason to tune.
pub const MAX_INFLIGHT_APPENDS: usize = 64;

/// How many rotated archives ONE sink keeps (`<path>.1` .. `<path>.{ARCHIVE_LIMIT}`) before the
/// oldest is dropped to make room for a new rotation. A RETENTION policy, not a truncation one:
/// every rotation preserves the just-completed file in full by renaming it, and nothing on disk is
/// ever discarded except an archive that has already aged past this many rotations.
pub const ARCHIVE_LIMIT: usize = 9;

/// Something one append did that the sink cannot act on itself, handed to whoever composed it.
///
/// Every variant is a thing the operator needs told and this crate has no way to tell them: it has
/// no logger it may name and no counter it may increment. The borrow is the sink's own configured
/// path, so reporting costs no allocation beyond the error text the platform already produced.
#[derive(Debug)]
pub enum Event<'a> {
    /// The current file outgrew `rotate_mb` and was rolled over to `archive` by rename. The one
    /// GOOD-NEWS variant: a rotation that worked is still a thing an operator watches.
    Rotated {
        /// The sink's configured path — now a fresh, empty file.
        path: &'a str,
        /// Where the completed file went (`<path>.1`).
        archive: &'a str,
    },
    /// The rename that matters failed. The sink continues to APPEND to the current file rather than
    /// truncate it, so no recorded data is lost — the file will exceed `rotate_mb` until this is
    /// resolved.
    RotateFailed {
        /// The sink's configured path, left exactly as it was.
        path: &'a str,
        /// The platform's error text.
        error: String,
    },
    /// One archive could not be shifted along the series. The older archive is left in place rather
    /// than lost.
    ArchiveShiftFailed {
        /// The archive that could not be moved.
        from: String,
        /// Where it was going.
        to: String,
        /// The platform's error text.
        error: String,
    },
    /// The oldest archive could not be removed, so the series may exceed [`ARCHIVE_LIMIT`].
    RetentionCleanupFailed {
        /// The archive that outlived its retention.
        archive: String,
        /// The platform's error text.
        error: String,
    },
    /// The file opened but the line could not be written. THIS LOG WAS DROPPED.
    AppendFailed {
        /// The sink's configured path.
        path: &'a str,
        /// The platform's error text.
        error: String,
    },
    /// The file could not be opened at all. THIS LOG WAS DROPPED.
    OpenFailed {
        /// The sink's configured path.
        path: &'a str,
        /// The platform's error text.
        error: String,
    },
}

/// Where a sink's [`Event`]s go. Implemented by whoever composed the sink, which is the only party
/// that knows what this process spells a warning with.
pub trait Report: Send + Sync {
    /// Take one event. Must not panic and must not block for long: it runs on the append path.
    fn report(&self, event: Event<'_>);
}

/// A [`Report`] that drops everything — the default a caller with nothing to report INTO gets, and
/// what [`FileSink::new`] uses when none is supplied.
pub struct Silent;

impl Report for Silent {
    fn report(&self, _event: Event<'_>) {}
}

/// One configured JSONL sink: a path, an optional rotate size in bytes, and the `Mutex` that
/// serializes concurrent appends so two deliveries never interleave a line.
pub struct FileSink {
    path: String,
    rotate_bytes: Option<u64>,
    lock: Mutex<()>,
    report: Arc<dyn Report>,
}

impl FileSink {
    /// Build a sink for one configured instance. `rotate_mb` absent ⇒ never rotate.
    pub fn new(path: String, rotate_mb: Option<u64>, report: Arc<dyn Report>) -> Self {
        Self {
            path,
            rotate_bytes: rotate_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            lock: Mutex::new(()),
            report,
        }
    }

    /// A sink that reports nowhere — for a caller that has no diagnostics to report into, and for
    /// tests that are about the bytes on disk.
    pub fn silent(path: String, rotate_mb: Option<u64>) -> Self {
        Self::new(path, rotate_mb, Arc::new(Silent))
    }

    /// This sink's configured path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Append one already-serialized line. BLOCKING: the caller decides which thread this runs on.
    /// Never panics, never propagates — a sink that failed to write says so through [`Report`] and
    /// the delivery is over.
    pub fn append(&self, line: &str) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        // Best-effort size bound (`rotate_mb`): when the file exceeds the configured size, roll it
        // over by RENAME to a numbered archive, never by truncation.
        let needs_rotate = self
            .rotate_bytes
            .and_then(|limit| std::fs::metadata(&self.path).ok().map(|m| m.len() >= limit))
            .unwrap_or(false);
        if needs_rotate {
            self.rotate();
        }
        // ALWAYS append, never truncate: even on a failed rotation the correct fallback is to keep
        // growing the current file, not to void it.
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{line}") {
                    self.report.report(Event::AppendFailed {
                        path: &self.path,
                        error: e.to_string(),
                    });
                }
            }
            Err(e) => self.report.report(Event::OpenFailed {
                path: &self.path,
                error: e.to_string(),
            }),
        }
    }

    /// Roll the current file over to the numbered archive series and free up the path for a fresh
    /// file. Called with the append `Mutex` already held, so this never races a concurrent append or
    /// a concurrent rotation on the same sink.
    ///
    /// ## Why this hand-rolls `fs::rename` rather than a publish-fresh-bytes dance
    ///
    /// A fsync-the-content-before-rename dance protects a WRITE from being observed torn. This
    /// function does no write: it renames a file whose bytes are already fully on disk. There was no
    /// torn-write contract to preserve either — this sink's appends are fire-and-forget and unfsynced
    /// by design (telemetry must not affect serving), so a concurrent tailer already has no
    /// atomicity guarantee across lines, and rotation weakens nothing that existed before it. And
    /// `fs::rename` only repoints a directory entry — it never touches the bytes it names — so a
    /// crash mid-rotation can leave content under its PRIOR name but can never lose it or leave it
    /// torn, which is exactly the property the truncate-free contract needs. The alternative would
    /// mean reading the whole log — sized by the operator via `rotate_mb` and legitimately hundreds
    /// of MB — into memory just to re-emit it as "new" bytes.
    fn rotate(&self) {
        // Free the oldest archive slot first so the shift below never collides with a still-occupied
        // name. Retention is a deliberate, documented bound (`ARCHIVE_LIMIT`), not a side effect.
        let oldest = format!("{}.{ARCHIVE_LIMIT}", self.path);
        if std::path::Path::new(&oldest).exists() {
            if let Err(e) = std::fs::remove_file(&oldest) {
                self.report.report(Event::RetentionCleanupFailed {
                    archive: oldest,
                    error: e.to_string(),
                });
            }
        }
        // Shift path.{i} -> path.{i+1}, oldest first, so no archive is ever renamed onto one that
        // still holds unshifted data.
        for i in (1..ARCHIVE_LIMIT).rev() {
            let from = format!("{}.{i}", self.path);
            if std::path::Path::new(&from).exists() {
                let to = format!("{}.{}", self.path, i + 1);
                if let Err(e) = std::fs::rename(&from, &to) {
                    self.report.report(Event::ArchiveShiftFailed {
                        from,
                        to,
                        error: e.to_string(),
                    });
                }
            }
        }
        // The rotation that matters: the just-completed, still-un-archived current file becomes `.1`.
        let archive = format!("{}.1", self.path);
        match std::fs::rename(&self.path, &archive) {
            Ok(()) => self.report.report(Event::Rotated {
                path: &self.path,
                archive: &archive,
            }),
            Err(e) => self.report.report(Event::RotateFailed {
                path: &self.path,
                error: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
