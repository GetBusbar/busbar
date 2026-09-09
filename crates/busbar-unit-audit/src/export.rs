// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY SINK WRITER — the bytes-to-disk half of an export sink, owned by the unit that
//! owns the sealed chain.
//!
//! An `export:` instance configured with `module: request-log-file` can legitimately be pointed at a
//! compliance mount, and then the file it writes IS evidence. What follows from that is one rule,
//! and it is an audit rule rather than a telemetry one:
//!
//! > **A size threshold may ROLL a file over. It may never DESTROY what the file already holds.**
//!
//! So the current file is only ever opened for append, never with `truncate`; a rollover is a
//! `rename` of a file whose bytes are already fully on disk; and the archive series is bounded by a
//! RETENTION limit — an archive is dropped only once it has aged past [`ROTATE_ARCHIVE_LIMIT`]
//! rotations — rather than by discarding a live file's contents. Every failure mode degrades toward
//! keeping data: a failed rename means the current file keeps growing past its cap, which is a
//! visible, diagnosed operational problem, where the alternative is silent loss of recorded history.
//!
//! ## What is deliberately NOT here
//!
//! The writer is a free function over a path. It holds no state, takes no lock, spawns nothing,
//! counts nothing and LOGS nothing. Which lines are OFFERED to it — the projection that bounds the
//! payload, the per-instance admission gate that sheds under saturation, the `spawn_blocking` that
//! keeps the filesystem off the request path, and the mutex that serialises concurrent appends to
//! one sink — belongs to the composition that configures the sink, and stays there. The unit owns
//! the rule about what happens to bytes already written; it does not own the telemetry fan-out.
//!
//! Nor does it own the WORDS. Every way this can fail is already a coded diagnostic an operator
//! greps for, and those codes live in the one catalog beside the composition that emits them. A
//! second catalog reachable from here would be a second code for the same operational fact, and
//! reaching for the existing one would be this unit taking a dependency on a crate of another kind
//! for no reason but a string. So a failure is handed BACK, as a [`Fault`] naming exactly what could
//! not be done and to which path, and the caller renders it under the code it has always used. The
//! same goes for the one fact the caller cannot derive — whether a rollover happened — which comes
//! back as a [`Rotation`] for the caller to count.

use std::io::Write;

/// How many rotated archives ONE sink keeps (`<path>.1` .. `<path>.{ROTATE_ARCHIVE_LIMIT}`) before
/// the oldest is dropped to make room for a new rotation.
///
/// This is a RETENTION policy, not a truncation one: every rotation preserves the just-completed
/// file in full by renaming it — nothing written to disk is ever discarded except an archive that
/// has already aged past this many rotations. Deliberately a compiled-in constant: the file
/// exporter's config surface is frozen, and a retention floor is not a per-deployment dial.
pub const ROTATE_ARCHIVE_LIMIT: usize = 9;

/// What [`append_line`] did about the size bound before it wrote, so the caller can count it.
///
/// The caller counts rather than the writer because the counters are the composition's and a unit
/// that emitted them would be a second metrics vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// No rollover was attempted — either the sink is unbounded, or the file is under its bound (or
    /// does not exist yet, which is the same thing for this purpose).
    NotNeeded,
    /// The current file was renamed to `<path>.1` and the line was written to a fresh file.
    Renamed,
    /// A rollover was due and its rename FAILED. Nothing was lost: the line was appended to the
    /// still-current file, which now exceeds its cap until the cause is resolved.
    RenameFailed,
}

/// One thing the writer could not do, handed back for the caller to diagnose under the code it
/// already publishes for it.
///
/// Every variant is NON-FATAL by construction — the writer carries on and degrades toward keeping
/// data — so the report is an operational picture, never a control signal.
#[derive(Debug)]
pub enum Fault<'a> {
    /// The current file could not be opened for append. This line was dropped.
    Open {
        /// The sink's path.
        path: &'a str,
        /// Why the open failed.
        error: std::io::Error,
    },
    /// The file was open but the line could not be written. This line was dropped.
    Append {
        /// The sink's path.
        path: &'a str,
        /// Why the write failed.
        error: std::io::Error,
    },
    /// The oldest archive could not be removed to make room, so the series may exceed
    /// [`ROTATE_ARCHIVE_LIMIT`]. Nothing recorded was lost — an archive that should have aged out is
    /// still on disk.
    RetentionCleanup {
        /// The archive that should have aged out.
        archive: &'a str,
        /// Why the removal failed.
        error: std::io::Error,
    },
    /// One archive could not be shifted one slot older. The older archive was left in place rather
    /// than overwritten, so nothing recorded was lost.
    ArchiveShift {
        /// The archive that could not be moved.
        from: &'a str,
        /// The slot it should have moved to.
        to: &'a str,
        /// Why the rename failed.
        error: std::io::Error,
    },
    /// The current file could not be renamed to `<path>.1`, so the rollover did not happen. The
    /// writer APPENDED to the current file rather than truncating it, so no recorded data was lost —
    /// the file will exceed its cap until this is resolved.
    RotateRename {
        /// The sink's path.
        path: &'a str,
        /// Why the rename failed.
        error: std::io::Error,
    },
}

/// Append one already-serialised line to `path`, rolling the file over first if it has reached
/// `rotate_bytes`, and reporting anything that could not be done through `fault`.
///
/// The line is written verbatim followed by a newline — the caller owns the line's shape, this owns
/// only that it lands on the end of the file. An open or write failure is REPORTED and dropped
/// rather than propagated: a sink that could refuse would be a sink that can affect serving, and the
/// contract is the other way round.
///
/// This is a synchronous, blocking filesystem call by construction. It must be invoked somewhere
/// that can block (the caller's blocking pool), and concurrent appends to the SAME path must be
/// serialised by the caller, or two lines can interleave.
pub fn append_line(
    path: &str,
    rotate_bytes: Option<u64>,
    line: &str,
    fault: &mut dyn FnMut(Fault<'_>),
) -> Rotation {
    // Best-effort size bound: when the file has reached the configured size, roll it over by RENAME,
    // never by truncation — this sink can be an audit trail, and destroying recorded history on a
    // size threshold is not an acceptable "rotation". A file that does not exist yet, or whose
    // metadata cannot be read, is treated as under the bound: the failure mode of guessing wrong is
    // "rotation is late", which loses nothing.
    let needs_rotate = rotate_bytes
        .and_then(|limit| std::fs::metadata(path).ok().map(|m| m.len() >= limit))
        .unwrap_or(false);
    let rotation = if needs_rotate {
        rotate(path, fault)
    } else {
        Rotation::NotNeeded
    };

    // ALWAYS append, never truncate: even on a failed rotation the correct fallback is to keep
    // growing the current file, not to void it.
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path);
    match opened {
        Ok(mut file) => {
            if let Err(error) = writeln!(file, "{line}") {
                fault(Fault::Append { path, error });
            }
        }
        Err(error) => fault(Fault::Open { path, error }),
    }
    rotation
}

/// Roll `path` over to a numbered archive series (`path.1` is the newest archive, `path.N` the
/// oldest retained one) and free up `path` for a fresh file.
///
/// Never truncates. On any rename failure this returns having changed nothing observable about
/// `path` itself — the caller then reopens it in append mode, so the file keeps growing past its cap
/// rather than losing what is already on disk. A stuck rename (permissions, a cross-device archive
/// dir, a racing external process) degrades to "rotation isn't happening", never to "history is
/// gone."
///
/// ## Why this hand-rolls `fs::rename` instead of routing through a durable publish
///
/// A durable publish owns "make freshly computed bytes visible so a reader never observes a torn
/// write" — a fsync-the-content-before-rename dance built to protect a WRITE. This function does no
/// write: it renames a file whose bytes are already fully on disk. There was never a torn-write
/// contract to preserve here either — this sink's appends are fire-and-forget and unfsynced by
/// design, so a concurrent tailer already has no atomicity guarantee across lines, and rotation
/// weakens nothing that existed before it. And `fs::rename` only repoints a directory entry — it
/// never touches the bytes it names — so a crash mid-rotation can leave content under its PRIOR name
/// but can never lose it or leave it torn, which is exactly the property the truncate-free contract
/// needs. Reusing a durable publish would mean reading the whole log — sized by the operator and
/// legitimately hundreds of MB — into memory just to re-emit it as "new" bytes. This is a LEDGERED
/// exemption in the `structure-lint` gate's choke-point registry (row A-persistence), not a silent
/// bypass.
fn rotate(path: &str, fault: &mut dyn FnMut(Fault<'_>)) -> Rotation {
    // Free the oldest archive slot first so the shift below never collides with a still-occupied
    // name. Retention is a deliberate, documented bound (`ROTATE_ARCHIVE_LIMIT`), not a side effect
    // of the rotation mechanism.
    let oldest = format!("{path}.{ROTATE_ARCHIVE_LIMIT}");
    if std::path::Path::new(&oldest).exists() {
        if let Err(error) = std::fs::remove_file(&oldest) {
            fault(Fault::RetentionCleanup {
                archive: &oldest,
                error,
            });
        }
    }
    // Shift path.{i} -> path.{i+1}, oldest first, so no archive is ever renamed onto one that still
    // holds unshifted data.
    for i in (1..ROTATE_ARCHIVE_LIMIT).rev() {
        let from = format!("{path}.{i}");
        if std::path::Path::new(&from).exists() {
            let to = format!("{path}.{}", i + 1);
            if let Err(error) = std::fs::rename(&from, &to) {
                fault(Fault::ArchiveShift {
                    from: &from,
                    to: &to,
                    error,
                });
            }
        }
    }
    // The rotation that matters: the just-completed, still-un-archived current file becomes `.1`.
    let archive = format!("{path}.1");
    match std::fs::rename(path, &archive) {
        Ok(()) => Rotation::Renamed,
        Err(error) => {
            fault(Fault::RotateRename { path, error });
            Rotation::RenameFailed
        }
    }
}
