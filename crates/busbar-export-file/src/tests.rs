// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this sink does with a delivery it has already been given room for: the bytes it writes, and
//! the history it must never destroy.

use super::*;

/// A [`Report`] that keeps every event's discriminant, so a test can assert what the sink SAID as
/// well as what it wrote.
#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Report for Recorder {
    fn report(&self, event: Event<'_>) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(match event {
                Event::Rotated { .. } => "rotated".to_string(),
                Event::RotateFailed { .. } => "rotate-failed".to_string(),
                Event::ArchiveShiftFailed { .. } => "archive-shift-failed".to_string(),
                Event::RetentionCleanupFailed { .. } => "retention-cleanup-failed".to_string(),
                Event::AppendFailed { .. } => "append-failed".to_string(),
                Event::OpenFailed { .. } => "open-failed".to_string(),
            });
    }
}

/// A private scratch directory, removed at the end of the test that made it.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-export-file-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// THE AUDIT-INTEGRITY PROPERTY: rotation preserves the completed file by RENAME.
///
/// The defect this pins shut reopened the sink's file with `.truncate(true)` on rollover, discarding
/// every previously written line with no rename and no archive — for a security product, a
/// size-triggered rotation silently destroying recorded evidence is the sharpest possible defect.
/// Against a truncating rollover the first assertion fails: the archive is never created and the
/// first line is gone.
#[test]
fn rotation_preserves_prior_lines_in_a_renamed_archive() {
    let dir = scratch("rotate");
    let path = dir.join("audit.jsonl");
    let path_str = path.to_string_lossy().to_string();
    let archive = format!("{path_str}.1");
    let recorder = Arc::new(Recorder::default());

    // Tiny threshold: the first line alone pushes the file past it.
    let sink = FileSink::new(path_str.clone(), Some(0), recorder.clone());

    let first = r#"{"correlation_id":"pre-rotation-evidence"}"#;
    let second = r#"{"correlation_id":"post-rotation"}"#;

    // The file does not exist yet, so no rotation check can fire; this lands in a fresh file.
    sink.append(first);
    assert!(std::fs::read_to_string(&path_str)
        .expect("the first append created the file")
        .contains(first));

    // The pre-write size check now sees the file over `rotate_bytes`, so this call rotates BEFORE
    // writing: the current file becomes fresh, the old one becomes `.1`.
    sink.append(second);

    assert!(
        std::fs::read_to_string(&archive)
            .unwrap_or_default()
            .contains(first),
        "rotation must PRESERVE the pre-rotation line in the renamed archive `{archive}`"
    );
    let current = std::fs::read_to_string(&path_str).unwrap_or_default();
    assert!(
        !current.contains(first),
        "the fresh current file must not still hold the pre-rotation line: {current:?}"
    );
    assert!(
        current.contains(second),
        "the fresh current file must hold what was written after rotation: {current:?}"
    );
    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec!["rotated".to_string()],
        "a rotation that worked is still reported"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A SINK THAT CANNOT WRITE SAYS SO. It has no logger it may name, so the only way an unopenable
/// path reaches an operator is the report — and swallowing it would make a misconfigured sink look
/// exactly like a working one.
#[test]
fn an_unopenable_path_is_reported_rather_than_swallowed() {
    let dir = scratch("unopenable");
    // A path whose parent is a FILE, so the open can never succeed.
    let blocker = dir.join("not-a-directory");
    std::fs::write(&blocker, b"x").expect("the blocking file");
    let recorder = Arc::new(Recorder::default());
    let sink = FileSink::new(
        blocker.join("req.jsonl").to_string_lossy().to_string(),
        None,
        recorder.clone(),
    );

    sink.append(r#"{"correlation_id":"dropped"}"#);

    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec!["open-failed".to_string()],
        "an unopenable sink reports, and the delivery is over"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// BYTE IDENTITY, ONE ROTATION CYCLE: the file NAMES the sink puts history under, and the exact
/// bytes of one row.
///
/// These are OPERATOR-VISIBLE BYTES. A dashboard tails `<path>`, a log shipper globs `<path>.N`,
/// and a compliance reader parses one line per delivery — so moving this sink out of the engine is
/// only correct if every one of those is unchanged, down to the byte. This pins all three at once:
///
/// - the archive series is `<path>.1` newest .. `<path>.9` oldest, and a SECOND rotation shifts the
///   first archive along to `.2` rather than overwriting it;
/// - nothing else appears in the directory — no `.tmp`, no `.0`, no timestamped name;
/// - one delivery is one line, terminated by exactly one `\n`, holding the payload's own bytes and
///   nothing added around them.
///
/// RED FIRST, three ways, each an observable an operator matches on: a rollover that truncates
/// instead of renaming leaves no `.1` at all; a rollover that renames straight onto `.1` without
/// shifting loses the older cycle's line; and a writer that pretties, prefixes or re-terminates the
/// row fails the exact-bytes assertion below.
#[test]
fn a_rotation_cycle_names_its_archives_and_a_row_is_the_payload_bytes_and_a_newline() {
    let dir = scratch("bytes");
    let path = dir.join("req.jsonl");
    let path_str = path.to_string_lossy().to_string();

    // `Some(0)` ⇒ any non-empty file is over the threshold, so every append after the first rotates:
    // one append per cycle, which is what makes the archive shift observable in three writes.
    let sink = FileSink::silent(path_str.clone(), Some(0));

    // The row an operator reads. Written as the caller hands it over — a serialized line, already
    // built to this sink's projection — so the assertion below is about THIS crate's framing and
    // not about anyone's serializer.
    let first = r#"{"correlation_id":"c1","status":200}"#;
    let second = r#"{"correlation_id":"c2","status":404}"#;
    let third = r#"{"correlation_id":"c3","status":500}"#;

    sink.append(first); // fresh file, no rotation possible
    sink.append(second); // rotates: first -> `.1`
    sink.append(third); // rotates: `.1` -> `.2`, second -> `.1`

    // THE BYTES OF ONE ROW: the payload, one `\n`, nothing else. Not `read_to_string().contains()`
    // — an exact comparison, because "contains" is satisfied by a prefix nobody asked for.
    assert_eq!(
        std::fs::read_to_string(&path_str).expect("the current file"),
        format!("{third}\n"),
        "one delivery is one line: the payload's own bytes and a single newline"
    );

    // THE ARCHIVE NAMES: `.1` is the most recent completed file, `.2` the one before it.
    assert_eq!(
        std::fs::read_to_string(format!("{path_str}.1")).expect("the newest archive"),
        format!("{second}\n"),
        "`<path>.1` is the JUST-completed file"
    );
    assert_eq!(
        std::fs::read_to_string(format!("{path_str}.2")).expect("the shifted archive"),
        format!("{first}\n"),
        "a second rotation SHIFTS the older archive along rather than overwriting it"
    );

    // AND NOTHING ELSE ON DISK. A rotation that published through a temp name, or that invented a
    // `.0`/timestamped spelling, would show up here and break every glob an operator wrote.
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("the scratch directory")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "req.jsonl".to_string(),
            "req.jsonl.1".to_string(),
            "req.jsonl.2".to_string()
        ],
        "the rotation cycle leaves exactly the current file and its numbered archives"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE RETENTION BOUND, at its own edge: the series stops at [`ARCHIVE_LIMIT`] and the oldest line
/// is the one that goes.
///
/// An unbounded series fills the disk the sink is writing to, which takes the whole node down —
/// so the bound is as operator-visible as the names are. Red first: without the oldest-slot removal
/// the shift collides with a still-occupied name and `.9` keeps the FIRST line forever.
#[test]
fn the_archive_series_stops_at_the_retention_bound() {
    let dir = scratch("retention");
    let path_str = dir.join("req.jsonl").to_string_lossy().to_string();
    let sink = FileSink::silent(path_str.clone(), Some(0));

    // One append per rotation cycle: enough to push a line past the end of the series. The first
    // append lands in a fresh file (nothing to rotate), so after the last one the current file holds
    // line `LAST` and `<path>.j` holds line `LAST - j`.
    const LAST: usize = ARCHIVE_LIMIT + 2;
    for i in 0..=LAST {
        sink.append(&format!(r#"{{"n":{i}}}"#));
    }

    assert!(
        !std::path::Path::new(&format!("{path_str}.{}", ARCHIVE_LIMIT + 1)).exists(),
        "the series never grows past the retention bound"
    );
    // The oldest surviving archive is the bound-th one back from the current file, and it is the
    // line that many cycles ago — never the first line the sink ever wrote.
    assert_eq!(
        std::fs::read_to_string(format!("{path_str}.{ARCHIVE_LIMIT}")).expect("the oldest archive"),
        format!("{{\"n\":{}}}\n", LAST - ARCHIVE_LIMIT),
        "the oldest archive has aged along the series rather than being pinned to the first write"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── the face ─────────────────────────────────────────────────────────────────────────────────

/// A host that lends nothing — what this sink is composed with, because a file sink's only
/// outside is the path it was configured with and it asks its host for neither a wire nor a
/// reading.
struct NoLoan;

impl busbar_contract::ExportHost for NoLoan {
    fn send(&self, _delivery: busbar_contract::Delivery) -> bool {
        unreachable!("a file sink never asks its host for a wire")
    }
    fn read(&self, _stream: &str) -> Option<String> {
        unreachable!("a file sink never asks its host for a reading")
    }
}

/// THE SERVED PATH REACHES THIS SINK THROUGH THE FACE, AND THE BYTES ARE THE SAME.
///
/// The whole of what this slot claims about the file sink: a request-log line handed to
/// `busbar_contract::Export::receive` through a `dyn Export` — no crate name, no `append` — lands
/// on disk byte for byte as the line the composer's direct call put there before the face existed.
/// Red first: without `impl Export for FileSink` this does not compile, and with a `receive` that
/// framed the line differently the two files would differ.
#[test]
fn a_line_through_the_face_is_the_line_the_direct_append_wrote() {
    use busbar_contract::{Ack, Export, ExportItem};

    let dir = scratch("through-the-face");
    let line = r#"{"correlation_id":"c-1","status":200}"#;

    // What the composer's direct call writes — this sink's own `append`, the 1.5.x bytes.
    let direct_path = dir.join("direct.jsonl").to_string_lossy().to_string();
    FileSink::silent(direct_path.clone(), None).append(line);

    // What the FACE writes, reached with the sink's name already forgotten.
    let faced_path = dir.join("faced.jsonl").to_string_lossy().to_string();
    let sink: Box<dyn Export> = Box::new(FileSink::silent(faced_path.clone(), None));
    let ack = sink.receive(
        ExportItem {
            stream: "logs",
            bytes: line.as_bytes(),
        },
        &NoLoan,
    );

    assert_eq!(
        std::fs::read(&faced_path).expect("the faced file"),
        std::fs::read(&direct_path).expect("the direct file"),
        "a line delivered through the contract's export face is byte-identical to the line the \
         direct append wrote"
    );
    assert_eq!(
        ack,
        Ack::Received,
        "an unfsynced append that succeeded is Received and never Durable"
    );
    assert_eq!(
        sink.streams(),
        &["logs"],
        "the sink declares the stream it carries, and the composer routes nothing else to it"
    );
    assert!(
        sink.routes().is_empty(),
        "a push sink declares no route: it is delivered to, never scraped"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// AN ITEM A PUSH SINK CANNOT WRITE IS `Retry`, AND `Retry` IS NOT A LIE.
///
/// The sink states that it did not take the record. What the composer does about that — this tree
/// counts a drop — is the composer's. Red first: a `receive` that returned `Received` regardless of
/// the write would claim bytes that are not on any disk.
#[test]
fn a_record_the_sink_could_not_write_is_not_acknowledged_as_taken() {
    use busbar_contract::{Ack, Export, ExportItem};

    let dir = scratch("unwritable");
    // A path whose parent is the file itself: the open cannot succeed and cannot be made to.
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"x").expect("the blocking file");
    let path = blocker
        .join("under-a-file.jsonl")
        .to_string_lossy()
        .to_string();

    let sink: Box<dyn Export> = Box::new(FileSink::silent(path, None));
    let ack = sink.receive(
        ExportItem {
            stream: "logs",
            bytes: b"{}",
        },
        &NoLoan,
    );

    assert_eq!(
        ack,
        Ack::Retry,
        "a record that reached no disk is not Received"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
