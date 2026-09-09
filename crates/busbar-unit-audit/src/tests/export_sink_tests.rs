// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE APPEND-ONLY SINK WRITER. The rule under test is the audit unit's, not a telemetry
//! convenience: a size threshold may ROLL a file over, and it may never DESTROY what the file
//! already holds. Every rotation is a rename; the current file is only ever opened for append; and
//! the archive series is bounded by a retention limit rather than by truncation.
//!
//! These are synchronous — the writer takes no lock, spawns nothing and knows nothing about
//! admission. Serialising concurrent appends and shedding under saturation belong to the caller
//! that owns the sink's configuration, and are proven there.

use crate::export::{append_line, Rotation, ROTATE_ARCHIVE_LIMIT};

/// A scratch directory unique to this test binary and thread.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-unit-audit-export-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// NO ROTATION BOUND ⇒ NO ROTATION. An unbounded sink appends forever and never renames.
#[test]
fn an_unbounded_sink_appends_and_never_rotates() {
    let dir = scratch("append");
    let path = dir.join("audit.jsonl");
    let p = path.to_string_lossy().to_string();

    assert!(matches!(
        append_line(&p, None, r#"{"n":1}"#),
        Rotation::NotNeeded
    ));
    assert!(matches!(
        append_line(&p, None, r#"{"n":2}"#),
        Rotation::NotNeeded
    ));

    let body = std::fs::read_to_string(&path).expect("the sink created its file");
    assert_eq!(
        body, "{\"n\":1}\n{\"n\":2}\n",
        "both lines must be present, in order, one per line"
    );
    assert!(
        !std::path::Path::new(&format!("{p}.1")).exists(),
        "an unbounded sink must never create an archive"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE AUDIT-INTEGRITY RULE. Crossing the size bound rolls the file over BY RENAME: the
/// pre-rotation content is readable in `<path>.1` afterwards, and the fresh current file holds only
/// what was written after the roll. A truncating rollover fails both halves.
#[test]
fn rotation_renames_and_preserves_every_prior_line() {
    let dir = scratch("rotate");
    let path = dir.join("audit.jsonl");
    let p = path.to_string_lossy().to_string();
    let archive = format!("{p}.1");

    // The file does not exist yet, so the first append cannot rotate; it lands in a fresh file and
    // pushes its size past the 16-byte bound.
    assert!(matches!(
        append_line(&p, Some(16), r#"{"evidence":"pre-rotation"}"#),
        Rotation::NotNeeded
    ));
    // The second append sees the file over the bound and must roll it over BEFORE writing.
    assert!(
        matches!(
            append_line(&p, Some(16), r#"{"evidence":"post"}"#),
            Rotation::Renamed
        ),
        "crossing the size bound must report a completed rename, so the caller can count it"
    );

    let archived = std::fs::read_to_string(&archive).expect("the archive exists");
    assert!(
        archived.contains("pre-rotation"),
        "rotation must PRESERVE the pre-rotation line in `{archive}`; got {archived:?}"
    );
    let current = std::fs::read_to_string(&path).expect("the current file exists");
    assert!(
        !current.contains("pre-rotation"),
        "the fresh current file must not still hold the pre-rotation line: {current:?}"
    );
    assert!(
        current.contains("post"),
        "the fresh current file must hold what was written after rotation: {current:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// RETENTION IS A BOUND ON THE SERIES, NOT ON THE CONTENT. Rolling over repeatedly shifts every
/// archive one slot older, oldest first so nothing is ever renamed onto a still-occupied name, and
/// only an archive that has aged past [`ROTATE_ARCHIVE_LIMIT`] rotations is dropped. Each surviving
/// archive still holds exactly the line it was written with — the shift moves files, never bytes.
#[test]
fn the_archive_series_shifts_oldest_first_and_stops_at_the_retention_limit() {
    let dir = scratch("retention");
    let path = dir.join("audit.jsonl");
    let p = path.to_string_lossy().to_string();

    // One line per rotation, each identifiable, with one more rotation than the series can retain.
    let rolls = ROTATE_ARCHIVE_LIMIT + 1;
    for i in 0..=rolls {
        append_line(&p, Some(1), &format!("{{\"line\":{i}}}"));
    }

    assert!(
        !std::path::Path::new(&format!("{p}.{}", ROTATE_ARCHIVE_LIMIT + 1)).exists(),
        "the series must stop at ROTATE_ARCHIVE_LIMIT ({ROTATE_ARCHIVE_LIMIT}); a slot beyond it \
         means retention is unbounded"
    );
    // `.1` is the NEWEST archive and `.N` the oldest, so slot `k` holds the line written
    // `k` rotations ago.
    for k in 1..=ROTATE_ARCHIVE_LIMIT {
        let slot = format!("{p}.{k}");
        let body = std::fs::read_to_string(&slot).unwrap_or_else(|e| panic!("{slot}: {e}"));
        let expected = rolls - k;
        assert_eq!(
            body,
            format!("{{\"line\":{expected}}}\n"),
            "archive slot {k} must still hold the line it was written with, unaltered"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
