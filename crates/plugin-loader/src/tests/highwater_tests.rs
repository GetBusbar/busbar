// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/highwater.rs`.

use super::*;

fn tmpdir() -> PathBuf {
    let mut p = std::env::temp_dir();
    let mut rnd = [0u8; 8];
    let _ = getrandom::fill(&mut rnd);
    p.push(format!(
        "busbar-highwater-test-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// PB-13: WITHOUT a data dir the store probes nothing and writes NOTHING. The marks still floor this
/// process — a mid-process swap is the window an attacker with directory write access operates in —
/// but no data-dir file is created, because a deployment with no `data_dir` has no data dir to
/// create one in.
#[test]
fn without_a_data_dir_the_store_creates_no_file() {
    let dir = tmpdir();
    let (mut marks, note) = HighWaterMarks::load(None);
    assert!(note.is_none());
    assert!(!marks.is_persistent());
    assert!(marks.raise("busbar-store-valkey-plugin", "1.2.0"));
    marks.persist().expect("a memory-only persist is a no-op");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "no data dir ⇒ no files"
    );
    // The floor is live in memory regardless.
    assert_eq!(
        marks.marks().get("busbar-store-valkey-plugin").unwrap(),
        "1.2.0"
    );
}

/// WITH a data dir the floor survives a restart — which is what makes it an anti-replay control
/// rather than a per-process one.
#[test]
fn with_a_data_dir_the_floor_survives_a_restart() {
    let dir = tmpdir();
    let (mut marks, _) = HighWaterMarks::load(Some(&dir));
    assert!(marks.is_persistent());
    assert!(marks.raise("busbar-store-valkey-plugin", "1.2.0"));
    marks.persist().unwrap();

    let (reloaded, note) = HighWaterMarks::load(Some(&dir));
    assert!(note.is_none(), "a file this store wrote reloads clean");
    assert_eq!(
        reloaded.marks().get("busbar-store-valkey-plugin").unwrap(),
        "1.2.0",
        "the floor survives the restart"
    );
}

/// The mark is a HIGH-WATER mark: it rises and never falls. An explicit rollback loads an older
/// artifact past its pin; it must not silently erase the floor every other node still enforces.
#[test]
fn the_mark_rises_and_never_falls() {
    let (mut marks, _) = HighWaterMarks::load(None);
    assert!(marks.raise("p", "1.2.0"), "first sighting sets the mark");
    assert!(!marks.raise("p", "1.2.0"), "the same version is idempotent");
    assert!(
        !marks.raise("p", "1.0.0"),
        "an older version never lowers it"
    );
    assert_eq!(marks.marks().get("p").unwrap(), "1.2.0");
    assert!(marks.raise("p", "1.3.0"), "a newer version raises it");
    assert_eq!(marks.marks().get("p").unwrap(), "1.3.0");
}

/// A mark that cannot be parsed is worse than no mark: `version_at_least` refuses an unparsable
/// floor outright, so keeping one would refuse a good plugin forever on the strength of a corrupt
/// byte. Unusable entries are DROPPED and the caller is told.
#[test]
fn unusable_entries_are_dropped_and_reported() {
    let dir = tmpdir();
    std::fs::write(
        dir.join(HIGH_WATER_FILE),
        br#"{"good-plugin":"1.2.0","bad-plugin":"v1.2","BAD NAME":"1.0.0"}"#,
    )
    .unwrap();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    let m = marks.marks();
    assert_eq!(m.len(), 1, "only the usable entry survives: {m:?}");
    assert_eq!(m.get("good-plugin").unwrap(), "1.2.0");
    let note = note.expect("the operator is told what was dropped");
    assert!(note.contains("bad-plugin"), "{note}");
    assert!(note.contains("BAD NAME"), "{note}");
}

/// FAIL-SOFT on a damaged file: an empty mark set is the same posture as a first boot, whereas
/// refusing the boot would let anyone who can corrupt one JSON file take the node down. Loud, not
/// fatal.
#[test]
fn a_corrupt_file_boots_with_no_floor_and_says_so() {
    let dir = tmpdir();
    std::fs::write(dir.join(HIGH_WATER_FILE), b"{ this is not json").unwrap();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    assert!(marks.marks().is_empty());
    let note = note.expect("a corrupt floor must be reported");
    assert!(note.contains("NO first-party floor"), "{note}");
}

/// A missing file is the normal first-boot state, not a problem — and no floor, because a first
/// install is not a downgrade.
#[test]
fn a_missing_file_is_a_clean_first_boot() {
    let dir = tmpdir();
    let (marks, note) = HighWaterMarks::load(Some(&dir));
    assert!(note.is_none());
    assert!(marks.marks().is_empty());
    assert!(marks.is_persistent());
}

/// The persisted file is `0600`: an integrity floor is not a secret, but it is written with the same
/// private mode as every other data-dir file.
#[cfg(unix)]
#[test]
fn the_persisted_floor_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir();
    let (mut marks, _) = HighWaterMarks::load(Some(&dir));
    marks.raise("p", "1.0.0");
    marks.persist().unwrap();
    let mode = std::fs::metadata(dir.join(HIGH_WATER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
    // The write is atomic: no temp file is left behind.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
}
