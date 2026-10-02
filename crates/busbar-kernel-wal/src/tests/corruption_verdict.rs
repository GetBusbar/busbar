// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mid-log corruption is not a torn tail, and recovery must not treat it as one.
//!
//! A crash mid-append leaves an incomplete final record with nothing verifying past it; cutting it
//! loses nothing that was acknowledged. A checksum failure with whole, verifying records BEHIND it is
//! acknowledged data the medium damaged. The node still boots — over the verified prefix — but the
//! damaged remainder is first copied byte for byte into a quarantine file beside the segment, made
//! durable, and only then cut; and the verdict naming the file, the offset and the byte count is
//! handed back so the caller can raise the alarm.

use std::path::{Path, PathBuf};

use crate::backend::DirectoryFactory;
use crate::record::{Record, FRAME_BYTES};
use crate::ship::NullShipper;
use crate::wal::Wal;

use super::fixtures::{durability_token, records, TempDir, METER};

/// Four single-frame records, so record `i` is exactly frame `i`.
fn four() -> Vec<Record> {
    records(3, 1, 4, 200)
}

/// Write `written` to a fresh log in `dir`, close it, and return the committed bytes of segment 0.
fn lay_down(dir: &Path, written: &[Record]) -> Vec<u8> {
    let mut wal = Wal::in_directory(
        dir,
        Box::new(NullShipper::new()),
        crate::tests::fixtures::wall_ms,
    )
    .unwrap();
    let ack = wal
        .append_batch(&durability_token(), METER, written)
        .unwrap();
    drop(wal);
    let bytes = std::fs::read(segment_path(dir)).unwrap();
    bytes[..usize::try_from(ack.durable_end).unwrap()].to_vec()
}

fn segment_path(dir: &Path) -> PathBuf {
    DirectoryFactory::new(dir).unwrap().segment_path(0)
}

/// Flip one byte of the segment file in place.
fn flip(dir: &Path, at: usize) {
    let path = segment_path(dir);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
}

/// Every quarantine file in `dir`, sorted by name.
fn quarantine_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".quarantine-"))
        })
        .collect();
    found.sort();
    found
}

/// THE MIGRATION PATH: a segment written BEFORE the header check (layout version 1) is still read,
/// under the rule it was written under — its flipped final record is a torn tail, cut silently, as
/// that build would have cut it; the frames it already holds are never reinterpreted.
#[test]
fn a_legacy_segment_keeps_the_rule_it_was_written_under() {
    let dir = TempDir::new("legacy-flip");
    let written = four();
    lay_down(dir.path(), &written);
    // Rewrite every frame of the segment under the legacy layout, byte for byte otherwise.
    let path = segment_path(dir.path());
    let mut legacy: Vec<u8> = written
        .iter()
        .flat_map(crate::record::encode_legacy)
        .flatten()
        .collect();
    let len = std::fs::read(&path).unwrap().len();
    legacy.resize(len, 0);
    std::fs::write(&path, legacy).unwrap();
    flip(dir.path(), 3 * FRAME_BYTES + 200);
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        crate::tests::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    assert!(wal.quarantined().is_empty());
    assert!(quarantine_files(dir.path()).is_empty());
}
