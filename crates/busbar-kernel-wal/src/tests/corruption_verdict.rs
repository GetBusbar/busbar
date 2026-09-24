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

use crate::backend::{DirectoryFactory, MemoryFactory, SegmentBackend, SegmentFactory};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::{QuarantineKept, TailVerdict};
use crate::ship::NullShipper;
use crate::wal::{Mode, OpenError, Wal};

use super::fixtures::{durability_token, records, TempDir, METER};

/// Four single-frame records, so record `i` is exactly frame `i`.
fn four() -> Vec<Record> {
    records(3, 1, 4, 200)
}

/// Write `written` to a fresh log in `dir`, close it, and return the committed bytes of segment 0.
fn lay_down(dir: &Path, written: &[Record]) -> Vec<u8> {
    let mut wal = Wal::in_directory(dir, Box::new(NullShipper::new())).unwrap();
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

#[test]
fn a_mid_log_checksum_flip_boots_keeps_the_prefix_and_quarantines_exactly_the_damage() {
    let dir = TempDir::new("corrupt-mid-log");
    let written = four();
    let original = lay_down(dir.path(), &written);
    assert_eq!(original.len(), 4 * FRAME_BYTES);

    // Damage the SECOND record's payload. Records three and four behind it are whole and verify.
    flip(dir.path(), FRAME_BYTES + 200);
    let damaged = std::fs::read(segment_path(dir.path())).unwrap()[..original.len()].to_vec();

    // Boot is never blocked.
    let wal = Wal::in_directory(dir.path(), Box::new(NullShipper::new()))
        .expect("a corrupt segment does not stop the log opening");

    // Every record before the damage is kept.
    assert_eq!(wal.recovered(), &written[..1]);
    let segment_now = std::fs::read(segment_path(dir.path())).unwrap();
    assert_eq!(segment_now, original[..FRAME_BYTES].to_vec());

    // The verdict names the file, the offset and the byte count.
    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "one corrupt segment, one quarantine");
    let q = &q[0];
    assert_eq!(q.segment, 0);
    assert_eq!(
        q.segment_file.as_deref(),
        Some(segment_path(dir.path()).as_path())
    );
    assert_eq!(q.offset, FRAME_BYTES as u64);
    assert_eq!(q.damage_at, FRAME_BYTES as u64);
    assert_eq!(q.bytes, 3 * FRAME_BYTES as u64);
    assert_eq!(
        q.identities,
        vec![(3, 3), (3, 4)],
        "the verifying records past the damage are named"
    );

    // The quarantine file is beside the segment and holds exactly the damaged bytes.
    let files = quarantine_files(dir.path());
    assert_eq!(files.len(), 1);
    assert_eq!(q.kept, QuarantineKept::File(files[0].clone()));
    let name = files[0].file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("0000000000000000.wal.quarantine-"),
        "the quarantine is named after its segment: {name}"
    );
    assert_eq!(
        std::fs::read(&files[0]).unwrap(),
        damaged[FRAME_BYTES..].to_vec()
    );

    // The numbers the set-aside records carried are never handed out again — not by the log, and
    // not by a journal resuming over it.
    assert_eq!(wal.next_free_seq(3), 5);
    assert_eq!(crate::journal::Journal::over(wal, 3).next_seq(), 5);
}

#[test]
fn a_torn_tail_is_cut_silently_and_nothing_is_quarantined() {
    let dir = TempDir::new("torn-tail");
    let written = four();
    let original = lay_down(dir.path(), &written);

    // A crash mid-append: the last record's frame is half on the medium, nothing after it.
    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    for b in &mut bytes[3 * FRAME_BYTES + 100..] {
        *b = 0;
    }
    std::fs::write(&path, bytes).unwrap();

    let wal = Wal::in_directory(dir.path(), Box::new(NullShipper::new())).unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    assert!(wal.quarantined().is_empty());
    assert!(quarantine_files(dir.path()).is_empty());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original[..3 * FRAME_BYTES].to_vec()
    );
}

#[test]
fn a_flipped_byte_in_the_final_record_is_a_torn_tail() {
    // Nothing verifies past it, which is exactly what a crash mid-append leaves.
    let dir = TempDir::new("flip-final");
    let written = four();
    lay_down(dir.path(), &written);
    flip(dir.path(), 3 * FRAME_BYTES + 200);
    let wal = Wal::in_directory(dir.path(), Box::new(NullShipper::new())).unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    assert!(wal.quarantined().is_empty());
    assert!(quarantine_files(dir.path()).is_empty());
}

#[test]
fn the_scan_names_the_verdict() {
    let dir = TempDir::new("verdicts");
    lay_down(dir.path(), &four());
    let mut factory = DirectoryFactory::new(dir.path()).unwrap();
    let scan_now = |factory: &mut DirectoryFactory| {
        let segment =
            crate::segment::Segment::open_at(factory.open(0).unwrap(), 0, 0, u64::MAX).unwrap();
        crate::recover::scan(&segment).unwrap()
    };
    assert_eq!(scan_now(&mut factory).verdict, TailVerdict::Clean);
    flip(dir.path(), 2 * FRAME_BYTES + 5);
    let corrupt = scan_now(&mut factory);
    assert_eq!(
        corrupt.verdict,
        TailVerdict::Corrupt {
            at: 2 * FRAME_BYTES as u64
        }
    );
    assert!(corrupt.was_corrupt() && !corrupt.was_torn());
    assert!(!corrupt.verdict.truncates());
}

/// A directory factory whose segments refuse to SHRINK — the moment between the quarantine copy
/// being durable and the segment being cut, frozen, which is what a crash there looks like.
struct CrashBeforeCut(DirectoryFactory);

struct NoShrink(Box<dyn SegmentBackend>);

impl SegmentBackend for NoShrink {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_all_at(offset, bytes)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.0.sync()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read_at(offset, buf)
    }
    fn len(&self) -> std::io::Result<u64> {
        self.0.len()
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        if len < self.0.len()? {
            return Err(std::io::Error::other("the process died before the cut"));
        }
        self.0.set_len(len)
    }
}

impl SegmentFactory for CrashBeforeCut {
    fn open(&mut self, index: u64) -> std::io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(NoShrink(self.0.open(index)?)))
    }
    fn highest_index(&self) -> std::io::Result<Option<u64>> {
        self.0.highest_index()
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn segment_file(&self, index: u64) -> Option<PathBuf> {
        self.0.segment_file(index)
    }
    fn quarantine(
        &mut self,
        index: u64,
        offset: u64,
        unix_ms: u64,
        bytes: &[u8],
    ) -> std::io::Result<Option<PathBuf>> {
        self.0.quarantine(index, offset, unix_ms, bytes)
    }
}

#[test]
fn a_crash_between_the_quarantine_copy_and_the_cut_loses_nothing() {
    let dir = TempDir::new("crash-before-cut");
    let written = four();
    let original = lay_down(dir.path(), &written);
    flip(dir.path(), FRAME_BYTES + 7);
    let path = segment_path(dir.path());
    let damaged_file = std::fs::read(&path).unwrap();
    let damaged = damaged_file[..original.len()].to_vec();

    // The first boot dies after the copy and before the cut.
    let crashed = Wal::with_parts(
        Box::new(CrashBeforeCut(DirectoryFactory::new(dir.path()).unwrap())),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        crate::segment::SEGMENT_BYTES,
    );
    assert!(matches!(crashed, Err(OpenError::Io(_))));
    // The copy is durable AND the segment is uncut: both halves of the damage exist.
    assert_eq!(std::fs::read(&path).unwrap(), damaged_file);
    let first = quarantine_files(dir.path());
    assert_eq!(first.len(), 1);
    assert_eq!(
        std::fs::read(&first[0]).unwrap(),
        damaged[FRAME_BYTES..].to_vec()
    );

    // The next boot completes. Nothing was lost across the two: the kept prefix and the first
    // copy together are every byte that was on the medium.
    let wal = Wal::in_directory(dir.path(), Box::new(NullShipper::new())).unwrap();
    assert_eq!(wal.recovered(), &written[..1]);
    let mut rebuilt = std::fs::read(&path).unwrap();
    rebuilt.extend(std::fs::read(&first[0]).unwrap());
    assert_eq!(rebuilt, damaged);
    // The second boot made its own copy rather than overwriting the first.
    let after = quarantine_files(dir.path());
    assert_eq!(after.len(), 2);
    for file in &after {
        assert_eq!(
            std::fs::read(file).unwrap(),
            damaged[FRAME_BYTES..].to_vec()
        );
    }
}

/// A memory factory whose quarantine cannot be made durable.
struct NoQuarantine(MemoryFactory);

impl SegmentFactory for NoQuarantine {
    fn open(&mut self, index: u64) -> std::io::Result<Box<dyn SegmentBackend>> {
        self.0.open(index)
    }
    fn highest_index(&self) -> std::io::Result<Option<u64>> {
        self.0.highest_index()
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn segment_file(&self, index: u64) -> Option<PathBuf> {
        self.0.segment_file(index)
    }
    fn quarantine(&mut self, _: u64, _: u64, _: u64, _: &[u8]) -> std::io::Result<Option<PathBuf>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "no space for the copy",
        ))
    }
}

#[test]
fn a_quarantine_that_cannot_be_made_leaves_the_damage_in_place_and_writes_elsewhere() {
    let factory = MemoryFactory::retaining();
    let written = four();
    {
        let mut wal = Wal::with_parts(
            Box::new(factory.clone()),
            Box::new(NullShipper::new()),
            Mode::OnDisk,
            64 * FRAME_BYTES as u64,
        )
        .unwrap();
        wal.append_batch(&durability_token(), METER, &written)
            .unwrap();
    }
    let seg0 = factory.segment_bytes(0);
    seg0.lock().unwrap()[FRAME_BYTES + 9] ^= 0xFF;
    let before = seg0.lock().unwrap().clone();

    let mut wal = Wal::with_parts(
        Box::new(NoQuarantine(factory.clone())),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        64 * FRAME_BYTES as u64,
    )
    .expect("a failed copy does not stop the log opening");
    assert_eq!(wal.recovered(), &written[..1]);
    assert!(matches!(
        wal.quarantined()[0].kept,
        QuarantineKept::InPlace(_)
    ));
    // Not cut, not overwritten.
    assert_eq!(*seg0.lock().unwrap(), before);
    assert!(wal.is_poisoned(), "the damaged segment is closed to writes");

    let next = records(3, 9, 1, 10);
    let ack = wal.append_batch(&durability_token(), METER, &next).unwrap();
    assert_eq!(ack.segment, 1, "the next append rolled past the damage");
    assert_eq!(*seg0.lock().unwrap(), before);
}

#[test]
fn a_memory_log_keeps_the_quarantined_bytes_in_the_factory() {
    let factory = MemoryFactory::retaining();
    let written = four();
    {
        let mut wal = Wal::with_parts(
            Box::new(factory.clone()),
            Box::new(NullShipper::new()),
            Mode::MemoryBuffered,
            64 * FRAME_BYTES as u64,
        )
        .unwrap();
        wal.append_batch(&durability_token(), METER, &written)
            .unwrap();
    }
    let seg0 = factory.segment_bytes(0);
    seg0.lock().unwrap()[2 * FRAME_BYTES + 40] ^= 0xFF;
    let damaged = seg0.lock().unwrap()[2 * FRAME_BYTES..4 * FRAME_BYTES].to_vec();

    let wal = Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::MemoryBuffered,
        64 * FRAME_BYTES as u64,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..2]);
    assert_eq!(wal.quarantined()[0].kept, QuarantineKept::Memory);
    let kept = factory.quarantined();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].segment, 0);
    assert_eq!(kept[0].offset, 2 * FRAME_BYTES as u64);
    assert_eq!(kept[0].bytes, damaged);
}

#[test]
fn the_journal_puts_a_durable_record_of_each_quarantine_on_the_chain() {
    use crate::journal::{BodyReader, Journal, RecordClass};

    let dir = TempDir::new("quarantine-record");
    lay_down(dir.path(), &four());
    flip(dir.path(), FRAME_BYTES + 3);

    let wal = Wal::in_directory(dir.path(), Box::new(NullShipper::new())).unwrap();
    let q = wal.quarantined()[0].clone();
    let QuarantineKept::File(file) = &q.kept else {
        panic!("an on-disk log quarantines to a file");
    };
    let line = q.to_string();
    assert!(line.contains(&segment_path(dir.path()).display().to_string()));
    assert!(line.contains(&format!("at byte {}", FRAME_BYTES)));
    assert!(line.contains(&file.display().to_string()));

    let mut journal = Journal::over(wal, 3);
    let ack = journal
        .record_quarantines(&durability_token(), METER, 1_700_000_000)
        .unwrap()
        .expect("a boot that set bytes aside records it");
    assert_eq!(ack.sealed.len(), 1);
    let record = &ack.sealed[0];
    assert_eq!(record.class, RecordClass::ChainBreak);
    assert_eq!(record.wall, 1_700_000_000);
    let mut body = BodyReader::new(&record.body);
    assert_eq!(body.text(), Some(crate::recover::QUARANTINE_BODY_TAG));
    let segment_file = segment_path(dir.path()).display().to_string();
    assert_eq!(body.text(), Some(segment_file.as_str()));
    assert_eq!(body.num(), Some(0));
    assert_eq!(body.num(), Some(FRAME_BYTES as u64));
    assert_eq!(body.num(), Some(FRAME_BYTES as u64));
    assert_eq!(body.num(), Some(3 * FRAME_BYTES as u64));
    let kept = file.display().to_string();
    assert_eq!(body.text(), Some(kept.as_str()));
    assert_eq!(body.num(), Some(q.at_unix_ms));
    assert_eq!(body.num(), Some(2));
    assert!(body.is_done());

    // A clean boot has nothing to record.
    drop(journal);
    let clean = TempDir::new("quarantine-record-clean");
    lay_down(clean.path(), &four());
    let mut journal = Journal::over(
        Wal::in_directory(clean.path(), Box::new(NullShipper::new())).unwrap(),
        3,
    );
    assert!(journal
        .record_quarantines(&durability_token(), METER, 1)
        .unwrap()
        .is_none());
}
