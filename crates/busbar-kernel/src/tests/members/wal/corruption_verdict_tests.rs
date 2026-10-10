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

use busbar_kernel_wal::backend::{DirectoryFactory, MemoryFactory, SegmentBackend, SegmentFactory};
use busbar_kernel_wal::record::{decode_frame, frame_version, FrameError, Record, FRAME_BYTES};
use busbar_kernel_wal::recover::{QuarantineKept, TailVerdict};
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, OpenError, Wal};

use super::fixtures::{durability_token, records, TempDir, METER};

/// Four single-frame records, so record `i` is exactly frame `i`.
fn four() -> Vec<Record> {
    records(3, 1, 4, 200)
}

/// Write `written` to a fresh log in `dir`, close it, and return the committed bytes of segment 0.
fn lay_down(dir: &Path, written: &[Record]) -> Vec<u8> {
    let mut wal =
        Wal::in_directory(dir, Box::new(NullShipper::new()), super::fixtures::wall_ms).unwrap();
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
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
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
        vec![(3, 2), (3, 3), (3, 4)],
        "the altered record and the verifying records past the damage are named"
    );
    assert_eq!(
        q.damaged.iter().map(Record::identity).collect::<Vec<_>>(),
        vec![(3, 2), (3, 3), (3, 4)],
        "every set-aside record is handed over, as it now reads, for the caller to attribute"
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
    assert_eq!(
        busbar_kernel_wal::journal::Journal::over(wal, 3).next_seq(),
        5
    );
}

#[test]
fn a_torn_tail_is_cut_silently_and_nothing_is_quarantined() {
    let dir = TempDir::new("torn-tail");
    let written = four();
    let original = lay_down(dir.path(), &written);

    // A crash mid-append: the write of the last record's frame stopped INSIDE its header, and
    // nothing after it was written. The header check fails: a torn write.
    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    for b in &mut bytes[3 * FRAME_BYTES + 20..] {
        *b = 0;
    }
    std::fs::write(&path, bytes).unwrap();

    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    assert!(wal.quarantined().is_empty());
    assert!(quarantine_files(dir.path()).is_empty());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original[..3 * FRAME_BYTES].to_vec()
    );
}

/// A WHOLE final record altered after it was written is QUARANTINED, never cut as if it were a torn
/// tail. Its header checks and its digest does not, so the write that made it completed and the
/// record was acknowledged: a silent cut would lose a settlement the node had made. (Under the rule
/// before the header check, this was cut silently.)
#[test]
fn a_flipped_byte_in_the_final_record_is_quarantined_not_cut() {
    let dir = TempDir::new("flip-final");
    let written = four();
    lay_down(dir.path(), &written);
    flip(dir.path(), 3 * FRAME_BYTES + 200);
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "the altered final record is set aside, loudly");
    assert_eq!(q[0].identities, vec![(3, 4)]);
    assert_eq!(
        q[0].damaged
            .iter()
            .map(Record::identity)
            .collect::<Vec<_>>(),
        vec![(3, 4)]
    );
    assert_eq!(quarantine_files(dir.path()).len(), 1);
}

/// The four records of [`four`], framed under layout VERSION 1 (the layout before the header check,
/// never released: 1.5.5 had no log), as a dev build before the check wrote them: 4 x
/// [`FRAME_BYTES`] = 2048 bytes, no padding.
///
/// PROVENANCE. A checked-in test vector, not produced by any encoder at test time. Generated once by
/// reproducing the version-1 encoder (crates/busbar-kernel-wal/src/record.rs, the
/// `#[cfg(test)] pub(crate) fn encode_legacy`, at commit 4aa05a13d71ce79bf8e2320c6689e39cb6e03033)
/// in a throwaway python3 script using `hashlib.sha256`. Per frame `i` (node 3, node_seq `i + 1`,
/// body byte `b` = `(node_seq + b) % 251` for `b` in `0..200`): `[0,4)` "BWAL"; `[4,6)` version 1
/// LE; `[6]` flags 0 (single part); `[7]` 0; `[8,16)` node LE; `[16,24)` node_seq LE; `[24,28)`
/// part index 0 LE; `[28,32)` part count 1 LE; `[32,34)` payload length 200 LE; `[34,64)` zero
/// (no header check under version 1); `[64,96)` SHA-256 over `[0,64)` then `[96,512)`; `[96,296)`
/// the body; `[296,512)` zero. SHA-256 of the whole file:
/// 29d9b3e634b4bf1d278445d7fdb862e5ee3c694e5a6d164dca9888a65eccc286. The full procedure is in
/// `vectors/legacy_segment.bin.provenance`. The test below checks the vector against the current
/// encoder before it relies on it.
const VERSION_1_SEGMENT: &[u8] = include_bytes!("vectors/legacy_segment.bin");

/// A VERSION-1 SEGMENT IS A LAYOUT THIS BUILD DOES NOT READ: quarantined whole, never read and never
/// cut. Version 1 was never released, so no segment in the field holds it; reading it under its old
/// rule (no header check, a digest failure cut as a torn tail) was a downgrade path and nothing else.
/// Every record it holds is set aside with its identity taken, so no acknowledged number is handed
/// out again.
#[test]
fn a_version_1_segment_is_quarantined_never_read() {
    let dir = TempDir::new("v1-segment");
    let written = four();
    lay_down(dir.path(), &written);
    let path = segment_path(dir.path());
    let mut v1: Vec<u8> = VERSION_1_SEGMENT.to_vec();
    // The vector is the version-1 framing of exactly `written`: version 1, no header check, a digest
    // that verifies, and every other byte the current encoder's.
    assert_eq!(v1.len(), written.len() * FRAME_BYTES);
    for (record, frame) in written.iter().zip(v1.as_chunks::<FRAME_BYTES>().0) {
        assert_eq!(frame_version(frame), 1);
        let current = record.encode().remove(0);
        assert_eq!(frame[0..4], current[0..4]);
        assert_eq!(frame[6..34], current[6..34]);
        assert_eq!(frame[34..64], [0u8; 30]);
        assert_eq!(frame[96..], current[96..]);
        assert_eq!(
            decode_frame(frame),
            Err(FrameError::UnknownVersion { found: 1 })
        );
    }
    let len = std::fs::read(&path).unwrap().len();
    v1.resize(len, 0);
    std::fs::write(&path, v1).unwrap();
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert!(
        wal.recovered().is_empty(),
        "a version-1 frame is never read"
    );
    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "the unreadable segment is set aside, loudly");
    assert_eq!(q[0].damage_at, 0);
    let mut ids = q[0].identities.clone();
    ids.sort_unstable();
    assert_eq!(ids, vec![(3, 1), (3, 2), (3, 3), (3, 4)]);
    assert_eq!(quarantine_files(dir.path()).len(), 1);
    assert_eq!(
        wal.next_free_seq(3),
        5,
        "no acknowledged number is handed out again"
    );
}

/// A WHOLE final frame RELABELLED to version 1 is quarantined, never cut as a torn tail (Q128
/// kernel-wal). Under a reader that still took version 1, the relabel skipped the header check and
/// the digest failure it caused read as a torn write, so an acknowledged record was cut silently.
#[test]
fn a_final_frame_relabelled_to_version_1_is_quarantined_not_cut() {
    let dir = TempDir::new("relabel-v1");
    let written = four();
    lay_down(dir.path(), &written);
    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    // `[4,6)` is the layout version, little-endian: 2 becomes 1.
    bytes[3 * FRAME_BYTES + 4..3 * FRAME_BYTES + 6].copy_from_slice(&1u16.to_le_bytes());
    std::fs::write(&path, bytes).unwrap();
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    let q = wal.quarantined();
    assert_eq!(
        q.len(),
        1,
        "the relabelled final record is set aside, loudly"
    );
    assert_eq!(q[0].damage_at, 3 * FRAME_BYTES as u64);
    assert_eq!(q[0].identities, vec![(3, 4)]);
    assert_eq!(quarantine_files(dir.path()).len(), 1);
    assert_eq!(wal.next_free_seq(3), 5);
}

/// A WHOLE final frame whose HEADER was altered after it was written is quarantined, never cut as a
/// torn tail (MONEY-AUDIT E4). A torn write leaves zeros past the point it stopped; this frame has
/// its digest and payload, so it was written in full and its record was acknowledged. The payload
/// length byte (33) and the magic (0) are both header bytes the check covers.
#[test]
fn a_whole_final_frame_with_an_altered_header_is_quarantined_not_cut() {
    for at in [33usize, 0] {
        let dir = TempDir::new(&format!("flip-final-header-{at}"));
        let written = four();
        lay_down(dir.path(), &written);
        flip(dir.path(), 3 * FRAME_BYTES + at);
        let wal = Wal::in_directory(
            dir.path(),
            Box::new(NullShipper::new()),
            super::fixtures::wall_ms,
        )
        .unwrap();
        assert_eq!(wal.recovered(), &written[..3]);
        let q = wal.quarantined();
        assert_eq!(
            q.len(),
            1,
            "byte {at}: the altered final record is set aside, loudly"
        );
        assert_eq!(q[0].damage_at, 3 * FRAME_BYTES as u64);
        assert_eq!(q[0].identities, vec![(3, 4)], "byte {at}");
        assert_eq!(quarantine_files(dir.path()).len(), 1, "byte {at}");
        assert_eq!(
            wal.next_free_seq(3),
            5,
            "byte {at}: the acknowledged record's number is never handed out again"
        );
    }
}

/// A tear INSIDE a version-2 frame's payload (the header was written whole) cannot be told from a
/// whole frame altered afterwards, so it is quarantined rather than cut: the loud side of the
/// ambiguity. Nothing is lost either way; the quarantine holds the bytes and says so.
#[test]
fn a_tear_inside_a_whole_header_frame_is_quarantined_not_cut() {
    let dir = TempDir::new("tear-payload");
    let written = four();
    lay_down(dir.path(), &written);
    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    for b in &mut bytes[3 * FRAME_BYTES + 100..] {
        *b = 0;
    }
    std::fs::write(&path, bytes).unwrap();
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &written[..3]);
    assert_eq!(wal.quarantined().len(), 1);
}

#[test]
fn the_scan_names_the_verdict() {
    let dir = TempDir::new("verdicts");
    lay_down(dir.path(), &four());
    let mut factory = DirectoryFactory::new(dir.path()).unwrap();
    let scan_now = |factory: &mut DirectoryFactory| {
        let segment =
            busbar_kernel_wal::segment::Segment::open_at(factory.open(0).unwrap(), 0, 0, u64::MAX)
                .unwrap();
        busbar_kernel_wal::recover::scan(&segment).unwrap()
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
    fn existing(&self, index: u64) -> std::io::Result<Option<Box<dyn SegmentBackend>>> {
        self.0.existing(index)
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
        busbar_kernel_wal::segment::SEGMENT_BYTES,
        super::fixtures::wall_ms,
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
    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
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
    fn existing(&self, index: u64) -> std::io::Result<Option<Box<dyn SegmentBackend>>> {
        self.0.existing(index)
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
            super::fixtures::wall_ms,
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
        super::fixtures::wall_ms,
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
            super::fixtures::wall_ms,
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
        super::fixtures::wall_ms,
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
    use busbar_kernel_wal::journal::{BodyReader, Journal, RecordClass};

    let dir = TempDir::new("quarantine-record");
    lay_down(dir.path(), &four());
    flip(dir.path(), FRAME_BYTES + 3);

    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
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
    assert_eq!(
        body.text(),
        Some(busbar_kernel_wal::recover::QUARANTINE_BODY_TAG)
    );
    let segment_file = segment_path(dir.path()).display().to_string();
    assert_eq!(body.text(), Some(segment_file.as_str()));
    assert_eq!(body.num(), Some(0));
    assert_eq!(body.num(), Some(FRAME_BYTES as u64));
    assert_eq!(body.num(), Some(FRAME_BYTES as u64));
    assert_eq!(body.num(), Some(3 * FRAME_BYTES as u64));
    let kept = file.display().to_string();
    assert_eq!(body.text(), Some(kept.as_str()));
    assert_eq!(body.num(), Some(q.at_unix_ms));
    // The record whose magic was flipped (3, 2) and the two verifying ones behind it: the flipped
    // frame was written whole, so its record was acknowledged and its identity is named too.
    assert_eq!(body.num(), Some(3));
    assert!(body.is_done());

    // A clean boot has nothing to record.
    drop(journal);
    let clean = TempDir::new("quarantine-record-clean");
    lay_down(clean.path(), &four());
    let mut journal = Journal::over(
        Wal::in_directory(
            clean.path(),
            Box::new(NullShipper::new()),
            super::fixtures::wall_ms,
        )
        .unwrap(),
        3,
    );
    assert!(journal
        .record_quarantines(&durability_token(), METER, 1)
        .unwrap()
        .is_none());
}
