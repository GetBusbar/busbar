// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::{Path, PathBuf};

use busbar_kernel_wal::backend::{DirectoryFactory, MemoryFactory, SegmentBackend, SegmentFactory};
use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};
use busbar_kernel_wal::record::{decode_frame, frame_version, FrameError, Record, FRAME_BYTES};
use busbar_kernel_wal::recover::{QuarantineKept, TailVerdict};
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, TempDir, METER};

fn four() -> Vec<Record> {
    records(3, 1, 4, 200)
}

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

fn flip(dir: &Path, at: usize) {
    let path = segment_path(dir);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
}

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
fn a_mid_log_checksum_flip_quarantines_only_the_damaged_record_and_keeps_every_one_behind_it() {
    let dir = TempDir::new("corrupt-mid-log");
    let written = four();
    let original = lay_down(dir.path(), &written);
    assert_eq!(original.len(), 4 * FRAME_BYTES);

    flip(dir.path(), FRAME_BYTES + 200);
    let damaged = std::fs::read(segment_path(dir.path())).unwrap()[..original.len()].to_vec();

    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .expect("a corrupt segment does not stop the log opening");

    assert_eq!(
        wal.recovered(),
        &[written[0].clone(), written[2].clone(), written[3].clone()]
    );

    let segment_now = std::fs::read(segment_path(dir.path())).unwrap();
    assert_eq!(segment_now[..original.len()].to_vec(), damaged);

    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "one damaged record, one quarantine");
    let q = &q[0];
    assert_eq!(q.segment, 0);
    assert_eq!(
        q.segment_file.as_deref(),
        Some(segment_path(dir.path()).as_path())
    );
    assert_eq!(q.offset, FRAME_BYTES as u64);
    assert_eq!(q.damage_at, FRAME_BYTES as u64);
    assert_eq!(q.bytes, FRAME_BYTES as u64);
    assert_eq!(
        q.identities,
        vec![(3, 2)],
        "only the altered record is named"
    );
    assert_eq!(
        q.damaged.iter().map(Record::identity).collect::<Vec<_>>(),
        vec![(3, 2)],
        "the set-aside record is handed over, as it now reads, for the caller to attribute"
    );
    assert_eq!(q.before, Some((3, 1)), "the record kept before the hole");
    assert_eq!(q.after, Some((3, 3)), "the record kept behind it");

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
        damaged[FRAME_BYTES..2 * FRAME_BYTES].to_vec()
    );

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
    assert_eq!((q[0].before, q[0].after), (Some((3, 3)), None));
    assert_eq!(
        std::fs::read(segment_path(dir.path())).unwrap()[3 * FRAME_BYTES + 200],
        written[3].encode()[0][200] ^ 0xFF,
        "an acknowledged record is never cut, at the tail either"
    );
    assert!(
        wal.is_poisoned(),
        "the segment is closed to writes, so the next append rolls past the damage"
    );
    assert_eq!(
        q[0].damaged
            .iter()
            .map(Record::identity)
            .collect::<Vec<_>>(),
        vec![(3, 4)]
    );
    assert_eq!(quarantine_files(dir.path()).len(), 1);
}

const VERSION_1_SEGMENT: &[u8] = include_bytes!("vectors/legacy_segment.bin");

#[test]
fn a_version_1_segment_is_quarantined_never_read() {
    let dir = TempDir::new("v1-segment");
    let written = four();
    lay_down(dir.path(), &written);
    let path = segment_path(dir.path());
    let mut v1: Vec<u8> = VERSION_1_SEGMENT.to_vec();

    assert_eq!(v1.len(), written.len() * FRAME_BYTES);
    for (record, frame) in written.iter().zip(v1.as_chunks::<FRAME_BYTES>().0) {
        assert_eq!(frame_version(frame), 1);
        let current = record.encode().remove(0);
        assert_eq!(frame[0..4], current[0..4]);
        assert_eq!(frame[6..34], current[6..34]);
        assert_eq!(frame[34..64], [0u8; 30]);

        assert_eq!(frame[96..FRAME_BYTES - 1], current[96..FRAME_BYTES - 1]);
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

#[test]
fn a_final_frame_relabelled_to_version_1_is_quarantined_not_cut() {
    let dir = TempDir::new("relabel-v1");
    let written = four();
    lay_down(dir.path(), &written);
    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();

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

#[test]
fn a_tear_inside_a_frames_payload_is_a_torn_tail_cut_silently() {
    let dir = TempDir::new("tear-payload");
    let written = four();
    let original = lay_down(dir.path(), &written);
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
    assert!(wal.quarantined().is_empty(), "a crash is not corruption");
    assert!(quarantine_files(dir.path()).is_empty());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original[..3 * FRAME_BYTES].to_vec(),
        "the torn frame is cut"
    );
    assert_eq!(
        wal.next_free_seq(3),
        4,
        "an identity nothing acknowledged is not taken"
    );
}

fn lay_down_commits(dir: &Path, commits: &[Vec<Record>]) -> Vec<u8> {
    let mut wal =
        Wal::in_directory(dir, Box::new(NullShipper::new()), super::fixtures::wall_ms).unwrap();
    let mut end = 0;
    for commit in commits {
        end = wal
            .append_batch(&durability_token(), METER, commit)
            .unwrap()
            .durable_end;
    }
    drop(wal);
    let bytes = std::fs::read(segment_path(dir)).unwrap();
    bytes[..usize::try_from(end).unwrap()].to_vec()
}

#[test]
fn a_commit_whose_pages_landed_out_of_order_is_a_torn_tail() {
    let dir = TempDir::new("pages-out-of-order");

    let acknowledged = records(3, 1, 2, 200);
    let torn_commit = records(3, 3, 12, 200);
    let original = lay_down_commits(dir.path(), &[acknowledged.clone(), torn_commit.clone()]);
    assert_eq!(original.len(), 14 * FRAME_BYTES);

    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    for b in &mut bytes[2 * FRAME_BYTES..8 * FRAME_BYTES] {
        *b = 0;
    }
    std::fs::write(&path, bytes).unwrap();

    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), acknowledged.as_slice());
    assert!(
        wal.quarantined().is_empty(),
        "a crash mid-commit is not corruption"
    );
    assert!(quarantine_files(dir.path()).is_empty());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original[..2 * FRAME_BYTES].to_vec(),
        "the whole torn commit is cut, the frames of it that landed included"
    );
    assert_eq!(
        wal.next_free_seq(3),
        3,
        "no identity of the commit nothing acknowledged is taken"
    );
}

#[test]
fn damage_in_a_commit_a_subsequent_commit_acknowledges_is_corrupt_whatever_its_shape() {
    let dir = TempDir::new("acknowledged-zeros");
    let first = records(3, 1, 4, 200);
    let next = records(3, 5, 2, 200);
    lay_down_commits(dir.path(), &[first.clone(), next.clone()]);

    let path = segment_path(dir.path());
    let mut bytes = std::fs::read(&path).unwrap();
    for b in &mut bytes[FRAME_BYTES..2 * FRAME_BYTES] {
        *b = 0;
    }
    std::fs::write(&path, bytes).unwrap();

    let wal = Wal::in_directory(
        dir.path(),
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    let mut kept = vec![first[0].clone(), first[2].clone(), first[3].clone()];
    kept.extend(next.iter().cloned());
    assert_eq!(
        wal.recovered(),
        kept.as_slice(),
        "every acknowledged record behind the zeroed one is kept"
    );
    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "the acknowledged record lost is reported");
    assert_eq!(q[0].damage_at, FRAME_BYTES as u64);
    assert_eq!(q[0].bytes, FRAME_BYTES as u64);
    assert!(
        q[0].identities.is_empty(),
        "a zeroed frame carries no identity to name"
    );
    assert_eq!((q[0].before, q[0].after), (Some((3, 1)), Some((3, 3))));
    assert_eq!(quarantine_files(dir.path()).len(), 1);
    assert_eq!(wal.next_free_seq(3), 7);
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
    assert_eq!(
        corrupt.records.len(),
        3,
        "the scan reads past the hole to the record behind it"
    );
    assert_eq!(corrupt.holes.len(), 1);
    assert_eq!(corrupt.tail, TailVerdict::Clean);
}

#[test]
fn acknowledged_damage_is_found_again_at_every_boot_with_one_copy() {
    let dir = TempDir::new("found-again");
    let written = four();
    let original = lay_down(dir.path(), &written);
    flip(dir.path(), FRAME_BYTES + 7);
    let path = segment_path(dir.path());
    let damaged = std::fs::read(&path).unwrap()[..original.len()].to_vec();

    let open = || {
        Wal::in_directory(
            dir.path(),
            Box::new(NullShipper::new()),
            super::fixtures::wall_ms,
        )
        .unwrap()
    };
    let first = open();
    let first_q = first.quarantined().to_vec();
    drop(first);
    let second = open();
    assert_eq!(
        second.recovered(),
        &[written[0].clone(), written[2].clone(), written[3].clone()]
    );
    assert_eq!(
        second.quarantined().len(),
        1,
        "the damage is reported again"
    );
    assert_eq!(second.quarantined()[0].kept, first_q[0].kept, "one copy");
    assert_eq!(
        std::fs::read(&path).unwrap()[..original.len()].to_vec(),
        damaged
    );
    let files = quarantine_files(dir.path());
    assert_eq!(files.len(), 1);
    assert_eq!(
        std::fs::read(&files[0]).unwrap(),
        damaged[FRAME_BYTES..2 * FRAME_BYTES].to_vec()
    );
}

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
    let before = seg0.lock().unwrap()[..4 * FRAME_BYTES].to_vec();

    let mut wal = Wal::with_parts(
        Box::new(NoQuarantine(factory.clone())),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        64 * FRAME_BYTES as u64,
        super::fixtures::wall_ms,
    )
    .expect("a failed copy does not stop the log opening");
    assert_eq!(
        wal.recovered(),
        &[written[0].clone(), written[2].clone(), written[3].clone()]
    );
    assert!(matches!(
        wal.quarantined()[0].kept,
        QuarantineKept::InPlace(_)
    ));

    assert_eq!(seg0.lock().unwrap()[..4 * FRAME_BYTES].to_vec(), before);

    assert!(wal.is_poisoned(), "the damaged segment is closed to writes");

    let next = records(3, 9, 1, 10);
    let ack = wal.append_batch(&durability_token(), METER, &next).unwrap();
    assert_eq!(ack.segment, 1, "the next append rolled past the damage");
    assert_eq!(seg0.lock().unwrap()[..4 * FRAME_BYTES].to_vec(), before);
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
    let damaged = seg0.lock().unwrap()[2 * FRAME_BYTES..3 * FRAME_BYTES].to_vec();

    let wal = Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::MemoryBuffered,
        64 * FRAME_BYTES as u64,
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(
        wal.recovered(),
        &[written[0].clone(), written[1].clone(), written[3].clone()]
    );
    assert_eq!(wal.quarantined()[0].kept, QuarantineKept::Memory);
    let kept = factory.quarantined();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].segment, 0);
    assert_eq!(kept[0].offset, 2 * FRAME_BYTES as u64);
    assert_eq!(kept[0].bytes, damaged);
}

#[test]
fn the_journal_puts_a_durable_record_of_each_quarantine_on_the_chain() {
    use busbar_kernel_wal::journal::BodyReader;

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
    assert_eq!(body.num(), Some(FRAME_BYTES as u64));
    let kept = file.display().to_string();
    assert_eq!(body.text(), Some(kept.as_str()));
    assert_eq!(body.num(), Some(q.at_unix_ms));

    assert_eq!(body.num(), Some(1));

    assert_eq!(
        [
            body.num(),
            body.num(),
            body.num(),
            body.num(),
            body.num(),
            body.num()
        ],
        [Some(1), Some(3), Some(1), Some(1), Some(3), Some(3)]
    );
    assert!(body.is_done());

    drop(journal);
    let mut journal = Journal::over(
        Wal::in_directory(
            dir.path(),
            Box::new(NullShipper::new()),
            super::fixtures::wall_ms,
        )
        .unwrap(),
        3,
    );
    assert_eq!(journal.log().quarantined().len(), 1);
    assert!(journal
        .record_quarantines(&durability_token(), METER, 1_700_000_001)
        .unwrap()
        .is_none());

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

fn seal_loads(journal: &mut Journal, n: u8, tag: u8) {
    for i in 0..n {
        journal
            .append(
                &durability_token(),
                METER,
                &[Entry::new(RecordClass::Load, vec![tag, i, 0, 0, 0, 0, 0, 0]).at(1, 0)],
            )
            .unwrap();
    }
}

fn journal_in(dir: &Path) -> Journal {
    Journal::in_directory(
        3,
        dir,
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap()
}

fn replayed_seqs(journal: &Journal) -> Vec<u64> {
    journal
        .replay()
        .expect("the log reads back")
        .expect("the chain verifies across the quarantine")
        .iter()
        .map(|r| r.node_seq)
        .collect()
}

#[test]
fn after_a_quarantine_every_later_replay_rebuilds_every_kept_record() {
    let dir = TempDir::new("chain-after-quarantine");
    seal_loads(&mut journal_in(dir.path()), 4, 1);

    flip(dir.path(), 3 * FRAME_BYTES + 200);

    let mut journal = journal_in(dir.path());
    assert_eq!(
        journal.log().quarantined().len(),
        1,
        "the quarantine is reported"
    );
    assert_eq!(replayed_seqs(&journal), vec![1, 2, 3]);
    let sealed = journal
        .record_quarantines(&durability_token(), METER, 1_700_000_000)
        .unwrap()
        .expect("the quarantine goes on the chain");
    assert_eq!(sealed.sealed[0].node_seq, 5, "number four stays taken");
    seal_loads(&mut journal, 3, 2);
    assert_eq!(
        replayed_seqs(&journal),
        vec![1, 2, 3, 5, 6, 7, 8],
        "the replay after the break rebuilds every kept record and every one after"
    );
    drop(journal);

    for boot in 0..2 {
        let mut journal = journal_in(dir.path());
        assert_eq!(
            journal.log().quarantined().len(),
            1,
            "boot {boot}: the damage is still there, and still reported"
        );
        assert_eq!(
            replayed_seqs(&journal),
            vec![1, 2, 3, 5, 6, 7, 8],
            "boot {boot}"
        );
        assert!(
            journal
                .record_quarantines(&durability_token(), METER, 1_700_000_001)
                .unwrap()
                .is_none(),
            "boot {boot}: the hole is on the chain once"
        );
    }
}

#[test]
fn a_mid_journal_hole_keeps_every_record_behind_it_on_the_chain() {
    let dir = TempDir::new("chain-mid-hole");
    seal_loads(&mut journal_in(dir.path()), 4, 1);
    flip(dir.path(), FRAME_BYTES + 200);

    let mut journal = journal_in(dir.path());
    assert_eq!(replayed_seqs(&journal), vec![1, 3, 4]);
    journal
        .record_quarantines(&durability_token(), METER, 1_700_000_000)
        .unwrap()
        .expect("the hole goes on the chain");
    seal_loads(&mut journal, 2, 2);
    assert_eq!(replayed_seqs(&journal), vec![1, 3, 4, 5, 6, 7]);
    drop(journal);
    assert_eq!(
        replayed_seqs(&journal_in(dir.path())),
        vec![1, 3, 4, 5, 6, 7]
    );
}

#[test]
fn a_gap_no_quarantine_names_still_breaks_the_chain() {
    let dir = TempDir::new("chain-unnamed-gap");
    let mut journal = journal_in(dir.path());
    seal_loads(&mut journal, 4, 1);
    let mut records = journal.replay().unwrap().unwrap();
    records.remove(1);
    assert!(matches!(
        busbar_kernel_wal::journal::verify(&records),
        Err(busbar_kernel_wal::journal::JournalBreak { at_index: 2, .. })
    ));
}

#[test]
fn damage_in_a_segment_below_the_tail_is_quarantined_reported_and_read_past() {
    const CEILING: u64 = 4 * FRAME_BYTES as u64;
    let open = |dir: &Path| {
        Journal::over(
            Wal::with_parts(
                Box::new(DirectoryFactory::new(dir).unwrap()),
                Box::new(NullShipper::new()),
                Mode::OnDisk,
                CEILING,
                super::fixtures::wall_ms,
            )
            .unwrap(),
            3,
        )
    };
    for (damaged, kept, before, after) in [
        (2u64, vec![1, 3, 4, 5, 6, 7, 8], (3, 1), (3, 3)),
        (4u64, vec![1, 2, 3, 5, 6, 7, 8], (3, 3), (3, 5)),
    ] {
        let dir = TempDir::new(&format!("below-tail-{damaged}"));
        seal_loads(&mut open(dir.path()), 8, 1);
        assert!(
            DirectoryFactory::new(dir.path())
                .unwrap()
                .segment_path(1)
                .exists(),
            "the log rolled"
        );
        flip(dir.path(), (damaged as usize - 1) * FRAME_BYTES + 200);

        let journal = open(dir.path());
        let q = journal.log().quarantined();
        assert_eq!(q.len(), 1, "record {damaged}: the damage is reported");
        assert_eq!(q[0].segment, 0);
        assert_eq!(q[0].offset, (damaged - 1) * FRAME_BYTES as u64);
        assert_eq!(q[0].identities, vec![(3, damaged)]);
        assert_eq!((q[0].before, q[0].after), (Some(before), Some(after)));
        assert_eq!(quarantine_files(dir.path()).len(), 1);
        let back: Vec<u64> = journal
            .log()
            .read_back()
            .unwrap()
            .records
            .iter()
            .map(|r| r.node_seq)
            .collect();
        assert_eq!(
            back, kept,
            "record {damaged}: the rest of the segment is read"
        );
        assert_eq!(replayed_seqs(&journal), kept, "record {damaged}");
    }
}
