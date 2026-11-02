// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A directory fsync that fails is an error, wherever the log makes directory durability.

use std::path::{Path, PathBuf};

use crate::backend::{DirectoryFactory, SegmentFactory};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::QuarantineKept;
use crate::segment::SEGMENT_BYTES;
use crate::ship::NullShipper;
use crate::tests::hooks::{fault_arm, fault_reset, parents_fsynced, FaultStep};
use crate::wal::{Mode, Wal};

/// Linux and macOS share this value. Injected via `from_raw_os_error`.
const EIO: i32 = 5;

/// A scratch path under the system temp directory, removed on drop. Not created: a test that wants
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-wal-dirfsync-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Scratch(path)
    }

    fn made(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        std::fs::create_dir_all(&scratch.0).expect("the scratch directory");
        scratch
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **A SEGMENT WHOSE DIRECTORY FSYNC FAILS IS NOT HANDED OUT, AND NOT LEFT BEHIND.** RED before the
#[test]
fn a_segment_whose_directory_fsync_fails_is_not_handed_out() {
    let scratch = Scratch::new("segment");
    let mut factory = DirectoryFactory::new(scratch.path()).expect("the data directory opens");
    let dir = scratch.path().to_path_buf();

    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = factory
        .open(0)
        .err()
        .expect("a segment whose entry is not durable is not handed out");
    assert_eq!(err.raw_os_error(), Some(EIO));
    assert!(
        !factory.segment_path(0).exists(),
        "the file is not left for the next open to find already existing"
    );

    fault_reset();
    factory.open(0).expect("the next open creates it again");
    assert_eq!(
        parents_fsynced(),
        vec![dir],
        "and makes its entry durable this time"
    );
}

/// **A QUARANTINE COPY WHOSE DIRECTORY FSYNC FAILS IS NOT KEPT, SO THE SEGMENT IS NOT CUT.** RED
#[test]
fn a_quarantine_whose_directory_fsync_fails_leaves_the_segment_uncut() {
    let scratch = Scratch::made("quarantine");
    let factory = DirectoryFactory::new(scratch.path()).expect("the data directory opens");
    let segment = factory.segment_path(0);
    let mut bytes = Vec::new();
    for (i, record) in (1..=4u64)
        .map(|seq| Record::new(3, seq, vec![seq as u8; 200]))
        .enumerate()
    {
        for frame in record.encode_in_commit(i == 0) {
            bytes.extend_from_slice(&frame);
        }
    }

    bytes[FRAME_BYTES + 200] ^= 0xFF;
    std::fs::write(&segment, &bytes).unwrap();

    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let wal = Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        SEGMENT_BYTES,
        crate::tests::fixtures::wall_ms,
    )
    .expect("a failed copy does not stop the log opening");
    let q = wal.quarantined();
    assert_eq!(q.len(), 1, "the damage is reported");
    assert!(
        matches!(q[0].kept, QuarantineKept::InPlace(_)),
        "a copy that was not made durable is not a copy kept: {:?}",
        q[0].kept
    );
    assert_eq!(
        std::fs::read(&segment).unwrap(),
        bytes,
        "the segment still holds every damaged byte"
    );
    assert!(wal.is_poisoned(), "and is closed to writes");
}

/// **A DATA DIRECTORY CREATED SEVERAL LEVELS DEEP HAS EVERY NEW DIRECTORY'S ENTRY FSYNCED.** RED
#[test]
fn a_deep_data_directory_has_every_directory_it_creates_fsynced() {
    let scratch = Scratch::made("deep");
    let root = scratch.path().to_path_buf();
    fault_reset();
    DirectoryFactory::new(root.join("a").join("b").join("journal")).expect("the tree is created");
    assert_eq!(
        parents_fsynced(),
        vec![root.clone(), root.join("a"), root.join("a").join("b")],
        "one parent fsync per created directory, shallowest first"
    );
}

/// **CREATING A SEGMENT FSYNCS THE DIRECTORY THAT HOLDS IT; OPENING ONE THAT EXISTS DOES NOT.**
#[test]
fn a_created_segment_has_its_holding_directory_fsynced_and_a_reopened_one_does_not() {
    let scratch = Scratch::new("segdir");
    let mut factory = DirectoryFactory::new(scratch.path()).expect("the data directory opens");
    let dir = factory
        .segment_path(0)
        .parent()
        .expect("a segment lives in the data directory")
        .to_path_buf();

    fault_reset();
    let _first = factory.open(0).expect("segment 0 is created");
    assert_eq!(
        parents_fsynced(),
        vec![dir.clone()],
        "creating segment 0 fsyncs its directory"
    );

    fault_reset();
    let _next = factory
        .open(1)
        .expect("segment 1 is created, as a roll does");
    assert_eq!(
        parents_fsynced(),
        vec![dir.clone()],
        "creating the next segment fsyncs it too"
    );

    fault_reset();
    let _again = factory.open(1).expect("segment 1 reopens");
    assert!(
        parents_fsynced().is_empty(),
        "an existing segment's entry is already durable; reopening it syncs nothing"
    );
    assert!(factory.segment_path(1).is_file());
}
