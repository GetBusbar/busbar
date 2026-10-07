// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A directory fsync that fails is an error, wherever directory durability is made.
//!
//! The entry a creation, a rename or an unlink changes is only durable once the directory holding
//! it is fsynced. Swallowing that fsync's failure hands the caller a success the medium did not
//! give: a publish reported durable whose rename a power loss can undo, a segment handed out whose
//! name a power loss can take with every acknowledged record in it, a quarantine copy reported kept
//! while recovery cuts the only other copy of the bytes. The one failure that is not the caller's
//! is a filesystem saying it does not support the operation at all.

use std::path::{Path, PathBuf};

use crate::backend::{DirectoryFactory, SegmentFactory};
use crate::durable;
use crate::record::{Record, FRAME_BYTES};
use crate::recover::QuarantineKept;
use crate::segment::SEGMENT_BYTES;
use crate::ship::NullShipper;
use crate::tests::hooks::{fault_arm, fault_reset, parents_fsynced, FaultStep};
use crate::wal::{Mode, Wal};

/// Linux and macOS share this value. Injected via `from_raw_os_error`.
const EIO: i32 = 5;
/// `EINVAL`: what `fsync(2)` answers for a descriptor that does not support synchronization.
const EINVAL: i32 = 22;

/// A scratch path under the system temp directory, removed on drop. Not created: a test that wants
/// it to exist creates it.
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

/// **A PUBLISH WHOSE DIRECTORY FSYNC FAILS IS AN ERROR.** RED before the fix: the failure was
/// swallowed and `write` answered `Ok` over a rename a power loss could still undo.
#[test]
fn a_publish_whose_directory_fsync_fails_is_an_error() {
    let scratch = Scratch::made("publish");
    let target = scratch.path().join("overlay.json");
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = durable::write(&target, b"new contents")
        .expect_err("a directory fsync that failed is not a durable publish");
    assert_eq!(
        err.raw_os_error(),
        Some(EIO),
        "the fsync's own error surfaces"
    );
    // The contract says what an error from the last step means: the rename happened, and it is
    // the entry's durability that was not given.
    assert_eq!(std::fs::read(&target).unwrap(), b"new contents");
}

/// **A REMOVAL WHOSE DIRECTORY FSYNC FAILS IS AN ERROR.** RED before the fix: `remove` answered
/// `Ok` once the unlink succeeded, whatever the fsync after it said.
#[test]
fn a_removal_whose_directory_fsync_fails_is_an_error() {
    let scratch = Scratch::made("remove");
    let target = scratch.path().join("plugin.tar.gz");
    std::fs::write(&target, b"artifact").unwrap();
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = durable::remove(&target).expect_err("the removal was not made durable");
    assert_eq!(err.raw_os_error(), Some(EIO));
}

/// **A DIRECTORY CREATED WHOSE PARENT'S FSYNC FAILS IS AN ERROR.** RED before the fix: the walk
/// fsynced each new directory's parent and ignored the answer.
#[test]
fn a_created_directory_whose_parent_fsync_fails_is_an_error() {
    let scratch = Scratch::made("mkdir");
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = durable::create_dir_all(&scratch.path().join("plugins"))
        .expect_err("the new directory's entry was not made durable");
    assert_eq!(err.raw_os_error(), Some(EIO));
}

/// A filesystem that does not support fsyncing a directory is not refused: there is nothing more
/// it can promise, and refusing every publish on it would leave no durability at all.
#[test]
fn a_directory_fsync_the_filesystem_does_not_support_is_not_an_error() {
    let scratch = Scratch::made("unsupported");
    let target = scratch.path().join("state.json");
    fault_reset();
    fault_arm(FaultStep::DirSync, EINVAL);
    durable::write(&target, b"contents").expect("an unsupported directory fsync is not a failure");
    assert_eq!(std::fs::read(&target).unwrap(), b"contents");
}

/// **A SEGMENT WHOSE DIRECTORY FSYNC FAILS IS NOT HANDED OUT, AND NOT LEFT BEHIND.** RED before the
/// fix: the factory swallowed the failure and handed out a segment whose name a power loss could
/// take with every record acknowledged in it. Left behind, the file would be found existing by the
/// next open, which would skip the fsync for good.
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
/// before the fix: the quarantine answered `Ok` over a copy whose name a power loss could take, and
/// recovery then cut the only other copy of the damaged bytes out of the segment.
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
    // The second record's payload is damaged; the two behind it verify.
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
/// before the fix: the factory created the tree with `std::fs::create_dir_all` and fsynced only the
/// leaf's parent, so an intermediate entry — and the whole log under it — could be lost to the first
/// power loss. It now goes through the one durable `create_dir_all`.
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
