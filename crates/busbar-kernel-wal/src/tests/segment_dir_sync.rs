// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A new segment's directory entry is made durable when the segment is created.

use std::path::PathBuf;

use crate::backend::{DirectoryFactory, SegmentFactory};
use crate::tests::hooks::{fault_reset, parents_fsynced};

fn syncs() -> Vec<PathBuf> {
    parents_fsynced()
}

fn reset() {
    fault_reset();
}

/// A scratch data directory, removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// **CREATING A SEGMENT FSYNCS THE DIRECTORY THAT HOLDS IT; OPENING ONE THAT EXISTS DOES NOT.**
///
/// RED before the fix: the factory opened (and so created) `<index>.wal` with no directory fsync,
/// so a segment rolled into could vanish from the directory after a power loss even though every
/// write in it had synced. Measured on the factory a durable log uses, for the first segment and
/// for a roll's next one.
#[test]
fn a_created_segment_has_its_holding_directory_fsynced_and_a_reopened_one_does_not() {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "busbar-wal-segdir-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    let mut factory = DirectoryFactory::new(&scratch.0).expect("the data directory opens");
    let dir = factory
        .segment_path(0)
        .parent()
        .expect("a segment lives in the data directory")
        .to_path_buf();

    reset();
    let _first = factory.open(0).expect("segment 0 is created");
    assert_eq!(
        syncs(),
        vec![dir.clone()],
        "creating segment 0 fsyncs its directory"
    );

    reset();
    let _next = factory
        .open(1)
        .expect("segment 1 is created, as a roll does");
    assert_eq!(
        syncs(),
        vec![dir.clone()],
        "creating the next segment fsyncs it too"
    );

    reset();
    let _again = factory.open(1).expect("segment 1 reopens");
    assert!(
        syncs().is_empty(),
        "an existing segment's entry is already durable; reopening it syncs nothing"
    );
    assert!(factory.segment_path(1).is_file());
}
