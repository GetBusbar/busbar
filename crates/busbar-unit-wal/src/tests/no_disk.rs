// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! No data directory means no file, anywhere.
//!
//! The claim is not "the log avoids writing files in this mode" — it is that a memory-buffered log
//! holds nothing that knows how to open one. The battery makes that observable: a temp directory is
//! created, a whole append-recover-restart cycle runs beside it, and the directory is asserted still
//! empty. The same assertion is made about the process's current directory, because a path bug
//! usually lands there rather than somewhere plausible.

use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, TempDir};

#[test]
fn a_memory_buffered_log_creates_no_file_anywhere() {
    let dir = TempDir::new("no-disk");
    let before = dir.walk();
    assert!(
        before.is_empty(),
        "the fixture directory did not start empty"
    );
    let cwd_before = std::fs::read_dir(".")
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);

    let mut wal = Wal::memory_buffered();
    assert_eq!(wal.mode(), Mode::MemoryBuffered);
    let token = durability_token();
    // Enough records, and enough of them large enough to continue across frames, that any
    // preallocation or segment roll would have to have happened by now.
    for batch in 0..8u64 {
        let batch_records = records(1, batch * 4 + 1, 4, 900);
        wal.append_batch(&token, busbar_caps::StepName::Meter, &batch_records)
            .unwrap();
    }
    let back = wal.read_back().unwrap();
    assert_eq!(back.records.len(), 32);

    assert!(
        dir.walk().is_empty(),
        "a memory-buffered log put something on a disk: {:?}",
        dir.walk()
    );
    let cwd_after = std::fs::read_dir(".")
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    assert_eq!(
        cwd_before, cwd_after,
        "something appeared in the working directory"
    );
}

#[test]
fn the_default_log_is_the_memory_buffered_one() {
    // Stated as a test because "the default is no disk" is a product claim, and a default that
    // quietly changed would otherwise be found by an operator rather than by the suite.
    assert_eq!(Wal::memory_buffered().mode(), Mode::MemoryBuffered);
}

#[test]
fn a_memory_buffered_log_ships_every_committed_batch_synchronously() {
    let shipper = crate::ship::BufferShipper::new();
    let mut wal = Wal::memory_buffered_to(Box::new(shipper.clone()));
    let token = durability_token();
    let first = records(4, 1, 3, 30);
    let second = records(4, 4, 2, 30);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &first)
        .unwrap();
    assert_eq!(
        shipper.records().len(),
        3,
        "the batch reached the store as part of the commit"
    );
    wal.append_batch(&token, busbar_caps::StepName::Meter, &second)
        .unwrap();
    let mut expected = first;
    expected.extend(second);
    assert_eq!(shipper.records(), expected);
}

#[test]
fn a_log_in_a_directory_does_write_files_there_and_nowhere_else() {
    // The other half of the claim: naming a directory is the decision to use it, and when it is
    // named the files appear in it rather than beside it.
    let dir = TempDir::new("on-disk");
    let inner = dir.path().join("wal");
    {
        let mut wal = Wal::in_directory(&inner, Box::new(crate::ship::NullShipper::new())).unwrap();
        assert_eq!(wal.mode(), Mode::OnDisk);
        let token = durability_token();
        wal.append_batch(&token, busbar_caps::StepName::Meter, &records(1, 1, 3, 100))
            .unwrap();
    }
    let files: Vec<_> = dir.walk().into_iter().filter(|p| p.is_file()).collect();
    assert_eq!(
        files.len(),
        1,
        "one segment file, in the named directory: {files:?}"
    );
    assert!(files[0].starts_with(&inner));

    // And it reopens onto what it wrote.
    let wal = Wal::in_directory(&inner, Box::new(crate::ship::NullShipper::new())).unwrap();
    assert_eq!(wal.recovered().len(), 3);
    assert!(wal.holds(1, 2));
}
