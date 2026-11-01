// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The default log uses memory-buffered mode.
//!
//! Append/readback and filesystem witnesses live in busbar-kernel's
//! `tests/members/wal/no_disk_tests.rs`, where the host can lend a durability grant. The adjacent
//! `journal_chain_tests.rs` verifies the shipped chain after dropping the memory journal.

use crate::wal::{Mode, Wal};

#[test]
fn the_default_log_is_the_memory_buffered_one() {
    // Stated as a test because "the default is no disk" is a product claim, and a default that
    // quietly changed would otherwise be found by an operator rather than by the suite. The
    // default is the log a node with no data directory is built with: memory-buffered, shipping to
    // whatever store the composition root binds.
    assert_eq!(
        Wal::memory_buffered_to(
            Box::new(crate::ship::NullShipper::new()),
            crate::tests::fixtures::wall_ms
        )
        .mode(),
        Mode::MemoryBuffered
    );
}
