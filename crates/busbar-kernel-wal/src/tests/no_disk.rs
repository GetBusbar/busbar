// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The default log uses memory-buffered mode.

use crate::wal::{Mode, Wal};

#[test]
fn the_default_log_is_the_memory_buffered_one() {
    assert_eq!(
        Wal::memory_buffered_to(
            Box::new(crate::ship::NullShipper::new()),
            crate::tests::fixtures::wall_ms
        )
        .mode(),
        Mode::MemoryBuffered
    );
}
