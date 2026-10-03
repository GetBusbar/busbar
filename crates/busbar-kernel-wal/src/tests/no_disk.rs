// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! No data directory means no file, anywhere.
//!
//! The claim is not "the log avoids writing files in this mode" — it is that a memory-buffered log
//! holds nothing that knows how to open one. The battery makes that observable: a temp directory is
//! created, a whole append-recover-restart cycle runs beside it, and the directory is asserted still
//! empty. The current directory is checked too, because a path bug usually lands there rather than
//! somewhere plausible — but as a set of names matching the log's own `<index>.wal` segments, not
//! as a count: the cwd is shared with every other test in the binary, so a count moves for reasons
//! that are nothing to do with the log, and a count that happens to hold still also hides one file
//! replacing another. The temp-directory walk is the primary evidence; the cwd set is the check
//! that the write did not simply land somewhere else.

use crate::wal::{Mode, Wal};

#[test]
fn the_default_log_is_the_memory_buffered_one() {
    // Stated as a test because "the default is no disk" is a product claim, and a default that
    // quietly changed would otherwise be found by an operator rather than by the suite.
    assert_eq!(
        Wal::memory_buffered(crate::tests::fixtures::wall_ms).mode(),
        Mode::MemoryBuffered
    );
}
