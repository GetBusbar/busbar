// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test side of `backend.rs`'s `#[cfg(test)]` hook point: the one directory fsync the log makes
//! for its own segment files and quarantine copies.
//!
//! `backend.rs` keeps only the call. What it consults — the armed fault and the recorded fsyncs —
//! lives here, per thread, so a test arms exactly the case it means and no other test sees it.

use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};

/// The step a fault can be armed at: the fsync of the directory holding an entry the log created.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FaultStep {
    /// The fsync of the directory holding a created segment, quarantine copy or data directory.
    DirSync,
}

thread_local! {
    /// `(step, raw_os_errno)` — the next matching step on this thread returns that errno once.
    static FAULT_INJECT: RefCell<Option<(FaultStep, i32)>> = const { RefCell::new(None) };
    /// Every directory the log fsynced on this thread, in order.
    static PARENT_FSYNCS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
}

/// Arm a one-shot fault: the next matching step returns `io::Error::from_raw_os_error(errno)`.
pub(crate) fn fault_arm(step: FaultStep, errno: i32) {
    FAULT_INJECT.with(|c| *c.borrow_mut() = Some((step, errno)));
}

/// Clear any armed fault and every recorded directory fsync (call at the start of each case).
pub(crate) fn fault_reset() {
    FAULT_INJECT.with(|c| *c.borrow_mut() = None);
    PARENT_FSYNCS.with(|c| c.borrow_mut().clear());
}

/// The directory-fsync hook: record `parent` as fsynced on this thread, then fail if a
/// [`FaultStep::DirSync`] fault is armed.
pub(crate) fn parent_fsync(parent: &Path) -> io::Result<()> {
    PARENT_FSYNCS.with(|c| c.borrow_mut().push(parent.to_path_buf()));
    FAULT_INJECT.with(|c| {
        let mut slot = c.borrow_mut();
        match *slot {
            Some((FaultStep::DirSync, errno)) => {
                *slot = None;
                Err(io::Error::from_raw_os_error(errno))
            }
            None => Ok(()),
        }
    })
}

/// Every directory fsynced, in order, for the ancestor-walk and segment-creation assertions.
pub(crate) fn parents_fsynced() -> Vec<PathBuf> {
    PARENT_FSYNCS.with(|c| c.borrow().clone())
}
