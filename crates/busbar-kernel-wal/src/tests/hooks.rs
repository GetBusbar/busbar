// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The test side of the production files' `#[cfg(test)]` hook points.
//!
//! `durable.rs` keeps only the calls: `fault_point!` at each fallible step of a publish, the decoy
//! plant before the temp is created, and the parent-fsync hook at the one directory fsync. What
//! those calls consult — the armed fault, the recorded fsyncs, the decoy switch — lives here, per
//! thread, so a test arms exactly the case it means and no other test sees it.

use std::cell::{Cell, RefCell};
use std::io;
use std::path::{Path, PathBuf};

/// The fallible steps of the durable primitive, in order (the fault-injection axis of the class
/// test), and the directory fsync every durable step ends with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FaultStep {
    Create,
    Write,
    Flush,
    Fsync,
    Rename,
    /// The fsync of the directory holding an entry that was created, renamed or removed.
    DirSync,
}

thread_local! {
    /// `(step, raw_os_errno)` — the next matching step on this thread returns that errno once.
    static FAULT_INJECT: RefCell<Option<(FaultStep, i32)>> = const { RefCell::new(None) };
    /// Every parent path the primitive fsync'd on this thread, in order. A Vec, not a single slot,
    /// because `create_dir_all` fsyncs one parent per directory it creates and the ancestor walk is
    /// the thing under test.
    static PARENT_FSYNCS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    /// One-shot: plant a decoy file at the NEXT write's exact temp path on this thread.
    static PLANT_DECOY: Cell<bool> = const { Cell::new(false) };
}

/// Arm a one-shot fault: the next matching step returns `io::Error::from_raw_os_error(errno)`.
pub(crate) fn fault_arm(step: FaultStep, errno: i32) {
    FAULT_INJECT.with(|c| *c.borrow_mut() = Some((step, errno)));
}

/// Clear any armed fault and every recorded parent fsync (call at the start of each case).
pub(crate) fn fault_reset() {
    FAULT_INJECT.with(|c| *c.borrow_mut() = None);
    PARENT_FSYNCS.with(|c| c.borrow_mut().clear());
}

/// If a fault is armed for `step`, consume it and return the injected error.
pub(crate) fn fault_take_if(step: FaultStep) -> Option<io::Error> {
    FAULT_INJECT.with(|c| {
        let mut slot = c.borrow_mut();
        match *slot {
            Some((s, errno)) if s == step => {
                *slot = None;
                Some(io::Error::from_raw_os_error(errno))
            }
            _ => None,
        }
    })
}

/// The parent-fsync hook: record `parent` as fsynced on this thread, then fail if a
/// [`FaultStep::DirSync`] fault is armed.
pub(crate) fn parent_fsync(parent: &Path) -> io::Result<()> {
    PARENT_FSYNCS.with(|c| c.borrow_mut().push(parent.to_path_buf()));
    match fault_take_if(FaultStep::DirSync) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// The LAST parent fsync'd, for the single-publish assertions.
pub(crate) fn parent_fsynced() -> Option<PathBuf> {
    PARENT_FSYNCS.with(|c| c.borrow().last().cloned())
}

/// Every parent fsync'd, in order, for the ancestor-walk and segment-creation assertions.
pub(crate) fn parents_fsynced() -> Vec<PathBuf> {
    PARENT_FSYNCS.with(|c| c.borrow().clone())
}

/// Arm a one-shot decoy: the next write on this thread finds a file ALREADY SITTING at the exact
/// temp path it is about to create. That is the crashed-previous-run state the `exclusive` posture's
/// pre-removal exists for, and the only way to reach it deterministically -- the temp name embeds a
/// pid and an atomic counter, so a test cannot name it from outside.
pub(crate) fn plant_decoy_arm() {
    PLANT_DECOY.with(|c| c.set(true));
}

/// The decoy hook: plant the decoy at `tmp` if one is armed.
pub(crate) fn plant_decoy_if_armed(tmp: &Path) {
    if PLANT_DECOY.with(|c| c.replace(false)) {
        let _ = std::fs::write(tmp, b"leftover from a crashed run");
    }
}
