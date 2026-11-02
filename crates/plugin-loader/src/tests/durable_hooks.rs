// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub(crate) fn fault_arm(step: FaultStep, errno: i32) {
    FAULT_INJECT.with(|c| *c.borrow_mut() = Some((step, errno)));
}

pub(crate) fn fault_reset() {
    FAULT_INJECT.with(|c| *c.borrow_mut() = None);
    PARENT_FSYNCS.with(|c| c.borrow_mut().clear());
}

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

pub(crate) fn parent_fsync(parent: &Path) -> io::Result<()> {
    PARENT_FSYNCS.with(|c| c.borrow_mut().push(parent.to_path_buf()));
    match fault_take_if(FaultStep::DirSync) {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

pub(crate) fn parent_fsynced() -> Option<PathBuf> {
    PARENT_FSYNCS.with(|c| c.borrow().last().cloned())
}

pub(crate) fn parents_fsynced() -> Vec<PathBuf> {
    PARENT_FSYNCS.with(|c| c.borrow().clone())
}

pub(crate) fn plant_decoy_arm() {
    PLANT_DECOY.with(|c| c.set(true));
}

pub(crate) fn plant_decoy_if_armed(tmp: &Path) {
    if PLANT_DECOY.with(|c| c.replace(false)) {
        let _ = std::fs::write(tmp, b"leftover from a crashed run");
    }
}
