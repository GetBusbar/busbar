// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host entry guard's thread state (IF §10.7, I10; W1-H0).
//!
//! Round 24: `OWNER` is a host-side `const`-initialised `thread_local!` `Cell<u32>` (`u32::MAX` = none): the
//! slot of the entry running on this thread, saved and set by every guard and restored at its exit and on
//! unwind, whatever the watch claim state. `Host::log` attributes every line by it (§10.7 `set_log_sink`), and
//! `watch::current_slot()` reads it, so a line from a live entry is attributed and scrubbed even on an
//! unwatched thread. Outside an entry it is none and the sink drops the line.
//!
//! `guard` itself (with `EntryOwner`, `DEPTH`, ACTIVE, the watch word and the outermost-exit arena reset) wraps
//! the pool's raw out buffer, the watch words and `Instance` (W1-H1, which the WBS orders after this task) and
//! lands with them. Rounds 7-9's `cold`, `cold_detached`, `cold_step`, `ColdStep`/`ColdPhase`/`ImageTail`,
//! `OwnedEntryOwner` and `set_cold_hop` stay deleted (§16.92): every entry is inline under the guard.

use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

std::thread_local! {
    static OWNER: Cell<u32> = const { Cell::new(u32::MAX) };
    static PURE: Cell<bool> = const { Cell::new(false) };
    static PURE_VIOLATION: Cell<bool> = const { Cell::new(false) };
    static MIGRATION: RefCell<Option<Arc<StoreMigrationAdmission>>> = const { RefCell::new(None) };
}

pub(crate) fn pure() -> bool {
    PURE.with(Cell::get)
}

/// Pure selection has no Host service authority. Buffer growth is only output allocation.
/// This is entry-local enforcement, not a sandbox against a malicious native plugin.
pub(crate) struct Pure {
    active: bool,
    violation: bool,
}

impl Pure {
    pub(crate) fn enter() -> Self {
        Self {
            active: PURE.with(|p| p.replace(true)),
            violation: PURE_VIOLATION.with(|v| v.replace(false)),
        }
    }
}

/// Nonsecret authority for one Store-open operation. Never retained by a serving instance.
pub struct StoreMigrationAdmission {
    recoverable_allowed: bool,
    first_refused: AtomicU64,
}

impl StoreMigrationAdmission {
    /// Root derives this verdict from its already resolved and parsed at-rest key.
    pub fn new(recoverable_allowed: bool) -> Self {
        Self {
            recoverable_allowed,
            first_refused: AtomicU64::new(0),
        }
    }

    /// The first refused positive count; zero is solely the unset sentinel.
    pub fn first_refused(&self) -> Option<u64> {
        match self.first_refused.load(Ordering::Acquire) {
            0 => None,
            count => Some(count),
        }
    }
}

impl Pure {
    pub(crate) fn violated(&self) -> bool {
        PURE_VIOLATION.with(Cell::get)
    }
}

/// Mark an attempted host service so a selector cannot succeed after ignoring the denial.
pub(crate) fn deny_service() -> bool {
    if pure() {
        PURE_VIOLATION.with(|v| v.set(true));
        true
    } else {
        false
    }
}

impl Drop for Pure {
    fn drop(&mut self) {
        PURE.with(|p| p.set(self.active));
        PURE_VIOLATION.with(|v| v.set(self.violation || (self.active && v.get())));
    }
}

/// A synchronous denial scope, restored on return and unwind. It cannot move between threads.
#[must_use]
pub struct MigrationScope {
    previous: Option<Arc<StoreMigrationAdmission>>,
    _thread: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl MigrationScope {
    pub fn deny() -> Self {
        Self::set(None)
    }

    pub(crate) fn set(admission: Option<Arc<StoreMigrationAdmission>>) -> Self {
        Self {
            previous: MIGRATION.with(|scope| scope.replace(admission)),
            _thread: core::marker::PhantomData,
        }
    }
}

impl Drop for MigrationScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = MIGRATION.try_with(|scope| scope.replace(previous));
    }
}

pub(crate) fn migration_admitted(count: u64) -> bool {
    if busbar_ffi::host::teardown_active() || owner().is_none() {
        return false;
    }
    MIGRATION
        .try_with(|scope| {
            let scope = scope.borrow();
            let Some(admission) = scope.as_ref() else {
                return false;
            };
            if count == 0 || admission.recoverable_allowed {
                return true;
            }
            let _ = admission.first_refused.compare_exchange(
                0,
                count,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            false
        })
        .unwrap_or(false)
}

/// The slot of the entry running on this thread, or None outside an entry.
pub(crate) fn owner() -> Option<u32> {
    match OWNER.with(Cell::get) {
        u32::MAX => None,
        slot => Some(slot),
    }
}

/// Runs `f` as if an entry of `slot` were running on this thread (the guard itself is W1-H1's); restores on exit.
#[cfg(test)]
pub(crate) fn within<R>(slot: u32, f: impl FnOnce() -> R) -> R {
    let saved = OWNER.with(|owner| owner.replace(slot));
    let answer = f();
    OWNER.with(|owner| owner.set(saved));
    answer
}

/// Restores the thread's `OWNER` when an entry returns or unwinds.
pub(crate) struct Owning(u32);

impl Owning {
    /// Marks `slot` as the entry running on this thread until the returned value drops.
    pub(crate) fn set(slot: u32) -> Owning {
        Owning(OWNER.with(|owner| owner.replace(slot)))
    }
}

impl Drop for Owning {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(self.0));
    }
}

/// The host entry guard (IF §10.7, I10): runs `call` inline on this thread as the entry `entry` of `slot`, with
/// `out` lent to the plugin for it, inside the watchdog word of the slot and with `OWNER` set so every log line
/// is attributed and scrubbed. Every driver step takes this path; the loader's cold entries (describe) call it
/// directly. None: busbar-ffi's ACTIVE stack is full, a host fault (no sink, no quarantine).
pub fn guard<R>(
    slot: u32,
    entry: u8,
    out: &mut crate::host_side::pool::PooledOut,
    call: impl FnOnce(&mut busbar_ffi::host::OutLease) -> R,
) -> Option<R> {
    crate::host_side::driver::step(slot, entry, None, out, call)
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use crate::host::HostExt;
    use crate::host_side::host_vt::HOST;
    use std::sync::Arc;

    #[test]
    fn migration_scope_restores_after_nested_denial_and_unwind() {
        let permit = Arc::new(StoreMigrationAdmission::new(true));
        assert!(HOST.migrate_admit(0).is_err());
        let _owner = Owning::set(7);
        let _scope = MigrationScope::set(Some(Arc::clone(&permit)));
        assert!(HOST.migrate_admit(9).is_ok());
        let result = std::panic::catch_unwind(|| {
            let _denied = MigrationScope::set(None);
            assert!(HOST.migrate_admit(0).is_err());
            assert!(HOST.migrate_admit(9).is_err());
            panic!("nested host unwind");
        });
        assert!(result.is_err());
        assert!(HOST.migrate_admit(9).is_ok());
        assert_eq!(permit.first_refused(), None);
    }

    #[test]
    fn first_positive_refusal_is_sticky_and_zero_does_not_clear_it() {
        let permit = Arc::new(StoreMigrationAdmission::new(false));
        let _owner = Owning::set(7);
        let _scope = MigrationScope::set(Some(Arc::clone(&permit)));
        assert!(HOST.migrate_admit(0).is_ok());
        assert!(HOST.migrate_admit(u64::MAX).is_err());
        assert!(HOST.migrate_admit(1).is_err());
        assert!(HOST.migrate_admit(0).is_ok());
        assert_eq!(permit.first_refused(), Some(u64::MAX));
    }

    #[test]
    fn pure_selection_cannot_inherit_store_open_migration_authority() {
        let permit = Arc::new(StoreMigrationAdmission::new(true));
        let _owner = Owning::set(7);
        let _scope = MigrationScope::set(Some(permit));
        {
            let pure = Pure::enter();
            assert!(HOST.migrate_admit(0).is_err());
            assert!(HOST.migrate_admit(9).is_err());
            assert!(pure.violated());
        }
        assert!(HOST.migrate_admit(9).is_ok());
    }
}

#[cfg(test)]
mod pure_tests {
    use super::*;

    #[test]
    fn pure_selection_suppresses_host_services_and_restores_after_unwind() {
        assert!(!pure());
        let result = std::panic::catch_unwind(|| {
            let _outer = Pure::enter();
            assert!(pure());
            {
                let _inner = Pure::enter();
                assert_eq!(crate::host_side::host_vt::vt::now(), 0);
                assert_eq!(crate::host_side::host_vt::vt::mono(), 0);
                assert_eq!(crate::host_side::host_vt::vt::log_level(), 0);
                assert!(_inner.violated());
            }
            assert!(pure());
            assert!(_outer.violated());
            panic!("selector unwind");
        });
        assert!(result.is_err());
        assert!(!pure());
    }
}
