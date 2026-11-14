// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COUNT PROBES FOR THE SINGLE-PATH STAGES (SINGLE-PATH §8).
//!
//! Every governed stage derives its inputs once and carries the result forward. A site that
//! derives one of those inputs calls [`tick`] with its [`Derive`] id; a test opens a [`Scope`] on
//! its thread, drives one request through the host, and reads how often each input was derived.
//!
//! The counting lives behind the dev-only `stage-probe` feature, which only `[dev-dependencies]`
//! edges may name (`tests/test_seal_is_dev_only.rs`). Without the feature [`tick`] is an empty
//! inline function and no counter, thread-local or scope type exists in the build.

/// One derivation a single-path stage owns. Each is counted where it is computed, never where a
/// carried answer is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Derive {
    /// A plane admission resolved on the unit's original head.
    PlaneAdmission,
    /// A plane admission resolved on a continuation call's own (stripped) head.
    AdmissionOnHead,
    /// A `HeaderMap` built from the unit's original head.
    HeaderMap,
    /// The served (stripped) head converted back to HTTP for the operator adapter.
    ServedHeaderMap,
    /// The caller credential read out of the original head's carriers.
    CredentialExtract,
    /// The token-exchange endpoint's own credential read; no inbound unit exists there.
    ExchangeToken,
    /// A presented unit reference's MAC checked by the kernel (SP-AU5).
    UnitMac,
    /// The kernel's inbound units table locked (SP-AU5). A lock, not a derivation, counted
    /// here so one scope reads both.
    UnitsLock,
}

impl Derive {
    /// Every id, in counter order.
    pub const ALL: [Derive; 8] = [
        Derive::PlaneAdmission,
        Derive::AdmissionOnHead,
        Derive::HeaderMap,
        Derive::ServedHeaderMap,
        Derive::CredentialExtract,
        Derive::ExchangeToken,
        Derive::UnitMac,
        Derive::UnitsLock,
    ];

    #[cfg(feature = "stage-probe")]
    const fn slot(self) -> usize {
        match self {
            Derive::PlaneAdmission => 0,
            Derive::AdmissionOnHead => 1,
            Derive::HeaderMap => 2,
            Derive::ServedHeaderMap => 3,
            Derive::CredentialExtract => 4,
            Derive::ExchangeToken => 5,
            Derive::UnitMac => 6,
            Derive::UnitsLock => 7,
        }
    }
}

/// Count one derivation in the current thread's [`Scope`], if one is open. Without the
/// `stage-probe` feature this compiles to nothing.
#[inline(always)]
pub fn tick(derive: Derive) {
    #[cfg(feature = "stage-probe")]
    counting::tick(derive);
    #[cfg(not(feature = "stage-probe"))]
    let _ = derive;
}

#[cfg(feature = "stage-probe")]
pub use counting::{Entered, Scope};

#[cfg(feature = "stage-probe")]
mod counting {
    use super::Derive;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    type Row = [AtomicU32; Derive::ALL.len()];

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Row>>> = const { RefCell::new(None) };
    }

    pub(super) fn tick(derive: Derive) {
        CURRENT.with(|current| {
            if let Some(row) = current.borrow().as_ref() {
                row[derive.slot()].fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// One request's counters. Opening a scope makes it current on this thread until it drops;
    /// work that leaves the thread carries it with [`Scope::enter`].
    #[derive(Debug)]
    pub struct Scope {
        row: Arc<Row>,
        previous: Option<Arc<Row>>,
    }

    impl Scope {
        /// Open a fresh, zeroed scope and make it current on this thread.
        #[must_use]
        pub fn open() -> Self {
            let row: Arc<Row> = Arc::new(std::array::from_fn(|_| AtomicU32::new(0)));
            let previous = CURRENT.with(|current| current.replace(Some(Arc::clone(&row))));
            Self { row, previous }
        }

        /// How often `derive` was counted in this scope so far.
        #[must_use]
        pub fn count(&self, derive: Derive) -> u32 {
            self.row[derive.slot()].load(Ordering::Relaxed)
        }

        /// Make this scope current on another thread (or inside a future polled elsewhere)
        /// until the returned guard drops.
        #[must_use]
        pub fn enter(&self) -> Entered {
            let previous = CURRENT.with(|current| current.replace(Some(Arc::clone(&self.row))));
            Entered { previous }
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            let previous = self.previous.take();
            CURRENT.with(|current| *current.borrow_mut() = previous);
        }
    }

    /// A scope carried onto another thread; restores that thread's previous scope on drop.
    #[derive(Debug)]
    pub struct Entered {
        previous: Option<Arc<Row>>,
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            let previous = self.previous.take();
            CURRENT.with(|current| *current.borrow_mut() = previous);
        }
    }
}

#[cfg(all(test, feature = "stage-probe"))]
mod tests {
    use super::{tick, Derive, Scope};

    #[test]
    fn a_scope_counts_only_its_own_thread_and_restores_the_previous_scope() {
        let outer = Scope::open();
        tick(Derive::HeaderMap);
        {
            let inner = Scope::open();
            tick(Derive::HeaderMap);
            tick(Derive::HeaderMap);
            assert_eq!(inner.count(Derive::HeaderMap), 2);
        }
        tick(Derive::HeaderMap);
        assert_eq!(outer.count(Derive::HeaderMap), 2);
        assert_eq!(outer.count(Derive::PlaneAdmission), 0);
        std::thread::scope(|s| {
            s.spawn(|| tick(Derive::HeaderMap));
        });
        assert_eq!(
            outer.count(Derive::HeaderMap),
            2,
            "another thread is not this scope"
        );
        std::thread::scope(|s| {
            s.spawn(|| {
                let _carried = outer.enter();
                tick(Derive::PlaneAdmission);
            });
        });
        assert_eq!(
            outer.count(Derive::PlaneAdmission),
            1,
            "a carried scope counts"
        );
    }
}
