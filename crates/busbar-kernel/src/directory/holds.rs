// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CA-5 hold snapshot (IF §12.29 "The hold", frozen consistency model). `held_ns` in the store is the truth;
//! each replica's [`HoldSet`] is a snapshot of it: (a) loaded by a full scan before a generation serves, (b)
//! refreshed by one task per set every `link.refresh_ms` when the store's generation moved, (c) swapped locally by
//! the writing replica before its DIRECTORY Need answers.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::Notify;

use crate::persistence::scoped::ScopedStore;

use super::events::{DirEvent, DirectoryEvents};
use super::store::HELD;
use super::{HoldSet, MAX_HELD};

/// The held principals, hashed with foldhash (the probe is one hash of the principal bytes).
pub(super) type Held = HashSet<Box<str>, foldhash::fast::RandomState>;

/// Consecutive refresh failures before `provisioning_hold_stale` is raised.
const STALE_AFTER: u32 = 3;

pub(super) fn empty() -> Held {
    HashSet::with_hasher(foldhash::fast::RandomState::default())
}

impl HoldSet {
    pub(super) fn new(held: Held, generation: u64) -> Self {
        let len = u32::try_from(held.len()).unwrap_or(u32::MAX);
        Self {
            len: AtomicU32::new(len),
            set: ArcSwap::from_pointee(held),
            wake: Notify::new(),
            generation: AtomicU64::new(generation),
        }
    }

    /// Swap in a new snapshot: the set first, then `len`, so a probe that reads a non-zero `len` always finds
    /// the set it counts.
    pub(super) fn swap(&self, held: Held) {
        let len = u32::try_from(held.len()).unwrap_or(u32::MAX);
        self.set.store(Arc::new(held));
        self.len.store(len, Ordering::Relaxed);
    }

    /// This replica's own write moved `principal` into (`true`) or out of (`false`) `held_ns`: swap locally before
    /// the Need answers, then wake the refresh so the store generation is taken up.
    pub(super) fn local(&self, principal: &str, held: bool) {
        let mut next = Held::clone(&self.set.load());
        let changed = if held {
            next.insert(principal.into())
        } else {
            next.remove(principal)
        };
        if changed {
            self.swap(next);
        }
        self.wake.notify_one();
    }

    pub(super) fn len(&self) -> u32 {
        self.len.load(Ordering::Relaxed)
    }
}

/// The full `held_ns` of one scope and the generation it was read at. Err = store fault, a namespace that kept
/// changing under the scan, or more than MAX_HELD rows.
pub(super) async fn load(scope: &ScopedStore) -> Result<(Held, u64), ()> {
    // A scan whose namespace moves between pages is stale: start again, a bounded number of times.
    for _ in 0..3 {
        match scan(scope).await {
            Ok(Some(found)) => return Ok(found),
            Ok(None) => continue,
            Err(()) => return Err(()),
        }
    }
    Err(())
}

/// Ok(None) = the namespace moved between pages.
async fn scan(scope: &ScopedStore) -> Result<Option<(Held, u64)>, ()> {
    let mut held = empty();
    let mut cursor = None;
    let mut generation = None;
    loop {
        let page = match scope.page(HELD, &[], cursor.as_ref()).await {
            Ok(page) => page,
            Err(_) if cursor.is_some() => return Ok(None),
            Err(_) => return Err(()),
        };
        generation.get_or_insert(page.generation);
        for (key, _) in &page.rows {
            let principal = core::str::from_utf8(key).map_err(|_| ())?;
            held.insert(principal.into());
            if held.len() > MAX_HELD as usize {
                return Err(());
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(Some((held, generation.unwrap_or(0)))),
        }
    }
}

/// The store's current generation of the scope's `held_ns` namespace (one first page).
async fn generation(scope: &ScopedStore) -> Result<u64, ()> {
    scope
        .page(HELD, &[], None)
        .await
        .map(|page| page.generation)
        .map_err(|_| ())
}

pub(super) async fn refresh(
    weak: Weak<HoldSet>,
    scope: ScopedStore,
    every: Duration,
    instance: Box<str>,
    events: Arc<dyn DirectoryEvents>,
) {
    let mut failures = 0u32;
    loop {
        {
            let Some(set) = weak.upgrade() else { return };
            tokio::select! {
                () = tokio::time::sleep(every) => {}
                () = set.wake.notified() => {}
            }
        }
        let Some(set) = weak.upgrade() else { return };
        let fresh = match generation(&scope).await {
            Ok(g) if g == set.generation.load(Ordering::Relaxed) => Ok(()),
            Ok(_) => load(&scope).await.map(|(held, g)| {
                set.swap(held);
                set.generation.store(g, Ordering::Relaxed);
            }),
            Err(()) => Err(()),
        };
        match fresh {
            Ok(()) => failures = 0,
            Err(()) => {
                // The last snapshot keeps serving.
                failures = failures.saturating_add(1);
                metrics::counter!(
                    "provisioning_hold_refresh_failed_total",
                    "instance" => instance.to_string()
                )
                .increment(1);
                if failures == STALE_AFTER {
                    events.event(DirEvent::HoldStale {
                        instance: &instance,
                    });
                }
            }
        }
    }
}
