// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.23: the line carriers. One carrier is the process's own stdin/stdout, served by `serve_lines`; it holds
//! one id (non-zero, unique for the process life), the owning plane instance's incarnation, the principal the
//! carrier serves under, and the one writer every line goes through. `PlaneOut::Emit { carrier, bytes }` from the
//! owning instance is [`LineCarriers::emit`]: a carrier that has ended, or one another instance owns, drops it
//! and counts `plane_emit_dropped_total` (the plane learns nothing about other instances, I2).

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::services::Incarnation;

/// The carrier's one writer: takes a line without its terminator, returns `false` once the writer is gone.
pub type CarrierSink = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

struct Carrier {
    owner: Incarnation,
    principal: Arc<str>,
    sink: CarrierSink,
}

/// The open carriers of one core. Ids come from one process-wide counter, so two registries never mint the same id.
#[derive(Default)]
pub struct LineCarriers {
    open: Mutex<HashMap<u64, Carrier>>,
    dropped: AtomicU64,
}

impl LineCarriers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a carrier owned by `owner`, serving as `principal`, writing through `sink`.
    pub fn open(&self, owner: &Incarnation, principal: Arc<str>, sink: CarrierSink) -> NonZeroU64 {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NonZeroU64::new(NEXT.fetch_add(1, Ordering::Relaxed))
            .expect("a process does not mint 2^64 carrier ids");
        self.lock().insert(
            id.get(),
            Carrier {
                owner: owner.clone(),
                principal,
                sink,
            },
        );
        id
    }

    /// Writes `bytes` as one line on carrier `id`, if `owner` owns it and it is open. Returns the carrier's
    /// principal on success. A refused write (the writer is gone) ends the carrier. Counts nothing: the plane
    /// path is [`LineCarriers::emit_from_plane`].
    pub fn emit(&self, owner: &Incarnation, id: u64, bytes: &[u8]) -> Option<Arc<str>> {
        let (sink, principal) = self
            .lock()
            .get(&id)
            .filter(|c| &c.owner == owner)
            .map(|c| (Arc::clone(&c.sink), Arc::clone(&c.principal)))?;
        if sink(bytes) {
            Some(principal)
        } else {
            self.end(id);
            None
        }
    }

    /// `PlaneOut::Emit`: [`LineCarriers::emit`], counting a drop in `plane_emit_dropped_total`.
    pub fn emit_from_plane(&self, owner: &Incarnation, id: u64, bytes: &[u8]) -> bool {
        let written = self.emit(owner, id, bytes).is_some();
        if !written {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        written
    }

    /// Ends carrier `id`; true if it was open.
    pub fn end(&self, id: u64) -> bool {
        self.lock().remove(&id).is_some()
    }

    /// Whether `owner` has carrier `id` open.
    #[must_use]
    pub fn is_open(&self, owner: &Incarnation, id: u64) -> bool {
        self.lock().get(&id).is_some_and(|c| &c.owner == owner)
    }

    /// `plane_emit_dropped_total`.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Carrier>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
