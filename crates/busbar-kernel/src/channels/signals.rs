// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The in-process DETACH-key registry behind SIGNAL and DX_BROADCAST (IF §12.19 round 18, §8.6
//! SignalRec, §16.159). One per gateway process; never replicated through the store.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_plugin_abi::plane::MAX_FANOUT;
use tokio::sync::mpsc;

use super::SessionSignals;

/// What a session's task receives: delivered by it as piece(FROM_CORE, 0, flags, bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signalled {
    pub flags: u32,
    pub bytes: Box<[u8]>,
}

struct Member {
    session: u64,
    subject: Option<[u8; 32]>,
    tx: mpsc::Sender<Signalled>,
}

type Key = (u64, Box<[u8]>);

#[derive(Default)]
struct Table {
    by_key: HashMap<Key, Vec<Member>>,
    next: u64,
}

/// The registry. Sessions register under the key their DETACH named; the guard unregisters on drop.
#[derive(Default)]
pub struct SignalRegistry {
    table: Mutex<Table>,
    dropped: AtomicU64,
}

/// Held by the session's task; dropping it removes the session from the registry.
pub struct Registered {
    registry: Arc<SignalRegistry>,
    key: Key,
    session: u64,
}

impl SignalRegistry {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a live session of plane instance `instance` under DETACH key `key`. `subject` = the
    /// session's subject hash (CH_PER_CALLER signals reach only its own sessions).
    pub fn register(
        self: &Arc<Self>,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        tx: mpsc::Sender<Signalled>,
    ) -> Registered {
        let _ = (instance, key, subject, tx, &self.table);
        todo!()
    }

    /// `plane_signal_dropped_total`: deliveries a full session channel refused.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Live sessions under (instance, key).
    #[must_use]
    pub fn live(&self, instance: u64, key: &[u8]) -> usize {
        let _ = (instance, key);
        todo!()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let _ = (
            &self.registry,
            &self.key,
            self.session,
            SignalRegistry::lock,
        );
    }
}

impl SessionSignals for SignalRegistry {
    fn signal(
        &self,
        instance: u64,
        key: &[u8],
        subject: Option<[u8; 32]>,
        flags: u32,
        bytes: &[u8],
    ) -> u32 {
        let _ = (instance, key, subject, flags, bytes, MAX_FANOUT);
        todo!()
    }
}

#[doc(hidden)]
#[allow(dead_code)]
fn _member_fields(m: &Member) -> (u64, Option<[u8; 32]>, &mpsc::Sender<Signalled>) {
    (m.session, m.subject, &m.tx)
}
