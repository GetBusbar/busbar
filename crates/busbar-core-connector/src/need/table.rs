// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONN TABLE (IF 13, rounds 15-16): conns keyed `(instance, chain, conn id)`.
//!
//! Every conn handler looks a conn up under the caller's own `(instance, chain)`, so a conn id of
//! another chain or another instance is a miss (`NeedErr::Invalid`), and a Need with `chain == 0`
//! is `Invalid` (C-CONN-SCOPE). `release` removes every conn of one chain and nothing else, so the
//! table never keeps a row of an ended chain. A conn in use is taken out of the table and put back,
//! so no lock is held across I/O.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use busbar_plugin_abi::host_side::needs::{ConnId, NeedErr};

use super::key::NeedKey;

/// A conn a chain holds: the conn, the key it re-pools under, and its pooled-conn id.
#[derive(Debug)]
pub struct Held<V> {
    /// The conn.
    pub conn: V,
    /// The key it was dialled under (re-keyed to `Tls::Upgraded` by STARTTLS).
    pub key: NeedKey,
    /// The pooled-conn id, kept through STARTTLS and every reuse.
    pub pooled: u64,
    /// The negotiated ALPN (empty when none).
    pub alpn: Box<str>,
    /// The OPEN asked for TLS_INBAND and STARTTLS has not completed.
    pub inband_pending: bool,
}

#[derive(Debug)]
struct Row<V> {
    id: u64,
    held: Held<V>,
}

/// The rows of each (instance, conn) chain.
type Chains<V> = HashMap<(u64, u64), Vec<Row<V>>>;

/// The table.
#[derive(Debug)]
pub struct ConnTable<V> {
    chains: Mutex<Chains<V>>,
    next: AtomicU64,
    max_per_chain: usize,
}

impl<V> ConnTable<V> {
    /// A table allowing `max_per_chain` conns per chain (`NeedLimits::max_conns_per_chain`).
    #[must_use]
    pub fn new(max_per_chain: usize) -> Self {
        ConnTable {
            chains: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            max_per_chain,
        }
    }

    /// Register `held` for `(instance, chain)` and return its conn id.
    ///
    /// # Errors
    /// `Invalid` for `chain == 0` (the conn comes back so the caller can close it), `Limit` over
    /// the per-chain cap.
    pub fn insert(&self, instance: u64, chain: u64, held: Held<V>) -> Result<ConnId, (NeedErr, V)> {
        if chain == 0 {
            return Err((NeedErr::Invalid, held.conn));
        }
        let mut chains = self.chains.lock().unwrap_or_else(PoisonError::into_inner);
        let rows = chains.entry((instance, chain)).or_default();
        if rows.len() >= self.max_per_chain {
            return Err((NeedErr::Limit, held.conn));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        rows.push(Row { id, held });
        Ok(ConnId(id))
    }

    /// Take the conn out for one operation. A miss (unknown id, another chain's or another
    /// instance's id, `chain == 0`) is `Invalid`.
    ///
    /// # Errors
    /// `NeedErr::Invalid`.
    pub fn take(&self, instance: u64, chain: u64, id: ConnId) -> Result<Held<V>, NeedErr> {
        if chain == 0 {
            return Err(NeedErr::Invalid);
        }
        let mut chains = self.chains.lock().unwrap_or_else(PoisonError::into_inner);
        let rows = chains.get_mut(&(instance, chain)).ok_or(NeedErr::Invalid)?;
        let at = rows
            .iter()
            .position(|r| r.id == id.0)
            .ok_or(NeedErr::Invalid)?;
        let row = rows.swap_remove(at);
        if rows.is_empty() {
            chains.remove(&(instance, chain));
        }
        Ok(row.held)
    }

    /// Put a taken conn back under its id. It returns the conn when the chain was released while
    /// it was out (the chain ended), for the caller to close.
    ///
    /// # Errors
    /// The conn, when the cap would be passed (cannot happen for a taken conn) or `chain == 0`.
    pub fn restore(&self, instance: u64, chain: u64, id: ConnId, held: Held<V>) -> Result<(), V> {
        if chain == 0 {
            return Err(held.conn);
        }
        let mut chains = self.chains.lock().unwrap_or_else(PoisonError::into_inner);
        chains
            .entry((instance, chain))
            .or_default()
            .push(Row { id: id.0, held });
        Ok(())
    }

    /// The chain ended: every conn it still held, for the caller to close non-reusably. A chain
    /// with no rows costs one map probe.
    pub fn release(&self, instance: u64, chain: u64) -> Vec<Held<V>> {
        self.chains
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(instance, chain))
            .map(|rows| rows.into_iter().map(|r| r.held).collect())
            .unwrap_or_default()
    }

    /// Chains with at least one conn (a row of an ended chain is a leak: C-CONN-SCOPE (g)).
    pub fn chains(&self) -> usize {
        self.chains
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The pooled-conn id counters (round 19): one per instance, starting at 1, minted once per dial
/// and dropped with the instance's pool entries at unbind. An id says nothing about any other
/// instance's dials.
#[derive(Debug, Default)]
pub struct PooledIds {
    next: Mutex<HashMap<u64, u64>>,
}

impl PooledIds {
    /// The next id of `instance`: 1, 2, 3, ... never repeated, never 0.
    pub fn mint(&self, instance: u64) -> u64 {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let n = next.entry(instance).or_insert(0);
        *n += 1;
        *n
    }

    /// The instance is unbound: drop its counter.
    pub fn forget(&self, instance: u64) {
        self.next
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&instance);
    }
}

#[cfg(test)]
#[path = "../tests/need_table_tests.rs"]
mod tests;
