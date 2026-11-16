// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEED POOL (IF 6.1, 13): conns keyed by value, so a hit is always a conn dialled, judged and
//! verified for this very destination and name.
//!
//! [`NeedKey`] isolates runtime instances, compares `dest`, `sni` and `alpn` by value (never by their hash), carries the judged
//! class, the TLS mode, the SHA-256 of the trust anchor and of the client certificate chain, and the
//! core-only `verify` bit (TRANSPORT-SECURITY-POLICY 3) that keeps a waived conn from serving an
//! instance that did not accept the waiver. The 0x20/0x40 key forms and the plaintext-fallback row
//! of round 24 do not exist: an un-upgraded TLS_INBAND conn is never pooled.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, PoisonError};

/// The TLS state a pooled conn is in, as a key part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tls {
    /// No TLS (an accepted plaintext conn).
    None,
    /// TLS from the first byte.
    Direct,
    /// TLS_INBAND after a completed STARTTLS: the post-upgrade key (an un-upgraded one is never
    /// pooled, so no key names it).
    Upgraded,
}

/// What a pooled conn was dialled, judged and verified for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NeedKey {
    /// The owning runtime instance. Authenticated sessions never cross instance boundaries.
    pub instance: u64,
    /// The normalised destination, `host:port` or `unix:/path`.
    pub dest: Box<str>,
    /// The effective SNI (empty when none).
    pub sni: Box<str>,
    /// The offered ALPN (empty when none).
    pub alpn: Box<str>,
    /// `guard::judged_class(stated, configured)`, never the stated class.
    pub class: u32,
    /// The conn's TLS state.
    pub tls: Tls,
    /// SHA-256 of the bound trust anchor (all zero = none).
    pub trust: [u8; 32],
    /// SHA-256 of the client certificate chain (all zero = none).
    pub cert: [u8; 32],
    /// Set exactly for a conn dialled under `accept: unverified_tls`.
    pub waived: bool,
}

/// One pooled conn and the pooled-conn id minted when it was dialled.
#[derive(Debug)]
pub struct Pooled<V> {
    /// The pooled-conn id (OPEN data1), non-zero, carried through STARTTLS and every reuse.
    pub id: u64,
    /// The conn.
    pub conn: V,
    /// The ALPN negotiated when it was dialled or upgraded (empty when none).
    pub alpn: Box<str>,
}

/// The pool, generic over its hasher (the binary uses [`RandomState`]; a test may pin a constant
/// one to prove a hit never rests on the hash alone).
#[derive(Debug)]
pub struct NeedPool<V, S = RandomState> {
    map: Mutex<HashMap<NeedKey, Vec<Pooled<V>>, S>>,
    per_key: usize,
}

impl<V> NeedPool<V, RandomState> {
    /// A pool holding at most `per_key` idle conns per key.
    #[must_use]
    pub fn new(per_key: usize) -> Self {
        Self::with_hasher(per_key, RandomState::new())
    }
}

impl<V, S: BuildHasher> NeedPool<V, S> {
    /// A pool over `hasher`.
    #[must_use]
    pub fn with_hasher(per_key: usize, hasher: S) -> Self {
        NeedPool {
            map: Mutex::new(HashMap::with_hasher(hasher)),
            per_key,
        }
    }

    /// The most recently pooled conn for exactly `key`, if any.
    pub fn take(&self, key: &NeedKey) -> Option<Pooled<V>> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = map.get_mut(key)?;
        let hit = slot.pop();
        if slot.is_empty() {
            map.remove(key);
        }
        hit
    }

    /// Pool `conn` under `key`. Over the per-key cap the conn comes back for the caller to close.
    ///
    /// # Errors
    /// The conn itself, when the key already holds `per_key` idle conns.
    pub fn put(&self, key: NeedKey, conn: Pooled<V>) -> Result<(), Pooled<V>> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = map.entry(key).or_default();
        if slot.len() >= self.per_key {
            return Err(conn);
        }
        slot.push(conn);
        Ok(())
    }

    /// Idle conns held, over every key.
    pub fn idle(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(Vec::len)
            .sum()
    }
}

#[cfg(test)]
#[path = "../tests/need_key_tests.rs"]
mod tests;
