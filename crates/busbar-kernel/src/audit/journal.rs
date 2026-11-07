// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::audit::{Chain, ChainBreak, ChainedRecord};
use indexmap::IndexMap;
use std::sync::{Mutex, MutexGuard};

/// Cache of verified chain positions. Persistence and conditional publication
/// remain with the native host owners.
pub(crate) struct Journal<R> {
    positions: Mutex<IndexMap<String, Chain<R>>>,
    cap: usize,
}
impl<R: ChainedRecord> Journal<R> {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            positions: Mutex::new(IndexMap::new()),
            cap,
        }
    }
    fn positions(&self) -> MutexGuard<'_, IndexMap<String, Chain<R>>> {
        self.positions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    fn commit(&self, scope: &str, chain: Chain<R>) {
        let mut positions = self.positions();
        match positions.get_index_of(scope) {
            Some(index) => {
                if let Some((_, slot)) = positions.get_index_mut(index) {
                    *slot = chain;
                }
                let last = positions.len() - 1;
                positions.move_index(index, last);
            }
            None => {
                positions.insert(scope.to_string(), chain);
            }
        }
        while positions.len() > self.cap {
            positions.shift_remove_index(0);
        }
    }
    pub(crate) fn seed_position(&self, scope: &str, records: &[R]) -> Option<ChainBreak> {
        let (chain, broken) = match Chain::from_persisted(records) {
            Ok(chain) => (chain, None),
            Err(broken) => (Chain::from_persisted_unverified(records), Some(broken)),
        };
        self.commit(scope, chain);
        broken
    }
    #[cfg(test)]
    pub(crate) fn forget(&self, scope: &str) {
        self.positions().shift_remove(scope);
    }
    #[cfg(test)]
    pub(crate) fn next_seq(&self, scope: &str) -> u64 {
        self.positions()
            .get(scope)
            .map(Chain::next_seq)
            .unwrap_or(1)
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.positions().len()
    }
}

/// The NEUTRAL durable body the store-backed journal persists per record — `{seq, prev_hash, hash,
/// content}`, naming no plane type. The journal persists THIS, and a stream's reframe callback is
/// the decode bridge that turns this shape back into a record on restore.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NeutralBody {
    /// The chain sequence the host minted for this record.
    pub seq: u64,
    /// The link to the previous record (empty at genesis).
    pub prev_hash: String,
    /// This record's sealed digest.
    pub hash: String,
    /// The plane's OPAQUE pre-framed content suffix (the bytes the digest appends RAW).
    pub content: Vec<u8>,
}

#[cfg(test)]
#[path = "tests/journal_lock_tests.rs"]
mod journal_lock_tests;
#[cfg(test)]
#[path = "tests/journal_tests.rs"]
mod journal_tests;
