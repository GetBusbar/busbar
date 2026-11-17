// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`crate::auth::verdicts`]'s sweeps: an instance's flush (rule 6, on the instance's flush event) and
//! the watchdog tick's expiry (rule 4). Neither runs per request; the request path only looks a key
//! up and leads or follows it.

use std::sync::atomic::Ordering;
use std::sync::PoisonError;

use crate::auth::verdicts::{hand, Verdicts, LEAD_S};

impl<V: Clone + Send + Sync + 'static, O: Clone + Send + Sync + 'static> Verdicts<V, O> {
    /// Rule 6: drop every cached identity of the instance and move its epoch, so no lead begun before fills;
    /// standing leads and their followers stay (they live in the lead table). The instance's record is made if
    /// it has none, so a lead that read its epoch before the record existed is still discarded.
    pub fn flush(&self, auth_instance: u64) {
        let mut book = self.write(auth_instance);
        let keys = book.entry(auth_instance).or_default();
        keys.epoch.fetch_add(1, Ordering::Relaxed);
        keys.ring.clear();
        keys.index.clear();
        keys.hand = 0;
    }

    /// The watchdog tick (rule 4, VerifyBook's `expire`): a lapsed lead passes to its first live follower, or
    /// ends; stale identities go, and an instance with nothing cached and an unmoved epoch is forgotten (a moved
    /// epoch is kept, so a lead begun before its flush can never see the epoch reset). Returns how many leads
    /// were handed on.
    pub fn expire(&self, now_s: u64) -> usize {
        let mut handed = 0;
        for shard in &self.lead_shards {
            let mut leads = shard.lock().unwrap_or_else(PoisonError::into_inner);
            leads.retain(|_, lead| {
                if now_s < lead.until {
                    return true;
                }
                if hand(lead) {
                    lead.until = now_s.saturating_add(LEAD_S);
                    handed += 1;
                    true
                } else {
                    false
                }
            });
        }
        for shard in &self.shards {
            let mut book = shard.write().unwrap_or_else(PoisonError::into_inner);
            for keys in book.values_mut() {
                let before = keys.ring.len();
                keys.ring.retain(|cached| now_s < cached.until);
                if keys.ring.len() != before {
                    keys.reindex();
                }
            }
            book.retain(|_, keys| !keys.ring.is_empty() || keys.epoch.load(Ordering::Relaxed) != 0);
        }
        handed
    }
}
