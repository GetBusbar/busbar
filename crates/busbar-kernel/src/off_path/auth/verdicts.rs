// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`crate::auth::verdicts`]'s sweeps: an instance's flush (rule 6, on the instance's flush event) and
//! the watchdog tick's expiry (rule 4). Neither runs per request; the request path only looks a key
//! up and leads or follows it.

use std::sync::atomic::Ordering;
use std::sync::PoisonError;

use crate::auth::verdicts::{hand, Verdicts, LEAD_S};

impl<V: Clone + Send + Sync + 'static, O: Clone + Send + Sync + 'static> Verdicts<V, O> {
    /// Rule 6: drop every entry of the instance and move its epoch, so no lead begun before fills; standing
    /// leads and their followers stay.
    pub fn flush(&self, auth_instance: u64) {
        let mut book = self.write(auth_instance);
        if let Some(keys) = book.get_mut(&auth_instance) {
            keys.epoch.fetch_add(1, Ordering::Relaxed);
            keys.keys.retain(|_, slot| !slot.idle());
            for slot in keys.keys.values_mut() {
                slot.entry = None;
            }
        }
    }

    /// The watchdog tick (rule 4, VerifyBook's `expire`): a lapsed lead passes to its first live follower, or
    /// ends; idle stale keys and empty instances go. Returns how many leads were handed on.
    pub fn expire(&self, now_s: u64) -> usize {
        let mut handed = 0;
        for shard in &self.shards {
            let mut book = shard.write().unwrap_or_else(PoisonError::into_inner);
            for keys in book.values_mut() {
                for slot in keys.keys.values_mut() {
                    if !slot.lead_until.is_some_and(|until| now_s >= until) {
                        continue;
                    }
                    if hand(slot) {
                        slot.lead_until = Some(now_s.saturating_add(LEAD_S));
                        handed += 1;
                    }
                }
                keys.keys
                    .retain(|_, slot| !(slot.idle() && slot.fresh(now_s).is_none()));
            }
            book.retain(|_, keys| !keys.keys.is_empty());
        }
        handed
    }
}
