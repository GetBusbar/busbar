// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST-SIDE VERIFY CACHE (`BUSBAR-1.6.0.md` THE DESIGN, §11.12 verify row: "the host-side
//! verify cache with single-flight leadership: hit, lead (the plane fetches and stores) or
//! follow"). The kernel owns the cache and the single-flight coordination; the plane does the
//! fetch, through its own declared need, and stores what it fetched.
//!
//! * **Per instance.** Every entry, lead and follower is keyed by the calling instance's LABEL and
//!   the plane's own key: two instances never read, lead or answer each other's entries.
//! * **Hit, lead or follow.** A fresh entry is a hit. Otherwise the first caller LEADS; while a
//!   lead stands, every other caller FOLLOWS: its answer pends until the leader stores, and is the
//!   leader's entry.
//! * **A lead never wedges its followers.** A lead lasts [`LEAD_MS`]. Past it, the next lookup takes
//!   the lead over, and the kernel's tick ([`VerifyBook::expire`]) hands it to the first waiting
//!   follower, answered as a LEAD; the others keep following.
//! * **Bounded.** An entry is at most [`MAX_ENTRY`] bytes; an instance holds at most [`MAX_KEYS`]
//!   keys (expired, idle ones are struck first, then the idle one expiring soonest); a key holds at
//!   most [`MAX_FOLLOWERS`] followers. Past a bound the call is REFUSED, never queued.
//!
//! Nothing here acts on what an entry says: the plane reads its own entry (Law 11).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::abi::host::service::{ItemSpan, VERIFY_FOLLOW, VERIFY_HIT, VERIFY_LEAD};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::services::{Later, Ran, Stored};

/// How long a lead stands before another caller may take it over, in milliseconds.
pub const LEAD_MS: u64 = 30_000;
/// How long an entry stands when its store names no time to live, in milliseconds.
pub const DEFAULT_TTL_MS: u64 = 60_000;
/// The most bytes one entry holds.
pub const MAX_ENTRY: usize = 64 * 1024;
/// The most keys one instance's cache holds.
pub const MAX_KEYS: usize = 4096;
/// The most callers one key's lead holds waiting.
pub const MAX_FOLLOWERS: usize = 1024;

/// The refusal of an entry longer than [`MAX_ENTRY`].
pub const ENTRY_TOO_LONG: &str = "the verify entry is longer than the host holds";
/// The refusal of a new key in a cache that holds [`MAX_KEYS`] keys, every one in use.
pub const CACHE_FULL: &str = "the verify cache holds as many keys as it may";
/// The refusal of a follower past [`MAX_FOLLOWERS`].
pub const TOO_MANY_FOLLOWERS: &str = "the verify lead holds as many followers as it may";

/// One key of one instance's cache.
#[derive(Default)]
struct Slot {
    /// The stored entry and when it goes stale (wall ms).
    entry: Option<(Arc<[u8]>, u64)>,
    /// When the standing lead lapses (wall ms); `None` = no lead.
    lead_until: Option<u64>,
    /// The callers waiting on the lead, in arrival order.
    followers: Vec<Later>,
}

impl Slot {
    fn fresh(&self, now: u64) -> Option<&Arc<[u8]>> {
        self.entry
            .as_ref()
            .filter(|(_, until)| now < *until)
            .map(|(e, _)| e)
    }

    /// No lead and nobody waiting.
    fn idle(&self) -> bool {
        self.lead_until.is_none() && self.followers.is_empty()
    }
}

/// One instance's keys.
type Keys = HashMap<Vec<u8>, Slot>;

/// THE VERIFY CACHE, every instance's, keyed by instance label then key.
#[derive(Default)]
pub struct VerifyBook {
    inner: Mutex<HashMap<Arc<str>, Keys>>,
}

impl std::fmt::Debug for VerifyBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyBook").finish_non_exhaustive()
    }
}

/// READY `value` with `entry` as span `0`'s value (key absent).
fn with_entry(value: u64, entry: &[u8]) -> Stored {
    let mut s = Stored::ready(value);
    s.bytes = entry.to_vec();
    s.spans.push(ItemSpan {
        key: Span {
            offset: SPAN_ABSENT,
            len: 0,
        },
        value: Span {
            offset: 0,
            len: u32::try_from(entry.len()).unwrap_or(u32::MAX),
        },
    });
    s
}

/// Make room for one more key in `keys` at `now`: strike every idle key with no fresh entry, then,
/// still full, the idle key whose entry goes stale soonest. `false` = every key is in use.
fn room(keys: &mut Keys, now: u64) -> bool {
    if keys.len() < MAX_KEYS {
        return true;
    }
    keys.retain(|_, s| !(s.idle() && s.fresh(now).is_none()));
    if keys.len() < MAX_KEYS {
        return true;
    }
    let soonest = keys
        .iter()
        .filter(|(_, s)| s.idle())
        .min_by_key(|(_, s)| s.entry.as_ref().map_or(0, |(_, until)| *until))
        .map(|(k, _)| k.clone());
    match soonest {
        Some(k) => {
            keys.remove(&k);
            true
        }
        None => false,
    }
}

impl VerifyBook {
    fn lock(&self) -> MutexGuard<'_, HashMap<Arc<str>, Keys>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `verify.lookup` for `instance` at wall time `now`: a hit, a lead, or a follow that `later`
    /// answers when the leader stores (or hands the follower the lead).
    pub fn lookup(&self, instance: &Arc<str>, key: &[u8], now: u64, later: Later) -> Ran {
        let mut book = self.lock();
        let keys = book.entry(Arc::clone(instance)).or_default();
        if !keys.contains_key(key) && !room(keys, now) {
            return Ran::Now(Stored::refused(CACHE_FULL));
        }
        let slot = keys.entry(key.to_vec()).or_default();
        if let Some(entry) = slot.fresh(now) {
            return Ran::Now(with_entry(VERIFY_HIT, entry));
        }
        match slot.lead_until {
            Some(until) if now < until => {
                if slot.followers.len() >= MAX_FOLLOWERS {
                    return Ran::Now(Stored::refused(TOO_MANY_FOLLOWERS));
                }
                slot.followers.push(later);
                Ran::Later
            }
            // No lead, or one that lapsed: this caller leads.
            _ => {
                slot.lead_until = Some(now.saturating_add(LEAD_MS));
                Ran::Now(Stored::ready(VERIFY_LEAD))
            }
        }
    }

    /// `verify.store` for `instance` at wall time `now`: the entry stands for `ttl_ms` (`0` =
    /// [`DEFAULT_TTL_MS`]), any lead on the key ends, and every follower is answered with it.
    pub fn store(
        &self,
        instance: &Arc<str>,
        key: &[u8],
        entry: &[u8],
        ttl_ms: u64,
        now: u64,
    ) -> Stored {
        if entry.len() > MAX_ENTRY {
            return Stored::refused(ENTRY_TOO_LONG);
        }
        let ttl = if ttl_ms == 0 { DEFAULT_TTL_MS } else { ttl_ms };
        let entry: Arc<[u8]> = Arc::from(entry);
        let followers = {
            let mut book = self.lock();
            let keys = book.entry(Arc::clone(instance)).or_default();
            if !keys.contains_key(key) && !room(keys, now) {
                return Stored::refused(CACHE_FULL);
            }
            let slot = keys.entry(key.to_vec()).or_default();
            slot.entry = Some((Arc::clone(&entry), now.saturating_add(ttl)));
            slot.lead_until = None;
            std::mem::take(&mut slot.followers)
        };
        // Answered outside the lock: an answer wakes its caller's ticket.
        for later in followers {
            later(with_entry(VERIFY_FOLLOW, &entry));
        }
        Stored::ready(0)
    }

    /// THE TICK: every lead that lapsed by `now` with callers waiting passes to the first of them,
    /// answered as a LEAD; a lapsed lead with nobody waiting simply ends. Returns how many leads
    /// were handed on.
    pub fn expire(&self, now: u64) -> usize {
        let mut handed = Vec::new();
        {
            let mut book = self.lock();
            for keys in book.values_mut() {
                for slot in keys.values_mut() {
                    let lapsed = slot.lead_until.is_some_and(|until| now >= until);
                    if !lapsed {
                        continue;
                    }
                    if slot.followers.is_empty() {
                        slot.lead_until = None;
                    } else {
                        slot.lead_until = Some(now.saturating_add(LEAD_MS));
                        handed.push(slot.followers.remove(0));
                    }
                }
                keys.retain(|_, s| !(s.idle() && s.entry.as_ref().is_none_or(|(_, u)| now >= *u)));
            }
            book.retain(|_, keys| !keys.is_empty());
        }
        let n = handed.len();
        for later in handed {
            later(Stored::ready(VERIFY_LEAD));
        }
        n
    }

    /// How many keys `instance` holds (a test's window into the bounds).
    #[must_use]
    pub fn keys(&self, instance: &str) -> usize {
        self.lock().get(instance).map_or(0, HashMap::len)
    }
}

#[cfg(test)]
#[path = "tests/host_verify_tests.rs"]
mod tests;
