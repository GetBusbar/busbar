// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CREDENTIAL CACHE: short-circuit repeat authentications so an
//! external auth module (a directory lookup over a socket) is consulted once per credential per
//! TTL, not once per request. In-process modules are microseconds and gain nothing, but they ride
//! the same seam — the cache is engine machinery, not module policy.
//!
//! Rules (spec-fixed):
//! - Key = `(module_name, SHA-256(credential bytes))` — the credential itself is NEVER stored.
//! - `Identify` cached with the module-suggested TTL (`Principal::ttl_secs`), clamped to a hard
//!   engine cap; absent = the engine default.
//! - `Pass` ("not mine") cached with a short jittered TTL so a prober can't use cache hits as a
//!   recently-probed timing oracle.
//! - `Reject` is NEVER cached: an invalid credential re-runs the module every time (fail-closed,
//!   and revocation is instant for the deny path by construction).
//! - Bounded: at capacity, expired entries are swept, then the oldest-inserted evicted.
//! - `flush(module)` / `flush_all()` — wired to the admin flush endpoint for instant revocation
//!   of the CACHED-ALLOW window.

use crate::auth::{AuthOutcome, Principal};
use std::collections::HashMap;
use std::sync::Mutex;

/// Default TTL for a cached `Identify` when the module suggests none, seconds.
const DEFAULT_IDENTIFY_TTL_SECS: u64 = 300;
/// Hard cap on any module-suggested `Identify` TTL, seconds — a module cannot pin a credential
/// valid for longer than this, no matter what it asks for.
const MAX_IDENTIFY_TTL_SECS: u64 = 3600;
/// Base TTL for a cached `Pass`, seconds (short: "not mine" can become "mine" after a directory
/// change, and the window bounds the staleness).
const PASS_TTL_SECS: u64 = 5;
/// Maximum cached entries across all modules.
const MAX_ENTRIES: usize = 4096;

/// A cacheable verdict: only the two outcomes the rules allow.
#[derive(Clone)]
enum CachedVerdict {
    Identify(Principal),
    Pass,
}

struct Entry {
    expires_at: u64,
    inserted_seq: u64,
    verdict: CachedVerdict,
}

/// The cache key: `(module_name, sha256_hex(credential))`.
type CacheKey = (String, String);

/// A FLUSH GENERATION token: the value of the cache's flush counter at a moment in time.
///
/// THE HAZARD IT CLOSES. `POST /api/v1/admin/auth/cache/flush` is documented as INSTANT REVOCATION
/// of the cached-allow window, and it returns `200 {"flushed": N}`. But an authentication already
/// IN FLIGHT across the flush computed its allow verdict BEFORE the flush and inserted it AFTER —
/// so the flush returned success having revoked nothing, and the pre-flush verdict kept serving for
/// up to `MAX_IDENTIFY_TTL_SECS` (an hour). The window is real and wide, not theoretical: the
/// shipped OIDC module does a blocking JWKS HTTPS round-trip with a 10-second timeout, and an admin
/// plugin chain runs on the blocking pool with its own multi-second budget.
///
/// THE FIX is the pattern this codebase already uses twice — `RevocationSync`'s union-never-replace
/// and `GovState::refresh_lock`'s serialize-the-swap: capture the generation BEFORE the module call
/// and hand it back to [`CredentialCache::put`], which drops the insert if the generation moved.
/// Because the token is a distinct TYPE that only [`CredentialCache::generation`] can produce, a
/// future call site cannot insert without having captured one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CacheGeneration(u64);

/// The mutex-protected cache state. Held together under ONE lock on purpose: the flush counter has
/// to move in the same critical section that clears the map, or `put`'s "has the generation moved?"
/// check and the flush's clear could interleave and let a stale verdict land anyway.
struct CacheState {
    entries: HashMap<CacheKey, Entry>,
    /// Monotonic insert counter — the eviction ordering.
    seq: u64,
    /// Monotonic FLUSH counter. Bumped by every `flush_all`/`flush_module`.
    flush_gen: u64,
}

pub(crate) struct CredentialCache {
    state: Mutex<CacheState>,
}

impl CredentialCache {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(CacheState {
                entries: HashMap::new(),
                seq: 0,
                flush_gen: 0,
            }),
        }
    }

    /// The CURRENT flush generation. Capture this BEFORE consulting an auth module, and pass it to
    /// [`CredentialCache::put`] afterwards: any flush that lands in between moves the counter, and
    /// the `put` is then dropped rather than resurrecting a pre-flush allow verdict. See
    /// [`CacheGeneration`].
    pub(crate) fn generation(&self) -> CacheGeneration {
        CacheGeneration(self.lock().flush_gen)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Look up a cached verdict for `(module, credential)` at time `now`. `None` = miss (expired
    /// entries are treated as misses and removed).
    pub(crate) fn get(&self, module: &str, credential: &str, now: u64) -> Option<AuthOutcome> {
        let key = (
            module.to_string(),
            crate::sigv4::sha256_hex(credential.as_bytes()),
        );
        let mut guard = self.lock();
        match guard.entries.get(&key) {
            Some(e) if e.expires_at > now => Some(match &e.verdict {
                CachedVerdict::Identify(p) => AuthOutcome::Identify(p.clone()),
                CachedVerdict::Pass => AuthOutcome::Pass,
            }),
            Some(_) => {
                guard.entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store a module's verdict per the rules. `Reject` is dropped on the floor — never
    /// cached. The `Identify` TTL is the module's suggestion clamped to the hard cap; `Pass` gets
    /// the short base TTL plus a per-key jitter (derived from the credential hash — deterministic,
    /// no clock/RNG — so distinct credentials expire at distinct offsets).
    ///
    /// `gen` is the generation captured BEFORE the module was consulted ([`CredentialCache::generation`]).
    /// If a flush landed in between, the generation has moved and this insert is DROPPED: an
    /// admin-ordered revocation must not be undone by a verdict that predates it. The check runs
    /// under the same lock the flush clears the map under, so the two cannot interleave.
    pub(crate) fn put(
        &self,
        module: &str,
        credential: &str,
        outcome: &AuthOutcome,
        now: u64,
        r#gen: CacheGeneration,
    ) {
        let hash = crate::sigv4::sha256_hex(credential.as_bytes());
        let (verdict, ttl) = match outcome {
            AuthOutcome::Identify(p) => (
                CachedVerdict::Identify(p.clone()),
                p.ttl_secs
                    .unwrap_or(DEFAULT_IDENTIFY_TTL_SECS)
                    .min(MAX_IDENTIFY_TTL_SECS),
            ),
            AuthOutcome::Pass => {
                // 0..=2s of deterministic per-key jitter on top of the base.
                let jitter = u64::from(hash.as_bytes()[0] % 3);
                (CachedVerdict::Pass, PASS_TTL_SECS + jitter)
            }
            AuthOutcome::Reject => return,
        };
        let mut guard = self.lock();
        if guard.flush_gen != r#gen.0 {
            // A flush landed while this authentication was in flight. The verdict is PRE-flush, so
            // caching it now would silently re-open the cached-allow window the operator just closed.
            return;
        }
        let CacheState {
            entries: map, seq, ..
        } = &mut *guard;
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, e| e.expires_at > now);
            if map.len() >= MAX_ENTRIES {
                // Still full of live entries: evict the oldest-inserted (bounded > perfect LRU).
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, e)| e.inserted_seq)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
        }
        *seq += 1;
        map.insert(
            (module.to_string(), hash),
            Entry {
                expires_at: now + ttl,
                inserted_seq: *seq,
                verdict,
            },
        );
    }

    /// Drop every cached verdict for one module (its partition) — the settings-change /
    /// revocation seam.
    ///
    /// Bumps the FLUSH GENERATION in the same critical section, so an in-flight authentication whose
    /// verdict predates this call cannot re-insert after it (see [`CacheGeneration`]). The bump is
    /// GLOBAL rather than per-module on purpose: the cost of dropping a concurrent OTHER module's
    /// insert is one cache miss, while the cost of getting the partitioning wrong is a missed
    /// revocation.
    pub(crate) fn flush_module(&self, module: &str) -> usize {
        let mut guard = self.lock();
        guard.flush_gen += 1;
        let before = guard.entries.len();
        guard.entries.retain(|(m, _), _| m != module);
        before - guard.entries.len()
    }

    /// Drop everything — the admin flush endpoint's no-body form (instant revocation of every
    /// cached-allow window). Bumps the flush generation for the reason [`CredentialCache::flush_module`]
    /// documents: without it this endpoint reported `200 {"flushed": N}` while an authentication in
    /// flight put its PRE-flush allow verdict straight back.
    pub(crate) fn flush_all(&self) -> usize {
        let mut guard = self.lock();
        guard.flush_gen += 1;
        let n = guard.entries.len();
        guard.entries.clear();
        n
    }
}

#[cfg(test)]
#[path = "tests/auth_cache_tests.rs"]
mod tests;
