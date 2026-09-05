// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The credential cache: consult an external verifier once per credential per lifetime rather than
//! once per request.
//!
//! The rules are fixed and none of them is a preference:
//!
//! - The key is the provider NAME plus a digest of the credential. The credential itself is never
//!   stored, and the name rather than the module's self-reported name is used because two named
//!   providers backed by one module are two different verifiers with two different settings — a
//!   shared row would let one admit the other's credential.
//! - An identify entry lives for the module's suggested lifetime clamped to an hour, five minutes
//!   when the module suggests none. A module cannot pin a credential valid for longer than the cap
//!   however loudly it asks.
//! - A pass entry lives five seconds plus zero to two seconds of deterministic jitter derived from
//!   the digest, so a prober cannot read "recently probed" off the response time.
//! - A reject is never cached at all. An invalid credential re-runs its module every time, which is
//!   what makes the deny path revoke instantly by construction.
//! - The cache is bounded. At capacity it first sweeps expired rows, then evicts the oldest
//!   inserted.
//!
//! ## The flush generation, and the hole it closes
//!
//! An administrative flush is documented as instant revocation. But an authentication already in
//! flight computed its verdict BEFORE the flush and inserts it AFTER — so the flush reported
//! success having revoked nothing, and a pre-flush allow kept serving for up to its whole lifetime.
//! The window is not theoretical: a verifier doing a blocking network round-trip sits inside it for
//! seconds. So the generation is captured before the first module is consulted and handed back at
//! insert time; a flush moves the counter and the insert is dropped. The check happens under the
//! same lock the flush clears the map under, so the two cannot interleave.

use crate::module::AuthOutcome;
use crate::principal::Principal;
use std::collections::HashMap;
use std::sync::Mutex;

/// The lifetime of a cached identification when the module suggests none, in seconds.
const DEFAULT_IDENTIFY_TTL_SECS: u64 = 300;
/// The hard ceiling on any module-suggested identification lifetime, in seconds.
const MAX_IDENTIFY_TTL_SECS: u64 = 3600;
/// The base lifetime of a cached pass, in seconds.
const PASS_TTL_SECS: u64 = 5;
/// The most rows the cache holds, across every module.
const MAX_ENTRIES: usize = 4096;

/// How a credential is digested for the cache key.
///
/// A function pointer rather than a hash dependency, because this crate deliberately carries none.
/// The kernel supplies the same digest it uses everywhere else, and the digest's first byte is what
/// the pass jitter is derived from, so a different digest changes the jitter and nothing else.
// contract: the kernel passes its own hex SHA-256.
pub type DigestFn = fn(&[u8]) -> String;

/// A verdict the rules allow to be cached. A rejection has no arm here, which is the rule stated as
/// a type rather than as a comment.
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

/// The cache key: the provider name and the credential digest.
type CacheKey = (String, String);

/// The value of the cache's flush counter at a moment in time.
///
/// Its constructor is [`CredentialCache::generation`] and nothing else, so an insert site cannot
/// skip capturing one — the type is the discipline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CacheGeneration(u64);

/// The locked state. The flush counter lives under the same lock as the map on purpose: it has to
/// move in the same critical section the map is cleared in.
struct CacheState {
    entries: HashMap<CacheKey, Entry>,
    /// The monotonic insert counter — the eviction ordering.
    seq: u64,
    /// The monotonic flush counter.
    flush_gen: u64,
}

/// The cache itself.
pub struct CredentialCache {
    state: Mutex<CacheState>,
    digest: DigestFn,
}

impl CredentialCache {
    /// A new, empty cache over the supplied credential digest.
    pub fn new(digest: DigestFn) -> Self {
        CredentialCache {
            state: Mutex::new(CacheState {
                entries: HashMap::new(),
                seq: 0,
                flush_gen: 0,
            }),
            digest,
        }
    }

    /// The current flush generation. Capture it before consulting a module and hand it back to
    /// [`CredentialCache::put`].
    pub fn generation(&self) -> CacheGeneration {
        CacheGeneration(self.lock().flush_gen)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        // A poisoned lock means some other thread panicked while holding it. The map is a cache;
        // the worst a torn view costs is a miss, so recovering is strictly better than propagating
        // the panic into an authentication.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Look up a verdict. An expired row is a miss and is removed on the way past.
    pub fn get(&self, module: &str, credential: &str, now: u64) -> Option<AuthOutcome> {
        let key = (module.to_string(), (self.digest)(credential.as_bytes()));
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

    /// Store a verdict under the rules above. A rejection is dropped on the floor.
    pub fn put(
        &self,
        module: &str,
        credential: &str,
        outcome: &AuthOutcome,
        now: u64,
        generation: CacheGeneration,
    ) {
        let hash = (self.digest)(credential.as_bytes());
        let (verdict, ttl) = match outcome {
            AuthOutcome::Identify(p) => (
                CachedVerdict::Identify(p.clone()),
                p.ttl_secs
                    .unwrap_or(DEFAULT_IDENTIFY_TTL_SECS)
                    .min(MAX_IDENTIFY_TTL_SECS),
            ),
            AuthOutcome::Pass => {
                // Zero to two seconds of per-key jitter on top of the base, taken from the digest so
                // it needs neither a clock nor a random source and is stable for one credential.
                let jitter = u64::from(hash.as_bytes().first().copied().unwrap_or(0) % 3);
                (CachedVerdict::Pass, PASS_TTL_SECS + jitter)
            }
            AuthOutcome::Reject => return,
        };
        let mut guard = self.lock();
        if guard.flush_gen != generation.0 {
            // A flush landed while this authentication was in flight. This verdict predates it, so
            // caching it now would re-open the window the operator just closed.
            return;
        }
        let CacheState {
            entries: map, seq, ..
        } = &mut *guard;
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, e| e.expires_at > now);
            if map.len() >= MAX_ENTRIES {
                // Still full of live rows: evict the oldest inserted. Bounded beats perfect.
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

    /// Drop every row for one module and bump the generation.
    ///
    /// The bump is global rather than per-module deliberately: dropping a concurrent other module's
    /// insert costs one cache miss, and getting the partitioning wrong costs a missed revocation.
    pub fn flush_module(&self, module: &str) -> usize {
        let mut guard = self.lock();
        guard.flush_gen += 1;
        let before = guard.entries.len();
        guard.entries.retain(|(m, _), _| m != module);
        before - guard.entries.len()
    }

    /// Drop everything and bump the generation. The count returned is a real count.
    pub fn flush_all(&self) -> usize {
        let mut guard = self.lock();
        guard.flush_gen += 1;
        let n = guard.entries.len();
        guard.entries.clear();
        n
    }

    /// How many rows the cache currently holds. For tests and for the admin report.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
