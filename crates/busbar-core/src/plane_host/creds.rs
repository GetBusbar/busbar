// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side credential MINT registry — the keystone of FLAG-4 (plane-secret removal).
//!
//! A plane NEVER holds a raw provider secret. It holds an OPAQUE `credential_ref` (a bare `u64`), and
//! the host owns the plaintext end to end: the host mints a short-lived per-hop `resolved_ref` (via
//! [`mint`], the body behind the `auth_resolve` seam), maps it to the plaintext HERE, and later — when
//! the plane opens an egress carrying that ref — the host RESOLVES it ([`resolve`]) and injects the
//! credential into the outbound request app-layer (see [`super::egress`]). The secret bytes cross the
//! seam in NEITHER direction: `auth_resolve` hands the plane only the opaque ref, and `egress_open`
//! reads the plaintext out of this host-owned map, never off a plane-supplied POD.
//!
//! Mints are short-lived (an `expires_unix` the host owns): [`resolve`] drops an expired entry
//! rather than serve it, so a stale ref fails closed. Resolution is deliberately NOT one-shot — the
//! plane is handed `expires_unix` (validity-until-expiry semantics), and a plane failover may
//! legitimately re-open an egress carrying the same still-live ref; a one-shot drop would make that
//! second open inject NOTHING (an unauthenticated request going out silently) rather than fail
//! closed. The map is process-wide because the resolved ref the plane holds is minted from a
//! process atomic (the same discipline the egress [`REGISTRY`](super::egress) uses), while the
//! LIFETIME is still governed host-side by the stamped expiry — the plane cannot extend it.
//!
//! ## What bounds the registry
//!
//! A ref the plane never carries into `egress_open` would otherwise sit forever — resolution-side
//! cleanup only ever sees refs something looked up. So [`mint`] is also the sweep trigger: when the
//! map has grown past an amortized watermark, every entry already expired at the caller's clock is
//! purged and the watermark resets to twice the surviving population (floored at
//! [`SWEEP_MIN_LEN`]). The map is therefore bounded by ~2x the mints inside one TTL window
//! (`DEFAULT_AUTH_TTL_SECS`), each sweep is O(live), and the amortized cost per mint is O(1) — no
//! full scan on every dispatch-path call, no background timer to schedule or leak.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// One minted credential: the plaintext the host injects, and the host-owned expiry past which it is
/// refused. The plaintext lives ONLY here (host-side); it is never written into a plane-facing POD.
struct Mint {
    /// The resolved credential plaintext the host injects at egress. NEVER crosses the seam.
    secret: Vec<u8>,
    /// Unix-seconds expiry the host stamped; [`resolve`] refuses (and drops) a mint past it.
    expires_unix: u64,
}

/// The mint map plus the sweep watermark it is bounded by (one lock, so the two cannot drift).
struct Registry {
    /// Live mints, keyed by the opaque `resolved_ref` the plane holds.
    map: HashMap<u64, Mint>,
    /// The amortization watermark: [`mint`] sweeps expired entries only when `map.len()` has
    /// reached this, then resets it to `max(2 * survivors, SWEEP_MIN_LEN)` — classic doubling, so
    /// sweep work is amortized O(1) per mint and the map never exceeds ~2x its live population.
    next_sweep_len: usize,
}

/// Below this the mint-time sweep never bothers running: a handful of stale entries is cheaper
/// than hashing the map for them, and the watermark can never amortize to zero.
const SWEEP_MIN_LEN: usize = 64;

/// The process-wide mint registry, keyed by the opaque `resolved_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        map: HashMap::new(),
        next_sweep_len: SWEEP_MIN_LEN,
    })
});

/// The next resolved-ref. `0` is the reserved "none" ref (a query naming no credential), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Mint a resolved credential ref for `secret`, valid until `expires_unix`. Returns the opaque
/// `resolved_ref` the plane carries back into `egress_open` — the ONLY thing about the credential that
/// crosses the seam. The plaintext stays host-side in the registry.
///
/// `now_unix` is the caller's clock read (the same one it derived `expires_unix` from): each mint is
/// also the sweep trigger that purges entries already expired at `now_unix`, so a ref that is minted
/// and never resolved cannot accumulate (see the module doc's bound).
#[must_use]
pub(crate) fn mint(secret: Vec<u8>, expires_unix: u64, now_unix: u64) -> u64 {
    let resolved_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    let mut reg = registry();
    // THE SWEEP: purge everything already expired at the caller's clock, amortized behind the
    // doubling watermark so the dispatch path never pays a full scan per mint. This — not
    // resolution — is what bounds the map: a ref minted and never carried into `egress_open`
    // has no other exit.
    if reg.map.len() >= reg.next_sweep_len {
        reg.map.retain(|_, m| now_unix <= m.expires_unix);
        reg.next_sweep_len = reg.map.len().saturating_mul(2).max(SWEEP_MIN_LEN);
    }
    reg.map.insert(
        resolved_ref,
        Mint {
            secret,
            expires_unix,
        },
    );
    resolved_ref
}

/// TEST ONLY: is `resolved_ref` physically present in the registry map? Distinct from [`resolve`]
/// (which answers `None` for expired-but-still-held entries): the retention tests need to see
/// whether the SWEEP removed an entry, not whether resolution would refuse it.
#[cfg(test)]
pub(crate) fn contains_for_test(resolved_ref: u64) -> bool {
    registry().map.contains_key(&resolved_ref)
}

/// Resolve `resolved_ref` to its plaintext, or `None` when the ref is unknown or has expired at
/// `now_unix` (an expired ref is DROPPED, so it fails closed and cannot be replayed). The returned
/// bytes are host-owned; the caller injects them into the outbound request and never hands them back
/// across the seam.
#[must_use]
pub(crate) fn resolve(resolved_ref: u64, now_unix: u64) -> Option<Vec<u8>> {
    if resolved_ref == 0 {
        return None;
    }
    let mut reg = registry();
    let expired = reg
        .map
        .get(&resolved_ref)
        .is_some_and(|m| now_unix > m.expires_unix);
    if expired {
        reg.map.remove(&resolved_ref);
        return None;
    }
    reg.map.get(&resolved_ref).map(|m| m.secret.clone())
}

#[cfg(test)]
#[path = "tests/creds_tests.rs"]
mod tests;
