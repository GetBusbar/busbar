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
//! Mints are short-lived (an `expires_unix` the host owns) and single-use-ish: [`resolve`] drops an
//! expired entry rather than serve it, so a stale ref fails closed. The map is process-wide because
//! the resolved ref the plane holds is minted from a process atomic (the same discipline the egress
//! [`REGISTRY`](super::egress) uses), while the LIFETIME is still governed host-side by the stamped
//! expiry — the plane cannot extend it.

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

/// The process-wide mint registry, keyed by the opaque `resolved_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, Mint>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next resolved-ref. `0` is the reserved "none" ref (a query naming no credential), so refs
/// start at `1`.
static NEXT_REF: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Mint>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Mint a resolved credential ref for `secret`, valid until `expires_unix`. Returns the opaque
/// `resolved_ref` the plane carries back into `egress_open` — the ONLY thing about the credential that
/// crosses the seam. The plaintext stays host-side in the registry.
#[must_use]
pub(crate) fn mint(secret: Vec<u8>, expires_unix: u64) -> u64 {
    let resolved_ref = NEXT_REF.fetch_add(1, Ordering::Relaxed);
    registry().insert(
        resolved_ref,
        Mint {
            secret,
            expires_unix,
        },
    );
    resolved_ref
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
        .get(&resolved_ref)
        .is_some_and(|m| now_unix > m.expires_unix);
    if expired {
        reg.remove(&resolved_ref);
        return None;
    }
    reg.get(&resolved_ref).map(|m| m.secret.clone())
}

#[cfg(test)]
#[path = "tests/creds_tests.rs"]
mod tests;
