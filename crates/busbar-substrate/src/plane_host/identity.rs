// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side mTLS CLIENT-IDENTITY registry — the mutual-handshake counterpart of the host-side credential registry.
//!
//! A plane presenting a client certificate on a governed hop never holds the private key. It holds an
//! OPAQUE `client_identity_ref` (a bare `u64`), and the host owns the parsed key end to end: the host
//! registers each boot-time client identity HERE ([`register`]) and hands back a ref; when the plane
//! opens an egress carrying that ref, the host RESOLVES it ([`resolve`]) and offers the identity to the
//! TLS stack at the host egress chokepoint. The key crosses the seam in NEITHER direction.
//!
//! Registered ONCE, at boot (a config generation), not per hop — a private key re-read on every tick is
//! a key crossing the resolver seam on every tick. The map is process-wide because the ref the plane
//! holds is minted from a process atomic (the same discipline the egress and credential registries
//! use); the identity is a parsed, immutable engine [`ClientIdentity`] that several hops may present
//! over a process lifetime.
//!
//! ## A GENERATION IS THE LIFETIME OF THE KEYS IN IT
//!
//! A registry that only ever grows is a registry of private keys that only ever grows. Every config
//! apply resolves an operator's client certificates again, so a deployment with N mTLS-pinned agents
//! reloaded M times used to leave N×M parsed private keys resident for the life of the process —
//! including the ones the operator had already retired from the config, still resolvable through any
//! ref that had been handed out.
//!
//! So a registration is not process-wide any more: it belongs to an [`IdentityGeneration`], and the
//! generation is a VALUE ITS INSTALLER OWNS. Dropping it retires every ref it minted — the entries
//! go, the key material is zeroized where this registry held the last copy, and [`resolve`] on a
//! retired ref fails CLOSED (`None`, the hop presents no certificate and an mTLS peer refuses it
//! itself, exactly as for a ref that never existed).
//!
//! OWNERSHIP, not a global "newest wins", is deliberate. The apply that builds the new generation is
//! not always the apply whose transports the plane goes on using (a plane that carries its
//! boot-resolved bundle across a re-apply keeps the OLD one), and a global retirement would pull the
//! keys out from under the transports still serving while leaving the discarded bundle's keys
//! resident. Tying the keys to the bundle that holds them gets both cases right: whichever bundle is
//! RELEASED is the one whose keys go, and a bundle still in use keeps working.

// PARTLY UNMOUNTED. `resolve` is live at the egress chokepoint today; `register` is the boot-time
// entry the plane calls when its egress call sites are flipped onto the seam (CLUSTER-3 Stage B), and
// is reached only by tests until then. The same posture `a2a::transport` records for its own
// not-yet-mounted pieces.
#![cfg_attr(not(test), allow(dead_code))]

use crate::egress::engine::ClientIdentity;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The process-wide client-identity registry, keyed by the opaque `client_identity_ref` the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, ClientIdentity>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next GENERATION number. The high half of every ref, so a ref minted by a retired generation can
/// never be re-minted by a later one.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// The next per-generation slot. `0` is the reserved "none" ref (a hop presenting no identity), and a
/// ref carries a nonzero generation in its high half, so no live ref is ever `0`.
static NEXT_SLOT: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, ClientIdentity>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// The generation half of a ref — what [`IdentityGeneration::drop`] retires by.
const fn generation_of(client_identity_ref: u64) -> u64 {
    client_identity_ref >> 32
}

/// ONE GENERATION OF REGISTERED IDENTITIES — the lifetime of the private keys registered through it.
///
/// Installed by whoever resolves a config's client certificates, held for as long as the transports
/// built on it are in use, and RETIRED when it is dropped: every ref it minted stops resolving and
/// the parsed keys are zeroized and dropped. Not `Clone`: a generation has exactly one owner, and
/// that owner's lifetime IS the keys' lifetime.
pub struct IdentityGeneration {
    generation: u64,
}

impl IdentityGeneration {
    /// Open a fresh generation. Retires nothing by itself — the PREVIOUS generation is retired when
    /// its own handle is dropped, which is what an apply does when it releases the bundle it built.
    #[must_use]
    pub fn install() -> Self {
        IdentityGeneration {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Register a parsed client `identity` IN THIS GENERATION, returning the opaque
    /// `client_identity_ref` the plane carries into `egress_open`. The ONLY thing about the identity
    /// that crosses the seam is this `u64`; the parsed key stays host-side in the registry, and it
    /// stays there only as long as this generation does.
    #[must_use]
    pub fn register(&self, identity: ClientIdentity) -> u64 {
        let slot = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) & 0xffff_ffff;
        let client_identity_ref = (self.generation << 32) | slot;
        registry().insert(client_identity_ref, identity);
        client_identity_ref
    }

    /// HOW MANY IDENTITIES THIS GENERATION IS HOLDING — the residency an apply is allowed. A
    /// generation-scoped count and not a registry-wide one on purpose: the registry is process-wide
    /// and every live generation shares it, so the number that means "this apply left no key behind"
    /// is this one.
    #[must_use]
    pub fn len(&self) -> usize {
        registry()
            .keys()
            .filter(|r| generation_of(**r) == self.generation)
            .count()
    }

    /// Whether this generation registered nothing (an apply that named no client certificate).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for IdentityGeneration {
    /// RETIRE the generation: drop every entry it minted, zeroizing the key material of each one this
    /// registry held the last reference to. A hop still carrying one of those refs now resolves to
    /// `None` and presents no certificate — the fail-closed outcome, not somebody else's identity.
    fn drop(&mut self) {
        let mut registry = registry();
        let retired: Vec<u64> = registry
            .keys()
            .copied()
            .filter(|r| generation_of(*r) == self.generation)
            .collect();
        for r in retired {
            if let Some(mut identity) = registry.remove(&r) {
                identity.zeroize_key();
            }
        }
    }
}

/// Resolve `client_identity_ref` to its parsed client identity, or `None` when the ref is `0` (present
/// no identity) or unknown. `None` is the HONEST mTLS outcome for an unknown ref: the hop is made
/// presenting no certificate, and an mTLS peer closes the handshake itself rather than the host
/// forging one — exactly the posture the a2a transport takes when a registration names no identity.
#[must_use]
pub fn resolve(client_identity_ref: u64) -> Option<ClientIdentity> {
    if client_identity_ref == 0 {
        return None;
    }
    registry().get(&client_identity_ref).cloned()
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod tests;
