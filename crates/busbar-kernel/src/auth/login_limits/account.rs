// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-ACCOUNT LIMITER, fleet-wide in the core store, built on single-use claims.
//!
//! An account has `max` SLOTS, `<fingerprint>/<i>`. An attempt claims the first free slot BEFORE the
//! plugin is called; the claim expires `window` after it was taken, at the store's native clock.
//! Every slot held means the account is throttled. Each slot is one compare-and-swap, so twenty
//! concurrent attempts across any number of nodes take at most `max` slots. A refund (the plugin
//! never ran) releases the attempt's slot; a success releases every slot (the failures are
//! cleared). The records hold only an expiry, never a name, and the shared claim maintenance sweeps
//! them. Any store failure is the caller's to fail closed on.

use crate::persistence::claims::{Claims, Outcome};
use crate::persistence::facade::CoreStore;

use super::policy::Limit;

/// The claims owner of the account slots.
pub(crate) const OWNER: &str = "busbar.login-attempts";
/// The claims kind of the account slots (versioned with the key derivation).
pub(crate) const KIND: &str = "account-v1";

/// A held slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotTicket {
    fingerprint: String,
    slot: u32,
}

/// The store could not answer; the caller fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreUnavailable;

/// What reserving answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reserved {
    /// A slot is held for this attempt.
    Held(SlotTicket),
    /// Every slot is held: the account is throttled.
    Full,
}

fn token(fingerprint: &str, slot: u32) -> String {
    format!("{fingerprint}/{slot}")
}

/// Register the slots' namespace with the shared claim maintenance (idempotent).
pub(crate) fn register(store: &CoreStore) {
    let _ = store.register_claim_scope(OWNER, KIND);
}

/// Claim the first free slot of `fingerprint` under `limit`.
pub(crate) async fn reserve(
    store: &CoreStore,
    fingerprint: &str,
    limit: Limit,
    now: u64,
) -> Result<Reserved, StoreUnavailable> {
    register(store);
    let claims = Claims::authorized(store, OWNER, KIND);
    let expires_at = now.checked_add(limit.window_secs).ok_or(StoreUnavailable)?;
    let mut attempt = [0u8; 16];
    busbar_contract::crypto::fill(&mut attempt)
        .map_err(|_| StoreUnavailable)?;
    for slot in 0..limit.max {
        match claims
            .redeem_as(&token(fingerprint, slot), expires_at, &attempt)
            .await
        {
            Ok(Outcome::Claimed) => {
                return Ok(Reserved::Held(SlotTicket {
                    fingerprint: fingerprint.to_string(),
                    slot,
                }))
            }
            Ok(Outcome::AlreadyClaimed) => continue,
            Ok(_) | Err(_) => return Err(StoreUnavailable),
        }
    }
    Ok(Reserved::Full)
}

/// Give one attempt's slot back: the plugin never judged it.
pub(crate) async fn refund(store: &CoreStore, ticket: &SlotTicket) -> Result<(), StoreUnavailable> {
    Claims::authorized(store, OWNER, KIND)
        .release(&token(&ticket.fingerprint, ticket.slot))
        .await
        .map(|_| ())
        .map_err(|_| StoreUnavailable)
}

/// Clear the account's failures: a successful sign-in releases every slot.
pub(crate) async fn clear(
    store: &CoreStore,
    fingerprint: &str,
    limit: Limit,
) -> Result<(), StoreUnavailable> {
    let claims = Claims::authorized(store, OWNER, KIND);
    let mut result = Ok(());
    for slot in 0..limit.max {
        if claims.release(&token(fingerprint, slot)).await.is_err() {
            result = Err(StoreUnavailable);
        }
    }
    result
}

/// Hold every free slot: the plugin says the directory locked the account (or its own limiter
/// refused), so nothing more is forwarded for this account until the window passes.
pub(crate) async fn saturate(
    store: &CoreStore,
    fingerprint: &str,
    limit: Limit,
    now: u64,
) -> Result<(), StoreUnavailable> {
    while let Reserved::Held(_) = reserve(store, fingerprint, limit, now).await? {}
    Ok(())
}
