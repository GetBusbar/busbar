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

use std::fmt::Write as _;

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
    token: Token,
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

/// The most bytes a slot token spells: an account fingerprint is 32 hex characters, so the room is
/// generous; a longer one is refused as the store failing (fail closed), never truncated.
const TOKEN_ROOM: usize = 128;

/// A slot's claim token, `<fingerprint>/<slot>`, spelled on the stack.
#[derive(Clone, PartialEq, Eq)]
struct Token {
    buf: [u8; TOKEN_ROOM],
    len: usize,
}

impl Token {
    fn new(fingerprint: &str, slot: u32) -> Result<Self, StoreUnavailable> {
        let mut token = Self {
            buf: [0; TOKEN_ROOM],
            len: 0,
        };
        write!(token, "{fingerprint}/{slot}").map_err(|_| StoreUnavailable)?;
        Ok(token)
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
    }
}

impl std::fmt::Write for Token {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self
            .len
            .checked_add(s.len())
            .filter(|end| *end <= TOKEN_ROOM)
            .ok_or(std::fmt::Error)?;
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
    busbar_contract::crypto::fill(&mut attempt).map_err(|_| StoreUnavailable)?;
    for slot in 0..limit.max {
        let token = Token::new(fingerprint, slot)?;
        match claims.redeem_as(token.as_str(), expires_at, &attempt).await {
            Ok(Outcome::Claimed) => return Ok(Reserved::Held(SlotTicket { token })),
            Ok(Outcome::AlreadyClaimed) => continue,
            Ok(_) | Err(_) => return Err(StoreUnavailable),
        }
    }
    Ok(Reserved::Full)
}

/// Give one attempt's slot back: the plugin never judged it.
pub(crate) async fn refund(store: &CoreStore, ticket: &SlotTicket) -> Result<(), StoreUnavailable> {
    Claims::authorized(store, OWNER, KIND)
        .release(ticket.token.as_str())
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
        let Ok(token) = Token::new(fingerprint, slot) else {
            result = Err(StoreUnavailable);
            continue;
        };
        if claims.release(token.as_str()).await.is_err() {
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
