// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TICKETS (row 132, the ARCHITECT ticket ruling): short-lived, single-use credentials the host
//! mints for the principal of a unit, through the same token stamp as every busbar key, and admits
//! once on a route that takes a ticket.
//!
//! A ticket is the minting plane's declared issued-id prefix followed by a signed token body whose
//! claims name the principal's key (`sub`, its binding's current generation), the ticket audience
//! ([`TICKET_AUDIENCE`]) and the ticket's id (`t`). The prefix is the plane's word; the host never
//! spells one of its own. Beside the ticket the host stores the record the plane handed it, keyed
//! by the ticket id, until the ticket's expiry.
//!
//! ADMISSION is all-or-nothing and fail-closed: the prefix strips, the body verifies under the
//! ticket audience and names a ticket id, the subject still stands as a key would (not revoked,
//! enabled, the current generation), the ticket id is redeemed for the first time, and its record
//! is there. Any other answer refuses, and a store that cannot say whether the ticket was spent
//! refuses too. A ticket is never a key: its body carries no key prefix, and its audience is refused
//! everywhere the gate does not expect a ticket.

use super::signing::TICKET_AUDIENCE;
use super::*;
use busbar_contract::records::{PlaneDisposition, PlaneRecordRef};

/// The record kind a ticket's record is stored under, keyed by the ticket id.
pub const TICKET_RECORD_KIND: &str = "ticket";

/// The record kind a ticket's single-use admission is spent under.
pub const TICKET_SPENT_KIND: &str = "ticket-spent";

/// Why a ticket was not minted. Each answer is the refusal's reason, never secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRefusal {
    /// This node holds no signing key.
    NoSigner,
    /// The principal's key does not stand (unknown, disabled or revoked).
    NoStanding,
    /// The lifetime left after the ceilings is zero.
    NoLifetime,
    /// The store did not keep the record.
    NotKept,
    /// The OS randomness source failed.
    NoRandomness,
}

impl TicketRefusal {
    /// The refusal's reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoSigner => "no ticket is minted: this node holds no signing key",
            Self::NoStanding => "no ticket is minted: the principal's key does not stand",
            Self::NoLifetime => "no ticket is minted: no lifetime is left under the ceilings",
            Self::NotKept => "no ticket is minted: the store did not keep its record",
            Self::NoRandomness => "no ticket is minted: the randomness source failed",
        }
    }
}

/// A fresh ticket id: 128 bits from the OS CSPRNG, hex.
fn ticket_id() -> Result<String, TicketRefusal> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| TicketRefusal::NoRandomness)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

impl GovState {
    /// MINT A TICKET for the key `key_id`, prefixed with `prefix`, living `ttl_secs` from `now`
    /// (Unix seconds) clamped to `ceiling_secs` (the deployment's mint ceiling) and never past the
    /// key's own expiry, and store `record` beside it. Answers the ticket and its expiry.
    ///
    /// # Errors
    ///
    /// The [`TicketRefusal`] that stopped the mint; nothing is stored then.
    pub fn mint_ticket(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        ceiling_secs: Option<u64>,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), TicketRefusal> {
        let material = self.signing_material().ok_or(TicketRefusal::NoSigner)?;
        let key = self
            .lookup_by_sub(key_id)
            .filter(|k| k.enabled && !self.is_revoked(&k.id))
            .ok_or(TicketRefusal::NoStanding)?;
        let ttl =
            mint_policy::apply_mint_ttl_ceiling(ttl_secs, false, ceiling_secs).unwrap_or(ttl_secs);
        let mut exp = now.saturating_add(ttl);
        if let Some(key_exp) = key.expires_at {
            exp = exp.min(key_exp);
        }
        if exp <= now {
            return Err(TicketRefusal::NoLifetime);
        }
        let id = ticket_id()?;
        let store = self.store();
        // Lapsed tickets go as each new one is minted: a record lives no longer than its ticket.
        let _purged = store.purge_plane_records_before(TICKET_RECORD_KIND, now);
        store
            .upsert_plane_record(PlaneRecordRef {
                kind: TICKET_RECORD_KIND,
                id: &id,
                parent: None,
                seq: 0,
                ts: exp,
                disposition: PlaneDisposition::Terminal,
                body: record,
            })
            .map_err(|_| TicketRefusal::NotKept)?;
        let generation = binding_generation(&key.generation_hash);
        let body = material
            .signer
            .mint_ticket_body(&key.id, exp, generation, &id);
        Ok((format!("{prefix}{body}"), exp))
    }

    /// ADMIT A TICKET presented as `credential` on a route that takes tickets prefixed `prefix`, at
    /// `now` (Unix seconds): the key it was minted for and the record stored beside it, once. `None`
    /// for anything that is not a standing, unspent ticket of this deployment, or when the store
    /// cannot answer; the ticket is spent by the call that answers `Some`.
    pub fn admit_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        if prefix.is_empty() {
            return None;
        }
        let body = credential.strip_prefix(prefix)?;
        let material = self.signing_material()?;
        let claims = match material
            .verifier
            .verify_body(body, now, Some(TICKET_AUDIENCE))
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "ticket verify rejected");
                return None;
            }
        };
        let id = claims.ticket.clone()?;
        let key = self.standing_key(&claims, now)?;
        let store = self.store();
        if !store
            .redeem_plane_token(TICKET_SPENT_KIND, &id, claims.exp, now)
            .unwrap_or(false)
        {
            tracing::debug!("ticket rejected: already spent, or the store cannot say");
            return None;
        }
        let record = store
            .get_plane_record(TICKET_RECORD_KIND, &id)
            .ok()
            .flatten()?;
        let _deleted = store.delete_plane_record(TICKET_RECORD_KIND, &id);
        Some((key, record))
    }
}

#[cfg(test)]
#[path = "tests/tickets_tests.rs"]
mod tests;
