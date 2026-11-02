// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{PlaneDisposition, PlaneRecordRef, Retention};

pub const TICKET_RECORD_KIND: &str = "ticket";

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

fn ticket_id() -> Result<String, TicketRefusal> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| TicketRefusal::NoRandomness)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

impl GovState {
    pub(crate) async fn admit_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let gov = Arc::clone(self);
        let owned_prefix = prefix.to_owned();
        let owned_credential = zeroize::Zeroizing::new(credential.to_owned());
        let (admitted, mut record) = crate::auth::ticket_store(move || {
            gov.admit_ticket(&owned_prefix, &owned_credential, now)
                .map(|(key, record)| (key, zeroize::Zeroizing::new(record)))
        })
        .await?;
        let (current, _, _) = self.checked_ticket(prefix, credential, now)?;
        (current.id == admitted.id).then(|| (current, std::mem::take(&mut *record)))
    }

    pub(crate) async fn peek_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<Arc<VirtualKey>> {
        let gov = Arc::clone(self);
        let owned_prefix = prefix.to_owned();
        let owned_credential = zeroize::Zeroizing::new(credential.to_owned());
        crate::auth::ticket_store(move || gov.peek_ticket(&owned_prefix, &owned_credential, now))
            .await?;
        self.checked_ticket(prefix, credential, now)
            .map(|(key, _, _)| key)
    }

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

        let _purged = store.purge_plane_records(TICKET_RECORD_KIND, now, Retention::Age);
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

    pub fn admit_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let (key, id, exp) = self.checked_ticket(prefix, credential, now)?;
        let store = self.store();
        if !store
            .redeem_plane_token(TICKET_SPENT_KIND, &id, exp, now)
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

    pub(crate) fn peek_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<Arc<VirtualKey>> {
        let (key, id, exp) = self.checked_ticket(prefix, credential, now)?;
        self.store()
            .plane_token_live(TICKET_RECORD_KIND, &id, exp, now)
            .ok()
            .filter(|live| *live)
            .map(|_| key)
    }

    fn checked_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, String, u64)> {
        if prefix.is_empty() {
            return None;
        }
        let body = credential.strip_prefix(prefix)?;
        let material = self.signing_material()?;
        let claims = match material.verifier.verify_ticket_body(body) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "ticket verify rejected");
                return None;
            }
        };
        let id = claims.ticket.clone()?;
        let key = self.standing_key(&claims, now)?;
        Some((key, id, claims.exp))
    }
}

#[cfg(test)]
#[path = "tests/tickets_tests.rs"]
mod tests;
