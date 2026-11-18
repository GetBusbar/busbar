// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`SealedTickets`]: MINT, is_ticket and AUTH_TICKET admission over the plugin-records namespace (IF §12.11).
//!
//! Wire form: `<prefix>bbt1.<base64url(iv ‖ ciphertext ‖ tag)>`. The payload (id, expiry, once, plugin, name,
//! audience, subject, scope) is encrypted with AES-256-CTR and authenticated encrypt-then-MAC with
//! HMAC-SHA256, both keys derived (HKDF-SHA256) from one 32-byte host key, all through `busbar-crypto`.
//! Rows (the MINT_ONCE marker and the MT_RECORD bytes) live in the core sub-namespace
//! (who.plugin, who.name, "ticket"), keyed by the ticket's random id.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use busbar_contract::crypto;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_ports::auth::Identity;

use super::{core_caller, core_name, TicketAdmitted, TicketDenied, TicketMint, Tickets};
use crate::plugin_records::{
    CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, MAX_TTL_S,
};

/// Core's ticket marker, right after the client-facing prefix.
pub const TICKET_MARKER: &str = "bbt1.";
/// The longest client-facing prefix.
const MAX_PREFIX: usize = 16;
/// MT_RECORD bound (IF §12.11, `MAX_TICKET_RECORD`).
const MAX_RECORD: usize = 65_536;
const TAG: &str = "ticket";
const VERSION: u8 = 1;
const IV: usize = 16;
const MAC: usize = 32;
const ID: usize = 16;
/// Row value: one flag byte, then the MT_RECORD bytes.
const ROW_FLAG: u8 = 1;

/// The ticket as opened from its seal.
struct Opened {
    id: [u8; ID],
    expires_at: u64,
    once: bool,
    has_row: bool,
    plugin: String,
    name: String,
    audience: String,
    subject: String,
    scope: String,
}

/// Seals and admits tickets. `R` is the plugin-records store the rows live in.
pub struct SealedTickets<R> {
    records: R,
    enc: SecureVec,
    mac: SecureVec,
    clock: fn() -> u64,
}

impl<R: PluginRecords> SealedTickets<R> {
    /// Tickets over `records`, sealed under `host_key` (32 bytes), timed by `clock` (UNIX seconds).
    /// `None` when the key is not 32 bytes or the key derivation is refused.
    pub fn new(records: R, host_key: &[u8], clock: fn() -> u64) -> Option<Self> {
        if host_key.len() != 32 {
            return None;
        }
        let info = |purpose: &[u8]| purpose.to_vec();
        let mut enc = SecureVec::zeroed(32);
        let mut mac = SecureVec::zeroed(32);
        crypto::hkdf_sha256(b"busbar.ticket.v1", host_key, &info(b"enc"), &mut enc[..]).ok()?;
        crypto::hkdf_sha256(b"busbar.ticket.v1", host_key, &info(b"mac"), &mut mac[..]).ok()?;
        Some(Self {
            records,
            enc,
            mac,
            clock,
        })
    }

    fn seal(&self, ticket: &Opened) -> Option<String> {
        let mut plain = Vec::new();
        plain.push(VERSION);
        plain.push(u8::from(ticket.once) | (u8::from(ticket.has_row) << 1));
        plain.extend_from_slice(&ticket.expires_at.to_be_bytes());
        plain.extend_from_slice(&ticket.id);
        for field in [
            &ticket.plugin,
            &ticket.name,
            &ticket.audience,
            &ticket.subject,
            &ticket.scope,
        ] {
            plain.extend_from_slice(&u16::try_from(field.len()).ok()?.to_be_bytes());
            plain.extend_from_slice(field.as_bytes());
        }
        let iv: [u8; IV] = crypto::random::<IV>().ok()?;
        let mut out = Vec::with_capacity(IV + plain.len() + MAC);
        out.extend_from_slice(&iv);
        out.resize(IV + plain.len(), 0);
        crypto::aes_ctr::apply(self.enc.as_slice(), &iv, &plain, &mut out[IV..]).ok()?;
        let tag = crypto::hmac_sha256(self.mac.as_slice(), &out).ok()?;
        out.extend_from_slice(&tag);
        Some(URL_SAFE_NO_PAD.encode(out))
    }

    fn open(&self, credential: &str) -> Option<Opened> {
        let at = credential.find(TICKET_MARKER)?;
        let raw = URL_SAFE_NO_PAD
            .decode(&credential[at + TICKET_MARKER.len()..])
            .ok()?;
        if raw.len() < IV + MAC {
            return None;
        }
        let (body, tag) = raw.split_at(raw.len() - MAC);
        crypto::hmac_sha256_verify(self.mac.as_slice(), body, tag).ok()?;
        let iv: [u8; IV] = body[..IV].try_into().ok()?;
        let mut plain = vec![0u8; body.len() - IV];
        crypto::aes_ctr::apply(self.enc.as_slice(), &iv, &body[IV..], &mut plain).ok()?;
        let (head, mut rest) = plain.split_at_checked(2 + 8 + ID)?;
        if head[0] != VERSION {
            return None;
        }
        let flags = head[1];
        let expires_at = u64::from_be_bytes(head[2..10].try_into().ok()?);
        let id: [u8; ID] = head[10..].try_into().ok()?;
        let mut fields: [String; 5] = Default::default();
        for field in &mut fields {
            let (len, tail) = rest.split_at_checked(2)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let (text, tail) = tail.split_at_checked(len)?;
            *field = String::from_utf8(text.to_vec()).ok()?;
            rest = tail;
        }
        if !rest.is_empty() {
            return None;
        }
        let [plugin, name, audience, subject, scope] = fields;
        Some(Opened {
            id,
            expires_at,
            once: flags & 1 != 0,
            has_row: flags & 2 != 0,
            plugin,
            name,
            audience,
            subject,
            scope,
        })
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What `admit` returns for a verified ticket's row: the value as stored.
fn row_record(row: &[u8]) -> Option<&[u8]> {
    match row.split_first() {
        Some((&ROW_FLAG, record)) => Some(record),
        _ => None,
    }
}

impl<R: PluginRecords> Tickets for SealedTickets<R> {
    fn mint<'a>(
        &'a self,
        who: &'a Caller<'_>,
        m: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(async move {
            if m.ttl_s == 0 || !valid_prefix(m.prefix) {
                return Err(RecordsDenied::Invalid);
            }
            if m.record.len() > MAX_RECORD {
                return Err(RecordsDenied::TooLarge);
            }
            let ttl_s = m.ttl_s.min(MAX_TTL_S);
            let expires_at = (self.clock)().saturating_add(ttl_s);
            let id: [u8; ID] = crypto::random::<ID>().map_err(|_| RecordsDenied::Unavailable)?;
            let has_row = m.once || !m.record.is_empty();
            let sealed = self
                .seal(&Opened {
                    id,
                    expires_at,
                    once: m.once,
                    has_row,
                    plugin: who.plugin.to_owned(),
                    name: who.name.to_owned(),
                    audience: m.audience.to_owned(),
                    subject: m.subject.to_owned(),
                    scope: m.scope.to_owned(),
                })
                .ok_or(RecordsDenied::Invalid)?;
            if has_row {
                let mut row = Vec::with_capacity(1 + m.record.len());
                row.push(ROW_FLAG);
                row.extend_from_slice(m.record);
                let name = core_name(who.name, TAG);
                let ns = core_caller(who, &name);
                self.records
                    .put(&ns, Scope::default(), &id, &row, ttl_s)
                    .await?;
            }
            Ok((
                format!("{}{TICKET_MARKER}{sealed}", m.prefix).into(),
                expires_at,
            ))
        })
    }

    fn is_ticket(&self, credential: &str) -> bool {
        let Some(at) = credential.find(TICKET_MARKER) else {
            return false;
        };
        at <= MAX_PREFIX && valid_prefix(&credential[..at])
    }

    fn admit<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(async move {
            if !self.is_ticket(credential) {
                return Err(TicketDenied::Invalid);
            }
            let t = self.open(credential).ok_or(TicketDenied::Invalid)?;
            if t.plugin != plane.plugin || t.name != plane.name || t.audience != audience {
                return Err(TicketDenied::Invalid);
            }
            if now_s >= t.expires_at {
                return Err(TicketDenied::Expired);
            }
            let mut record = None;
            if t.has_row {
                let name = core_name(plane.name, TAG);
                let ns = core_caller(plane, &name);
                let mut row = None::<Vec<u8>>;
                let found = self
                    .records
                    .get(&ns, Scope::default(), &t.id, &mut |v| {
                        row = Some(v.to_vec())
                    })
                    .await
                    .map_err(|_| TicketDenied::Unavailable)?;
                let row = match (found, row) {
                    (true, Some(row)) => row,
                    // A MINT_ONCE row already taken is a replay; a record row that is gone is not a ticket.
                    _ if t.once => return Err(TicketDenied::Replayed),
                    _ => return Err(TicketDenied::Invalid),
                };
                let bytes = row_record(&row).ok_or(TicketDenied::Invalid)?;
                if t.once {
                    // Read and delete in one store commit: exactly one request on any replica wins.
                    let ops = [
                        CommitOp::Equals {
                            key: &t.id,
                            value: &row,
                            caller: false,
                        },
                        CommitOp::Del {
                            key: &t.id,
                            caller: false,
                        },
                    ];
                    match self
                        .records
                        .commit(&ns, Scope::default(), &ops)
                        .await
                        .map_err(|_| TicketDenied::Unavailable)?
                    {
                        CommitOutcome::Applied => {}
                        CommitOutcome::Conflict { .. } => return Err(TicketDenied::Replayed),
                    }
                }
                if !bytes.is_empty() {
                    record = Some(SecureVec::from(bytes));
                }
            }
            Ok(TicketAdmitted {
                identity: Identity::from_ticket(&t.subject, &t.scope),
                record,
            })
        })
    }
}
