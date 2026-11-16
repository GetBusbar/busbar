// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Entitlements, tickets, host signing, signed ingress, replay claims and the KEYS_STALE refresh policy (IF §12.11).
//! The frozen contract is below; W1-K10's implementations: [`RequestGrants`] (entitle.rs), [`SealedTickets`]
//! (tickets.rs), [`CoreJwsSigner`] (signer.rs), [`KeyRefresh`] (refresh.rs). The signed-ingress verifier and the
//! replay guard live in `crate::ingress` (`signed_ingress`, `replay`).

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::types::Pair;
use busbar_plugin_loader::ports::auth::Identity;

use crate::plugin_records::RecordsDenied;

mod entitle;
mod refresh;
mod signer;
mod tickets;

pub use entitle::{GrantResolver, RequestGrants};
pub use refresh::KeyRefresh;
pub use signer::CoreJwsSigner;
pub use tickets::{SealedTickets, TICKET_MARKER};

/// A core-owned sub-namespace of `who`'s records namespace: (who.plugin, who.name, `tag`) (IF §12.11 "CoreStore
/// namespace (who.plugin, who.name, "ticket")"). The tag rides in the configured-name half after a NUL, which no
/// configured instance name holds, so a plugin's own RECORD/STORE namespace never reaches these rows.
pub(crate) fn core_name(name: &str, tag: &str) -> String {
    let mut out = String::with_capacity(name.len() + 1 + tag.len());
    out.push_str(name);
    out.push('\0');
    out.push_str(tag);
    out
}

/// `who` re-addressed at its core sub-namespace `name` (from [`core_name`]).
pub(crate) fn core_caller<'a>(who: &Caller<'a>, name: &'a str) -> Caller<'a> {
    Caller { name, ..*who }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// ENTITLE. The grant set of the verified principal (or ticket) is resolved once per request by the existing
/// entitlement code (today's `entitlement.check` service) and cached on the request; `check` is a lookup.
pub trait Entitlements: Send + Sync + 'static {
    fn check(&self, who: &Caller<'_>, identity: &[u8], grant: &str) -> bool;
}
/// MINT and AUTH_TICKET routes. A ticket is sealed with a core key (AEAD_SEAL through busbar-crypto, key in
/// custody, shared by every replica), binds (plane plugin, plane instance **name**, ticket id, subject, scope,
/// audience, expiry, once), and is accepted only on an AUTH_TICKET route of an instance with the same plugin and
/// name and a matching audience, on any replica and after a restart or reconfigure. Replaces streaming's
/// CLAIM_TICKET / `ticket.mint` / `ticket.take` (contract abi/host/service.rs `TicketMintIn`, `TicketTakeIn`) and
/// a2a's push capability tokens. **Round 15: the record and single use are core's again**, as today: a ticket
/// that is MINT_ONCE or carries a record has one row in CoreStore namespace (who.plugin, who.name, "ticket"),
/// keyed by the ticket id, TTL = the ticket's life, holding the record bytes (possibly empty).
/// The client-facing text is `<MT_PREFIX><core marker "bbt1."><base64url sealed body>`.
pub struct TicketMint<'a> {
    pub subject: &'a str,
    pub scope: &'a str,
    pub audience: &'a str,
    pub ttl_s: u64,
    /// MINT_ONCE.
    pub once: bool,
    /// MT_PREFIX ("" when absent); validated by the plane adapter (≤ 16 bytes, `[A-Za-z0-9_-]`).
    pub prefix: &'a str,
    /// MT_RECORD (empty when absent), ≤ MAX_TICKET_RECORD.
    pub record: &'a [u8],
}
/// The admitted ticket (IF §12.11). W1-K10: the IF's `record` type is `zeroize::Zeroizing<Vec<u8>>`, which core
/// bans (clippy-crate-wide disallowed-types, LR-094); it is its named replacement `SecureVec`, as for every other
/// W0-ABI secret value.
pub struct TicketAdmitted {
    pub identity: Identity,
    pub record: Option<busbar_contract::secure::SecureVec>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketDenied {
    /// The seal does not open, or plugin/name/audience do not match (R_BAD_CREDENTIAL).
    Invalid,
    /// R_EXPIRED.
    Expired,
    /// A MINT_ONCE ticket already admitted a request, on any replica (R_REPLAYED, audit `ticket_replay`).
    Replayed,
    /// The store could not be reached: refuse, fail closed (R_DENIED with core's text, audited).
    Unavailable,
}
pub trait Tickets: Send + Sync + 'static {
    /// MINT. Seals the ticket; when `once` or `record` is non-empty, writes its row first and answers only
    /// after the write is durable (today's "may pend until durably published").
    fn mint<'a>(
        &'a self,
        who: &'a Caller<'_>,
        m: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64 /*expires_at_s*/), RecordsDenied>>;
    /// Pure and sync, no crypto and no store: the credential holds core's ticket marker `bbt1.` right after a
    /// prefix of ≤ 16 bytes of `[A-Za-z0-9_-]`. Used only to classify a request on a PRINCIPAL+TICKET route.
    fn is_ticket(&self, credential: &str) -> bool;
    /// AUTH_TICKET admission. Opens the seal and checks plugin, name, audience and expiry; then: `once` =>
    /// one atomic take of the row (read and delete in one store commit; no row => Replayed), so exactly one
    /// request on any replica is admitted; not once but with a row => read it. The record (if any) becomes
    /// `PlaneReq.ticket_record`.
    fn admit<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        audience: &'a str,
        credential: &'a str,
        now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>>;
}
/// SIGN. The host's signing key (the existing notary/stamp signer seam, CRYPTO-SEAM §2.6 `Signer`), so keys may
/// live in KMS/HSM. Core picks alg and kid. Never available to a plugin as key bytes.
pub trait HostSigner: Send + Sync + 'static {
    fn sign_jws<'a>(
        &'a self,
        who: &'a Caller<'_>,
        payload: &'a [u8],
        detached: bool,
    ) -> BoxFut<'a, Result<SignedJws, RecordsDenied>>;
}
pub enum SignedJws {
    Compact(Box<str>),
    Detached {
        protected: Box<str>,
        signature: Box<str>,
    },
}
/// AUTH_SIGNED_INGRESS. Verifies the inbound request's signature with the route's configured secret (custody)
/// under Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`; HMAC-SHA256 via the facade;
/// 5-minute tolerance). Today's plane-llm `exchange/webhook.rs` verifier moves here.
/// A verified request is admitted only after `ReplayGuard::claim(plane, "standard-webhooks/<ts>/<id>", 300)` wins.
pub trait IngressVerifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        route_secret: &'a busbar_contract::secret_ref::SecretRef,
        headers: &'a [Pair<'a>],
        body: &'a [u8],
        now_s: u64,
    ) -> BoxFut<'a, bool>;
}
/// Replay claims (auth REPLAY answers, signed ingress). One atomic put-if-absent in the CoreStore namespace
/// (who.plugin, who.name, "replay"), visible to every replica, ttl clamped 1..=86_400 s. Ok(true) = first
/// sighting (admit); Ok(false) = replay (refuse R_REPLAYED, audit `auth_replay`). Unavailable => refuse
/// (fail closed). Owner K10.
pub trait ReplayGuard: Send + Sync + 'static {
    fn claim<'a>(
        &'a self,
        who: &'a Caller<'_>,
        key: &'a [u8],
        ttl_s: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>>;
}
