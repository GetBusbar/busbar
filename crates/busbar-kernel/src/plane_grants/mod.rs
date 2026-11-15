// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Entitlements, tickets, host signing, signed ingress, replay claims and the KEYS_STALE refresh policy (IF §12.11). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K10 fills it.

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::types::Pair;

use crate::plugin_records::RecordsDenied;

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
// W0-ABI: `TicketAdmitted { identity: Identity, record: Option<Zeroizing<Vec<u8>>> }` names `Identity`, a
// busbar-plugin-loader type (IF §11.3 auth); the kernel does not depend on the loader in wave 0. W1-K10 adds it
// (and `Tickets::admit`, below) with that dependency.
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
    // W0-ABI: `admit<'a>(&'a self, plane: &'a Caller<'_>, audience: &'a str, credential: &'a str, now_s: u64)
    // -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>>` returns `TicketAdmitted` (see above); W1-K10 adds it
    // with its IF doc lines once the kernel depends on plugin-loader.
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
/// KEYS_STALE handling, owned by the auth adapter (L5) with this core policy: per auth instance, at most one
/// `refresh` in flight (later KEYS_STALE verifies await the same one), and at most one started per
/// `min_interval` (config `auth.unknown_key_refresh_s`, default 30 s, min 5 s). After it completes, the verify
/// runs once more; a second KEYS_STALE or a declined refresh => `Verdict::Rejected { code: BAD_CREDENTIAL }`.
pub struct KeyRefresh {
    // W0-ABI: private fields (last_started: AtomicU64 (mono s), inflight: tokio::sync::OnceCell per round) land with
    // W1-K10.
    _stub: (),
}
impl KeyRefresh {
    pub fn new(min_interval: std::time::Duration) -> Self {
        let _ = min_interval;
        todo!()
    }
    // W0-ABI: `refresh<'a>(&'a self, port: &'a dyn AuthPort, cx: CallCx) -> Option<BoxFut<'a, Result<(),
    // PortError>>>` (doc: "Some(fut) = run or join the single-flight refresh; None = declined by the rate
    // limit.") names `AuthPort`, `CallCx` and `PortError`, busbar-plugin-loader types (IF §11.3); W1-K10 adds it
    // once the kernel depends on the loader.
}
