// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth port (IF §11.3) and `IssuedShape` (IF §12.8: it lives in plugin-loader and the kernel re-exports
//! it). W0-ABI stub: frozen signatures, `todo!()` bodies; L5 fills it.

use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::types::Pair;

use crate::ports::{CallCx, PortError};

// W0-ABI: the IF types the secret bytes of `LoginAnswer` and `OutboundAnswer` as `zeroize::Zeroizing<Vec<u8>>`;
// the workspace bans `Zeroizing` crate-wide (clippy-crate-wide/clippy.toml, owner 2026-11-14), so the stub uses
// its named replacement `busbar_contract::secure::SecureVec`.

/// authority = h2/h3 `:authority`, else the h1 `Host` value (AuthReq.authority, Q_AUTHORITY); core fills it from
/// the request it parsed, once per request, alongside `headers`.
pub struct AuthIn<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub authority: &'a str,
    pub headers: &'a [Pair<'a>],
    pub peer: &'a str,
    pub tls_peer_cert: &'a [u8],
    pub body: &'a [u8],
    pub now_s: u64,
}

/// The verified answer, kept as its record bytes: one allocation (the Arc) per uncached verify, none on a
/// verdict-cache hit (this is the cache value; round 23: the kernel `VerdictCache`, §12.28, rules 1-6). `identity_records()` is passed unchanged as
/// `PlaneIn::identity` and into hook views (generic ID_* tags, so no re-encode).
#[derive(Clone, Debug)]
pub struct Identity {
    recs: Arc<[u8]>,
    id_len: u32,
    cache_s: Option<u32>,
    expires_at_s: Option<u64>,
    replay: Option<(Box<[u8]>, u64)>,
}

impl Identity {
    /// The contiguous ID_SUBJECT, ID_GROUP*, ID_CLAIM* prefix (the adapter validates it is first and contiguous).
    pub fn identity_records(&self) -> &[u8] {
        let _ = (&self.recs, self.id_len);
        todo!()
    }

    /// Lazy typed accessors over the same bytes (policy, audit). No allocation.
    pub fn subject(&self) -> &str {
        let _ = &self.recs;
        todo!()
    }

    pub fn groups(&self) -> impl Iterator<Item = &str> {
        let _ = &self.recs;
        // W0-ABI stub value; L5 replaces it.
        core::iter::empty()
    }

    pub fn claims(&self) -> impl Iterator<Item = (&str, &[u8])> {
        let _ = &self.recs;
        // W0-ABI stub value; L5 replaces it.
        core::iter::empty()
    }

    pub fn strip(&self) -> impl Iterator<Item = &str> {
        let _ = &self.recs;
        // W0-ABI stub value; L5 replaces it.
        core::iter::empty()
    }

    /// None when the answer carried REPLAY (never verdict-cached), else F_CACHE_S.
    pub fn cache_s(&self) -> Option<u32> {
        let _ = self.cache_s;
        todo!()
    }

    pub fn expires_at_s(&self) -> Option<u64> {
        let _ = self.expires_at_s;
        todo!()
    }

    /// The REPLAY claim (key, ttl_s). The adapter has already claimed it (§12.11 `ReplayGuard`) before
    /// returning `Verdict::Identity`; a lost claim is returned as `Rejected { code: R_REPLAYED }`.
    pub fn replay(&self) -> Option<(&[u8], u64)> {
        let _ = &self.replay;
        todo!()
    }

    /// Built by core for a verified ticket (§12.11): ID_SUBJECT = the ticket subject, ID_CLAIM `scope`.
    pub fn from_ticket(subject: &str, scope: &str) -> Identity {
        let _ = (subject, scope);
        todo!()
    }
}

/// Round 24: Clone, so a verdict-cache lead hands its outcome to its followers (§12.28 rule 4).
#[derive(Clone, Debug)]
pub enum Verdict {
    Identity(Identity),
    NotMine,
    Rejected { code: u32, text: Box<str> },
}

/// Sync plugins finish without boxing; verify_io plugins, sync plugins that answered ISSUED_WANTED (the
/// adapter looks the credential up through IssuedCredentials §12.8 and calls verify again), sync answers with
/// REPLAY (the claim is a store round trip), and KEYS_STALE refusals (single-flight `refresh`, then verify once
/// more; rate limit and single-flight owned by the adapter's `KeyRefresh` state, §12.11) return the box.
pub enum Verify<'a> {
    Done(Result<Verdict, PortError>),
    Io(BoxFut<'a, Result<Verdict, PortError>>),
}

pub enum LoginIn<'a> {
    /// Round 22: code_challenge, nonce and code_verifier are core-minted (L_CODE_CHALLENGE, L_NONCE, L_CODE_VERIFIER).
    Begin {
        return_to: &'a str,
        redirect_uri: &'a str,
        state_key: &'a str,
        code_challenge: &'a str,
        nonce: &'a str,
        connect: Option<&'a str>,
        scope: Option<&'a str>,
    },
    Complete {
        callback_query: &'a str,
        state: &'a [u8],
        redirect_uri: &'a str,
        code_verifier: &'a str,
        nonce: &'a str,
        connect: Option<&'a str>,
    },
    Credential {
        username: &'a str,
        password: &'a [u8],
    },
}

pub enum LoginAnswer {
    Redirect {
        url: Box<str>,
        state: SecureVec,
    },
    Identity(Identity),
    /// COMPLETE of a caller connection (L_CONNECT): the grant blob core keeps (§12.12).
    Grant(SecureVec),
}

/// caller_cred = the inbound credential header(s) core verified for this request, set only when the route
/// enables passthrough and the outbound plugin declared FB_PASSTHROUGH (encoded as O_CALLER_CRED*).
/// scope = the plane's UP_SCOPE for this exchange (O_SCOPE), round 22: Some only for a STYLE_SCOPE binding.
/// caller_grant = the verified caller's stored grant for this upstream when the binding is caller-mode
/// (`UpstreamAuth.caller`, STYLE_CALLER) and core holds one (O_CALLER_GRANT).
pub struct UpstreamIn<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [Pair<'a>],
    pub body_sha256: Option<[u8; 32]>,
    pub caller_cred: &'a [Pair<'a>],
    pub scope: Option<&'a str>,
    pub caller_grant: Option<&'a [u8]>,
}

pub struct OutboundAnswer {
    pub headers: Vec<(Box<str>, SecureVec)>,
    pub query: Vec<(Box<str>, SecureVec)>,
    pub cache_s: u32,
    pub grant_update: Option<SecureVec>,
}

pub trait AuthPort: Send + Sync + 'static {
    fn facts(&self) -> u64;
    fn cred_headers(&self) -> &[Box<str>];
    /// D_ISSUED_KIND, if declared.
    fn issued_kind(&self) -> Option<&str>;
    fn verify<'a>(&'a self, cx: CallCx, req: &'a AuthIn<'a>) -> Verify<'a>;
    fn login<'a>(
        &'a self,
        cx: CallCx,
        step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>>;
    fn outbound<'a>(
        &'a self,
        cx: CallCx,
        req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>>;
    fn refresh<'a>(&'a self, cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>>;
    /// Round 29 (FB_PROVISION only; otherwise `Err(Refused { code: R_UNSUPPORTED, .. })` without a call). `req` is the request
    /// K8 routed from `/provision/<instance>/*` after its own client check (§12.29); headers already stripped.
    fn serve<'a>(
        &'a self,
        cx: CallCx,
        req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>>;
}

/// Round 29. `path` = the path below the mount; `client` = the matched `provisioning.clients` name.
pub struct ServeIn<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a [u8])],
    pub body: &'a [u8],
    pub client: &'a str,
}

pub struct ServeOut {
    pub status: u16,
    pub headers: Vec<(Box<str>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Round 12: the shape core mints for one issued kind, from that kind's declaring auth plugin's D_ISSUED_SHAPE
/// (§8.3), via `Registry::issued_shapes` (§11.2). Field-for-field today's busbar-contract `IssuedShape`
/// (auth_calls.rs:285-306), which it replaces; it lives in plugin-loader and the kernel re-exports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuedShape {
    pub id_prefix: Box<str>,
    pub id_len: usize,
    pub id_alphabet: Box<str>,
    pub secret_len: usize,
    pub secret_alphabet: Box<str>,
}
