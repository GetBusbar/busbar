// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 auth chain walk with the verdict cache wired in (IF §12.11, §12.28 rules 1, 4 and 6). For each
//! instance of the route's effective chain, in chain order: an eligible instance (rule 1) asks the cache first
//! (a hit answers without calling the plugin; a standing lead is followed and its outcome shared; otherwise this
//! request leads, verifies and settles); an ineligible one verifies unshared. The first identity admits,
//! NOT_MINE moves on, a rejection or a port error ends the walk, and all NOT_MINE is "no identity".

use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::issued::IssuedCredentials;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use busbar_contract::crypto::Sha256;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::BAD_CREDENTIAL;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::types::Pair;
use busbar_plugin_abi::types::{Bytes, Str};
use busbar_ports::auth::{AuthIn, AuthPort, Identity, Verify, VerifyAnswer};
use busbar_ports::{CallCx, PortError};

use super::verdicts::{eligible, CredentialHash, VerdictCache, VerdictGet, VerdictKey};

/// One instance of a route's effective chain: its auth instance id (the verdict cache's key) and its port.
#[derive(Clone, Copy)]
pub struct ChainInstance<'a> {
    pub id: u64,
    pub port: &'a dyn AuthPort,
    pub caller: &'a Caller<'a>,
    pub keys: &'a KeyRefresh,
    pub holds: &'a [std::sync::Arc<crate::directory::HoldSet>],
}

/// A kernel decision, after host policy. Never part of the plugin port vocabulary.
#[derive(Clone, Debug)]
pub enum Verdict {
    Identity(Identity),
    NotMine,
    Held,
    PolicyRejected { code: u32 },
    Rejected { code: u32, text: Box<str> },
}

/// Complete policy for this invocation. The epoch covers its route, bindings and serving generation.
pub trait IdentityPolicy: Send + Sync {
    fn epoch(&self) -> u64;
    fn authorize(&self, instance: u64, identity: &Identity, req: &AuthIn<'_>) -> Result<(), u32>;
}

/// Kernel-owned decision services, supplied complete before the auth walk starts.
pub struct AuthServices<'a> {
    pub issued: &'a dyn IssuedCredentials,
    pub replay: &'a dyn ReplayGuard,
    pub policy: &'a dyn IdentityPolicy,
}

/// How a walk ended.
#[derive(Debug)]
pub enum ChainEnd {
    /// The first identity of the chain.
    Admitted {
        instance: u64,
        identity: Identity,
    },
    /// Every instance answered NOT_MINE (or the chain is empty): R_AUTH_REQUIRED.
    NoIdentity,
    /// An instance refused the credential; `code` is the plugin's (a kind code core maps before any client
    /// sees it, §12.15). The plugin's text goes to audit only.
    Rejected {
        instance: u64,
        code: u32,
        text: Box<str>,
    },
    /// CA-5: the identity is held by a provisioning instance that links this inbound instance: R_DENIED, no plugin
    /// is asked (the principal-held audit is the caller's). Checked after the verdict, so a cached identity is
    /// held the same.
    Held {
        instance: u64,
    },
    PolicyRejected {
        instance: u64,
        code: u32,
    },
    /// An instance failed (FAILED or a call error).
    Failed {
        instance: u64,
        error: PortError,
    },
}

/// `VerdictKey.credential` (§12.28): SHA-256, through the facade, over, for each D_CRED_HEADER name in declared
/// order, the u32 LE name length, the name, the u32 LE count of that header's values on the request and each
/// value with its u32 LE length. No allocation.
#[must_use]
pub fn credential_hash(cred_headers: &[Box<str>], headers: &[Pair<'_>]) -> [u8; 32] {
    let mut h = Sha256::new();
    for name in cred_headers {
        h.update(&len_le(name.len()));
        h.update(name.as_bytes());
        let values = || {
            headers
                .iter()
                .filter(|p| p.name.get().eq_ignore_ascii_case(name))
        };
        h.update(&len_le(values().count()));
        for pair in values() {
            let value = pair.value.get();
            h.update(&len_le(value.len()));
            h.update(value);
        }
    }
    h.finish()
}

fn len_le(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes()
}

/// Runs the effective chain over one request.
pub fn run_chain<'a>(
    services: &'a AuthServices<'a>,
    cache: &'a dyn VerdictCache,
    chain: &'a [ChainInstance<'a>],
    cx: CallCx,
    req: &AuthIn<'_>,
) -> impl std::future::Future<Output = ChainEnd> + Send + 'a {
    run_owned_chain(services, cache, chain, cx, Request::new(req))
}

/// The same walk for a consumer retaining its own ports and callers. Snapshot before constructing
/// the future so borrowed ABI request views never cross a suspension point.
pub async fn run_owned_chain<'a>(
    services: &'a AuthServices<'a>,
    cache: &'a dyn VerdictCache,
    chain: &'a [ChainInstance<'a>],
    cx: CallCx,
    req: Request,
) -> ChainEnd {
    for instance in chain {
        match verify_owned(services, cache, *instance, cx, &req).await {
            Ok(Verdict::Identity(identity)) => {
                return ChainEnd::Admitted {
                    instance: instance.id,
                    identity,
                };
            }
            Ok(Verdict::Held) => {
                return ChainEnd::Held {
                    instance: instance.id,
                }
            }
            Ok(Verdict::PolicyRejected { code }) => {
                return ChainEnd::PolicyRejected {
                    instance: instance.id,
                    code,
                }
            }
            Ok(Verdict::NotMine) => {}
            Ok(Verdict::Rejected { code, text }) => {
                return ChainEnd::Rejected {
                    instance: instance.id,
                    code,
                    text,
                }
            }
            Err(error) => {
                return ChainEnd::Failed {
                    instance: instance.id,
                    error,
                }
            }
        }
    }
    ChainEnd::NoIdentity
}

/// One instance's verdict through the cache (§12.28 rule 4). A KEYS_STALE answer flushes the instance (rule 6).
pub fn verify_cached<'a>(
    services: &'a AuthServices<'a>,
    cache: &'a dyn VerdictCache,
    instance: ChainInstance<'a>,
    cx: CallCx,
    req: &AuthIn<'_>,
) -> impl std::future::Future<Output = Result<Verdict, PortError>> + Send + 'a {
    let req = Request::new(req);
    async move { verify_owned(services, cache, instance, cx, &req).await }
}

async fn verify_owned(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &Request,
) -> Result<Verdict, PortError> {
    let verdict = prepare_owned(services, cache, instance, cx, req).await?;
    finish(services, instance, req, verdict).await
}

/// Verification only. This result carries no route authority or replay admission. Every recipient
/// must perform its own final admission; cache followers share only the raw verification result.
pub async fn prepare_owned(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &Request,
) -> Result<Verdict, PortError> {
    prepare_request(services, cache, instance, cx, req).await
}

/// Native preparation retains the original charged snapshot and uses the same verification/cache core.
/// A failed view reservation refuses before calling the port; it creates no replay or route authority.
pub async fn prepare_snapshot(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &ChargedRequestSnapshot,
) -> Result<Verdict, PortError> {
    prepare_request(services, cache, instance, cx, req).await
}

trait RequestView: Sync {
    fn now_s(&self) -> u64;
    fn with_view<R>(&self, f: impl FnOnce(&AuthIn<'_>) -> R) -> Result<R, PortError>;
}

impl RequestView for Request {
    fn now_s(&self) -> u64 {
        self.now_s
    }
    fn with_view<R>(&self, f: impl FnOnce(&AuthIn<'_>) -> R) -> Result<R, PortError> {
        Ok(self.view(f))
    }
}

impl RequestView for ChargedRequestSnapshot {
    fn now_s(&self) -> u64 {
        self.now_s()
    }
    fn with_view<R>(&self, f: impl FnOnce(&AuthIn<'_>) -> R) -> Result<R, PortError> {
        self.with_auth_input(f).map_err(Into::into)
    }
}

async fn prepare_request(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &impl RequestView,
) -> Result<Verdict, PortError> {
    let verdict = cached_raw(services, cache, instance, cx, req).await?;
    if let Verdict::Identity(id) = &verdict {
        if crate::holds::held_by(Some(instance.holds), id.subject()).is_some() {
            return Ok(Verdict::Held);
        }
        if id.subject().is_empty() || id.expires_at_s().is_some_and(|until| req.now_s() >= until) {
            return Ok(rejected(BAD_CREDENTIAL));
        }
    }
    Ok(verdict)
}

async fn cached_raw(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &impl RequestView,
) -> Result<Verdict, PortError> {
    let port = instance.port;
    if !eligible(port.cred_headers().len(), port.facts()) {
        return settle(services, cache, instance, cx, req).await;
    }
    let key = VerdictKey {
        auth_instance: instance.id,
        policy_epoch: services.policy.epoch(),
        credential: CredentialHash(
            req.with_view(|req| credential_hash(port.cred_headers(), req.headers))?,
        ),
    };
    let lead = match cache.begin(key, req.now_s()) {
        VerdictGet::Hit(identity) => return Ok(Verdict::Identity(identity)),
        VerdictGet::Bypass => return settle(services, cache, instance, cx, req).await,
        VerdictGet::Lead(lead) => lead,
        VerdictGet::Follow(follow) => match follow.await {
            Ok(shared) => return shared,
            Err(lead) => lead,
        },
    };
    let outcome = settle(services, cache, instance, cx, req).await;
    lead.settle(&outcome, req.now_s());
    outcome
}

/// Rule 6: a `refresh` that completed OK (scheduled, or after KEYS_STALE) drops every entry of the instance.
pub fn refreshed(
    cache: &dyn VerdictCache,
    auth_instance: u64,
    result: &Result<Option<u32>, PortError>,
) {
    if result.is_ok() {
        cache.flush_instance(auth_instance);
    }
}

async fn verify(
    port: &dyn AuthPort,
    cx: CallCx,
    req: &impl RequestView,
    issued: Option<&[u8]>,
) -> Result<VerifyAnswer, PortError> {
    match req.with_view(|req| port.verify(cx, req, issued))? {
        Verify::Done(done) => done,
        Verify::Io(io) => io.await,
    }
}

fn rejected(code: u32) -> Verdict {
    Verdict::Rejected {
        code,
        text: "auth admission refused".into(),
    }
}

async fn settle(
    services: &AuthServices<'_>,
    cache: &dyn VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &impl RequestView,
) -> Result<Verdict, PortError> {
    let mut issued = None;
    let mut refreshed_once = false;
    loop {
        match verify(instance.port, cx, req, issued.as_deref()).await? {
            VerifyAnswer::Identity(id) => {
                return Ok(Verdict::Identity(id));
            }
            VerifyAnswer::NotMine => return Ok(Verdict::NotMine),
            VerifyAnswer::Refused { code, text } => return Ok(Verdict::Rejected { code, text }),
            VerifyAnswer::IssuedWanted(id) => {
                let Some(kind) = instance.port.issued_kind().filter(|_| issued.is_none()) else {
                    return Ok(rejected(BAD_CREDENTIAL));
                };
                issued = Some(services.issued.lookup(instance.id, kind, &id).await);
            }
            VerifyAnswer::KeysStale => {
                cache.flush_instance(instance.id);
                if refreshed_once {
                    return Ok(rejected(BAD_CREDENTIAL));
                }
                refreshed_once = true;
                let Some(refresh) = instance.keys.refresh(instance.port, cx) else {
                    return Ok(rejected(BAD_CREDENTIAL));
                };
                refresh.await?;
                cache.flush_instance(instance.id);
            }
        }
    }
}

/// Policy is checked for every recipient of a cached/shared decision. Replay is the final operation,
/// outside the single-flight result, so followers each compete for the atomic claim themselves.
async fn finish(
    services: &AuthServices<'_>,
    instance: ChainInstance<'_>,
    req: &Request,
    verdict: Verdict,
) -> Result<Verdict, PortError> {
    let Verdict::Identity(id) = verdict else {
        return Ok(verdict);
    };
    if crate::holds::held_by(Some(instance.holds), id.subject()).is_some() {
        return Ok(Verdict::Held);
    }
    if let Err(code) = req.view(|req| services.policy.authorize(instance.id, &id, req)) {
        return Ok(Verdict::PolicyRejected { code });
    }
    if let Some((key, ttl_s)) = id.replay() {
        match services.replay.claim(instance.caller, key, ttl_s).await {
            Ok(true) => {}
            Ok(false) => return Ok(rejected(busbar_plugin_abi::fail::refused::R_REPLAYED)),
            Err(_) => {
                return Err(PortError::Failed {
                    code: busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
                    text: "replay guard unavailable".into(),
                    retry_after_s: None,
                    backend_status: None,
                    error: None,
                })
            }
        }
    }
    Ok(Verdict::Identity(id))
}

/// A request snapshot owns every carrier before any await. ABI Pair views are rebuilt only for
/// synchronous port entry and policy checks, and never cross a suspension point.
pub struct Request {
    method: String,
    path: String,
    query: String,
    authority: String,
    headers: Vec<(String, SecureVec)>,
    peer: String,
    tls_peer_cert: SecureVec,
    body: SecureVec,
    now_s: u64,
}
impl Drop for Request {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.method.zeroize();
        self.path.zeroize();
        self.query.zeroize();
        self.authority.zeroize();
        self.peer.zeroize();
    }
}
impl Request {
    pub fn new(req: &AuthIn<'_>) -> Self {
        let copy = |bytes: &[u8]| {
            let mut out = SecureVec::new();
            out.extend_from_slice(bytes);
            out
        };
        Self {
            method: req.method.into(),
            path: req.path.into(),
            query: req.query.into(),
            authority: req.authority.into(),
            headers: req
                .headers
                .iter()
                .map(|pair| (pair.name.get().into(), copy(pair.value.get())))
                .collect(),
            peer: req.peer.into(),
            tls_peer_cert: copy(req.tls_peer_cert),
            body: copy(req.body),
            now_s: req.now_s,
        }
    }
    pub fn view<R>(&self, f: impl FnOnce(&AuthIn<'_>) -> R) -> R {
        let headers: Vec<Pair<'_>> = self
            .headers
            .iter()
            .map(|(name, value)| Pair {
                name: Str::new(name),
                value: Bytes::new(value),
            })
            .collect();
        f(&AuthIn {
            method: &self.method,
            path: &self.path,
            query: &self.query,
            authority: &self.authority,
            headers: &headers,
            peer: &self.peer,
            tls_peer_cert: &self.tls_peer_cert,
            body: &self.body,
            now_s: self.now_s,
        })
    }
}

#[cfg(test)]
#[path = "tests/chain_policy_tests.rs"]
mod policy_tests;
