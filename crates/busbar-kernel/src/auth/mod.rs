// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_AUTH_CHAIN_EMPTY, ADMIN_CHAIN_STALLED,
    ADMIN_FORBIDDEN_SUPPRESSED, ADMIN_MODULE_UNRESOLVED, ADMIN_OFFLOAD_SATURATED,
    AUTH_CHAIN_PANICKED, AUTH_OFFLOAD_SATURATED, KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
};
use crate::state::App;
use busbar_contract::auth_calls::{
    AuthCalls, Replay, Strip, StripPlace, Verified, VerifyAnswer, VerifyRequest,
};
use busbar_kernel_identity::operator::Judgement;

mod admin_sender_constraint;
mod admitted;
pub mod effect;
pub mod native_admin;
pub mod native_chain;
pub mod native_data;
pub mod native_policy;
pub mod relend;
pub mod verdicts;
#[cfg(test)]
use crate::off_path::auth::chain::admin_head;
pub(crate) use crate::off_path::auth::chain::auth_refusal;
use crate::off_path::auth::chain::{
    admin_door_of_key, admin_head_with, admin_keys_arm, admin_verbs_named, module_scope_cap,
};
pub use admitted::{admitted_context, AdmittedContext, AdmittedRefusal};

const AUTH_SCHEME_BEARER: &str = "bearer";

pub const HEALTHZ_PATH: &str = "/healthz";
pub const LIVEZ_PATH: &str = "/livez";
pub const READYZ_PATH: &str = "/readyz";

pub const ADMIN_PATH: &str = "/api";

const ADMIN_PATH_PREFIX: &str = "/api/";

pub use busbar_contract::config::UpstreamCreds;

pub use busbar_contract::auth::CallerToken;

pub use busbar_contract::auth::{AuthVerdict, Principal};

mod signed_request;
pub use signed_request::SignedRequestAuthority;

/// The whole CHAIN's verdict for one request: admitted-with-identity, admitted-anonymously (the
/// empty-chain open front door), or denied. Distinct from the per-module [`AuthVerdict`] so the
/// middleware can attach the principal (or its absence) to the request.
///
/// NOT `Eq`: the engine-only `resolved` `VirtualKey` is `PartialEq` but not `Eq` (its `Debug` is a
/// hand-written, credential-redacting impl in `busbar-api`).
#[derive(Debug, Clone, PartialEq)]
pub enum ChainVerdict {
    /// Admitted with identity: the IDENTITY PROVIDER that identified + the principal.
    ///
    /// 1.5.3: `module` carries the PROVIDER NAME (the `identity-providers:` key), not the backing
    /// plugin's own reported name. That is the identity `role_bindings.<name>` binds and
    /// `auth_scope_caps` keys off — so two NAMED providers sharing one plugin module (the whole point
    /// of the named-definition pattern) get INDEPENDENT bindings and ceilings instead of
    /// silently collapsing onto the plugin's single self-reported name.
    Identified {
        module: String,
        principal: Principal,
        /// ENGINE-ONLY resolved governance key. Populated ONLY by engine arms (the built-in `keys`
        /// verifier and the ingress-protocol AWS SigV4 request-signing pre-step), which authenticate
        /// a busbar-MINTED credential
        /// and can therefore hand back the enforced [`VirtualKey`]. ALWAYS `None` for a plugin
        /// module: the plugin ABI ([`AuthVerdict`]) can only `Identify(Principal)` — it can never
        /// construct a `VirtualKey`. When `Some`, enforcement rides it directly and the role-binding
        /// synth is skipped (`resolved.or_else(synth)`). This field is never plugin-facing.
        resolved: Option<std::sync::Arc<crate::governance::VirtualKey>>,
        /// Only the real signed keys arm can mint this take-once request occurrence.
        signed_authority: Option<SignedRequestAuthority>,
    },
    Open,
    Denied,
}

pub struct AuthMiddleware {
    pub keys_in_chain: bool,

    pub(crate) chain: Vec<ChainEntry>,

    pub(crate) readers: Vec<CredentialReader>,

    /// Each configured carrier header name to the first reader (index into `readers`) it
    /// carries for, built with the readers: a request finds its reader by the lines it holds.
    pub(crate) reader_by_carrier: foldhash::HashMap<HeaderName, usize>,

    pub(crate) carriers: Vec<HeaderName>,

    pub(crate) issued: Option<(String, busbar_contract::auth_calls::IssuedShape)>,
}

pub(crate) struct CredentialReader {
    pub(crate) name: std::sync::Arc<str>,
    pub(crate) calls: std::sync::Arc<dyn AuthCalls>,
    pub(crate) kinds: std::sync::Arc<[String]>,

    pub(crate) issued: Option<busbar_contract::auth_calls::IssuedShape>,
}

pub(crate) struct ChainEntry {
    pub(crate) provider: String,

    pub(crate) calls: std::sync::Arc<dyn AuthCalls>,

    pub(crate) name: String,
}

/// A credential reader the signed path hands on: its name, its calls and the kinds it verifies.
pub(crate) type SignedReader = (
    std::sync::Arc<str>,
    std::sync::Arc<dyn AuthCalls>,
    std::sync::Arc<[String]>,
);

fn chain_verdict_of(answer: VerifyAnswer) -> Judgement {
    Judgement::answered(answer)
}

fn chain_position_verdict(module: &str, verdict: AuthVerdict) -> Option<ChainVerdict> {
    match verdict {
        AuthVerdict::Identify(principal) => Some(ChainVerdict::Identified {
            module: module.to_string(),
            principal,
            resolved: None,
            signed_authority: None,
        }),
        AuthVerdict::Reject => Some(ChainVerdict::Denied),
        AuthVerdict::Pass => None,
    }
}

fn complete_chain(verdict: Option<ChainVerdict>) -> ChainVerdict {
    verdict.unwrap_or(ChainVerdict::Denied)
}

fn deny_unavailable_chain(verdict: Result<ChainVerdict, VerifierUnavailable>) -> ChainVerdict {
    verdict.unwrap_or(ChainVerdict::Denied)
}

fn refused_keeping_strips(answer: VerifyAnswer) -> Judgement {
    Judgement {
        strips: answer.strips,
        ..Judgement::of(AuthVerdict::Reject)
    }
}

fn verify_without_verdict(plane: &'static str, provider: &str, kind: &'static str) {
    if tripped(&NO_VERDICT_WARNED) {
        tracing::warn!(
            plane,
            provider,
            kind,
            "auth verify answered no verdict (a module failure); refusing the request 503 with \
             Retry-After (fail-closed), not 401: the caller's credential was not judged"
        );
    } else {
        tracing::debug!(
            plane,
            provider,
            kind,
            "auth verify answered no verdict (a module failure); refusing the request 503 with \
             Retry-After (fail-closed), not 401: the caller's credential was not judged"
        );
    }
}

pub(crate) const AUTH_REPLAY_OWNER: &str = "busbar.auth-replay";
pub(crate) const AUTH_REPLAY: &str = "auth-replay";

pub(crate) async fn replay_claimed(
    gov: Option<&crate::governance::GovState>,
    provider: &str,
    replay: &Replay,
    now: u64,
) -> bool {
    if replay.key.is_empty() {
        return true;
    }
    let Some(gov) = gov else {
        return false;
    };
    let Ok(core) = gov.core_store() else {
        return false;
    };
    // `provider/key`, built on the stack (a heap block only for an unusually long key).
    let mut token: smallvec::SmallVec<[u8; 256]> = smallvec::SmallVec::new();
    token.extend_from_slice(provider.as_bytes());
    token.push(b'/');
    token.extend_from_slice(replay.key.as_bytes());
    let Ok(token) = std::str::from_utf8(&token) else {
        return false;
    };
    let Some(expires_at) = now
        .checked_add(replay.ttl_secs)
        .filter(|expiry| *expiry < u64::MAX)
    else {
        return false;
    };
    if !matches!(
        crate::persistence::claims::Claims::authorized(core, AUTH_REPLAY_OWNER, AUTH_REPLAY)
            .redeem(token, expires_at)
            .await,
        Ok(crate::persistence::claims::Outcome::Claimed)
    ) {
        return false;
    }
    // Custody resolution may report an original Applied receipt after expiry.
    // A fresh auth invocation can receive that win only inside its original
    // native deadline, never by extending the retained candidate's expiry.
    core.backend()
        .clock(core.info().dataset)
        .await
        .is_ok_and(|clock| {
            clock.authority == core.info().clock_authority && clock.unix_seconds <= expires_at
        })
}

/// A REPLAY CLAIM NOT YET WON: the claim a verified identity asked `provider` for, at the instant
/// `now` its request was judged. Won ([`replay_claimed`]) only as the LAST step of admission — after
/// every decision that could still refuse the request (role binding, key synth, admin scope), before
/// the request proceeds to anything with a side effect (budget and rate admission, the handler) —
/// so a refused request never burns its key and the store holds a claim only for an admitted one.
/// A request refused by a budget or rate gate downstream of the auth gate has already won its claim:
/// it was admitted by auth, and its sender's retry is a replay, as the spec's "a sender's retry
/// inside the window is a replay" says.
#[derive(Debug, Clone)]
struct ReplayClaim {
    provider: String,
    replay: Box<Replay>,
    now: u64,
}

impl ReplayClaim {
    fn of(provider: &str, replay: Option<Box<Replay>>, now: u64) -> Option<Self> {
        replay.map(|replay| ReplayClaim {
            provider: provider.to_string(),
            replay,
            now,
        })
    }

    async fn win(&self, gov: Option<&crate::governance::GovState>) -> bool {
        replay_claimed(gov, &self.provider, &self.replay, self.now).await
    }
}

pub struct PendingClaim(PendingKind);

enum PendingKind {
    Legacy {
        claim: ReplayClaim,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
    },
    Native(native_admin::Pending),
}

impl std::fmt::Debug for PendingClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingClaim").finish_non_exhaustive()
    }
}

impl PendingClaim {
    pub(crate) fn for_identity(
        provider: &str,
        identity: &busbar_contract::auth_calls::VerifiedIdentity,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        now: u64,
    ) -> Option<Self> {
        Self::of(ReplayClaim::of(provider, identity.replay.clone(), now), gov)
    }
    fn of(
        claim: Option<ReplayClaim>,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
    ) -> Option<Self> {
        claim.map(|claim| PendingClaim(PendingKind::Legacy { claim, gov }))
    }

    pub async fn win(&self) -> bool {
        match &self.0 {
            PendingKind::Legacy { claim, gov } => claim.win(gov.as_deref()).await,
            PendingKind::Native(_) => false,
        }
    }

    fn native(
        invocation: native_admin::Invocation,
        prepared: std::sync::Arc<native_admin::PreparedIdentity>,
    ) -> Self {
        Self(PendingKind::Native(native_admin::Pending::new(
            invocation, prepared,
        )))
    }

    pub async fn complete_admin(
        &self,
    ) -> Result<native_admin::ExecutionAdmission, native_admin::AdmissionRefused> {
        match &self.0 {
            PendingKind::Native(pending) => pending.complete().await,
            PendingKind::Legacy { claim, gov } => claim
                .win(gov.as_deref())
                .await
                .then(native_admin::ExecutionAdmission::legacy)
                .ok_or(native_admin::AdmissionRefused),
        }
    }

    pub async fn complete_admin_classified(
        &self,
    ) -> Result<native_admin::ExecutionAdmission, native_admin::AdminCompletionRefused> {
        match &self.0 {
            PendingKind::Native(pending) => pending.complete_classified().await,
            PendingKind::Legacy { claim, gov } => claim
                .win(gov.as_deref())
                .await
                .then(native_admin::ExecutionAdmission::legacy)
                .ok_or(native_admin::AdminCompletionRefused::Unavailable),
        }
    }

    #[must_use]
    pub(crate) fn win_now(&self) -> bool {
        futures::executor::block_on(self.win())
    }
}

async fn claim_won(pending: Option<&PendingClaim>) -> bool {
    match pending {
        None => true,
        Some(pending) => pending.win().await,
    }
}

async fn admit_verified_session(
    bindings: &crate::config::RoleBindings,
    verdict: ChainVerdict,
    claim: Option<&PendingClaim>,
) -> Result<(AuthPrincipal, crate::governance::PlaneRequestCtx), IdentityRefusal> {
    let admitted = resolve_identity_from_bindings(bindings, verdict)?;
    match claim {
        Some(claim) if !claim.win().await => Err(IdentityRefusal::Denied),
        _ => Ok(admitted),
    }
}

async fn claimed_chain_identity(
    verdict: Result<ChainVerdict, VerifierUnavailable>,
    pending: Option<&PendingClaim>,
) -> Result<ChainVerdict, VerifierUnavailable> {
    match verdict {
        Ok(ChainVerdict::Identified { .. }) if !claim_won(pending).await => {
            Ok(ChainVerdict::Denied)
        }
        verdict => verdict,
    }
}

#[cfg(test)]
async fn signed_replay_claimed(
    gov: Option<&crate::governance::GovState>,
    reader: &str,
    id: &busbar_contract::auth_calls::VerifiedIdentity,
    now: u64,
) -> bool {
    match ReplayClaim::of(reader, id.replay.clone(), now) {
        None => true,
        Some(claim) => claim.win(gov).await,
    }
}

fn strike_named<'s>(
    req: &mut Request<Body>,
    consumed: &mut ConsumedCredentials,
    strips: impl Iterator<Item = &'s Strip> + Clone,
) {
    consumed.carry_iter(
        strips
            .clone()
            .filter(|s| s.place == StripPlace::Field)
            .filter_map(|s| HeaderName::from_bytes(s.name.as_bytes()).ok()),
    );
    let keys = strips.filter(|s| s.place == StripPlace::Query);
    if keys.clone().next().is_none() {
        return;
    }
    let named = |key: &str| keys.clone().any(|s| s.name == key);
    if let Some(uri) = without_query_where(req.uri(), &named) {
        *req.uri_mut() = uri;
    }
    if let Some(original) = req.extensions_mut().get_mut::<axum::extract::OriginalUri>() {
        if let Some(uri) = without_query_where(&original.0, &named) {
            original.0 = uri;
        }
    }
}

/// `uri` without the query pairs whose key (raw or form-decoded) `named` picks.
fn without_query_where(
    uri: &axum::http::Uri,
    named: &dyn Fn(&str) -> bool,
) -> Option<axum::http::Uri> {
    let query = uri.query()?;
    let kept = without_query_text_where(query, named)?;
    let path_and_query = if kept.is_empty() {
        uri.path().to_string()
    } else {
        format!("{}?{kept}", uri.path())
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    axum::http::Uri::from_parts(parts).ok()
}

/// `query` without the pairs whose key (raw or form-decoded) `is_key` picks, written once into the
/// one owned text; `None` when no pair is picked. It needs no enclosing HTTP URI.
pub(crate) fn without_query_text_where(
    query: &str,
    is_key: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let named = |pair: &&str| {
        let key = pair.split_once('=').map_or(*pair, |(k, _)| k);
        is_key(key)
            || url::form_urlencoded::parse(key.as_bytes())
                .next()
                .is_some_and(|(decoded, _)| is_key(&decoded))
    };
    if !query.split('&').any(|p| named(&p)) {
        return None;
    }
    let mut kept = String::with_capacity(query.len());
    for (at, pair) in query.split('&').filter(|p| !named(p)).enumerate() {
        if at > 0 {
            kept.push('&');
        }
        kept.push_str(pair);
    }
    Some(kept)
}

const AUTH_ADMISSION_MAX_INFLIGHT: usize = 64;

const AUTH_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

static AUTH_ADMISSION_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(AUTH_ADMISSION_MAX_INFLIGHT));

const ADMIN_ADMISSION_MAX_INFLIGHT: usize = 16;

const ADMIN_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

pub fn admin_call_context(id: crate::state::InvocationId) -> busbar_ports::CallCx {
    busbar_ports::CallCx {
        deadline: std::time::Instant::now() + ADMIN_ADMISSION_WAIT,
        request_id: id.request_id().get(),
        stack: Default::default(),
    }
}

static ADMIN_ADMISSION_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(ADMIN_ADMISSION_MAX_INFLIGHT));

static AUTH_SATURATED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static AUTH_FAULTED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static ADMIN_SATURATED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static ADMIN_STALLED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static NO_VERDICT_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn tripped(latch: &std::sync::atomic::AtomicBool) -> bool {
    !latch.swap(true, std::sync::atomic::Ordering::Relaxed)
}

fn cleared(latch: &std::sync::atomic::AtomicBool) {
    latch.store(false, std::sync::atomic::Ordering::Relaxed);
}

fn auth_saturated() {
    auth_saturated_on(&AUTH_SATURATED_WARNED);
}

fn auth_saturated_on(latch: &std::sync::atomic::AtomicBool) {
    if tripped(latch) {
        diag_warn!(
            AUTH_OFFLOAD_SATURATED,
            "auth chain offload could not be started within {AUTH_ADMISSION_WAIT:?} \
             ({AUTH_ADMISSION_MAX_INFLIGHT} already in flight); an auth plugin is not \
             returning. Denying (fail-closed) rather than admitting unverified."
        );
    } else {
        diag_debug!(
            AUTH_OFFLOAD_SATURATED,
            "auth chain offload could not be started within {AUTH_ADMISSION_WAIT:?} \
             ({AUTH_ADMISSION_MAX_INFLIGHT} already in flight); an auth plugin is not \
             returning. Denying (fail-closed) rather than admitting unverified."
        );
    }
}

fn auth_faulted() {
    auth_faulted_on(&AUTH_FAULTED_WARNED);
}

fn auth_faulted_on(latch: &std::sync::atomic::AtomicBool) {
    let error = "the auth plugin faulted";
    if tripped(latch) {
        diag_warn!(AUTH_CHAIN_PANICKED, error = %error, "auth chain panicked; denying (fail-closed)");
    } else {
        diag_debug!(AUTH_CHAIN_PANICKED, error = %error, "auth chain panicked; denying (fail-closed)");
    }
}

fn admin_saturated() {
    admin_saturated_on(&ADMIN_SATURATED_WARNED);
}

fn admin_saturated_on(latch: &std::sync::atomic::AtomicBool) {
    if tripped(latch) {
        diag_warn!(
            ADMIN_OFFLOAD_SATURATED,
            "admin auth chain offload could not be started within {ADMIN_ADMISSION_WAIT:?} \
             ({ADMIN_ADMISSION_MAX_INFLIGHT} already in flight); an admin auth plugin is not \
             returning. Denying (fail-closed) rather than admitting unverified."
        );
    } else {
        diag_debug!(
            ADMIN_OFFLOAD_SATURATED,
            "admin auth chain offload could not be started within {ADMIN_ADMISSION_WAIT:?} \
             ({ADMIN_ADMISSION_MAX_INFLIGHT} already in flight); an admin auth plugin is not \
             returning. Denying (fail-closed) rather than admitting unverified."
        );
    }
}

fn admin_stalled() {
    admin_stalled_on(&ADMIN_STALLED_WARNED);
}

fn admin_stalled_on(latch: &std::sync::atomic::AtomicBool) {
    if tripped(latch) {
        diag_warn!(
            ADMIN_CHAIN_STALLED,
            "admin auth chain did not complete within {ADMIN_ADMISSION_WAIT:?} (or panicked); \
         denying (fail-closed)."
        );
    } else {
        diag_debug!(
            ADMIN_CHAIN_STALLED,
            "admin auth chain did not complete within {ADMIN_ADMISSION_WAIT:?} (or panicked); \
         denying (fail-closed)."
        );
    }
}

fn data_verdict_of(
    provider: &str,
    answer: VerifyAnswer,
    faulted: bool,
) -> Result<Judgement, VerifierUnavailable> {
    if faulted {
        auth_faulted();
        verify_without_verdict("data", provider, "fault");
        return Err(VerifierUnavailable::NoVerdict);
    }
    cleared(&AUTH_FAULTED_WARNED);
    if matches!(answer.verified, Verified::Overloaded) {
        return Err(VerifierUnavailable::Overloaded);
    }
    cleared(&AUTH_SATURATED_WARNED);
    if matches!(answer.verified, Verified::Failed) {
        verify_without_verdict("data", provider, "failed");
        return Err(VerifierUnavailable::NoVerdict);
    }
    cleared(&NO_VERDICT_WARNED);
    Ok(chain_verdict_of(answer))
}

fn signed_verdict_of(answer: VerifyAnswer, faulted: bool) -> (Verified, Vec<Strip>) {
    let VerifyAnswer {
        verified,
        strips: named,
        ..
    } = answer;
    if faulted {
        auth_faulted();
        return (Verified::Failed, named);
    }
    cleared(&AUTH_FAULTED_WARNED);
    (verified, named)
}

fn admin_verdict_of(answer: VerifyAnswer, faulted: bool) -> Judgement {
    if faulted {
        admin_stalled();
        return Judgement::without_verdict(answer.strips);
    }
    cleared(&ADMIN_STALLED_WARNED);
    if matches!(answer.verified, Verified::Overloaded) {
        admin_saturated();
        return refused_keeping_strips(answer);
    }
    cleared(&ADMIN_SATURATED_WARNED);
    chain_verdict_of(answer)
}

/// A data-plane chain position whose `verify` judged nothing. The chain stops there, the request is
/// refused (fail-closed), and the data plane answers it 503 with `Retry-After` rather than 1.5.5's
/// 401 — the caller's credential was never judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierUnavailable {
    /// Its instance's `max_inflight` was full and the call was not queued.
    /// HTTP callers report 503 for this overload.
    Overloaded,
    /// It answered NO VERDICT: FAILED (a module failure, e.g. an OIDC plugin whose key set is
    /// unavailable), a FAULT, or a timeout. HTTP callers report 503 for this module failure,
    /// never 401.
    NoVerdict,
}

/// How a chain run reaches each position's verifier.
#[derive(Debug, Clone, Copy)]
enum Reach {
    /// On the caller's own thread, for a SYNC caller (`run_chain`, `run_chain_with`): each position
    /// on the spot, and a door that must wait awaited where the caller polls.
    Inline,
    /// On the request path: each position's `verify` admitted on the data-plane budget, submitted
    /// and awaited.
    RequestPath,
}

/// THE REQUEST'S HEAD as the data-plane chain lends it to each position's `verify` at the `Head`
/// point (THE DESIGN, "Auth points and guest lists"): the method, the authority off the `host`
/// line, the path and query as received, and the field lines as presented (lower-cased names, in
/// order). The chain adds the candidate credential and the clock per call. Empty (`default`) where
/// the caller holds no request head (the stdio identity bind): the candidate alone is lent.
#[derive(Debug, Clone, Default)]
pub struct ChainHead {
    lines: Vec<(String, busbar_contract::redacted::Secret<Vec<u8>>)>,
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
}

impl ChainHead {
    pub fn of(req: &Request<Body>) -> Self {
        Self::of_parts(
            req.method().as_str(),
            req.uri()
                .path_and_query()
                .map_or_else(|| req.uri().path(), |pq| pq.as_str()),
            req.headers(),
        )
    }

    pub fn of_parts(method: &str, target: &str, headers: &HeaderMap) -> Self {
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query.to_string())),
            None => (target, None),
        };
        let authority = headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Self {
            lines: headers
                .iter()
                .map(|(n, v)| {
                    let value = busbar_contract::redacted::Secret::new(v.as_bytes().to_vec());
                    (n.as_str().to_string(), value)
                })
                .collect(),
            method: method.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            query,
        }
    }

    fn request(&self, candidate: Option<&str>, now: u64) -> VerifyRequest {
        VerifyRequest {
            point: busbar_contract::abi::auth::AuthPoint::Head,
            credential: candidate
                .map(|c| busbar_contract::redacted::Secret::new(c.as_bytes().to_vec())),
            lines: self.lines.clone(),
            method: self.method.clone(),
            authority: self.authority.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            timestamp: now,
            conn: 0,
            unit: 0,
            peer: None,
            body: None,
        }
    }
}

pub struct AdminAuthChain {
    pub modules: foldhash::HashMap<String, AdminModule>,

    pub operator: Operator,
}

pub struct AdminModule {
    pub calls: std::sync::Arc<dyn AuthCalls>,
}

pub use busbar_kernel_identity::{
    caller_ref::CallerRefKey,
    operator::{Operator, OperatorCredential},
};

impl fmt::Debug for AdminAuthChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminAuthChain")
            .field("modules", &self.modules.keys())
            .finish()
    }
}

impl fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("keys_in_chain", &self.keys_in_chain)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

impl AuthMiddleware {
    pub(crate) fn signed_reader(&self, headers: &HeaderMap) -> Option<SignedReader> {
        if !self.keys_in_chain {
            return None;
        }
        self.carrying_reader(headers).map(|r| {
            (
                std::sync::Arc::clone(&r.name),
                std::sync::Arc::clone(&r.calls),
                std::sync::Arc::clone(&r.kinds),
            )
        })
    }

    /// The first configured credential reader (in reader order) one of whose carrier lines
    /// `headers` holds: looked up by each presented line name, never by sweeping the readers.
    pub(crate) fn carrying_reader(&self, headers: &HeaderMap) -> Option<&CredentialReader> {
        let first = headers
            .keys()
            .filter_map(|name| self.reader_by_carrier.get(name).copied())
            .min()?;
        self.readers.get(first)
    }

    pub fn is_open(&self) -> bool {
        self.chain.is_empty() && !self.keys_in_chain
    }

    pub fn run_chain(&self, candidate: Option<&str>) -> ChainVerdict {
        self.run_chain_with(candidate, None, busbar_kernel::store::now(), None)
    }

    pub fn run_chain_with(
        &self,
        candidate: Option<&str>,
        gov: Option<&crate::governance::GovState>,
        now: u64,
        expected_aud: Option<&str>,
    ) -> ChainVerdict {
        futures::executor::block_on(async {
            let mut claim = None;
            let verdict = self
                .walk(
                    &ChainHead::default(),
                    candidate,
                    gov,
                    now,
                    expected_aud,
                    Reach::Inline,
                    &mut None,
                    &mut claim,
                )
                .await
                .unwrap_or(ChainVerdict::Denied);

            match claim {
                Some(claim) if !claim.win(gov).await => ChainVerdict::Denied,
                _ => verdict,
            }
        })
    }

    async fn walk(
        &self,
        head: &ChainHead,
        candidate: Option<&str>,
        gov: Option<&crate::governance::GovState>,
        now: u64,
        expected_aud: Option<&str>,
        reach: Reach,
        strips: &mut Option<Vec<Strip>>,
        claim: &mut Option<ReplayClaim>,
    ) -> Result<ChainVerdict, VerifierUnavailable> {
        if self.chain.is_empty() && !self.keys_in_chain {
            return Ok(ChainVerdict::Open);
        }
        for entry in &self.chain {
            let judged = judge(entry, head.request(candidate, now), reach).await?;
            // The first stripping position's lines move in whole; only a later one appends.
            match strips {
                Some(held) => held.extend(judged.strips),
                None if judged.strips.is_empty() => {}
                None => *strips = Some(judged.strips),
            }
            if let Some(verdict) = chain_position_verdict(&entry.provider, judged.verdict) {
                if matches!(verdict, ChainVerdict::Identified { .. }) {
                    *claim = ReplayClaim::of(&entry.provider, judged.replay, now);
                }
                return Ok(complete_chain(Some(verdict)));
            }
        }

        if self.keys_in_chain {
            return Ok(keys_arm_verdict(gov, candidate, now, expected_aud));
        }
        Ok(complete_chain(None))
    }

    pub async fn run_chain_on_request_path(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<String>,
        head: ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> ChainVerdict {
        deny_unavailable_chain(
            Self::judge_chain_on_request_path(auth, candidate, head, gov, expected_aud).await,
        )
    }

    pub(crate) async fn judge_chain_on_request_path(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<String>,
        head: ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> Result<ChainVerdict, VerifierUnavailable> {
        let (verdict, _, pending) = Self::judge_chain_on_request_path_naming(
            auth,
            candidate.as_deref(),
            &head,
            gov,
            expected_aud.as_deref(),
        )
        .await;

        claimed_chain_identity(verdict, pending.as_ref()).await
    }

    pub async fn judge_chain_on_request_path_naming(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<&str>,
        head: &ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<&str>,
    ) -> (
        Result<ChainVerdict, VerifierUnavailable>,
        Vec<Strip>,
        Option<PendingClaim>,
    ) {
        let now = busbar_kernel::store::now();
        let mut strips = None;
        let mut claim = None;
        let verdict = auth
            .walk(
                head,
                candidate,
                gov.as_deref(),
                now,
                expected_aud,
                Reach::RequestPath,
                &mut strips,
                &mut claim,
            )
            .await;
        (
            verdict,
            strips.unwrap_or_default(),
            PendingClaim::of(claim, gov),
        )
    }

    pub fn constant_time_eq(a: &str, b: &str) -> bool {
        busbar_contract::redacted::constant_time_eq(a, b)
    }

    pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
        let (scheme, token) = auth_header.split_once(' ')?;
        let token = token.trim_start_matches(' ');
        if scheme.eq_ignore_ascii_case(AUTH_SCHEME_BEARER) && !token.is_empty() {
            Some(token)
        } else {
            None
        }
    }

    pub fn extract_client_token(&self, headers: &HeaderMap) -> Option<String> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::CredentialExtract);
        carried_credential(&self.carriers, headers)
    }

    /// The token-exchange endpoint's own credential read. That endpoint is a plain HTTP request
    /// with no inbound unit, so there is no carried credential to read instead.
    pub(crate) fn exchange_token(&self, headers: &HeaderMap) -> Option<String> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::ExchangeToken);
        carried_credential(&self.carriers, headers)
    }

    pub fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        self.issued.clone()
    }

    pub(crate) fn carriers(&self) -> &[HeaderName] {
        &self.carriers
    }

    pub fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
}

async fn auth_admission_permit() -> Result<tokio::sync::SemaphorePermit<'static>, Box<Judgement>> {
    match tokio::time::timeout(AUTH_ADMISSION_WAIT, AUTH_ADMISSION_PERMITS.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        _ => {
            auth_saturated();
            Err(Box::new(Judgement::of(AuthVerdict::Reject)))
        }
    }
}

async fn admin_admission_permit() -> Result<tokio::sync::SemaphorePermit<'static>, Box<Judgement>> {
    match tokio::time::timeout(ADMIN_ADMISSION_WAIT, ADMIN_ADMISSION_PERMITS.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        _ => {
            admin_saturated();
            Err(Box::new(Judgement::of(AuthVerdict::Reject)))
        }
    }
}

fn admin_verification_timed_out(_: tokio::time::error::Elapsed) -> Judgement {
    admin_stalled();
    Judgement::without_verdict(Vec::new())
}

async fn judge(
    entry: &ChainEntry,
    request: VerifyRequest,
    reach: Reach,
) -> Result<Judgement, VerifierUnavailable> {
    match reach {
        Reach::Inline => match entry.calls.verify_now(&request) {
            Some(answer) => data_verdict_of(&entry.provider, answer, false),
            None => {
                let mut call = entry.calls.verify(request);
                let answer = (&mut call).await;
                data_verdict_of(&entry.provider, answer, call.faulted())
            }
        },

        Reach::RequestPath => {
            let permit = match auth_admission_permit().await {
                Ok(permit) => permit,
                Err(refusal) => return Ok(*refusal),
            };
            let mut call = entry.calls.verify(request);
            let answer = (&mut call).await;
            drop(permit);
            data_verdict_of(&entry.provider, answer, call.faulted())
        }
    }
}

pub(crate) fn keys_arm_verdict(
    gov: Option<&crate::governance::GovState>,
    candidate: Option<&str>,
    now: u64,
    expected_aud: Option<&str>,
) -> ChainVerdict {
    let Some(token) = candidate.filter(|t| !t.is_empty()) else {
        return ChainVerdict::Denied;
    };
    let Some(gov) = gov else {
        return ChainVerdict::Denied;
    };

    match gov.verify_token_authority(token, now, expected_aud) {
        Some(authority) => ChainVerdict::Identified {
            module: crate::config::KEYS_MODULE.to_string(),
            principal: principal_from_vkey(authority.original_key()),
            resolved: Some(authority.original_key().clone()),
            signed_authority: Some(SignedRequestAuthority::verified(authority)),
        },
        None => ChainVerdict::Denied,
    }
}

pub(crate) fn principal_from_vkey(key: &crate::governance::VirtualKey) -> Principal {
    Principal {
        id: key.id.clone(),
        name: Some(key.name.clone()),
        roles: Vec::new(),
        ttl_secs: None,
    }
}

fn ingress_for_path(app: &crate::state::App, path: &str) -> crate::plane_driver::dispatch::Ingress {
    if crate::router::is_private_listener() {
        crate::plane_driver::dispatch::Ingress::Fallback(None)
    } else {
        app.planes.ingress_of(path)
    }
}

fn vendor_auth_failure_message(proto: &str) -> &'static str {
    crate::ingress::protocols::vendor_auth_failure_message(proto)
}

pub fn auth_failure_status_and_kind(proto: &str) -> (StatusCode, &'static str) {
    let (status, kind) = crate::ingress::protocols::auth_failure_status_and_kind(proto);
    StatusCode::from_u16(status)
        .map(|status| (status, kind))
        .unwrap_or((
            StatusCode::UNAUTHORIZED,
            busbar_contract::protocol::KIND_AUTHENTICATION,
        ))
}

pub(crate) type RefusalDoor = (
    busbar_kernel::plane_routes::PlaneRefuseFn,
    busbar_contract::secure::SecureString,
);

fn refuse_door((refuse, target): &RefusalDoor) -> Response {
    refuse(busbar_contract::caps::ReasonCode::Unauthenticated, target)
}

fn unauthorized_response(
    app: &crate::state::App,
    path: &str,
    door: Option<&RefusalDoor>,
) -> Response {
    if let Some(door) = door {
        return refuse_door(door);
    }
    unauthorized_ingress_response(ingress_for_path(app, path))
}

/// The one rendering of a sender-constraint refusal for the door and plane admission: the RFC 9728
/// challenge where the resource declares metadata, the plane's own refusal where it renders
/// authentication refusals itself, and otherwise the endpoint's native error carrying the reason.
fn sender_constraint_response(
    app: &std::sync::Arc<crate::state::App>,
    path: &str,
    door: Option<&RefusalDoor>,
    resource_metadata: Option<&str>,
    reason: dpop::Refusal,
) -> Response {
    let ingress = ingress_for_path(app, path);
    let description = reason.description(app.oauth_as.is_none());
    if let Some(resource_metadata) = resource_metadata {
        return challenge::refuse(
            challenge::ChallengeError::InvalidToken,
            resource_metadata,
            description,
            None,
        );
    }
    if let Some(door) = door {
        return refuse_door(door);
    }
    sender_constraint_native(ingress, description)
}

fn sender_constraint_native(
    ingress: crate::plane_driver::dispatch::Ingress,
    description: &str,
) -> Response {
    crate::ingress::native::native_error(
        ingress,
        StatusCode::UNAUTHORIZED,
        busbar_contract::protocol::KIND_AUTHENTICATION,
        description,
    )
}

fn unauthorized_ingress_response(ingress: crate::plane_driver::dispatch::Ingress) -> Response {
    let dialect = crate::ingress::native::envelope_dialect(ingress);
    let message = vendor_auth_failure_message(dialect);
    let (status, kind) = auth_failure_status_and_kind(dialect);
    crate::ingress::native::native_error(ingress, status, kind, message)
}

/// The inbound candidate credential: a DPoP-bound token first (when this node is an OAuth
/// authorization server), else the first carrier. Read once per unit, by its `Derived` record,
/// which counts the read; a refusal with no unit reads it through a record of its own.
pub(crate) fn candidate_of(
    app: &crate::state::App,
    headers: &HeaderMap,
) -> Option<busbar_contract::redacted::Secret<String>> {
    candidate_from_metadata(app.oauth_as.is_some(), app.auth.carriers(), headers)
}

fn candidate_from_metadata(
    has_oauth_as: bool,
    carriers: &[HeaderName],
    headers: &HeaderMap,
) -> Option<busbar_contract::redacted::Secret<String>> {
    has_oauth_as
        .then(|| dpop::dpop_credential(headers))
        .flatten()
        .or_else(|| carried_credential(carriers, headers))
        .map(busbar_contract::redacted::Secret::new)
}

pub fn carried_credential(carriers: &[HeaderName], headers: &HeaderMap) -> Option<String> {
    let token = carriers
        .iter()
        .find_map(|carrier| carried_token(headers.get(carrier)?, *carrier == AUTHORIZATION))?;
    Some(token.to_owned())
}

/// The first credential carried under one of `carriers` (header names as configured), borrowed.
pub(crate) fn carried_named<'h, 'c>(
    carriers: impl IntoIterator<Item = &'c str>,
    headers: &'h HeaderMap,
) -> Option<&'h str> {
    carriers.into_iter().find_map(|carrier| {
        let authorization = carrier.eq_ignore_ascii_case(AUTHORIZATION.as_str());
        carried_token(headers.get(carrier)?, authorization)
    })
}

/// The credential one carrier line holds: the bearer token on `authorization`, else the value.
fn carried_token(value: &HeaderValue, authorization: bool) -> Option<&str> {
    let value = value.to_str().ok()?;
    if authorization {
        AuthMiddleware::extract_bearer_token(value)
    } else {
        Some(value).filter(|t| !t.is_empty())
    }
}

pub use busbar_contract::auth::AuthPrincipal;

type AdminChainAnswer = (ChainVerdict, Option<busbar_contract::authz::Scope>);

/// What an admin chain walk carries beside its answer: the lines every module it called named for
/// the transport to strip, whatever its verdict (THE DESIGN §6.4), the identifying module's
/// replay claim — the provider and the claim — which the admin door claims before admitting, and
/// whether the walk was denied because a module answered NO VERDICT (the admin door then answers
/// 503 with `Retry-After`, SIGN-auth-kind 2026-10-30).
#[derive(Debug, Default)]
pub(crate) struct AdminCarried {
    native: Option<std::sync::Arc<native_admin::PreparedIdentity>>,
    strips: Vec<Strip>,
    replay: Option<(String, Box<Replay>)>,
    no_verdict: bool,
    /// The closed 401 reason a presented `keys` admin credential was refused for.
    denial: Option<&'static str>,
}

fn carry_admin_outcome(
    carried: &mut AdminCarried,
    name: &str,
    outcome: Judgement,
) -> (AuthVerdict, Option<Box<Replay>>) {
    carried.strips.extend(outcome.strips);
    if outcome.no_verdict {
        verify_without_verdict("admin", name, "no verdict");
        carried.no_verdict = true;
    }
    (outcome.verdict, outcome.replay)
}

fn unresolved_admin_module(name: &str) -> Judgement {
    diag_error!(
        ADMIN_MODULE_UNRESOLVED,
        module = name,
        "admin_auth names a module with no resolved plugin; skipping (boot resolves \
         every non-builtin admin module, fail-closed)"
    );
    Judgement::of(AuthVerdict::Pass)
}

async fn run_admin_chain(
    app: &crate::state::App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
    carried: &mut AdminCarried,
    invocation: Option<&native_admin::Invocation>,
) -> AdminChainAnswer {
    // No anonymous admin posture (ADMIN-API-1.6-ONE-MODEL §8.1): an empty chain identifies no one,
    // so it falls through to the closed verdict below. Boot refuses `admin_auth: []` (§8.1.1).
    let candidate = carried_named(
        app.admin_modules
            .operator
            .carriers()
            .iter()
            .map(String::as_str),
        headers,
    );
    let now = busbar_kernel::store::now();
    // The built-in `keys` position. A busbar-signed key credential is told by its prefix, so it is
    // judged before the operator arm, which would otherwise refuse a credential it does not own.
    if app
        .admin_chain
        .iter()
        .any(|name| name == crate::config::KEYS_MODULE)
    {
        match admin_keys_arm(app, headers, now) {
            KeysAdmin::Absent => {}
            KeysAdmin::Refused(reason) => {
                carried.denial = Some(reason);
                return (ChainVerdict::Denied, None);
            }
            KeysAdmin::Identified(verdict) => {
                if admin_sender_constraint::downgraded(app, crate::config::KEYS_MODULE, headers) {
                    return (ChainVerdict::Denied, None);
                }
                return (verdict, None);
            }
        }
    }
    for name in &app.admin_chain {
        if name == crate::config::KEYS_MODULE {
            // Judged first, above the loop: a busbar-signed key is told by its prefix.
            continue;
        }
        let operator = app.admin_modules.operator.is(name);
        if let Some(native) = app.native_admin.as_ref() {
            let cx = invocation.map_or_else(
                || busbar_ports::CallCx {
                    deadline: std::time::Instant::now() + ADMIN_ADMISSION_WAIT,
                    request_id: app.next_request_id(),
                    stack: Default::default(),
                },
                |invocation| invocation.cx,
            );
            let Some(invocation) = invocation else {
                // A diagnostic header-only call owns no original admission to charge. It may
                // not fabricate a native request or spend the physical request's custody.
                carried.no_verdict = true;
                return (ChainVerdict::Denied, None);
            };
            let request = std::sync::Arc::clone(&invocation.request);
            let answer = if probe {
                let mut future = native.prepare(name, cx, request);
                let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
                match std::future::Future::poll(future.as_mut(), &mut cx) {
                    std::task::Poll::Ready(answer) => Some(answer),
                    std::task::Poll::Pending => None,
                }
            } else {
                let Ok(permit) = admin_admission_permit().await else {
                    carried.no_verdict = true;
                    return (ChainVerdict::Denied, None);
                };
                let answer =
                    tokio::time::timeout(ADMIN_ADMISSION_WAIT, native.prepare(name, cx, request))
                        .await
                        .ok();
                drop(permit);
                answer
            };
            match answer {
                Some(Ok(native_admin::PreparedAnswer::NotMine)) => continue,
                Some(Ok(native_admin::PreparedAnswer::Identity(prepared))) => {
                    if admin_sender_constraint::downgraded(app, name, headers)
                        || admin_sender_constraint::downgraded_in(
                            headers,
                            prepared.credential_headers(),
                        )
                    {
                        return (ChainVerdict::Denied, None);
                    }
                    let identity = prepared.identity();
                    carried
                        .strips
                        .extend(identity.strip().map(|name| Strip::field(name.to_owned())));
                    let verdict = ChainVerdict::Identified {
                        module: name.clone(),
                        principal: Principal {
                            id: identity.subject().to_owned(),
                            name: None,
                            roles: identity.groups().map(str::to_owned).collect(),
                            ttl_secs: identity.cache_s().map(u64::from),
                        },
                        resolved: None,
                        signed_authority: None,
                    };
                    carried.native = Some(prepared);
                    return (verdict, module_admin_scope_cap(app, name));
                }
                Some(Ok(
                    native_admin::PreparedAnswer::Rejected | native_admin::PreparedAnswer::Held,
                )) => return (ChainVerdict::Denied, None),
                Some(Err(_)) | None => {
                    carried.no_verdict = true;
                    return (ChainVerdict::Denied, None);
                }
            }
        }
        let outcome = match name.as_str() {
            // The operator arm stays first. A backed provider with an opened instance is judged
            // through the same bounded admission call as every admin module; an unset one passes.
            _ if operator => {
                let operator = &app.admin_modules.operator;
                match operator.instance(name) {
                    Some(calls) => {
                        let head = admin_head_with(method, target, headers, now, candidate);
                        Some(judge_admin_calls(calls, head, probe).await)
                    }
                    None if operator.unset(name) => Some(Judgement::of(AuthVerdict::Pass)),
                    None => None,
                }
            }

            other => {
                let request = admin_head_with(method, target, headers, now, candidate);
                external_admin_module(app, other, request, probe).await
            }
        }
        .unwrap_or_else(|| unresolved_admin_module(name));
        let (verdict, replay) = carry_admin_outcome(carried, name, outcome);
        if let Some(verdict) = chain_position_verdict(name, verdict) {
            if matches!(verdict, ChainVerdict::Identified { .. }) {
                if admin_sender_constraint::downgraded(app, name, headers) {
                    return (ChainVerdict::Denied, None);
                }
                carried.replay = replay.map(|r| (name.clone(), r));
                let cap = module_admin_scope_cap(app, name);
                return (complete_chain(Some(verdict)), cap);
            }
            return (complete_chain(Some(verdict)), None);
        }
    }
    (complete_chain(None), None)
}

/// What the built-in `keys` position of an admin chain made of one request.
pub(crate) enum KeysAdmin {
    /// No busbar-signed key credential is carried: the chain goes on to the next position.
    Absent,
    /// A key credential is carried and refused, for this closed 401 reason.
    Refused(&'static str),
    /// A live key holding an `admin` grant: identified as `key:<id>`, the key riding along.
    Identified(ChainVerdict),
}

async fn external_admin_module(
    app: &crate::state::App,
    name: &str,
    request: VerifyRequest,
    probe: bool,
) -> Option<Judgement> {
    let module = app.admin_modules.modules.get(name)?;
    Some(judge_admin_calls(&module.calls, request, probe).await)
}

/// One admin-chain position judged by its opened instance `calls`: the synchronous probe, or the
/// bounded call that takes an admission permit and waits at most `ADMIN_ADMISSION_WAIT`. Every
/// admin module and the operator credential share this one budget and this one timeout.
pub(crate) async fn judge_admin_calls(
    calls: &std::sync::Arc<dyn AuthCalls>,
    request: VerifyRequest,
    probe: bool,
) -> Judgement {
    if probe {
        return calls.verify_now(&request).map_or_else(
            || Judgement::without_verdict(Vec::new()),
            |answer| admin_verdict_of(answer, false),
        );
    }

    let permit = match admin_admission_permit().await {
        Ok(permit) => permit,
        Err(refusal) => return *refusal,
    };
    let mut call = calls.verify(request);
    let answered = tokio::time::timeout(ADMIN_ADMISSION_WAIT, &mut call).await;
    drop(permit);
    match answered {
        Ok(answer) => admin_verdict_of(answer, call.faulted()),
        Err(elapsed) => admin_verification_timed_out(elapsed),
    }
}

fn module_admin_scope_cap(
    app: &crate::state::App,
    module: &str,
) -> Option<busbar_contract::authz::Scope> {
    module_scope_cap(&app.auth_scope_caps, &app.admin_modules.operator, module)
}

pub fn dry_run_admin_scope(
    app: &crate::state::App,
    headers: &HeaderMap,
) -> busbar_contract::authz::Grants {
    if app.admin_chain.is_empty() {
        diag_warn!(
            ADMIN_AUTH_CHAIN_EMPTY,
            "admin-scope dry-run evaluated an EMPTY admin_auth chain: it identifies no one, so \
             THIS caller earns no scope (1.6.0 has no open admin posture)"
        );
        return busbar_contract::authz::Grants::default();
    }

    admin_scope_from_door(&probe_admin_door(app, "GET", "/", headers, false))
}

fn admin_scope_from_door(door: &AdminDoor) -> busbar_contract::authz::Grants {
    match door {
        AdminDoor::Identified(_, grants) | AdminDoor::Listed(_, grants, _) => *grants,

        AdminDoor::Denied | AdminDoor::Rejected(_) | AdminDoor::Unavailable(_) => {
            busbar_contract::authz::Grants::default()
        }
    }
}

/// THE ADMIN DOOR'S VERDICT for one request, on the snapshot it is handed: the chain (1.5.5
/// `auth/mod.rs:847-948`), then the scope its principal earns (`:1061-1100`), capped by the
/// identifying module's ceiling. What every admin door answers from — this middleware, the
/// dry-run, and the root's admin loop — so there is one admin chain, read live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminDoor {
    /// Identified: who the chain identified, and the grants it earns (empty = authenticated, not
    /// authorized).
    Identified(Principal, busbar_contract::authz::Grants),
    /// Identified, and holding admin verbs BY NAME (`role_bindings.<provider>.<role>.verbs: [ … ]`,
    /// #77(9) l.2279): the grants are every rung the principal reaches — the two-rung matrix the
    /// gate compares first — and the allow-list is what the verb itself must then be on. A
    /// principal whose bindings name no verb is [`AdminDoor::Identified`], the 1.5.5 grant.
    Listed(Principal, busbar_contract::authz::Grants, VerbAllowList),
    /// A verifier answered no verdict: fail closed, but retain why for the caller's 503 answer.
    Unavailable(VerifierUnavailable),
    /// Refused: invalid credentials or the unchanged admin overload policy.
    Denied,
    /// Refused as [`AdminDoor::Denied`] is, for a presented `keys` admin credential, naming the
    /// closed 401 reason (`credential_expired`, `credential_revoked`, `credential_invalid`).
    Rejected(&'static str),
}

fn admin_chain_outcome(
    verdict: ChainVerdict,
    no_verdict: bool,
) -> Result<ChainVerdict, VerifierUnavailable> {
    if no_verdict && verdict == ChainVerdict::Denied {
        Err(VerifierUnavailable::NoVerdict)
    } else {
        Ok(verdict)
    }
}

fn admin_probe_projection(
    verdict: Result<ChainVerdict, VerifierUnavailable>,
    project: impl FnOnce(ChainVerdict) -> (AdminDoor, Option<PendingClaim>),
) -> (AdminDoor, Option<PendingClaim>) {
    match verdict {
        Ok(verdict) => project(verdict),
        Err(error) => (AdminDoor::Unavailable(error), None),
    }
}

fn unclaimed_admin_replay(
    identified: bool,
    replay: Option<(String, Box<Replay>)>,
    now: u64,
) -> Option<ReplayClaim> {
    replay
        .filter(|_| identified)
        .and_then(|(provider, replay)| ReplayClaim::of(&provider, Some(replay), now))
}

async fn judge_admin_door(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
    claim: bool,
) -> Result<(AdminDoor, Vec<Strip>), VerifierUnavailable> {
    let (verdict, cap, replay, no_verdict, strips, denial) =
        judge_admin_chain(app, method, target, headers, probe).await;
    let verdict = admin_chain_outcome(verdict, no_verdict)?;
    let (door, pending) = admin_door_claim_of(app, verdict, cap, replay, denial);

    Ok((
        claimed_admin_door(door, pending.as_ref(), method, target, claim).await,
        strips,
    ))
}

async fn claimed_admin_door(
    door: AdminDoor,
    pending: Option<&PendingClaim>,
    method: &str,
    target: &str,
    claim: bool,
) -> AdminDoor {
    if claim && admin_door_admits(&door, method, target) && !claim_won(pending).await {
        return AdminDoor::Denied;
    }
    door
}

/// THE ADMIN DOOR'S VERDICT with its identity's replay claim UNWON ([`PendingClaim`]), for an admin
/// surface that decides more after the door (the root's admin units: revocation, then approve) and
/// wins the claim as the last step of its own admission.
#[derive(Debug)]
pub struct AdminVerdict {
    /// The door's verdict.
    pub door: AdminDoor,
    /// The replay claim the identified principal asks for, unwon; `None` when it asks for none.
    pub claim: Option<PendingClaim>,
}

impl From<AdminDoor> for AdminVerdict {
    fn from(door: AdminDoor) -> Self {
        AdminVerdict { door, claim: None }
    }
}

fn admin_door_claim_of(
    app: &App,
    verdict: ChainVerdict,
    cap: Option<busbar_contract::authz::Scope>,
    replay: Option<(String, Box<Replay>)>,
    denial: Option<&'static str>,
) -> (AdminDoor, Option<PendingClaim>) {
    let identified = matches!(verdict, ChainVerdict::Identified { .. });
    let now = busbar_kernel::store::now();
    let claim = unclaimed_admin_replay(identified, replay, now);
    (
        match (admin_door_of(app, verdict, cap), denial) {
            (AdminDoor::Denied, Some(reason)) => AdminDoor::Rejected(reason),
            (door, _) => door,
        },
        PendingClaim::of(claim, app.governance.clone()),
    )
}

pub fn admin_door_admits(door: &AdminDoor, method: &str, target: &str) -> bool {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let required = crate::admin::scope::admin_required_scope(method, path);
    match door {
        AdminDoor::Denied | AdminDoor::Rejected(_) | AdminDoor::Unavailable(_) => false,
        AdminDoor::Identified(_, grants) => grants.allows(required),
        AdminDoor::Listed(_, grants, list) => {
            grants.allows(required)
                && list.admits(crate::admin::seam::admin_verb_at(method, path), required)
        }
    }
}

async fn judge_admin_chain(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
) -> (
    ChainVerdict,
    Option<busbar_contract::authz::Scope>,
    Option<(String, Box<Replay>)>,
    bool,
    Vec<Strip>,
    Option<&'static str>,
) {
    let mut carried = AdminCarried::default();
    let (verdict, cap) =
        run_admin_chain(app, method, target, headers, probe, &mut carried, None).await;
    (
        verdict,
        cap,
        carried.replay,
        carried.no_verdict,
        carried.strips,
        carried.denial,
    )
}

fn cap_admin_scope(
    grants: busbar_contract::authz::Grants,
    cap: Option<busbar_contract::authz::Scope>,
) -> busbar_contract::authz::Grants {
    cap.map_or(grants, |cap| grants.capped_by(cap))
}

fn admin_door_of(
    app: &App,
    verdict: ChainVerdict,
    cap: Option<busbar_contract::authz::Scope>,
) -> AdminDoor {
    admin_door_from_bindings(
        &app.role_bindings,
        &app.admin_modules.operator,
        crate::config::operator_principal_id(),
        verdict,
        cap,
        crate::admin::seam::admin_verb_rung,
    )
}

fn admin_door_from_bindings(
    bindings: &crate::config::RoleBindings,
    operator: &Operator,
    operator_principal: &str,
    verdict: ChainVerdict,
    cap: Option<busbar_contract::authz::Scope>,
    rung_of: impl Fn(&str) -> Option<busbar_contract::authz::Scope>,
) -> AdminDoor {
    match verdict {
        // No anonymous admin posture (ADMIN-API-1.6-ONE-MODEL §8.1): a verdict that identifies no
        // one opens no admin door.
        ChainVerdict::Open | ChainVerdict::Denied => AdminDoor::Denied,
        ChainVerdict::Identified {
            module,
            principal,
            resolved: Some(key),
            ..
        } if module == crate::config::KEYS_MODULE && key.admin.is_some() => {
            admin_door_of_key(principal, &key, &rung_of)
        }
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            let grants = admin_scope_from_bindings(
                bindings,
                operator,
                operator_principal,
                Some(&module),
                Some(&principal),
            );
            let rungs = cap_admin_scope(grants, cap);
            let named = admin_verbs_named(bindings, &module, &principal, cap, &rung_of);
            if named.is_empty() {
                return AdminDoor::Identified(principal, rungs);
            }

            let reach = (named.iter())
                .filter_map(|verb| rung_of(verb.as_str()))
                .fold(rungs, busbar_contract::authz::Grants::with);
            AdminDoor::Listed(principal, reach, VerbAllowList { rungs, named })
        }
    }
}

/// Who the admin chain says a request is, for `GET /whoami` (ADMIN-API r5 section 2.2): the door
/// the request holds, and what stands behind it.
#[derive(Debug, Clone)]
pub struct AdminWho {
    /// The door the credential opens: the grants and verbs `/whoami` reports.
    pub door: AdminDoor,
    /// `operator`, `key` or `identity_provider`.
    pub kind: &'static str,
    /// The credential's id: the key id for `key`, the principal id for `identity_provider`.
    pub id: Option<String>,
    /// The identity provider (or operator provider) that identified the principal.
    pub provider: Option<String>,
    /// The credential's expiry, Unix seconds, when one is stated.
    pub expires_at: Option<u64>,
}

/// The request extension `GET /whoami` reads: [`admin_who`] taken at the gate, before the credential
/// lines are struck from the request.
#[derive(Debug, Clone)]
pub struct AdminWhoSlot(pub Option<AdminWho>);

/// The identity of an admitted admin request: the chain read again for `headers`, on the same path
/// the gate read it. `None` when the chain refuses the credential (the gate answered first, so a
/// handler never sees that).
pub async fn admin_who(app: &App, headers: &HeaderMap) -> Option<AdminWho> {
    let mut carried = AdminCarried::default();
    let (verdict, cap) = run_admin_chain(
        app,
        "GET",
        "/api/v1/admin/whoami",
        headers,
        false,
        &mut carried,
        None,
    )
    .await;
    if carried.no_verdict {
        return None;
    }
    admin_who_of(
        app,
        verdict,
        cap,
        carried
            .native
            .as_ref()
            .and_then(|p| p.identity().expires_at_s()),
    )
}

fn admin_who_of(
    app: &App,
    verdict: ChainVerdict,
    cap: Option<busbar_contract::authz::Scope>,
    native_expiry: Option<u64>,
) -> Option<AdminWho> {
    let (kind, id, provider, expires_at) = match &verdict {
        ChainVerdict::Open | ChainVerdict::Denied => return None,
        ChainVerdict::Identified {
            module, resolved, ..
        } if module == crate::config::KEYS_MODULE => (
            "key",
            resolved.as_ref().map(|key| key.id.clone()),
            None,
            resolved.as_ref().and_then(|key| key.expires_at),
        ),
        ChainVerdict::Identified {
            module, principal, ..
        } if app.admin_modules.operator.mints(
            Some(module.as_str()),
            &principal.id,
            crate::config::operator_principal_id(),
        ) =>
        {
            ("operator", None, Some(module.clone()), None)
        }
        ChainVerdict::Identified {
            module, principal, ..
        } => (
            "identity_provider",
            Some(principal.id.clone()),
            Some(module.clone()),
            None,
        ),
    };
    Some(AdminWho {
        door: admin_door_of(app, verdict, cap),
        kind,
        id,
        provider,
        expires_at: expires_at.or(native_expiry),
    })
}

/// Authoritative entry supplied with the exact selected generation and original request. The
/// returned pending object is completed only after the caller's revocation/approval checks.
pub async fn admin_verdict_for(
    invocation: native_admin::Invocation,
    headers: &HeaderMap,
) -> AdminVerdict {
    match judge_admin_invocation(&invocation, headers).await {
        Ok((verdict, _, _)) => verdict,
        Err(why) => AdminDoor::Unavailable(why).into(),
    }
}

async fn judge_admin_invocation(
    invocation: &native_admin::Invocation,
    headers: &HeaderMap,
) -> Result<(AdminVerdict, Vec<Strip>, Option<AdminWho>), VerifierUnavailable> {
    let app = &invocation.selected;
    let method = invocation.request.method();
    let target = invocation.request.target();
    if !native_admin::snapshot_matches_http(
        &invocation.request,
        method,
        target,
        headers,
        invocation.request.body(),
    ) {
        return Ok((AdminDoor::Denied.into(), Vec::new(), None));
    }
    let mut carried = AdminCarried::default();
    let (verdict, cap) = run_admin_chain(
        app,
        method,
        target,
        headers,
        false,
        &mut carried,
        Some(invocation),
    )
    .await;
    let verdict = admin_chain_outcome(verdict, carried.no_verdict)?;
    let who = admin_who_of(
        app,
        verdict.clone(),
        cap,
        carried
            .native
            .as_ref()
            .and_then(|p| p.identity().expires_at_s()),
    );
    let (door, mut claim) = admin_door_claim_of(app, verdict, cap, carried.replay, carried.denial);
    if let Some(prepared) = carried.native {
        claim = Some(PendingClaim::native(invocation.clone(), prepared));
    }
    Ok((AdminVerdict { door, claim }, carried.strips, who))
}

pub fn admin_verdict(app: &App, method: &str, target: &str, headers: &HeaderMap) -> AdminVerdict {
    let (door, claim) = probe_admin_verdict(app, method, target, headers);
    AdminVerdict { door, claim }
}

/// Await authoritative credential verification before projecting the admin verdict.
/// Replay custody is returned to the same admission owner as the synchronous probe.
pub async fn admin_verdict_async(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
) -> AdminVerdict {
    let (door, claim) = probe_admin_verdict_async(app, method, target, headers, false).await;
    AdminVerdict { door, claim }
}

fn probe_admin_door(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    claim: bool,
) -> AdminDoor {
    let (door, pending) = probe_admin_verdict(app, method, target, headers);

    probed_admin_claim(door, pending.as_ref(), method, target, claim)
}

fn probed_admin_claim(
    door: AdminDoor,
    pending: Option<&PendingClaim>,
    method: &str,
    target: &str,
    claim: bool,
) -> AdminDoor {
    if claim && admin_door_admits(&door, method, target) && pending.is_some_and(|p| !p.win_now()) {
        return AdminDoor::Denied;
    }
    door
}

fn probe_admin_verdict(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
) -> (AdminDoor, Option<PendingClaim>) {
    let judged = std::pin::pin!(probe_admin_verdict_async(
        app, method, target, headers, true
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(judged, &mut cx) {
        std::task::Poll::Ready(verdict) => verdict,
        std::task::Poll::Pending => (AdminDoor::Unavailable(VerifierUnavailable::NoVerdict), None),
    }
}

async fn probe_admin_verdict_async(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
) -> (AdminDoor, Option<PendingClaim>) {
    // A probe judges only; the lines the chain named for stripping are dropped with it.
    let (verdict, cap, replay, no_verdict, _, denial) =
        judge_admin_chain(app, method, target, headers, probe).await;
    admin_probe_projection(admin_chain_outcome(verdict, no_verdict), |verdict| {
        admin_door_claim_of(app, verdict, cap, replay, denial)
    })
}

fn admin_scope_from_bindings(
    role_bindings: &crate::config::RoleBindings,
    operator: &Operator,
    operator_principal: &str,
    module: Option<&str>,
    principal: Option<&Principal>,
) -> busbar_contract::authz::Grants {
    use busbar_contract::authz::{Grants, Scope};
    let Some(p) = principal else {
        return Grants::of(Scope::Full);
    };

    if p.roles.is_empty() {
        if operator.mints(module, &p.id, operator_principal) {
            return Grants::of(Scope::Full);
        }
        return Grants::default();
    }
    let Some(table) = module.and_then(|m| role_bindings.get(m)) else {
        return Grants::default();
    };

    let all = |b: &crate::config::RoleBindingCfg| {
        matches!(b.verb_grant(), Some(Ok(crate::config::VerbGrant::All))).then_some(Scope::Full)
    };
    p.roles
        .iter()
        .filter_map(|role| table.get(role))
        .flat_map(|b| [b.admin_scope.as_deref().and_then(Scope::parse), all(b)])
        .flatten()
        .fold(Grants::default(), Grants::with)
}

/// The per-verb allow-list an identified admin principal holds beside its rung grants.
/// Each verb is authorized by the per-verb allow-list on the admin token
/// (`verbs: [ … ]` or `verbs: "*"`; `read-only` and
/// `full` stay the 1.5.5 shorthands). Built only for a principal some bound role grants verbs BY
/// NAME; every other principal is judged on its rungs alone, as 1.5.5 judged it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerbAllowList {
    /// The rungs held WHOLE — `admin_scope:` (the 1.5.5 shorthands) or `verbs: "*"`, capped by the
    /// identifying provider's `max_admin_scope:`: every verb such a rung reaches is admitted.
    pub rungs: busbar_contract::authz::Grants,
    /// The verbs held BY NAME (`verbs: [ … ]`), each admitted whatever rung it needs; a name above
    /// the provider's ceiling, or one the closed table does not declare, is never here.
    pub named: std::collections::BTreeSet<String>,
}

/// The verb every identified admin principal holds whatever it names: reading its own identity.
pub const WHOAMI_VERB: &str = "get_whoami";

impl VerbAllowList {
    #[must_use]
    pub fn admits(&self, verb: Option<&str>, needed: busbar_contract::authz::Scope) -> bool {
        self.rungs.allows(needed)
            || verb.is_some_and(|v| v == WHOAMI_VERB || self.named.contains(v))
    }
}

fn admin_unauthorized_response() -> Response {
    let mut response = crate::admin::gate::err_json(&crate::admin::gate::ApiError::Unauthorized);
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
    );
    response
}

/// The admin 401 for a presented `keys` credential refused for the closed `reason`.
fn admin_rejected_response(reason: &str) -> Response {
    let mut response = crate::admin::gate::unauthorized_for(reason);
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
    );
    response
}

fn forbidden_response(needed: busbar_contract::authz::Scope, verb: Option<&str>) -> Response {
    crate::admin::gate::scope_insufficient_for(needed.as_str(), verb)
}

/// The admin door's 429: `rate_limited` (BUSBAR-8108) with the REAL time until the source's oldest
/// refused credential leaves its window.
fn rate_limited_after(retry_after_secs: u64) -> Response {
    let mut response = rate_limited_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from(retry_after_secs.max(1)),
    );
    response
}

fn rate_limited_response() -> Response {
    let mut response = crate::admin::gate::err_json(&crate::admin::gate::ApiError::RateLimited);
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from(crate::ratelimit::MUTATION_RATE_WINDOW_SECS),
    );
    response
}

pub(crate) fn unauthorized_with_completion_taps(
    app: &std::sync::Arc<crate::state::App>,
    path: &str,
    door: Option<&RefusalDoor>,
) -> Response {
    scoped_unauthorized_with_completion_taps(app, path, door, None, false)
}

pub(crate) fn scoped_unauthorized_with_completion_taps(
    app: &std::sync::Arc<crate::state::App>,
    path: &str,
    door: Option<&RefusalDoor>,
    admission: Option<&crate::plane_driver::dispatch::PlaneAdmission>,
    client_token_present: bool,
) -> Response {
    identity_refusal_response(
        IdentityRefusal::Denied,
        admission,
        client_token_present,
        || unauthorized_response(app, path, door),
    )
}

pub(crate) fn verifier_unavailable_response() -> Response {
    crate::limits::admission::inbound_overloaded_response()
}

fn data_verifier_error_response(error: VerifierUnavailable) -> Response {
    match error {
        VerifierUnavailable::Overloaded | VerifierUnavailable::NoVerdict => {
            verifier_unavailable_response()
        }
    }
}

fn identity_refusal_response(
    refusal: IdentityRefusal,
    admission: Option<&crate::plane_driver::dispatch::PlaneAdmission>,
    client_token_present: bool,
    legacy: impl FnOnce() -> Response,
) -> Response {
    if let Some(admission) = admission {
        return match refusal {
            IdentityRefusal::Denied => challenge::refuse(
                if client_token_present {
                    challenge::ChallengeError::InvalidToken
                } else {
                    challenge::ChallengeError::Absent
                },
                &admission.resource_metadata,
                "Authentication is required for this resource.",
                None,
            ),
            IdentityRefusal::NoGrant => challenge::refuse(
                challenge::ChallengeError::InsufficientScope,
                &admission.resource_metadata,
                "The authenticated principal carries no grant on this resource.",
                None,
            ),
        };
    }
    legacy()
}

pub const ADMIN_AUTH_UNAVAILABLE_MESSAGE: &str =
    "admin authentication is unavailable (the auth module answered no verdict); retry shortly";

pub const ADMIN_AUTH_RETRY_AFTER: &str = crate::limits::admission::OVERLOADED_RETRY_AFTER;

/// THE TRUST DECISION AUTHORITY this admission verdict grants (TRUST-ADMIN-PRODUCER-DESIGN r3
/// §4.2a, condition B-C1): `approve`/`revoke` exactly when the door admits `POST /trust/approve` /
/// `POST /trust/revoke` under the gate's own rules (full scope; a non-empty verb list must name the
/// verb). A refused door, or one admitting neither, grants none.
pub(crate) fn trust_decision_authority(
    door: &AdminDoor,
) -> Option<crate::host_services::TrustDecisionAuthority> {
    let principal = match door {
        AdminDoor::Identified(principal, _) | AdminDoor::Listed(principal, _, _) => {
            principal.id.clone()
        }
        AdminDoor::Denied | AdminDoor::Rejected(_) | AdminDoor::Unavailable(_) => return None,
    };
    let approve = admin_door_admits(door, "POST", "/api/v1/admin/trust/approve");
    let revoke = admin_door_admits(door, "POST", "/api/v1/admin/trust/revoke");
    (approve || revoke).then_some(crate::host_services::TrustDecisionAuthority {
        principal,
        approve,
        revoke,
    })
}

fn admin_principal_or_response(door: AdminDoor) -> Result<Principal, Box<Response>> {
    match door {
        AdminDoor::Identified(principal, _) | AdminDoor::Listed(principal, _, _) => Ok(principal),
        AdminDoor::Denied => Err(Box::new(admin_unauthorized_response())),
        AdminDoor::Rejected(reason) => Err(Box::new(admin_rejected_response(reason))),
        AdminDoor::Unavailable(_) => Err(Box::new(admin_unavailable_response())),
    }
}

fn admin_unavailable_response() -> Response {
    let unavailable = crate::admin::gate::ApiError::Unavailable(String::new());
    let mut resp = crate::admin::gate::admin_error_envelope(
        unavailable.http_status(),
        unavailable.code(),
        ADMIN_AUTH_UNAVAILABLE_MESSAGE,
    );
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from_static(ADMIN_AUTH_RETRY_AFTER),
    );
    resp
}

pub(crate) fn gate_consumed(app: &App, is_admin: bool, dpop_proven: bool) -> ConsumedCredentials {
    consumed_from_carriers(
        app.auth.carriers(),
        (!app.admin_chain.is_empty()).then(|| app.admin_modules.operator.carriers()),
        is_admin,
        dpop_proven,
    )
}

fn consumed_from_carriers(
    carriers: &[HeaderName],
    operator_carriers: Option<&[String]>,
    is_admin: bool,
    dpop_proven: bool,
) -> ConsumedCredentials {
    let mut consumed = ConsumedCredentials::carrying(carriers);
    if let Some(operator_carriers) = operator_carriers {
        consumed.carry_iter(
            operator_carriers
                .iter()
                .filter_map(|w| HeaderName::from_bytes(w.as_bytes()).ok()),
        );
    }
    if dpop_proven || is_admin {
        consumed.carry(&[dpop::DPOP_HEADER]);
    }
    consumed
}

#[cfg(test)]
async fn ticket_verdict(
    signed: bool,
    keys_in_chain: bool,
    prefix: Option<&str>,
    token: Option<&str>,
    gov: Option<&std::sync::Arc<crate::governance::GovState>>,
    now: u64,
) -> Result<Option<(ChainVerdict, Vec<u8>)>, ()> {
    claimed_ticket_verdict(
        PresentedTicket {
            signed,
            keys_in_chain,
            prefix,
            carried: None,
        },
        token,
        gov,
        now,
        &crate::appbuild::AcceptAll,
    )
    .await
    .map(|admitted| admitted.map(|(verdict, record, _)| (verdict, record)))
}

type ClaimedTicketVerdict = (
    ChainVerdict,
    Vec<u8>,
    Option<crate::host_services::HostTicketAdmission>,
);

/// What one request presents for door-ticket redemption, besides its token: whether it arrived
/// signed, whether keys are in the chain, the door's ticket prefix, and the ticket its auth point
/// already verified (SINGLE-PATH SP-AU3). The presented token is lent to the redemption as its own
/// argument: this value is copied and holds no credential.
#[derive(Clone, Copy)]
struct PresentedTicket<'a> {
    signed: bool,
    keys_in_chain: bool,
    prefix: Option<&'a str>,
    carried: Option<&'a crate::governance::VerifiedTicket>,
}

async fn claimed_ticket_verdict(
    presented: PresentedTicket<'_>,
    token: Option<&str>,
    gov: Option<&std::sync::Arc<crate::governance::GovState>>,
    now: u64,
    rules: &dyn crate::appbuild::RootRules,
) -> Result<Option<ClaimedTicketVerdict>, ()> {
    use crate::host_services::{HostTicketAdmission, TicketClaimDisposition};
    let PresentedTicket {
        signed,
        keys_in_chain,
        prefix,
        carried,
    } = presented;
    match (!signed, prefix, token) {
        (true, Some(prefix), Some(token)) if keys_in_chain && token.starts_with(prefix) => {
            let gov = gov.ok_or(())?;
            // The auth point verified this ticket and read its record (SP-AU3); a request whose
            // auth point verified none, or another credential, verifies it here, once.
            let verified;
            let ticket = match carried.filter(|ticket| ticket.presented_as(prefix, token)) {
                Some(ticket) => ticket,
                None => {
                    verified = gov.verify_ticket(prefix, token, now).ok_or(())?.0;
                    &verified
                }
            };
            let identity = gov.prepare_verified_ticket(ticket, now).await.ok_or(())?;

            let reservation = match rules.claim_ticket_admission(&identity) {
                TicketClaimDisposition::Ordinary => None,
                TicketClaimDisposition::Reserved(reservation) => {
                    if !reservation.matches(&identity) {
                        return Err(());
                    }
                    Some(reservation)
                }
                TicketClaimDisposition::Refused => return Err(()),
            };
            let (key, record) = gov
                .redeem_prepared_ticket(identity, ticket, now)
                .await
                .ok_or(())?;
            let admission = match reservation {
                Some(reservation) => {
                    let spent = crate::plane_driver::SpentTicketReservation::after_redemption(
                        reservation,
                        &key,
                    )
                    .map_err(|returned| {
                        drop(returned);
                    })?;
                    Some(HostTicketAdmission::new(spent))
                }
                None => None,
            };
            Ok(Some((
                ChainVerdict::Identified {
                    module: crate::config::KEYS_MODULE.to_string(),
                    principal: principal_from_vkey(&key),
                    resolved: Some(key),
                    signed_authority: None,
                },
                record,
                admission,
            )))
        }
        _ => Ok(None),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "axum middleware answers a response on either side"
)]
pub(crate) async fn auth_middleware(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    handle: std::sync::Arc<crate::state::AppHandle>,
    body_limit: usize,
    core_routes: &crate::core_routes::CoreRouteTable,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Remove the one-shot capability before any body, auth or handler suspension.
    let mut physical_pending = req
        .extensions_mut()
        .remove::<crate::inbound::native::AdminPhysicalRequest>()
        .map(|carrier| carrier.take())
        .transpose()
        .map_err(|_| admin_unauthorized_response())?;
    let mut physical_execution = req
        .extensions()
        .get::<std::sync::Arc<crate::inbound::native::PhysicalAdminExecution>>()
        .cloned();
    if physical_pending.is_some() && physical_execution.is_some() {
        return Err(admin_unauthorized_response());
    }
    let physical_binding = physical_pending
        .as_ref()
        .map(|p| p.binding().clone())
        .or_else(|| physical_execution.as_ref().map(|p| p.binding().clone()));
    let app = if let Some(binding) = &physical_binding {
        if !std::sync::Arc::ptr_eq(binding.handle(), &handle)
            || binding.check_live().is_err()
            || req
                .extensions()
                .get::<crate::inbound::RequestAdmission>()
                .is_some()
        {
            return Err(admin_unauthorized_response());
        }
        let app = binding.app().clone();
        req.extensions_mut().insert(app.clone());
        app
    } else {
        app
    };
    let inbound = req
        .extensions()
        .get::<crate::inbound::RequestAdmission>()
        .cloned();
    if let Some(inbound) = inbound.as_ref().filter(|request| {
        matches!(
            request.selected_line().claimant,
            crate::guest::Claimant::Plane(_)
        )
    }) {
        let mut context = match admitted_context(inbound).await {
            Ok(context) => context,
            Err(refused) => {
                let path = req.uri().path();
                let door = crate::cold::auth::chain::refusal_door(
                    core_routes,
                    path,
                    req.method(),
                    req.uri()
                        .path_and_query()
                        .map_or(path, |target| target.as_str()),
                );
                let admission = inbound.plane_admission();
                let token = inbound.client_token();
                return Err(match refused {
                    AdmittedRefusal::Identity(refusal) => {
                        identity_refusal_response(refusal, admission, token.is_some(), || {
                            unauthorized_with_completion_taps(&app, path, door.as_ref())
                        })
                    }
                    AdmittedRefusal::SenderConstraint(reason) => sender_constraint_response(
                        &app,
                        path,
                        door.as_ref(),
                        admission.map(|a| a.resource_metadata.as_str()),
                        reason,
                    ),
                    AdmittedRefusal::Audience(description) => match admission {
                        Some(admission) => challenge::refuse(
                            challenge::ChallengeError::InvalidToken,
                            &admission.resource_metadata,
                            description,
                            None,
                        ),
                        None => unauthorized_response(&app, path, door.as_ref()),
                    },
                });
            }
        };
        // The operator adapter alone converts the admitted neutral head back to HTTP.
        *req.headers_mut() = crate::inbound::served_header_map(&context.head);
        strike_named(&mut req, &mut context.consumed, inbound.inner.strips.iter());
        let token = inbound.client_token().map(str::to_owned).or_else(|| {
            app.oauth_as
                .as_ref()
                .and_then(|_| dpop::dpop_credential(inbound.original_headers()))
        });
        req.extensions_mut().insert(CallerToken(token));
        req.extensions_mut().insert(context.principal);
        req.extensions_mut().insert(context.gov);
        req.extensions_mut().insert(context.consumed);
        return Ok(next.run(req).await);
    }
    let inbound_headers = inbound
        .as_ref()
        .map(crate::inbound::RequestAdmission::original_headers);

    // A handle on the received target (shared bytes, no copy): `req` is rewritten below.
    let uri = req.uri().clone();
    let path = uri.path();
    let admission = inbound.as_ref().map_or_else(
        || {
            (!crate::router::is_private_listener())
                .then(|| app.planes.admission_for(path).cloned())
                .flatten()
        },
        |inbound| inbound.plane_admission().cloned(),
    );

    // The refusal door and its target are read only when this request is refused.
    let door = |method: &axum::http::Method| -> Option<RefusalDoor> {
        crate::cold::auth::chain::refusal_door(
            core_routes,
            path,
            method,
            uri.path_and_query().map_or(path, |t| t.as_str()),
        )
    };

    let mut declared_admin = false;
    let mut declared_core_admin = false;

    let mut claimed_at_key = false;
    if let Some(auth) = core_routes.declared_auth(path, req.method()) {
        match auth {
            busbar_contract::abi::mechanism::route::RouteAuth::None => {
                if physical_binding.is_some() {
                    return Err(admin_unauthorized_response());
                }
                return Ok(next.run(req).await);
            }
            busbar_contract::abi::mechanism::route::RouteAuth::Admin => {
                declared_admin = true;
                declared_core_admin = true;
            }
            busbar_contract::abi::mechanism::route::RouteAuth::Key => claimed_at_key = true,
        }
    }

    if let Some(auth) = (!claimed_at_key && !declared_admin)
        .then(|| app.plugin_routes.declared_auth(path, req.method()))
        .flatten()
    {
        match auth {
            busbar_contract::abi::mechanism::route::RouteAuth::None => {
                if physical_binding.is_some() {
                    return Err(admin_unauthorized_response());
                }
                return Ok(next.run(req).await);
            }
            busbar_contract::abi::mechanism::route::RouteAuth::Admin => declared_admin = true,
            busbar_contract::abi::mechanism::route::RouteAuth::Key => {}
        }
    }

    let is_admin = declared_admin
        || (!claimed_at_key && (path == ADMIN_PATH || path.starts_with(ADMIN_PATH_PREFIX)));
    if !is_admin && physical_binding.is_some() {
        return Err(admin_unauthorized_response());
    }
    // The request's one wall reading: every limiter, ticket and credential check below uses it.
    let now = busbar_kernel::store::now();

    let client_token: Option<String> = match inbound.as_ref() {
        Some(inbound) => inbound.client_token().map(str::to_owned),
        None => app.auth.extract_client_token(req.headers()),
    };

    let mut dpop_proven = false;

    let mut read = None;
    let client_token = if is_admin {
        client_token
    } else {
        match dpop::judge(
            &app,
            req.method(),
            path,
            inbound_headers.unwrap_or_else(|| req.headers()),
            dpop::Surface::Door,
        )
        .await
        {
            dpop::SenderConstraint::Unconstrained => client_token,
            dpop::SenderConstraint::Proven(token) => {
                dpop_proven = true;
                Some(token)
            }
            dpop::SenderConstraint::Refused(reason) => {
                if let Some(inbound) = inbound.as_ref() {
                    inbound.refuse(
                        busbar_contract::caps::StepName::Authenticate,
                        busbar_contract::caps::ReasonCode::Unauthenticated,
                    );
                }
                return Err(sender_constraint_response(
                    &app,
                    path,
                    door(req.method()).as_ref(),
                    admission.as_ref().map(|a| a.resource_metadata.as_str()),
                    reason,
                ));
            }
        }
    };

    let mut consumed = gate_consumed(&app, is_admin, dpop_proven);
    consumed.caller = verified_caller_credential(
        inbound
            .as_ref()
            .map(|admission| admission.inner.credential.as_ref()),
        client_token.as_deref(),
    );

    req.extensions_mut()
        .insert(CallerToken(client_token.clone()));

    if is_admin {
        // THE ADMIN DOOR'S FAILURE BUDGET: a source that has presented too many refused admin
        // credentials is answered 429 before any credential is judged.
        let admin_source = app.login_guard.source_of(
            req.extensions()
                .get::<login_limits::ClientAddr>()
                .map(|a| a.0.ip()),
            inbound_headers.unwrap_or_else(|| req.headers()),
        );
        let presented = carried_named(
            app.admin_modules
                .operator
                .carriers()
                .iter()
                .map(String::as_str),
            inbound_headers.unwrap_or_else(|| req.headers()),
        )
        .is_some();
        if let Some(retry_after) = app.login_guard.admin_throttled(admin_source, now) {
            if let Some(admission) = &inbound {
                admission.refuse(
                    busbar_contract::caps::StepName::Admit,
                    busbar_contract::caps::ReasonCode::RateLimited,
                );
            }
            return Err(rate_limited_after(retry_after));
        }
        let target = uri.path_and_query().map_or("/", |t| t.as_str());
        // The root deliberately defers core Admin routes to this verifier, independent
        // of the data chain. Their unverified open guest verdict is not an admin grant.
        let deferred_core_admin = declared_core_admin
            && inbound.as_ref().is_some_and(|admission| {
                matches!(&admission.selected_line().claimant,
                crate::guest::Claimant::Clean(name) if name == "core")
                    && matches!(admission.selected_line().auth, crate::guest::LineAuth::None)
            });
        let completed = req
            .extensions()
            .get::<std::sync::Arc<native_admin::ExecutionAdmission>>()
            .filter(|e| e.native().is_some())
            .cloned();
        let (door, strips, who) = if let Some(execution) = completed {
            let physical = physical_execution
                .as_ref()
                .ok_or_else(admin_unauthorized_response)?;
            if !std::sync::Arc::ptr_eq(physical.admission(), &execution)
                || physical.check_executing().is_err()
            {
                return Err(admin_unauthorized_response());
            }
            let original = req
                .extensions()
                .get::<std::sync::Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>>()
                .cloned()
                .ok_or_else(admin_unavailable_response)?;
            let request_lease = req
                .extensions()
                .get::<crate::limits::process_admission::RequestLease>()
                .cloned()
                .ok_or_else(admin_unavailable_response)?;
            let (lease, prepared) = execution.native().ok_or_else(admin_unauthorized_response)?;
            if !std::sync::Arc::ptr_eq(lease.generation(), &app)
                || !std::sync::Arc::ptr_eq(prepared.request(), &original)
                || !original.request().same_request(&request_lease)
            {
                return Err(admin_unauthorized_response());
            }
            let body = std::mem::replace(req.body_mut(), Body::empty());
            let bytes = crate::limits::input_body::gather(body, &request_lease, body_limit)
                .await
                .map_err(|error| match error {
                    crate::limits::input_body::GatherError::Capacity(_) => {
                        admin_unavailable_response()
                    }
                    crate::limits::input_body::GatherError::Body(_)
                    | crate::limits::input_body::GatherError::TooLarge => (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body exceeds configured limit",
                    )
                        .into_response(),
                })?;
            if !execution.matches_http(
                req.method().as_str(),
                target,
                inbound_headers.unwrap_or_else(|| req.headers()),
                &bytes,
            ) {
                return Err(admin_unauthorized_response());
            }
            *req.body_mut() = Body::from(original.body_bytes());
            let door = execution
                .door_for(lease.generation())
                .ok_or_else(admin_unauthorized_response)?;
            let strips = prepared
                .identity()
                .strip()
                .map(|name| Strip::field(name.to_owned()))
                .collect();
            (door, strips, execution.who())
        } else if let Some(admission) = inbound.as_ref().filter(|_| !deferred_core_admin) {
            let verdict = admission.admin_verdict();
            if admin_door_admits(&verdict.door, req.method().as_str(), target)
                && !admission.claim_admin_replay().await
            {
                admission.refuse(
                    busbar_contract::caps::StepName::Authenticate,
                    busbar_contract::caps::ReasonCode::Unauthenticated,
                );
                return Err(admin_unauthorized_response());
            }
            if let Some(execution) = admission.admin_execution() {
                req.extensions_mut().insert(execution);
            }
            (verdict.door, Vec::new(), admission.admin_who())
        } else if app.native_admin.is_none() && physical_pending.is_none() {
            let headers = inbound_headers.unwrap_or_else(|| req.headers());
            let (verdict, cap, replay, no_verdict, strips, denial) =
                judge_admin_chain(&app, req.method().as_str(), target, headers, false).await;
            let verdict = admin_chain_outcome(verdict, no_verdict)
                .map_err(|_| admin_unavailable_response())?;
            let who = admin_who_of(&app, verdict.clone(), cap, None);
            let (door, pending) = admin_door_claim_of(&app, verdict, cap, replay, denial);
            let door =
                claimed_admin_door(door, pending.as_ref(), req.method().as_str(), target, true)
                    .await;
            (door, strips, who)
        } else {
            let binding = physical_pending
                .as_ref()
                .ok_or_else(admin_unavailable_response)?
                .binding()
                .clone();
            let original = req
                .extensions()
                .get::<std::sync::Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot>>()
                .cloned()
                .ok_or_else(admin_unavailable_response)?;
            let request_lease = req
                .extensions()
                .get::<crate::limits::process_admission::RequestLease>()
                .cloned()
                .ok_or_else(admin_unavailable_response)?;
            if !original.request().same_request(&request_lease)
                || !binding.request().same_request(&request_lease)
                || !binding
                    .snapshot()
                    .is_ok_and(|snapshot| std::sync::Arc::ptr_eq(&snapshot, &original))
            {
                return Err(admin_unauthorized_response());
            }
            let body = std::mem::replace(req.body_mut(), Body::empty());
            let bytes = crate::limits::input_body::gather(body, &request_lease, body_limit)
                .await
                .map_err(|error| match error {
                    crate::limits::input_body::GatherError::Capacity(_) => {
                        admin_unavailable_response()
                    }
                    crate::limits::input_body::GatherError::Body(_)
                    | crate::limits::input_body::GatherError::TooLarge => (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body exceeds configured limit",
                    )
                        .into_response(),
                })?;
            let headers = inbound_headers.unwrap_or_else(|| req.headers());
            if !native_admin::snapshot_matches_http(
                &original,
                req.method().as_str(),
                target,
                headers,
                &bytes,
            ) {
                return Err(admin_unauthorized_response());
            }
            drop(bytes);
            let id = binding.invocation();
            let mut cx = admin_call_context(id);
            if let Some(deadline) = binding.deadline() {
                cx.deadline = cx.deadline.min(deadline);
            }
            let invocation = native_admin::Invocation {
                handle: binding.handle().clone(),
                selected: binding.app().clone(),
                id,
                cx,
                request: original.clone(),
            };
            let Ok((verdict, strips, projected)) =
                judge_admin_invocation(&invocation, headers).await
            else {
                return Err(admin_unavailable_response());
            };
            *req.body_mut() = Body::from(original.body_bytes());
            if admin_door_admits(&verdict.door, req.method().as_str(), target) {
                if let Some(pending) = verdict.claim {
                    let execution =
                        pending
                            .complete_admin_classified()
                            .await
                            .map_err(|error| match error {
                                native_admin::AdminCompletionRefused::ReplayDenied(_) => {
                                    admin_unauthorized_response()
                                }
                                native_admin::AdminCompletionRefused::ReplayUnknown(_)
                                | native_admin::AdminCompletionRefused::Unavailable => {
                                    admin_unavailable_response()
                                }
                            })?;
                    let execution = std::sync::Arc::new(execution);
                    let physical = std::sync::Arc::new(
                        physical_pending
                            .take()
                            .ok_or_else(admin_unauthorized_response)?
                            .complete_admin(execution.clone())
                            .map_err(|_| admin_unauthorized_response())?,
                    );
                    req.extensions_mut().insert(execution);
                    req.extensions_mut().insert(physical.clone());
                    physical_execution = Some(physical);
                }
            }
            (verdict.door, strips, projected)
        };
        if physical_pending.is_some() {
            return Err(admin_unauthorized_response());
        }
        let effect_context = if let Some(physical) = &physical_execution {
            effect::Context::from_physical(physical.clone())
                .map_err(|_| admin_unauthorized_response())?
        } else {
            if req
                .extensions()
                .get::<std::sync::Arc<native_admin::ExecutionAdmission>>()
                .is_some_and(|execution| execution.native().is_some())
            {
                return Err(admin_unauthorized_response());
            }
            effect::Context::new(
                req.method().as_str(),
                target,
                inbound_headers
                    .cloned()
                    .unwrap_or_else(|| req.headers().clone()),
                &door,
            )
        };
        let authorized = admin_door_admits(&door, req.method().as_str(), path);
        if path == crate::admin::gate::WHOAMI_PATH
            || (req.method() == axum::http::Method::POST && path == crate::admin::gate::KEYS_PATH)
        {
            req.extensions_mut().insert(AdminWhoSlot(who));
        }
        strike_named(&mut req, &mut consumed, strips.iter());
        req.extensions_mut().insert(consumed);

        if (presented && matches!(door, AdminDoor::Denied))
            || matches!(door, AdminDoor::Rejected(_))
        {
            app.login_guard.admin_refused(admin_source, now);
        }
        // TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a, condition B-C1: what a plane admin route this request
        // reaches may decide trust under, built only from this gate's own verdict.
        let trust_authority = trust_decision_authority(&door);
        let principal = match admin_principal_or_response(door) {
            Ok(principal) => principal,
            Err(response) => {
                if let Some(admission) = &inbound {
                    admission.refuse(
                        busbar_contract::caps::StepName::Authenticate,
                        busbar_contract::caps::ReasonCode::Unauthenticated,
                    );
                }
                return Err(*response);
            }
        };
        let required = crate::admin::gate::required_scope(req.method(), path);

        if !authorized {
            if let Some(admission) = &inbound {
                admission.refuse(
                    busbar_contract::caps::StepName::Approve,
                    busbar_contract::caps::ReasonCode::ScopeDenied,
                );
            }
            let actor = principal.id.as_str();
            if let crate::ratelimit::RateCheck::Denied {
                first_in_window: true,
            } =
                app.mutation_limiter
                    .check(actor, crate::ratelimit::MutationClass::Forbidden, now)
            {
                crate::audit_ring::AUDIT.record_by(
                    "admin.forbidden",
                    path,
                    crate::audit_ring::OUTCOME_REJECTED,
                    actor,
                );
            } else {
                diag_debug!(ADMIN_FORBIDDEN_SUPPRESSED, principal = %actor, path = %path, required = %required.as_str(),
                    "admin request forbidden (audit suppressed: already recorded this window)");
            }
            return Err(forbidden_response(
                required,
                crate::admin::seam::admin_verb_at(req.method().as_str(), path),
            ));
        }

        let method = req.method();
        let is_mutation = method == axum::http::Method::POST
            || method == axum::http::Method::PUT
            || method == axum::http::Method::PATCH
            || method == axum::http::Method::DELETE;
        if is_mutation {
            let rel = path
                .strip_prefix(crate::admin::gate::ADMIN_PREFIX)
                .unwrap_or(path);
            let class = crate::ratelimit::classify_mutation(rel);
            let actor = principal.id.as_str();
            if let crate::ratelimit::RateCheck::Denied { first_in_window } =
                app.mutation_limiter.check(actor, class, now)
            {
                if first_in_window {
                    crate::cold::auth::chain::record_admin_rate_limited(class.label(), path, actor);
                }
                if let Some(admission) = &inbound {
                    admission.refuse(
                        busbar_contract::caps::StepName::Admit,
                        busbar_contract::caps::ReasonCode::RateLimited,
                    );
                }
                return Err(rate_limited_response());
            }
        }
        req.extensions_mut().insert(AuthPrincipal(Some(principal)));
        if let Some(authority) = trust_authority {
            req.extensions_mut().insert(authority);
        }

        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        if physical_execution
            .as_ref()
            .is_some_and(|physical| physical.check_executing().is_err())
        {
            return Err(admin_unauthorized_response());
        }
        let response = effect::scope(Some(effect_context), next.run(req)).await;
        return Ok(match physical_execution {
            Some(physical) => native_admin::retain_physical_response(response, physical),
            None => response,
        });
    }

    if app.auth.keys_in_chain && app.upstream_creds() == UpstreamCreds::Passthrough {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            diag_warn!(
                KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
                "auth.chain names `keys` with upstream_credentials: passthrough: the keys verifier \
                 requires a valid virtual key on every request and supersedes passthrough's \
                 accept-and-forward-caller-credential intent. Use upstream_credentials: own (or omit \
                 it) alongside `keys`."
            );
        });
    }

    let ingress_signed = core_routes.signed_ingress(path);

    // The lines to strip: the admission's, then the signed reader's, then the chain's.
    let admitted_strips = inbound
        .as_ref()
        .map_or(&[][..], |admission| admission.inner.strips.as_slice());
    let mut signed_strips = Vec::new();
    let mut chain_strips = Vec::new();

    let reader =
        (inbound.is_none() && admission.is_none() && app.auth.keys_in_chain && ingress_signed)
            .then(|| app.auth.carrying_reader(req.headers()))
            .flatten();

    let mut pending: Option<PendingClaim> = None;
    let signed = match reader {
        None => inbound
            .as_ref()
            .filter(|admission| admission.inner.signed)
            .map(|admission| admission.verdict()),
        Some(reader) => {
            let (parts, body) = req.into_parts();
            let Ok(body_bytes) = axum::body::to_bytes(
                body,
                busbar_kernel_egress::upstream::max_translate_body_bytes(),
            )
            .await
            else {
                return Err(unauthorized_response(
                    &app,
                    path,
                    door(&parts.method).as_ref(),
                ));
            };
            let request = signed_request(&parts, &body_bytes);
            req = Request::from_parts(parts, Body::from(body_bytes));
            let mut call = reader.calls.verify(request);
            let answer = (&mut call).await;
            let (verified, named) = signed_verdict_of(answer, call.faulted());
            signed_strips = named;
            match verified {
                Verified::Pass => None,
                Verified::Identity(id) => {
                    let key = app.governance.as_deref().and_then(|gov| {
                        reader.kinds.iter().find_map(|kind| {
                            let (key, cred) = gov.lookup_credential(kind, &id.subject)?;
                            (key.enabled
                                && !crate::governance::key_row_expired(&key, now)
                                && cred.meta.is_live(now)
                                && !gov.is_revoked(&key.id))
                            .then(|| (*key).clone())
                        })
                    });

                    pending = PendingClaim::of(
                        ReplayClaim::of(&reader.name, id.replay, now),
                        app.governance.clone(),
                    );
                    match key {
                        Some(key) => Some(ChainVerdict::Identified {
                            module: crate::config::KEYS_MODULE.to_string(),
                            principal: principal_from_vkey(&key),
                            resolved: Some(std::sync::Arc::new(key)),
                            signed_authority: None,
                        }),
                        None => {
                            return Err(unauthorized_response(
                                &app,
                                path,
                                door(req.method()).as_ref(),
                            ))
                        }
                    }
                }

                Verified::Reject => {
                    return Err(unauthorized_response(
                        &app,
                        path,
                        door(req.method()).as_ref(),
                    ))
                }

                Verified::Failed => {
                    verify_without_verdict("data", &reader.name, "no verdict");
                    return Err(verifier_unavailable_response());
                }

                Verified::Overloaded => return Err(verifier_unavailable_response()),
            }
        }
    };

    let ticketed = match claimed_ticket_verdict(
        PresentedTicket {
            signed: signed.is_some(),
            keys_in_chain: app.auth.keys_in_chain,
            prefix: core_routes.door_ticket(path, req.method()),
            carried: inbound
                .as_ref()
                .and_then(crate::inbound::RequestAdmission::carried_ticket),
        },
        client_token.as_deref(),
        app.governance.as_ref(),
        now,
        app.root_rules.as_ref(),
    )
    .await
    {
        Ok(Some((verdict, record, admission))) => {
            consumed.ticket = Some(record);
            consumed.host_ticket_admission = admission;
            Some(verdict)
        }
        Ok(None) => None,
        Err(()) => {
            return Err(unauthorized_response(
                &app,
                path,
                door(req.method()).as_ref(),
            ))
        }
    };
    let verdict = if let Some(verdict) = signed {
        verdict
    } else if let Some(verdict) = ticketed {
        verdict
    } else {
        if let (Some(adm), Some(tok)) = (admission.as_ref(), client_token.as_deref()) {
            let read = read.get_or_insert_with(|| audience::Bearer::read(tok));
            match read.binding(&adm.audience) {
                audience::Binding::Deferred | audience::Binding::Bound => {}
                audience::Binding::Mismatch => {
                    return Err(challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        audience::MISMATCH_DESCRIPTION,
                        None,
                    ));
                }
                audience::Binding::Opaque => {
                    return Err(challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        audience::OPAQUE_DESCRIPTION,
                        None,
                    ));
                }
            }
        }
        let (judged, named, claim) = if let Some(admission) = &inbound {
            (Ok(admission.verdict()), Vec::new(), None)
        } else {
            AuthMiddleware::judge_chain_on_request_path_naming(
                &app.auth,
                client_token.as_deref(),
                &ChainHead::of(&req),
                app.governance.clone(),
                admission.as_ref().map(|a| a.audience.as_str()),
            )
            .await
        };
        match judged {
            Ok(verdict) => {
                chain_strips = named;
                pending = claim;
                verdict
            }

            Err(error) => return Err(data_verifier_error_response(error)),
        }
    };

    let signed_authority = match &verdict {
        ChainVerdict::Identified {
            signed_authority, ..
        } => signed_authority.clone(),
        _ => None,
    };
    let resolved = match resolve_data_plane_identity(&app, verdict) {
        Ok(admitted)
            if match &inbound {
                Some(admission) => admission.claim_replay().await,
                None => claim_won(pending.as_ref()).await,
            } =>
        {
            Ok(admitted)
        }
        Ok(_) => Err(IdentityRefusal::Denied),
        Err(refused) => Err(refused),
    };
    match resolved {
        Ok((principal, gov)) => {
            req.extensions_mut().insert(principal);
            req.extensions_mut().insert(gov);
            if let Some(authority) = signed_authority {
                req.extensions_mut().insert(authority);
            }
            strike_named(
                &mut req,
                &mut consumed,
                admitted_strips
                    .iter()
                    .chain(&signed_strips)
                    .chain(&chain_strips),
            );
            req.extensions_mut().insert(consumed);
        }
        Err(refusal) => {
            return Err(identity_refusal_response(
                refusal,
                admission.as_ref(),
                client_token.is_some(),
                || unauthorized_with_completion_taps(&app, path, door(req.method()).as_ref()),
            ));
        }
    }

    Ok(next.run(req).await)
}

pub use busbar_contract::auth::IdentityRefusal;

pub fn resolve_data_plane_identity(
    app: &crate::state::App,
    verdict: ChainVerdict,
) -> Result<(AuthPrincipal, crate::governance::GovCtx), IdentityRefusal> {
    resolve_identity_from_bindings(&app.role_bindings, verdict)
}

fn resolve_identity_from_bindings(
    role_bindings: &crate::config::RoleBindings,
    verdict: ChainVerdict,
) -> Result<(AuthPrincipal, crate::governance::GovCtx), IdentityRefusal> {
    match verdict {
        ChainVerdict::Open => Ok((AuthPrincipal(None), crate::governance::GovCtx::default())),
        ChainVerdict::Denied => Err(IdentityRefusal::Denied),
        ChainVerdict::Identified {
            module,
            principal,
            resolved,
            ..
        } => {
            let gov_key = resolved.or_else(|| {
                crate::governance::synthesize_bound_key(&module, &principal, role_bindings)
            });
            let Some(key) = gov_key else {
                if admits_ungoverned(&module, &principal, role_bindings) {
                    return Ok((
                        AuthPrincipal(Some(principal)),
                        crate::governance::GovCtx { key: None },
                    ));
                }
                return Err(IdentityRefusal::NoGrant);
            };
            Ok((
                AuthPrincipal(Some(principal)),
                crate::governance::GovCtx { key: Some(key) },
            ))
        }
    }
}

pub(crate) const REFUSE_EVERY_UNGOVERNED_PRINCIPAL: bool = true;

fn admits_ungoverned(
    module: &str,
    principal: &busbar_contract::auth::Principal,
    role_bindings: &crate::config::RoleBindings,
) -> bool {
    admits_ungoverned_under(
        REFUSE_EVERY_UNGOVERNED_PRINCIPAL,
        module,
        principal,
        role_bindings,
    )
}

fn admits_ungoverned_under(
    refuse_every: bool,
    module: &str,
    principal: &busbar_contract::auth::Principal,
    role_bindings: &crate::config::RoleBindings,
) -> bool {
    !refuse_every && (principal.roles.is_empty() || !role_bindings.contains_key(module))
}

fn signed_request(parts: &axum::http::request::Parts, body: &[u8]) -> VerifyRequest {
    use busbar_contract::redacted::Secret;
    VerifyRequest {
        point: busbar_contract::abi::auth::AuthPoint::HeadBody,
        lines: parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    Secret::new(value.as_bytes().to_vec()),
                )
            })
            .collect(),
        body: Some(body.to_vec()),
        method: parts.method.as_str().to_string(),
        authority: parts
            .uri
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        timestamp: busbar_kernel::store::now(),
        conn: 0,
        unit: 0,
        credential: None,
        peer: None,
    }
}

pub mod admit;

pub mod caller_credential;
use caller_credential::verified_caller_credential;
pub use caller_credential::{CallerCredential, ConsumedCredentials};

pub mod audience;

pub mod dpop;

pub mod challenge;

pub mod self_keys;

pub mod exchange;

pub mod login;

pub mod instances;
pub mod login_limits;

pub mod chain_run;
pub mod login_facts;
pub mod route_chain;
pub mod sight_redirect;
pub mod upstream_binding;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/plugin_chain_tests.rs"]
mod plugin_chain_tests;

#[cfg(test)]
#[path = "tests/chain_walk_tests.rs"]
mod chain_walk_tests;

#[cfg(test)]
#[path = "tests/instances_tests.rs"]
mod instances_tests;

#[cfg(test)]
#[path = "tests/acceptance_1_5_5_tests.rs"]
mod acceptance_1_5_5_tests;

#[cfg(test)]
#[path = "tests/ticket_admission_policy.rs"]
mod ticket_admission_policy;

#[cfg(test)]
#[path = "tests/ticket_single_path.rs"]
mod ticket_single_path;

#[cfg(test)]
#[path = "tests/verified_caller_policy.rs"]
mod verified_caller_policy;

// Script only the plugin boundary; the regression runs the ordinary inbound host.
#[cfg(test)]
impl AuthMiddleware {
    pub(crate) fn inbound_reader_fixture(
        calls: std::sync::Arc<dyn AuthCalls>,
        carrier: &'static str,
    ) -> Self {
        let carrier = HeaderName::from_static(carrier);
        Self {
            keys_in_chain: true,
            chain: Vec::new(),
            readers: vec![CredentialReader {
                name: "reader".into(),
                calls,
                kinds: std::sync::Arc::from([]),
                issued: None,
            }],
            reader_by_carrier: std::iter::once((carrier.clone(), 0)).collect(),
            carriers: vec![carrier],
            issued: None,
        }
    }
}

#[cfg(test)]
#[path = "tests/admin_grant_tests.rs"]
mod admin_grant_tests;

#[cfg(test)]
#[path = "tests/trust_authority_tests.rs"]
mod trust_authority_tests;
