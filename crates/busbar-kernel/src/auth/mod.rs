// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::config::AuthCfg;
use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_AUTH_CHAIN_EMPTY, ADMIN_CHAIN_STALLED,
    ADMIN_FORBIDDEN_SUPPRESSED, ADMIN_MODULE_UNRESOLVED, ADMIN_OFFLOAD_SATURATED,
    AUTH_CHAIN_OPEN_RELAY, AUTH_CHAIN_PANICKED, AUTH_OFFLOAD_SATURATED,
    KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
};
use crate::state::App;
use busbar_contract::auth_calls::{
    AuthCalls, Replay, Strip, StripPlace, Verified, VerifyAnswer, VerifyRequest,
};
use busbar_kernel_identity::operator::Judgement;

const AUTH_SCHEME_BEARER: &str = "bearer";

pub const HEALTHZ_PATH: &str = "/healthz";

pub const ADMIN_PATH: &str = "/api";

const ADMIN_PATH_PREFIX: &str = "/api/";

pub use busbar_contract::config::UpstreamCreds;

pub use busbar_contract::auth::CallerToken;

pub use busbar_contract::auth::{AuthModule, AuthVerdict, Principal};

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
    },
    Open,
    Denied,
}

pub struct AuthMiddleware {
    pub keys_in_chain: bool,

    chain: Vec<ChainEntry>,

    readers: Vec<CredentialReader>,

    carriers: Vec<HeaderName>,

    issued: Option<(String, busbar_contract::auth_calls::IssuedShape)>,
}

struct CredentialReader {
    name: String,
    calls: std::sync::Arc<dyn AuthCalls>,
    kinds: Vec<String>,
    carriers: Vec<HeaderName>,

    issued: Option<busbar_contract::auth_calls::IssuedShape>,
}

impl CredentialReader {
    fn carried(&self, headers: &HeaderMap) -> bool {
        self.carriers.iter().any(|c| headers.contains_key(c))
    }
}

struct ChainEntry {
    provider: String,

    calls: std::sync::Arc<dyn AuthCalls>,

    name: String,
}

fn chain_verdict_of(answer: VerifyAnswer) -> Judgement {
    Judgement::answered(answer)
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

const AUTH_REPLAY: &str = "auth-replay";

pub(crate) async fn replay_claimed(
    gov: Option<&crate::governance::GovState>,
    provider: &str,
    replay: &Replay,
    now: u64,
) -> bool {
    if replay.key.is_empty() {
        return true;
    }
    let Some(calls) = gov.and_then(crate::governance::GovState::store_calls) else {
        return false;
    };
    let token = format!("{provider}/{}", replay.key);
    let expires_at = now.saturating_add(replay.ttl_secs);
    calls
        .redeem_plane_token(AUTH_REPLAY, &token, expires_at, now)
        .await
        .unwrap_or(false)
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

pub struct PendingClaim {
    claim: ReplayClaim,
    gov: Option<std::sync::Arc<crate::governance::GovState>>,
}

impl std::fmt::Debug for PendingClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingClaim")
            .field("provider", &self.claim.provider)
            .finish_non_exhaustive()
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
        claim.map(|claim| PendingClaim { claim, gov })
    }

    pub async fn win(&self) -> bool {
        self.claim.win(self.gov.as_deref()).await
    }

    #[must_use]
    pub fn win_now(&self) -> bool {
        futures::executor::block_on(self.win())
    }
}

async fn claim_won(pending: Option<&PendingClaim>) -> bool {
    match pending {
        None => true,
        Some(pending) => pending.win().await,
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

fn strike_named(req: &mut Request<Body>, consumed: &mut ConsumedCredentials, strips: &[Strip]) {
    let fields: Vec<HeaderName> = strips
        .iter()
        .filter(|s| s.place == StripPlace::Field)
        .filter_map(|s| HeaderName::from_bytes(s.name.as_bytes()).ok())
        .collect();
    consumed.carry(&fields);
    let keys: Vec<&str> = strips
        .iter()
        .filter(|s| s.place == StripPlace::Query)
        .map(|s| s.name.as_ref())
        .collect();
    if keys.is_empty() {
        return;
    }
    if let Some(uri) = without_query_keys(req.uri(), &keys) {
        *req.uri_mut() = uri;
    }
    if let Some(original) = req.extensions_mut().get_mut::<axum::extract::OriginalUri>() {
        if let Some(uri) = without_query_keys(&original.0, &keys) {
            original.0 = uri;
        }
    }
}

pub(crate) fn without_query_keys(uri: &axum::http::Uri, keys: &[&str]) -> Option<axum::http::Uri> {
    let query = uri.query()?;
    let named = |pair: &&str| {
        let key = pair.split_once('=').map_or(*pair, |(k, _)| k);
        let decoded = url::form_urlencoded::parse(key.as_bytes())
            .next()
            .map(|(k, _)| k);
        keys.iter()
            .any(|k| *k == key || decoded.as_deref() == Some(*k))
    };
    if !query.split('&').any(|p| named(&p)) {
        return None;
    }
    let kept: Vec<&str> = query.split('&').filter(|p| !named(p)).collect();
    let path_and_query = match kept.is_empty() {
        true => uri.path().to_string(),
        false => format!("{}?{}", uri.path(), kept.join("&")),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    axum::http::Uri::from_parts(parts).ok()
}

const AUTH_ADMISSION_MAX_INFLIGHT: usize = 64;

const AUTH_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

static AUTH_ADMISSION_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(AUTH_ADMISSION_MAX_INFLIGHT));

struct TicketStoreTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for TicketStoreTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn ticket_store<T: Send + 'static>(
    run: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    ticket_store_on(&AUTH_ADMISSION_PERMITS, run).await
}

async fn ticket_store_on<T: Send + 'static>(
    permits: &'static tokio::sync::Semaphore,
    run: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    if tokio::runtime::Handle::try_current().is_err() {
        return run();
    }
    let Ok(Ok(permit)) = tokio::time::timeout(AUTH_ADMISSION_WAIT, permits.acquire()).await else {
        auth_saturated();
        return None;
    };
    let mut task = TicketStoreTask(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        run()
    }));
    (&mut task.0).await.ok().flatten()
}

const ADMIN_ADMISSION_MAX_INFLIGHT: usize = 16;

const ADMIN_ADMISSION_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

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

fn signed_verdict_of(answer: VerifyAnswer, faulted: bool, strips: &mut Vec<Strip>) -> Verified {
    let VerifyAnswer {
        verified,
        strips: named,
        ..
    } = answer;
    strips.extend(named);
    if faulted {
        auth_faulted();
        return Verified::Failed;
    }
    cleared(&AUTH_FAULTED_WARNED);
    verified
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
    pub modules: std::collections::HashMap<String, AdminModule>,

    pub operator: Operator,
}

pub struct AdminModule {
    pub calls: std::sync::Arc<dyn AuthCalls>,
}

impl AdminModule {
    #[cfg(test)]
    pub fn in_process(module: Box<dyn AuthModule>) -> Self {
        Self {
            calls: std::sync::Arc::new(stand_in::InProcessAuth::new(module)),
        }
    }
}

pub use busbar_kernel_identity::{
    caller_ref::CallerRefKey,
    operator::{Operator, OperatorCredential},
};

pub fn open_operator(
    registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
    digest: Option<String>,
    providers: &crate::config::IdentityProviders,
) -> Result<Operator, String> {
    let op = crate::config::operator_provider();
    let axis = crate::preflight::auth_axis(registry.clone());
    let answered = axis.as_ref().is_some_and(|axis| axis.answers(op));
    let defs = providers.iter().map(|(n, d)| (n.as_str(), d.module.trim()));
    let is_op = |m: &str| crate::config::names_operator(m);

    let carriers = axis.as_ref().map(|a| a.carriers(op)).unwrap_or_default();
    Operator::open(op, defs, &is_op, answered, digest, |d| {
        let axis = axis.ok_or_else(|| format!("no `kind: auth` plugin answers to '{op}'"))?;
        axis.open(op, op, &serde_json::Value::String(d.to_string()))
    })
    .map(|operator| operator.with_carriers(carriers))
}

pub(crate) fn auth_refusal(
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    module: &str,
) -> String {
    registry.kind_refusal(
        busbar_contract::abi::mechanism::kind::AUTH,
        "serve as an auth module",
        module,
    )
}

impl fmt::Debug for AdminAuthChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminAuthChain")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AdminAuthChain {
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            modules: std::collections::HashMap::new(),
            operator: Operator::new(crate::config::operator_provider()),
        }
    }

    pub fn build(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut modules: std::collections::HashMap<String, AdminModule> =
            std::collections::HashMap::new();
        let op = crate::config::operator_provider();
        let is_op = |m: &str| crate::config::names_operator(m);
        let mut axis: Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for entry in &cfg.admin_auth {
            match entry.module.as_str() {
                module if Operator::backed(op, &entry.name, Some(module), &is_op) => {}
                other => {
                    let name = entry.name.as_str();
                    let resolved = crate::config::secret::resolve_settings(
                        &entry.settings,
                        &registry.secret_slots(other),
                        &registry.reference_slots(other),
                        other,
                        secret_resolver,
                        &busbar_contract::config_time::ConfigScope::config_time(),
                    )
                    .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;
                    let refused = |e: String| {
                        format!(
                            "auth.admin_auth provider '{name}' (module '{other}') could not be \
                             loaded as a `kind: auth` plugin: {e}"
                        )
                    };

                    let axis = match &axis {
                        Some(axis) => axis.clone(),
                        None => {
                            let opened =
                                crate::preflight::auth_axis(registry.clone()).ok_or_else(|| {
                                    refused(format!("no `kind: auth` plugin answers to '{other}'"))
                                })?;
                            axis.insert(opened).clone()
                        }
                    };

                    if !axis.answers(other) {
                        return Err(refused(auth_refusal(registry.as_ref(), other)));
                    }

                    let label = format!("admin_auth.{name}");

                    let calls = axis
                        .open(other, &label, resolved.as_value())
                        .map_err(refused)?;

                    modules.insert(name.to_string(), AdminModule { calls });
                }
            }
        }
        Ok(Self {
            modules,
            operator: Operator::new(op),
        })
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
    pub fn new(
        cfg: &AuthCfg,
        registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut keys_in_chain = false;
        let mut chain: Vec<ChainEntry> = Vec::new();
        let mut axis: Option<std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>> = None;
        for entry in &cfg.chain {
            match entry.module.as_str() {
                crate::config::KEYS_MODULE => {
                    keys_in_chain = true;
                }
                other => {
                    let resolved = crate::config::secret::resolve_settings(
                        &entry.settings,
                        &registry.secret_slots(other),
                        &registry.reference_slots(other),
                        other,
                        secret_resolver,
                        &busbar_contract::config_time::ConfigScope::config_time(),
                    )
                    .map_err(|e| format!("auth.chain module '{other}' settings: {e}"))?;
                    let refused = |e: String| {
                        format!(
                            "auth.chain module '{other}' could not be loaded as a `kind: auth` \
                             plugin: {e}"
                        )
                    };
                    let axis = match &axis {
                        Some(axis) => axis.clone(),
                        None => {
                            let opened =
                                crate::preflight::auth_axis(registry.clone()).ok_or_else(|| {
                                    refused(format!("no `kind: auth` plugin answers to '{other}'"))
                                })?;
                            axis.insert(opened).clone()
                        }
                    };

                    if !axis.answers(other) {
                        return Err(refused(auth_refusal(registry.as_ref(), other)));
                    }
                    let opened = axis.open(other, &entry.name, resolved.as_value());

                    drop(resolved);
                    let calls = opened.map_err(refused)?;
                    chain.push(ChainEntry {
                        provider: entry.name.clone(),
                        name: calls.name().to_string(),
                        calls,
                    });
                }
            }
        }

        if chain.is_empty() && !keys_in_chain {
            diag_warn!(
                AUTH_CHAIN_OPEN_RELAY,
                "auth.chain is empty (open relay) - only acceptable for dev; reject in production"
            );
        }

        let mut readers = Vec::new();
        if keys_in_chain {
            let axis = match &axis {
                Some(axis) => Some(axis.clone()),
                None => crate::preflight::auth_axis(registry.clone()),
            };
            for module in axis.iter().flat_map(|a| a.credential_readers()) {
                let calls = axis
                    .as_ref()
                    .map(|a| a.open(&module, &module, &serde_json::json!({})))
                    .transpose()
                    .map_err(|e| {
                        format!(
                            "auth.chain names `keys`, and the `kind: auth` plugin '{module}' that \
                             verifies the credentials it holds could not be loaded: {e}"
                        )
                    })?;
                if let Some(calls) = calls {
                    readers.push(CredentialReader {
                        name: module.to_string(),
                        kinds: calls.credential_kinds(),
                        issued: calls.issued_shape(),
                        carriers: calls
                            .carriers()
                            .iter()
                            .filter_map(|c| HeaderName::from_bytes(c.as_bytes()).ok())
                            .collect(),
                        calls,
                    });
                }
            }
        }

        let carriers = match &axis {
            Some(axis) => axis.default_inbound_style()?,
            None => crate::preflight::auth_axis(registry.clone())
                .map(|axis| axis.default_inbound_style())
                .transpose()?
                .unwrap_or_default(),
        };

        let issued = readers
            .iter()
            .find_map(|r| {
                let kind = r.kinds.first()?.clone();
                r.issued.clone().map(|shape| (kind, shape))
            })
            .or_else(|| match &axis {
                Some(axis) => axis.issued_credential(),
                None => crate::preflight::auth_axis(registry.clone())
                    .and_then(|axis| axis.issued_credential()),
            });
        Ok(Self {
            keys_in_chain,
            chain,
            readers,
            carriers: header_names(&carriers),
            issued,
        })
    }

    #[cfg(test)]
    pub fn new_builtin(cfg: &AuthCfg) -> Self {
        let mut mw = Self::new(
            cfg,
            &crate::test_support::rows::empty(),
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect("builtin-only auth chain never fails to construct");
        if mw.carriers.is_empty() {
            mw.carriers = test_inbound_style();
        }

        if mw.issued.is_none() {
            mw.issued = Some(crate::test_support::issued::double());
        }
        mw
    }

    pub fn chain_names(&self) -> Vec<String> {
        self.chain.iter().map(|e| e.name.clone()).collect()
    }

    #[must_use]
    pub fn position_calls(&self, provider: &str) -> Option<std::sync::Arc<dyn AuthCalls>> {
        self.chain
            .iter()
            .find(|e| e.provider == provider)
            .map(|e| std::sync::Arc::clone(&e.calls))
    }

    pub(crate) fn signed_reader(
        &self,
        headers: &HeaderMap,
    ) -> Option<(String, std::sync::Arc<dyn AuthCalls>, Vec<String>)> {
        if !self.keys_in_chain {
            return None;
        }
        self.readers.iter().find(|r| r.carried(headers)).map(|r| {
            (
                r.name.clone(),
                std::sync::Arc::clone(&r.calls),
                r.kinds.clone(),
            )
        })
    }

    pub fn position_points(&self, provider: &str) -> busbar_contract::abi::auth::AuthPoints {
        use busbar_contract::abi::auth::AuthPoints;
        if let Some(entry) = self.chain.iter().find(|e| e.provider == provider) {
            return entry.calls.inbound_points();
        }
        let readers = self
            .readers
            .iter()
            .fold(0, |set, r| set | r.calls.inbound_points().bits());
        if readers == 0 {
            AuthPoints::HEAD
        } else {
            AuthPoints(readers)
        }
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
                    &mut Vec::new(),
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

    #[allow(clippy::too_many_arguments)]
    async fn walk(
        &self,
        head: &ChainHead,
        candidate: Option<&str>,
        gov: Option<&crate::governance::GovState>,
        now: u64,
        expected_aud: Option<&str>,
        reach: Reach,
        strips: &mut Vec<Strip>,
        claim: &mut Option<ReplayClaim>,
    ) -> Result<ChainVerdict, VerifierUnavailable> {
        if self.chain.is_empty() && !self.keys_in_chain {
            return Ok(ChainVerdict::Open);
        }
        for entry in &self.chain {
            let judged = judge(entry, head.request(candidate, now), reach).await?;
            strips.extend(judged.strips);
            match judged.verdict {
                AuthVerdict::Identify(principal) => {
                    *claim = ReplayClaim::of(&entry.provider, judged.replay, now);

                    return Ok(ChainVerdict::Identified {
                        module: entry.provider.clone(),
                        principal,
                        resolved: None,
                    });
                }
                AuthVerdict::Reject => return Ok(ChainVerdict::Denied),
                AuthVerdict::Pass => {}
            }
        }

        if self.keys_in_chain {
            return Ok(keys_arm_verdict(gov, candidate, now, expected_aud));
        }
        Ok(ChainVerdict::Denied)
    }

    pub fn flush_verified(&self, module: Option<&str>) -> Result<u64, String> {
        let mut flushed = 0;
        let mut failure = None;
        for entry in self
            .chain
            .iter()
            .filter(|e| module.is_none_or(|m| m == e.provider))
        {
            match entry.calls.refresh() {
                Ok(count) => flushed += count,
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(flushed), Err)
    }

    pub async fn run_chain_on_request_path(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<String>,
        head: ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> ChainVerdict {
        Self::judge_chain_on_request_path(auth, candidate, head, gov, expected_aud)
            .await
            .unwrap_or(ChainVerdict::Denied)
    }

    pub async fn judge_chain_on_request_path(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<String>,
        head: ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> Result<ChainVerdict, VerifierUnavailable> {
        let (verdict, _, pending) =
            Self::judge_chain_on_request_path_naming(auth, candidate, head, gov, expected_aud)
                .await;

        match verdict {
            Ok(ChainVerdict::Identified { .. }) if !claim_won(pending.as_ref()).await => {
                Ok(ChainVerdict::Denied)
            }
            verdict => verdict,
        }
    }

    pub async fn judge_chain_on_request_path_naming(
        auth: &std::sync::Arc<AuthMiddleware>,
        candidate: Option<String>,
        head: ChainHead,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> (
        Result<ChainVerdict, VerifierUnavailable>,
        Vec<Strip>,
        Option<PendingClaim>,
    ) {
        let now = busbar_kernel::store::now();
        let mut strips = Vec::new();
        let mut claim = None;
        let verdict = auth
            .walk(
                &head,
                candidate.as_deref(),
                gov.as_deref(),
                now,
                expected_aud.as_deref(),
                Reach::RequestPath,
                &mut strips,
                &mut claim,
            )
            .await;
        (verdict, strips, PendingClaim::of(claim, gov))
    }

    pub fn constant_time_eq(a: &str, b: &str) -> bool {
        busbar_contract::redacted::constant_time_eq(a, b)
    }

    pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
        let (scheme, token) = auth_header.split_once(' ')?;
        let token = token.trim_start_matches(' ');
        if scheme.eq_ignore_ascii_case(AUTH_SCHEME_BEARER) && !token.is_empty() {
            Some(token.to_string())
        } else {
            None
        }
    }

    pub fn extract_client_token(&self, headers: &HeaderMap) -> Option<String> {
        carried_credential(&self.carriers, headers)
    }

    pub fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        self.issued.clone()
    }

    pub(crate) fn carriers(&self) -> &[HeaderName] {
        &self.carriers
    }

    #[allow(dead_code)]
    pub fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
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
            let Ok(Ok(permit)) =
                tokio::time::timeout(AUTH_ADMISSION_WAIT, AUTH_ADMISSION_PERMITS.acquire()).await
            else {
                auth_saturated();
                return Ok(Judgement::of(AuthVerdict::Reject));
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

    match gov.verify_token(token, now, expected_aud) {
        Some(key) => ChainVerdict::Identified {
            module: crate::config::KEYS_MODULE.to_string(),
            principal: principal_from_vkey(&key),
            resolved: Some(key),
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
    zeroize::Zeroizing<String>,
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

fn unauthorized_ingress_response(ingress: crate::plane_driver::dispatch::Ingress) -> Response {
    let dialect = crate::ingress::native::envelope_dialect(ingress);
    let message = vendor_auth_failure_message(dialect);
    let (status, kind) = auth_failure_status_and_kind(dialect);
    crate::ingress::native::native_error(ingress, status, kind, message)
}

pub(crate) fn inbound_candidate(
    app: &crate::state::App,
    headers: &HeaderMap,
) -> Option<busbar_contract::redacted::Secret<String>> {
    app.oauth_as
        .as_ref()
        .and_then(|_| dpop::dpop_credential(headers))
        .or_else(|| app.auth.extract_client_token(headers))
        .map(busbar_contract::redacted::Secret::new)
}

pub fn carried_credential(carriers: &[HeaderName], headers: &HeaderMap) -> Option<String> {
    carriers.iter().find_map(|carrier| {
        let value = headers.get(carrier)?.to_str().ok()?;
        if *carrier == AUTHORIZATION {
            AuthMiddleware::extract_bearer_token(value)
        } else {
            Some(value.to_owned()).filter(|t| !t.is_empty())
        }
    })
}

pub(crate) fn header_names(words: &[String]) -> Vec<HeaderName> {
    words
        .iter()
        .filter_map(|w| HeaderName::from_bytes(w.as_bytes()).ok())
        .collect()
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
    strips: Vec<Strip>,
    replay: Option<(String, Box<Replay>)>,
    no_verdict: bool,
}

async fn run_admin_chain(
    app: &crate::state::App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
    carried: &mut AdminCarried,
) -> AdminChainAnswer {
    if app.admin_chain.is_empty() {
        return (ChainVerdict::Open, None);
    }

    let candidate = carried_credential(
        &header_names(app.admin_modules.operator.carriers()),
        headers,
    );
    let candidate = candidate.as_deref();
    let now = busbar_kernel::store::now();
    for name in &app.admin_chain {
        let operator = app.admin_modules.operator.is(name);
        let outcome = match name.as_str() {
            _ if operator => {
                let operator = &app.admin_modules.operator;
                let mut head = admin_head(method, target, headers, now);

                head.credential = candidate
                    .map(|c| busbar_contract::redacted::Secret::new(c.as_bytes().to_vec()));
                match probe {
                    true => operator.probe(&head),
                    false => operator.judge(head).await,
                }
            }

            other => {
                let mut request = admin_head(method, target, headers, now);
                request.credential = candidate
                    .map(|c| busbar_contract::redacted::Secret::new(c.as_bytes().to_vec()));
                external_admin_module(app, other, request, probe).await
            }
        }
        .unwrap_or_else(|| {
            diag_error!(
                ADMIN_MODULE_UNRESOLVED,
                module = name.as_str(),
                "admin_auth names a module with no resolved plugin; skipping (boot resolves \
                 every non-builtin admin module, fail-closed)"
            );
            Judgement::of(AuthVerdict::Pass)
        });
        carried.strips.extend(outcome.strips);
        if outcome.no_verdict {
            verify_without_verdict("admin", name, "no verdict");
            carried.no_verdict = true;
        }
        match outcome.verdict {
            AuthVerdict::Identify(principal) => {
                carried.replay = outcome.replay.map(|r| (name.clone(), r));

                let cap = module_admin_scope_cap(app, name);
                return (
                    ChainVerdict::Identified {
                        module: name.clone(),
                        principal,
                        resolved: None,
                    },
                    cap,
                );
            }
            AuthVerdict::Reject => return (ChainVerdict::Denied, None),
            AuthVerdict::Pass => {}
        }
    }
    (ChainVerdict::Denied, None)
}

async fn external_admin_module(
    app: &crate::state::App,
    name: &str,
    request: VerifyRequest,
    probe: bool,
) -> Option<Judgement> {
    let module = app.admin_modules.modules.get(name)?;
    if probe {
        return Some(module.calls.verify_now(&request).map_or_else(
            || Judgement::without_verdict(Vec::new()),
            |answer| admin_verdict_of(answer, false),
        ));
    }

    let Ok(Ok(permit)) =
        tokio::time::timeout(ADMIN_ADMISSION_WAIT, ADMIN_ADMISSION_PERMITS.acquire()).await
    else {
        admin_saturated();
        return Some(Judgement::of(AuthVerdict::Reject));
    };
    let mut call = module.calls.verify(request);
    let answered = tokio::time::timeout(ADMIN_ADMISSION_WAIT, &mut call).await;
    drop(permit);
    Some(match answered {
        Ok(answer) => admin_verdict_of(answer, call.faulted()),
        Err(_) => {
            admin_stalled();
            Judgement::without_verdict(Vec::new())
        }
    })
}

fn module_admin_scope_cap(
    app: &crate::state::App,
    module: &str,
) -> Option<busbar_contract::authz::Scope> {
    module_scope_cap(&app.auth_scope_caps, &app.admin_modules.operator, module)
}

fn module_scope_cap(
    caps: &std::collections::HashMap<String, String>,
    operator: &Operator,
    module: &str,
) -> Option<busbar_contract::authz::Scope> {
    use busbar_contract::authz::Scope;
    if operator.is(module) {
        return None;
    }
    Some(
        caps.get(module)
            .map(String::as_str)
            .and_then(Scope::parse)
            .unwrap_or(Scope::ReadOnly),
    )
}

pub fn dry_run_admin_scope(
    app: &crate::state::App,
    headers: &HeaderMap,
) -> busbar_contract::authz::Grants {
    if app.admin_chain.is_empty() {
        diag_warn!(
            ADMIN_AUTH_CHAIN_EMPTY,
            "admin-scope dry-run evaluated an EMPTY admin_auth chain: the open (anonymous, \
             full-authority) dev posture earns THIS caller no credential-based scope and is \
             reported as no-grant, never full"
        );
        return busbar_contract::authz::Grants::default();
    }

    match probe_admin_door(app, "GET", "/", headers, false) {
        AdminDoor::Identified(_, grants) | AdminDoor::Listed(_, grants, _) => grants,

        AdminDoor::Open | AdminDoor::Denied | AdminDoor::Unavailable(_) => {
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
    /// The explicit `admin_auth: []` open posture: anonymous, full authority.
    Open,
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
}

fn admin_head(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    now: u64,
) -> busbar_contract::auth_calls::VerifyRequest {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (target, None),
    };
    let authority = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    busbar_contract::auth_calls::VerifyRequest {
        point: busbar_contract::abi::auth::AuthPoint::Head,
        lines: (headers.iter())
            .map(|(n, v)| {
                let value = busbar_contract::redacted::Secret::new(v.as_bytes().to_vec());
                (n.as_str().to_string(), value)
            })
            .collect(),
        method: method.to_string(),
        authority: authority.to_string(),
        path: path.to_string(),
        query,
        timestamp: now,
        conn: 0,
        unit: 0,
        credential: None,
        peer: None,
        body: None,
    }
}

async fn judge_admin_door(
    app: &App,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    probe: bool,
    claim: bool,
    strips: &mut Vec<Strip>,
) -> Result<AdminDoor, VerifierUnavailable> {
    let (verdict, cap, replay, no_verdict) =
        judge_admin_chain(app, method, target, headers, probe, strips).await;
    if no_verdict && verdict == ChainVerdict::Denied {
        return Err(VerifierUnavailable::NoVerdict);
    }
    let (door, pending) = admin_door_claim_of(app, verdict, cap, replay);

    if claim && admin_door_admits(&door, method, target) && !claim_won(pending.as_ref()).await {
        return Ok(AdminDoor::Denied);
    }
    Ok(door)
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
) -> (AdminDoor, Option<PendingClaim>) {
    let identified = matches!(verdict, ChainVerdict::Identified { .. });
    let now = busbar_kernel::store::now();
    let claim = replay
        .filter(|_| identified)
        .and_then(|(provider, replay)| ReplayClaim::of(&provider, Some(replay), now));
    (
        admin_door_of(app, verdict, cap),
        PendingClaim::of(claim, app.governance.clone()),
    )
}

pub fn admin_door_admits(door: &AdminDoor, method: &str, target: &str) -> bool {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let required = crate::admin::scope::admin_required_scope(method, path);
    match door {
        AdminDoor::Open => true,
        AdminDoor::Denied | AdminDoor::Unavailable(_) => false,
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
    strips: &mut Vec<Strip>,
) -> (
    ChainVerdict,
    Option<busbar_contract::authz::Scope>,
    Option<(String, Box<Replay>)>,
    bool,
) {
    let mut carried = AdminCarried::default();
    let (verdict, cap) = run_admin_chain(app, method, target, headers, probe, &mut carried).await;
    strips.append(&mut carried.strips);
    (verdict, cap, carried.replay, carried.no_verdict)
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
    match verdict {
        ChainVerdict::Open => AdminDoor::Open,
        ChainVerdict::Denied => AdminDoor::Denied,
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            let grants = admin_scope_for(app, Some(&module), Some(&principal));
            let rungs = cap_admin_scope(grants, cap);
            let named = admin_verbs_named(app, &module, &principal, cap);
            if named.is_empty() {
                return AdminDoor::Identified(principal, rungs);
            }

            let reach = (named.iter())
                .filter_map(|verb| crate::admin::seam::admin_verb_rung(verb.as_str()))
                .fold(rungs, busbar_contract::authz::Grants::with);
            AdminDoor::Listed(principal, reach, VerbAllowList { rungs, named })
        }
    }
}

pub fn admin_door(app: &App, method: &str, target: &str, headers: &HeaderMap) -> AdminDoor {
    probe_admin_door(app, method, target, headers, true)
}

pub fn admin_verdict(app: &App, method: &str, target: &str, headers: &HeaderMap) -> AdminVerdict {
    let (door, claim) = probe_admin_verdict(app, method, target, headers);
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

    if claim
        && admin_door_admits(&door, method, target)
        && pending.as_ref().is_some_and(|p| !p.win_now())
    {
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
    let mut strips = Vec::new();
    let judged = std::pin::pin!(judge_admin_chain(
        app,
        method,
        target,
        headers,
        true,
        &mut strips
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let (verdict, cap, replay, no_verdict) = match std::future::Future::poll(judged, &mut cx) {
        std::task::Poll::Ready(judged) => judged,

        std::task::Poll::Pending => {
            return (AdminDoor::Unavailable(VerifierUnavailable::NoVerdict), None)
        }
    };
    if no_verdict && verdict == ChainVerdict::Denied {
        return (AdminDoor::Unavailable(VerifierUnavailable::NoVerdict), None);
    }
    admin_door_claim_of(app, verdict, cap, replay)
}

fn admin_scope_for(
    app: &crate::state::App,
    module: Option<&str>,
    principal: Option<&Principal>,
) -> busbar_contract::authz::Grants {
    admin_scope_from_bindings(
        &app.role_bindings,
        &app.admin_modules.operator,
        crate::config::operator_principal_id(),
        module,
        principal,
    )
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

impl VerbAllowList {
    #[must_use]
    pub fn admits(&self, verb: Option<&str>, needed: busbar_contract::authz::Scope) -> bool {
        self.rungs.allows(needed) || verb.is_some_and(|v| self.named.contains(v))
    }
}

fn admin_verbs_named(
    app: &crate::state::App,
    module: &str,
    principal: &Principal,
    cap: Option<busbar_contract::authz::Scope>,
) -> std::collections::BTreeSet<String> {
    let Some(table) = app.role_bindings.get(module) else {
        return std::collections::BTreeSet::new();
    };
    (principal.roles.iter())
        .filter_map(|role| table.get(role))
        .filter_map(|b| match b.verb_grant() {
            Some(Ok(crate::config::VerbGrant::Named(names))) => Some(names),
            _ => None,
        })
        .flatten()
        .filter(|verb| {
            crate::admin::seam::admin_verb_rung(verb.as_str())
                .is_some_and(|rung| cap.is_none_or(|c| c.allows(rung)))
        })
        .collect()
}

fn admin_unauthorized_response() -> Response {
    let e = crate::admin::gate::ApiError::Unauthorized;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::WWW_AUTHENTICATE, "Bearer")
        .body(Body::from(body))
        .expect("static unauthorized response")
}

fn forbidden_response(needed: busbar_contract::authz::Scope) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": "forbidden",
            "message": format!(
                "this endpoint requires the `{}` admin scope",
                needed.as_str()
            ),
        }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static forbidden response")
}

fn rate_limited_response() -> Response {
    let e = crate::admin::gate::ApiError::RateLimited;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .header(
            axum::http::header::RETRY_AFTER,
            crate::ratelimit::MUTATION_RATE_WINDOW_SECS.to_string(),
        )
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static rate-limited response")
}

pub(crate) fn unauthorized_with_completion_taps(
    app: &std::sync::Arc<crate::state::App>,
    path: &str,
    door: Option<&RefusalDoor>,
) -> Response {
    let proto = crate::ingress::native::envelope_dialect(ingress_for_path(app, path));
    if !app.tap_hooks_response.is_empty() {
        let shape = crate::hooks::taps::StageShape::zeroed(app.next_request_id(), "", proto, false);
        let status = auth_failure_status_and_kind(proto).0.as_u16();

        let host = crate::plane_driver::engine_host_value(app);
        let host: &dyn crate::plane_driver::EngineHost = &host;
        crate::hooks::taps::fire_stage_taps_where(
            &app.tap_hooks_response,
            &shape,
            busbar_contract::hook_wire::HookStageProjection {
                at: "response",
                model: None,
                attempt_number: None,
                remaining_candidates: None,
                previous_failure: None,
                outcome: Some("rejected_by_auth"),
                status: Some(status),
            },
            Default::default(),
            &|groups: &[String]| host.caller_in_hook_groups(None, groups),
        );
    }
    unauthorized_response(app, path, door)
}

pub(crate) fn verifier_unavailable_response() -> Response {
    crate::limits::admission::inbound_overloaded_response()
}

pub const ADMIN_AUTH_UNAVAILABLE_MESSAGE: &str =
    "admin authentication is unavailable (the auth module answered no verdict); retry shortly";

pub const ADMIN_AUTH_RETRY_AFTER: &str = crate::limits::admission::OVERLOADED_RETRY_AFTER;

fn admin_unavailable_response() -> Response {
    let mut resp = crate::admin::gate::err_json(&crate::admin::gate::ApiError::Unavailable(
        ADMIN_AUTH_UNAVAILABLE_MESSAGE.to_string(),
    ));
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from_static(ADMIN_AUTH_RETRY_AFTER),
    );
    resp
}

pub(crate) fn gate_consumed(app: &App, is_admin: bool, dpop_proven: bool) -> ConsumedCredentials {
    let mut consumed = ConsumedCredentials::carrying(app.auth.carriers());
    if !app.admin_chain.is_empty() {
        consumed.carry(&header_names(app.admin_modules.operator.carriers()));
    }
    if dpop_proven || is_admin {
        consumed.carry(&[dpop::DPOP_HEADER]);
    }
    consumed
}

#[allow(clippy::result_large_err)]
pub(crate) async fn auth_middleware(
    crate::state::CurrentApp(app): crate::state::CurrentApp,

    core_routes: &crate::core_routes::CoreRouteTable,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let inbound = req
        .extensions()
        .get::<crate::inbound::RequestAdmission>()
        .cloned();
    let inbound_headers = inbound
        .as_ref()
        .map(|admission| crate::inbound::header_map(&admission.inner.original));

    let mut _mw = crate::profile::start(crate::profile::Stage::MwAuth);
    let path = req.uri().path().to_owned();
    let admission = inbound.as_ref().map_or_else(
        || {
            (!crate::router::is_private_listener())
                .then(|| app.planes.admission_for(&path).cloned())
                .flatten()
        },
        crate::inbound::RequestAdmission::plane_admission,
    );

    let door: Option<RefusalDoor> = core_routes.door_refusal(&path, req.method()).map(|refuse| {
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| path.clone(), |t| t.as_str().to_owned());
        (refuse.clone(), zeroize::Zeroizing::new(target))
    });

    let mut declared_admin = false;

    let mut claimed_at_key = false;
    if let Some(auth) = core_routes.declared_auth(&path, req.method()) {
        match auth {
            busbar_contract::abi::mechanism::route::RouteAuth::None => {
                drop(_mw.take());
                return Ok(next.run(req).await);
            }
            busbar_contract::abi::mechanism::route::RouteAuth::Admin => declared_admin = true,
            busbar_contract::abi::mechanism::route::RouteAuth::Key => claimed_at_key = true,
        }
    }

    if let Some(auth) = (!claimed_at_key && !declared_admin)
        .then(|| app.plugin_routes.declared_auth(&path, req.method()))
        .flatten()
    {
        match auth {
            busbar_contract::abi::mechanism::route::RouteAuth::None => {
                drop(_mw.take());
                return Ok(next.run(req).await);
            }
            busbar_contract::abi::mechanism::route::RouteAuth::Admin => declared_admin = true,
            busbar_contract::abi::mechanism::route::RouteAuth::Key => {}
        }
    }

    let is_admin = declared_admin
        || (!claimed_at_key && (path == ADMIN_PATH || path.starts_with(ADMIN_PATH_PREFIX)));

    let client_token: Option<String> = app
        .auth
        .extract_client_token(inbound_headers.as_ref().unwrap_or_else(|| req.headers()));

    let mut dpop_proven = false;

    let mut read = None;
    let client_token = if is_admin {
        client_token
    } else {
        match dpop::judge(
            &app,
            req.method(),
            &path,
            inbound_headers.as_ref().unwrap_or_else(|| req.headers()),
            client_token.as_deref(),
            &mut read,
        )
        .await
        {
            dpop::SenderConstraint::Unconstrained => client_token,
            dpop::SenderConstraint::Proven(token) => {
                dpop_proven = true;
                Some(token)
            }
            dpop::SenderConstraint::Refused => {
                return Err(match admission.as_ref() {
                    Some(adm) => challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        "A DPoP-bound access token needs its DPoP proof (RFC 9449), and this one \
                         did not verify.",
                        None,
                    ),
                    None => unauthorized_response(&app, &path, door.as_ref()),
                });
            }
        }
    };

    let mut consumed = gate_consumed(&app, is_admin, dpop_proven);
    consumed.caller =
        match &inbound {
            Some(admission) => admission.inner.credential.as_ref().map(|credential| {
                CallerCredential::verified(credential.expose(&crate::seal::lend()))
            }),
            None => client_token.as_deref().map(CallerCredential::verified),
        };

    req.extensions_mut()
        .insert(CallerToken(client_token.clone()));

    if is_admin {
        let target = req.uri().path_and_query().map_or("/", |t| t.as_str());
        let mut strips = Vec::new();
        let judged = judge_admin_door(
            &app,
            req.method().as_str(),
            target,
            inbound_headers.as_ref().unwrap_or_else(|| req.headers()),
            false,
            true,
            &mut strips,
        );

        let Ok(door) = judged.await else {
            return Err(admin_unavailable_response());
        };
        let authorized = admin_door_admits(&door, req.method().as_str(), &path);
        strike_named(&mut req, &mut consumed, &strips);
        req.extensions_mut().insert(consumed);

        let principal = match door {
            AdminDoor::Identified(principal, _) | AdminDoor::Listed(principal, _, _) => {
                Some(principal)
            }

            AdminDoor::Open => None,

            AdminDoor::Denied => return Err(admin_unauthorized_response()),
            AdminDoor::Unavailable(_) => return Err(admin_unavailable_response()),
        };
        let required = crate::admin::gate::required_scope(req.method(), &path);

        if !authorized {
            let actor = principal
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or("anonymous");
            if let crate::ratelimit::RateCheck::Denied {
                first_in_window: true,
            } = app.mutation_limiter.check(
                actor,
                crate::ratelimit::MutationClass::Forbidden,
                busbar_kernel::store::now(),
            ) {
                crate::audit_ring::AUDIT.record_by(
                    "admin.forbidden",
                    &path,
                    crate::audit_ring::OUTCOME_REJECTED,
                    actor,
                );
            } else {
                diag_debug!(ADMIN_FORBIDDEN_SUPPRESSED, principal = %actor, path = %path, required = %required.as_str(),
                    "admin request forbidden (audit suppressed: already recorded this window)");
            }
            return Err(forbidden_response(required));
        }

        let method = req.method();
        let is_mutation = method == axum::http::Method::POST
            || method == axum::http::Method::PUT
            || method == axum::http::Method::PATCH
            || method == axum::http::Method::DELETE;
        if is_mutation {
            let rel = path
                .strip_prefix(crate::admin::gate::ADMIN_PREFIX)
                .unwrap_or(&path);
            let class = crate::ratelimit::classify_mutation(rel);
            let actor = principal
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or("anonymous");
            if let crate::ratelimit::RateCheck::Denied { first_in_window } = app
                .mutation_limiter
                .check(actor, class, busbar_kernel::store::now())
            {
                if first_in_window {
                    crate::audit_ring::AUDIT.record_by(
                        "admin.rate_limited",
                        &format!("{}:{path}", class.label()),
                        crate::audit_ring::OUTCOME_REJECTED,
                        actor,
                    );
                }
                return Err(rate_limited_response());
            }
        }
        req.extensions_mut().insert(AuthPrincipal(principal));

        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        drop(_mw.take());
        return Ok(next.run(req).await);
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

    let ingress_signed = core_routes.signed_ingress(&path);

    let mut strips = inbound
        .as_ref()
        .map_or_else(Vec::new, |admission| admission.inner.strips.clone());

    let reader =
        (inbound.is_none() && admission.is_none() && app.auth.keys_in_chain && ingress_signed)
            .then(|| app.auth.readers.iter().find(|r| r.carried(req.headers())))
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
                return Err(unauthorized_response(&app, &path, door.as_ref()));
            };
            let request = signed_request(&parts, &body_bytes);
            req = Request::from_parts(parts, Body::from(body_bytes));
            let mut call = reader.calls.verify(request);
            let answer = (&mut call).await;
            match signed_verdict_of(answer, call.faulted(), &mut strips) {
                Verified::Pass => None,
                Verified::Identity(id) => {
                    let now = busbar_kernel::store::now();
                    let key = app.governance.as_deref().and_then(|gov| {
                        reader.kinds.iter().find_map(|kind| {
                            let (key, cred) = gov.lookup_credential(kind, &id.subject)?;
                            (key.enabled && cred.meta.is_live(now) && !gov.is_revoked(&key.id))
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
                        }),
                        None => return Err(unauthorized_response(&app, &path, door.as_ref())),
                    }
                }

                Verified::Reject => return Err(unauthorized_response(&app, &path, door.as_ref())),

                Verified::Failed => {
                    verify_without_verdict("data", &reader.name, "no verdict");
                    return Err(verifier_unavailable_response());
                }

                Verified::Overloaded => return Err(verifier_unavailable_response()),
            }
        }
    };

    let ticketed = match (
        signed.is_none(),
        core_routes.door_ticket(&path, req.method()),
        client_token.as_deref(),
    ) {
        (true, Some(prefix), Some(token))
            if app.auth.keys_in_chain && token.starts_with(prefix) =>
        {
            let admitted = match app.governance.as_ref() {
                Some(gov) => {
                    gov.admit_ticket_async(prefix, token, busbar_kernel::store::now())
                        .await
                }
                None => None,
            };
            match admitted {
                Some((key, record)) => {
                    consumed.ticket = Some(record);
                    Some(ChainVerdict::Identified {
                        module: crate::config::KEYS_MODULE.to_string(),
                        principal: principal_from_vkey(&key),
                        resolved: Some(key),
                    })
                }
                None => return Err(unauthorized_response(&app, &path, door.as_ref())),
            }
        }
        _ => None,
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
                    ))
                }
                audience::Binding::Opaque => {
                    return Err(challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        audience::OPAQUE_DESCRIPTION,
                        None,
                    ))
                }
            }
        }
        let (judged, named, claim) = if let Some(admission) = &inbound {
            (Ok(admission.verdict()), Vec::new(), None)
        } else {
            AuthMiddleware::judge_chain_on_request_path_naming(
                &app.auth,
                client_token.clone(),
                ChainHead::of(&req),
                app.governance.clone(),
                admission.as_ref().map(|a| a.audience.clone()),
            )
            .await
        };
        match judged {
            Ok(verdict) => {
                strips.extend(named);
                pending = claim;
                verdict
            }

            Err(VerifierUnavailable::Overloaded | VerifierUnavailable::NoVerdict) => {
                return Err(verifier_unavailable_response())
            }
        }
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
            strike_named(&mut req, &mut consumed, &strips);
            req.extensions_mut().insert(consumed);
        }
        Err(IdentityRefusal::Denied) => {
            if let Some(adm) = admission.as_ref() {
                let kind = if client_token.is_none() {
                    challenge::ChallengeError::Absent
                } else {
                    challenge::ChallengeError::InvalidToken
                };
                return Err(challenge::refuse(
                    kind,
                    &adm.resource_metadata,
                    "Authentication is required for this resource.",
                    None,
                ));
            }
            return Err(unauthorized_with_completion_taps(
                &app,
                &path,
                door.as_ref(),
            ));
        }
        Err(IdentityRefusal::NoGrant) => {
            if let Some(adm) = admission.as_ref() {
                return Err(challenge::refuse(
                    challenge::ChallengeError::InsufficientScope,
                    &adm.resource_metadata,
                    "The authenticated principal carries no grant on this resource.",
                    None,
                ));
            }
            return Err(unauthorized_with_completion_taps(
                &app,
                &path,
                door.as_ref(),
            ));
        }
    }

    drop(_mw.take());
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

pub const REFUSE_EVERY_UNGOVERNED_PRINCIPAL: bool = true;

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

#[cfg(test)]
fn test_inbound_style() -> Vec<HeaderName> {
    if crate::preflight::linked_auth_names().is_empty() {
        return header_names(&crate::test_support::outbound_auth::double_inbound_style());
    }
    header_names(
        &crate::preflight::linked_auth_axis()
            .and_then(|axis| axis.default_inbound_style().ok())
            .unwrap_or_default(),
    )
}

#[cfg(any(test, feature = "test-support"))]
impl AuthMiddleware {
    pub fn from_calls_for_test(
        chain: Vec<(String, std::sync::Arc<dyn AuthCalls>)>,
        carriers: &[&str],
    ) -> Self {
        let chain = chain
            .into_iter()
            .map(|(provider, calls)| ChainEntry {
                provider,
                name: calls.name().to_string(),
                calls,
            })
            .collect();
        Self {
            keys_in_chain: false,
            chain,
            readers: Vec::new(),
            carriers: carriers
                .iter()
                .filter_map(|word| HeaderName::from_bytes(word.as_bytes()).ok())
                .collect(),
            issued: None,
        }
    }

    #[cfg(test)]
    pub fn from_doors_for_test(chain: Vec<(String, std::sync::Arc<dyn AuthCalls>)>) -> Self {
        let carriers = test_inbound_style();
        let names: Vec<&str> = carriers.iter().map(HeaderName::as_str).collect();
        Self::from_calls_for_test(chain, &names)
    }

    #[must_use]
    pub fn with_reader_for_test(
        mut self,
        calls: std::sync::Arc<dyn AuthCalls>,
        kinds: Vec<String>,
        carriers: &[&str],
    ) -> Self {
        self.keys_in_chain = true;
        self.readers.push(CredentialReader {
            name: "test-reader".to_owned(),
            kinds,
            issued: None,
            carriers: carriers
                .iter()
                .filter_map(|c| HeaderName::from_bytes(c.as_bytes()).ok())
                .collect(),
            calls,
        });
        self
    }
}

pub mod admit;

pub mod caller_credential;
pub use caller_credential::{present_caller, CallerCredential, ConsumedCredentials};

pub mod audience;

pub mod dpop;

pub mod challenge;

pub mod self_keys;

pub mod exchange;

pub mod login;

#[cfg(test)]
pub(crate) use crate::test_support::auth_stand_in as stand_in;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/plugin_chain_tests.rs"]
mod plugin_chain_tests;

#[cfg(test)]
#[path = "tests/acceptance_1_5_5_tests.rs"]
mod acceptance_1_5_5_tests;

#[cfg(test)]
#[path = "tests/ticket_store_tests.rs"]
mod ticket_store_tests;
