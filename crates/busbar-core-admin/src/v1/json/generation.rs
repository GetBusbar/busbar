// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 6: ETags on every GET, `If-Match` against the durable config generation,
//! `Idempotency-Key` on every mutation, and `GET /operations/{key}`.
//!
//! One router layer, [`preconditions`], does all three so no handler changes: config resources
//! carry `"<deployment_id>.<config_generation>"`; every other GET carries a weak digest ETag and
//! answers `If-None-Match` with 304; a mutation with an `Idempotency-Key` retains its exact intent
//! in the Store before it runs. A complete answer replays afterwards; an unknown effect stays held.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;

use busbar_kernel::admin::gate;
use busbar_kernel::state::{App, AppHandle};

use super::{err_json, err_json_cond};
use crate::idempotency::durable::{self, Claim, Looked, Refused, Settled};
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

/// The deployment segment of a config ETag before boot has published an identity (no Store).
const NO_DEPLOYMENT: &str = "dep_00000000000000000000000000000000";
/// The most body bytes the layer buffers, request or response.
const BODY_CAP: usize = 16 * 1024 * 1024;
const REPLAYED: &str = "idempotent-replayed";
// Both Answer layouts and the intent bind the same versioned, length-framed fingerprint.
const LEGACY_ANSWER_LAYOUT: u8 = 2;
const ANSWER_LAYOUT: u8 = 4;
const INTENT_LAYOUT: u8 = 3;

/// Original wire fields, before the shared generation check translates the value for handlers.
/// Keeping every field prevents a strict consumer from accepting a collapsed duplicate header.
#[derive(Clone)]
pub(crate) struct OriginalConfigPrecondition {
    count: usize,
    first: Option<HeaderValue>,
}

impl OriginalConfigPrecondition {
    fn capture(headers: &axum::http::HeaderMap) -> Self {
        let values = headers.get_all(header::IF_MATCH);
        Self {
            count: values.iter().count(),
            first: values.iter().next().cloned(),
        }
    }

    pub(crate) fn require_strong(&self) -> Result<&HeaderValue, Box<Response>> {
        if self.count == 0 {
            return Err(Box::new(refusal(
                428,
                "invalid_request",
                "if_match_required",
                "this write needs one strong If-Match config ETag",
            )));
        }
        if let Some(value) = self.first.as_ref().filter(|_| self.count == 1) {
            let bytes = value.as_bytes();
            if bytes.len() >= 2
                && bytes[0] == b'"'
                && bytes[bytes.len() - 1] == b'"'
                && bytes[1..bytes.len() - 1]
                    .iter()
                    .all(|b| *b == b'!' || (b'#'..=b'~').contains(b) || *b >= 0x80)
            {
                return Ok(value);
            }
        }
        Err(Box::new(err_json_cond(
            &AdminError::Validation("expected exactly one strong If-Match config ETag".into()),
            Cond::MalformedIfMatch,
        )))
    }
}

/// Frozen under the config transaction's guard, alongside the response readback. A later
/// publication must neither replace this tag nor change the generation retained for replay.
#[derive(Clone)]
pub(crate) struct ConfigResponseEtag {
    generation: u64,
    value: HeaderValue,
}

impl ConfigResponseEtag {
    pub(crate) fn capture(app: &App) -> Self {
        let generation = app
            .config_generation
            .load(std::sync::atomic::Ordering::Acquire);
        Self {
            generation,
            value: HeaderValue::from_str(&etag_at(generation)).expect("config ETag is ASCII"),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn attach(self, mut response: Response) -> Response {
        response
            .headers_mut()
            .insert(header::ETAG, self.value.clone());
        response.extensions_mut().insert(self);
        response
    }
}

/// The strong, shared ETag of every config resource: `"<deployment_id>.<config_generation>"`.
pub(crate) fn config_etag(app: &App) -> String {
    etag_at(
        app.config_generation
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

fn etag_at(generation: u64) -> String {
    let deployment = busbar_kernel::persistence::boot_identity::live().map_or_else(
        || NO_DEPLOYMENT.to_string(),
        |l| l.deployment_id().to_string(),
    );
    format!("\"{deployment}.{generation}\"")
}

fn rel_path(path: &str) -> &str {
    path.strip_prefix(crate::v1::contract::ADMIN_PREFIX)
        .unwrap_or(path)
}

fn under(rel: &str, root: &str) -> bool {
    rel == root
        || rel
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

/// Groups, hooks, named maps, `/admin-auth` and `/config*`: the resources the generation versions.
fn config_resource(rel: &str) -> bool {
    under(rel, "/config")
        || under(rel, crate::v1::contract::PATH_HOOKS)
        || under(rel, crate::v1::contract::PATH_GROUPS)
        || under(rel, gate::PATH_ADMIN_AUTH)
        || busbar_kernel::config::named_map::NamedMapSection::sections()
            .iter()
            .any(|section| under(rel, section.path_root().as_ref()))
}

/// A guarded mutation: the config writes that take `If-Match`.
fn guarded(method: &Method, rel: &str) -> bool {
    config_resource(rel)
        && (matches!(*method, Method::PUT | Method::PATCH | Method::DELETE)
            || (*method == Method::POST && matches!(rel, "/config/apply" | "/config/rollback")))
}

fn refusal(status: u16, code: &str, reason: &str, message: &str) -> Response {
    gate::admin_error_envelope_with(
        status,
        code,
        Some(reason),
        message,
        &serde_json::Value::Object(serde_json::Map::new()),
    )
}

/// Compares `If-Match` to the config generation. A match is rewritten to the process-local
/// `config_version` the handlers still compare, so their own check cannot fail on the same read.
fn check_if_match(req: &mut Request, app: &App, rel: &str) -> Result<(), Box<Response>> {
    let Some(raw) = req.headers().get(header::IF_MATCH) else {
        if app.require_if_match && guarded(req.method(), rel) {
            return Err(Box::new(refusal(
                428,
                "invalid_request",
                "if_match_required",
                "this write needs an `If-Match` header carrying the ETag of the resource it changes",
            )));
        }
        return Ok(());
    };
    let value = raw.to_str().unwrap_or("").trim();
    if value == "*" {
        return Ok(());
    }
    let bare = value.strip_prefix("W/").unwrap_or(value);
    let quoted = bare.len() >= 2 && bare.starts_with('"') && bare.ends_with('"');
    if !quoted {
        return Err(Box::new(err_json_cond(
            &AdminError::Validation(
                "malformed If-Match: expected the quoted config ETag or *".into(),
            ),
            Cond::MalformedIfMatch,
        )));
    }
    let current = config_etag(app);
    if bare != current {
        return Err(Box::new(err_json_cond(
            &AdminError::VersionConflict(format!(
                "If-Match {bare} is stale (current is {current})"
            )),
            Cond::StaleIfMatch,
        )));
    }
    if let Ok(version) = HeaderValue::from_str(&format!("\"{}\"", app.config_version)) {
        req.headers_mut().insert(header::IF_MATCH, version);
    }
    Ok(())
}

fn check_new_dispatch(
    req: &mut Request,
    app: &App,
    rel: &str,
    strong_required: bool,
) -> Result<(), Box<Response>> {
    if strong_required {
        let original = req
            .extensions()
            .get::<OriginalConfigPrecondition>()
            .ok_or_else(|| Box::new(err_json(&AdminError::Internal)))?;
        original.require_strong()?;
    }
    check_if_match(req, app, rel)
}

fn if_none_match(value: Option<&HeaderValue>, etag: &str) -> bool {
    fn weak(value: &str) -> &str {
        let value = value.trim();
        value.strip_prefix("W/").unwrap_or(value)
    }
    value.and_then(|v| v.to_str().ok()).is_some_and(|v| {
        let ours = weak(etag);
        v.trim() == "*" || v.split(',').any(|candidate| weak(candidate) == ours)
    })
}

fn not_modified(etag: &str) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// The router layer: preconditions before the handler, ETags and idempotency around it.
pub(crate) async fn preconditions(mut req: Request, next: Next) -> Response {
    let Some(handle) = req.extensions().get::<Arc<AppHandle>>().cloned() else {
        return next.run(req).await;
    };
    let app = handle.load();
    let rel = rel_path(req.uri().path()).to_string();
    let method = req.method().clone();
    let is_read = matches!(method, Method::GET | Method::HEAD);
    let config = config_resource(&rel);

    if config && !is_read {
        let original = OriginalConfigPrecondition::capture(req.headers());
        req.extensions_mut().insert(original);
    }
    if !is_read {
        use busbar_kernel::audit::auditlog::{note_generation_source, note_idempotency_key};
        if let Some(key) = req
            .headers()
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
        {
            note_idempotency_key(key);
        }
        if config {
            let source = handle.clone();
            note_generation_source(Arc::new(move || source.load().config_version));
        }
    }
    if !is_read {
        let key = req
            .headers()
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap_or("").to_string());
        if let Some(key) = key.filter(|_| !self_idempotent(&req, &rel)) {
            return idempotent(req, next, &app, &handle, key).await;
        }
    }
    if config && !is_read {
        if let Err(response) = check_if_match(&mut req, &app, &rel) {
            return *response;
        }
    }
    if config && is_read {
        let etag = config_etag(&app);
        if if_none_match(req.headers().get(header::IF_NONE_MATCH), &etag) {
            return not_modified(&etag);
        }
    }
    let request_if_none = req.headers().get(header::IF_NONE_MATCH).cloned();
    let mut response = next.run(req).await;
    if method != Method::GET || !response.status().is_success() {
        if config && response.status().is_success() {
            restamp(&mut response, &handle);
        }
        return response;
    }
    if config {
        restamp(&mut response, &handle);
        return response;
    }
    if response.headers().contains_key(header::ETAG)
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, BODY_CAP).await else {
        return gate::admin_error_envelope(500, "internal", "response could not be read");
    };
    let digest = busbar_contract::redacted::sha256_hex(&bytes);
    let etag = format!("W/\"{}\"", &digest[..32]);
    if let Ok(value) = HeaderValue::from_str(&etag) {
        parts.headers.insert(header::ETAG, value);
    }
    if if_none_match(request_if_none.as_ref(), &etag) {
        return not_modified(&etag);
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Preserve a transaction-frozen tag. Legacy handlers still receive the existing live-generation
/// stamp; a producer needing snapshot-bound readback must attach ConfigResponseEtag under its lock.
fn restamp(response: &mut Response, handle: &Arc<AppHandle>) {
    let frozen = response
        .extensions()
        .get::<ConfigResponseEtag>()
        .cloned()
        .unwrap_or_else(|| ConfigResponseEtag::capture(&handle.load()));
    response
        .headers_mut()
        .insert(header::ETAG, frozen.value.clone());
    // Even a legacy live stamp must keep the same generation if collecting its response body
    // yields to a later publication before the idempotency answer is encoded.
    response.extensions_mut().insert(frozen);
}

pub(crate) fn valid_idempotency_key(key: &str) -> bool {
    (1..=128).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn self_idempotent(req: &Request, rel: &str) -> bool {
    let template = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or(rel, |m| rel_path(m.as_str()));
    let full = format!("{}{template}", crate::v1::contract::ADMIN_PREFIX);
    crate::verb::verb_for(req.method().as_str(), &full)
        .and_then(crate::verb::row_of)
        .is_some_and(|row| row.self_idempotent)
}

fn operation_store(app: &App) -> Option<busbar_kernel::persistence::scoped::ScopedStore> {
    let core = app.governance.as_ref()?.core_store_handle().ok()?;
    durable::scoped_store(core).ok()
}

fn principal_of(req: &Request) -> String {
    req.extensions()
        .get::<busbar_kernel::auth::AuthPrincipal>()
        .map_or_else(|| "anonymous".to_string(), |p| p.actor_id().to_string())
}

async fn idempotent(
    req: Request,
    next: Next,
    app: &Arc<App>,
    handle: &Arc<AppHandle>,
    key: String,
) -> Response {
    let rel = rel_path(req.uri().path()).to_string();
    if !valid_idempotency_key(&key) {
        return refusal(
            400,
            "invalid_request",
            "invalid_request",
            "Idempotency-Key must be 1 to 128 characters of A-Z a-z 0-9 . _ : -",
        );
    }
    let Some(store) = operation_store(app) else {
        return refusal(
            503,
            "unavailable",
            "service_unavailable",
            "an Idempotency-Key needs the Store, which is unavailable; nothing was done",
        );
    };
    let principal = principal_of(&req);
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, BODY_CAP).await else {
        return gate::admin_error_envelope(
            413,
            busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE,
            "admin request body exceeds the configured limit",
        );
    };
    let mut framed = Vec::with_capacity(bytes.len() + 96);
    framed.extend_from_slice(b"busbar.admin.request.v2\0");
    // Bind component boundaries as well as their bytes: moving a byte between the query and
    // body must never turn a different request into a replay of the original operation.
    for component in [
        parts.method.as_str().as_bytes(),
        parts.uri.path().as_bytes(),
        parts.uri.query().unwrap_or("").as_bytes(),
        bytes.as_ref(),
    ] {
        framed.extend_from_slice(
            &u64::try_from(component.len())
                .expect("request component length fits u64")
                .to_be_bytes(),
        );
        framed.extend_from_slice(component);
    }
    let fingerprint = busbar_contract::abi::sdk::digest::sha256(&framed);
    let now = busbar_kernel::store::now();
    let claim_key = (principal, format!("op:{key}"));
    // Replay is not a new mutation: its original precondition can be stale precisely because
    // the retained mutation succeeded. Keep replay and exclusion in the one held-claim engine.
    let claim = match durable::claim_held(&store, &claim_key, now).await {
        Err(Refused::Answer(answer)) => return replay(&answer, &fingerprint),
        Err(Refused::Retained(receipt)) => return retained(&receipt, &fingerprint),
        Err(Refused::InFlight | Refused::Applied(_)) => return in_flight(),
        Err(Refused::Unavailable(why)) => {
            tracing::warn!(error = %why, "idempotency claim failed; nothing was done");
            return refusal(
                503,
                "unavailable",
                "service_unavailable",
                "the Store could not record this Idempotency-Key; nothing was done",
            );
        }
        Ok(claim) => claim,
    };
    // The typed settings mode strengthens only NEW dispatch. An identical retained reply
    // above uses the original request fingerprint and performs no new mutation.
    let strong_required = parts.method == Method::PUT
        && rel == "/config/settings"
        && super::instance_settings::is_request(&bytes);
    let mut req = Request::from_parts(parts, Body::from(bytes));
    if config_resource(&rel) {
        if let Err(response) = check_new_dispatch(&mut req, app, &rel, strong_required) {
            // This is the only release here: no handler or intent has been dispatched.
            // A failed acknowledgement cannot turn this refusal into an execution.
            settle(&store, &claim, &Settled::Released).await;
            return *response;
        }
    }
    let generation = app
        .config_generation
        .load(std::sync::atomic::Ordering::Acquire);
    let intent = Settled::Retained(encode_intent(now, generation, &fingerprint));
    if let Err(why) = durable::settle(&store, &claim, now, &intent).await {
        tracing::warn!(error = %why, "admin intent was not confirmed; nothing was dispatched");
        return refusal(
            503,
            "unavailable",
            "service_unavailable",
            "the Store could not retain this operation's intent; nothing was dispatched",
        );
    }
    let mut response = next.run(req).await;
    if config_resource(&rel) && response.status().is_success() {
        restamp(&mut response, handle);
    }
    let (rparts, rbody) = response.into_parts();
    let Ok(rbytes) = axum::body::to_bytes(rbody, BODY_CAP).await else {
        // The handler may have committed. Keep its acknowledged intent and permanent
        // exclusion; failure to collect a reply cannot authorize another execution.
        return gate::admin_error_envelope(500, "internal", "response could not be read");
    };
    let status = rparts.status;
    // Dispatch may have committed an effect even when its public reply is 5xx or 429.
    // A response status cannot authorize another execution of the same action.
    let generation = rparts.extensions.get::<ConfigResponseEtag>().map_or_else(
        || {
            app.config_generation
                .load(std::sync::atomic::Ordering::Acquire)
        },
        ConfigResponseEtag::generation,
    );
    let answer = encode_answer(
        status.as_u16(),
        now,
        generation,
        &fingerprint,
        &rparts.headers,
        &rbytes,
    );
    if let Some(answer) = answer {
        settle(&store, &claim, &Settled::Answer(answer)).await;
    } else {
        // Never truncate a reply header or release a possibly committed operation.
        tracing::warn!("admin reply headers exceeded the retained layout; intent remains held");
    }
    Response::from_parts(rparts, Body::from(rbytes))
}

async fn settle(
    store: &busbar_kernel::persistence::scoped::ScopedStore,
    claim: &Claim,
    settled: &Settled,
) {
    if let Err(why) = durable::settle(store, claim, busbar_kernel::store::now(), settled).await {
        tracing::warn!(error = %why, "the Store did not confirm an Idempotency-Key's outcome; its held exclusion continues to prevent retries");
    }
}

fn mismatch() -> Response {
    refusal(
        409,
        "conflict",
        "idempotency_mismatch",
        "Idempotency-Key is bound to different request bytes",
    )
}

fn retained(receipt: &[u8], fingerprint: &[u8; 32]) -> Response {
    let Some(intent) = decode_intent(receipt) else {
        return unreadable_replay();
    };
    if intent.fingerprint == fingerprint.as_slice() {
        in_flight()
    } else {
        mismatch()
    }
}

fn in_flight() -> Response {
    let mut response = refusal(
        409,
        "conflict",
        "idempotency_in_flight",
        "a request with this Idempotency-Key is already in flight",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn unreadable_replay() -> Response {
    refusal(
        503,
        "unavailable",
        "service_unavailable",
        "the retained operation has an unsupported or unreadable binding; nothing was dispatched",
    )
}

struct Intent<'a> {
    received_at: u64,
    generation: u64,
    fingerprint: &'a [u8],
}

fn encode_intent(received_at: u64, generation: u64, fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![INTENT_LAYOUT];
    bytes.extend_from_slice(&received_at.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(fingerprint);
    bytes
}

fn decode_intent(bytes: &[u8]) -> Option<Intent<'_>> {
    if bytes.len() != 49 || bytes[0] != INTENT_LAYOUT {
        return None;
    }
    Some(Intent {
        received_at: u64::from_be_bytes(bytes[1..9].try_into().ok()?),
        generation: u64::from_be_bytes(bytes[9..17].try_into().ok()?),
        fingerprint: &bytes[17..],
    })
}

/// A settled answer: layout, status, received_at, generation, request digest, exact optional
/// Content-Type and ETag fields, body. Layout 2 remains readable without inventing its lost ETag.
fn encode_answer(
    status: u16,
    received_at: u64,
    generation: u64,
    fingerprint: &[u8; 32],
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Option<Vec<u8>> {
    let mut out = vec![ANSWER_LAYOUT];
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&received_at.to_be_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(fingerprint);
    for name in [header::CONTENT_TYPE, header::ETAG] {
        match headers.get(name) {
            None => out.push(0),
            Some(value) => {
                let bytes = value.as_bytes();
                let len = u32::try_from(bytes.len()).ok()?;
                out.push(1);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }
    out.extend_from_slice(body);
    Some(out)
}

struct Answer<'a> {
    status: u16,
    received_at: u64,
    generation: u64,
    fingerprint: &'a [u8],
    content_type: Option<&'a [u8]>,
    etag: Option<&'a [u8]>,
    body: &'a [u8],
}

fn decode_answer(bytes: &[u8]) -> Option<Answer<'_>> {
    let (&layout, rest) = bytes.split_first()?;
    if !matches!(layout, ANSWER_LAYOUT | LEGACY_ANSWER_LAYOUT) || rest.len() < 2 + 8 + 8 + 32 {
        return None;
    }
    let status = u16::from_be_bytes(rest[..2].try_into().ok()?);
    StatusCode::from_u16(status).ok()?;
    let received_at = u64::from_be_bytes(rest[2..10].try_into().ok()?);
    let generation = u64::from_be_bytes(rest[10..18].try_into().ok()?);
    let fingerprint = &rest[18..50];
    let mut tail = &rest[50..];
    let (content_type, etag) = if layout == LEGACY_ANSWER_LAYOUT {
        let (&len, rest) = tail.split_first()?;
        let value = rest.get(..usize::from(len))?;
        tail = &rest[usize::from(len)..];
        let content_type = if value.is_empty() {
            None
        } else {
            HeaderValue::from_bytes(value).ok()?;
            Some(value)
        };
        (content_type, None)
    } else {
        (decode_header(&mut tail)?, decode_header(&mut tail)?)
    };
    Some(Answer {
        status,
        received_at,
        generation,
        fingerprint,
        content_type,
        etag,
        body: tail,
    })
}

fn decode_header<'a>(tail: &mut &'a [u8]) -> Option<Option<&'a [u8]>> {
    let (&present, rest) = tail.split_first()?;
    *tail = rest;
    match present {
        0 => Some(None),
        1 => {
            let len = usize::try_from(u32::from_be_bytes(tail.get(..4)?.try_into().ok()?)).ok()?;
            let end = 4usize.checked_add(len)?;
            let value = tail.get(4..end)?;
            HeaderValue::from_bytes(value).ok()?;
            *tail = &tail[end..];
            Some(Some(value))
        }
        _ => None,
    }
}

fn replay(answer: &[u8], fingerprint: &[u8; 32]) -> Response {
    let Some(answer) = decode_answer(answer) else {
        return unreadable_replay();
    };
    if answer.fingerprint != fingerprint.as_slice() {
        return mismatch();
    }
    let mut response = Response::new(Body::from(answer.body.to_vec()));
    *response.status_mut() = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::OK);
    for (name, bytes) in [
        (header::CONTENT_TYPE, answer.content_type),
        (header::ETAG, answer.etag),
    ] {
        if let Some(bytes) = bytes {
            // decode_answer validated every stored field before any reply is emitted.
            if let Ok(value) = HeaderValue::from_bytes(bytes) {
                response.headers_mut().insert(name, value);
            }
        }
    }
    response
        .headers_mut()
        .insert(REPLAYED, HeaderValue::from_static("true"));
    response
}

/// `GET /operations/{key}`: one idempotent operation of the caller's own, by its key.
pub(crate) async fn get_operation(
    State(handle): State<Arc<AppHandle>>,
    principal: Option<Extension<busbar_kernel::auth::AuthPrincipal>>,
    Path(key): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let app = handle.load();
    let actor = principal.map_or_else(
        || "anonymous".to_string(),
        |Extension(p)| p.actor_id().to_string(),
    );
    if query.get("principal").is_some_and(|other| *other != actor) {
        return refusal(
            403,
            "forbidden",
            "scope_insufficient",
            "reading another principal's operation needs the full admin scope",
        );
    }
    let missing = || err_json(&AdminError::not_found("operation"));
    if !valid_idempotency_key(&key) {
        return missing();
    }
    let Some(store) = operation_store(&app) else {
        return refusal(
            503,
            "unavailable",
            "service_unavailable",
            "operations are kept in the Store, which is unavailable",
        );
    };
    let now = busbar_kernel::store::now();
    let looked = match durable::lookup(&store, &(actor.clone(), format!("op:{key}")), now).await {
        Ok(Some(looked)) => looked,
        Ok(None) => return missing(),
        Err(why) => {
            tracing::warn!(error = %why, "operation lookup failed");
            return refusal(
                503,
                "unavailable",
                "service_unavailable",
                "the Store could not read this operation",
            );
        }
    };
    let operation_id = format!(
        "op_{}",
        &busbar_contract::redacted::sha256_hex(format!("{actor}\0{key}").as_bytes())[..32]
    );
    let body = match looked {
        Looked::Retained { receipt } => {
            let Some(intent) = decode_intent(&receipt) else {
                return unreadable_replay();
            };
            serde_json::json!({
                "idempotency_key": key, "principal": actor, "operation_id": operation_id,
                "state": "in_flight", "status": null,
                "request_sha256": hex::encode(intent.fingerprint), "received_at": intent.received_at,
                "completed_at": null, "config_generation": intent.generation, "audit_seq": null,
                "response": null,
            })
        }
        Looked::InFlight {
            request_sha256,
            received_at,
        } => busbar_contract::json::json!({
            "idempotency_key": key, "principal": actor, "operation_id": operation_id,
            "state": "in_flight", "status": null,
            "request_sha256": hex::encode(request_sha256), "received_at": received_at,
            "completed_at": null, "config_generation": null, "audit_seq": null,
            "response": null,
        }),
        Looked::Done {
            answer,
            completed_at,
        } => {
            let Some(done) = decode_answer(&answer) else {
                return gate::admin_error_envelope(
                    500,
                    "internal",
                    "the stored answer is unreadable",
                );
            };
            busbar_contract::json::json!({
                "idempotency_key": key, "principal": actor, "operation_id": operation_id,
                "state": if done.status >= 400 { "rejected" } else { "applied" },
                "status": done.status,
                "request_sha256": hex::encode(done.fingerprint),
                "received_at": done.received_at, "completed_at": completed_at,
                "config_generation": done.generation, "audit_seq": null,
                "response": busbar_contract::json::parse_value(done.body)
                    .unwrap_or_default(),
            })
        }
    };
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            busbar_contract::protocol::APPLICATION_JSON,
        )],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
#[path = "generation_tests.rs"]
mod tests;
