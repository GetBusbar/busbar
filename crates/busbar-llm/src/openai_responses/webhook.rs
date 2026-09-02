// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INBOUND WEBHOOK RECEIVER for the OpenAI Responses async / background surface (T3).
//!
//! When a client creates a Responses turn in `background: true` mode, the upstream does NOT answer
//! synchronously: it accepts the request, returns a `resp_…` id, and — once the turn finishes —
//! delivers a signed WEBHOOK to a URL the operator registered with OpenAI. This module is the plane's
//! inbound leg for that webhook: it VERIFIES the provider signature, PARSES the event body, and
//! SURFACES the parsed event (with the `resp_…` correlation id) into the plane's IR/handler path.
//!
//! WHAT THIS IS AND IS NOT. Busbar is a TRANSLATOR, not a conversation-state store (the same stance
//! the stateful `previous_response_id`/`store` codec work takes): this receiver AUTHENTICATES and
//! NORMALIZES the event, it does not itself persist or resume a background response. The correlation
//! id it extracts (`data.id`, a `resp_…`) is the SAME key the stateful leg threads — a client that
//! stored a response and later receives its completion webhook can line the two up.
//!
//! SIGNATURE SCHEME — Standard Webhooks (the spec OpenAI's webhooks follow). Three request headers
//! carry the proof: `webhook-id` (the unique message id), `webhook-timestamp` (unix seconds the
//! message was signed), and `webhook-signature` (one or more space-separated `v<n>,<base64>` tokens).
//! The signed content is the exact byte string `{webhook-id}.{webhook-timestamp}.{body}`. The signer
//! key is the operator's secret with its `whsec_` prefix stripped and the remainder base64-decoded.
//! Verification recomputes `base64(HMAC-SHA256(key, signed_content))` and accepts the request iff it
//! CONSTANT-TIME-equals one of the presented `v1` signatures. NO secret, key, or signature byte is
//! ever logged.
//!
//! DEFERRED (reported, gated OFF behind `webhook-receiver`). The LIVE HTTP-route mount lives at the
//! bottom of this file behind `#[cfg(feature = "webhook-receiver")]`. It is off by default because
//! the operator-facing SECRET CONFIGURATION seam is not yet available to a plane: the LLM plane is
//! the fallback catch-all (`PLANE_DECL.build` yields no dispatch slot, and there is no `webhooks:`
//! config section to carry a per-deployment signing secret). Until that seam exists the gated route
//! reads the secret from `BUSBAR_LLM_WEBHOOK_SECRET` and, with it unset, mounts NOTHING — so no
//! unauthenticated endpoint is ever exposed. The parse+verify+surface logic below is complete and
//! tested regardless of the mount.

use axum::http::HeaderMap;
use base64::Engine as _;

/// Standard-Webhooks request header: the unique message id (also part of the signed content).
const HDR_WEBHOOK_ID: &str = "webhook-id";
/// Standard-Webhooks request header: unix seconds the message was signed (part of the signed content).
const HDR_WEBHOOK_TIMESTAMP: &str = "webhook-timestamp";
/// Standard-Webhooks request header: the space-separated `v<n>,<base64>` signature list.
const HDR_WEBHOOK_SIGNATURE: &str = "webhook-signature";

/// The signing-secret prefix OpenAI/Standard-Webhooks put in front of the base64 key material.
const SECRET_PREFIX: &str = "whsec_";

/// The only signature-scheme version this receiver accepts. A token prefixed with any other version
/// (a future `v2,…`) is ignored, not matched — an unknown scheme must never silently pass.
const SIG_VERSION: &str = "v1";

/// Top-level webhook body key: the event kind (`response.completed`, `response.failed`, …).
const KEY_TYPE: &str = "type";
/// Top-level webhook body key: the unique EVENT id (`evt_…`), distinct from the response id.
const KEY_ID: &str = "id";
/// Top-level webhook body key: unix seconds the event was created.
const KEY_CREATED_AT: &str = "created_at";
/// Top-level webhook body key: the event payload; carries the `resp_…` correlation id at `data.id`.
const KEY_DATA: &str = "data";

/// Why an inbound webhook was refused. Each arm maps to the HTTP status the live route returns; NONE
/// carries secret, key, or signature material (so a rejection can be logged safely).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookReject {
    /// A required Standard-Webhooks header (`webhook-id`/`webhook-timestamp`/`webhook-signature`) was
    /// absent, empty, or not valid UTF-8. A genuinely unsigned request lands here → HTTP 400.
    MissingSignatureHeaders,
    /// The configured signing secret was malformed (missing the `whsec_` prefix, or its remainder was
    /// not valid base64). This is an OPERATOR misconfiguration, not a caller fault → HTTP 500.
    MalformedSecret,
    /// The recomputed HMAC matched NONE of the presented `v1` signatures — a forged, tampered, or
    /// wrong-secret request. Also covers a signature header carrying no `v1` token at all → HTTP 401.
    SignatureMismatch,
    /// The verified body was not a JSON object, or a MODELED field was present-but-wrong-typed
    /// (`type` not a non-empty string, `data`/`data.id` malformed, `created_at` not an integer). The
    /// leniency contract still tolerates absent/unknown fields → HTTP 400.
    MalformedBody,
}

impl WebhookReject {
    /// The HTTP status the live route returns for this rejection. `MalformedSecret` is the only 5xx
    /// (an operator config fault); every caller-attributable refusal is a 4xx.
    pub fn http_status(self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            WebhookReject::MissingSignatureHeaders | WebhookReject::MalformedBody => {
                StatusCode::BAD_REQUEST
            }
            WebhookReject::SignatureMismatch => StatusCode::UNAUTHORIZED,
            WebhookReject::MalformedSecret => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A verified, parsed inbound Responses webhook event, surfaced into the plane's IR/handler path.
///
/// The load-bearing field is [`Self::response_id`] — the `resp_…` id at `data.id`, the correlation
/// key back to the response the client created (and, in stateful mode, stored). `raw` keeps the full
/// verified body verbatim so a downstream sink/handler forwards it losslessly rather than re-encoding
/// a lossy projection.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponsesWebhookEvent {
    /// The unique EVENT id (`evt_…`) from the body's top-level `id`, if present.
    pub event_id: Option<String>,
    /// The event kind verbatim (`response.completed`, `response.failed`, `response.incomplete`,
    /// `response.cancelled`, …). Always present (a body without it is rejected).
    pub event_type: String,
    /// Unix seconds the event was created, if the body carried a well-typed `created_at`.
    pub created_at: Option<u64>,
    /// The `resp_…` correlation id (`data.id`) — the key that lines this webhook up with the response
    /// the client created/stored. Always non-empty (a body without it is rejected).
    pub response_id: String,
    /// The full verified body, verbatim, for lossless downstream surfacing.
    pub raw: serde_json::Value,
}

impl ResponsesWebhookEvent {
    /// True when this event reports the background turn has reached a TERMINAL state (the turn is
    /// finished — completed, failed, incomplete, or cancelled). Recognizing the same terminal
    /// vocabulary the streaming reader uses keeps the webhook leg consistent with the plane's IR
    /// stop-reason semantics rather than re-inventing a second notion of "done".
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "response.completed" | "response.failed" | "response.incomplete" | "response.cancelled"
        )
    }
}

/// HMAC-SHA256 of `data` under `key`. Mirrors `busbar_substrate::sigv4::hmac` (which is private, so it
/// cannot be reused): `Hmac::new_from_slice` is infallible for HMAC (any key length is legal), but we
/// avoid `expect()`/panic on the request path — an unreachable init error yields an empty digest,
/// which simply fails the signature comparison (a safe refusal) rather than aborting the task.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    match <Hmac<Sha256>>::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        // Unreachable (HMAC accepts any key length); return an empty digest so verification FAILS
        // (SignatureMismatch) rather than panicking on the request path.
        Err(_) => Vec::new(),
    }
}

/// Decode a `whsec_<base64>` signing secret into its raw key bytes. Returns
/// [`WebhookReject::MalformedSecret`] when the prefix is missing or the remainder is not valid
/// base64 — an operator-config fault the caller cannot cause.
fn decode_secret(secret: &str) -> Result<Vec<u8>, WebhookReject> {
    let b64 = secret
        .strip_prefix(SECRET_PREFIX)
        .ok_or(WebhookReject::MalformedSecret)?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| WebhookReject::MalformedSecret)
}

/// VERIFY a Standard-Webhooks signature over `(webhook_id, webhook_timestamp, body)`.
///
/// Recomputes `base64(HMAC-SHA256(key, "{id}.{timestamp}.{body}"))` and accepts iff it constant-time
/// equals one of the `v1` tokens in `signature_header` (a space-separated `v<n>,<base64>` list). The
/// key is `secret` with its `whsec_` prefix stripped and the remainder base64-decoded. Returns
/// [`WebhookReject::SignatureMismatch`] when no `v1` token matches (forged/tampered/wrong-secret, or
/// a header with no `v1` token), and [`WebhookReject::MalformedSecret`] on a bad secret. The
/// constant-time compare of the two base64 strings uses the neutral `busbar_api::constant_time_eq`.
pub fn verify_signature(
    secret: &str,
    webhook_id: &str,
    webhook_timestamp: &str,
    signature_header: &str,
    body: &[u8],
) -> Result<(), WebhookReject> {
    let key = decode_secret(secret)?;

    // Signed content is the exact byte string `{id}.{timestamp}.{body}`. Build it as bytes (the body
    // may not be UTF-8-clean in pathological cases, so it is appended raw rather than via a `format!`).
    let mut signed =
        Vec::with_capacity(webhook_id.len() + webhook_timestamp.len() + body.len() + 2);
    signed.extend_from_slice(webhook_id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(webhook_timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(hmac_sha256(&key, &signed));

    // The header may carry MULTIPLE space-separated signatures (key rotation / overlap window); accept
    // if ANY `v1` token matches. Compare with the neutral constant-time primitive so a timing side
    // channel cannot leak how many leading bytes of a forged signature were correct.
    for token in signature_header.split(' ').filter(|t| !t.is_empty()) {
        let Some((version, sig)) = token.split_once(',') else {
            continue;
        };
        if version == SIG_VERSION && busbar_api::constant_time_eq(sig, &expected_b64) {
            return Ok(());
        }
    }
    Err(WebhookReject::SignatureMismatch)
}

/// PARSE a verified webhook body into a [`ResponsesWebhookEvent`], enforcing the plane's leniency
/// contract: tolerate absent/unknown fields, but REJECT a present-but-wrong-typed MODELED field
/// ([`WebhookReject::MalformedBody`]). The load-bearing fields — `type` (the event kind) and
/// `data.id` (the `resp_…` correlation key) — are REQUIRED and must be non-empty strings; a body
/// missing either cannot be surfaced usefully, so it is refused rather than surfaced blank.
pub fn parse_event(body: &[u8]) -> Result<ResponsesWebhookEvent, WebhookReject> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| WebhookReject::MalformedBody)?;
    let obj = value.as_object().ok_or(WebhookReject::MalformedBody)?;

    // `type` — REQUIRED non-empty string (a present non-string is a wrong-typed rejection).
    let event_type = match obj.get(KEY_TYPE) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(WebhookReject::MalformedBody),
    };

    // `data.id` — REQUIRED non-empty string. `data` must be an object if present; a missing `data`,
    // a non-object `data`, or a missing/blank/wrong-typed `data.id` is a malformed event (there is no
    // correlation key to surface).
    let data = obj.get(KEY_DATA).ok_or(WebhookReject::MalformedBody)?;
    let data_obj = data.as_object().ok_or(WebhookReject::MalformedBody)?;
    let response_id = match data_obj.get(KEY_ID) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(WebhookReject::MalformedBody),
    };

    // `id` (event id) — OPTIONAL; tolerated absent. Present-but-wrong-typed (non-string) is a
    // wrong-typed rejection per the house policy; a present non-empty string is carried.
    let event_id = match obj.get(KEY_ID) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()).filter(|s| !s.is_empty()),
        Some(_) => return Err(WebhookReject::MalformedBody),
    };

    // `created_at` — OPTIONAL unix seconds; tolerated absent. Present-but-wrong-typed (non-integer)
    // is a wrong-typed rejection.
    let created_at = match obj.get(KEY_CREATED_AT) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or(WebhookReject::MalformedBody)?),
    };

    Ok(ResponsesWebhookEvent {
        event_id,
        event_type,
        created_at,
        response_id,
        raw: value,
    })
}

/// THE INBOUND WEBHOOK INGRESS HANDLER: verify the provider signature over the request, THEN parse
/// the body into a [`ResponsesWebhookEvent`] surfaced into the plane's IR/handler path. Signature
/// verification runs FIRST (an unsigned/forged request is refused before its body is trusted or
/// parsed). The three Standard-Webhooks headers are extracted from `headers`; any missing/blank/
/// non-UTF-8 one yields [`WebhookReject::MissingSignatureHeaders`].
pub fn receive(
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ResponsesWebhookEvent, WebhookReject> {
    let header = |name: &str| -> Result<&str, WebhookReject> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or(WebhookReject::MissingSignatureHeaders)
    };
    let webhook_id = header(HDR_WEBHOOK_ID)?;
    let webhook_timestamp = header(HDR_WEBHOOK_TIMESTAMP)?;
    let signature_header = header(HDR_WEBHOOK_SIGNATURE)?;

    verify_signature(
        secret,
        webhook_id,
        webhook_timestamp,
        signature_header,
        body,
    )?;
    parse_event(body)
}

// ─────────────────────────── LIVE HTTP-ROUTE MOUNT (DEFAULT OFF) ───────────────────────────
// Gated behind `webhook-receiver`. See the module header for why the mount is off by default (the
// operator-facing secret-config seam on the fallback plane is the reported deferred remainder).

/// Environment variable the gated route reads the `whsec_…` signing secret from. When unset the route
/// mounts NOTHING — no unauthenticated webhook endpoint is ever exposed.
#[cfg(feature = "webhook-receiver")]
const SECRET_ENV: &str = "BUSBAR_LLM_WEBHOOK_SECRET";

/// The path the OpenAI Responses webhook receiver is mounted at (concrete, no prefix match — the auth
/// middleware's exact-match discipline is preserved).
#[cfg(feature = "webhook-receiver")]
const WEBHOOK_PATH: &str = "/v1/llm/webhooks/openai";

/// BUILD THE WEBHOOK PLANE ROUTE(S) — the `PLANE_DECL.routes` contribution when `webhook-receiver` is
/// enabled. The fallback plane has no dispatch slot, so `_slot` is ignored. The signing secret is
/// read from [`SECRET_ENV`]; with it unset an EMPTY vec is returned (mount nothing), so an operator
/// who has not configured a secret never gets an unauthenticated endpoint. `RouteAuth::None` bypasses
/// the key chain (the webhook is authenticated by its OWN signature, verified in-handler), matching
/// how MCP mounts its open RFC 9728 metadata route.
#[cfg(feature = "webhook-receiver")]
pub fn webhook_routes(
    _slot: &dyn std::any::Any,
) -> Vec<busbar_substrate::plane_routes::PlaneRouteSpec> {
    use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};
    use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};

    // Read once at mount time; a route is contributed only when a secret is configured.
    let Ok(secret) = std::env::var(SECRET_ENV) else {
        return Vec::new();
    };
    if secret.is_empty() {
        return Vec::new();
    }
    let secret = std::sync::Arc::new(secret);

    vec![PlaneRouteSpec {
        path: WEBHOOK_PATH.to_string(),
        method: RouteMethod::Post,
        auth: RouteAuth::None,
        handler: std::sync::Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
            let secret = secret.clone();
            Box::pin(async move { webhook_route_handler(&secret, ctx) })
        }),
    }]
}

/// The gated route body: verify + parse via [`receive`], then ACK. A verified event returns 200 with
/// a small JSON ack (busbar is a translator — it acknowledges receipt and surfaces the event; it does
/// not resume the background turn). A rejection returns the mapped status with NO secret material.
#[cfg(feature = "webhook-receiver")]
fn webhook_route_handler(
    secret: &str,
    ctx: busbar_substrate::plane_routes::PlaneReqCtx,
) -> busbar_substrate::plane_routes::PlaneResponse {
    use axum::response::IntoResponse as _;
    match receive(secret, &ctx.headers, &ctx.body) {
        Ok(event) => {
            // SURFACE into the plane's handler path. Busbar holds no background-turn state, so the
            // honest action is to acknowledge receipt with the correlation id echoed back; a later
            // config seam can route `event` to an operator sink. Never log the secret/signature.
            tracing::info!(
                response_id = %event.response_id,
                event_type = %event.event_type,
                terminal = event.is_terminal(),
                "received a verified OpenAI Responses webhook"
            );
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "received": true,
                    "response_id": event.response_id,
                    "type": event.event_type,
                })),
            )
                .into_response()
        }
        Err(reject) => reject.http_status().into_response(),
    }
}

#[cfg(test)]
#[path = "tests/webhook_tests.rs"]
mod tests;
