// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE-PLANE UNIVERSAL INGRESS, relocated from busbar-core (1.6.0 money-path Phase 3-4 C).
//!
//! Pool/model resolution + governance admission + the-one-engine forward every LLM arrival runs once
//! its model is known. It reads the LLM routing tables (now in `crate::engine`) so it lives in the
//! plane; it calls DOWN into core for the neutral accounting -- the allowed plane->core edge. The two
//! entry points downcast the opaque `ArrivalCtx` to core's `ArrivalPayload`.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use busbar_substrate::ingress::arrival::ArrivalCtx;
// The neutral host seam — the plane holds an `Arc<dyn EngineHost>` (carried on the arrival) and reaches
// the engine's finish/label/guard/admission capabilities through its typed methods (App-retype WEDGE 3).
use busbar_substrate::plane_host::EngineHost;

use crate::engine::{native_runtime_arc, EngineTables, NativeRuntime, WeightedLane};

/// The first occurrence of `needle` in `hay`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// THE BOUNDARY, off the `Content-Type` — the one thing that says where a part begins.
///
/// A multipart body has no structure without it: every delimiter in the document is spelled from
/// this value, so a reader that does not have it is not reading parts, it is reading bytes that
/// resemble them. `None` where the header carries no `boundary` parameter, which is a body no
/// conforming parser can read either — including the provider's.
///
/// The parameter is matched as a WHOLE key rather than by substring, so a `boundary` that appears
/// inside some other parameter's quoted value is not mistaken for the real one; the value may be
/// quoted and is unquoted here, per RFC 2045.
fn multipart_boundary(content_type: &str) -> Option<String> {
    for param in split_params(content_type).skip(1) {
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            let v = value.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(v);
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

/// Split a header value on `;`, IGNORING separators inside a quoted string.
///
/// A naive `split(';')` cuts a quoted `filename="a;b"` in half and turns the tail into a parameter
/// that was never written. The first item is the value's own token (`multipart/form-data`), which is
/// why the boundary search above skips it.
fn split_params(value: &str) -> impl Iterator<Item = &str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0usize, false);
    for (i, c) in value.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out.into_iter()
}

/// Whether a part's header block declares the form field `model`.
///
/// The `name` parameter of `Content-Disposition`, matched as a whole key against a whole value —
/// never as a substring of the header block. `filename="model"` is a different parameter and does not
/// answer this; a `name` written inside some other part's body is not a header at all and never
/// reaches here, because the caller only hands over bytes the boundary said were headers.
fn part_is_model(headers: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(headers) else {
        // A header block is ASCII by construction. One that is not is not a header block this
        // reader will guess at.
        return false;
    };
    // Header field lines are unfolded here only as far as the split: a folded `Content-Disposition`
    // is not something any HTTP client emits for a form part, and a continuation line that failed to
    // match simply makes this part not-the-model, which is the safe direction.
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        for param in split_params(value).skip(1) {
            let Some((key, v)) = param.split_once('=') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("name") {
                continue;
            }
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|r| r.strip_suffix('"'))
                .unwrap_or(v);
            return v == "model";
        }
    }
    false
}

/// RUNG 2 OF THE MODEL LADDER — the `model` form field of a multipart arrival, read as a DOCUMENT.
///
/// The model this returns decides the lane the unit is verified against, the pool it is admitted to
/// and the card that prices it. The provider decides which model actually answers, by parsing the
/// same bytes with a conforming multipart parser. Those two readings have to agree, or the caller
/// picks what busbar charges for independently of what it receives — so this walks the parts the
/// boundary delimits and reads the `model` part's headers, rather than scanning for a string that
/// occurs just as readily inside somebody's prompt.
///
/// TWO `model` PARTS RESOLVE TO NOTHING. Repetition is legal and no rule says which one a provider
/// takes, so a body carrying two is a body whose model busbar cannot know. It falls to the ladder's
/// floor and gets the same missing-model refusal an absent field gets — before the door, so it costs
/// the caller nothing and cannot be made to charge for the wrong lane.
///
/// The 64 KiB bound is kept: it is far larger than any plausible run of text form fields preceding
/// the audio blob, and it is what stops this from walking a megabyte of binary looking for a
/// delimiter. A `model` part beyond it is not found, which is the same answer the scan gave and the
/// same safe direction — a refusal, never a different model.
///
/// `pub(crate)` rather than private so the Decode step can CALL this rung of the model ladder instead
/// of carrying a second copy of it. A copy would be a second reading of the same wire, and two
/// readings of one wire are two answers waiting to disagree.
pub(crate) fn multipart_model(content_type: &str, body: &[u8]) -> Option<String> {
    const HEAD: usize = 64 * 1024;
    let boundary = multipart_boundary(content_type)?;
    let head = &body[..body.len().min(HEAD)];

    // Every part after the first is opened by CRLF + `--boundary`; the first is opened by
    // `--boundary` at the very start of the body (an optional preamble may precede it, and then it
    // too is CRLF-prefixed). Both forms are the same delimiter with one optional CRLF in front, so
    // the walk searches for the dashed form and accepts it only where the document says a delimiter
    // may be: at offset zero, or immediately after a CRLF.
    let dashed = format!("--{boundary}");
    let closing = format!("\r\n--{boundary}");
    let mut found: Option<String> = None;
    let mut at = 0usize;

    while at < head.len() {
        let Some(rel) = find_sub(&head[at..], dashed.as_bytes()) else {
            break;
        };
        let abs = at + rel;
        // A `--boundary` that is not at a line start is text that happens to look like a delimiter.
        if abs != 0 && !head[..abs].ends_with(b"\r\n") {
            at = abs + dashed.len();
            continue;
        }
        let after = abs + dashed.len();
        let rest = &head[after..];
        if rest.starts_with(b"--") {
            // The closing delimiter. Everything past it is the epilogue.
            break;
        }
        // A delimiter line may carry linear whitespace before its CRLF; anything else is not a
        // delimiter line, and a document this reader cannot follow is a document it does not guess
        // at.
        let Some(line_end) = find_sub(rest, b"\r\n") else {
            break;
        };
        if rest[..line_end].iter().any(|b| !matches!(b, b' ' | b'\t')) {
            at = after;
            continue;
        }
        let hdr_at = after + line_end + 2;
        // The part's header block ends at the blank line. A part whose block does not close inside
        // the head is a part this read does not reach.
        let Some(hdr_len) = find_sub(&head[hdr_at..], b"\r\n\r\n") else {
            break;
        };
        let body_at = hdr_at + hdr_len + 4;
        let Some(body_len) = find_sub(&head[body_at..], closing.as_bytes()) else {
            break;
        };
        if part_is_model(&head[hdr_at..hdr_at + hdr_len]) {
            if found.is_some() {
                // Two `model` parts: no model, rather than a guess at which one is billed.
                return None;
            }
            found = Some(
                String::from_utf8_lossy(&head[body_at..body_at + body_len])
                    .trim()
                    .to_string(),
            );
        }
        at = body_at + body_len + 2;
    }
    found.filter(|m| !m.is_empty())
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn operation_ingress_inner(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let started = Instant::now();
    // C10 (state/store port): the header-arrival epoch is read off the HOST's clock port
    // (`ClockHost::clock_now_secs`, inherited through `EngineHost`) rather than the ambient free
    // function. Value-identical — the wired `clock_now` slot is `store::now_ms()` scaled to nanos and
    // divided back down, i.e. the same `SystemTime` epoch seconds `store::now()` returns — so the
    // money path (`charged_at`) is byte-identical; the plane now takes its clock from the port.
    let charged_at = host.clock_now_secs();
    // App-retype WEDGE 3: the pre-routing finish/label/guard capabilities route through the `host`
    // threaded in (the arrival's `Arc<dyn EngineHost>`), so this plane names no core ingress module.

    let Some(rh) = busbar_substrate::handlers::request_handler(proto) else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            ),
        );
    };
    let Some(op_handler) = rh.operation_handler(operation) else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            ),
        );
    };

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // VALIDATE ONCE, before model extraction, so a malformed JSON body gets the parse 400 (below),
    // never a misleading missing-model 400. `LazyBody::parse` preserves the exact malformed-body
    // reject set of the old eager `parse::<Value>` (same depth guard, same parser, full-body scan)
    // but builds NO DOM — only the top-level head projection the passthrough path reads. The full
    // `Value` tree is materialized downstream ONLY on the paths that need it (cross-protocol
    // translation, hooks, taps, gates, failover hops 2+).
    let parsed_v: Option<crate::engine::LazyBody> = if ct.starts_with("application/json")
        || ct.is_empty()
    {
        match crate::engine::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
                return host.finish_rejected(
                    gov,
                    proto,
                    crate::engine::POOL_LABEL_UNRESOLVED,
                    started,
                    charged_at,
                    busbar_substrate::proxy::ingress_error(
                        proto,
                        StatusCode::BAD_REQUEST,
                        crate::engine::KIND_INVALID_REQUEST,
                        "We could not parse the JSON body of your request.",
                    ),
                );
            }
        }
    } else {
        None
    };
    let model = if let Some(m) = model_hint {
        Some(m)
    } else if ct.starts_with("multipart/") {
        multipart_model(ct, &body)
    } else {
        // `model` is a captured head key: this point read never materializes the DOM and returns
        // exactly what the full `Value` returned (missing / non-string / non-object body -> None).
        parsed_v.as_ref().and_then(|v| {
            v.probe()
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "Missing required parameter: 'model'.",
                ),
            );
        }
    };

    operation_resolved(
        host,
        gov,
        proto,
        operation,
        op_handler,
        &model,
        headers,
        body,
        parsed_v,
        caller_token,
        started,
        charged_at,
        None,
    )
    .await
}
/// THE NATIVE (LLM) PLANE — the pool/engine routing that lives in-core today (the path an LLM arrival
/// takes), now expressed as a sibling on the NEUTRAL gauntlet seam
/// ([`busbar_substrate::plane_host::GauntletPlane`]) so it rides the exact SAME shared sequence as the
/// extracted MCP/A2A planes. Named plane-neutrally so the neutral core spells no plane-family type
/// (per the freeze and purity law). Holds this request's owned + borrowed payload; `drive` moves it
/// into the one engine.
///
/// The two hooks are today's inline gauntlet logic, VERBATIM: `verify_destination` is the
/// pre-admission [`destination_guard`] (pool ACL, fallback-pool ACL, unpriced-model gate); `drive` is
/// the single budget-admission door ([`admission_door`]) → pool/lane candidate selection →
/// `forward_with_pool_parsed` (THE ONE ENGINE, streaming) → [`finish_admitted`]. Byte-identical to
/// the pre-seam `operation_resolved`: same order, same errors, same `model_not_found_message`/not-found
/// shaping, same budget-door position, same stream-end metering. A later milestone relocates this
/// impl into its plane crate; M3 only makes it a sibling on the shared seam.
struct NativePlane<'a> {
    host: &'a Arc<dyn EngineHost>,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    headers: &'a HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
    caller_token: Option<&'a str>,
    /// A dialect's PRE-SHAPED model-not-found body, or `None` for the neutral copy. The dialect that
    /// owns the request built this at arrival (a path-model dialect that echoes its own not-found
    /// vocabulary); `drive` uses it verbatim on a model miss, opaque to every other stage — core names
    /// no dialect here.
    model_not_found_message: Option<&'a str>,
}

#[async_trait::async_trait]
impl busbar_substrate::plane_host::GauntletPlane for NativePlane<'_> {
    fn verify_destination(
        &self,
        req: &busbar_substrate::plane_host::GauntletRequest<'_>,
    ) -> busbar_substrate::plane_host::VerifyOutcome {
        use busbar_substrate::plane_host::VerifyOutcome;
        // STAGE 2 — the pre-admission destination guard, verbatim. Its `Err` is the already-finished,
        // protocol-native rejection; the seam returns it as `Refuse` (byte-identical shaping).
        match self.host.destination_guard(
            req.gov,
            self.proto,
            req.destination,
            req.started,
            req.charged_at,
        ) {
            Ok(()) => VerifyOutcome::Proceed,
            Err(resp) => VerifyOutcome::Refuse(*resp),
        }
    }

    async fn drive(
        self: Box<Self>,
        req: busbar_substrate::plane_host::GauntletRequest<'_>,
    ) -> Response {
        // Move the owned per-request payload out of the box; the borrowed fields ride along.
        let NativePlane {
            host,
            proto,
            operation,
            op_handler,
            headers,
            body,
            parsed_v,
            caller_token,
            model_not_found_message,
        } = *self;
        // App-retype WEDGE 3: resolve this plane's runtime tables off the host slot ONCE (alloc-free:
        // one `Arc::clone` + a downcast), borrowed for the whole served-path tail. The finish/label/
        // admission seams route through `host`, so this tail names no core ingress module.
        let rt = native_runtime_arc(host.as_ref());

        // STAGE 3–4 — THE single budget-admission door charges the chain buckets, through the host seam.
        // On rejection nothing was charged (the door finished it).
        let (admit, downgraded) =
            match host.admission_door(req.gov, proto, req.destination, req.started, req.charged_at)
            {
                Err(resp) => return *resp,
                Ok(admitted) => admitted,
            };
        let charged = admit.is_some();
        // A budget downgrade re-pooled the admission: dispatch through the pool the charge actually
        // landed on, not the one the client asked for.
        let model = downgraded.as_deref().unwrap_or(req.destination);

        // STAGE 5 — candidate selection + THE ONE ENGINE.
        let (cands, pool_name): (Vec<WeightedLane>, &str) =
            if let Some(c) = EngineTables::new(&rt).pools().get(model) {
                (c.clone(), model)
            } else if let Some(&i) = EngineTables::new(&rt).by_model().get(model) {
                (
                    vec![WeightedLane {
                        reasoning: None,
                        idx: i,
                        weight: 1,
                        attempt_timeout_ms: None,
                    }],
                    "",
                )
            } else {
                // The destination did not resolve — the dialect-shaped not-found, finished through the
                // SAME stage-6 tail as a served request (so the pre-seam not-found accounting is exact).
                let resp = busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::NOT_FOUND,
                    crate::engine::KIND_NOT_FOUND,
                    &busbar_substrate::ingress::not_found_message(model, model_not_found_message),
                );
                return host.finish_admitted(
                    req.gov,
                    proto,
                    host.pool_label(model),
                    req.started,
                    req.charged_at,
                    resp,
                    charged,
                );
            };

        // THE ONE ENGINE: every operation — chat included — forwards through the same failover/
        // breaker/policy pipeline. JSON bodies ride parsed (`Some(v)`, parsed once by the caller);
        // opaque bodies (multipart/binary) ride `None` and relay/translate at the byte level via the
        // operation codecs.
        let ct = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Session affinity: the pool's configured affinity header, read generically for EVERY
        // operation (sticky routing is an engine capability, not a chat feature).
        let affinity_key: Option<String> = headers
            .get(affinity_header_for(&rt, model))
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let resp = crate::engine::forward_with_pool_parsed(
            host,
            &rt,
            cands,
            body,
            parsed_v,
            // `ct` borrows `headers` (a caller-held reference that outlives this call) — no per-request
            // `to_string` copy is needed to thread the Content-Type through.
            if ct.is_empty() {
                crate::engine::APPLICATION_JSON
            } else {
                ct
            },
            caller_token,
            // The key the auth layer resolved/synthesized for this caller — lets the routing-signal
            // path project rate_headroom/identity for group/SSO principals whose token is not a
            // virtual-key secret (so a token `lookup` would miss).
            req.gov.key.as_ref(),
            pool_name,
            affinity_key.as_deref(),
            proto,
            // THE THIRD AXIS IS DECIDED AT THE ARRIVAL, which is the only place that knows it. This is
            // an axum handler: the exchange came in on one HTTP request and leaves on its response, so
            // the transport is `Http` and saying so is a statement of fact, not a default. The stdio
            // and gRPC arrivals get their own entry points and frame the same codecs.
            busbar_substrate::handlers::frame(
                busbar_substrate::transport::Transport::Http,
                operation,
                op_handler,
            ),
            usage_sink(host, req.gov, pool_name, req.charged_at, admit),
            // CLIENT-HEADER FIDELITY: capture the allowlisted client beta/version headers the caller
            // ACTUALLY SENT (opt-in — empty unless one is present), via the neutral collector fed the
            // plane's forwardable-name set. Dialect scoping to the matching egress lane is applied
            // later, at the egress assembly site.
            busbar_substrate::proxy::collect_client_headers(
                headers,
                &crate::engine::forwardable_client_header_names(),
            ),
        )
        .await;

        // STAGE 6 — the admitted finish: per-request metrics, the request-log webhook, and the
        // refund of the flat admission fee on a non-2xx outcome. No audit record is written here;
        // the admin-audit and call-log seams are reached from elsewhere and this path touches
        // neither.
        //
        // The label is the EFFECTIVE model, which is the downgraded pool wherever a budget
        // downgrade re-pooled the admission — the name the charge landed on, so the metric row and
        // the ledger row name the same pool. `pool_label` is what bounds the Prometheus
        // cardinality; on this path it is the name itself, because a request that reached stage 6
        // resolved to a configured pool or by-model lane, and the `"unresolved"` sentinel belongs
        // to the not-found return above.
        host.finish_admitted(
            req.gov,
            proto,
            host.pool_label(model),
            req.started,
            req.charged_at,
            resp,
            charged,
        )
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn run(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    model_not_found_message: Option<&str>,
) -> Response {
    let plane = NativePlane {
        host,
        proto,
        operation,
        op_handler,
        headers,
        body,
        parsed_v,
        caller_token,
        model_not_found_message,
    };
    // The shared sequence owns only stage 1 (identity, via `gov`) and the verify-before-admit order;
    // the LLM plane's `drive` owns admission/route/metering/finish byte-identically. `correlation_id`
    // is `0` here: the LLM engine stamps its own per-request id inside `forward_with_pool_parsed`
    // (`App::next_request_id`), so the shared field is unused on this path and must NOT pre-stamp one
    // (that would double-advance the counter and shift every request id).
    let req = busbar_substrate::plane_host::GauntletRequest {
        gov,
        destination: model,
        correlation_id: 0,
        charged_at,
        started,
    };
    busbar_substrate::plane_host::run_gauntlet(req, Box::new(plane)).await
}

/// The stable ingress name for the resolved-operation gauntlet, retained as a thin delegator to the
/// canonical [`run`] (surfaced as [`crate::operation::run`]). Signature- and behavior-identical to
/// `run`: its three callers — `operation_ingress`, the ingress core's chat entry, and the
/// MCP-sampling veneer in `plane_host` — plus the `pub use dispatch::operation_resolved` re-export
/// keep their exact call surface while `run` becomes the single entry the plane hooks grow onto.
#[allow(clippy::too_many_arguments)]
pub async fn operation_resolved(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    op_handler: &'static dyn busbar_substrate::handlers::OperationHandler,
    model: &str,
    headers: &HeaderMap,
    body: Bytes,
    parsed_v: Option<crate::engine::LazyBody>,
    caller_token: Option<&str>,
    started: Instant,
    charged_at: u64,
    model_not_found_message: Option<&str>,
) -> Response {
    run(
        host,
        gov,
        proto,
        operation,
        op_handler,
        model,
        headers,
        body,
        parsed_v,
        caller_token,
        started,
        charged_at,
        model_not_found_message,
    )
    .await
}
pub(crate) fn usage_sink(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    pool: &str,
    charged_at: u64,
    admit: Option<busbar_substrate::plane_host::AdmitHandle>,
) -> Option<crate::engine::UsageSink> {
    // App-retype WEDGE 3: the sink holds the OPAQUE governance/cost handles the host mints over the
    // SAME `GovState`/`CostModel` the pre-flip `app.governance`/`app.cost` named — byte-identical accrual
    // at the stream-end metering seams. `governance()` is `Some` iff governance is configured.
    match (host.governance(), &gov.key) {
        (Some(g), Some(key)) => Some(crate::engine::UsageSink {
            gov: g,
            // The resolved cost model handle rides along (one Arc bump) so the stream-end accrual can
            // walk the key's budget-group chain without reaching back into the App snapshot.
            cost: host.cost(),
            // Share the resolved key by `Arc`: no per-request `id` String clone; it is read
            // through `sink.key` at charge time.
            key: key.clone(),
            // The admitted pool: the accounting scope for pool-qualified limits (accrual mirrors
            // the admission charge).
            pool: std::sync::Arc::from(pool),
            // The header-arrival epoch this request was admitted at — reused for the token fee so it
            // shares the flat per-request fee's window (#29). See `UsageSink::charged_at`.
            charged_at,
            // The admission's in-flight HOLDS (the `concurrent` limit gauges) ride the sink so
            // they release when the response stream completes / the request context unwinds - the
            // sink is the one per-request object that provably lives to stream end. The opaque
            // `AdmitHandle` already wraps the grant in an `Arc`; the LAST clone dropping releases the gauges.
            admit,
        }),
        // No governance/key = nothing was admitted through the limit engine; a grant cannot exist.
        _ => None,
    }
}

/// The default affinity header name used when a pool's `affinity` config does not specify a custom
/// header. Both the `Some`-arm fallback and the `None`-arm of `affinity_header_for` must agree on
/// this spelling; a single const prevents them from silently diverging.
const DEFAULT_AFFINITY_HEADER: &str = "x-session-id";

/// The request header that pins a session to a lane for a pool. Defaults to `x-session-id`; a
/// pool's `affinity` config (mode `session`) may name a different header (e.g. `x-user-id`).
pub(crate) fn affinity_header_for<'a>(rt: &'a Arc<NativeRuntime>, pool: &str) -> &'a str {
    match EngineTables::new(rt)
        .pool_runtime()
        .get(pool)
        .and_then(|r| r.affinity.as_ref())
    {
        // The affinity block's presence IS the `session` mode fact (the only supported mode, so the
        // neutral AffinityInput carries no mode enum); honour the configured header name.
        Some(a) => a.header_name.as_deref().unwrap_or(DEFAULT_AFFINITY_HEADER),
        None => DEFAULT_AFFINITY_HEADER,
    }
}

#[allow(clippy::too_many_arguments)]
async fn ingress_path_model_inner(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    caller_token: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    model: &str,
    operation: busbar_api::operation::Operation,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<&str>,
) -> Response {
    let started = Instant::now();
    // Header-arrival epoch pinned once and reused for both the per-request and token fees (#29).
    // C10: read off the host's clock port (`ClockHost::clock_now_secs`), value-identical to the
    // ambient `store::now()` it replaces.
    let charged_at = host.clock_now_secs();
    // App-retype WEDGE 3: the pre-routing finish seam routes through the threaded `host` (the body-model
    // twin does the same).
    let mut v: Value = match busbar_substrate::json::parse(&body) {
        Ok(v) => v,
        Err(_) => {
            // Log a SANITIZED note for operators (just the byte length), never the parser's raw error:
            // with sonic-rs it embeds a fragment of the malformed body, which can contain secrets/PII.
            // The client gets only the generic, vendor-plausible message.
            tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-routing failure (model never resolved): route through `finish_rejected` with the
            // bounded `"unresolved"` label so the malformed-body request is still counted in REQUESTS_TOTAL /
            // REQUEST_DURATION_SECONDS and fires the request-log webhook, mirroring the model-miss
            // path. A raw early-return made it invisible to Prometheus and the webhook.
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                ),
            );
        }
    };

    // Inject model+stream so the shared resolution/forward plumbing (which reads both from the
    // body) works for protocols whose native wire carries them in the URL instead. A native client
    // body is always a JSON object; if it is not, return a protocol-shaped 400 rather than panic.
    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.to_string()));
            obj.insert("stream".to_string(), Value::Bool(stream));
            // Signal a non-`alt=sse` streaming request so the response is framed as a JSON array
            // rather than SSE (only Gemini's writer carries such a key today). The marker key is
            // resolved through the writer vtable by protocol NAME — ingress names no protocol
            // submodule, so "delete proto/gemini → app is gemini-free" holds. The shim is stripped
            // before the upstream call (`proxy::strip_router_shim_keys`); cross-protocol egress
            // drops it via the IR.
            if gemini_json_array {
                if let Some(shim_key) = busbar_substrate::proto::array_stream_shim_key_for(proto) {
                    obj.insert(shim_key.to_string(), Value::Bool(true));
                }
            }
        }
        None => {
            // Pre-routing failure (body is not a JSON object → model never resolved): route through
            // `finish_rejected` with the bounded `"unresolved"` label so it is observable in metrics +
            // the webhook, not a silent early-return — and never charged, so nothing to refund.
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "Request body must be a JSON object.",
                ),
            );
        }
    }

    // Re-serializing a `serde_json::Value` we just parsed (with only `String`/`Bool` keys spliced
    // in) cannot fail in practice — `to_vec` on an in-memory `Value` has no fallible component. The
    // `Err` arm is kept as a non-panicking, protocol-shaped guard (never `unwrap`) so the request
    // path stays panic-free even if a future change introduces a non-serializable injected value;
    // it is effectively unreachable today, hence not exercised by a dedicated test.
    let injected: Bytes = match busbar_substrate::json::to_vec(&v) {
        Ok(b) => b.into(),
        Err(_e) => {
            // Same leak class as the parse arms above: the JSON library's error Display is a
            // busbar-internal tell (on the parse side it embeds raw body fragments), so we never echo
            // it — a bare operator breadcrumb only, consistent with the `parse_err_log` policy used at
            // every deserialize site. (Serialization errors don't carry body bytes today, but aligning
            // here closes the latent leak class if that ever changes.)
            tracing::debug!("injected request body re-serialization failed");
            // Pre-routing failure (model never reached resolution): route through `finish_rejected`
            // with the bounded `"unresolved"` label so it is observable in metrics + the webhook. This
            // arm is effectively unreachable today (see the comment above), but keeping it on
            // `finish_rejected` preserves the observability invariant for every pre-routing exit.
            return host.finish_rejected(
                gov,
                proto,
                crate::engine::POOL_LABEL_UNRESOLVED,
                started,
                charged_at,
                busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "The request body could not be processed.",
                ),
            );
        }
    };

    // UNIVERSAL: the caller (that protocol's routing arm) already resolved WHICH operation this is
    // (`RequestHandler::resolve_operation`); look its handler up through the registry — identical
    // for every protocol and operation. This arm's only per-protocol work was the URL parsing above.
    let Some(op_handler) = busbar_substrate::handlers::request_handler(proto)
        .and_then(|rh| rh.operation_handler(operation))
    else {
        return host.finish_rejected(
            gov,
            proto,
            crate::engine::POOL_LABEL_UNRESOLVED,
            started,
            charged_at,
            busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                crate::engine::KIND_NOT_FOUND,
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
            ),
        );
    };
    operation_resolved(
        host,
        gov,
        proto,
        operation,
        op_handler,
        model,
        headers,
        injected,
        // Path-model ingress already parsed (and shim-injected into) the body — carry the DOM
        // eagerly; the engine's pristine head check reads it directly and behaves as before.
        Some(crate::engine::LazyBody::from_value(v)),
        caller_token,
        started,
        charged_at,
        model_not_found_message,
    )
    .await
}

fn payload(ctx: &ArrivalCtx) -> &busbar_substrate::ingress::arrival::ArrivalPayload {
    ctx.downcast_ref::<busbar_substrate::ingress::arrival::ArrivalPayload>()
        .expect("ArrivalCtx must carry the neutral ArrivalPayload -- a wiring bug otherwise")
}

/// THE LLM PLANE'S RESOLVED-COMPLETION SYNTHESIZER — installed into the substrate completion seam
/// (`install_completion_ingress` in production `main.rs`, `set_test_completion_ingress` in a
/// `test-support` build) and reached by core's `EngineHost::synthesize_completion` (the MCP-sampling
/// re-entry). Drives ONE non-streaming chat completion (a known `model` + body) through the SAME
/// resolved-op path (`operation_resolved`) a first-party arrival takes, so governance attribution and
/// metering are byte-identical to an arrival. The successor to the former core-resident
/// `synthesize_completion_over` body: the residual-default chat dialect is read by NAME off the
/// registry (so this spells no dialect), `Transport::Http`, `caller_token` from the arrival, model
/// explicit, `model_not_found_message = None`. Matches the `CompletionIngress` fn-pointer shape.
pub fn synthesize_completion(
    a: busbar_substrate::ingress::arrival::CompletionArrival,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    Box::pin(async move {
        let busbar_substrate::ingress::arrival::CompletionArrival {
            ctx,
            model,
            headers,
            body,
        } = a;
        let p = payload(&ctx);
        // THE DEFAULT CHAT PROTOCOL the synthesized completion is driven as — the registry's
        // residual-default protocol, read by NAME so no dialect literal appears here. `None` is the
        // all-planes-off configuration with no chat dialect to drive; the caller reads the non-2xx
        // body as an unsatisfiable ask, the same honest error the neutral seam returns when unlinked.
        let Some(proto) = busbar_substrate::proto::residual_default_protocol() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "no default chat protocol is installed",
            )
                .into_response();
        };
        // THE BODY, PARSED — and a malformed one REFUSED, in the dialect the completion is driven
        // as. `.ok()` swallowed the parse error here and drove on with `parsed = None`, so a body
        // the arrival path answers with a 400 before the door was instead admitted, charged and
        // relayed upstream by this entry point. Two ways in, one of them billing for a body it had
        // already failed to read: the re-entry is meant to be byte-identical to an arrival, and
        // this is the one place it was not. Refused AFTER the protocol is resolved so the refusal
        // wears the same envelope the arrival's does.
        let parsed = match crate::engine::LazyBody::parse(&body) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "synthesized completion body JSON parse failed");
                return busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    crate::engine::KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                );
            }
        };
        let op =
            busbar_substrate::handlers::chat(proto, busbar_substrate::transport::Transport::Http);
        operation_resolved(
            &p.host,
            &p.gov,
            proto,
            op.operation,
            op.op_handler,
            &model,
            &headers,
            body,
            parsed,
            p.caller_token.as_deref(),
            Instant::now(),
            // C10: the synthesized completion's charge epoch, off the arrival payload's own host
            // clock port rather than the ambient free function. Same value, one clock.
            p.host.clock_now_secs(),
            None,
        )
        .await
    })
}

/// BODY-MODEL UNIVERSAL INGRESS -- every operation whose model rides IN THE BODY.
pub async fn operation_ingress(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    proto: &'static str,
    operation: busbar_api::operation::Operation,
    model_hint: Option<String>,
) -> Response {
    let p = payload(ctx);
    operation_ingress_inner(
        &p.host,
        &p.gov,
        p.caller_token.as_deref(),
        &headers,
        body,
        proto,
        operation,
        model_hint,
    )
    .await
}

/// PATH-MODEL UNIVERSAL INGRESS -- gemini/bedrock keep their model in the URL.
#[allow(clippy::too_many_arguments)]
pub async fn ingress_path_model(
    ctx: &ArrivalCtx,
    headers: HeaderMap,
    body: Bytes,
    model: String,
    operation: busbar_api::operation::Operation,
    stream: bool,
    gemini_json_array: bool,
    proto: &'static str,
    model_not_found_message: Option<String>,
) -> Response {
    let p = payload(ctx);
    ingress_path_model_inner(
        &p.host,
        &p.gov,
        p.caller_token.as_deref(),
        &headers,
        body,
        &model,
        operation,
        stream,
        gemini_json_array,
        proto,
        model_not_found_message.as_deref(),
    )
    .await
}

#[cfg(test)]
#[path = "multipart_model_tests.rs"]
mod multipart_model_tests;
