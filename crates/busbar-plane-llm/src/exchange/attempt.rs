//! One attempt's far-end request, sans I/O: the verb, the target, the head fields and the body the
//! plane answers an ATTEMPT piece with. The kernel joins the target onto the member's base URL,
//! adds the credential fields (its one auth call) and sends it.
//!
//! This is the previous release's request assembly for one hop, in its order and nothing else:
//! the stream intent read off the caller's body, the pristine short-circuit (a same-dialect body
//! the far end would receive unchanged goes out as the caller's own bytes), the cross-dialect
//! translation and the per-far-end rewrites, the usage opt-in for a streamed request whose far
//! end reports usage only when asked, the far end's path, and the head fields a native client of
//! the far end sends. Credentials, timing, the breaker and the audit record of a dropped control
//! are the kernel's; a dropped control comes back to the caller of [`build`] to record.

use std::borrow::Cow;

use busbar_contract::codec::{EgressCtx, EgressWire, IngressReject, OperationHandler};
use busbar_contract::ir::egress_prep::EgressPrep;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::{
    HeadFields, ProtocolDecl, APPLICATION_JSON, KIND_API_ERROR, KIND_INVALID_REQUEST,
    KIND_NOT_FOUND,
};
use serde_json::Value;

use super::arrive::Arrived;
use super::shaping::{FarShape, Lane, Shaping};
use crate::codec::json_splice::{self, Edit};
use crate::codec::translate::{TranslateCodec as _, TranslateReqInput, TranslateReqReject};
use crate::codec::DECLS;
use crate::dialect::DIALECTS;

/// A refusal the attempt answers the caller with instead of reaching the far end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The status.
    pub status: u16,
    /// The dialect whose error writer renders it (the caller's).
    pub envelope: &'static str,
    /// The error kind token.
    pub kind: &'static str,
    /// The message.
    pub message: Cow<'static, str>,
}

/// The request bound for the far end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FarRequest {
    /// The method.
    pub verb: &'static str,
    /// The path and query the kernel joins onto the member's base URL; it starts with `/`.
    pub target: String,
    /// The head fields, in order; the kernel's credential fields follow them.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
    /// The body went out as the caller sent it.
    pub pristine: bool,
    /// Controls the far end's dialect cannot represent, dropped from the request (the kernel
    /// records each: `egress.control_unrepresentable`, `<control> on <dialect>`, degraded).
    pub dropped_controls: Vec<&'static str>,
}

/// The caller's stream intent, read off the caller's body before any rewrite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamIntent {
    /// The caller asked for a stream.
    pub wants_stream: bool,
    /// The caller asked for usage in the stream itself.
    pub client_include_usage: bool,
}

/// The caller's stream intent under `handler` (an operation that never streams asks for none).
#[must_use]
pub fn stream_intent(handler: &dyn OperationHandler, body: Option<&Value>) -> StreamIntent {
    let wants_stream = body.is_some_and(|v| handler.wants_stream(v));
    let client_include_usage = wants_stream
        && body
            .and_then(|v| v.pointer("/stream_options/include_usage"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    StreamIntent {
        wants_stream,
        client_include_usage,
    }
}

/// The message a request the plane cannot write is answered with.
pub const DETAIL_INTERNAL_ERROR: &str =
    "We received an unexpected internal error. Please try again.";
/// The message an operation the far end's model does not serve is answered with.
pub const DETAIL_MODEL_UNSUPPORTED_OPERATION: &str = "This model does not support that operation.";
/// The message an operation the caller's dialect does not serve is answered with.
pub const DETAIL_ENDPOINT_UNSUPPORTED_OPERATION: &str =
    "This endpoint does not support that operation.";

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

fn answer(
    envelope: &'static str,
    status: u16,
    kind: &'static str,
    message: impl Into<Cow<'static, str>>,
) -> Answer {
    Answer {
        status,
        envelope,
        kind,
        message: message.into(),
    }
}

fn internal(envelope: &'static str) -> Answer {
    answer(envelope, 500, KIND_API_ERROR, DETAIL_INTERNAL_ERROR)
}

/// The caller's refusal for a request its own dialect's reader turned away.
#[must_use]
pub fn ingress_reject(envelope: &'static str, reject: &IngressReject) -> Answer {
    match reject {
        IngressReject::BadRequest(_) => answer(
            envelope,
            400,
            KIND_INVALID_REQUEST,
            "We could not process the content of your request.",
        ),
        IngressReject::UnsupportedSubOp { op, model } => answer(
            envelope,
            404,
            KIND_NOT_FOUND,
            format!("{} is not supported for model \"{model}\".", op.name()),
        ),
    }
}

/// The caller's refusal for a translation the far end's dialect turned away.
#[must_use]
pub fn translate_reject(envelope: &'static str, reject: TranslateReqReject) -> Answer {
    match reject {
        TranslateReqReject::Ingress(reject) => ingress_reject(envelope, &reject),
        TranslateReqReject::EgressUnsupported => answer(
            envelope,
            404,
            KIND_NOT_FOUND,
            DETAIL_MODEL_UNSUPPORTED_OPERATION,
        ),
        TranslateReqReject::Unrepresentable(reason) => {
            answer(envelope, 400, KIND_INVALID_REQUEST, reason)
        }
    }
}

/// Whether a caller's body is JSON, by the arrival's own rule: a path-model arrival always is (its
/// model and stream were spliced into it), a body-model one when its content type says so or names
/// none.
fn relays_json(ingress: &str, content_type: &str) -> bool {
    decl(ingress).is_some_and(|d| d.has_model_in_url)
        || content_type.starts_with(APPLICATION_JSON)
        || content_type.is_empty()
}

/// The members a far end at a `path_base` needs reshaped, read off its own writer: each member the
/// reshape removes and each it sets (Claude-on-Vertex: no `model`, an `anthropic_version`).
fn path_base_members(far: &ProtocolDecl) -> Vec<(String, Option<Vec<u8>>)> {
    let mut probe = serde_json::json!({ "model": "" });
    let reshaped = far
        .dialect()
        .is_some_and(|dc| dc.reshape_for_path_base(&mut probe));
    let Some(obj) = probe.as_object().filter(|_| reshaped) else {
        return Vec::new();
    };
    let mut members: Vec<(String, Option<Vec<u8>>)> = obj
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), Some(serde_json::to_vec(v).ok()?))))
        .filter(|(k, v)| k.as_str() != "model" || v.as_deref() != Some(b"\"\"".as_slice()))
        .collect();
    if !obj.contains_key("model") {
        members.push(("model".to_string(), None));
    }
    members
}

/// THE RELAY of one same-dialect body: the caller's bytes with the governed splices only, each a
/// byte-level member edit (`json_splice`), never a re-serialization (LLM DIALECT FIDELITY, owner
/// 2026-10-02; DIALECT-FIDELITY-DESIGN F2). The governed members: busbar's own router keys (never a
/// far end's); for a path-model far end the `model` and `stream` the arrival spliced in (both ride
/// the URL); for a body-model far end the mapped `model`, and a `path_base` far end's reshape.
/// A body that is not a JSON object goes out as the caller sent it.
#[must_use]
pub fn relay_request<'a>(
    lane: FarShape<'_>,
    content_type: &str,
    hop_bytes: &'a [u8],
) -> Translated<'a> {
    let unchanged = Translated {
        bytes: Cow::Borrowed(hop_bytes),
        pristine: true,
    };
    let Some(far) = decl(lane.dialect) else {
        return unchanged;
    };
    if !relays_json(lane.dialect, content_type) {
        return unchanged;
    }
    let model = serde_json::to_vec(lane.wire_model).unwrap_or_default();
    let reshape = if lane.path_base.is_some() {
        path_base_members(far)
    } else {
        Vec::new()
    };
    let mut edits: Vec<Edit<'_>> = DECLS
        .iter()
        .filter_map(|d| d.array_stream_shim_key)
        .map(Edit::Remove)
        .collect();
    if far.has_model_in_url {
        edits.push(Edit::Remove("stream"));
        edits.push(Edit::Remove("model"));
    } else {
        edits.push(Edit::Set("model", Cow::Borrowed(&model)));
    }
    for (k, v) in &reshape {
        edits.push(match v {
            Some(v) => Edit::Set(k, Cow::Borrowed(v)),
            None => Edit::Remove(k),
        });
    }
    match json_splice::apply_top(hop_bytes, &edits) {
        Some(bytes) => Translated {
            bytes: Cow::Owned(bytes),
            pristine: false,
        },
        None => unchanged,
    }
}

/// What the far end is sent for one hop's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Translated<'a> {
    /// The bytes: the caller's own, borrowed, when the hop is pristine.
    pub bytes: Cow<'a, [u8]>,
    /// The caller's bytes went out unchanged.
    pub pristine: bool,
}

/// One hop's translation: its outcome, and the two facts the kernel records whatever the outcome
/// (the translation counter's event when the request is read for a far end of another dialect, and
/// each control that far end cannot represent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Translation<'a> {
    /// The body, or the caller's refusal.
    pub outcome: Result<Translated<'a>, Answer>,
    /// A JSON request was read for a far end of another dialect.
    pub crossed: bool,
    /// Controls the far end's dialect cannot represent.
    pub dropped_controls: Vec<&'static str>,
}

fn static_name(name: &str) -> &'static str {
    decl(name).map_or("", |d| d.name)
}

/// THE TRANSLATION OF ONE HOP'S BODY for the far end `lane`: `body` is the caller's JSON (`None`
/// for an opaque body; never read within one dialect, which relays `hop_bytes` with its governed
/// splices, [`relay_request`]), `hop_bytes` the caller's bytes.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn translate_request<'a>(
    ingress: &str,
    operation: OpVerb,
    lane: FarShape<'_>,
    default_max_tokens: u32,
    reasoning_budgets: [u32; 4],
    reasoning_allowed: bool,
    body: Option<Value>,
    content_type: &str,
    hop_bytes: &'a [u8],
) -> Translation<'a> {
    let envelope = static_name(ingress);
    let mut t = Translation {
        outcome: Err(internal(envelope)),
        crossed: false,
        dropped_controls: Vec::new(),
    };
    t.outcome = translate_into(
        &mut t,
        ingress,
        envelope,
        operation,
        lane,
        default_max_tokens,
        reasoning_budgets,
        reasoning_allowed,
        body,
        content_type,
        hop_bytes,
    );
    t
}

#[allow(clippy::too_many_arguments)]
fn translate_into<'a>(
    t: &mut Translation<'a>,
    ingress: &str,
    envelope: &'static str,
    operation: OpVerb,
    lane: FarShape<'_>,
    default_max_tokens: u32,
    reasoning_budgets: [u32; 4],
    reasoning_allowed: bool,
    body: Option<Value>,
    content_type: &str,
    hop_bytes: &'a [u8],
) -> Result<Translated<'a>, Answer> {
    let egress = lane.dialect;
    if ingress == egress {
        return Ok(relay_request(lane, content_type, hop_bytes));
    }
    let far = decl(egress);
    let prep = EgressPrep {
        ingress_protocol: envelope,
        egress_requires_max_tokens: far.is_some_and(|d| d.requires_max_tokens),
        lane_default_max_tokens: lane.default_max_tokens,
        global_default_max_tokens: default_max_tokens,
        reasoning_allowed,
        reasoning_budgets,
        prompt_caching_allowed: lane.prompt_caching
            || !far.is_some_and(|d| d.cache_markers_model_gated),
        cache_control_cap: far.and_then(|d| d.max_cache_control_breakpoints),
        lane_caps: lane.caps,
        thought_signature_fill: far.is_some_and(|d| d.fills_thought_signature)
            && lane.path_base.is_none(),
    };
    let handler_of = |p: &str| {
        decl(p)
            .and_then(|d| d.handler)
            .and_then(|rh| rh.operation_handler(operation))
    };
    let Some(body) = body else {
        let (Some(ih), Some(_eh)) = (handler_of(ingress), handler_of(egress)) else {
            return Err(answer(
                envelope,
                404,
                KIND_NOT_FOUND,
                DETAIL_MODEL_UNSUPPORTED_OPERATION,
            ));
        };
        let translated = ih
            .translate_request(
                TranslateReqInput::Opaque {
                    bytes: hop_bytes,
                    content_type,
                },
                Some(egress),
                &prep,
                lane.wire_model,
            )
            .map_err(|e| translate_reject(envelope, e))?;
        let bytes = match translated.wire {
            EgressWire::Bytes(b) => Cow::Owned(b.as_slice().to_vec()),
            EgressWire::Json(v) => {
                Cow::Owned(crate::codec::json::to_vec(&v).map_err(|_| internal(envelope))?)
            }
            EgressWire::Unrepresentable { reason } => {
                return Err(translate_reject(
                    envelope,
                    TranslateReqReject::Unrepresentable(reason),
                ))
            }
        };
        return Ok(Translated {
            bytes,
            pristine: false,
        });
    };
    t.crossed = true;
    let Some(ingress_dialect) = decl(ingress).and_then(|d| d.dialect()) else {
        return Err(answer(
            envelope,
            400,
            KIND_INVALID_REQUEST,
            DETAIL_INTERNAL_ERROR,
        ));
    };
    let _ = ingress_dialect.requested_candidate_count(&body);
    let Some(ingress_handler) = handler_of(ingress) else {
        return Err(answer(
            envelope,
            404,
            KIND_NOT_FOUND,
            DETAIL_ENDPOINT_UNSUPPORTED_OPERATION,
        ));
    };
    let translated = ingress_handler
        .translate_request(
            TranslateReqInput::Json(&body),
            handler_of(egress).map(|_| egress),
            &prep,
            lane.wire_model,
        )
        .map_err(|e| translate_reject(envelope, e))?;
    t.dropped_controls = translated.dropped_controls;
    let mut body = match translated.wire {
        EgressWire::Json(written) => written,
        EgressWire::Bytes(b) => {
            return Ok(Translated {
                bytes: Cow::Owned(b.as_slice().to_vec()),
                pristine: false,
            })
        }
        EgressWire::Unrepresentable { reason } => {
            return Err(translate_reject(
                envelope,
                TranslateReqReject::Unrepresentable(reason),
            ))
        }
    };
    crate::codec::wire_shim::strip_router_shim_keys(&mut body, egress);
    let far_dialect = far.and_then(|d| d.dialect());
    if let Some(dc) = far_dialect.as_ref() {
        dc.rewrite_model_if_needed(&mut body, lane.wire_model);
        if lane.path_base.is_some() {
            dc.reshape_for_path_base(&mut body);
        }
    }
    let bytes = crate::codec::json::to_vec(&body).map_err(|_| internal(envelope))?;
    Ok(Translated {
        bytes: Cow::Owned(bytes),
        pristine: false,
    })
}

/// The far end's path for `operation` on `lane`: the provider's fixed path, else the far end's
/// dialect's own path for the wire model and the stream intent.
#[must_use]
pub fn upstream_path(lane: &Lane, operation: OpVerb, stream: bool) -> Option<String> {
    let rh = decl(lane.dialect).and_then(|d| d.handler)?;
    Some(match &lane.path {
        Some(p) => p.clone(),
        None => rh.upstream_path(&EgressCtx {
            operation,
            model: lane.wire_model(),
            stream,
            path_base: lane.path_base.as_deref(),
        }),
    })
}

fn path_is_uri_unreserved(path: &str) -> bool {
    path.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/')
    })
}

/// RFC 3986 percent-encoding of a path, `/` kept: every byte outside the unreserved set is `%XX`.
#[must_use]
pub fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The path as it goes on the wire and as a request signature canonicalises it: an unreserved path
/// is both; any other is percent-encoded on the wire and encoded twice for the signature.
#[must_use]
pub fn wire_and_canonical_path(url_path: &str) -> (String, String) {
    let (path, query) = match url_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url_path, None),
    };
    if path_is_uri_unreserved(path) {
        let wire = match query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        };
        return (wire, path.to_string());
    }
    let wire_path = uri_encode_path(path);
    let canonical = uri_encode_path(&wire_path);
    let wire = match query {
        Some(q) => format!("{wire_path}?{q}"),
        None => wire_path,
    };
    (wire, canonical)
}

/// Whether busbar governs the request header `name` (compared without case) for ANY dialect.
///
/// The union, not the arrival dialect's own row: busbar reads its caller's credential from any of
/// these carriers whatever the dialect, so a name another dialect declares a credential is never a
/// header to hand a far end either.
#[must_use]
pub fn governed(name: &str) -> bool {
    DIALECTS.iter().any(|d| {
        d.governed_headers
            .iter()
            .any(|g| name.eq_ignore_ascii_case(g))
    })
}

/// A value a head field can carry as text: visible ASCII and the tab.
fn legal_field_value(v: &[u8]) -> bool {
    v.iter().all(|b| *b == b'\t' || (0x20..0x7f).contains(b))
}

/// The head fields a native client of `lane`'s dialect sends,
/// then, when the caller speaks that dialect, every field the caller sent but the ones busbar
/// governs ([`governed`]):
/// busbar is invisible to upstreams (OWNER HARD RULE 2026-10-02). The caller's value of a name
/// replaces busbar's native default; the per-connection mechanics are the kernel's to drop as it
/// writes the head. A translated route forwards no caller field: none maps between dialects.
fn head_fields(
    lane: &Lane,
    handler: &dyn OperationHandler,
    arrived: &Arrived,
    caller: HeadFields<'_>,
    body_is_json: bool,
    wants_stream: bool,
) -> Result<Vec<(String, Vec<u8>)>, Answer> {
    let egress = lane.dialect;
    let far = decl(egress);
    let content_type: String = if body_is_json {
        APPLICATION_JSON.to_string()
    } else if arrived.dialect == egress {
        arrived.content_type.clone()
    } else {
        far.and_then(|d| d.handler)
            .and_then(|rh| rh.operation_handler(arrived.operation))
            .map_or(APPLICATION_JSON, |h| h.egress_request_content_type())
            .to_string()
    };
    if !legal_field_value(content_type.as_bytes()) {
        return Err(internal(arrived.dialect));
    }
    let user_agent = far.map_or(busbar_contract::protocol::EGRESS_UA_DEFAULT, |d| {
        d.egress_user_agent
    });
    let stream_accept = far.map_or(busbar_contract::protocol::TEXT_EVENT_STREAM, |d| {
        d.egress_stream_accept
    });
    let accept = (
        "accept".to_string(),
        handler
            .egress_accept(stream_accept, wants_stream)
            .as_bytes()
            .to_vec(),
    );
    let content_type = ("content-type".to_string(), content_type.into_bytes());
    // A native client's user-agent, never a UA-less request (1.5.5's bytes); a same-dialect
    // caller's own replaces it below.
    let user_agent = ("user-agent".to_string(), user_agent.as_bytes().to_vec());
    let mut fields = vec![content_type, user_agent, accept];
    if arrived.dialect != egress {
        return Ok(fields);
    }
    // The caller's fields, in the order the caller sent them; a repeated name keeps every value.
    let forwarded: Vec<(String, Vec<u8>)> = caller
        .iter()
        .filter_map(|(name, value)| {
            let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            (!governed(&name)).then(|| (name, value.to_vec()))
        })
        .collect();
    fields.retain(|(own, _)| !forwarded.iter().any(|(name, _)| name == own));
    fields.extend(forwarded);
    Ok(fields)
}

/// BUILD ONE ATTEMPT'S FAR-END REQUEST for `member` of `pool`.
///
/// # Errors
///
/// The caller's refusal when the request cannot be written for this far end.
pub fn build(
    arrived: &Arrived,
    caller: HeadFields<'_>,
    shaping: &Shaping,
    pool: &str,
    member: &str,
) -> Result<FarRequest, Answer> {
    let ingress = arrived.dialect;
    let lane = shaping.lane(member).ok_or_else(|| internal(ingress))?;
    let handler = decl(ingress)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(arrived.operation))
        .ok_or_else(|| internal(ingress))?;
    let body_is_json = arrived.parsed.is_some();
    let intent = stream_intent(handler, arrived.parsed.as_ref());
    let relay = ingress == lane.dialect;
    let hop_v = if relay || !body_is_json {
        None
    } else {
        arrived.parsed.clone()
    };
    let reasoning = shaping.reasoning(pool, member).unwrap_or(lane.reasoning);
    let t = translate_request(
        ingress,
        arrived.operation,
        lane.shape(),
        shaping.default_max_tokens,
        shaping.reasoning_budgets,
        reasoning,
        hop_v,
        &arrived.content_type,
        &arrived.body,
    );
    let (translated, dropped_controls) = (t.outcome?, t.dropped_controls);
    let pristine = translated.pristine;
    let body = inject_stream_usage(
        ingress,
        lane,
        &intent,
        body_is_json,
        translated.bytes.into_owned(),
    )?;
    let path = upstream_path(lane, arrived.operation, intent.wants_stream)
        .ok_or_else(|| internal(ingress))?;
    let (target, _canonical) = wire_and_canonical_path(&path);
    let fields = head_fields(
        lane,
        handler,
        arrived,
        caller,
        body_is_json,
        intent.wants_stream,
    )?;
    Ok(FarRequest {
        verb: "POST",
        target,
        fields,
        body,
        pristine,
        dropped_controls,
    })
}

/// The caller's `stream_options` is not an object, so usage cannot be asked for.
pub const DETAIL_STREAM_OPTIONS_NOT_OBJECT: &str =
    "Invalid type for 'stream_options': expected an object.";

/// A streamed request to a far end that reports usage only when asked is asked, unless the caller
/// asked already: the governed METERING edit (`stream_options.include_usage`), a byte splice.
fn inject_stream_usage(
    ingress: &'static str,
    lane: &Lane,
    intent: &StreamIntent,
    body_is_json: bool,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Answer> {
    if !(intent.wants_stream
        && body_is_json
        && decl(lane.dialect).is_some_and(|d| d.stream_usage_requires_opt_in)
        && !intent.client_include_usage)
    {
        return Ok(payload);
    }
    try_inject_stream_include_usage(payload).map_err(|_unmeterable| {
        answer(
            ingress,
            400,
            KIND_INVALID_REQUEST,
            DETAIL_STREAM_OPTIONS_NOT_OBJECT,
        )
    })
}

/// The member a streamed request is asked for its usage with, and the object it lives in.
const STREAM_OPTIONS: &str = "stream_options";
/// The opt-in member itself.
const INCLUDE_USAGE: &str = "include_usage";

/// Ask a streamed request for its usage: `stream_options.include_usage = true`, the object made
/// when absent or null. A byte-level splice over the payload (every other byte stays): the member is
/// set where it stands, or inserted after the opening brace. `Err` carries the payload back verbatim
/// when `stream_options` is not an object (the request cannot be asked, and the caller refuses it
/// rather than bill it blind); a payload that is not a JSON object goes out unchanged.
///
/// # Errors
///
/// The payload, verbatim, when its `stream_options` is not an object.
pub fn try_inject_stream_include_usage(payload: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let Some(top) = json_splice::object_at(&payload, 0) else {
        return Ok(payload);
    };
    let value: Cow<'_, [u8]> = match top.last(STREAM_OPTIONS) {
        None => Cow::Borrowed(br#"{"include_usage":true}"#),
        Some(m) if &payload[m.value_start..m.value_end] == b"null" => {
            Cow::Borrowed(br#"{"include_usage":true}"#)
        }
        Some(m) => {
            let Some(inner) = json_splice::object_at(&payload[..m.value_end], m.value_start) else {
                return Err(payload);
            };
            let set = [Edit::Set(INCLUDE_USAGE, Cow::Borrowed(b"true"))];
            match json_splice::apply(&payload[..m.value_end], &inner, &set) {
                Some(edited) => Cow::Owned(edited[m.value_start..].to_vec()),
                None => Cow::Borrowed(&payload[m.value_start..m.value_end]),
            }
        }
    };
    let set = [Edit::Set(STREAM_OPTIONS, value)];
    let out = json_splice::apply(&payload, &top, &set);
    drop(set);
    Ok(out.unwrap_or(payload))
}
