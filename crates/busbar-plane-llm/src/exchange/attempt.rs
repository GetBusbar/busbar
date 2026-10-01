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
use crate::codec::translate::{TranslateCodec as _, TranslateReqInput, TranslateReqReject};
use crate::codec::DECLS;

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
    /// The caller sent `stream_options` at all.
    pub client_has_stream_options: bool,
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
    let client_has_stream_options =
        wants_stream && body.is_some_and(|v| v.get("stream_options").is_some());
    StreamIntent {
        wants_stream,
        client_include_usage,
        client_has_stream_options,
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

/// A same-dialect body the far end would receive unchanged, proved from its top-level keys alone:
/// no router shim key, no `stream` key for a path-model far end, the lane's wire model as the
/// body's model, no path-base reshape, and no body `model` for a path-model far end. One-sided:
/// `false` means "translate and see".
#[must_use]
pub fn provably_pristine(lane: FarShape<'_>, body: &Value) -> bool {
    let Some(obj) = body.as_object() else {
        return true;
    };
    let shims = DECLS.iter().filter_map(|d| d.array_stream_shim_key);
    for k in shims {
        if obj.contains_key(k) {
            return false;
        }
    }
    let far = decl(lane.dialect);
    let model_in_url = far.is_some_and(|d| d.has_model_in_url);
    if model_in_url && obj.contains_key("stream") {
        return false;
    }
    if obj.get("model").and_then(Value::as_str) != Some(lane.wire_model) {
        return false;
    }
    if lane.path_base.is_some() && far.is_some_and(|d| d.reshapes_body_at_path_base) {
        return false;
    }
    if model_in_url && obj.contains_key("model") {
        return false;
    }
    true
}

/// A same-dialect path-model body carries its model in the URL, never in the body.
pub fn strip_same_protocol_model_shim(v: &mut Value, ingress: &str) -> bool {
    if decl(ingress).is_some_and(|d| d.has_model_in_url) {
        if let Some(obj) = v.as_object_mut() {
            return obj.remove("model").is_some();
        }
    }
    false
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
/// for an opaque body, or for a hop proved pristine), `hop_bytes` the caller's bytes.
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
    let far = decl(egress);
    let prep = (ingress != egress).then(|| EgressPrep {
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
    });
    let handler_of = |p: &str| {
        decl(p)
            .and_then(|d| d.handler)
            .and_then(|rh| rh.operation_handler(operation))
    };
    let Some(mut body) = body else {
        if let Some(prep) = &prep {
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
                    prep,
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
        }
        return Ok(Translated {
            bytes: Cow::Borrowed(hop_bytes),
            pristine: true,
        });
    };
    let mut pristine = true;
    if let Some(prep) = &prep {
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
                prep,
                lane.wire_model,
            )
            .map_err(|e| translate_reject(envelope, e))?;
        t.dropped_controls = translated.dropped_controls;
        match translated.wire {
            EgressWire::Json(written) => body = written,
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
        }
        pristine = false;
    }
    pristine &= !crate::codec::wire_shim::strip_router_shim_keys(&mut body, egress);
    let far_dialect = far.and_then(|d| d.dialect());
    pristine &= !far_dialect
        .as_ref()
        .is_some_and(|dc| dc.rewrite_model_if_needed(&mut body, lane.wire_model));
    if lane.path_base.is_some()
        && far_dialect
            .as_ref()
            .is_some_and(|dc| dc.reshape_for_path_base(&mut body))
    {
        pristine = false;
    }
    if ingress == egress {
        pristine &= !strip_same_protocol_model_shim(&mut body, ingress);
    }
    if ingress == egress && pristine {
        return Ok(Translated {
            bytes: Cow::Borrowed(hop_bytes),
            pristine: true,
        });
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

/// A value a head field can carry as text: visible ASCII and the tab.
fn legal_field_value(v: &[u8]) -> bool {
    v.iter().all(|b| *b == b'\t' || (0x20..0x7f).contains(b))
}

/// The head fields a native client of `lane`'s dialect sends, then, when the caller speaks that
/// dialect, every field the caller sent but the ones busbar governs ([`crate::dialect::governed`]):
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
    let mut fields = vec![
        ("content-type".to_string(), content_type.into_bytes()),
        ("user-agent".to_string(), user_agent.as_bytes().to_vec()),
        (
            "accept".to_string(),
            handler
                .egress_accept(stream_accept, wants_stream)
                .as_bytes()
                .to_vec(),
        ),
    ];
    if arrived.dialect != egress {
        return Ok(fields);
    }
    // The caller's fields, in the order the caller sent them; a repeated name keeps every value.
    let forwarded: Vec<(String, Vec<u8>)> = caller
        .iter()
        .filter_map(|(name, value)| {
            let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            (!crate::dialect::governed(&name)).then(|| (name, value.to_vec()))
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
    let pristine_head = ingress == lane.dialect
        && arrived
            .parsed
            .as_ref()
            .is_some_and(|v| provably_pristine(lane.shape(), v));
    let hop_v = if pristine_head || !body_is_json {
        None
    } else {
        arrived.parsed.clone()
    };
    let reasoning = shaping.reasoning(pool, member).unwrap_or(lane.reasoning);
    let (translated, dropped_controls) = if pristine_head {
        (
            Translated {
                bytes: Cow::Borrowed(arrived.body.as_slice()),
                pristine: true,
            },
            Vec::new(),
        )
    } else {
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
        (t.outcome?, t.dropped_controls)
    };
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
/// asked already.
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
    let injected = if intent.client_has_stream_options {
        try_inject_stream_include_usage(payload)
    } else {
        try_inject_stream_include_usage_pristine(payload)
    };
    injected.map_err(|_unmeterable| {
        answer(
            ingress,
            400,
            KIND_INVALID_REQUEST,
            DETAIL_STREAM_OPTIONS_NOT_OBJECT,
        )
    })
}

/// Ask a streamed request for its usage: `stream_options.include_usage = true`, the object made
/// when absent or null. `Err` carries the payload back verbatim when `stream_options` is not an
/// object (the request cannot be asked, and the caller refuses it rather than bill it blind); a
/// payload that is not a JSON object goes out unchanged.
///
/// # Errors
///
/// The payload, verbatim, when its `stream_options` is not an object.
pub fn try_inject_stream_include_usage(payload: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let mut v: Value = match crate::codec::json::parse(&payload) {
        Ok(v) => v,
        Err(_) => return Ok(payload),
    };
    let Some(obj) = v.as_object_mut() else {
        return Ok(payload);
    };
    let so = obj
        .entry("stream_options".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if so.is_null() {
        *so = Value::Object(serde_json::Map::new());
    }
    let Some(so_obj) = so.as_object_mut() else {
        return Err(payload);
    };
    so_obj.insert("include_usage".to_string(), Value::Bool(true));
    match crate::codec::json::to_vec(&v) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(payload),
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The same ask without a parse when the caller's bytes provably carry no `stream_options`: the
/// member is spliced in after the object's opening brace, so every other byte stays the caller's.
/// Anything else falls back to [`try_inject_stream_include_usage`].
///
/// # Errors
///
/// As [`try_inject_stream_include_usage`].
pub fn try_inject_stream_include_usage_pristine(payload: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    const INSERT: &[u8] = br#""stream_options":{"include_usage":true},"#;
    if contains_subslice(&payload, br#""stream_options""#) {
        return try_inject_stream_include_usage(payload);
    }
    let mut i = 0usize;
    while i < payload.len() && payload[i].is_ascii_whitespace() {
        i += 1;
    }
    let opens_object = payload.get(i) == Some(&b'{');
    let next = {
        let mut j = i + 1;
        while j < payload.len() && payload[j].is_ascii_whitespace() {
            j += 1;
        }
        payload.get(j).copied()
    };
    if !opens_object || next != Some(b'"') {
        return try_inject_stream_include_usage(payload);
    }
    let brace_end = i + 1;
    let mut out = Vec::with_capacity(payload.len() + INSERT.len());
    out.extend_from_slice(&payload[..brace_end]);
    out.extend_from_slice(INSERT);
    out.extend_from_slice(&payload[brace_end..]);
    Ok(out)
}
