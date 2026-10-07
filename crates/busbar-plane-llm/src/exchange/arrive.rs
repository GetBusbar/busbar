//! `arrive`, sans I/O: which dialect an arrival speaks, which operation it asks for, which model it
//! names, and the bytes a unit forwards; or the refusal the previous release answered instead.
//!
//! This is the reading the previous release did in four places, in its order, and nothing else:
//! the router's detection fold and its one operation check (`protocol_dispatch`), the two
//! convenience surfaces that name a model in the path (`/{name}/v1/messages` and
//! `/{provider}/{model}/v1/messages`), the path-model dialects' own URL parses, and the body-model
//! arrival and decode steps. Every refusal carries the envelope dialect, the kind, the status and the
//! message the previous release rendered; the plane renders it through the dialect's own error
//! writer when the kernel asks (`refusal`, keyed by the unit).
//!
//! The caller's credential is not read here: the kernel's authenticate step owns it.

use std::borrow::Cow;

use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::{HeadFields, KIND_INVALID_REQUEST, KIND_NOT_FOUND};
use serde_json::Value;

use crate::codec::gemini::STREAM_QUERY;
use crate::codec::proto_codec::{PROTO_BEDROCK, PROTO_GEMINI};
use crate::codec::DECLS;

/// Why an arrival was refused: the plane's own code, handed to the kernel on a refused `arrive` and
/// echoed back to `refusal`. Never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Decline {
    /// No dialect claims the path.
    NoResource = 1,
    /// The dialect resolves the operation but serves no handler for it.
    UnsupportedOperation = 2,
    /// The body is not JSON.
    BodyParse = 3,
    /// A path-model body is JSON but not an object.
    NotAnObject = 4,
    /// A path-model body could not be written back after the model was spliced in.
    Reserialize = 5,
    /// No model could be read.
    MissingModel = 6,
    /// A path-model dialect's URL names no model and action, or an action it does not serve.
    PathNotFound = 7,
    /// An InvokeModel body names no supported operation.
    InvokeBody = 8,
    /// The ad-hoc surface names a model another provider serves.
    ProviderMismatch = 9,
    /// A dialect path hit with a method other than POST.
    MethodNotAllowed = 10,
}

impl Decline {
    /// The code on the plane ABI.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

impl Declined {
    /// A dialect READ the request it refuses, so the refusal is counted among the requests its
    /// dialect refused, whatever its status: a path-model dialect's URL that names no model and
    /// action, or an action that dialect does not serve (v1.5.5 `crates/busbar/src/ingress/mod.rs`
    /// `:843`, `:864`, `:913`, `:931`, each through `finish_rejected`). A path no dialect claims, a
    /// verb a dialect path does not take and an operation with no handler never reached a dialect's
    /// own reading, and are counted only as their status says.
    #[must_use]
    pub const fn counted(&self) -> bool {
        matches!(self.why, Decline::PathNotFound)
    }
}

/// A refused arrival: what the previous release answered, in the dialect envelope it answered in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declined {
    /// Why.
    pub why: Decline,
    /// The status, 400 to 499.
    pub status: u16,
    /// The dialect whose error writer renders it; empty for the agnostic envelope.
    pub envelope: &'static str,
    /// The error kind token.
    pub kind: &'static str,
    /// The message.
    pub message: Cow<'static, str>,
}

/// Where the model came from, when the URL names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathModel {
    /// The caller asked for a stream.
    pub stream: bool,
    /// The stream is a JSON array rather than an event stream (gemini asked without the query's event-stream switch).
    pub json_array: bool,
    /// The dialect's own model-not-found sentence, when it has one.
    pub model_not_found_message: Option<String>,
}

/// An arrival the plane will serve.
#[derive(Clone, Debug)]
pub struct Arrived {
    /// The dialect it speaks.
    pub dialect: &'static str,
    /// The operation it asks for.
    pub operation: OpVerb,
    /// The model it names.
    pub model: String,
    /// Its `Content-Type`, or empty.
    pub content_type: String,
    /// The bytes a unit forwards: the caller's, or (for a path-model body) the caller's object with
    /// the model and the stream flag spliced in as byte-level members ([`splice_path_facts`]).
    pub body: Vec<u8>,
    /// The body as JSON, when it is JSON.
    pub parsed: Option<Value>,
    /// The request path.
    pub path: String,
    /// The query, without its `?`.
    pub query: Option<String>,
    /// Set when the URL names the model.
    pub path_model: Option<PathModel>,
}

/// What the plane knows of the configured catalogue, for the one surface that checks it at the door.
pub trait Catalogue {
    /// The provider serving `model`, when a configured model of that name exists.
    fn provider_of(&self, model: &str) -> Option<&str>;
}

/// No catalogue: every ad-hoc route is taken as asked.
impl Catalogue for () {
    fn provider_of(&self, _model: &str) -> Option<&str> {
        None
    }
}

use crate::exchange::decl_for as decl;

/// THE DETECTION FOLD: every dialect's claim on `(fields, path)`, the tightest winning, a tie going
/// to the earlier declaration.
#[must_use]
pub fn detect(path: &str, fields: HeadFields<'_>) -> Option<&'static str> {
    DECLS
        .iter()
        .filter_map(|d| d.claim_over(path, fields).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// The dialect a path names from its shape alone.
#[must_use]
pub fn residual(path: &str) -> Option<&'static str> {
    DECLS
        .iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// The envelope a refusal on `path` is rendered in: the dialect the path's shape names, else the
/// residual default, else the agnostic envelope (empty).
#[must_use]
pub fn envelope_for(path: &str) -> &'static str {
    residual(path)
        .or_else(|| DECLS.iter().find(|d| d.residual_default).map(|d| d.name))
        .unwrap_or("")
}

/// `%XX` decoding of a path segment; a malformed escape (or invalid UTF-8) is left as it was.
#[must_use]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn declined(
    why: Decline,
    status: u16,
    envelope: &'static str,
    kind: &'static str,
    message: impl Into<Cow<'static, str>>,
) -> Declined {
    Declined {
        why,
        status,
        envelope,
        kind,
        message: message.into(),
    }
}

/// The router's own not-found for a path no dialect serves.
fn no_resource(path: &str) -> Declined {
    declined(
        Decline::NoResource,
        404,
        envelope_for(path),
        KIND_NOT_FOUND,
        "the requested resource was not found",
    )
}

const ENDPOINT_UNSUPPORTED: &str = "This endpoint does not support that operation.";

/// The router's own 405 for a dialect path hit with another method.
fn method_not_allowed(path: &str) -> Declined {
    declined(
        Decline::MethodNotAllowed,
        405,
        envelope_for(path),
        busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

/// A field value as its header's text: visible ASCII (and tabs) only, else nothing.
fn field_text(value: &[u8]) -> Option<&str> {
    value
        .iter()
        .all(|b| *b == b'\t' || (0x20..0x7f).contains(b))
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

/// The first `content-type` field's text, or empty.
fn content_type(fields: HeadFields<'_>) -> String {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"content-type"))
        .and_then(|(_, v)| field_text(v))
        .unwrap_or("")
        .to_string()
}

/// The two convenience surfaces: `/{name}/v1/messages` (a pool or model named in the path) and
/// `/{provider}/{model}/v1/messages` (an ad-hoc route). Both speak the residual dialect of
/// `/v1/messages`.
enum Convenience {
    Named(String),
    Adhoc(String, String),
}

fn convenience(path: &str) -> Option<Convenience> {
    let rest = path.strip_prefix('/')?.strip_suffix("/v1/messages")?;
    let segs: Vec<&str> = rest.split('/').collect();
    match segs.as_slice() {
        [name] if !name.is_empty() => Some(Convenience::Named(percent_decode(name))),
        [provider, model] if !provider.is_empty() && !model.is_empty() => Some(Convenience::Adhoc(
            percent_decode(provider),
            percent_decode(model),
        )),
        _ => None,
    }
}

/// Where an arrival was addressed: its path and its query (without the `?`).
#[derive(Clone, Copy)]
struct Target<'a> {
    path: &'a str,
    query: Option<&'a str>,
}

/// `/{name}/v1/messages`: a pool or a model named in the path, read in the residual dialect of
/// `/v1/messages`, under the span the previous release opened for this route, with the name it
/// carried (v1.5.5 `crates/busbar/src/ingress/mod.rs:1161`).
#[tracing::instrument(level = "debug", name = "named", skip_all, fields(pool = %name))]
fn named(
    at: Target<'_>,
    fields: HeadFields<'_>,
    body: &[u8],
    name: String,
) -> Result<Arrived, Declined> {
    let proto = residual("/v1/messages").unwrap_or("");
    body_arrival(proto, at.path, at.query, fields, body, Some(name))
}

/// `/{provider}/{model}/v1/messages`: an ad-hoc route, read in the residual dialect of
/// `/v1/messages`, under the span the previous release opened for this route, with the provider and
/// the model it carried (v1.5.5 `crates/busbar/src/ingress/mod.rs:1292`). A model the catalogue
/// says another provider serves is refused.
#[tracing::instrument(
    level = "debug",
    name = "adhoc",
    skip_all,
    fields(provider = %provider, model = %model)
)]
fn adhoc(
    at: Target<'_>,
    fields: HeadFields<'_>,
    body: &[u8],
    catalogue: &dyn Catalogue,
    provider: &str,
    model: String,
) -> Result<Arrived, Declined> {
    let proto = residual("/v1/messages").unwrap_or("");
    if let Some(serving) = catalogue.provider_of(&model) {
        if serving != provider {
            return Err(declined(
                Decline::ProviderMismatch,
                400,
                proto,
                KIND_INVALID_REQUEST,
                super::refuse::model_not_found(&model, None),
            ));
        }
    }
    body_arrival(proto, at.path, at.query, fields, body, Some(model))
}

/// READ ONE ARRIVAL. `method` is the request method, `target` the request target (path and query),
/// `fields` its head fields, `body` the whole body. Every dialect path takes POST only.
///
/// # Errors
///
/// The refusal the previous release answered, with its envelope, kind, status and message.
pub fn arrive(
    method: &str,
    target: &str,
    fields: HeadFields<'_>,
    body: &[u8],
    catalogue: &dyn Catalogue,
) -> Result<Arrived, Declined> {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    // The convenience surfaces are the router's own routes: they take precedence over the fold.
    if let Some(c) = convenience(path) {
        if method != "POST" {
            return Err(method_not_allowed(path));
        }
        let at = Target { path, query };
        return match c {
            Convenience::Named(name) => named(at, fields, body, name),
            Convenience::Adhoc(provider, model) => {
                adhoc(at, fields, body, catalogue, &provider, model)
            }
        };
    }
    let Some(proto) = detect(path, fields) else {
        return Err(no_resource(path));
    };
    if method != "POST" {
        return Err(method_not_allowed(path));
    }
    let d = decl(proto).ok_or_else(|| no_resource(path))?;
    if let Some(rh) = d.handler {
        if let Some(op) = rh.resolve_operation(path, body) {
            if rh.operation_handler(op).is_none() {
                return Err(declined(
                    Decline::UnsupportedOperation,
                    404,
                    proto,
                    KIND_NOT_FOUND,
                    ENDPOINT_UNSUPPORTED,
                ));
            }
        }
    }
    match proto {
        PROTO_GEMINI => gemini_arrival(path, query, fields, body),
        PROTO_BEDROCK => bedrock_arrival(path, query, fields, body),
        _ => body_arrival(proto, path, query, fields, body, None),
    }
}

/// A body-model arrival: the operation off the path and body, then the arrival step (the body
/// read), then the decode step (the handler, then the model ladder).
fn body_arrival(
    proto: &'static str,
    path: &str,
    query: Option<&str>,
    fields: HeadFields<'_>,
    body: &[u8],
    model_hint: Option<String>,
) -> Result<Arrived, Declined> {
    let rh = decl(proto).and_then(|d| d.handler);
    let Some(operation) = rh.and_then(|rh| rh.resolve_operation(path, body)) else {
        return Err(no_resource(path));
    };
    // The handler is read before the bytes: a pair with no handler is answered with the endpoint's
    // own refusal, never with a parse error the endpoint would not have reached.
    let handled = match rh {
        None => Err(declined(
            Decline::UnsupportedOperation,
            404,
            proto,
            KIND_NOT_FOUND,
            "This protocol does not support that operation.",
        )),
        Some(rh) => rh.operation_handler(operation).map(|_| ()).ok_or_else(|| {
            declined(
                Decline::UnsupportedOperation,
                404,
                proto,
                KIND_NOT_FOUND,
                ENDPOINT_UNSUPPORTED,
            )
        }),
    };
    let ct = content_type(fields);
    let parsed = if handled.is_ok() && (ct.starts_with("application/json") || ct.is_empty()) {
        match crate::codec::json::parse::<Value>(body) {
            Ok(v) => Some(v),
            Err(_) => {
                return Err(declined(
                    Decline::BodyParse,
                    400,
                    proto,
                    KIND_INVALID_REQUEST,
                    "We could not parse the JSON body of your request.",
                ))
            }
        }
    } else {
        None
    };
    handled?;
    let model = match model_hint {
        Some(m) => Some(m),
        None if ct.starts_with("multipart/") => super::multipart::multipart_model(&ct, body),
        None => parsed
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    let model = match model {
        Some(m) if !m.is_empty() => m,
        _ => {
            return Err(declined(
                Decline::MissingModel,
                400,
                proto,
                KIND_INVALID_REQUEST,
                "Missing required parameter: 'model'.",
            ))
        }
    };
    Ok(Arrived {
        dialect: proto,
        operation,
        model,
        content_type: ct,
        body: body.to_vec(),
        parsed,
        path: path.to_string(),
        query: query.map(str::to_string),
        path_model: None,
    })
}

fn query_asks_events(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair.split_once('=') == Some(STREAM_QUERY))
}

fn gemini_api_version(path: &str) -> &'static str {
    if path.starts_with("/v1beta/") {
        "v1beta"
    } else if path.starts_with("/v1/") {
        "v1"
    } else {
        "v1beta"
    }
}

/// The not-found a path-model dialect answers for its own URL space: its native sentence when it has
/// one, else the router's.
fn path_not_found(path: &str, native: impl FnOnce() -> String) -> Declined {
    let envelope = envelope_for(path);
    if decl(envelope).is_some_and(|d| d.has_native_path_not_found) {
        declined(
            Decline::PathNotFound,
            404,
            envelope,
            KIND_NOT_FOUND,
            native(),
        )
    } else {
        declined(
            Decline::PathNotFound,
            404,
            envelope,
            KIND_NOT_FOUND,
            "the requested resource was not found",
        )
    }
}

/// GEMINI: `…/models/{model}:{action}`, under the span the previous release opened for this
/// dialect's arrivals (v1.5.5 `crates/busbar/src/ingress/mod.rs:788`).
#[tracing::instrument(level = "debug", name = "gemini_ingress", skip_all)]
fn gemini_arrival(
    path: &str,
    query: Option<&str>,
    fields: HeadFields<'_>,
    body: &[u8],
) -> Result<Arrived, Declined> {
    let rest = percent_decode(path.split("/models/").nth(1).unwrap_or(""));
    let api_version = gemini_api_version(path);
    let (model, action) = match rest.rsplit_once(':') {
        Some((m, a)) if !m.is_empty() && !a.is_empty() => (m.to_string(), a.to_string()),
        _ => {
            return Err(path_not_found(path, || {
                format!("Invalid resource path: models/{rest} is not found for API version {api_version}.")
            }))
        }
    };
    let operation = decl(PROTO_GEMINI)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.resolve_operation(path, body));
    let Some(operation) = operation else {
        return Err(path_not_found(path, || {
            format!(
                "models/{model} is not found for API version {api_version}, \
                 or is not supported for {action}."
            )
        }));
    };
    let stream = action == "streamGenerateContent";
    let json_array = stream && !query.is_some_and(query_asks_events);
    let facts = PathModel {
        stream,
        json_array,
        model_not_found_message: Some(format!(
            "models/{model} is not found for API version {api_version}, \
             or is not supported for the task you are trying to perform."
        )),
    };
    path_model_arrival(
        PROTO_GEMINI,
        path,
        query,
        fields,
        body,
        model,
        operation,
        facts,
    )
}

/// BEDROCK: `/model/{id}/converse`, `/converse-stream` and `/invoke`.
fn bedrock_arrival(
    path: &str,
    query: Option<&str>,
    fields: HeadFields<'_>,
    body: &[u8],
) -> Result<Arrived, Declined> {
    let rh = decl(PROTO_BEDROCK).and_then(|d| d.handler);
    let model_id = rh
        .and_then(|rh| rh.path_model(path))
        .map(|m| percent_decode(&m))
        .unwrap_or_default();
    let at = Target { path, query };
    if path.ends_with("/converse") {
        return bedrock_converse(at, fields, body, model_id);
    }
    if path.ends_with("/converse-stream") {
        return bedrock_converse_stream(at, fields, body, model_id);
    }
    if path.ends_with("/invoke") {
        let Some(_operation) = rh.and_then(|rh| rh.resolve_operation(path, body)) else {
            return Err(declined(
                Decline::InvokeBody,
                400,
                PROTO_BEDROCK,
                KIND_INVALID_REQUEST,
                "InvokeModel body is not a supported operation (expected inputText or textToImageParams).",
            ));
        };
        return body_arrival(PROTO_BEDROCK, path, query, fields, body, Some(model_id));
    }
    Err(no_resource(path))
}

/// BEDROCK `/model/{id}/converse`, under the span the previous release opened for it (v1.5.5
/// `crates/busbar/src/ingress/mod.rs:1043`).
#[tracing::instrument(level = "debug", name = "bedrock_converse", skip_all)]
fn bedrock_converse(
    at: Target<'_>,
    fields: HeadFields<'_>,
    body: &[u8],
    model_id: String,
) -> Result<Arrived, Declined> {
    converse_arrival(at, fields, body, model_id, false)
}

/// BEDROCK `/model/{id}/converse-stream`, under the span the previous release opened for it
/// (v1.5.5 `crates/busbar/src/ingress/mod.rs:1070`).
#[tracing::instrument(level = "debug", name = "bedrock_converse_stream", skip_all)]
fn bedrock_converse_stream(
    at: Target<'_>,
    fields: HeadFields<'_>,
    body: &[u8],
    model_id: String,
) -> Result<Arrived, Declined> {
    converse_arrival(at, fields, body, model_id, true)
}

/// A converse arrival (`stream` = the `-stream` endpoint): the operation the endpoint names, as a
/// path-model arrival.
fn converse_arrival(
    at: Target<'_>,
    fields: HeadFields<'_>,
    body: &[u8],
    model_id: String,
    stream: bool,
) -> Result<Arrived, Declined> {
    let suffix = if stream {
        "converse-stream"
    } else {
        "converse"
    };
    let op = decl(PROTO_BEDROCK)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.resolve_operation(&format!("/model/{model_id}/{suffix}"), body));
    let Some(op) = op else {
        return Err(declined(
            Decline::UnsupportedOperation,
            404,
            PROTO_BEDROCK,
            KIND_NOT_FOUND,
            ENDPOINT_UNSUPPORTED,
        ));
    };
    path_model_arrival(
        PROTO_BEDROCK,
        at.path,
        at.query,
        fields,
        body,
        model_id,
        op,
        PathModel {
            stream,
            json_array: false,
            model_not_found_message: None,
        },
    )
}

/// THE PATH-MODEL CARRY: the URL's facts (the `model`, the `stream` flag and, when asked, the
/// array-stream shim key) spliced into the caller's object as byte-level member edits. Every byte of
/// the caller's own stays where it was, so the relay's governed removals of the same members give
/// the far end the caller's bytes back (DIALECT FIDELITY). `None` when the body is not an object.
#[must_use]
pub fn splice_path_facts(
    body: &[u8],
    model: &str,
    stream: bool,
    shim_key: Option<&str>,
) -> Option<Vec<u8>> {
    use crate::codec::json_splice::{self, Edit};
    use std::borrow::Cow;
    let obj = json_splice::object_at(body, 0)?;
    let model = serde_json::to_vec(model).ok()?;
    let flag: &[u8] = if stream { b"true" } else { b"false" };
    let mut edits = vec![
        Edit::Set("model", Cow::Owned(model)),
        Edit::Set("stream", Cow::Borrowed(flag)),
    ];
    if let Some(key) = shim_key {
        edits.push(Edit::Set(key, Cow::Borrowed(b"true")));
    }
    Some(json_splice::apply(body, &obj, &edits).unwrap_or_else(|| body.to_vec()))
}

/// A path-model arrival's arrival step (the model and the stream flag spliced into the caller's
/// object) and decode step (the handler, in the path surface's one sentence).
#[allow(clippy::too_many_arguments)]
fn path_model_arrival(
    proto: &'static str,
    path: &str,
    query: Option<&str>,
    fields: HeadFields<'_>,
    body: &[u8],
    model: String,
    operation: OpVerb,
    facts: PathModel,
) -> Result<Arrived, Declined> {
    let refuse =
        |why, message: &'static str| Err(declined(why, 400, proto, KIND_INVALID_REQUEST, message));
    let mut v: Value = match crate::codec::json::parse(body) {
        Ok(v) => v,
        Err(_) => {
            return refuse(
                Decline::BodyParse,
                "We could not parse the JSON body of your request.",
            )
        }
    };
    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.clone()));
            obj.insert("stream".to_string(), Value::Bool(facts.stream));
            if facts.json_array {
                if let Some(key) = decl(proto).and_then(|d| d.array_stream_shim_key) {
                    obj.insert(key.to_string(), Value::Bool(true));
                }
            }
        }
        None => return refuse(Decline::NotAnObject, "Request body must be a JSON object."),
    }
    let shim = facts
        .json_array
        .then(|| decl(proto).and_then(|d| d.array_stream_shim_key))
        .flatten();
    let Some(spliced) = splice_path_facts(body, &model, facts.stream, shim) else {
        return refuse(
            Decline::Reserialize,
            "The request body could not be processed.",
        );
    };
    let handled = decl(proto)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(operation));
    if handled.is_none() {
        return Err(declined(
            Decline::UnsupportedOperation,
            404,
            proto,
            KIND_NOT_FOUND,
            ENDPOINT_UNSUPPORTED,
        ));
    }
    Ok(Arrived {
        dialect: proto,
        operation,
        model,
        content_type: content_type(fields),
        body: spliced,
        parsed: Some(v),
        path: path.to_string(),
        query: query.map(str::to_string),
        path_model: Some(facts),
    })
}
