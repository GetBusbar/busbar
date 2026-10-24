//! THE INVOKE-MODEL ENVELOPE, sans I/O: an Anthropic Messages exchange carried over Amazon
//! Bedrock's `InvokeModel` / `InvokeModelWithResponseStream` operations (the owner's 2026-09-29
//! compat scope, "Bedrock InvokeModel dialect"; ARCHITECT 2026-10-14, the envelope design).
//!
//! WHAT IT IS. Bedrock serves Anthropic's models over two APIs. Its unified Converse API is the
//! plane's `bedrock` dialect. Its model-native `InvokeModel` API takes the Anthropic Messages body
//! itself, so this is not a dialect of its own: the request body, the answer body, the stream's
//! events and the usage they carry are the Anthropic dialect's, read and written by that dialect,
//! and only the envelope around them is Bedrock's. A model selects it with
//! `models.<m>.protocol: bedrock-invoke` ([`PROTOCOL`]); a provider never defaults to it, because
//! the name is no codec protocol the kernel knows, so the provider sweep refuses it in the previous
//! release's words. The kernel names none of this.
//!
//! THE ENVELOPE, both ways:
//! - the target is `/model/{model}/invoke`, or `/model/{model}/invoke-with-response-stream` for a
//!   streamed answer ([`path`]);
//! - the body loses `model` (it rides the target) and `stream` (the operation says it), and states
//!   `anthropic_version: bedrock-2023-05-31`; the caller's `anthropic-beta` field becomes the body's
//!   `anthropic_beta` list and the `anthropic-version` field is not sent ([`body`], [`fields`]);
//! - a streamed answer arrives as AWS event-stream frames, each `chunk` carrying one Anthropic
//!   stream event base64-encoded in `bytes`; it is re-framed as the Anthropic dialect's own
//!   server-sent events, the event JSON byte for byte ([`Transcoder`]);
//! - a refusal arrives as `{"message": …}` beside an `x-amzn-ErrorType` field (or, mid-stream, an
//!   exception frame); it is re-stated as the Anthropic dialect's error envelope ([`error_body`]).
//!
//! The credential is the provider's: a Bedrock provider's SigV4 style, which the composition root
//! falls back to when the model's own protocol states no default style.

use std::borrow::Cow;

use busbar_contract::protocol::HeadFields;
use serde_json::Value;

use crate::codec::eventstream::{drain_frames_checked, DrainStatus};
use crate::codec::json_splice::{self, Edit};

/// The protocol a model names to be served over the envelope.
pub const PROTOCOL: &str = "bedrock-invoke";

/// The dialect the envelope carries: its bodies, events and usage are that dialect's own.
pub const CARRIED: &str = "anthropic";

/// The API version the envelope's body states.
const VERSION: &str = "bedrock-2023-05-31";
/// The body member that states it.
const VERSION_KEY: &str = "anthropic_version";
/// The body member the caller's beta flags ride in.
const BETA_KEY: &str = "anthropic_beta";
/// The head field the caller's beta flags arrive in.
const BETA_FIELD: &str = "anthropic-beta";
/// The head field the Messages API version arrives in; the envelope states it in the body.
const VERSION_FIELD: &str = "anthropic-version";
/// The content type of a streamed answer on the wire.
pub const EVENTSTREAM: &str = "application/vnd.amazon.eventstream";
/// The frame that carries one stream event.
const CHUNK: &str = "chunk";
/// The head field a refusal names its exception in.
const ERROR_TYPE_FIELD: &str = "x-amzn-errortype";

/// The far end's target for `model`, as written before encoding.
#[must_use]
pub fn path(model: &str, stream: bool) -> String {
    let op = if stream {
        "invoke-with-response-stream"
    } else {
        "invoke"
    };
    format!("/model/{model}/{op}")
}

/// One head field: its name and its value bytes.
pub type HeadField = (String, Vec<u8>);

/// The far request's head fields over the envelope: the Messages API version is not sent (the body
/// states the envelope's), the caller's beta flags are taken out to ride in the body, and a streamed
/// answer is asked for in the event-stream framing. Returns the fields and the beta flags.
#[must_use]
pub fn fields(fields: Vec<HeadField>, stream: bool) -> (Vec<HeadField>, Vec<Vec<u8>>) {
    let (beta, rest): (Vec<_>, Vec<_>) = fields
        .into_iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case(VERSION_FIELD))
        .partition(|(name, _)| name.eq_ignore_ascii_case(BETA_FIELD));
    let out = rest
        .into_iter()
        .map(|(name, value)| {
            if stream && name.eq_ignore_ascii_case("accept") {
                (name, EVENTSTREAM.as_bytes().to_vec())
            } else {
                (name, value)
            }
        })
        .collect();
    (out, beta.into_iter().map(|(_, v)| v).collect())
}

/// The far request's body over the envelope, a byte-level edit of the Messages body (never a
/// re-serialization): `model` and `stream` removed, `anthropic_version` stated, and the caller's
/// beta flags (each field's comma-separated list, in order) as `anthropic_beta`. `None` when the body
/// is not a JSON object.
#[must_use]
pub fn body(messages: &[u8], beta: &[Vec<u8>]) -> Option<Vec<u8>> {
    let flags: Vec<Value> = beta
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|f| f.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|f| !f.is_empty())
        .map(Value::String)
        .collect();
    let version = serde_json::to_vec(VERSION).ok()?;
    let mut edits = vec![
        Edit::Remove("model"),
        Edit::Remove("stream"),
        Edit::Set(VERSION_KEY, Cow::Owned(version)),
    ];
    if !flags.is_empty() {
        edits.push(Edit::Set(
            BETA_KEY,
            Cow::Owned(serde_json::to_vec(&Value::Array(flags)).ok()?),
        ));
    }
    json_splice::apply_top(messages, &edits)
}

/// The Anthropic dialect's error kind for a Bedrock exception name (`ValidationException`, or the
/// event-stream form `validationException`, with or without a `:…` suffix).
fn kind_of(exception: &str) -> &'static str {
    let name = exception.split(':').next().unwrap_or("").trim();
    match name.to_ascii_lowercase().as_str() {
        "validationexception" => "invalid_request_error",
        "accessdeniedexception" | "unrecognizedclientexception" => "permission_error",
        "resourcenotfoundexception" => "not_found_error",
        "throttlingexception" | "servicequotaexceededexception" => "rate_limit_error",
        "serviceunavailableexception" | "modelnotreadyexception" => "overloaded_error",
        "modeltimeoutexception" => "timeout_error",
        _ => "api_error",
    }
}

/// The Anthropic dialect's error envelope for a refusal's `kind` and `message`.
fn envelope(kind: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": "error",
        "error": { "type": kind, "message": message },
    }))
    .unwrap_or_default()
}

/// A refused answer's body, re-stated in the Anthropic dialect's error envelope from Bedrock's
/// `{"message": …}` and its `x-amzn-ErrorType` field. A body already in that envelope is kept.
#[must_use]
pub fn error_body(head: HeadFields<'_>, body: &[u8]) -> Vec<u8> {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    if parsed
        .as_ref()
        .and_then(|v| v.get("type"))
        .and_then(Value::as_str)
        == Some("error")
    {
        return body.to_vec();
    }
    let exception = head
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(ERROR_TYPE_FIELD.as_bytes()))
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    let message = parsed
        .as_ref()
        .and_then(|v| v.get("message").or_else(|| v.get("Message")))
        .and_then(Value::as_str)
        .map_or_else(
            || String::from_utf8_lossy(body).into_owned(),
            str::to_string,
        );
    envelope(kind_of(&exception), &message)
}

/// ONE STREAMED ANSWER'S RE-FRAMING: AWS event-stream frames in, the Anthropic dialect's own
/// server-sent events out. Each `chunk` frame's base64 `bytes` decode to one Anthropic stream event,
/// written as `event: <its type>` and `data: <its bytes>`; an exception frame becomes the dialect's
/// `error` event; a malformed frame ends the stream with one. Bytes of a frame not yet whole wait.
#[derive(Debug, Default)]
pub struct Transcoder {
    pending: Vec<u8>,
    ended: bool,
}

impl Transcoder {
    /// A fresh re-framing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The server-sent events the frames completed by `bytes` re-frame to.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.ended {
            return out;
        }
        self.pending.extend_from_slice(bytes);
        let (frames, status, _) = drain_frames_checked(&mut self.pending, None);
        for (event_type, payload) in frames {
            if event_type == CHUNK {
                let Some(event) = chunk_event(&payload) else {
                    sse(
                        &mut out,
                        "error",
                        &envelope("api_error", "malformed InvokeModel stream chunk"),
                    );
                    self.ended = true;
                    return out;
                };
                let kind = serde_json::from_slice::<Value>(&event)
                    .ok()
                    .and_then(|v| v.get("type").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_default();
                sse(&mut out, &kind, &event);
            } else if !event_type.is_empty() {
                let message = serde_json::from_slice::<Value>(&payload)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or_else(|| v.get("Message"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| String::from_utf8_lossy(&payload).into_owned());
                sse(&mut out, "error", &envelope(kind_of(&event_type), &message));
                self.ended = true;
                return out;
            }
        }
        if status == DrainStatus::MalformedPrelude {
            sse(
                &mut out,
                "error",
                &envelope("api_error", "malformed InvokeModel stream frame"),
            );
            self.ended = true;
        }
        out
    }
}

/// One `chunk` frame's event: its `bytes` member, base64-decoded. An event that spans lines is
/// written on one, since a server-sent event's data is one line here.
fn chunk_event(payload: &[u8]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let encoded = v.get("bytes")?.as_str()?;
    let event = busbar_contract::media::base64_decode(encoded)?.to_vec();
    if event.contains(&b'\n') {
        let parsed: Value = serde_json::from_slice(&event).ok()?;
        return serde_json::to_vec(&parsed).ok();
    }
    Some(event)
}

/// One server-sent event, the data written as it came.
fn sse(out: &mut Vec<u8>, event: &str, data: &[u8]) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(event.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
}
