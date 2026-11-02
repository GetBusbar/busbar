// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC 2.0 ENVELOPE READER — one reader, for every protocol that speaks JSON-RPC.
//!
//! Pure and stateless: a parsed value in, a verdict out. No I/O, no clock, nothing remembered
//! between two calls. Every caller that reads a JSON-RPC envelope reads it here, so the envelope's
//! rules exist once and a protocol supplies its wire transport, never its own envelope semantics.
//! The HTTP answers built from these verdicts are the host's, not this module's.
//!
//! # What the specification requires, quoted, because the three cases differ
//!
//! **JSON-RPC 2.0 section 4 (Request object), `id`:** *"An identifier established by the Client that MUST
//! contain a String, Number, or NULL value if included. If it is not included it is assumed to be a
//! notification. The value SHOULD normally not be Null [1] …"* — and footnote **[1]**: *"The use of
//! Null as a value for the id member in a Request object is discouraged, because this specification
//! uses a value of Null for the id member in a Response object to indicate an unknown id (e.g.
//! Parse error/Invalid Request). Also, because JSON-RPC 1.0 uses an id value of Null for
//! Notifications this could cause confusion in handling."*
//!
//! **JSON-RPC 2.0 section 4.1 (Notification):** *"A Notification is a Request object without an `id`
//! member. … The Server MUST NOT reply to a Notification, including those that are within a batch
//! request."*
//!
//! **JSON-RPC 2.0 section 5 (Response object), `id`:** *"This member is REQUIRED. It MUST be the same as
//! the value of the id member in the Request Object. If there was an error in detecting the id in
//! the Request object (e.g. Parse error/Invalid Request), it MUST be Null."*
//!
//! # The one judgement call: a `null` request id is refused for every caller
//!
//! Base JSON-RPC says `null` is *discouraged*; some protocols riding the envelope forbid it outright.
//! This reader refuses it for every caller:
//!
//! 1. section 5 spends the value `null` on a *different meaning* — "I could not tell which request this
//!    was". A SUCCESS response carrying `"id": null` is therefore byte-identical to the envelope
//!    reserved for an unattributable failure. A caller cannot correlate it, which is the entire
//!    purpose of the member. Footnote [1] says precisely this is why `null` is discouraged.
//! 2. `SHOULD NOT` binds the SENDER. Nothing obliges a server to accept a discouraged id, and
//!    `-32600 Invalid Request` is exactly the code for an envelope a server will not honour.
//! 3. The alternative is two readers, differing on one member.
//!
//! # The other half: reading a RESPONSE
//!
//! [`read`] reads a request that ARRIVES. [`read_response`] reads a response that comes BACK from a
//! party that was called. Same envelope, same version member, same `id` member, opposite direction
//! of travel. The response is correlated to the request that was sent: a reader that never looks
//! at `id` accepts a mismatched one, a `null` one, or one with no `id` member at all as the answer
//! to whatever it happened to be waiting on, and under adversarial timing that is how caller A is
//! served upstream B's reply.
//!
//! **The correlation is WITHIN ONE CALL and introduces no state.** `sent_id` is passed in by the
//! code that built the outbound request, and is gone when that code returns: nothing is remembered
//! between two calls, so there is nothing to invalidate.

use serde_json::Value;

/// The JSON-RPC 2.0 standard error codes this module can produce.

pub const PARSE_ERROR: i64 = -32700;
/// `-32600`: the body is JSON and is not an envelope this reader will honour.
pub const INVALID_REQUEST: i64 = -32600;

/// What an inbound message IS, once the envelope has been read.
///
/// Two variants, and there is deliberately no third for "a request with a bad id": an envelope that
/// does not name a caller-correlatable request is not a request, so it never becomes one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// A REQUEST. `id` is a JSON string or number — never `null`, never absent, never a bool, array
    /// or object. That is a type-level guarantee: the only constructor is [`read`], and every other
    /// shape leaves through [`Invalid`]. A handler that holds one of these may echo `id` into its
    /// response without checking anything.
    Request {
        /// The request's `id`, a JSON string or number, echoed verbatim on its response.
        id: Value,
        /// The `method` member.
        method: String,
    },
    /// A NOTIFICATION: no `id` member. **The caller MUST acknowledge it with no body.**
    Notification {
        /// The `method` member.
        method: String,
    },
}

/// A refusal at the envelope level, carrying the `id` the response must echo.
///
/// `id` is carried rather than recomputed by the caller because section 5 makes it a two-case rule that is
/// easy to get subtly wrong: echo the request's id when one could be established, `Null` when it
/// could not. Deciding that once, next to the code that established it, is the point.
#[derive(Debug, Clone)]
pub struct Invalid {
    /// The JSON-RPC error code the refusal carries.
    pub code: i64,
    /// The refusal's message, fixed text naming the defect.
    pub message: &'static str,
    /// section 5: *"If there was an error in detecting the id in the Request object … it MUST be Null."*
    pub id: Value,
}

/// Read a parsed JSON body as a JSON-RPC 2.0 envelope.

pub fn read(value: &Value) -> Result<Envelope, Invalid> {
    let Some(obj) = value.as_object() else {
        return Err(Invalid {
            code: INVALID_REQUEST,
            message: "The request body must be a single JSON-RPC message object; batches are not \
                      supported.",
            id: Value::Null,
        });
    };

    let echo = match obj.get("id") {
        Some(id) if is_legible_id(id) => id.clone(),
        _ => Value::Null,
    };

    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(Invalid {
            code: INVALID_REQUEST,
            message: "`jsonrpc` is required and must be exactly \"2.0\".",
            id: echo,
        });
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Err(Invalid {
            code: INVALID_REQUEST,
            message: "`method` is required and must be a string.",
            id: echo,
        });
    };
    let method = method.to_string();

    match obj.get("id") {




        None => Ok(Envelope::Notification { method }),

        Some(Value::Null) => Err(Invalid {
            code: INVALID_REQUEST,
            message: "`id` must not be null. A response echoing a null id is indistinguishable \
                      from the envelope JSON-RPC 2.0 section 5 reserves for a request whose id could not \
                      be established, so no caller could correlate it. Omit `id` entirely to send \
                      a notification.",
            id: Value::Null,
        }),
        Some(id) if is_legible_id(id) => Ok(Envelope::Request {
            id: id.clone(),
            method,
        }),


        Some(_) => Err(Invalid {
            code: INVALID_REQUEST,
            message: "`id` must be a string or a number.",
            id: Value::Null,
        }),
    }
}

/// Whether a value is an id a response can be correlated by: a String or a Number, per section 4, minus

fn is_legible_id(id: &Value) -> bool {
    id.is_string() || id.is_number()
}

/// What a RESPONSE envelope carries, once it has been read AND correlated to the request that was
/// sent. Section 5: *"Either the `result` member or `error` member MUST be included, but both members
/// MUST NOT be included."*
///
/// There is deliberately no `Uncorrelated` variant: a message that does not name the request that was
/// sent is not that request's answer, so it never becomes one of these. Holding one of these IS the
/// proof that correlation succeeded.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// The `result` member, verbatim. Present-but-`null` is a legal result and stays one; it is the
    /// MEMBER's presence that decides, never its truthiness.
    Result(Value),
    /// The `error` member. `code` is carried as the raw `Value` because callers render it
    /// differently on their own wires (one as an `i64`, one as a string) and normalising it here
    /// would change what an operator reads in a log.
    Error {
        /// The error's `code` member, verbatim, when present.
        code: Option<Value>,
        /// The error's `message` member, or empty when absent or not a string.
        message: String,
    },
}

/// WHICH KIND of non-answer a body is. Two, and they are two because an operator acts on them
/// differently: one says the peer is broken, the other says the peer answered a question nobody
/// asked it — which is either a broken multiplexer or an attempt to have one caller served
/// another caller's answer.
///
/// It is an enum rather than something a caller re-derives from the prose, because a caller that
/// had to grep the message for the word "id" would be parsing a sentence to recover a decision this
/// module already made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAnAnswerKind {
    /// The body is not a JSON-RPC 2.0 response at all, or carries both / neither of `result` and
    /// `error`.
    NotAResponse,
    /// The body IS a JSON-RPC response and it does not name the request that was sent: a mismatched
    /// `id`, `"id": null`, or no `id` member.
    Uncorrelated,
}

/// Why a body is not the answer to the request that was sent. Carries prose as well as the kind,
/// because every caller does the same thing with the prose — puts it in front of an operator — and
/// the specific reason is the whole value of the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAnAnswer {
    /// Which kind of non-answer it is.
    pub kind: NotAnAnswerKind,
    /// The specific reason, for the operator.
    pub reason: String,
}

impl std::fmt::Display for NotAnAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Read a parsed JSON body as the JSON-RPC 2.0 RESPONSE to a request whose id was `sent_id`.

pub fn read_response(value: &Value, sent_id: &Value) -> Result<Reply, NotAnAnswer> {
    let refuse = |reason: String| {
        Err(NotAnAnswer {
            kind: NotAnAnswerKind::NotAResponse,
            reason,
        })
    };
    let uncorrelated = |reason: String| {
        Err(NotAnAnswer {
            kind: NotAnAnswerKind::Uncorrelated,
            reason,
        })
    };

    let Some(obj) = value.as_object() else {
        return refuse("the response is not a single JSON-RPC message object".to_string());
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return refuse(
            "the response has no `jsonrpc` member equal to \"2.0\", so it is not a JSON-RPC 2.0 \
             response"
                .to_string(),
        );
    }
    match obj.get("id") {
        None => return uncorrelated(
            "the response carries no `id` member; JSON-RPC 2.0 section 5 makes it REQUIRED, and \
                 a response that names no request cannot be attributed to one"
                .to_string(),
        ),
        Some(Value::Null) => {
            return uncorrelated(
                "the response carries `\"id\": null`, which JSON-RPC 2.0 section 5 reserves for a \
                 request whose id the sender could not establish; it is not an answer to any \
                 request"
                    .to_string(),
            )
        }
        Some(got) if !same_id(got, sent_id) => {
            return uncorrelated(format!(
                "the response is correlated to `id` {got}, but this dispatch sent `id` {sent_id}; \
                 it is the answer to a different request and is refused rather than served"
            ))
        }
        Some(_) => {}
    }

    let error = obj.get("error").filter(|e| !e.is_null());
    let result = obj.get("result");
    match (result, error) {
        (Some(_), Some(_)) => refuse(
            "the response carries BOTH `result` and `error`; JSON-RPC 2.0 section 5 says both MUST \
             NOT be included, and guessing which one the sender meant is how a failure gets served \
             as a success"
                .to_string(),
        ),
        (None, None) => refuse(
            "the response carries neither `result` nor `error`; JSON-RPC 2.0 section 5 requires \
             exactly one"
                .to_string(),
        ),
        (_, Some(err)) => Ok(Reply::Error {
            code: err.get("code").cloned(),
            message: err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        (Some(result), None) => Ok(Reply::Result(result.clone())),
    }
}

/// Whether a response's `id` names the request that was sent.

fn same_id(got: &Value, sent: &Value) -> bool {
    match (got, sent) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            a == b
                || match (a.is_f64(), b.is_f64()) {
                    (false, true) => integer_matches_float(a, b),
                    (true, false) => integer_matches_float(b, a),
                    _ => false,
                }
        }
        _ => false,
    }
}

fn integer_matches_float(integer: &serde_json::Number, float: &serde_json::Number) -> bool {
    let integer = integer
        .as_i64()
        .map(i128::from)
        .or_else(|| integer.as_u64().map(i128::from));
    match (integer, float.as_f64()) {
        (Some(integer), Some(float)) => float.fract() == 0.0 && float as i128 == integer,
        _ => false,
    }
}

/// The JSON-RPC error envelope, as a value.

pub fn error_body(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = serde_json::Map::new();
    error.insert("code".into(), Value::from(code));
    error.insert("message".into(), Value::from(message));
    if let Some(d) = data {
        error.insert("data".into(), d);
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), Value::from("2.0"));
    envelope.insert("id".into(), id);
    envelope.insert("error".into(), Value::Object(error));
    Value::Object(envelope)
}

/// WHETHER `origin` MAY DRIVE THIS DEPLOYMENT.

#[must_use]
pub fn origin_admitted(origin: &str, allowed: &[String]) -> bool {
    is_loopback_origin(origin) || allowed.iter().any(|a| a == origin)
}

fn is_loopback_origin(origin: &str) -> bool {
    let host = match origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    {
        Some(rest) => rest.split('/').next().unwrap_or(""),

        None => return false,
    };
    let host = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
            h
        } else {
            host
        }
    });
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// A unit-less kernel refusal of `Unauthenticated`, as v1.5.5 wrote it on the wire.
const UNITLESS_UNAUTHENTICATED: &[u8] =
    br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"authentication failed"}}"#;
/// A unit-less kernel refusal of `BodyTooLarge`, as v1.5.5 wrote it on the wire.
const UNITLESS_BODY_TOO_LARGE: &[u8] = br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request body exceeds the maximum allowed size"}}"#;

/// THE JSON-RPC RENDERING OF A KERNEL REFUSAL THAT NAMES NO UNIT: the exact bytes v1.5.5 answered

#[must_use]
pub fn unitless_kernel_body(reason: u32) -> Option<&'static [u8]> {
    use crate::abi::plane::RefusalCode;
    if reason == RefusalCode::Unauthenticated.code() {
        Some(UNITLESS_UNAUTHENTICATED)
    } else if reason == RefusalCode::BodyTooLarge.code() {
        Some(UNITLESS_BODY_TOO_LARGE)
    } else {
        None
    }
}

const ID_PREFIX: &[u8] = b"{\"id\":";
const RESULT_MEMBER: &[u8] = b",\"jsonrpc\":\"2.0\",\"result\":";
const ERROR_PREFIX: &[u8] = b"{\"error\":{\"code\":";
const ERROR_DATA_MEMBER: &[u8] = b",\"data\":";
const ERROR_MESSAGE_MEMBER: &[u8] = b",\"message\":";
const ERROR_ID_MEMBER: &[u8] = b"},\"id\":";
const RESPONSE_END: &[u8] = b",\"jsonrpc\":\"2.0\"}";
const CALL_PREFIX: &[u8] = b"\"jsonrpc\":\"2.0\",\"method\":";
const PARAMS_MEMBER: &[u8] = b",\"params\":";
const OBJECT_START: &[u8] = b"{";
const OBJECT_END: &[u8] = b"}";
const MEMBER_SEPARATOR: &[u8] = b",";

/// Count serializer output without retaining any of the serialized payload.
#[derive(Default)]
struct JsonLength(usize);

impl std::io::Write for JsonLength {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Count and emit the same borrowed envelope twice. The first pass retains no payload; the second

fn envelope_bytes(write: impl Fn(&mut dyn std::io::Write) -> std::io::Result<()>) -> Vec<u8> {
    let mut length = JsonLength::default();
    write(&mut length).expect("JSON-RPC envelope length overflow");
    let mut out = zeroize::Zeroizing::new(vec![0; length.0]);
    let mut remaining = out.as_mut_slice();
    write(&mut remaining).expect("counted JSON-RPC envelope fits its output");
    assert!(
        remaining.is_empty(),
        "counted JSON-RPC envelope fills its output"
    );
    std::mem::take(&mut *out)
}

fn push_str(out: &mut dyn std::io::Write, value: &str) -> std::io::Result<()> {
    serde_json::to_writer(out, value).map_err(std::io::Error::other)
}

/// A success response: `{"id":<id>,"jsonrpc":"2.0","result":<result>}`. `id` and `result` are

#[must_use]
pub fn result_bytes(id: &[u8], result: &[u8]) -> Vec<u8> {
    envelope_bytes(|out| {
        out.write_all(ID_PREFIX)?;
        out.write_all(id)?;
        out.write_all(RESULT_MEMBER)?;
        out.write_all(result)?;
        out.write_all(OBJECT_END)
    })
}

/// An error response:

#[must_use]
pub fn error_bytes(id: &[u8], code: i64, message: &str, data: Option<&[u8]>) -> Vec<u8> {
    envelope_bytes(|out| {
        out.write_all(ERROR_PREFIX)?;
        serde_json::to_writer(&mut *out, &code).map_err(std::io::Error::other)?;
        if let Some(data) = data {
            out.write_all(ERROR_DATA_MEMBER)?;
            out.write_all(data)?;
        }
        out.write_all(ERROR_MESSAGE_MEMBER)?;
        push_str(out, message)?;
        out.write_all(ERROR_ID_MEMBER)?;
        out.write_all(id)?;
        out.write_all(RESPONSE_END)
    })
}

/// A request: `{"id":<id>,"jsonrpc":"2.0","method":<method>,"params":<params>}`, with no `params`

#[must_use]
pub fn request_bytes(id: &[u8], method: &str, params: Option<&[u8]>) -> Vec<u8> {
    envelope_bytes(|out| {
        out.write_all(ID_PREFIX)?;
        out.write_all(id)?;
        out.write_all(MEMBER_SEPARATOR)?;
        push_call(out, method, params)
    })
}

/// A notification: `{"jsonrpc":"2.0","method":<method>,"params":<params>}`, with no `params`

#[must_use]
pub fn notification_bytes(method: &str, params: Option<&[u8]>) -> Vec<u8> {
    envelope_bytes(|out| {
        out.write_all(OBJECT_START)?;
        push_call(out, method, params)
    })
}

/// The members a request and a notification share, and the closing brace.
fn push_call(
    out: &mut dyn std::io::Write,
    method: &str,
    params: Option<&[u8]>,
) -> std::io::Result<()> {
    out.write_all(CALL_PREFIX)?;
    push_str(out, method)?;
    if let Some(params) = params {
        out.write_all(PARAMS_MEMBER)?;
        out.write_all(params)?;
    }
    out.write_all(OBJECT_END)
}

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
