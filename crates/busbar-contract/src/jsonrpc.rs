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
///
/// Defined HERE and re-exported by every reader of the envelope rather than re-declared, so `-32600`
/// cannot come to mean two things in one binary. A protocol's own extension codes stay with the
/// protocol that defines them: they are not JSON-RPC's.
///
/// `-32700`: the body is not JSON at all.
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
///
/// ## The ORDER of these checks is load-bearing
///
/// `jsonrpc` and `method` are validated BEFORE `id` is looked at. That is not stylistic: a message
/// that fails either of them is not a JSON-RPC message at all, so "is this a notification?" is not
/// yet a question with an answer, and section 5's *"error in detecting the id"* clause is exactly the case
/// it describes — answer, with `id` echoed if one was legible and `Null` if not.
///
/// Only once the message IS a JSON-RPC message does the absence of `id` mean *notification*, at
/// which point section 4.1's MUST NOT applies with no exception for "but the rest of it was wrong".
pub fn read(value: &Value) -> Result<Envelope, Invalid> {
    // A top-level array is a BATCH. No protocol this reader serves carries batches, and refusing
    // explicitly beats reading `method` off an array as absent — which would answer the wrong
    // question with the wrong message.
    let Some(obj) = value.as_object() else {
        return Err(Invalid {
            code: INVALID_REQUEST,
            message: "The request body must be a single JSON-RPC message object; batches are not \
                      supported.",
            id: Value::Null,
        });
    };

    // The id AS THE RESPONSE SHOULD ECHO IT, computed once. A legible id is echoed on the refusals
    // below; anything else collapses to Null, per section 5.
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
        // section 4.1. NO id member — and note this is `get`, not a truthiness test: the difference
        // between "the member is absent" and "the member is present and null" is the difference
        // between the two arms below, and it is the distinction implementations most often lose,
        // often to a single `.unwrap_or(Value::Null)`.
        None => Ok(Envelope::Notification { method }),
        // A null id is refused for every caller. See the module header for why.
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
        // A bool, array or object id. section 4 permits only a String, a Number or NULL, so this is not a
        // discouraged id — it is not an id.
        Some(_) => Err(Invalid {
            code: INVALID_REQUEST,
            message: "`id` must be a string or a number.",
            id: Value::Null,
        }),
    }
}

/// Whether a value is an id a response can be correlated by: a String or a Number, per section 4, minus
/// the NULL that section 5 has already spent on another meaning.
fn is_legible_id(id: &Value) -> bool {
    id.is_string() || id.is_number()
}

// ══ THE RESPONSE HALF ════════════════════════════════════════════════════════════════════════════

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
///
/// ## The ORDER is load-bearing here too, and for a sharper reason than on the request side
///
/// `jsonrpc` and `id` are checked BEFORE `result` or `error` is looked at, so that the payload of a
/// message that does not belong to this dispatch is never read at all. A reader that pulled
/// `result` out first and correlated afterwards would already have handed the value to a `match`
/// arm, and every such arm is a place the payload can escape.
///
/// ## What each refusal is
///
/// - **not an object / `jsonrpc` not `"2.0"`** — not a JSON-RPC message, so section 5 does not
///   describe it and nothing in it can be trusted to mean what it looks like.
/// - **no `id` member** — section 5 makes it REQUIRED on a Response. A response with no `id` is
///   uncorrelatable by construction; it is also the exact shape a NOTIFICATION has, and a
///   notification is a thing nobody may send in answer to a request.
/// - **`"id": null`** — section 5 spends `null` on "I could not tell which request this was". It is
///   a legible statement, and what it states is that this is not an answer to any request. Accepting
///   it as one is accepting the sender's own admission that it does not know.
/// - **a mismatched `id`** — the answer to a DIFFERENT request. This is the arm that matters: it is
///   the difference between serving a caller their own answer and serving them somebody else's.
/// - **both / neither of `result` and `error`** — section 5 forbids both and requires one.
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

    // `"error": null` is treated as ABSENT rather than as an error, because peers do emit it
    // alongside a `result`. That is why the both-present check below is written against the same
    // non-null filter: otherwise every such peer would trip it.
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
///
/// A String matches a String and a Number matches a Number; nothing else matches anything, so a
/// bool, array or object `id` can never correlate. The one deliberate looseness is INSIDE the
/// number case: JSON has a single number type, so `1` and `1.0` are the same value, and
/// `serde_json`'s own `Number` equality — which compares the parsed REPRESENTATION — would refuse a
/// peer that echoed `1` as `1.0`. Refusing a correct answer is as much a correlation failure as
/// accepting a wrong one, so the comparison is on the numeric value. It is still exact: no
/// cross-type coercion, and `"1"` never matches `1`.
fn same_id(got: &Value, sent: &Value) -> bool {
    match (got, sent) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            a == b
                || match (a.as_f64(), b.as_f64()) {
                    (Some(x), Some(y)) => x == y,
                    _ => false,
                }
        }
        _ => false,
    }
}

/// The JSON-RPC error envelope, as a value.
///
/// ONE builder for every caller and every code, because the pairing of `id` with `error` is the
/// contract and a second builder is a second place for them to disagree. `id` is a `Value` and not
/// an `Option`, deliberately: section 5 makes the member REQUIRED on a Response, so there is no shape this
/// function could be asked for in which omitting it is right.
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

#[cfg(test)]
#[path = "tests/jsonrpc_tests.rs"]
mod jsonrpc_tests;
