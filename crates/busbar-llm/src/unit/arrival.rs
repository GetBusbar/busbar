// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEP 0 — ARRIVAL, as the LLM plane sees it.
//!
//! By the time the plane is asked anything, the kernel's own arrival gate has already run: size,
//! rate, source, the cursor and credential budgets, the in-flight table. Those are the kernel's
//! questions and they are answered without any plane being known yet, which is why a refusal there
//! is rendered through the transport's generic envelope rather than through a dialect's. What is
//! left for the plane at step 0 is the one thing the kernel cannot do for it: read the bytes far
//! enough to say whether they are the shape this plane speaks at all.
//!
//! Concretely, this step is the reading the live path does before the model is known:
//!
//! * the content-type read, and
//! * either the body-model parse (`LazyBody::parse`, which validates the bytes as JSON and captures
//!   the head projection WITHOUT building a DOM), or
//! * the path-model parse-and-inject, for the two dialects that keep the model in the URL: parse the
//!   body as a document, splice `model` and `stream` (and the array-stream shim, when asked) into
//!   it, and re-serialize.
//!
//! Every one of those is TODAY's function, called. `LazyBody::parse`, `busbar_substrate::json::parse`,
//! `busbar_substrate::json::to_vec` and `busbar_substrate::proto::array_stream_shim_key_for` are the
//! same items the live arms in `native_ingress.rs` call, so the reject set, the depth guard and the
//! serializer are the same ones — not an equivalent set, the same one. Nothing here parses a second
//! time and nothing here has an opinion of its own.
//!
//! ## What this step does NOT do
//!
//! It does not resolve a handler and it does not extract a model. Both of those are step 1, and both
//! live in `decode.rs`. The split is the loop's, not a preference: step 0 is the shape of the bytes,
//! step 1 is what they say.
//!
//! ## The order the two entry points compose in
//!
//! The two live entry points interleave step 0 and step 1 DIFFERENTLY, and the difference is
//! observable, so it is written down here rather than discovered later:
//!
//! | entry point | live order |
//! |---|---|
//! | body-model (`operation_ingress_inner`) | handler lookup (step 1) → parse (step 0) → model (step 1) |
//! | path-model (`ingress_path_model_inner`) | parse + inject (step 0) → handler lookup (step 1) |
//!
//! So on the body-model path a request that is BOTH unregistered and malformed answers 404, not 400.
//! A composition that ran this file's function first would answer 400 and that would be a diff. The
//! step functions here are therefore pure and free of ordering: the caller composes them in the live
//! order, and `decode.rs` pins that order with a test.
//!
//! ## Where this lands on the kernel's seam
//!
//! `busbar_kernel::teller::Units::arrival` takes the step's token and returns `Decision<Arrival>` —
//! proceed with facts, or refuse. This plane does not name the kernel (a plane depends on the
//! neutral ABI and nothing else), so the shape is expressed here as `Result<_, ArrivalRefusal>`:
//! `Ok` is the facts a `Decision::proceed` would carry, `Err` is the closed reason a
//! `Decision::refuse` would carry. The adapter that mints the token and calls this lives in the
//! module root, which is the only file in this plane allowed to hold one.
//!
//! On the pure-codec side the same reading is `Plane::decode_ingress`'s own `parse`, whose whole
//! failure vocabulary is `Decode::Malformed`. All three refusals below map onto that one code; the
//! three distinct sentences are the 1.5.5 wire, which the code word does not carry and the client
//! reads.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use busbar_substrate::proxy::KIND_INVALID_REQUEST;

use crate::engine::LazyBody;
use crate::unit::audit::RefusalOutcome;

/// THE CLOSED SET OF REASONS STEP 0 MAY REFUSE FOR.
///
/// Three, and there is no fourth. Each one is one of the live path's `ingress_error` arms, and the
/// (status, kind, message) triple each renders is the 1.5.5 wire — pinned by the tests below against
/// the literal spelled at the live site, so a change to either spelling is a red test rather than a
/// silent divergence on a released surface.
///
/// The kernel's own `Arrival` refusals — the budgets, the in-flight cap, the credential slab — are
/// NOT in this set and never can be: they are decided before any plane is known, and are rendered by
/// the kernel through the transport's generic envelope. A plane that could name them would be a
/// plane answering a question it was not asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrivalRefusal {
    /// The bytes are not JSON. `native_ingress.rs`'s parse arm, both entry points.
    BodyParse,
    /// The bytes are JSON but not a document — an array, a bare scalar. Path-model only: the
    /// body-model path has nothing to splice into a non-object and reads `model` off the head
    /// projection, which simply resolves nothing, so it reaches the missing-model refusal in step 1
    /// instead.
    NotAnObject,
    /// The document could not be re-serialized after the splice. Effectively unreachable — the value
    /// was just parsed and only `String`/`Bool` members were added — and kept as a non-panicking
    /// guard rather than an `unwrap`, exactly as the live arm keeps it.
    Reserialize,
}

impl ArrivalRefusal {
    /// The status this refusal wears on the wire.
    pub fn status(self) -> StatusCode {
        // All three are the client's fault and all three are the same status; they are spelled out
        // rather than collapsed so that adding a fourth reason has to state its own answer.
        match self {
            ArrivalRefusal::BodyParse
            | ArrivalRefusal::NotAnObject
            | ArrivalRefusal::Reserialize => StatusCode::BAD_REQUEST,
        }
    }

    /// The kind token this refusal wears on the wire.
    pub fn kind(self) -> &'static str {
        match self {
            ArrivalRefusal::BodyParse
            | ArrivalRefusal::NotAnObject
            | ArrivalRefusal::Reserialize => KIND_INVALID_REQUEST,
        }
    }

    /// The sentence the client reads. These are the 1.5.5 literals, verbatim.
    pub fn message(self) -> &'static str {
        match self {
            ArrivalRefusal::BodyParse => "We could not parse the JSON body of your request.",
            ArrivalRefusal::NotAnObject => "Request body must be a JSON object.",
            ArrivalRefusal::Reserialize => "The request body could not be processed.",
        }
    }

    /// NAME the refusal as an outcome value — the whole of what this step answers with.
    ///
    /// It is deliberately not bytes. The three values below are the live arm's own three, and they
    /// are handed to the audit step, which owns the one shaper that turns them into a dialect's
    /// envelope and the one door that posts the result. A step that rendered here would be a step
    /// with two jobs and a second way out of the plane; the construction gate reads this file's
    /// signatures for exactly that.
    ///
    /// None of the three carries a header of its own: an arrival refusal is a plain 400 in whatever
    /// envelope the caller's dialect wears.
    pub fn outcome(self) -> RefusalOutcome {
        RefusalOutcome::new(self.status(), self.kind(), self.message())
    }
}

/// What step 0 hands step 1 on the body-model path.
pub struct BodyArrival {
    /// The content type as the live path reads it: the header, or `""` when absent or not UTF-8.
    pub content_type: String,
    /// The pristine bytes, retained. A refcount bump, not a copy — the same handle the engine
    /// forwards.
    pub body: Bytes,
    /// The validated body with its head projection, or `None` when the content type says these bytes
    /// are not JSON and the live path therefore never parsed them.
    pub parsed: Option<LazyBody>,
}

// Hand-written rather than derived: `LazyBody` is not `Debug`, and giving it one would put a
// request body into a formatter — which is how a body ends up in a log line. What is printed here is
// the shape of the arrival, never its content.
impl std::fmt::Debug for BodyArrival {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyArrival")
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .field("parsed", &self.parsed.is_some())
            .finish()
    }
}

/// What step 0 hands step 1 on the path-model path.
pub struct PathArrival {
    /// The body with `model`, `stream` and — when asked — the array-stream shim spliced in, ready to
    /// forward. These are the bytes the engine carries.
    pub injected: Bytes,
    /// The same document, eagerly held: the path-model path already built the DOM to splice into it,
    /// so it hands it on rather than making the engine parse the bytes it just wrote.
    pub parsed: LazyBody,
}

impl PathArrival {
    /// THE PATH-MODEL ARRIVAL, AS THE CARRY HOLDS ONE.
    ///
    /// The two shapes differ in exactly one way that matters downstream: a body-model arrival hands
    /// on the bytes the client sent and the head projection taken off them, and a path-model arrival
    /// hands on the bytes it WROTE and the document it wrote them from. Everything past step 1 wants
    /// the same two things — the bytes to forward and the projection to read — so the path shape is
    /// stated in the body shape's vocabulary here, once, rather than by every caller assembling one.
    ///
    /// The content type is the arrival's own header value, carried because step 1's ladder asks it
    /// whether these bytes are multipart. On this path the answer never decides anything — the URL
    /// already named the model — and it is carried anyway, because a field that is sometimes filled
    /// in is a field nobody can read with confidence.
    #[must_use]
    pub fn into_arrival(self, content_type: String) -> BodyArrival {
        BodyArrival {
            content_type,
            body: self.injected,
            parsed: Some(self.parsed),
        }
    }
}

// Same reason as `BodyArrival`'s: the shape, never the content.
impl std::fmt::Debug for PathArrival {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathArrival")
            .field("injected_len", &self.injected.len())
            .finish()
    }
}

/// The content-type read, exactly as the live path performs it.
///
/// Absent, or present and not UTF-8, both read as the empty string — which is the value the JSON
/// arm below treats as "assume JSON". That is deliberate and it is 1.5.5's: a client that sends a
/// JSON body with no content type is served, not refused.
pub fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// STEP 0, BODY-MODEL PATH.
///
/// Read the content type; if it says JSON — or says nothing — validate the bytes and capture the
/// head projection. Otherwise carry the bytes opaque, which is how multipart audio and binary
/// bodies ride: they are relayed and translated at the byte level by the operation codecs, and
/// parsing them would be a reading nobody asked for.
///
/// The validation is done BEFORE the model is looked for, on purpose, and the ordering is worth a
/// sentence because it is the difference between two error messages a client reads: a malformed
/// body must get the parse refusal, never the misleading missing-model one.
pub fn arrival_body(headers: &HeaderMap, body: &Bytes) -> Result<BodyArrival, ArrivalRefusal> {
    let ct = content_type(headers);
    let parsed = if ct.starts_with("application/json") || ct.is_empty() {
        match LazyBody::parse(body) {
            Ok(v) => Some(v),
            Err(_) => {
                // The parser's own error is never echoed and never logged: with sonic-rs it embeds a
                // fragment of the malformed body, which can carry secrets. The operator gets the
                // byte length, the client gets the generic sentence.
                tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
                return Err(ArrivalRefusal::BodyParse);
            }
        }
    } else {
        None
    };
    Ok(BodyArrival {
        content_type: ct.to_string(),
        body: body.clone(),
        parsed,
    })
}

/// STEP 0, PATH-MODEL PATH.
///
/// Two dialects carry the model in the URL rather than the body. The shared resolution and forward
/// plumbing downstream reads both the model and the stream flag from the body, so this step splices
/// them in — which is the reason this path parses a full document where the body-model path is
/// content to validate and project a head.
///
/// `gemini_json_array` marks a streaming request that is NOT `alt=sse` and must be framed as a JSON
/// array. The marker key is resolved through the writer vtable BY PROTOCOL NAME, never by naming a
/// dialect module, so "delete a dialect and the plane is free of it" stays true of this file too.
/// The shim is stripped again before the upstream call.
pub fn arrival_path_model(
    body: &Bytes,
    model: &str,
    stream: bool,
    gemini_json_array: bool,
    proto: &str,
) -> Result<PathArrival, ArrivalRefusal> {
    let mut v: Value = match busbar_substrate::json::parse(body) {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
            return Err(ArrivalRefusal::BodyParse);
        }
    };

    match v.as_object_mut() {
        Some(obj) => {
            obj.insert("model".to_string(), Value::String(model.to_string()));
            obj.insert("stream".to_string(), Value::Bool(stream));
            if gemini_json_array {
                if let Some(shim_key) = busbar_substrate::proto::array_stream_shim_key_for(proto) {
                    obj.insert(shim_key.to_string(), Value::Bool(true));
                }
            }
        }
        // A native client body is always a document. If it is not, there is nothing to splice the
        // model into, and the model is what the whole path exists to establish.
        None => return Err(ArrivalRefusal::NotAnObject),
    }

    let injected: Bytes = match busbar_substrate::json::to_vec(&v) {
        Ok(b) => b.into(),
        Err(_e) => {
            // Same leak class as the parse arms: the library's error Display is a busbar-internal
            // tell, so it is never echoed — an operator breadcrumb only.
            tracing::debug!("injected request body re-serialization failed");
            return Err(ArrivalRefusal::Reserialize);
        }
    };

    Ok(PathArrival {
        parsed: LazyBody::from_value(v),
        injected,
    })
}

#[cfg(test)]
#[path = "tests/arrival.rs"]
mod tests;
