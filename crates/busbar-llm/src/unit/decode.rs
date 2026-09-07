// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEP 1 — DECODE, as the LLM plane sees it.
//!
//! Step 0 said the bytes are the right shape. Step 1 says what they are: which handler owns this
//! (protocol, operation) pair, and which model the caller asked for. Those two answers are what every
//! later step is about — verify checks where that model may go, admit prices it, route dials it — so
//! a unit that cannot produce them is a unit that has nothing left to decide.
//!
//! This is deliberately a small step. The plane's own `Plane::decode_ingress` walks the detection
//! ladder over the transport facts to name a dialect; on this path the ladder has ALREADY been
//! walked — the router matched a route, so the protocol and the operation arrived as arguments — and
//! what remains of the ladder is the model ladder:
//!
//! 1. a model handed down from the URL (the two path-model dialects resolved it themselves), else
//! 2. a `name="model"` form field, when the body is multipart (audio, which cannot be parsed as
//!    JSON and must still be routed by model), else
//! 3. the `model` member of the head projection step 0 captured.
//!
//! The ladder is walked ONCE and in that order, which is the point of writing it as a ladder rather
//! than three conditions: an ordered walk repeated is an ordered walk that can disagree with itself.
//! Rung 2 is `native_ingress::multipart_model`, CALLED — not a copy of it. A copy would be a second
//! reading of one wire.
//!
//! ## Two lookups, two sentences
//!
//! The handler lookup is spelled twice below because the live path spells it twice, and the two
//! spellings send DIFFERENT bytes:
//!
//! * the body-model entry point looks the protocol up, then the operation, and has a distinct
//!   sentence for each miss;
//! * the path-model entry point chains the two into one lookup and has only the second sentence.
//!
//! Collapsing them would be a one-line simplification that changes a released 404 body, so they stay
//! two functions and the tests below pin both.
//!
//! ## The order this composes in
//!
//! The body-model entry point runs the handler lookup BEFORE step 0's parse and the model ladder
//! AFTER it. The path-model entry point runs its lookup after step 0 entirely. That interleaving is
//! observable — a request that is both unregistered and malformed answers 404 on one path — so the
//! functions here are pure and ordering-free, the caller composes them in the live order, and
//! [`tests::the_body_entry_point_answers_the_handler_miss_before_the_parse_miss`] pins it.
//!
//! ## Where this lands on the kernel's seam
//!
//! `busbar_kernel::teller::Units::decode` returns `Decision<Decode>`. This plane does not name the
//! kernel, so the shape is `Result<DecodeFacts, DecodeRefusal>`: `Ok` is what a `Decision::proceed`
//! would carry, `Err` the closed reason a `Decision::refuse` would. On the pure-codec side both 404s
//! are `Decode::UnsupportedOperation`; the missing-model refusal has NO codec counterpart, because
//! the codec treats `model` as a fact that may simply be absent while this path treats it as the
//! thing without which there is nothing to route.

use axum::body::Bytes;
use axum::http::StatusCode;
use busbar_api::operation::Operation;
use busbar_substrate::handlers::OperationHandler;
use busbar_substrate::proxy::{KIND_INVALID_REQUEST, KIND_NOT_FOUND};

use crate::engine::LazyBody;
use crate::unit::audit::RefusalOutcome;

/// THE CLOSED SET OF REASONS STEP 1 MAY REFUSE FOR.
///
/// Three, and there is no fourth. Two are the same status with different sentences — that is not
/// redundancy, it is the released wire: one says the protocol is not here at all, the other says it
/// is here and does not do this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeRefusal {
    /// No handler is registered for this protocol — the plugin carrying it is not linked, or was
    /// deleted. The body-model entry point's first lookup.
    UnknownProtocol,
    /// The protocol is registered and declares no handler for this operation. Both entry points.
    UnsupportedOperation,
    /// The model ladder resolved nothing, or resolved the empty string. An empty model is a missing
    /// model: a caller that sends `"model": ""` has named nothing, and routing it would mean picking
    /// a destination the caller did not ask for.
    MissingModel,
}

impl DecodeRefusal {
    /// The status this refusal wears on the wire.
    pub fn status(self) -> StatusCode {
        match self {
            DecodeRefusal::UnknownProtocol | DecodeRefusal::UnsupportedOperation => {
                StatusCode::NOT_FOUND
            }
            DecodeRefusal::MissingModel => StatusCode::BAD_REQUEST,
        }
    }

    /// The kind token this refusal wears on the wire.
    pub fn kind(self) -> &'static str {
        match self {
            DecodeRefusal::UnknownProtocol | DecodeRefusal::UnsupportedOperation => KIND_NOT_FOUND,
            DecodeRefusal::MissingModel => KIND_INVALID_REQUEST,
        }
    }

    /// The sentence the client reads. These are the 1.5.5 literals, verbatim, including the two 404s
    /// differing only in their subject.
    ///
    /// The endpoint one is READ from the hoisted copy rather than respelled: the const exists so the
    /// sentence cannot drift between the sites that render it, and a step file that keeps its own
    /// spelling is a site the hoist does not cover. The protocol one has no hoisted twin — this is
    /// its only site — so it stays a literal here.
    pub fn message(self) -> &'static str {
        match self {
            DecodeRefusal::UnknownProtocol => "This protocol does not support that operation.",
            DecodeRefusal::UnsupportedOperation => {
                crate::engine::DETAIL_ENDPOINT_UNSUPPORTED_OPERATION
            }
            DecodeRefusal::MissingModel => "Missing required parameter: 'model'.",
        }
    }

    /// NAME the refusal as an outcome value. Shaping it into a dialect's envelope, and counting and
    /// logging it, are both the audit step's job and neither is this one's — which is why what
    /// leaves this file is three values rather than a response.
    ///
    /// Neither 404 nor the missing-model 400 carries a header of its own.
    pub fn outcome(self) -> RefusalOutcome {
        RefusalOutcome::new(self.status(), self.kind(), self.message())
    }
}

/// What step 1 establishes: who handles this, and what was asked for.
#[derive(Clone, Copy)]
pub struct DecodeFacts<'a> {
    /// The handler for this (protocol, operation) cell, resolved through the registry the composition
    /// root populated.
    pub op_handler: &'static dyn OperationHandler,
    /// The model the caller named, non-empty. Borrowed from the arrival, which outlives the unit.
    pub model: &'a str,
}

// Hand-written: a handler is a vtable, and the only honest thing to print about it is that one is
// there. Deriving would demand `Debug` on the trait object, which would be surface added to the
// plugin ABI for a formatter's benefit.
impl std::fmt::Debug for DecodeFacts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeFacts")
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// RUNG 1+2+3 OF THE MODEL LADDER, walked once, in order.
///
/// `model_hint` is rung 1: the URL already carried the model, so nothing in the body can override it.
/// A multipart body is rung 2 — it cannot be JSON, so the form field is the only place a model can
/// be. Everything else is rung 3, a point read of the head projection step 0 captured, which never
/// materializes a DOM and answers exactly what a full parse would have: a missing member, a
/// non-string member and a non-document body all resolve nothing.
///
/// The empty string is not a model. That check sits at the bottom of the ladder rather than inside a
/// rung so that every rung is held to it — a URL that carried an empty model is as unroutable as a
/// body that carried one.
pub fn model_from<'a>(
    content_type: &str,
    body: &Bytes,
    parsed: Option<&'a LazyBody>,
    model_hint: Option<&'a str>,
) -> Result<String, DecodeRefusal> {
    let model = if let Some(m) = model_hint {
        Some(m.to_string())
    } else if content_type.starts_with("multipart/") {
        // The content type is handed on rather than dropped: it carries the boundary, and a
        // multipart body has no parts without one. Rung 2 reads a document, not a byte pattern.
        crate::native_ingress::multipart_model(content_type, body)
    } else {
        parsed.and_then(|v| {
            v.probe()
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
    };
    match model {
        Some(m) if !m.is_empty() => Ok(m),
        _ => Err(DecodeRefusal::MissingModel),
    }
}

/// THE HANDLER LOOKUP, BODY-MODEL SPELLING.
///
/// Two lookups, two sentences: an unregistered protocol and a registered protocol that does not do
/// this operation are different facts, and the live path tells the client which one it hit.
pub fn handler_for(
    proto: &str,
    operation: Operation,
) -> Result<&'static dyn OperationHandler, DecodeRefusal> {
    let rh =
        busbar_substrate::handlers::request_handler(proto).ok_or(DecodeRefusal::UnknownProtocol)?;
    rh.operation_handler(operation)
        .ok_or(DecodeRefusal::UnsupportedOperation)
}

/// THE HANDLER LOOKUP, PATH-MODEL SPELLING.
///
/// One chained lookup with one sentence. It reads as an accident of how the live arm was written,
/// and perhaps it is, but it is a released 404 body: a client that pins on it is right to, and this
/// rebuild does not get to decide otherwise. If the two spellings are ever reconciled it is a wire
/// change with its own registered row, not a tidy-up here.
pub fn handler_for_path_model(
    proto: &str,
    operation: Operation,
) -> Result<&'static dyn OperationHandler, DecodeRefusal> {
    busbar_substrate::handlers::request_handler(proto)
        .and_then(|rh| rh.operation_handler(operation))
        .ok_or(DecodeRefusal::UnsupportedOperation)
}

/// STEP 1, BODY-MODEL PATH: the handler, then the model.
///
/// The two halves are exposed separately above because the live entry point runs step 0's parse
/// BETWEEN them. This composes them for the callers that have no such interleaving, and for the
/// tests that want the whole step in one call.
pub fn decode_body<'a>(
    proto: &str,
    operation: Operation,
    content_type: &str,
    body: &Bytes,
    parsed: Option<&LazyBody>,
    model_hint: Option<&str>,
    model_out: &'a mut String,
) -> Result<DecodeFacts<'a>, DecodeRefusal> {
    let op_handler = handler_for(proto, operation)?;
    *model_out = model_from(content_type, body, parsed, model_hint)?;
    Ok(DecodeFacts {
        op_handler,
        model: model_out.as_str(),
    })
}

/// STEP 1, PATH-MODEL PATH: the model is already known, so only the handler is left.
///
/// THE LADDER'S FLOOR IS THE BODY'S FLOOR, AND ONLY THE BODY'S. An empty name here is passed
/// through, not refused, because the shipped path-model entry point passes it through: it injects
/// whatever the URL gave into the body and lets pool resolution answer, which for a name nothing
/// matches is the ordinary model-miss 404 — taken after the door, and therefore charged. The
/// body-model entry point is the one that carries an empty-model rung, and it carries it because a
/// JSON document with `"model": ""` is a document that failed to name one.
///
/// The difference matters because the empty URL model is reachable: bedrock's path parse ends
/// `unwrap_or_default()`, so a converse path whose model segment the handler did not recognise
/// arrives with an empty string in hand. Refusing it here would turn that request from a charged
/// 404 into an uncharged 400 — a different status, a different envelope and a different ledger than
/// the node has ever given it.
pub fn decode_path_model<'a>(
    proto: &str,
    operation: Operation,
    model: &'a str,
) -> Result<DecodeFacts<'a>, DecodeRefusal> {
    let op_handler = handler_for_path_model(proto, operation)?;
    Ok(DecodeFacts { op_handler, model })
}

#[cfg(test)]
#[path = "tests/decode.rs"]
mod tests;
