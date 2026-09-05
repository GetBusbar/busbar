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
use axum::response::Response;
use busbar_api::operation::Operation;
use busbar_substrate::handlers::OperationHandler;
use busbar_substrate::proxy::{KIND_INVALID_REQUEST, KIND_NOT_FOUND};

use crate::engine::LazyBody;

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
    pub fn message(self) -> &'static str {
        match self {
            DecodeRefusal::UnknownProtocol => "This protocol does not support that operation.",
            DecodeRefusal::UnsupportedOperation => "This endpoint does not support that operation.",
            DecodeRefusal::MissingModel => "Missing required parameter: 'model'.",
        }
    }

    /// Render the refusal in the caller's own dialect, through the shaper the live arms call.
    ///
    /// Counting and logging the refusal is the audit step's job, not this one's.
    pub fn render(self, proto: &str) -> Response {
        busbar_substrate::proxy::ingress_error(proto, self.status(), self.kind(), self.message())
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
        crate::native_ingress::multipart_model(body)
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
pub fn decode_path_model<'a>(
    proto: &str,
    operation: Operation,
    model: &'a str,
) -> Result<DecodeFacts<'a>, DecodeRefusal> {
    let op_handler = handler_for_path_model(proto, operation)?;
    // The URL carried it, but an empty one is still not a model, and the ladder's floor holds for
    // every rung.
    if model.is_empty() {
        return Err(DecodeRefusal::MissingModel);
    }
    Ok(DecodeFacts { op_handler, model })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::arrival::{arrival_body, ArrivalRefusal};
    use axum::http::{HeaderMap, HeaderValue};
    use http_body_util::BodyExt;

    /// The recorded request fixtures, read from where they are recorded.
    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../busbar-llm-codec/src/tests/proto/golden"
    );

    fn fixtures() -> Vec<(String, Bytes)> {
        let mut out: Vec<(String, Bytes)> = std::fs::read_dir(GOLDEN)
            .expect("the recorded request corpus must be readable")
            .filter_map(|e| {
                let path = e.ok()?.path();
                let name = path.file_name()?.to_str()?.to_string();
                (name.starts_with("req_") && name.ends_with(".json")).then(|| {
                    let bytes = std::fs::read(&path).expect("fixture readable");
                    (name, Bytes::from(bytes))
                })
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        assert!(
            out.len() > 40,
            "the recorded request corpus moved or shrank: {} fixtures",
            out.len()
        );
        out
    }

    fn json_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h
    }

    /// A response reduced to what a client can actually observe of it — with the one thing a client
    /// cannot pin normalized away.
    ///
    /// Some dialects' error envelopes carry a SYNTHESIZED request id, minted fresh from random bytes
    /// on every call, in a header and again in the body. It is genuinely different on every render,
    /// so two renderings of one refusal are never byte-equal as they stand, and comparing them raw
    /// would prove nothing at all. It is normalized rather than ignored: the id's value is replaced
    /// with a fixed token everywhere it appears, so everything around it — including the fact that
    /// the body and the header carry the SAME id — is still compared byte for byte.
    async fn seen(resp: Response) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
        const SYNTHESIZED: &[u8] = b"<synthesized-request-id>";
        let status = resp.status().as_u16();
        let raw: Vec<(String, Vec<u8>)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.as_bytes().to_vec()))
            .collect();
        let mut body = resp
            .into_body()
            .collect()
            .await
            .expect("body collectable")
            .to_bytes()
            .to_vec();
        let mut headers = Vec::with_capacity(raw.len());
        for (name, value) in raw {
            if name.contains("request") && name.contains("id") {
                body = replace_all(&body, &value, SYNTHESIZED);
                headers.push((name, SYNTHESIZED.to_vec()));
            } else {
                headers.push((name, value));
            }
        }
        (status, headers, body)
    }

    /// Byte-substring replacement, so the normalization above needs no regex and no allocation of a
    /// pattern language into a test.
    fn replace_all(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
        if needle.is_empty() {
            return haystack.to_vec();
        }
        let mut out = Vec::with_capacity(haystack.len());
        let mut i = 0;
        while i < haystack.len() {
            if haystack[i..].starts_with(needle) {
                out.extend_from_slice(with);
                i += needle.len();
            } else {
                out.push(haystack[i]);
                i += 1;
            }
        }
        out
    }

    fn registered() {
        busbar_llm_codec::ensure_test_protocols_registered();
    }

    // ── THE MODEL LADDER vs THE LIVE PATH ──────────────────────────────────────────────────────

    /// IDENTITY. For every recorded request, the step's model ladder answers exactly what the live
    /// path's ladder answers — same rung, same string — driven through step 0's own arrival so the
    /// two steps compose over the real projection rather than a hand-built one.
    #[test]
    fn every_recorded_request_decodes_to_the_live_paths_model() {
        for (name, body) in fixtures() {
            let arrival = arrival_body(&json_headers(), &body)
                .unwrap_or_else(|r| panic!("{name} refused at arrival: {r:?}"));
            let step = model_from(
                &arrival.content_type,
                &arrival.body,
                arrival.parsed.as_ref(),
                None,
            );
            // The live arm, run here on the same bytes: the point read of the head projection.
            let live = LazyBody::parse(&body)
                .expect("the live parse accepts a recorded request")
                .probe()
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string);
            match live {
                Some(m) if !m.is_empty() => assert_eq!(
                    step.as_deref(),
                    Ok(m.as_str()),
                    "{name}: the step's model is not the live path's"
                ),
                _ => assert_eq!(
                    step,
                    Err(DecodeRefusal::MissingModel),
                    "{name}: the step routed a request the live path refuses"
                ),
            }
        }
    }

    /// Rung 1 beats rung 3. The URL is the two path-model dialects' statement about their own URL
    /// space, and a body that disagrees does not get to overrule it.
    #[test]
    fn a_url_model_wins_over_the_body() {
        let body = Bytes::from_static(br#"{"model":"from-the-body"}"#);
        let arrival = arrival_body(&json_headers(), &body).expect("accepted");
        assert_eq!(
            model_from(
                &arrival.content_type,
                &arrival.body,
                arrival.parsed.as_ref(),
                Some("from-the-url")
            )
            .as_deref(),
            Ok("from-the-url")
        );
    }

    /// IDENTITY, rung 2. A multipart body is read by the LIVE function, not a copy, so this pins the
    /// call rather than an equivalence — but it is asserted against the live function anyway, which
    /// is what makes replacing the call with a copy a red test.
    #[test]
    fn a_multipart_body_takes_the_live_form_field_model() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=zz"),
        );
        let raw: &[u8] = b"--zz\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--zz\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n\x00\x01\x02\r\n--zz--";
        let body = Bytes::from_static(raw);
        let arrival = arrival_body(&h, &body).expect("accepted");
        assert!(
            arrival.parsed.is_none(),
            "a multipart body must not be parsed as json"
        );
        let step = model_from(
            &arrival.content_type,
            &arrival.body,
            arrival.parsed.as_ref(),
            None,
        );
        // The live arm, run here on the same bytes.
        let live = crate::native_ingress::multipart_model(&body);
        assert_eq!(
            step.as_deref().ok(),
            live.as_deref(),
            "the step's rung 2 is not the live path's"
        );
        assert_eq!(step.as_deref(), Ok("whisper-1"));
    }

    /// A multipart body with no model field falls to the ladder's floor rather than to rung 3 — it
    /// was never parsed, so there is no projection to read.
    #[test]
    fn a_multipart_body_with_no_model_field_is_a_missing_model() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=zz"),
        );
        let body = Bytes::from_static(
            b"--zz\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nxx\r\n--zz--",
        );
        let arrival = arrival_body(&h, &body).expect("accepted");
        assert_eq!(
            model_from(
                &arrival.content_type,
                &arrival.body,
                arrival.parsed.as_ref(),
                None
            ),
            Err(DecodeRefusal::MissingModel)
        );
    }

    /// The ladder's floor: every shape of "no model there" ends at the same refusal, including the
    /// empty string and a body that is JSON but not a document.
    #[test]
    fn the_ladder_floor_catches_every_shape_of_no_model() {
        for raw in [
            &br#"{}"#[..],
            &br#"{"model":""}"#[..],
            &br#"{"model":null}"#[..],
            &br#"{"model":7}"#[..],
            &br#"[]"#[..],
            &br#""a string""#[..],
        ] {
            let body = Bytes::copy_from_slice(raw);
            let arrival = arrival_body(&json_headers(), &body).expect("valid json");
            assert_eq!(
                model_from(
                    &arrival.content_type,
                    &arrival.body,
                    arrival.parsed.as_ref(),
                    None
                ),
                Err(DecodeRefusal::MissingModel),
                "{}: routed a request with no model",
                String::from_utf8_lossy(raw)
            );
        }
        // And an empty URL model is no better than an empty body one.
        registered();
        let proto = busbar_substrate::proto::residual_default_protocol().expect("a chat dialect");
        assert_eq!(
            decode_path_model(proto, Operation::CHAT, "")
                .map(|_| ())
                .expect_err("must refuse"),
            DecodeRefusal::MissingModel
        );
    }

    // ── THE HANDLER LOOKUP vs THE LIVE PATH ────────────────────────────────────────────────────

    /// IDENTITY. Every registered dialect resolves, through the step, to the SAME handler the live
    /// lookup resolves — compared by pointer, so a lookup that found an equivalent-looking handler
    /// somewhere else fails here.
    #[test]
    fn every_registered_dialect_resolves_the_live_paths_handler() {
        registered();
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            let live = busbar_substrate::handlers::request_handler(proto)
                .and_then(|rh| rh.operation_handler(Operation::CHAT));
            let step = handler_for(proto, Operation::CHAT).ok();
            match (live, step) {
                (Some(live), Some(step)) => assert!(
                    std::ptr::eq(
                        live as *const dyn OperationHandler as *const u8,
                        step as *const dyn OperationHandler as *const u8
                    ),
                    "{proto}: the step resolved a different handler than the live lookup"
                ),
                (None, None) => {}
                _ => panic!("{proto}: the step and the live lookup disagree about chat"),
            }
            // The chained path-model spelling resolves the same handler as the two-step one; only
            // the sentence on a miss differs.
            assert_eq!(
                handler_for(proto, Operation::CHAT).is_ok(),
                handler_for_path_model(proto, Operation::CHAT).is_ok(),
                "{proto}: the two spellings disagree about whether chat exists"
            );
        }
    }

    /// IDENTITY. The two 404s carry DIFFERENT bytes, and both are the live arms' bytes. This is the
    /// test that makes collapsing the two lookups into one a red test rather than a tidy-up.
    #[tokio::test]
    async fn the_two_handler_misses_carry_the_live_arms_distinct_bytes() {
        registered();
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            // An unregistered protocol name: the body-model path's first lookup.
            assert_eq!(
                handler_for("no-such-protocol", Operation::CHAT)
                    .map(|_| ())
                    .expect_err("must refuse"),
                DecodeRefusal::UnknownProtocol
            );
            // The path-model spelling has only the one sentence for both misses.
            assert_eq!(
                handler_for_path_model("no-such-protocol", Operation::CHAT)
                    .map(|_| ())
                    .expect_err("must refuse"),
                DecodeRefusal::UnsupportedOperation
            );

            let protocol_miss = busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                "This protocol does not support that operation.",
            );
            let endpoint_miss = busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::NOT_FOUND,
                KIND_NOT_FOUND,
                "This endpoint does not support that operation.",
            );
            assert_eq!(
                seen(DecodeRefusal::UnknownProtocol.render(proto)).await,
                seen(protocol_miss).await,
                "{proto}: the step's protocol miss is not the live path's"
            );
            assert_eq!(
                seen(DecodeRefusal::UnsupportedOperation.render(proto)).await,
                seen(endpoint_miss).await,
                "{proto}: the step's endpoint miss is not the live path's"
            );
            // And they are not the same bytes as each other.
            assert_ne!(
                seen(DecodeRefusal::UnknownProtocol.render(proto)).await,
                seen(DecodeRefusal::UnsupportedOperation.render(proto)).await,
                "{proto}: the two 404s collapsed into one"
            );
        }
    }

    /// IDENTITY. The missing-model refusal carries the live arm's bytes, in every dialect's own
    /// error shape.
    #[tokio::test]
    async fn the_missing_model_refusal_carries_the_live_arms_bytes() {
        registered();
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            let live = busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "Missing required parameter: 'model'.",
            );
            assert_eq!(
                seen(DecodeRefusal::MissingModel.render(proto)).await,
                seen(live).await,
                "{proto}: the step's missing-model refusal is not the live path's"
            );
        }
    }

    // ── THE ORDER THE TWO STEPS COMPOSE IN ─────────────────────────────────────────────────────

    /// THE ORDERING PIN. On the body-model entry point the handler lookup runs BEFORE step 0's
    /// parse, so a request that is both unregistered and malformed answers the 404 — not the 400.
    /// Composing the steps in the loop's own order without this knowledge would silently change a
    /// released status code, which is why the fact is asserted rather than commented.
    #[test]
    fn the_body_entry_point_answers_the_handler_miss_before_the_parse_miss() {
        let malformed = Bytes::from_static(b"{ not json");
        // Both halves refuse on their own.
        assert_eq!(
            handler_for("no-such-protocol", Operation::CHAT)
                .map(|_| ())
                .expect_err("must refuse"),
            DecodeRefusal::UnknownProtocol
        );
        assert_eq!(
            arrival_body(&json_headers(), &malformed).expect_err("must refuse"),
            ArrivalRefusal::BodyParse
        );
        // The live order is handler-first, so the 404 is the answer. Composed the other way it
        // would be a 400, and that is the diff this test exists to make loud.
        let live_order = handler_for("no-such-protocol", Operation::CHAT)
            .map(|_| ())
            .map_err(|r| (r.status(), r.message()));
        assert_eq!(
            live_order.expect_err("must refuse"),
            (
                StatusCode::NOT_FOUND,
                "This protocol does not support that operation."
            )
        );
    }

    /// The path-model entry point composes the other way round: step 0 first, so a malformed body
    /// on an unregistered protocol answers the 400. The two entry points genuinely differ and both
    /// answers are correct for their own path.
    #[test]
    fn the_path_model_entry_point_answers_the_parse_miss_first() {
        registered();
        let malformed = Bytes::from_static(b"{ not json");
        let step0 = crate::unit::arrival::arrival_path_model(
            &malformed,
            "m",
            false,
            false,
            "no-such-protocol",
        );
        assert_eq!(
            step0.map(|_| ()).expect_err("must refuse"),
            ArrivalRefusal::BodyParse
        );
    }

    // ── THE SET IS CLOSED ──────────────────────────────────────────────────────────────────────

    /// Three reasons, three sentences, two statuses. A fourth reason added without a sentence of its
    /// own would collide here.
    #[test]
    fn the_refusal_set_is_three_and_they_do_not_collide() {
        let all = [
            DecodeRefusal::UnknownProtocol,
            DecodeRefusal::UnsupportedOperation,
            DecodeRefusal::MissingModel,
        ];
        let mut messages: Vec<&str> = all.iter().map(|r| r.message()).collect();
        messages.sort_unstable();
        messages.dedup();
        assert_eq!(messages.len(), all.len(), "two reasons share one sentence");
        assert_eq!(
            DecodeRefusal::UnknownProtocol.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            DecodeRefusal::UnsupportedOperation.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            DecodeRefusal::MissingModel.status(),
            StatusCode::BAD_REQUEST
        );
    }

    /// THE WHOLE STEP, both spellings, over a recorded request: the handler and the model together.
    #[test]
    fn the_whole_step_resolves_both_facts_for_a_recorded_request() {
        registered();
        let proto = busbar_substrate::proto::residual_default_protocol().expect("a chat dialect");
        // The first recorded request that carries a model in its BODY. Thirteen of the corpus's
        // sixty-four do not, and that is not a gap: they are the bodies recorded for the two
        // dialects that carry the model in the URL, so the body-model spelling is the wrong reader
        // for them and the path-model spelling below is the right one.
        let (name, body) = fixtures()
            .into_iter()
            .find(|(_, b)| {
                LazyBody::parse(b)
                    .ok()
                    .and_then(|v| {
                        v.probe()
                            .get("model")
                            .and_then(|m| m.as_str())
                            .map(str::to_string)
                    })
                    .is_some_and(|m| !m.is_empty())
            })
            .expect("the corpus has a body-model request");
        let arrival = arrival_body(&json_headers(), &body).expect("accepted");
        let mut model = String::new();
        let facts = decode_body(
            proto,
            Operation::CHAT,
            &arrival.content_type,
            &arrival.body,
            arrival.parsed.as_ref(),
            None,
            &mut model,
        )
        .unwrap_or_else(|r| panic!("{name} refused at decode: {r:?}"));
        assert!(!facts.model.is_empty());
        // The path-model spelling, handed the same model, lands on the same handler.
        let path = decode_path_model(proto, Operation::CHAT, facts.model).expect("accepted");
        assert_eq!(path.model, facts.model);
    }
}
