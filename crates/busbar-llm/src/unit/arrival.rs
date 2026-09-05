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
fn content_type(headers: &HeaderMap) -> &str {
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
mod tests {
    use super::*;
    use crate::unit::audit::render_refusal;
    use axum::response::Response;
    use http_body_util::BodyExt;

    /// The recorded request fixtures, read from where they are recorded rather than copied here. A
    /// copy would be a second corpus, and a second corpus drifts.
    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../busbar-llm-codec/src/tests/proto/golden"
    );

    /// Every recorded request body, as bytes.
    fn fixtures() -> Vec<(String, Bytes)> {
        let mut out: Vec<(String, Bytes)> = std::fs::read_dir(GOLDEN)
            .expect("the recorded request corpus must be readable")
            .filter_map(|e| {
                let path = e.ok()?.path();
                let name = path.file_name()?.to_str()?.to_string();
                // The request goldens only: the response and projection goldens are a different
                // corpus with a different shape.
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
            axum::http::HeaderValue::from_static("application/json"),
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

    /// The dialect the refusal-rendering tests shape against. Read off the recorded declarations by
    /// name rather than spelled, so this file names no dialect.
    fn a_registered_protocol() -> &'static str {
        registered();
        busbar_substrate::proto::residual_default_protocol()
            .expect("a chat dialect must be registered in this test binary")
    }

    // ── STEP 0 vs THE LIVE PATH: the same bytes ────────────────────────────────────────────────

    /// IDENTITY, body-model. For every recorded request, the step's parse and the live path's parse
    /// are the SAME parse: same acceptance, and the same head projection down to the value.
    #[test]
    fn the_body_step_projects_what_the_live_parse_projects() {
        for (name, body) in fixtures() {
            let step = arrival_body(&json_headers(), &body)
                .unwrap_or_else(|r| panic!("{name} refused at arrival: {r:?}"));
            // The live arm, run here on the same bytes.
            let live = LazyBody::parse(&body).expect("the live parse accepts a recorded request");
            let step_parsed = step.parsed.expect("a json content type parses");
            assert_eq!(
                step_parsed.probe(),
                live.probe(),
                "{name}: the step's head projection is not the live path's"
            );
            assert_eq!(
                step.body, body,
                "{name}: the step did not retain the pristine bytes"
            );
        }
    }

    /// IDENTITY, path-model. For every recorded request, the step's injected bytes are byte-for-byte
    /// the bytes the live splice produces — same members, same order, same serializer.
    #[test]
    fn the_path_model_step_injects_the_bytes_the_live_splice_injects() {
        let proto = a_registered_protocol();
        for (name, body) in fixtures() {
            let step = arrival_path_model(&body, "pinned-model", true, false, proto)
                .unwrap_or_else(|r| panic!("{name} refused at arrival: {r:?}"));
            // The live arm, run here on the same bytes.
            let mut v: Value = busbar_substrate::json::parse(&body).expect("live parse");
            let obj = v.as_object_mut().expect("a recorded request is a document");
            obj.insert(
                "model".to_string(),
                Value::String("pinned-model".to_string()),
            );
            obj.insert("stream".to_string(), Value::Bool(true));
            let live: Bytes = busbar_substrate::json::to_vec(&v)
                .expect("live serialize")
                .into();
            assert_eq!(
                step.injected, live,
                "{name}: the step's injected body is not the live path's"
            );
            assert_eq!(
                step.parsed.probe(),
                &v,
                "{name}: the step handed on a document that is not the one it wrote"
            );
        }
    }

    /// The step honours the URL's model and stream flag over whatever the body said.
    #[test]
    fn the_url_model_and_stream_flag_win_over_the_body() {
        let proto = a_registered_protocol();
        let body = Bytes::from_static(br#"{"model":"from-the-body","stream":false,"x":1}"#);
        let step = arrival_path_model(&body, "from-the-url", true, false, proto).expect("accepted");
        let v = step.parsed.probe();
        assert_eq!(v.get("model").and_then(Value::as_str), Some("from-the-url"));
        assert_eq!(v.get("stream").and_then(Value::as_bool), Some(true));
        // Everything else the client sent survives the splice untouched.
        assert_eq!(v.get("x").and_then(Value::as_i64), Some(1));
    }

    /// The array-stream shim is spliced only when asked, and only where the writer vtable declares a
    /// key for it. A dialect with no such key is unchanged either way.
    #[test]
    fn the_array_stream_shim_is_spliced_only_when_asked() {
        registered();
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            let body = Bytes::from_static(br#"{"a":1}"#);
            let off = arrival_path_model(&body, "m", true, false, proto).expect("accepted");
            let on = arrival_path_model(&body, "m", true, true, proto).expect("accepted");
            match busbar_substrate::proto::array_stream_shim_key_for(proto) {
                Some(key) => {
                    assert!(
                        off.parsed.probe().get(key).is_none(),
                        "{proto}: the shim appeared without being asked for"
                    );
                    assert_eq!(
                        on.parsed.probe().get(key).and_then(Value::as_bool),
                        Some(true),
                        "{proto}: the shim was asked for and did not appear"
                    );
                }
                None => assert_eq!(
                    off.injected, on.injected,
                    "{proto}: a dialect with no shim key changed shape anyway"
                ),
            }
        }
    }

    // ── THE CONTENT-TYPE READ ──────────────────────────────────────────────────────────────────

    /// A body with no content type is assumed to be JSON and validated — which is what makes a
    /// header-less client work rather than get a refusal it cannot act on.
    #[test]
    fn an_absent_content_type_is_read_as_json() {
        let body = Bytes::from_static(br#"{"model":"m"}"#);
        let step = arrival_body(&HeaderMap::new(), &body).expect("accepted");
        assert_eq!(step.content_type, "");
        assert!(step.parsed.is_some(), "an empty content type must parse");
    }

    /// A content type that is not JSON carries the bytes opaque. Multipart audio is the reason:
    /// parsing it would fail on a body that is perfectly valid for its operation.
    #[test]
    fn a_non_json_content_type_carries_the_bytes_opaque() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("multipart/form-data; boundary=zz"),
        );
        // Bytes that are emphatically not JSON, so an accidental parse would be visible.
        let body = Bytes::from_static(b"--zz\r\nnot json at all\r\n--zz--");
        let step = arrival_body(&h, &body).expect("accepted");
        assert!(
            step.parsed.is_none(),
            "a non-json content type must not be parsed"
        );
        assert_eq!(step.body, body);
    }

    /// A charset parameter does not stop the JSON arm: the live read is `starts_with`, and a client
    /// that spells `application/json; charset=utf-8` is a client sending JSON.
    #[test]
    fn a_json_content_type_with_parameters_still_parses() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        let body = Bytes::from_static(br#"{"model":"m"}"#);
        assert!(arrival_body(&h, &body).expect("accepted").parsed.is_some());
    }

    // ── THE REFUSALS: the same refusal, and the same bytes ─────────────────────────────────────

    /// IDENTITY. A malformed body refuses with the live arm's own three values, rendered by the live
    /// shaper — so the bytes a client reads are the bytes the live path sends, in every registered
    /// dialect's own error shape.
    #[tokio::test]
    async fn a_malformed_body_refuses_with_the_live_arms_bytes() {
        registered();
        let body = Bytes::from_static(b"{ this is not json");
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            // Body-model.
            let refusal = arrival_body(&json_headers(), &body).expect_err("must refuse");
            assert_eq!(refusal, ArrivalRefusal::BodyParse);
            // Path-model, same bytes, same refusal.
            assert_eq!(
                arrival_path_model(&body, "m", false, false, proto).expect_err("must refuse"),
                ArrivalRefusal::BodyParse
            );
            // The live arm's literals, spelled here so a change to either side is a red test.
            let live = busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            );
            assert_eq!(
                seen(render_refusal(proto, &refusal.outcome())).await,
                seen(live).await,
                "{proto}: the step's parse refusal is not the live path's"
            );
        }
    }

    /// IDENTITY. A body that is JSON but not a document refuses on the path-model path with the live
    /// arm's own bytes — a different sentence from the parse refusal, and the difference matters to
    /// a client trying to fix its request.
    #[tokio::test]
    async fn a_non_object_body_refuses_with_the_live_arms_bytes() {
        registered();
        for body in [
            Bytes::from_static(b"[]"),
            Bytes::from_static(b"\"a string\""),
            Bytes::from_static(b"7"),
        ] {
            for proto in busbar_substrate::proto::known_protocols().iter().copied() {
                let refusal =
                    arrival_path_model(&body, "m", false, false, proto).expect_err("must refuse");
                assert_eq!(refusal, ArrivalRefusal::NotAnObject);
                let live = busbar_substrate::proxy::ingress_error(
                    proto,
                    StatusCode::BAD_REQUEST,
                    KIND_INVALID_REQUEST,
                    "Request body must be a JSON object.",
                );
                assert_eq!(
                    seen(render_refusal(proto, &refusal.outcome())).await,
                    seen(live).await,
                    "{proto}: the step's non-object refusal is not the live path's"
                );
            }
        }
    }

    /// IDENTITY. The re-serialization guard, which is effectively unreachable on the request path
    /// and is therefore pinned by its rendering rather than by reaching it: the sentence and the
    /// shape are the live arm's.
    #[tokio::test]
    async fn the_reserialize_guard_renders_the_live_arms_bytes() {
        registered();
        for proto in busbar_substrate::proto::known_protocols().iter().copied() {
            let live = busbar_substrate::proxy::ingress_error(
                proto,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "The request body could not be processed.",
            );
            assert_eq!(
                seen(render_refusal(
                    proto,
                    &ArrivalRefusal::Reserialize.outcome()
                ))
                .await,
                seen(live).await,
                "{proto}: the step's reserialize refusal is not the live path's"
            );
        }
    }

    /// IDENTITY, THE WHOLE SET, THROUGH THE TERMINAL. Every refusal this step can produce, in every
    /// registered dialect, rendered the way the loop will actually render it — the named outcome
    /// handed to the audit step — is byte-for-byte the response the legacy arm built directly.
    ///
    /// The three tests above each pin ONE refusal; this one pins that the set has no member that
    /// escaped them, and pins the path rather than the values: if a refusal ever grew a header of its
    /// own, or the terminal ever shaped an envelope of its own, the two sides would part here.
    #[tokio::test]
    async fn every_arrival_refusal_renders_through_audit_to_the_legacy_bytes() {
        registered();
        // The refusal, and the (status, kind, message) triple the legacy arm passed to the shaper —
        // spelled out at the call rather than read back off the refusal, so a change to either side
        // is a red test rather than a tautology.
        let cases = [
            (
                ArrivalRefusal::BodyParse,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            ),
            (
                ArrivalRefusal::NotAnObject,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "Request body must be a JSON object.",
            ),
            (
                ArrivalRefusal::Reserialize,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "The request body could not be processed.",
            ),
        ];
        assert_eq!(cases.len(), 3, "the closed set grew without a case here");
        // Every registered dialect, and one that is not registered at all: a plane with no dialect
        // linked still has to answer, and the neutral envelope is as much the legacy path's as the
        // dialect-shaped ones are.
        let mut protos: Vec<&str> = busbar_substrate::proto::known_protocols().to_vec();
        protos.push("no-such-protocol");
        for proto in protos {
            for (refusal, status, kind, message) in cases {
                let legacy = busbar_substrate::proxy::ingress_error(proto, status, kind, message);
                assert_eq!(
                    seen(render_refusal(proto, &refusal.outcome())).await,
                    seen(legacy).await,
                    "{proto}: {refusal:?} rendered through the terminal is not the legacy bytes"
                );
                // And the value itself carries no header of its own, which is why the two sides can
                // be equal at all.
                assert!(
                    refusal.outcome().headers().is_empty(),
                    "{refusal:?} grew a header with nothing pinning it"
                );
            }
        }
    }

    /// THE SET IS CLOSED, AND ITS MEMBERS ARE DISTINGUISHABLE. Three reasons, three sentences, one
    /// status, one kind. A fourth reason added without a sentence of its own would collide here.
    #[test]
    fn the_refusal_set_is_three_and_they_do_not_collide() {
        let all = [
            ArrivalRefusal::BodyParse,
            ArrivalRefusal::NotAnObject,
            ArrivalRefusal::Reserialize,
        ];
        let mut messages: Vec<&str> = all.iter().map(|r| r.message()).collect();
        messages.sort_unstable();
        messages.dedup();
        assert_eq!(messages.len(), all.len(), "two reasons share one sentence");
        for r in all {
            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            assert_eq!(r.kind(), KIND_INVALID_REQUEST);
        }
    }

    /// A refusal in an unregistered dialect still renders. Deleting every LLM dialect must leave an
    /// honest neutral envelope, not a panic and not an empty body.
    #[tokio::test]
    async fn a_refusal_renders_even_with_no_dialect_registered() {
        let (status, _headers, body) = seen(render_refusal(
            "no-such-protocol",
            &ArrivalRefusal::BodyParse.outcome(),
        ))
        .await;
        assert_eq!(status, 400);
        assert!(
            !body.is_empty(),
            "an unregistered dialect must still get an envelope"
        );
    }
}
