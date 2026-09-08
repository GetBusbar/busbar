//! Tests for `arrival.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
