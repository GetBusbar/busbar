// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One JSON-RPC arrival decided in the served order, and its refusal rendered in the line's
//! dialect. The byte-for-byte pins against the engine's own answers live on the engine's side
//! (`busbar-a2a` `door_pin_tests`); these pin the order and the words.

use super::*;

/// A head with the given `content-type` and `a2a-version`.
fn head<'a>(
    ct: Option<&'a str>,
    version: Option<&'a str>,
) -> impl Fn(&str) -> Option<&'a str> + Copy {
    with_origin(None, ct, version)
}

/// A head with the given `origin`, `content-type` and `a2a-version`.
fn with_origin<'a>(
    origin: Option<&'a str>,
    ct: Option<&'a str>,
    version: Option<&'a str>,
) -> impl Fn(&str) -> Option<&'a str> + Copy {
    move |name: &str| match name {
        H_ORIGIN => origin,
        H_CONTENT_TYPE => ct,
        H_VERSION => version,
        _ => None,
    }
}

fn refused(d: Disposition) -> Refusal {
    match d {
        Disposition::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"SendMessage","params":{}}"#;

#[test]
fn the_media_type_is_judged_before_the_body_and_the_version() {
    // A wrong media type over a body that is not JSON and an unspoken version: the header is the
    // thing to fix, so the header is what is said.
    let r = refused(decide(b"not json", head(Some("text/plain"), Some("9.9"))));
    assert_eq!(r.status, 415);
    assert_eq!(r.code, CODE_CONTENT_TYPE_NOT_SUPPORTED);
    assert_eq!(r.id, None);
    assert_eq!(
        r.message,
        "this endpoint reads `application/json` and any `+json` media type; the request declared \
         `text/plain`"
    );
}

#[test]
fn a_json_media_type_in_any_spelling_is_read() {
    for ct in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/a2a+json",
        "application/vnd.x+JSON ; q=1",
    ] {
        assert!(
            matches!(
                decide(SEND, head(Some(ct), None)),
                Disposition::Request { .. }
            ),
            "{ct}"
        );
    }
    // No media type at all is not a wrong one.
    assert!(matches!(
        decide(SEND, head(None, None)),
        Disposition::Request { .. }
    ));
}

#[test]
fn the_version_is_negotiated_on_major_minor_and_absent_is_0_3() {
    let version = |v: Option<&str>| match decide(SEND, head(None, v)) {
        Disposition::Request { version, .. } => version,
        other => panic!("{other:?}"),
    };
    assert_eq!(version(None), "0.3");
    assert_eq!(version(Some("")), "0.3");
    assert_eq!(version(Some("  ")), "0.3");
    assert_eq!(version(Some("1.0")), "1.0");
    assert_eq!(version(Some("1.0.7")), "1.0");
    assert_eq!(version(Some(" 0.3 ")), "0.3");
    let r = refused(decide(SEND, head(None, Some(" 2.1 "))));
    assert_eq!(
        (r.status, r.code, r.id.clone()),
        (400, CODE_VERSION_NOT_SUPPORTED, None)
    );
    assert_eq!(
        r.message,
        "this endpoint speaks A2A 0.3 and 1.0; the request asked for `2.1`"
    );
}

#[test]
fn a_body_that_is_not_json_is_a_parse_refusal_with_no_id() {
    let r = refused(decide(b"{", head(None, None)));
    assert_eq!(
        r,
        Refusal {
            status: 400,
            id: None,
            code: -32700,
            message: NOT_JSON.to_string(),
        }
    );
}

#[test]
fn an_envelope_the_reader_refuses_echoes_the_id_it_could_read() {
    let batch = refused(decide(b"[]", head(None, None)));
    assert_eq!((batch.status, batch.code, batch.id), (400, -32600, None));
    let wrong_version = refused(decide(
        br#"{"jsonrpc":"1.0","id":"a","method":"SendMessage"}"#,
        head(None, None),
    ));
    let invalid = busbar_contract::jsonrpc::read(&serde_json::json!(
        {"jsonrpc":"1.0","id":"a","method":"SendMessage"}
    ))
    .expect_err("the reader refuses it");
    assert_eq!(wrong_version.code, invalid.code);
    assert_eq!(wrong_version.message, invalid.message);
    assert_eq!(
        wrong_version.id,
        (!invalid.id.is_null()).then_some(invalid.id)
    );
}

#[test]
fn a_notification_is_acknowledged_and_never_answered() {
    assert_eq!(
        decide(
            br#"{"jsonrpc":"2.0","method":"SendMessage"}"#,
            head(None, None)
        ),
        Disposition::Notice {
            method: "SendMessage".to_string()
        }
    );
}

#[test]
fn a_request_is_classed_by_its_row_and_an_unlisted_method_is_kept_verbatim() {
    match decide(SEND, head(None, Some("1.0"))) {
        Disposition::Request { row, id, version } => {
            assert_eq!(row.op, crate::ops::OP_MESSAGE_SEND);
            assert_eq!(id, serde_json::json!(7));
            assert_eq!(version, "1.0");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        decide(
            br#"{"jsonrpc":"2.0","id":"x","method":"vendor/Thing"}"#,
            head(None, None)
        ),
        Disposition::Unlisted {
            method: "vendor/Thing".to_string(),
            id: serde_json::json!("x"),
            version: "0.3",
        }
    );
}

#[test]
fn a_refused_arrivals_words_read_back_as_the_same_refusal() {
    for r in [
        Refusal {
            status: 415,
            id: None,
            code: -32005,
            message: "m `x`".to_string(),
        },
        Refusal {
            status: 400,
            id: Some(serde_json::json!("id-1")),
            code: -32600,
            message: "bad".to_string(),
        },
        Refusal {
            status: 400,
            id: Some(serde_json::json!(3)),
            code: -32600,
            message: String::new(),
        },
    ] {
        assert_eq!(Refusal::from_words(r.words().as_bytes()), Some(r.clone()));
    }
    assert_eq!(Refusal::from_words(b"not the plane's words"), None);
    assert_eq!(Refusal::from_words(br#"{"status":-1}"#), None);
}

#[test]
fn the_json_rpc_rendering_is_the_one_envelope_with_error_info_for_an_a2a_code() {
    let r = Refusal {
        status: 415,
        id: None,
        code: -32005,
        message: "m".to_string(),
    };
    let out = render(Dialect::JsonRpc, &r, true);
    assert_eq!(out.status, 415);
    assert_eq!(out.content_type, "application/json");
    let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("json");
    assert_eq!(
        doc,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32005,
                "message": "m",
                "data": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "domain": "a2a-protocol.org",
                    "reason": "CONTENT_TYPE_NOT_SUPPORTED",
                }],
            },
        })
    );
    // A JSON-RPC code of its own carries no ErrorInfo.
    let parse = refused(decide(b"{", head(None, None)));
    let doc: serde_json::Value =
        serde_json::from_slice(&render(Dialect::JsonRpc, &parse, true).body).expect("json");
    assert!(doc["error"].get("data").is_none());
}

#[test]
fn the_rest_rendering_is_the_aip193_document() {
    let r = Refusal {
        status: 400,
        id: Some(serde_json::json!(1)),
        code: -32009,
        message: "v".to_string(),
    };
    let doc: serde_json::Value =
        serde_json::from_slice(&render(Dialect::RestJson, &r, true).body).expect("json");
    assert_eq!(
        doc,
        serde_json::json!({"error": {
            "code": 400,
            "status": "UNIMPLEMENTED",
            "message": "v",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "VERSION_NOT_SUPPORTED",
            }],
        }})
    );
    // A code with no status of its own takes the HTTP status's name.
    let odd = Refusal {
        status: 429,
        id: None,
        code: -1,
        message: String::new(),
    };
    assert_eq!(odd.aip193()["error"]["status"], "RESOURCE_EXHAUSTED");
}

#[test]
fn a_kernel_refusal_keeps_the_kernels_status_and_is_worded_as_an_unsupported_operation() {
    let r = kernel_refusal(403, "this key may not reach that agent");
    let out = render(Dialect::JsonRpc, &r, false);
    assert_eq!(out.status, 0, "the kernel's status stands");
    let doc: serde_json::Value = serde_json::from_slice(&out.body).expect("json");
    assert_eq!(doc["id"], serde_json::Value::Null);
    assert_eq!(doc["error"]["code"], -32004);
    assert_eq!(doc["error"]["message"], "this key may not reach that agent");
    assert_eq!(doc["error"]["data"][0]["reason"], "UNSUPPORTED_OPERATION");
}

/// THE WORDS NEVER OVERFLOW THE ABI CAP (spec ruling log 2026-09-30, new-plane refusals follow
/// predev bytes): a refusal that echoes a field line of the largest size a transport admits, made
/// of the characters JSON escapes, still fits `MAX_REFUSAL_TEXT`, and reads back whole.
#[test]
fn the_words_of_a_head_refusal_echoing_the_largest_admitted_field_line_fit_the_abi_cap() {
    use busbar_contract::abi::plane::{LARGEST_ADMITTED_FIELD_LINE, MAX_REFUSAL_TEXT};
    let line = |name: &str, c: char| {
        c.to_string()
            .repeat(LARGEST_ADMITTED_FIELD_LINE as usize - name.len() - 2)
    };
    let (quotes, slashes) = (line(H_CONTENT_TYPE, '"'), line(H_VERSION, '\\'));
    for r in [
        refused(decide(b"", head(Some(&quotes), None))),
        refused(decide(b"", head(None, Some(&slashes)))),
    ] {
        let words = r.words();
        assert!(
            words.len() as u64 <= MAX_REFUSAL_TEXT,
            "{} > {MAX_REFUSAL_TEXT}",
            words.len()
        );
        assert_eq!(Refusal::from_words(words.as_bytes()), Some(r));
    }
}

/// AN `Origin` IS JUDGED FIRST, as the engine's sequence judged it before every request-line rule:
/// a non-loopback origin over a wrong media type, an unspoken version and a body that is not JSON
/// is refused for its origin, `403` + `-32004`, no id.
#[test]
fn an_origin_that_is_not_loopback_is_refused_before_every_other_rule() {
    for origin in [
        "http://evil.example",
        "null",
        "file://x",
        "https://localhost.evil.example",
    ] {
        let r = refused(decide(
            b"not json",
            with_origin(Some(origin), Some("text/plain"), Some("9.9")),
        ));
        assert_eq!(
            r,
            Refusal {
                status: STATUS_FORBIDDEN,
                id: None,
                code: CODE_UNSUPPORTED_OPERATION,
                message: ORIGIN_REFUSED.to_string(),
            },
            "{origin}"
        );
    }
    for origin in [
        "http://localhost",
        "http://127.0.0.1:8080",
        "https://[::1]:3000",
    ] {
        assert!(
            matches!(
                decide(SEND, with_origin(Some(origin), None, None)),
                Disposition::Request { .. }
            ),
            "{origin}"
        );
    }
}

/// A METHOD THE VOCABULARY DOES NOT LIST IS RELAYED, NEVER REFUSED: classed as the hop the engine
/// relays it on, a request or a notification alike.
#[test]
fn an_unlisted_method_is_classed_as_the_hop_the_engine_relays_it_on() {
    use crate::ops::{OP_MESSAGE_SEND, OP_MESSAGE_STREAM, OP_TASK_GET};
    for (method, op) in [
        ("vendor/Thing", OP_MESSAGE_SEND),
        ("Frobnicate", OP_MESSAGE_SEND),
        ("vendor/stream", OP_MESSAGE_STREAM),
        ("tasks/get", OP_TASK_GET),
    ] {
        let request = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
        let notice = format!(r#"{{"jsonrpc":"2.0","method":"{method}"}}"#);
        for body in [request, notice] {
            assert_eq!(
                decide(body.as_bytes(), head(None, None)).op_class(),
                Some(op),
                "{body}"
            );
        }
    }
    assert_eq!(
        Disposition::Refused(refused(decide(b"{", head(None, None)))).op_class(),
        None
    );
}

/// THE gRPC LINE'S RENDERING is the JSON-RPC envelope at the refusal's neutral status, the bytes
/// the grpc transport maps to `grpc-status`; a kernel refusal keeps the kernel's status.
#[test]
fn the_grpc_rendering_is_the_envelope_at_the_neutral_status() {
    let own = refused(decide(b"", head(Some("text/plain"), None)));
    assert_eq!(
        render(Dialect::Framed, &own, true),
        render(Dialect::JsonRpc, &own, true)
    );
    assert_eq!(render(Dialect::Framed, &own, true).status, 415);
    let kernel = kernel_refusal(429, "this key's budget is spent");
    let out = render(Dialect::Framed, &kernel, false);
    assert_eq!(out.status, 0);
    assert_eq!(out, render(Dialect::JsonRpc, &kernel, false));
}
