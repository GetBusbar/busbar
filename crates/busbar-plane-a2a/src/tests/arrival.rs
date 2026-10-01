// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One JSON-RPC arrival decided in the served order, and its refusal rendered in the line's
//! dialect. The byte-for-byte pins against the engine's own answers live on the engine's side
//! (`busbar-a2a` `door_pin_tests`); these pin the order and the words.

use super::*;

/// A head with the given `content-type` and `a2a-version`.
fn head<'a>(ct: Option<&'a str>, version: Option<&'a str>) -> impl Fn(&str) -> Option<&'a str> {
    move |name: &str| match name {
        H_CONTENT_TYPE => ct,
        H_VERSION => version,
        _ => None,
    }
}

fn refused(d: Decision) -> Refusal {
    match d {
        Decision::Refused(r) => r,
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
            matches!(decide(SEND, head(Some(ct), None)), Decision::Request { .. }),
            "{ct}"
        );
    }
    // No media type at all is not a wrong one.
    assert!(matches!(
        decide(SEND, head(None, None)),
        Decision::Request { .. }
    ));
}

#[test]
fn the_version_is_negotiated_on_major_minor_and_absent_is_0_3() {
    let version = |v: Option<&str>| match decide(SEND, head(None, v)) {
        Decision::Request { version, .. } => version,
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
        Decision::Notice {
            method: "SendMessage".to_string()
        }
    );
}

#[test]
fn a_request_is_classed_by_its_row_and_an_unlisted_method_is_kept_verbatim() {
    match decide(SEND, head(None, Some("1.0"))) {
        Decision::Request { row, id, version } => {
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
        Decision::Unlisted {
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

#[test]
fn the_words_of_every_head_refusal_fit_the_abi_cap_for_a_bounded_header() {
    let cap = busbar_contract::abi::plane::MAX_REFUSAL_TEXT as usize;
    let long = "x".repeat(1024);
    let ct = format!("text/{long}");
    for r in [
        refused(decide(b"", head(Some(&ct), None))),
        refused(decide(b"", head(None, Some(&long)))),
    ] {
        assert!(r.words().len() <= cap, "{}", r.words().len());
    }
}
