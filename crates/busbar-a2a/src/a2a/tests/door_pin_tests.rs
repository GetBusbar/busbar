// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE AND THE DOOR STATE THE SAME FACTS. While the engine still serves, its declaration,
//! its route table and its admin routes are written a second time in the door; these tests pin
//! the two equal, entry by entry, so neither drifts.

use super::*;
use busbar_contract::abi::mechanism::route::RouteAuth;

/// A fixture endpoint: the secure scheme and a reserved example host, spelled once.
fn endpoint(host: &str, rest: &str) -> String {
    format!("https://{host}.example{rest}")
}

#[test]
fn the_declaration_states_the_doors_nouns() {
    let d = &PLANE_DECLARATION;
    assert_eq!(d.scope_kinds, [door::SCOPE]);
    assert_eq!(d.subject_noun, config::SUBJECT_NOUN);
    assert_eq!(d.admin_noun, door::ADMIN_NOUN);
    assert_eq!(d.audit_kind, door::AUDIT_KIND);
    assert_eq!(d.card_signing_domain, Some(door::CARD_SIGNING_DOMAIN));
    assert_eq!(d.card_kid_prefix, Some(door::CARD_KID_PREFIX));
    assert_eq!(d.billable_classes.len(), 1);
    assert_eq!(d.billable_classes[0].family, door::BYTES_FAMILY);
    assert_eq!(d.fee_units, [door::FEE_PER_REQUEST]);
    assert_eq!(door::TAIL.record_kinds_len, d.record_kinds.len());
    assert_eq!(
        d.trust_keys.iter().map(|k| k.key).collect::<Vec<_>>(),
        config::TRUST_KEYS.iter().map(|k| k.key).collect::<Vec<_>>()
    );
    assert_eq!(door::TAIL.trust_keys_len, d.trust_keys.len());
    assert_eq!(
        d.caller_credential_refusal,
        Some(config::REFUSE_PASSTHROUGH_SECTION)
    );
    assert_eq!(
        door::TAIL.caller_credential_refusal.len,
        config::REFUSE_PASSTHROUGH_SECTION.len()
    );
}

#[test]
fn the_engines_routes_are_the_doors_routes_in_order() {
    let section = format!(
        r#"{{"planner": {{"url": "{}", "pin": {{"mechanism": "unpinned"}}}}}}"#,
        endpoint("vendor", "/planner")
    );
    let cfg = door::read_settings(section.as_bytes()).expect("a valid section");
    let plane = plane::A2aPlane::from_config(&cfg, Some(&endpoint("busbar", ""))).expect("a plane");
    let engine: Vec<(&str, String, bool)> = receive::a2a_routes(plane.as_ref())
        .iter()
        .map(|r| (r.method.as_str(), r.path.clone(), r.auth == RouteAuth::None))
        .collect();
    let door: Vec<(&str, String, bool)> = door::ROUTES
        .iter()
        .map(|r| (r.verb, r.target.to_string(), r.open))
        .collect();
    assert_eq!(engine, door);
}

#[test]
fn the_engines_admin_routes_are_the_doors_admin_verbs() {
    let engine: Vec<(&str, String)> = admin_routes(&())
        .iter()
        .map(|r| (r.method.as_str(), r.path.clone()))
        .collect();
    let door: Vec<(&str, String)> = door::ADMIN_VERBS
        .iter()
        .map(|(v, t)| (*v, (*t).to_string()))
        .collect();
    assert_eq!(engine, door);
}

#[test]
fn the_engines_openapi_fragment_keys_the_doors_admin_verbs() {
    let doc = openapi_fragment();
    let keys: Vec<&String> = doc.as_object().expect("an object").keys().collect();
    assert_eq!(keys.len(), door::ADMIN_VERBS.len());
    for (_, target) in door::ADMIN_VERBS {
        assert!(
            keys.iter().any(|k| k.ends_with(target)),
            "{target} is missing from {keys:?}"
        );
    }
}

/// A response's status, `content-type` and body.
fn answered(resp: axum::response::Response) -> (u16, String, Vec<u8>) {
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
        .expect("a body");
    (status, ct, body.to_vec())
}

/// The door's rendering of a refusal it made itself, as the same three facts.
fn rendered(r: &busbar_plane_a2a::arrival::Refusal) -> (u16, String, Vec<u8>) {
    let out = busbar_plane_a2a::arrival::render(
        busbar_plane_a2a::arrival::Dialect::JsonRpc,
        r,
        true,
    );
    (
        u16::try_from(out.status).expect("a status"),
        out.content_type.to_string(),
        out.body,
    )
}

/// THE DOOR'S HEAD REFUSALS ARE THE ENGINE'S, byte for byte: the media-type gate, then the
/// version gate, judged before the body, each with the engine's status, words and id.
#[test]
fn the_doors_head_refusals_are_the_engines() {
    let cases: &[(Option<&str>, Option<&str>)] = &[
        (Some("text/plain"), None),
        (Some("TEXT/HTML; charset=utf-8"), Some("9.9")),
        (Some("application/xml"), Some("1.0")),
        (None, Some("2.0")),
        (None, Some(" 1.1.4 ")),
        (None, Some("abc")),
        (Some("application/json; charset=utf-8"), Some("1.0.7")),
        (Some("application/a2a+json"), None),
        (None, Some("")),
        (None, None),
    ];
    for (ct, version) in cases {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(ct) = ct {
            headers.insert("content-type", ct.parse().expect("a header"));
        }
        if let Some(v) = version {
            headers.insert("a2a-version", v.parse().expect("a header"));
        }
        let engine = receive::Wire::from_headers(&headers)
            .refuse()
            .map(answered);
        let door = busbar_plane_a2a::arrival::head_refusal(|name| match name {
            "content-type" => *ct,
            "a2a-version" => *version,
            _ => None,
        })
        .err()
        .map(|r| rendered(&r));
        assert_eq!(door, engine, "content-type {ct:?}, a2a-version {version:?}");
    }
}

/// THE DOOR'S BODY REFUSALS ARE THE ENGINE'S: a body that is not JSON and every envelope the
/// shared reader refuses, in the words the engine's `A2aWords` gives them.
#[test]
fn the_doors_body_refusals_are_the_engines() {
    use busbar_kernel::ingress::protocol::{CoreRefusal, Words as _};
    let door = |body: &[u8]| match busbar_plane_a2a::arrival::decide(body, |_| None) {
        busbar_plane_a2a::arrival::Decision::Refused(r) => rendered(&r),
        other => panic!("the door did not refuse: {other:?}"),
    };
    assert_eq!(
        door(b"{not json"),
        answered(words::A2aWords.refuse(CoreRefusal::NotJson))
    );
    for body in [
        "[]",
        "7",
        r#"{"jsonrpc":"1.0","id":1,"method":"SendMessage"}"#,
        r#"{"jsonrpc":"2.0","id":"a"}"#,
        r#"{"jsonrpc":"2.0","id":true,"method":"SendMessage"}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"SendMessage"}"#,
        r#"{"jsonrpc":"2.0","id":"a","method":7}"#,
    ] {
        let value: serde_json::Value = serde_json::from_str(body).expect("json");
        let invalid = busbar_contract::jsonrpc::read(&value).expect_err("the reader refuses it");
        assert_eq!(
            door(body.as_bytes()),
            answered(words::A2aWords.refuse(CoreRefusal::InvalidEnvelope(&invalid))),
            "{body}"
        );
    }
}

/// A KERNEL REFUSAL the door renders is the engine's admission refusal: the kernel's status, the
/// engine's `-32004` words, no id.
#[test]
fn the_doors_kernel_refusal_is_the_engines_admission_words() {
    use busbar_kernel::ingress::protocol::{CoreRefusal, Words as _};
    for (status, text) in [
        (401_u16, "the key is not live"),
        (403, "this key's scopes do not reach that agent"),
        (429, "this key's budget is spent"),
    ] {
        let engine = answered(words::A2aWords.refuse(CoreRefusal::Admission {
            id: serde_json::Value::Null,
            status: axum::http::StatusCode::from_u16(status).expect("a status"),
            message: text.to_string(),
            reason: None,
        }));
        let out = busbar_plane_a2a::arrival::render(
            busbar_plane_a2a::arrival::Dialect::JsonRpc,
            &busbar_plane_a2a::arrival::kernel_refusal(u32::from(status), text),
            false,
        );
        assert_eq!(out.status, 0, "the kernel's status stands");
        assert_eq!(
            (status, out.content_type.to_string(), out.body),
            engine,
            "{status}"
        );
    }
}

/// THE REST LINE'S RENDERING IS THE ENGINE'S REFRAME: every error the JSON-RPC line can say, as
/// the AIP-193 document `rest::reframe` answers it with.
#[test]
fn the_doors_rest_rendering_is_the_engines_reframe() {
    for (status, code) in [
        (415_u32, -32005_i64),
        (400, -32009),
        (400, -32700),
        (400, -32600),
        (404, -32001),
        (409, -32002),
        (403, -32004),
        (429, -32004),
        (502, -32006),
        (500, -32603),
        (503, -1),
        (401, -1),
    ] {
        let r = busbar_plane_a2a::arrival::Refusal {
            status,
            id: None,
            code,
            message: "words".to_string(),
        };
        let engine = rpcerror::aip193(
            u16::try_from(status).expect("a status"),
            &r.envelope()["error"],
        );
        assert_eq!(r.aip193(), engine, "{status} {code}");
        let out = busbar_plane_a2a::arrival::render(
            busbar_plane_a2a::arrival::Dialect::RestJson,
            &r,
            true,
        );
        assert_eq!(out.body, serde_json::to_vec(&engine).expect("json"));
    }
    // The envelope's error object is the engine's `rpcerror::body` for every code it names.
    for code in [-32001_i64, -32005, -32009, -32600, -32601, -32602, -32603, -32700] {
        let err = rpcerror::A2aError::from_code(code).expect("a code");
        let r = busbar_plane_a2a::arrival::Refusal {
            status: 400,
            id: Some(serde_json::json!("i")),
            code,
            message: "m".to_string(),
        };
        assert_eq!(
            serde_json::to_vec(&r.envelope()).expect("json"),
            serde_json::to_vec(&rpcerror::body(&serde_json::json!("i"), err, "m")).expect("json"),
            "{code}"
        );
    }
}
