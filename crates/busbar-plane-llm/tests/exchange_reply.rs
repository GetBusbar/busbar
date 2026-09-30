// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far end's answer, sans I/O: a far-end error judged, a whole answer translated, a relayed
//! answer, and the reply that drives them, through the public API.

use std::collections::HashMap;

use busbar_contract::operation::OpVerb;
use busbar_contract::upstream::{Disposition, RawUpstreamError, StatusClass};
use busbar_plane_llm::exchange::reply::failure::{
    auth_failure, judge, normalize, relay_verbatim, FarError,
};
use busbar_plane_llm::exchange::reply::wire::head_field;
use serde_json::Value;

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

fn raw(status: u16, code: Option<&str>, ty: Option<&str>) -> RawUpstreamError {
    let mut r = RawUpstreamError::from_status(status);
    r.provider_code = code.map(str::to_string);
    r.structured_type = ty.map(str::to_string);
    r
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn field<'a>(fields: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}

/// A dialect may declare a relayed head field the way its vendor spells it; the caller reads the
/// wire (lower-case) form, and a name that is no legal field name is dropped, never fatal.
#[test]
fn a_declared_head_field_name_is_lowered_and_an_illegal_one_dropped() {
    let (name, value) = head_field("x-amzn-RequestId", b"req-1").expect("a legal name");
    assert_eq!(name, "x-amzn-requestid");
    assert_eq!(value, b"req-1");
    assert_eq!(
        head_field("x-amzn-requestid", b"req-1").map(|f| f.0),
        Some(name)
    );
    for illegal in ["x amzn requestid", "x-amzn-\u{1f600}", ""] {
        assert!(head_field(illegal, b"v").is_none(), "{illegal:?}");
    }
}

/// The class of a far-end error: a mapped code, the built-in context-length code on a request-size
/// status only, a mapped structured type, and the status; `context_length` never masks a 5xx.
#[test]
fn a_far_end_error_is_placed_in_its_class() {
    let em = map(&[
        ("1302", "rate_limit"),
        ("quota", "billing"),
        ("ctx", "context_length"),
        ("typo", "rate_limt"),
        ("overloaded_error", "overloaded"),
    ]);
    let cases: &[(u16, Option<&str>, Option<&str>, StatusClass)] = &[
        (400, Some("1302"), None, StatusClass::RateLimit),
        (402, Some("quota"), None, StatusClass::Billing),
        (400, Some("ctx"), None, StatusClass::ContextLength),
        (503, Some("ctx"), None, StatusClass::ServerError),
        (
            400,
            Some("context_length_exceeded"),
            None,
            StatusClass::ContextLength,
        ),
        (
            413,
            Some("context_length_exceeded"),
            None,
            StatusClass::ContextLength,
        ),
        (
            401,
            Some("context_length_exceeded"),
            None,
            StatusClass::Auth,
        ),
        (400, Some("typo"), None, StatusClass::ClientError),
        (500, None, Some("overloaded_error"), StatusClass::Overloaded),
        (503, None, Some("ctx"), StatusClass::ServerError),
        (401, None, None, StatusClass::Auth),
        (403, None, None, StatusClass::Auth),
        (429, None, None, StatusClass::RateLimit),
        (408, None, None, StatusClass::Timeout),
        (529, None, None, StatusClass::Overloaded),
        (502, None, None, StatusClass::ServerError),
        (404, None, None, StatusClass::ClientError),
        (302, None, None, StatusClass::ClientError),
    ];
    for &(status, code, ty, want) in cases {
        let r = raw(status, code, ty);
        assert_eq!(normalize(status, &r, &em).class, want, "{r:?}");
    }
    let sig = normalize(400, &raw(400, Some("1302"), None), &em);
    assert_eq!(sig.provider_signal.as_deref(), Some("1302"));
}

const JSON_HEAD: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];

/// A far-end error judged, for every dialect: a caller's own credential failing is relayed
/// unjudged; a client fault within one dialect is the far end's bytes, across dialects the
/// caller's envelope; the deployment's refused credential is the caller's own refusal; a transient
/// carries the relay the walk ends on.
#[test]
fn a_far_end_error_is_judged_for_every_pair() {
    let head = JSON_HEAD;
    let body = br#"{"error":{"message":"bad things","type":"invalid_request_error"}}"#;
    for ingress in SIX {
        for egress in SIX {
            let far = |status| FarError { status, head, body };
            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                true,
                &far(401),
            );
            assert_eq!(j.signal, None);
            assert_eq!(j.disposition, Disposition::ClientFault);
            assert_eq!(j.answer.status, 401);

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(400),
            );
            assert_eq!(
                j.disposition,
                Disposition::ClientFault,
                "{ingress}<-{egress}"
            );
            if ingress == egress {
                assert_eq!(j.answer.body, body, "{ingress}: verbatim");
                assert_eq!(
                    field(&j.answer.fields, "content-type"),
                    Some(b"application/json".as_slice())
                );
            } else {
                let v: Value = serde_json::from_slice(&j.answer.body).expect("JSON");
                assert!(
                    v.to_string().contains("bad things"),
                    "{ingress}<-{egress}: {v}"
                );
            }

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(401),
            );
            assert_eq!(j.disposition, Disposition::HardDown);
            assert_eq!(j.answer, auth_failure(ingress), "{ingress}<-{egress}");

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(503),
            );
            assert_eq!(j.disposition, Disposition::TransientUpstream);
            assert_eq!(j.answer.status, 503);
        }
    }
}

/// A caller that relays the far end's `x-amzn-*` fields reads them verbatim on a same-dialect
/// relay; any other caller reads the far end's own request id.
#[test]
fn a_verbatim_relay_carries_the_native_head_fields() {
    let head: &[(&[u8], &[u8])] = &[
        (b"Content-Type", b"application/json"),
        (b"x-amzn-requestid", b"amzn-1"),
        (b"x-amzn-errortype", b"ValidationException"),
        (b"request-id", b"req_1"),
    ];
    let far = FarError {
        status: 400,
        head,
        body: b"{}",
    };
    let bedrock = relay_verbatim("bedrock", &far);
    assert_eq!(
        field(&bedrock.fields, "x-amzn-requestid"),
        Some(b"amzn-1".as_slice())
    );
    assert_eq!(
        field(&bedrock.fields, "x-amzn-errortype"),
        Some(b"ValidationException".as_slice())
    );
    let anthropic = relay_verbatim("anthropic", &far);
    assert_eq!(
        field(&anthropic.fields, "request-id"),
        Some(b"req_1".as_slice())
    );
    let openai = relay_verbatim("openai", &far);
    assert_eq!(openai.fields.len(), 1, "{:?}", openai.fields);
}
