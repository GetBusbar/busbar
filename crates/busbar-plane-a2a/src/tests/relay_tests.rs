// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unary hop, piece by piece: the request each attempt sends, the body relayed verbatim, and
//! the caller's answer in the served engine's bytes (`busbar-a2a` `relay`, `refusal_client`,
//! `receive::refuse_hop_early`).

use super::*;
use serde_json::json;

const URL: &str = "https://vendor.example/a2a/v1?tenant=t1";
const ASK: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard"}"#;

fn kernel(url: Option<&str>) -> Piece<'_> {
    Piece {
        from: From::Kernel(url),
        bytes: &[],
        status: None,
        last: false,
    }
}

fn caller(bytes: &[u8]) -> Piece<'_> {
    Piece {
        from: From::Caller,
        bytes,
        status: None,
        last: true,
    }
}

fn far(status: Option<u32>, bytes: &[u8], last: bool) -> Piece<'_> {
    Piece {
        from: From::FarEnd,
        bytes,
        status,
        last,
    }
}

/// A hop through its attempt and the caller's body, waiting on the far end.
fn sent() -> Relay {
    let mut r = Relay::new(json!(7), "1.0");
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    assert_eq!(r.on_piece(caller(ASK)), Answer::ToFarEnd(ASK.to_vec()));
    r
}

fn answered(r: &mut Relay, status: u32, body: &[u8]) -> Reply {
    match r.on_piece(far(Some(status), body, true)) {
        Answer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    }
}

/// The engine's refused-hop body for `code` and `sentence`, under id 7.
fn refused(code: &str, sentence: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {
            "code": -32006,
            "message": format!("{code}: {sentence}"),
            "data": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": "a2a-protocol.org",
                "reason": "INVALID_AGENT_RESPONSE",
            }],
        },
    }))
    .expect("json")
}

#[test]
fn an_attempt_posts_to_the_agents_own_path_with_the_engines_three_fields_in_order() {
    let mut r = Relay::new(json!(7), "1.0");
    assert_eq!(
        r.on_piece(kernel(Some(URL))),
        Answer::Attempt(Attempt {
            verb: "POST",
            target: "/a2a/v1?tenant=t1".to_string(),
            fields: vec![
                ("content-type", "application/json".to_string()),
                ("accept", "application/json".to_string()),
                ("a2a-version", "1.0".to_string()),
            ],
        })
    );
}

#[test]
fn an_agent_url_with_no_path_is_posted_to_at_its_root() {
    assert_eq!(target_of("https://vendor.example").as_deref(), Some("/"));
    assert_eq!(target_of("not a url"), None);
}

#[test]
fn an_attempt_at_an_agent_the_section_does_not_name_is_refused() {
    let mut r = Relay::new(json!(7), "0.3");
    assert_eq!(r.on_piece(kernel(None)), Answer::Refused);
}

#[test]
fn the_callers_body_reaches_the_far_end_verbatim() {
    let odd = br#"{ "jsonrpc" : "2.0", "id":7, "method":"GetExtendedAgentCard", "x":[1,2] }"#;
    let mut r = Relay::new(json!(7), "0.3");
    let _ = r.on_piece(kernel(Some(URL)));
    assert_eq!(r.on_piece(caller(odd)), Answer::ToFarEnd(odd.to_vec()));
}

#[test]
fn a_correlated_result_is_relayed_whole_under_the_callers_id() {
    let mut r = sent();
    assert_eq!(
        r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","id":7,"#, false)),
        Answer::Nothing
    );
    let reply = match r.on_piece(far(
        None,
        br#""result":{"name":"Vendor","skills":[]}}"#,
        true,
    )) {
        Answer::ToCaller(reply) => reply,
        other => panic!("no answer: {other:?}"),
    };
    assert_eq!(reply.status, 200);
    assert_eq!(reply.content_type, "application/json");
    let expected = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"name": "Vendor", "skills": []},
    }))
    .expect("json");
    assert_eq!(reply.body, expected);
    assert!(r.answered());
    assert_eq!(r.on_piece(far(None, b"late", true)), Answer::Nothing);
}

#[test]
fn a_status_outside_2xx_is_the_engines_backend_status_refusal() {
    let reply = answered(&mut sent(), 404, br#"{"jsonrpc":"2.0","id":7,"result":{}}"#);
    assert_eq!(reply.status, 502);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn an_answer_to_another_request_is_refused_not_relayed() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":8,"result":{"s":1}}"#,
    );
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_uncorrelated",
            "this agent's backend answered something busbar cannot correlate to the request it \
             sent, so it is refused rather than relayed"
        )
    );
}

#[test]
fn the_backends_own_error_is_refused_without_its_words() {
    let reply = answered(
        &mut sent(),
        200,
        br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"internal host db.vendor"}}"#,
    );
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_refused",
            "this agent's backend refused the request"
        )
    );
    assert!(!String::from_utf8_lossy(&reply.body).contains("db.vendor"));
}

#[test]
fn a_reply_that_is_not_a_json_rpc_answer_is_refused() {
    let sentence = "this agent's backend replied with something that is not a JSON-RPC answer";
    for body in [&b"<html>"[..], br#"{"id":7,"result":{}}"#] {
        let reply = answered(&mut sent(), 200, body);
        assert_eq!(reply.body, refused("a2a.hop.reply_not_json", sentence));
    }
}

#[test]
fn a_reply_over_the_ceiling_is_refused_and_a_refused_status_is_judged_first() {
    let mut big = br#"{"jsonrpc":"2.0","id":7,"result":""#.to_vec();
    big.resize(MAX_REPLY_BYTES + 10, b'a');
    let reply = answered(&mut sent(), 200, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.reply_too_large",
            "this agent's backend replied with more than the configured ceiling"
        )
    );
    let reply = answered(&mut sent(), 500, &big);
    assert_eq!(
        reply.body,
        refused(
            "a2a.hop.backend_status",
            "this agent's backend refused busbar's request"
        )
    );
}

#[test]
fn the_bytes_moved_count_both_ways_once_the_far_end_answers() {
    let mut r = sent();
    assert_eq!(r.moved(), 0, "nothing was exchanged yet");
    let body = br#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
    let _ = answered(&mut r, 200, body);
    assert_eq!(r.moved(), (ASK.len() + body.len()) as u64);
}

#[test]
fn a_new_attempt_forgets_the_previous_far_end() {
    let mut r = sent();
    let _ = r.on_piece(far(Some(200), br#"{"jsonrpc":"2.0","#, false));
    assert!(matches!(r.on_piece(kernel(Some(URL))), Answer::Attempt(_)));
    let _ = r.on_piece(caller(ASK));
    assert_eq!(r.moved(), 0);
    let reply = answered(&mut r, 200, br#"{"jsonrpc":"2.0","id":7,"result":1}"#);
    assert_eq!(reply.status, 200);
}

#[test]
fn a_last_far_end_piece_with_no_status_is_refused() {
    let mut r = sent();
    assert_eq!(r.on_piece(far(None, b"{}", true)), Answer::Refused);
}
