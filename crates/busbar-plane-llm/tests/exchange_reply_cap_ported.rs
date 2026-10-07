// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far end's answer against the translation cap, ported from the legacy engine's tests before
//! that crate is deleted. This test binary's host holds a 4 KiB cap (the legacy tests installed the
//! same small cap), so an over-cap body need not be large; it is its own binary because the cap
//! reader is installed once per process.

use busbar_contract::operation::OpVerb;
use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::attempt::stream_intent;
use busbar_plane_llm::exchange::reply::{At, Fault, Reply, ReplyCtx, Units, Verdict};
use busbar_plane_llm::exchange::shaping::Lane;
use serde_json::{json, Value};

/// The cap this binary's host holds.
const CAP: usize = 4096;

const AT: At = At {
    now_s: 1_752_000_000,
    elapsed_ms: Some(3),
};

/// The host's seams: the small cap, and entropy for a dialect that mints an id.
fn host() {
    busbar_contract::codec::install_translate_cap_reader(|| CAP);
    busbar_contract::codec::install_entropy_source(|out| {
        out.fill(7);
        true
    });
    assert_eq!(busbar_contract::codec::max_translate_body_bytes(), CAP);
}

fn lane(dialect: &'static str) -> Lane {
    Lane {
        model: "m0".to_string(),
        provider: "p".to_string(),
        dialect,
        path: None,
        path_base: None,
        organization: None,
        project: None,
        upstream_model: None,
        default_max_tokens: None,
        context_max: None,
        reasoning: false,
        prompt_caching: false,
        caps: Default::default(),
        error_map: Default::default(),
        statics: &[],
    }
}

fn arrival(dialect: &str) -> Arrived {
    let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
    fields.push((b"content-type", b"application/json"));
    let (target, body): (&str, Value) = match dialect {
        "openai" => (
            "/v1/chat/completions",
            json!({"model": "p", "messages": [{"role": "user", "content": "hi"}]}),
        ),
        "anthropic" => {
            fields.push((b"anthropic-version", b"2023-06-01"));
            (
                "/v1/messages",
                json!({"model": "p", "max_tokens": 16,
                    "messages": [{"role": "user", "content": "hi"}]}),
            )
        }
        other => panic!("{other}"),
    };
    let bytes = serde_json::to_vec(&body).unwrap();
    arrive("POST", target, &fields, &bytes, &()).expect("an arrival")
}

/// What the caller read of an answer fed in `pieces`.
struct Read {
    status: u16,
    body: Vec<u8>,
    units: Units,
    verdict: Verdict,
    fault: Option<Fault>,
    done: bool,
}

fn answer(arrived: &Arrived, egress: &'static str, pieces: &[&[u8]]) -> Read {
    let lane = lane(egress);
    let handler = busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == arrived.dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("chat");
    let ctx = ReplyCtx {
        arrived,
        lane: &lane,
        intent: stream_intent(handler, arrived.parsed.as_ref()),
        passthrough: false,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(&ctx, 200, head);
    let mut read = Read {
        status: 0,
        body: Vec::new(),
        units: Units::default(),
        verdict: Verdict::None,
        fault: None,
        done: false,
    };
    for (i, p) in pieces.iter().enumerate() {
        let piece = reply.feed(&ctx, p, i + 1 == pieces.len(), AT);
        if let Some(h) = piece.head {
            read.status = h.status;
        }
        read.body.extend_from_slice(&piece.bytes);
        read.units = piece.units;
        read.verdict = piece.verdict;
        read.fault = piece.fault;
        read.done = piece.done;
        if piece.done {
            break;
        }
    }
    read
}

/// An OpenAI chat answer whose content is `filler`, its usage (600 in, 400 out) before the choices
/// when `usage_first`, else after them as every dialect writes it.
fn openai_answer(filler: &str, usage_first: bool) -> String {
    let usage = r#""usage":{"prompt_tokens":600,"completion_tokens":400}"#;
    let choices = format!(
        r#""choices":[{{"index":0,"message":{{"role":"assistant","content":"{filler}"}},"finish_reason":"stop"}}]"#
    );
    if usage_first {
        format!(r#"{{"id":"chatcmpl-huge","object":"chat.completion",{usage},{choices}}}"#)
    } else {
        format!(r#"{{"id":"chatcmpl-huge","object":"chat.completion",{choices},{usage}}}"#)
    }
}

/// A same-dialect body far over the cap relays to the caller whole and byte for byte, and its
/// trailing usage is still read (the kept copy is anchored at the tail): 600 in, 400 out. Ports
/// legacy
/// `ingress_indistinguishability_tests.rs::test_same_protocol_nonstream_over_cap_body_still_bills_tail_usage`.
#[test]
fn a_relayed_body_over_the_cap_still_bills_its_trailing_usage() {
    host();
    let body = openai_answer(&"x".repeat(CAP * 3), false);
    assert!(body.len() > CAP * 2);
    let pieces: Vec<&[u8]> = body.as_bytes().chunks(512).collect();
    let r = answer(&arrival("openai"), "openai", &pieces);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body.as_bytes(), "the whole body, verbatim");
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (600, 400));
    assert_eq!((r.verdict, r.fault), (Verdict::Ok, None));
}

/// A same-dialect body over the cap whose usage fell out of the kept tail (it came first) bills the
/// floor over the kept tail, `CAP / 4` output tokens, never 0; the caller still reads the whole
/// body. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_truncated_beyond_recovery_bills_nonzero_floor_not_zero`.
#[test]
fn a_relayed_body_over_the_cap_whose_usage_is_lost_bills_the_floor() {
    host();
    let body = openai_answer(&"x".repeat(CAP * 3), true);
    let pieces: Vec<&[u8]> = body.as_bytes().chunks(512).collect();
    let r = answer(&arrival("openai"), "openai", &pieces);
    assert_eq!(r.body, body.as_bytes());
    let floor = CAP as u64 / busbar_plane_llm::codec::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN;
    assert!(r.units.tokens_in + r.units.tokens_out > 0, "never 0");
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (0, floor));
}

/// An answer to translate that is over the cap is the caller's 500 at once: our limit, not the far
/// end's fault, so no fault is recorded and nothing is charged; the far end served, and the budget
/// unit its success spent is the kernel's to keep. Ports the plane half of legacy
/// `ingress_indistinguishability_tests.rs::test_truncated_body_does_not_refund_budget`.
#[test]
fn an_answer_to_translate_over_the_cap_is_a_500_with_no_fault() {
    host();
    let body = openai_answer(&"x".repeat(CAP + 1024), false).replace("400}", "999999}");
    let r = answer(&arrival("anthropic"), "openai", &[body.as_bytes()]);
    assert_eq!(r.status, 500);
    assert!(r.done);
    assert_eq!(r.verdict, Verdict::Hard);
    assert_eq!(r.fault, None, "our cap, not the far end's fault");
    assert_eq!(r.units, Units::default());
}

/// The cap is held to the byte: an answer of exactly the cap is translated and delivered; one byte
/// more is over the cap. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_read_capped_enforces_cap_exactly_and_reports_truncated`.
#[test]
fn the_cap_admits_exactly_its_bytes() {
    host();
    let bare = openai_answer("", false);
    let at_cap = openai_answer(&"y".repeat(CAP - bare.len()), false);
    assert_eq!(at_cap.len(), CAP);
    let pieces: Vec<&[u8]> = at_cap.as_bytes().chunks(1000).collect();
    let r = answer(&arrival("anthropic"), "openai", &pieces);
    assert_eq!(r.status, 200, "exactly the cap is admitted");
    assert_eq!(r.verdict, Verdict::Ok);

    let over = openai_answer(&"y".repeat(CAP - bare.len() + 1), false);
    assert_eq!(over.len(), CAP + 1);
    let pieces: Vec<&[u8]> = over.as_bytes().chunks(1000).collect();
    let r = answer(&arrival("anthropic"), "openai", &pieces);
    assert_eq!(r.status, 500, "one byte more is over the cap");
    assert_eq!((r.verdict, r.fault), (Verdict::Hard, None));
}
