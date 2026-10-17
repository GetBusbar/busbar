// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/proxy/lazy_body.rs`.

use super::*;
use crate::test_support::{chat, LaneSpec, TestApp};
use serde_json::json;

/// The head projection must answer every captured-key point read EXACTLY as the full DOM does —
/// including missing fields, non-string models, non-bool streams, duplicate keys (last wins),
/// and non-object top levels.
#[test]
fn head_matches_dom_for_captured_keys() {
    crate::testkit::install_test_seams();
    let bodies: &[&str] = &[
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#,
        r#"{"model":"gpt-4o","stream":false,"system":"you are helpful"}"#,
        r#"{"messages":[]}"#,
        r#"{"model":42,"stream":"yes"}"#,
        r#"{"model":null,"system":""}"#,
        r#"{"model":"a","model":"b"}"#, // duplicate: last wins on both paths
        r#"{"__busbar_gemini_json_array":true,"contents":[]}"#,
        r#"{"system":{"nested":true},"stream":{"deep":[1,2]}}"#,
        r#"{"model":" gpt-4o "}"#, // whitespace preserved, never trimmed
        r#"[1,2,3]"#,
        r#""just a string""#,
        r#"42"#,
        r#"null"#,
        r#"true"#,
        r#"{}"#,
    ];
    for raw in bodies {
        let bytes = Bytes::from(raw.as_bytes().to_vec());
        let lazy = LazyBody::parse(&bytes).expect("valid JSON must head-parse");
        let dom: Value = busbar_plane_llm::codec::json::parse(&bytes).unwrap();
        for key in captured_head_keys() {
            assert_eq!(
                lazy.probe().get(key),
                dom.get(key),
                "head/DOM divergence for key {key:?} on body {raw}"
            );
        }
    }
}

/// The head parse must accept/reject EXACTLY the same inputs as the old eager DOM parse —
/// the malformed-body 400 contract is byte-identical.
#[test]
fn head_parse_rejects_iff_dom_parse_rejects() {
    crate::testkit::install_test_seams();
    let inputs: &[&[u8]] = &[
        b"{\"model\":\"m\"}",
        b"not json",
        b"{\"model\":",
        b"{\"model\":\"m\"} trailing",
        b"",
        b"{\"a\":1,}",
        b"{\"a\":00}",
        b"{\"a\":\"\\x\"}",
        b"\xff\xfe",
        b"{\"a\":\"\xff\"}", // invalid UTF-8 inside a string
        b"[1,2",
        b"{\"deep\":\"[[[[[ not depth, in a string\"}",
    ];
    for raw in inputs {
        let bytes = Bytes::copy_from_slice(raw);
        let dom_ok = busbar_plane_llm::codec::json::parse::<Value>(&bytes).is_ok();
        let head_ok = LazyBody::parse(&bytes).is_ok();
        assert_eq!(
            head_ok,
            dom_ok,
            "accept/reject divergence on input {:?}",
            String::from_utf8_lossy(raw)
        );
    }
    // The depth security floor holds on the head path too (no IgnoredAny recursion blowup).
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(LazyBody::parse(&Bytes::from(deep.into_bytes())).is_err());
}

/// Within one dialect a hop's body is the caller's bytes with the governed splices only (DIALECT
/// FIDELITY): an alias model is replaced where it stands, busbar's own router key is
/// removed, a path-model arrival's spliced `model`/`stream` come back out, and nothing else moves —
/// key order, spacing, number spelling and unknown members stay the caller's. A re-serialize (the
/// RED arm) would sort `z` after `a` and print `1.50` as `1.5`.
#[test]
fn a_same_dialect_hop_is_the_callers_bytes_with_governed_splices() {
    crate::testkit::install_test_seams();
    let shim = busbar_kernel::proto::array_stream_shim_key_for("gemini").expect("shim key");
    let shimmed = format!(r#"{{"model":"gpt-4o", "{shim}":true,"z":1.50,"a":[]}}"#);
    let cases: Vec<(&'static str, &'static str, &'static str, String, String)> = vec![
        (
            crate::proto_codec::PROTO_OPENAI,
            "openai",
            "gpt-4o-real",
            r#"{"z":1.50, "model":"alias","never_heard_of":{"y":1,"x":2},"messages":[]}"#.into(),
            r#"{"z":1.50, "model":"gpt-4o-real","never_heard_of":{"y":1,"x":2},"messages":[]}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_ANTHROPIC,
            "anthropic",
            "claude-3",
            r#"{"max_tokens":7,"model":"claude-3","messages":[],"zz":{"b":1,"a":2}}"#.into(),
            r#"{"max_tokens":7,"model":"claude-3","messages":[],"zz":{"b":1,"a":2}}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_OPENAI,
            "openai",
            "gpt-4o",
            shimmed,
            r#"{"model":"gpt-4o","z":1.50,"a":[]}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_GEMINI,
            "gemini",
            "url-model-x",
            r#"{"model":"url-model-x","stream":false,"contents":[{"role":"user","parts":[{"text":"hi"}]}],"b":1,"a":2}"#.into(),
            r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"b":1,"a":2}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_COHERE,
            "cohere",
            "command-r",
            r#"{"zz_never_heard_of":[1.50,{"b":1,"a":2}], "model":"alias","messages":[]}"#.into(),
            r#"{"zz_never_heard_of":[1.50,{"b":1,"a":2}], "model":"command-r","messages":[]}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_RESPONSES,
            "responses",
            "gpt-4o",
            r#"{"input":"hi", "model":"gpt-4o","zz_never_heard_of":{"b":1,"a":2}}"#.into(),
            r#"{"input":"hi", "model":"gpt-4o","zz_never_heard_of":{"b":1,"a":2}}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_BEDROCK,
            "bedrock",
            "anthropic.claude",
            r#"{"model":"anthropic.claude","stream":true,"messages":[{"role":"user","content":[{"text":"hi"}]}], "zz_never_heard_of":{"b":1,"a":2}}"#.into(),
            r#"{"messages":[{"role":"user","content":[{"text":"hi"}]}], "zz_never_heard_of":{"b":1,"a":2}}"#.into(),
        ),
        (
            crate::proto_codec::PROTO_OPENAI,
            "openai",
            "m",
            "[1,2,3]".into(),
            "[1,2,3]".into(),
        ),
    ];
    for (proto, name, lane_model, carried, expected) in cases {
        let app = TestApp::new()
            .lane(LaneSpec::new(lane_model, proto, "http://unused.local"))
            .build();
        let hop_bytes = Bytes::from(carried.into_bytes());
        let (host, rt) = crate::engine::test_host_rt(&app);
        let out = translate_request_cross_protocol(
            &host,
            &rt,
            0,
            name,
            chat(name, busbar_contract::transport::transport::Transport::Http),
            None,
            APPLICATION_JSON,
            true,
            &hop_bytes,
            "test-key",
        )
        .expect("a same-dialect relay is infallible");
        assert_eq!(
            String::from_utf8_lossy(&out),
            expected,
            "{name}: only the governed members move"
        );
    }
}

/// Materialization round-trip: ensure_dom parses the same tree the eager path built, and a
/// mutation through ensure_dom is visible to subsequent probe() reads (DOM authoritative).
#[test]
fn ensure_dom_materializes_and_probe_tracks_mutation() {
    crate::testkit::install_test_seams();
    let bytes = Bytes::from(r#"{"model":"a","messages":[{"role":"user","content":"hi"}]}"#);
    let mut lazy = LazyBody::parse(&bytes).unwrap();
    assert_eq!(
        lazy.probe().get("model").and_then(|m| m.as_str()),
        Some("a")
    );
    let dom = lazy.ensure_dom().expect("validated bytes must re-parse");
    assert_eq!(
        *dom,
        busbar_plane_llm::codec::json::parse::<Value>(&bytes).unwrap()
    );
    dom.as_object_mut()
        .unwrap()
        .insert("model".into(), json!("b"));
    assert_eq!(
        lazy.probe().get("model").and_then(|m| m.as_str()),
        Some("b"),
        "probe must read the materialized (mutated) DOM, not the stale head"
    );
    assert_eq!(
        lazy.into_value().unwrap().get("model").unwrap(),
        &json!("b")
    );
}

/// The first user-turn text projected from a request's facts — the read these tests use to tell one
/// parse of a body from another. Reads through the neutral [`busbar_contract::ir::facts::IrFacts`] projection
/// (the first `user` turn's content items) rather than the concrete IR, mirroring `ensure_ir`'s
/// facts return.
fn first_user_text(ir: &(dyn busbar_contract::ir::facts::IrFacts + Send + Sync)) -> String {
    let items = ir.content();
    let Some(first) = items
        .iter()
        .find(|it| it.author() == "user")
        .and_then(|it| it.slot().turn_index())
    else {
        return String::new();
    };
    items
        .iter()
        .filter(|it| it.slot().turn_index() == Some(first))
        .map(|it| it.screenable_text().into_owned())
        .collect()
}

/// `ensure_ir` reads the body through the INGRESS operation's own handler, so the hook seam's view
/// and the cross-protocol translate path's view come from one parse. The in-band system turn is
/// folded into the IR's system prompt, which is the IR's reading and not the raw body's; the hook
/// view puts it back as a turn (1.5.5), so it does not count as a system FIELD.
#[test]
fn ensure_ir_reads_the_body_through_the_ingress_reader() {
    crate::testkit::install_test_seams();
    let bytes = Bytes::from(
        r#"{"model":"gpt-4o","messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hi"}]}"#,
    );
    let mut lazy = LazyBody::parse(&bytes).unwrap();
    let ir = lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .expect("a well-formed openai chat body must read into the IR");
    let shape = ir.shape();
    assert_eq!(
        shape.turn_count, 2,
        "the system turn counts as a wire turn, as 1.5.5 counted it"
    );
    assert_eq!(
        shape.system_chars, 0,
        "an in-band system turn is a turn, not the system field (1.5.5)"
    );
    assert_eq!(
        shape.text_chars,
        "be terse".len() + "hi".len(),
        "the folded system turn is read: its text is in the IR"
    );
    assert_eq!(first_user_text(ir), "hi");
}

/// One request costs one read: the memo is installed on the first call and returned on the second.
/// Pinned by MUTATING the materialized DOM behind the memo's back — a second read of the body would
/// see the mutation, a memo hit cannot.
#[test]
fn ensure_ir_is_memoized_within_one_request() {
    crate::testkit::install_test_seams();
    let bytes = Bytes::from(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let mut lazy = LazyBody::parse(&bytes).unwrap();
    assert!(lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .is_some());
    // Reach past `ensure_dom` (which would legitimately drop the memo) straight to the tree.
    match &mut lazy.body {
        Body::Dom(v) => {
            v["messages"][0]["content"] = json!("mutated");
        }
        Body::Head { .. } => panic!("ensure_ir must have materialized the DOM"),
    }
    let ir = lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .expect("the memo must still be present");
    assert_eq!(
        first_user_text(ir),
        "hi",
        "the second call must be a memo hit, not a re-read"
    );
}

/// Handing out a MUTABLE body drops the memo. This is the invariant that stops the two views of one
/// request from disagreeing: after a rewrite hook mutates the tree, the next IR read must see the
/// request as it now stands, never as it arrived.
#[test]
fn ensure_dom_invalidates_the_memoized_ir() {
    crate::testkit::install_test_seams();
    let bytes = Bytes::from(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let mut lazy = LazyBody::parse(&bytes).unwrap();
    assert!(lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .is_some());
    lazy.ensure_dom().unwrap()["messages"][0]["content"] = json!("rewritten");
    let ir = lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .expect("the IR must be re-readable after a rewrite");
    assert_eq!(
        first_user_text(ir),
        "rewritten",
        "an IR read after a mutation must reflect the mutation"
    );
}

/// A body the ingress reader REJECTS, and an unregistered ingress protocol, both yield `None` — the
/// caller falls back to what it does today rather than to a guess. Neither poisons the memo.
#[test]
fn ensure_ir_is_none_when_the_body_or_the_protocol_has_no_reading() {
    crate::testkit::install_test_seams();
    let unreadable = Bytes::from(r#"{"model":"gpt-4o","messages":"not an array"}"#);
    let mut lazy = LazyBody::parse(&unreadable).unwrap();
    assert!(lazy
        .ensure_ir(crate::proto_codec::PROTO_OPENAI, crate::test_support::CHAT)
        .is_none());

    let ok = Bytes::from(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#);
    let mut lazy = LazyBody::parse(&ok).unwrap();
    assert!(lazy
        .ensure_ir("no-such-protocol", crate::test_support::CHAT)
        .is_none());
}
