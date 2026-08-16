// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/hooks/wire.rs`.

/// A hook-supplied multi-byte help/label/unit must cap at a CHAR
/// boundary, never panic (String::truncate takes bytes — 100 × '€' panicked the admin handler).
#[test]
fn status_metric_hints_cap_char_safe() {
    let long_euro = "€".repeat(400);
    let m = [
        serde_json::json!({"name": "ok_total", "type": "counter", "value": 1.0,
                                    "help": long_euro, "label": long_euro, "unit": long_euro}),
    ];
    let parsed = super::parse_status_metrics(&m);
    assert_eq!(parsed.len(), 1);
    let metric = &parsed[0];
    assert_eq!(metric.name, "ok_total");
    assert_eq!(
        metric.help.as_ref().unwrap().chars().count(),
        super::MAX_METRIC_HELP_CHARS
    );
    assert_eq!(
        metric.label.as_ref().unwrap().chars().count(),
        super::MAX_METRIC_LABEL_CHARS
    );
    assert_eq!(
        metric.unit.as_ref().unwrap().chars().count(),
        super::MAX_METRIC_UNIT_CHARS
    );
    // Out-of-vocabulary viz + non-finite max drop individually; the metric survives.
    let m2 = [
        serde_json::json!({"name": "g", "type": "gauge", "value": 0.5,
                                     "viz": "hologram", "max": f64::NAN}),
    ];
    let parsed2 = super::parse_status_metrics(&m2);
    assert_eq!(parsed2.len(), 1);
    assert!(parsed2[0].viz.is_none());
    assert!(parsed2[0].max.is_none());
}

/// The redesigned metric shape (the Headroom fit-test): a Prometheus-style ARRAY carrying
/// per-dimension LABELS, a HISTOGRAM distribution via quantiles, and an ESTIMATE with a CI —
/// the shapes a real plugin dashboard needs and the old flat map could not express. Malformed
/// optional members are dropped individually; the entry survives.
#[test]
fn status_metrics_labels_quantiles_and_estimates() {
    let m = [
        // Two entries share a NAME, differ by pool label (the per-pool breakdown).
        serde_json::json!({"name":"chars_saved_total","type":"counter","value":812000.0,
                               "labels":{"pool":"chat"}}),
        serde_json::json!({"name":"chars_saved_total","type":"counter","value":410000.0,
                               "labels":{"pool":"code","BAD KEY":"dropped"}}),
        // A histogram: value is the count, distribution rides quantiles; a >1 quantile drops.
        serde_json::json!({"name":"compress_ms","type":"histogram","value":900.0,
                               "quantiles":{"0.5":12.0,"0.95":34.0,"1.5":99.0,"x":1.0}}),
        // An estimate with a valid CI; a second with an INVERTED CI (both bounds dropped).
        serde_json::json!({"name":"dollars_saved","type":"gauge","value":31.2,
                               "estimated":true,"ci_low":27.7,"ci_high":35.7}),
        serde_json::json!({"name":"bad_ci","type":"gauge","value":1.0,
                               "ci_low":9.0,"ci_high":1.0}),
        // Whole-entry drops: bad name, unknown type.
        serde_json::json!({"name":"Bad Name","type":"counter","value":1.0}),
        serde_json::json!({"name":"weird","type":"summary","value":1.0}),
    ];
    let parsed = super::parse_status_metrics(&m);
    assert_eq!(parsed.len(), 5, "2 bad entries dropped whole");
    let by = |i: usize| &parsed[i];
    // Labels: valid key kept, out-of-charset key dropped.
    assert_eq!(by(0).labels.as_ref().unwrap()["pool"], "chat");
    assert_eq!(by(1).labels.as_ref().unwrap().len(), 1);
    assert!(!by(1).labels.as_ref().unwrap().contains_key("BAD KEY"));
    // Quantiles: probabilities in [0,1] with finite values kept; "1.5"/"x" dropped.
    let q = by(2).quantiles.as_ref().unwrap();
    assert_eq!(q.len(), 2);
    assert_eq!(q["0.95"], 34.0);
    // Estimate CI: valid pair kept; inverted pair fully dropped.
    assert_eq!(by(3).estimated, Some(true));
    assert_eq!((by(3).ci_low, by(3).ci_high), (Some(27.7), Some(35.7)));
    assert_eq!((by(4).ci_low, by(4).ci_high), (None, None));
}

/// Unlike labels/buckets, the `[0,1]` filter on quantile keys does not bound the COUNT —
/// "0.5001", "0.5002", ... are all distinct strings that all parse in range. A hostile or buggy
/// hook could otherwise mint an unbounded quantile map, defeating `scrape.rs`'s stated BOUNDED
/// scrape-output property (one Prometheus line per quantile per metric).
#[test]
fn status_metrics_caps_the_quantile_count() {
    let mut quantiles = serde_json::Map::new();
    for i in 1..=500 {
        quantiles.insert(format!("0.{i:04}"), serde_json::json!(1.0));
    }
    let m = [
        serde_json::json!({"name":"h","type":"histogram","value":1.0,
                                     "quantiles": quantiles}),
    ];
    let parsed = super::parse_status_metrics(&m);
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0].quantiles.as_ref().unwrap().len(),
        super::MAX_METRIC_LABELS,
        "quantile count must be capped exactly like labels and buckets"
    );
}

/// Native histogram `buckets` are validated like quantiles: a key must be `+Inf` or parse as a
/// finite `le` bound, a count must be finite and non-negative, and an all-bad map drops to
/// `None` (so the renderer never emits a malformed histogram).
#[test]
fn status_metrics_validates_native_buckets() {
    let m = [
        // Good bucket map: finite bounds + "+Inf" kept; NaN count, non-numeric key dropped.
        serde_json::json!({"name":"headroom_compression_ratio","type":"histogram","value":7.0,
                               "buckets":{"0.5":3.0,"1":7.0,"+Inf":7.0,
                                          "abc":1.0,"2":-2.0}}),
        // Every entry invalid => the whole buckets map drops to None.
        serde_json::json!({"name":"all_bad","type":"histogram","value":1.0,
                               "buckets":{"x":1.0,"y":-1.0}}),
    ];
    let parsed = super::parse_status_metrics(&m);
    assert_eq!(parsed.len(), 2);
    let good = parsed[0].buckets.as_ref().expect("valid buckets kept");
    assert_eq!(good.len(), 3, "3 valid bounds; bad key & neg-count dropped");
    assert_eq!(good["0.5"], 3.0);
    assert_eq!(good["+Inf"], 7.0);
    assert!(!good.contains_key("abc"), "non-numeric le key dropped");
    assert!(!good.contains_key("2"), "negative count dropped");
    assert!(
        parsed[1].buckets.is_none(),
        "all-invalid buckets map drops to None"
    );
}

use super::*;
use crate::hooks::{CallerIdentity, PromptProjection};

fn cand(idx: usize, tags: &'static [String]) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: Some("large"),
        cost_per_mtok: Some(3.0),
        tags,
        latency_ms: Some(42.0),
        available_concurrency: 4,
        budget_remaining: Some(1000),
        rate_headroom: Some(0.75),
        signals: Default::default(),
    }
}

fn req() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 2,
        tool_count: 0,
        has_tools: false,
        total_chars: 10,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
    }
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// The DEFAULT payload is shape-only and byte-stable: none of the opt-in keys (`system`,
/// `messages`, `user`) nor an empty `tags` may appear — an existing hook parsing strictly must
/// see the exact pre-opt-in contract.
#[test]
fn default_payload_omits_opt_in_keys() {
    let r = req();
    let cands = [cand(0, &[])];
    let c = ctx();
    let json = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
    for key in ["\"system\"", "\"messages\"", "\"user\"", "\"tags\""] {
        assert!(!json.contains(key), "default payload leaked {key}: {json}");
    }
}

/// With the opt-ins populated (as `forward` does behind `send_prompt`/`send_user`) and tags
/// declared, the payload carries all of them — and never any secret-shaped field.
#[test]
fn opt_in_payload_carries_prompt_identity_tags() {
    static TAGS: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| vec!["team-a".into(), "eu".into()]);
    let mut r = req();
    r.prompt = Some(PromptProjection {
        system: Some("be brief".into()),
        messages: vec![("user".into(), "hello world".into())],
    });
    r.identity = Some(CallerIdentity {
        key_id: Some("k-123".into()),
        key_name: Some("sales-team".into()),
        user: Some("alice@example.com".into()),
    });
    let cands = [cand(0, TAGS.as_slice())];
    let c = ctx();
    let json = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["request"]["system"], "be brief");
    assert_eq!(v["request"]["messages"][0]["role"], "user");
    assert_eq!(v["request"]["messages"][0]["text"], "hello world");
    assert_eq!(v["request"]["user"]["key_id"], "k-123");
    assert_eq!(v["request"]["user"]["key_name"], "sales-team");
    assert_eq!(v["request"]["user"]["user"], "alice@example.com");
    assert_eq!(v["candidates"][0]["tags"][0], "team-a");
    assert_eq!(v["candidates"][0]["tags"][1], "eu");
    // The identity projection is built from the key RECORD: no token/secret field exists.
    for key in ["\"token\"", "\"secret\"", "\"generation_hash\""] {
        assert!(!json.contains(key), "payload leaked {key}: {json}");
    }
}

/// `send_prompt` on + no system prompt: `messages` is PRESENT (possibly empty) so a hook can
/// distinguish "opted in, empty" from "not opted in"; `system` stays absent.
#[test]
fn opt_in_prompt_without_system_still_sends_messages() {
    let mut r = req();
    r.prompt = Some(PromptProjection {
        system: None,
        messages: vec![],
    });
    let cands = [cand(0, &[])];
    let c = ctx();
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap())
            .unwrap();
    assert!(v["request"].get("system").is_none());
    assert_eq!(v["request"]["messages"], serde_json::json!([]));
}

fn norm(json: &str) -> RoutingDecision {
    let parsed: HookResponse = serde_json::from_str(json).unwrap();
    let cands = [cand(0, &[]), cand(1, &[])];
    normalize(parsed, &cands)
}

/// A bare `{"reject":{}}` is a full-strength rejection with the defaults: 403 + generic message.
#[test]
fn reject_bare_uses_defaults() {
    match norm(r#"{"reject":{}}"#) {
        RoutingDecision::Reject { status, message } => {
            assert_eq!(status, 403);
            assert_eq!(message, REJECT_MESSAGE_DEFAULT);
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// A hook may only speak client errors: in-range statuses pass, everything else clamps to 403 —
/// including values that would not even FIT a u16 (70000, -1): the reject verb must stay a
/// rejection, never abort the reply parse and silently route the request.
#[test]
fn reject_status_clamps_to_4xx() {
    for (sent, want) in [
        (400, 400),
        (404, 404),
        (499, 499),
        (200, 403),
        (302, 403),
        (500, 403),
        (0, 403),
        (999, 403),
        (70000, 403),
        (-1, 403),
    ] {
        match norm(&format!(r#"{{"reject":{{"status":{sent}}}}}"#)) {
            RoutingDecision::Reject { status, .. } => {
                assert_eq!(status, want, "sent {sent}");
            }
            other => panic!("expected Reject for {sent}, got {other:?}"),
        }
    }
}

/// The reject message is sanitized: control chars (CRLF/log injection) stripped, length capped,
/// and a message that sanitizes to nothing falls back to the default.
#[test]
fn reject_message_is_sanitized() {
    match norm("{\"reject\":{\"message\":\"no\\r\\nSet-Cookie: x\\u0000!\"}}") {
        RoutingDecision::Reject { message, .. } => {
            assert_eq!(message, "noSet-Cookie: x!");
        }
        other => panic!("expected Reject, got {other:?}"),
    }
    let long = "x".repeat(1000);
    match norm(&format!(r#"{{"reject":{{"message":"{long}"}}}}"#)) {
        RoutingDecision::Reject { message, .. } => {
            assert_eq!(message.chars().count(), REJECT_MESSAGE_MAX_CHARS);
        }
        other => panic!("expected Reject, got {other:?}"),
    }
    match norm("{\"reject\":{\"message\":\"\\r\\n\\t\"}}") {
        RoutingDecision::Reject { message, .. } => {
            assert_eq!(message, REJECT_MESSAGE_DEFAULT);
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// `reject` wins over `order` AND `abstain`: a hook that says both meant reject.
#[test]
fn reject_takes_precedence() {
    for json in [
        r#"{"order":[1,0],"reject":{"status":451}}"#,
        r#"{"abstain":true,"reject":{"status":451}}"#,
    ] {
        match norm(json) {
            RoutingDecision::Reject { status, .. } => assert_eq!(status, 451),
            other => panic!("expected Reject for {json}, got {other:?}"),
        }
    }
}

/// The reject verb is FAIL-CLOSED: any malformed / non-object `reject` value still rejects with
/// the defaults (403 + canned message) — a hook that tried to say "reject" must never have its
/// request silently routed because a detail was mis-typed. The one explicit opt-out is
/// `reject: false` (and `null`, which parses as absent): those defer to `order`/`abstain`.
#[test]
fn reject_is_fail_closed_on_malformed_values() {
    for json in [
        r#"{"reject":true}"#,
        r#"{"reject":"nope"}"#,
        r#"{"reject":123}"#,
        r#"{"reject":[]}"#,
        r#"{"reject":{"status":"451"}}"#,
        r#"{"reject":{"status":451.5}}"#,
        r#"{"reject":{"message":123}}"#,
    ] {
        match norm(json) {
            RoutingDecision::Reject { status, message } => {
                assert_eq!(
                    status, 403,
                    "malformed reject must use the default status: {json}"
                );
                assert_eq!(message, REJECT_MESSAGE_DEFAULT, "for {json}");
            }
            other => panic!("expected fail-closed Reject for {json}, got {other:?}"),
        }
    }
    // The explicit opt-outs: false / null defer to the rest of the reply.
    assert!(matches!(
        norm(r#"{"order":[1,0],"reject":false}"#),
        RoutingDecision::Prefer(o) if o == vec![1, 0]
    ));
    assert!(matches!(
        norm(r#"{"order":[1,0],"reject":null}"#),
        RoutingDecision::Prefer(o) if o == vec![1, 0]
    ));
}

/// U+2028/U+2029 (line/paragraph separators — log-record splitters in several pipelines) AND
/// the invisible formatting chars (bidi overrides/isolates: terminal log-line spoofing;
/// zero-widths/BOM: hidden content) are stripped from the reject message.
#[test]
fn reject_message_strips_unicode_line_separators() {
    match norm("{\"reject\":{\"message\":\"a\\u2028b\\u2029c\"}}") {
        RoutingDecision::Reject { message, .. } => assert_eq!(message, "abc"),
        other => panic!("expected Reject, got {other:?}"),
    }
    // Bidi override + isolate + zero-width + BOM all stripped; visible text intact.
    match norm("{\"reject\":{\"message\":\"ok\\u202Espoof\\u2066x\\u200By\\uFEFFz\"}}") {
        RoutingDecision::Reject { message, .. } => assert_eq!(message, "okspoofxyz"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// PINS the "opted in, anonymous" wire shape: `send_user` on with an all-None identity emits
/// `"user": {}` (present but empty) — a hook detects the opt-in by the KEY's presence, so a
/// future skip-if-all-none "cleanup" would silently break that contract.
#[test]
fn anonymous_identity_emits_empty_user_object() {
    let mut r = req();
    r.identity = Some(CallerIdentity {
        key_id: None,
        key_name: None,
        user: None,
    });
    let cands = [cand(0, &[])];
    let c = ctx();
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap())
            .unwrap();
    assert_eq!(v["request"]["user"], serde_json::json!({}));
}

/// NDJSON framing invariant: prompt text containing literal newlines/control chars must stay
/// ONE serialized line — serde_json escapes them inside string values, and the socket
/// transport's whole framing rests on that. This is the tripwire against any future custom
/// serializer that would let a raw 0x0A reach the wire and desync the hook's line reader.
#[test]
fn opt_in_content_with_newlines_stays_one_line() {
    let mut r = req();
    r.prompt = Some(PromptProjection {
        system: Some("line1\nline2".into()),
        messages: vec![("user".into(), "a\nb\rc\u{2028}d".into())],
    });
    let cands = [cand(0, &[])];
    let c = ctx();
    let line = serde_json::to_string(&build(OP_DECIDE, &r, &cands, &c)).unwrap();
    assert!(
        !line.contains('\n') && !line.contains('\r'),
        "serialized hook payload must contain no raw newline bytes: {line}"
    );
    // And the content round-trips intact through a parse of that single line.
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["request"]["system"], "line1\nline2");
    assert_eq!(v["request"]["messages"][0]["text"], "a\nb\rc\u{2028}d");
}

/// The pre-reject behaviors are untouched: order normalizes, abstain abstains, `{}` abstains.
#[test]
fn non_reject_replies_unchanged() {
    assert!(matches!(
        norm(r#"{"order":[1,0]}"#),
        RoutingDecision::Prefer(o) if o == vec![1, 0]
    ));
    assert!(matches!(
        norm(r#"{"abstain":true}"#),
        RoutingDecision::Abstain
    ));
    assert!(matches!(norm(r#"{}"#), RoutingDecision::Abstain));
}

/// `normalize` maps `restrict` to `RoutingDecision::Restrict` with reject > restrict > order
/// precedence; a malformed restrict is fail-closed to an EMPTY tag set (→ on_empty downstream),
/// and `restrict: false` is the explicit opt-out.
#[test]
fn normalize_restrict_precedence_and_fail_closed() {
    // Well-formed restrict → the tags.
    match norm(r#"{"restrict":{"tags_any":["baa"]}}"#) {
        RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
        other => panic!("expected Restrict, got {other:?}"),
    }
    // reject WINS over a co-present restrict.
    assert!(matches!(
        norm(r#"{"reject":{"status":403},"restrict":{"tags_any":["baa"]}}"#),
        RoutingDecision::Reject { .. }
    ));
    // restrict WINS over a co-present order.
    assert!(matches!(
        norm(r#"{"restrict":{"tags_any":["x"]},"order":[0,1]}"#),
        RoutingDecision::Restrict { .. }
    ));
    // Malformed restrict → fail-closed empty tag set (→ on_empty), never allow-all/order.
    match norm(r#"{"restrict":{"tags_any":[]}}"#) {
        RoutingDecision::Restrict { tags_any } => assert!(tags_any.is_empty()),
        other => panic!("malformed restrict must stay Restrict (fail-closed), got {other:?}"),
    }
    // Explicit opt-out: `restrict: false` is NOT a restriction.
    assert!(matches!(
        norm(r#"{"restrict":false,"order":[1,0]}"#),
        RoutingDecision::Prefer(_)
    ));
}

/// `parse_restrict` is FAIL-CLOSED: a well-formed restrict yields the trimmed non-empty tags; any
/// malformed shape yields `None` (the caller routes to on_error, never allow-all).
#[test]
fn parse_restrict_is_fail_closed() {
    let ok = parse_restrict(&serde_json::json!({"tags_any": ["baa", " gpu ", ""]}))
        .expect("well-formed restrict parses");
    assert_eq!(ok.tags_any, vec!["baa".to_string(), "gpu".to_string()]);

    // Malformed → None (fail-closed): no tags_any, empty list, whitespace-only, non-array, non-object.
    assert!(parse_restrict(&serde_json::json!({})).is_none());
    assert!(parse_restrict(&serde_json::json!({"tags_any": []})).is_none());
    assert!(parse_restrict(&serde_json::json!({"tags_any": ["", "  "]})).is_none());
    assert!(parse_restrict(&serde_json::json!({"tags_any": "baa"})).is_none());
    assert!(parse_restrict(&serde_json::json!("baa")).is_none());
}

/// `parse_rewrite` is FAIL-CLOSED: a well-formed rewrite yields the messages (+ optional tools);
/// any malformed shape yields `None` (the caller keeps the ORIGINAL body).
#[test]
fn parse_rewrite_is_fail_closed() {
    let ok = parse_rewrite(&serde_json::json!({
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "headroom_retrieve"}]
    }))
    .expect("well-formed rewrite parses");
    assert_eq!(ok.messages.len(), 1);
    assert_eq!(ok.tools.len(), 1);

    // tools optional → defaults empty.
    let no_tools = parse_rewrite(&serde_json::json!({"messages": [{"role": "user"}]}))
        .expect("rewrite without tools parses");
    assert!(no_tools.tools.is_empty());

    // Malformed → None (fail-closed): no messages, empty messages, non-array, non-object.
    assert!(parse_rewrite(&serde_json::json!({})).is_none());
    assert!(parse_rewrite(&serde_json::json!({"messages": []})).is_none());
    assert!(parse_rewrite(&serde_json::json!({"messages": "hi"})).is_none());
    assert!(parse_rewrite(&serde_json::json!("hi")).is_none());
}
