// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: hook` test-support plugin: `open`'s config parsing and every
//! `HookConfig` knob's effect on `TestGate`'s `decide`/`transform`/`notify`/`describe`/`status`/
//! `configure` behavior. This crate is itself a TEST fixture for other crates' seam tests, so its
//! own tests exercise it directly (no dlopen/ABI crossing here — that is what `busbar`'s
//! `DlopenPolicy` seam tests use this cdylib for).

use super::*;

fn payload_with_message(text: &str) -> serde_json::Value {
    serde_json::json!({"request": {"messages": [{"text": text}]}})
}

fn empty_payload() -> serde_json::Value {
    serde_json::json!({})
}

// ── open() config parsing ────────────────────────────────────────────────────────────────────

#[test]
fn open_with_empty_config_yields_an_abstaining_gate() {
    let gate = open("").expect("empty config must open cleanly");
    assert_eq!(gate.decide(&empty_payload()), serde_json::json!({}));
}

#[test]
fn open_with_blank_whitespace_config_is_also_treated_as_empty() {
    assert!(open("   \n\t ").is_ok());
}

#[test]
fn open_with_malformed_json_is_a_load_error() {
    let err = match open("{ not json") {
        Err(e) => e,
        Ok(_) => panic!("malformed config must not open"),
    };
    assert!(
        err.contains("invalid test-hook plugin config"),
        "error must name the failure: {err}"
    );
}

// ── decide(): the `order` knob ───────────────────────────────────────────────────────────────

#[test]
fn decide_with_no_order_abstains() {
    let gate = open("").unwrap();
    assert_eq!(gate.decide(&empty_payload()), serde_json::json!({}));
}

#[test]
fn decide_with_order_echoes_it() {
    let gate = open(r#"{"order": [2, 0, 1]}"#).unwrap();
    assert_eq!(
        gate.decide(&empty_payload()),
        serde_json::json!({"order": [2, 0, 1]})
    );
}

// ── decide(): the `reject_if_contains` / `reject_status` knobs ──────────────────────────────────

#[test]
fn decide_rejects_when_a_projected_message_contains_the_token() {
    let gate = open(r#"{"reject_if_contains": "BLOCKME"}"#).unwrap();
    let got = gate.decide(&payload_with_message("please BLOCKME now"));
    assert_eq!(
        got,
        serde_json::json!({"reject": {"status": 403, "message": "blocked by test gate"}})
    );
}

#[test]
fn decide_does_not_reject_when_the_token_is_absent() {
    let gate = open(r#"{"reject_if_contains": "BLOCKME"}"#).unwrap();
    let got = gate.decide(&payload_with_message("all clear"));
    assert_eq!(got, serde_json::json!({}));
}

#[test]
fn decide_reject_status_is_configurable() {
    let gate = open(r#"{"reject_if_contains": "X", "reject_status": 451}"#).unwrap();
    let got = gate.decide(&payload_with_message("X marks the spot"));
    assert_eq!(
        got,
        serde_json::json!({"reject": {"status": 451, "message": "blocked by test gate"}})
    );
}

#[test]
fn should_reject_ignores_a_payload_with_no_messages_array() {
    // The `is_some_and` chain over request.messages must tolerate a payload shaped without one —
    // it should read as "no match", not panic or short-circuit into a false reject.
    let gate = open(r#"{"reject_if_contains": "X"}"#).unwrap();
    assert_eq!(gate.decide(&empty_payload()), serde_json::json!({}));
    assert_eq!(
        gate.decide(&serde_json::json!({"request": {}})),
        serde_json::json!({})
    );
}

// ── decide(): `restrict_tags` ─────────────────────────────────────────────────────────────────

#[test]
fn decide_with_restrict_tags_restricts() {
    let gate = open(r#"{"restrict_tags": ["a", "b"]}"#).unwrap();
    assert_eq!(
        gate.decide(&empty_payload()),
        serde_json::json!({"restrict": {"tags_any": ["a", "b"]}})
    );
}

#[test]
fn reject_wins_over_restrict_tags() {
    // `should_reject` is checked first in `decide`: a gate configured with BOTH a reject token and
    // restrict tags must reject when the token matches, never fall through to restrict.
    let gate = open(r#"{"reject_if_contains": "BLOCKME", "restrict_tags": ["a"]}"#).unwrap();
    let got = gate.decide(&payload_with_message("BLOCKME"));
    assert_eq!(
        got,
        serde_json::json!({"reject": {"status": 403, "message": "blocked by test gate"}})
    );
}

// ── decide(): `raw_decide_reply` wins over everything ────────────────────────────────────────

#[test]
fn raw_decide_reply_overrides_reject_and_order_and_restrict() {
    let gate = open(
        r#"{"reject_if_contains": "BLOCKME", "order": [1,0], "restrict_tags": ["a"], "raw_decide_reply": {"weird": true}}"#,
    )
    .unwrap();
    let got = gate.decide(&payload_with_message("BLOCKME"));
    assert_eq!(got, serde_json::json!({"weird": true}));
}

// ── decide_result / transform_result: `fail_decide` / `fail_transform` ──────────────────────────

#[test]
fn fail_decide_reports_err_not_an_abstain() {
    let gate = open(r#"{"fail_decide": "dependency down"}"#).unwrap();
    let err = gate
        .decide_result(&empty_payload())
        .expect_err("fail_decide must be an Err, not an Ok abstain");
    assert_eq!(err, "dependency down");
}

#[test]
fn fail_decide_still_counts_towards_the_decides_metric() {
    let gate = open(r#"{"fail_decide": "down"}"#).unwrap();
    let _ = gate.decide_result(&empty_payload());
    let status = gate.status();
    assert_eq!(
        status["status"]["metrics"][0]["value"],
        serde_json::json!(1.0)
    );
}

#[test]
fn without_fail_decide_decide_result_delegates_to_decide() {
    let gate = open(r#"{"order": [0]}"#).unwrap();
    assert_eq!(
        gate.decide_result(&empty_payload()).unwrap(),
        serde_json::json!({"order": [0]})
    );
}

#[test]
fn fail_transform_reports_err_not_an_untouched_forward() {
    let gate = open(r#"{"fail_transform": "classifier down"}"#).unwrap();
    let err = gate
        .transform_result(&empty_payload())
        .expect_err("fail_transform must be an Err");
    assert_eq!(err, "classifier down");
}

#[test]
fn without_fail_transform_transform_result_delegates_to_transform() {
    let gate = open("").unwrap();
    assert_eq!(
        gate.transform_result(&empty_payload()).unwrap(),
        serde_json::json!({"rewrite": {"messages": [{"role": "user", "content": "rewritten by test gate"}]}})
    );
}

// ── transform(): reject-then-raw-override-then-default-rewrite ordering ─────────────────────────

#[test]
fn transform_rejects_when_the_token_matches() {
    let gate = open(r#"{"reject_if_contains": "BLOCKME"}"#).unwrap();
    let got = gate.transform(&payload_with_message("BLOCKME"));
    assert_eq!(
        got,
        serde_json::json!({"reject": {"status": 451, "message": "screened"}})
    );
}

#[test]
fn transform_raw_reply_overrides_the_default_rewrite() {
    let gate = open(r#"{"raw_transform_reply": {"rewrite": {"messages": []}}}"#).unwrap();
    let got = gate.transform(&empty_payload());
    assert_eq!(got, serde_json::json!({"rewrite": {"messages": []}}));
}

#[test]
fn transform_reject_wins_over_raw_transform_reply() {
    let gate = open(
        r#"{"reject_if_contains": "BLOCKME", "raw_transform_reply": {"rewrite": {"messages": []}}}"#,
    )
    .unwrap();
    let got = gate.transform(&payload_with_message("BLOCKME"));
    assert_eq!(
        got,
        serde_json::json!({"reject": {"status": 451, "message": "screened"}})
    );
}

#[test]
fn transform_default_rewrite_when_nothing_configured() {
    let gate = open("").unwrap();
    let got = gate.transform(&empty_payload());
    assert_eq!(
        got,
        serde_json::json!({"rewrite": {"messages": [{"role": "user", "content": "rewritten by test gate"}]}})
    );
}

// ── notify(): the notifies counter ───────────────────────────────────────────────────────────

#[test]
fn notify_increments_the_notifies_metric() {
    let gate = open("").unwrap();
    gate.notify(&empty_payload());
    gate.notify(&empty_payload());
    let status = gate.status();
    assert_eq!(
        status["status"]["metrics"][1]["value"],
        serde_json::json!(2.0)
    );
}

// ── describe() / status(): `empty_management` ────────────────────────────────────────────────

#[test]
fn describe_reports_a_schema_by_default() {
    let gate = open("").unwrap();
    let d = gate.describe();
    assert!(d.get("schema").is_some());
}

#[test]
fn describe_is_empty_when_empty_management_is_set() {
    let gate = open(r#"{"empty_management": true}"#).unwrap();
    assert_eq!(gate.describe(), serde_json::json!({}));
}

#[test]
fn status_is_empty_when_empty_management_is_set() {
    let gate = open(r#"{"empty_management": true}"#).unwrap();
    assert_eq!(gate.status(), serde_json::json!({}));
}

#[test]
fn status_reports_metrics_in_the_documented_order() {
    let gate = open("").unwrap();
    let _ = gate.decide(&empty_payload());
    gate.notify(&empty_payload());
    let status = gate.status();
    assert_eq!(status["status"]["metrics"][0]["name"], "test_decides_total");
    assert_eq!(
        status["status"]["metrics"][1]["name"],
        "test_notifies_total"
    );
}

// ── configure(): `nack_configure` ────────────────────────────────────────────────────────────

#[test]
fn configure_acks_by_default() {
    let gate = open("").unwrap();
    assert!(gate.configure(&serde_json::Map::new(), 1));
}

#[test]
fn configure_nacks_when_nack_configure_is_set() {
    let gate = open(r#"{"nack_configure": true}"#).unwrap();
    assert!(!gate.configure(&serde_json::Map::new(), 1));
}

// ── decide(): `panic_decide` is caught by the plugin-sdk boundary, not asserted here (that is the
// dlopen-seam test's job in `busbar`'s own `hooks::tests`) — but the raw call itself really must
// panic (never silently swallow it at this layer), which this pins directly.
#[test]
#[should_panic(expected = "test gate panic_decide")]
fn panic_decide_actually_panics_when_called_directly() {
    let gate = open(r#"{"panic_decide": true}"#).unwrap();
    let _ = gate.decide(&empty_payload());
}

/// THE CATALOG IS WELL-FORMED: what the host reads at load and refuses if it does not check.
#[test]
fn the_catalog_is_a_catalog_document_that_checks() {
    let catalog = catalog();
    catalog.check().expect("the catalog checks");
    for e in catalog.entries.as_slice() {
        assert!(
            catalog.template(&e.code, "en").is_some(),
            "{} has an en template",
            e.code
        );
    }
}
