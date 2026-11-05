// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn request(action: &str) -> super::super::super::AdminRequest {
    super::super::super::AdminRequest {
        method: "POST".into(), path: "/api/v1/admin/adjust".into(), credential: None,
        headers: vec![("idempotency-key".into(), action.into())],
        body: serde_json::to_vec(&serde_json::json!({
            "key": "key", "lane": "lane", "entry": busbar_kernel::cost::EntryKey::new(300, [7; 8], 1).hex(),
            "card_epoch_ms": 350, "pool": "pool", "delta": {"input": "-0.000001"},
            "reason": "private operator explanation"
        })).unwrap(), at: busbar_kernel::store::now(), unit: 1,
    }
}

#[test]
fn adjustment_lost_response_replays_durable_action_without_second_delta() {
    let store = crate::root::real_store::records();
    let replay_store: super::super::super::bound::ReplayStore = {
        let store = store.clone();
        Arc::new(move || Some(store.clone()))
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let adjuster: UsageAdjuster = {
        let calls = calls.clone();
        Arc::new(move |correction| {
            assert_eq!(
                correction.delta["input"],
                busbar_contract::Count::from_micros(-1)
            );
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Ok(()))
        })
    };
    let mut unit = request("lost-response");
    let ask = |unit: &super::super::super::AdminRequest, actor| {
        adjust_request(
            unit,
            &unit.body,
            busbar_contract::authz::Scope::Full,
            actor,
            Some(&replay_store),
            &|_| true,
            &adjuster,
        )
        .unwrap()
    };
    let discarded = ask(&unit, "actor-a");
    assert_eq!(discarded.status, 200);
    unit.at += 86_400;
    let replay = ask(&unit, "actor-a");
    assert_eq!(replay.body, discarded.body);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let receipt: serde_json::Value = serde_json::from_slice(&replay.body).unwrap();
    assert_eq!(receipt["effect"], "applied");
    assert_eq!(receipt["actor"], "actor-a");
    assert_eq!(receipt["target"], "key");
    assert_eq!(
        receipt["reason_hash"],
        busbar_contract::redacted::sha256_hex(b"private operator explanation")
    );
    assert!(!String::from_utf8(replay.body)
        .unwrap()
        .contains("private operator explanation"));
    let original = unit.body.clone();
    unit.body = b"{".to_vec();
    assert_eq!(ask(&unit, "actor-a").status, 409);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    unit.body = original;
    unit.headers[0].1 = "intentional-second-action".into();
    assert_eq!(ask(&unit, "actor-a").status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(ask(&unit, "actor-b").status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn adjustment_unknown_effect_remains_in_custody_without_reapplying() {
    let store = crate::root::real_store::records();
    let replay_store: super::super::super::bound::ReplayStore =
        Arc::new(move || Some(store.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let adjuster: UsageAdjuster = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("effect landed but acknowledgement failed".into())
        })
    };
    let mut unit = request("unknown-effect");
    unit.headers
        .push(("x-busbar-adjust-effect".into(), "applied".into()));
    for _ in 0..2 {
        let answer = adjust_request(
            &unit,
            &unit.body,
            busbar_contract::authz::Scope::Full,
            "actor",
            Some(&replay_store),
            &|_| true,
            &adjuster,
        )
        .unwrap();
        assert_eq!(answer.status, 409);
        assert_eq!(
            super::super::super::adjustment_audit_outcome(Some(&answer), false),
            busbar_kernel::audit_ring::OUTCOME_DEGRADED
        );
        let doc: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(doc["effect"], "unknown");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_adjustment_rejects_excess_precision_and_blank_reason_before_effect() {
    let unit = request("precision");
    let mut body: serde_json::Value = serde_json::from_slice(&unit.body).unwrap();
    body["delta"]["input"] = serde_json::json!("0.0000001");
    assert!(parse_correction(&serde_json::to_vec(&body).unwrap(), &|_| true, true).is_err());
    body["delta"]["input"] = serde_json::json!("-0.000001");
    body["reason"] = serde_json::json!(" ");
    assert!(parse_correction(&serde_json::to_vec(&body).unwrap(), &|_| true, true).is_err());
}

#[test]
fn adjustment_audit_reads_host_answer_only_and_preserves_known_applied() {
    assert_eq!(
        super::super::super::adjustment_audit_outcome(None, false),
        busbar_kernel::audit_ring::OUTCOME_REJECTED
    );
    let receipt = Receipt {
        operation_id: "action".into(),
        actor: "actor".into(),
        target: "key".into(),
        fingerprint: "digest".into(),
        reason_hash: "digest".into(),
        effect: "applied".into(),
        status: 409,
    };
    let response = answer(&receipt).unwrap();
    assert_eq!(
        super::super::super::adjustment_audit_outcome(Some(&response), false),
        busbar_kernel::audit_ring::OUTCOME_APPLIED
    );
}
