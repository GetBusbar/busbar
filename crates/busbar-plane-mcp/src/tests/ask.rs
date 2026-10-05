// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Busbar's own ask: the decision in the engine's order, over a seal the test holds.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::*;
use crate::tools_config::AskRoundCfg;

/// A seal that writes the state as JSON behind a marker and spends each nonce once.
#[derive(Default)]
struct Plain {
    spent: BTreeSet<String>,
    next: u32,
}

const MARK: &str = "sealed:";

impl Seal for Plain {
    fn mint(&mut self, state: &AskState) -> Option<String> {
        Some(format!("{MARK}{}", serde_json::to_string(state).ok()?))
    }
    fn open(&mut self, blob: &str) -> Result<AskState, Rejected> {
        let body = blob.strip_prefix(MARK).ok_or(Rejected::BadSignature)?;
        serde_json::from_str(body).map_err(|_| Rejected::Malformed)
    }
    fn nonce(&mut self) -> Option<String> {
        self.next += 1;
        Some(format!("n{}", self.next))
    }
    fn redeem(&mut self, nonce: &str, _: u64, _: u64) -> bool {
        self.spent.insert(nonce.to_string())
    }
}

fn round(entries: &[(&str, &str)]) -> AskRoundCfg {
    let map: serde_json::Map<String, Value> = entries
        .iter()
        .map(|(k, m)| {
            (
                (*k).to_string(),
                json!({ "method": m, "params": { "message": "sure?" } }),
            )
        })
        .collect();
    serde_json::from_value(Value::Object(map)).expect("the operator's round reads")
}

fn confirm() -> Vec<AskRoundCfg> {
    vec![round(&[("ok", crate::tools_config::ASK_ELICITATION)])]
}

fn bind(principal: &str) -> Bind<'_> {
    Bind {
        principal,
        method: "tools/call",
        capability: "fs_confirm",
        generation: 1,
        now: 100,
        roots_epoch: 0,
    }
}

fn caps() -> Value {
    json!({ "elicitation": {} })
}

#[test]
fn no_rounds_proceed_and_unasked_state_is_refused() {
    let d = decide(&[], 3, &caps(), Retry::default(), bind("k"), "d", None);
    assert_eq!(d, AskDecision::Proceed);
    let answers = json!({ "ok": true });
    let retry = Retry {
        responses: Some(&answers),
        state: None,
    };
    let AskDecision::Refuse(r) = decide(&[], 3, &caps(), retry, bind("k"), "d", None) else {
        panic!("refused");
    };
    assert_eq!(r.audit_reason(), "ask_unsolicited_state");
    assert_eq!(r.refusal(&json!(1)).status, 403);
}

#[test]
fn an_undeclared_capability_is_refused_before_the_seal_is_asked() {
    let AskDecision::Refuse(r) = decide(
        &confirm(),
        3,
        &json!({}),
        Retry::default(),
        bind("k"),
        "d",
        None,
    ) else {
        panic!("refused");
    };
    let refusal = r.refusal(&json!(1));
    assert_eq!(
        (refusal.status, refusal.code),
        (400, crate::codec::CODE_MISSING_CLIENT_CAPABILITY)
    );
    assert_eq!(
        refusal.data.expect("data")["requiredCapabilities"],
        json!({ "elicitation": {} })
    );
}

#[test]
fn with_no_seal_a_declared_ask_is_refused_unprotected() {
    let AskDecision::Refuse(r) = decide(
        &confirm(),
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        None,
    ) else {
        panic!("refused");
    };
    assert_eq!(r.audit_reason(), "ask_no_sealer");
}

#[test]
fn the_exchange_asks_then_proceeds_once() {
    let mut seal = Plain::default();
    let AskDecision::Ask {
        asks,
        request_state,
        round,
    } = decide(
        &confirm(),
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    )
    else {
        panic!("asks");
    };
    assert_eq!((asks.len(), round), (1, 0));
    let body: Value =
        serde_json::from_slice(&input_required_result(&json!(4), &asks, &request_state))
            .expect("json");
    assert_eq!(body["result"]["resultType"], json!("input_required"));
    assert_eq!(
        body["result"]["inputRequests"]["ok"]["method"],
        json!("elicitation/create")
    );
    let answers = json!({ "ok": true });
    let retry = Retry {
        responses: Some(&answers),
        state: Some(&request_state),
    };
    let d = decide(
        &confirm(),
        3,
        &caps(),
        retry,
        bind("k"),
        "d",
        Some(&mut seal),
    );
    assert_eq!(d, AskDecision::Proceed);
    let AskDecision::Refuse(r) = decide(
        &confirm(),
        3,
        &caps(),
        retry,
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("a replay is refused");
    };
    assert_eq!(r.audit_reason(), "state_already_spent");
}

#[test]
fn state_for_another_caller_or_request_is_refused_as_tampered() {
    let mut seal = Plain::default();
    let AskDecision::Ask { request_state, .. } = decide(
        &confirm(),
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("asks");
    };
    let answers = json!({ "ok": true });
    let retry = Retry {
        responses: Some(&answers),
        state: Some(&request_state),
    };
    for (who, digest, reason) in [
        ("other", "d", "state_wrong_principal"),
        ("k", "other", "state_wrong_request"),
    ] {
        let AskDecision::Refuse(r) = decide(
            &confirm(),
            3,
            &caps(),
            retry,
            bind(who),
            digest,
            Some(&mut seal),
        ) else {
            panic!("refused");
        };
        assert_eq!(r.audit_reason(), reason);
        let refusal = r.refusal(&json!(1));
        assert_eq!(
            (refusal.status, refusal.code),
            (400, crate::codec::CODE_INVALID_PARAMS)
        );
    }
    let forged = Retry {
        responses: Some(&answers),
        state: Some("forged"),
    };
    let AskDecision::Refuse(r) = decide(
        &confirm(),
        3,
        &caps(),
        forged,
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("refused");
    };
    assert_eq!(r.audit_reason(), "state_bad_signature");
}

#[test]
fn a_retry_that_answers_nothing_is_refused() {
    let mut seal = Plain::default();
    let two = vec![
        round(&[("ok", crate::tools_config::ASK_ELICITATION)]),
        round(&[("why", crate::tools_config::ASK_ELICITATION)]),
    ];
    let AskDecision::Ask { request_state, .. } = decide(
        &two,
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("asks");
    };
    let retry = Retry {
        responses: None,
        state: Some(&request_state),
    };
    let AskDecision::Refuse(r) = decide(&two, 3, &caps(), retry, bind("k"), "d", Some(&mut seal))
    else {
        panic!("refused");
    };
    assert_eq!(r.audit_reason(), "ask_unanswered");
    let AskDecision::Refuse(r) = decide(
        &two,
        1,
        &caps(),
        Retry {
            responses: Some(&json!({ "ok": true })),
            state: Some(&request_state),
        },
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("capped");
    };
    assert_eq!(r.audit_reason(), "ask_round_cap");
}

#[test]
fn a_roots_answer_goes_stale_when_the_caller_moves_its_roots() {
    let mut seal = Plain::default();
    let roots = vec![round(&[("r", crate::tools_config::ASK_ROOTS)])];
    let caps = json!({ "roots": {} });
    let AskDecision::Ask { request_state, .. } = decide(
        &roots,
        3,
        &caps,
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("asks");
    };
    let answers = json!({ "r": {} });
    let retry = Retry {
        responses: Some(&answers),
        state: Some(&request_state),
    };
    let mut moved = bind("k");
    moved.roots_epoch = 1;
    let AskDecision::Refuse(r) = decide(&roots, 3, &caps, retry, moved, "d", Some(&mut seal))
    else {
        panic!("refused");
    };
    assert_eq!(r.audit_reason(), "state_stale_roots");
}

#[test]
fn the_digest_is_the_serialisations() {
    assert_eq!(
        digest_arguments(&json!({ "b": 1, "a": 2 })),
        busbar_contract::redacted::sha256_hex(br#"{"a":2,"b":1}"#)
    );
}

/// THE OPERATOR-AUTHORED ASK (choke point H): the `params` a caller is shown are exactly the bytes
/// the operator wrote, deserialised from configuration and carried verbatim into the
/// `input_required` result; nothing else can make a [`CallerAsk`].
#[test]
fn the_asks_params_are_the_operators_bytes_and_nothing_else() {
    let params = json!({
        "mode": "form",
        "message": "Confirm the transfer",
        "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
    });
    let rounds: Vec<AskRoundCfg> = serde_json::from_value(json!([
        { "confirm": { "method": crate::tools_config::ASK_ELICITATION, "params": params.clone() } }
    ]))
    .expect("the operator's rounds read");
    let mut seal = Plain::default();
    let AskDecision::Ask {
        asks,
        request_state,
        ..
    } = decide(
        &rounds,
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    )
    else {
        panic!("asks");
    };
    assert_eq!(asks[0].params(), &params);
    let body: Value =
        serde_json::from_slice(&input_required_result(&json!(1), &asks, &request_state))
            .expect("json");
    assert_eq!(body["result"]["inputRequests"]["confirm"]["params"], params);
}

/// LAW 11 (U16): AN UPSTREAM'S ASK IS RELAYED under busbar's one sealed state, which pins the member
/// and nests the upstream's own. Its retry, on a tool with or without rounds of busbar's own, is
/// the relayed retry, spent once; the state presented by another principal, on another call, or
/// forged is refused.
#[test]
fn a_relayed_asks_retry_is_pinned_spent_once_and_bound_to_its_caller() {
    let mut seal = Plain::default();
    let leg = UpstreamLeg {
        member: "fs".into(),
        state: Some(json!("upstream-state")),
        round: 1,
    };
    let state = relay_state(bind("k"), "d", leg.clone(), &mut seal).expect("sealed");
    let answers = json!({ "r": { "roots": [] } });
    let retry = Retry {
        responses: Some(&answers),
        state: Some(&state),
    };
    // Busbar's own rounds do not stand in its way: they were answered before the call went out.
    for rounds in [Vec::new(), confirm()] {
        let mut fresh = Plain::default();
        assert_eq!(
            decide(&rounds, 3, &caps(), retry, bind("k"), "d", Some(&mut fresh)),
            AskDecision::Relayed(leg.clone())
        );
    }
    // RED: spent once.
    assert_eq!(
        decide(&[], 3, &caps(), retry, bind("k"), "d", Some(&mut seal)),
        AskDecision::Relayed(leg.clone())
    );
    assert_eq!(
        decide(&[], 3, &caps(), retry, bind("k"), "d", Some(&mut seal)),
        AskDecision::Refuse(AskRefusal::StateRejected(Rejected::AlreadySpent))
    );
    // RED: another principal, another call's arguments.
    let mut other = Plain::default();
    assert_eq!(
        decide(&[], 3, &caps(), retry, bind("other"), "d", Some(&mut other)),
        AskDecision::Refuse(AskRefusal::StateRejected(Rejected::WrongPrincipal))
    );
    assert_eq!(
        decide(&[], 3, &caps(), retry, bind("k"), "e", Some(&mut other)),
        AskDecision::Refuse(AskRefusal::StateRejected(Rejected::WrongRequest))
    );
    // RED: a forged state is never a relayed retry.
    let forged = Retry {
        responses: Some(&answers),
        state: Some("forged"),
    };
    assert!(matches!(
        decide(
            &confirm(),
            3,
            &caps(),
            forged,
            bind("k"),
            "d",
            Some(&mut other)
        ),
        AskDecision::Refuse(AskRefusal::StateRejected(_))
    ));
}

/// The relayed result is the upstream's, `inputRequests` verbatim; only its state is busbar's.
#[test]
fn the_relayed_result_keeps_the_upstreams_requests_verbatim() {
    let upstream = json!({
        "resultType": "input_required",
        "inputRequests": { "s": { "method": "sampling/createMessage", "params": { "x": [1, 2] } } },
        "requestState": "theirs",
    });
    let body: Value =
        serde_json::from_slice(&relayed_result(&json!(7), &upstream, "ours")).expect("json");
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["result"]["inputRequests"], upstream["inputRequests"]);
    assert_eq!(body["result"]["requestState"], json!("ours"));
}
