// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ASK DECISION, and the source-scan gate that keeps it unable to launder.
//!
//! The tests split in two, and the split is the point:
//!
//! - Behaviour: deny-by-default, the capability filter, the empty-filter trap, the sealed round
//!   index, the re-ask.
//! - STRUCTURE: `callerask.rs` may not so much as name `inputreq` or `upstream`. That is asserted by
//!   scanning the source, and the scan has a companion test that plants a violation in a copy of the
//!   source and proves the scan catches it — because a scan nobody has watched fail is a scan that
//!   might be matching nothing at all.

use super::*;
use crate::mcp::askstate::SpentAskStates;
use crate::mcp::config::{AskEntryCfg, AskRoundCfg};

const KEY: [u8; 32] = [3u8; 32];
const NOW: u64 = 1_700_000_000;
const PRINCIPAL: &str = "vk_caller_a";
const CAP: &str = "test_thing";

fn sealer() -> Sealer {
    Sealer::derive(&KEY)
}

fn bind() -> Bind<'static> {
    Bind {
        principal: PRINCIPAL,
        method: "tools/call",
        capability: CAP,
        generation: 1,
        now: NOW,
    }
}

/// One round declaring one ask, in the map shape the config grammar uses.
fn round(key: &str, method: &str) -> AskRoundCfg {
    let mut m = AskRoundCfg::new();
    m.insert(
        key.to_string(),
        AskEntryCfg {
            method: method.to_string(),
            params: Some(serde_json::json!({ "message": "operator text" })),
        },
    );
    m
}

/// One round declaring several asks, for the capability filter.
fn round_of(entries: &[(&str, &str)]) -> AskRoundCfg {
    let mut m = AskRoundCfg::new();
    for (key, method) in entries {
        m.insert(
            (*key).to_string(),
            AskEntryCfg {
                method: (*method).to_string(),
                params: Some(serde_json::json!({ "message": "operator text" })),
            },
        );
    }
    m
}

fn all_capabilities() -> serde_json::Value {
    serde_json::json!({ "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } })
}

const DIGEST: &str = "d";

fn decide_with(rounds: &[AskRoundCfg], caps: &serde_json::Value, retry: Retry<'_>) -> AskDecision {
    decide(
        rounds,
        3,
        caps,
        retry,
        bind(),
        DIGEST,
        Approvals {
            sealer: Some(&sealer()),
            spent: &SpentAskStates::new(),
        },
    )
}

/// DENY BY DEFAULT, BY ABSENCE. A capability with no `ask_caller` never asks — which is every
/// capability in every deployment that has not opted in, i.e. today's behaviour, unchanged.
#[test]
fn a_capability_that_declares_no_ask_proceeds() {
    assert_eq!(
        decide_with(&[], &all_capabilities(), Retry::default()),
        AskDecision::Proceed
    );
}

/// ...and it does not accept state either. busbar verifying a blob it had no reason to have minted
/// is the beginning of accepting one it did not mint.
#[test]
fn a_capability_that_declares_no_ask_refuses_state_rather_than_verifying_it() {
    let got = decide_with(
        &[],
        &all_capabilities(),
        Retry {
            responses: None,
            state: Some("anything-at-all"),
        },
    );
    assert!(matches!(
        got,
        AskDecision::Refuse(Refusal::Unsolicited { .. })
    ));
}

/// The opening round: the configured ask, sealed, with the state busbar minted.
#[test]
fn a_configured_ask_is_emitted_with_state_busbar_minted() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let AskDecision::Ask {
        asks,
        request_state,
        round,
    } = decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("the first round must ask");
    };
    assert_eq!(round, 0);
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].key(), "user_name");
    assert_eq!(asks[0].method(), "elicitation/create");
    // The state is BUSBAR'S, and it opens under busbar's key bound to this caller and this request.
    let opened = sealer()
        .open(&request_state, NOW)
        .expect("busbar minted it, so busbar opens it");
    opened
        .matches(PRINCIPAL, "tools/call", CAP, DIGEST, 1)
        .expect("bound to this request");
    assert_eq!(opened.round, 0);
}

/// `mrtr.mdx:246` — an ask the caller has not declared support for is NOT sent. This is the
/// `capability-check` scenario's property, asserted where the decision is made.
#[test]
fn an_ask_the_caller_did_not_declare_is_filtered_out_and_the_declared_one_survives() {
    let rounds = vec![round_of(&[
        ("confirm", "elicitation/create"),
        ("draft", "sampling/createMessage"),
    ])];
    // Exactly the suite's declaration: sampling, and elicitation deliberately omitted.
    let caps = serde_json::json!({ "sampling": {} });
    let AskDecision::Ask { asks, .. } = decide_with(&rounds, &caps, Retry::default()) else {
        panic!("a declared ask survives the filter, so busbar still asks");
    };
    assert_eq!(
        asks.iter().map(|a| a.method()).collect::<Vec<_>>(),
        ["sampling/createMessage"],
        "the undeclared elicitation must not be sent"
    );
}

/// THE EMPTY-FILTER TRAP, and it is the single most likely way to ship this with a hole: a caller
/// that declares NOTHING must not thereby skip the operator's gate.
///
/// The counterfactual is stated in the assertion rather than left to the reader: `Proceed` here
/// would mean any caller can strip a confirmation gate by declaring no capabilities.
#[test]
fn filtering_to_empty_refuses_and_never_proceeds() {
    let rounds = vec![round("confirm", "elicitation/create")];
    for caps in [
        serde_json::json!({}),
        serde_json::json!({ "sampling": {} }),
        // `null` is what a client sends to mean "no", and must not read as a declaration.
        serde_json::json!({ "elicitation": null }),
    ] {
        let got = decide_with(&rounds, &caps, Retry::default());
        assert!(
            matches!(
                got,
                AskDecision::Refuse(Refusal::NoDeclaredCapability { .. })
            ),
            "declaring `{caps}` must REFUSE, not proceed — proceeding would let any caller strip \
             the operator's gate by declaring nothing. Got {got:?}"
        );
    }
}

/// An ask naming a method outside the closed set has no capability that could declare it, so it can
/// never be legal to send (`mrtr.mdx:246`) and is filtered — which, on its own, is the empty filter.
#[test]
fn an_ask_naming_an_unknown_method_is_never_sent() {
    let rounds = vec![round("x", "some/future/method")];
    let got = decide_with(&rounds, &all_capabilities(), Retry::default());
    assert!(matches!(
        got,
        AskDecision::Refuse(Refusal::NoDeclaredCapability { .. })
    ));
}

/// THE RETRY COMPLETES THE CALL — and only with state busbar minted for exactly this request.
#[test]
fn a_retry_carrying_busbars_own_state_proceeds_to_dispatch() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let AskDecision::Ask { request_state, .. } =
        decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("the first round asks");
    };
    let responses =
        serde_json::json!({ "user_name": { "action": "accept", "content": { "name": "Alice" } } });
    assert_eq!(
        decide_with(
            &rounds,
            &all_capabilities(),
            Retry {
                responses: Some(&responses),
                state: Some(&request_state),
            },
        ),
        AskDecision::Proceed
    );
}

/// THE SUITE'S TAMPER, driven through the decision rather than the codec: the answer must be a
/// REFUSAL, and specifically not a fresh ask — `sep-2322-reject-tampered-state` counts a re-prompt
/// as a failure exactly as it counts a complete result.
#[test]
fn a_tampered_state_is_refused_and_is_not_answered_with_another_ask() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let AskDecision::Ask { request_state, .. } =
        decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("the first round asks");
    };
    let tampered = format!("{request_state}-TAMPERED");
    let responses = serde_json::json!({ "user_name": { "action": "accept", "content": {} } });
    let got = decide_with(
        &rounds,
        &all_capabilities(),
        Retry {
            responses: Some(&responses),
            state: Some(&tampered),
        },
    );
    match got {
        AskDecision::Refuse(Refusal::StateRejected(_)) => {}
        AskDecision::Ask { .. } => panic!(
            "re-prompting on tampered state is a FAILURE by the suite's own comment, not a \
             recovery"
        ),
        other => panic!("tampered state must be refused, got {other:?}"),
    }
}

/// CALLER A's STATE, PRESENTED BY CALLER B. `mrtr.mdx:235`. This is the property a relayer cannot
/// have, driven end to end through the decision.
#[test]
fn one_callers_state_is_not_redeemable_by_another() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let AskDecision::Ask { request_state, .. } =
        decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("the first round asks");
    };
    let responses = serde_json::json!({ "user_name": { "action": "accept", "content": {} } });
    let mut b = bind();
    b.principal = "vk_caller_b";
    let got = decide(
        &rounds,
        3,
        &all_capabilities(),
        Retry {
            responses: Some(&responses),
            state: Some(&request_state),
        },
        b,
        DIGEST,
        Approvals {
            sealer: Some(&sealer()),
            spent: &SpentAskStates::new(),
        },
    );
    assert!(matches!(
        got,
        AskDecision::Refuse(Refusal::StateRejected(
            crate::mcp::askstate::Rejected::WrongPrincipal
        ))
    ));
}

/// MULTI-ROUND, and the property the suite asserts about it: the second state DIFFERS from the
/// first. A deterministic seal would produce the same string and `sep-2322-multi-round-r2` would be
/// red while everything else was green.
#[test]
fn a_second_round_asks_again_with_a_different_state() {
    let rounds = vec![
        round("step1", "elicitation/create"),
        round("step2", "elicitation/create"),
    ];
    let AskDecision::Ask {
        request_state: s1, ..
    } = decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("the first round asks");
    };
    let responses = serde_json::json!({ "step1": { "action": "accept", "content": {} } });
    let AskDecision::Ask {
        request_state: s2,
        round,
        asks,
    } = decide_with(
        &rounds,
        &all_capabilities(),
        Retry {
            responses: Some(&responses),
            state: Some(&s1),
        },
    )
    else {
        panic!("the second round asks again");
    };
    assert_eq!(round, 1);
    assert_eq!(asks[0].key(), "step2");
    assert_ne!(s1, s2, "the suite requires the state to have changed");
    // And the third round completes.
    let responses2 = serde_json::json!({ "step2": { "action": "accept", "content": {} } });
    assert_eq!(
        decide_with(
            &rounds,
            &all_capabilities(),
            Retry {
                responses: Some(&responses2),
                state: Some(&s2),
            },
        ),
        AskDecision::Proceed
    );
}

/// THE BOUND, and the replay it exists to stop. A caller that keeps presenting round-1 state keeps
/// being at the first round — it cannot walk past the cap, because the index is inside the seal and not in
/// anything the caller writes.
#[test]
fn the_round_cap_is_hard_and_cannot_be_reset_by_replaying_an_earlier_state() {
    // Four configured rounds, cap of two.
    let rounds: Vec<AskRoundCfg> = (0..4)
        .map(|i| round(&format!("step{i}"), "elicitation/create"))
        .collect();
    let responses = serde_json::json!({ "any": { "action": "accept", "content": {} } });
    let mut state: Option<String> = None;
    for expected in 0..2u32 {
        let retry = Retry {
            responses: state.as_ref().map(|_| &responses),
            state: state.as_deref(),
        };
        let AskDecision::Ask {
            request_state,
            round,
            ..
        } = decide(
            &rounds,
            2,
            &all_capabilities(),
            retry,
            bind(),
            DIGEST,
            Approvals {
                sealer: Some(&sealer()),
                spent: &SpentAskStates::new(),
            },
        )
        else {
            panic!("round {expected} must be allowed under a cap of 2");
        };
        assert_eq!(round, expected);
        state = Some(request_state);
    }
    // The third is past the cap and stays refused.
    for _ in 0..3 {
        let got = decide(
            &rounds,
            2,
            &all_capabilities(),
            Retry {
                responses: Some(&responses),
                state: state.as_deref(),
            },
            bind(),
            DIGEST,
            Approvals {
                sealer: Some(&sealer()),
                spent: &SpentAskStates::new(),
            },
        );
        assert!(
            matches!(got, AskDecision::Refuse(Refusal::RoundCapExceeded { .. })),
            "a cap that resets is not a cap: {got:?}"
        );
    }
}

/// A cap of ZERO never asks. An operator kill switch that works without editing every capability.
#[test]
fn a_cap_of_zero_never_asks() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let got = decide(
        &rounds,
        0,
        &all_capabilities(),
        Retry::default(),
        bind(),
        DIGEST,
        Approvals {
            sealer: Some(&sealer()),
            spent: &SpentAskStates::new(),
        },
    );
    assert!(matches!(
        got,
        AskDecision::Refuse(Refusal::RoundCapExceeded { .. })
    ));
}

/// `input-required-result-missing-input-response` is a `SHOULD` to RE-ASK rather than error. A retry
/// naming the wrong key, with no state, is a caller that has not answered — so it is asked again.
#[test]
fn a_retry_with_the_wrong_key_and_no_state_is_asked_again_rather_than_errored() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let responses = serde_json::json!({ "wrong_key": { "action": "accept", "content": {} } });
    let got = decide_with(
        &rounds,
        &all_capabilities(),
        Retry {
            responses: Some(&responses),
            state: None,
        },
    );
    assert!(
        matches!(got, AskDecision::Ask { round: 0, .. }),
        "the SHOULD is to re-request, not to error: {got:?}"
    );
}

/// `input-required-result-validate-input` sends structurally invalid `inputResponses` — the number
/// `12345` and the literal `null`. Neither may produce a COMPLETE result.
#[test]
fn structurally_invalid_input_responses_never_produce_a_complete_result() {
    let rounds = vec![round("user_name", "elicitation/create")];
    for responses in [
        serde_json::json!({ "user_name": 12345 }),
        serde_json::json!(null),
    ] {
        let got = decide_with(
            &rounds,
            &all_capabilities(),
            Retry {
                responses: Some(&responses),
                state: None,
            },
        );
        assert!(
            !matches!(got, AskDecision::Proceed),
            "`{responses}` must not dispatch: {got:?}"
        );
    }
}

/// NO SIGNING KEY, NO ASK. An ask busbar cannot seal is an ask whose answer busbar would have to
/// take on trust, so the fail-closed arm is a refusal and not an unprotected `requestState`.
#[test]
fn a_deployment_with_no_signing_key_refuses_rather_than_asking_with_unprotected_state() {
    let rounds = vec![round("user_name", "elicitation/create")];
    let got = decide(
        &rounds,
        3,
        &all_capabilities(),
        Retry::default(),
        bind(),
        DIGEST,
        Approvals {
            sealer: None,
            spent: &SpentAskStates::new(),
        },
    );
    assert!(matches!(got, AskDecision::Refuse(Refusal::NoSealer { .. })));
}

/// The params busbar puts on the wire are the OPERATOR'S, verbatim. Asserted as equality against the
/// configured value rather than "contains", because a substitution would show up as a difference and
/// a `contains` would not.
#[test]
fn the_asks_params_are_the_operators_bytes_and_nothing_else() {
    let params = serde_json::json!({
        "mode": "form",
        "message": "Confirm the transfer",
        "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
    });
    let mut only = AskRoundCfg::new();
    only.insert(
        "confirm".to_string(),
        AskEntryCfg {
            method: "elicitation/create".to_string(),
            params: Some(params.clone()),
        },
    );
    let rounds = vec![only];
    let AskDecision::Ask { asks, .. } = decide_with(&rounds, &all_capabilities(), Retry::default())
    else {
        panic!("asks");
    };
    assert_eq!(asks[0].params(), &params);
}
