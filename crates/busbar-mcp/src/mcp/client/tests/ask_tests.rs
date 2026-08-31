// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An upstream's `InputRequiredResult`: deny-by-default, re-checked on every retry, bounded and
//! metered, and never proxied outward. An upstream must not be able to induce busbar to spend
//! busbar's own authority — an LLM completion on busbar's pools and budget, a prompt to a user, or
//! disclosure of filesystem roots — that the operator never granted that server.

use crate::mcp::client::jsonrpc::{
    parse_response, AskRefusal, InputRequiredLoop, RpcOutcome, ServerAsk, ServerRequestGrants,
};

/// An `InputRequiredResult` in the shape the SPECIFICATION defines, which is the only shape a
/// conformant upstream ever puts on the wire.
///
/// `mrtr.mdx:126-180` and the SDK's `spec.types.2026-07-28.ts`: the discriminator is `resultType`,
/// the asks are a MAP at `inputRequests` keyed by server-assigned identifiers, and each value is a
/// request object naming a `method`. There is no `type` field and no `request` field anywhere in
/// `InputRequiredResult`.
///
/// This function used to mint `{"type":"input_required","request":"…"}` — a shape busbar invented.
/// The fixture and the parser agreed with each other and with no server in existence, so every test
/// below passed while the gate they describe was open against every real upstream.
fn input_required(method: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "input_required",
            "inputRequests": { "ask_0": { "method": method, "params": {} } },
            "requestState": "opaque-to-busbar",
        },
    }))
    .expect("fixture serialises")
}

#[test]
fn an_input_required_result_is_recognised_and_not_reported_as_a_plain_result() {
    let cases = [
        ("sampling/createMessage", ServerAsk::Sampling),
        ("elicitation/create", ServerAsk::Elicitation),
        ("roots/list", ServerAsk::Roots),
    ];
    assert_eq!(cases.len(), 3);
    for (request, expected) in cases {
        assert_eq!(
            parse_response(&input_required(request), 1),
            RpcOutcome::InputRequired { kind: expected },
            "`{request}` must be recognised as an ask"
        );
    }
}

/// An ask naming something we do not recognise is still an ask. Returning it as a plain result would
/// hand an unrecognised request for authority straight through.
#[test]
fn an_unrecognised_ask_is_refused_rather_than_passed_through_as_a_result() {
    assert_eq!(
        parse_response(&input_required("some/future/method"), 1),
        RpcOutcome::InputRequired {
            kind: ServerAsk::Sampling
        }
    );
}

/// `mrtr.mdx:245`: a server MUST include AT LEAST ONE of `inputRequests` or `requestState`. So a
/// result carrying `resultType: "input_required"` and nothing else is a conformant ask, and it must
/// terminate exactly like one that names methods. Keying the recognition off `inputRequests` alone
/// would let an upstream slip an ask through by omitting the field the spec makes optional.
#[test]
fn an_ask_carrying_only_request_state_is_still_an_ask() {
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "resultType": "input_required", "requestState": "opaque" },
    }))
    .expect("fixture serialises");
    assert_eq!(
        parse_response(&body, 1),
        RpcOutcome::InputRequired {
            kind: ServerAsk::Sampling
        },
        "an ask with no `inputRequests` is still an ask"
    );
}

/// The recogniser must not over-match either: a plain, complete result is a result, and answering
/// `InputRequired` to one would refuse every ordinary tool call.
#[test]
fn a_complete_result_is_not_mistaken_for_an_ask() {
    for result in [
        serde_json::json!({ "content": [{ "type": "text", "text": "hi" }] }),
        serde_json::json!({ "resultType": "complete", "content": [] }),
        // `type` appearing INSIDE content is the everyday case and must stay a result.
        serde_json::json!({ "content": [{ "type": "input_required", "text": "not a discriminator" }] }),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": result,
        }))
        .expect("fixture serialises");
        assert!(
            matches!(parse_response(&body, 1), RpcOutcome::Result(_)),
            "must remain a plain result: {result}"
        );
    }
}

/// A single `inputRequests` map can name SEVERAL methods (`mrtr.mdx` allows it, and the conformance
/// suite's `multiple-input-requests` scenario requires a server to emit three at once). busbar must
/// refuse against the MOST PRIVILEGED grant in the set, not the first key it happens to iterate:
/// answering against the cheapest ask would let an upstream smuggle a sampling request behind a
/// `roots/list` it knows busbar is allowed to satisfy.
#[test]
fn a_multi_method_ask_is_judged_against_the_most_privileged_method_it_names() {
    let body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "resultType": "input_required",
            "inputRequests": {
                "a": { "method": "roots/list", "params": {} },
                "b": { "method": "sampling/createMessage", "params": {} },
            },
        },
    }))
    .expect("fixture serialises");
    assert_eq!(
        parse_response(&body, 1),
        RpcOutcome::InputRequired {
            kind: ServerAsk::Sampling
        }
    );
}

#[test]
fn grants_are_all_false_at_construction_and_there_is_no_way_to_turn_them_all_on() {
    let g = ServerRequestGrants::default();
    for ask in [
        ServerAsk::Sampling,
        ServerAsk::Elicitation,
        ServerAsk::Roots,
    ] {
        assert!(!g.allows(ask), "{ask:?} must be denied by default");
    }
}

#[test]
fn an_ungranted_ask_is_refused_and_the_message_names_the_grant() {
    let mut l = InputRequiredLoop::new("payments", 3);
    let err = l
        .may_satisfy(ServerAsk::Sampling, ServerRequestGrants::default())
        .expect_err("deny by default");
    assert_eq!(
        err,
        AskRefusal::Ungranted {
            server: "payments".into(),
            ask: "sampling"
        }
    );
    assert!(
        err.to_string().contains("not proxied to the caller"),
        "the refusal must state that the ask terminates at busbar: {err}"
    );
    // A refused round does not consume the budget: a hostile upstream must not be able to exhaust
    // the loop with asks it was never going to be allowed to make.
    assert_eq!(l.rounds(), 0);
}

/// The grant is re-derived on EVERY round. There is no handshake to authorise once and then trust,
/// so each retry must re-read the live registry — which is what makes a revocation bite on the very
/// next retry rather than at the end of a conversation that has no end.
#[test]
fn a_revoked_grant_bites_on_the_very_next_retry() {
    let granted = ServerRequestGrants {
        sampling: true,
        ..Default::default()
    };
    let mut l = InputRequiredLoop::new("s", 10);
    assert!(l.may_satisfy(ServerAsk::Sampling, granted).is_ok());
    assert!(l.may_satisfy(ServerAsk::Sampling, granted).is_ok());
    // The operator revokes. The next round is refused — there is no handshake this was authorised
    // at, and nothing cached the earlier answer.
    assert!(l
        .may_satisfy(ServerAsk::Sampling, ServerRequestGrants::default())
        .is_err());
    assert_eq!(l.rounds(), 2, "only the satisfied rounds are counted");
}

/// One grant does not imply another. A server allowed to ask for sampling may not ask for roots.
#[test]
fn each_grant_is_independent() {
    let sampling_only = ServerRequestGrants {
        sampling: true,
        ..Default::default()
    };
    let mut l = InputRequiredLoop::new("s", 10);
    assert!(l.may_satisfy(ServerAsk::Sampling, sampling_only).is_ok());
    assert!(l.may_satisfy(ServerAsk::Roots, sampling_only).is_err());
    assert!(l
        .may_satisfy(ServerAsk::Elicitation, sampling_only)
        .is_err());
}

/// The loop is a HARD CAP, refused past it, not a warning. This is the cost-amplification defence:
/// dropping the handshake turns one call into a SEQUENCE, a hostile upstream can answer
/// `InputRequiredResult` forever, and every satisfied sampling round is a real LLM call against real
/// budget.
#[test]
fn a_hostile_upstream_cannot_amplify_cost_by_asking_forever() {
    let granted = ServerRequestGrants {
        sampling: true,
        ..Default::default()
    };
    let mut l = InputRequiredLoop::new("hostile", 3);
    for i in 0..3 {
        assert!(
            l.may_satisfy(ServerAsk::Sampling, granted).is_ok(),
            "round {i} must be allowed"
        );
    }
    let err = l
        .may_satisfy(ServerAsk::Sampling, granted)
        .expect_err("the cap must be hard");
    assert_eq!(
        err,
        AskRefusal::LoopExhausted {
            server: "hostile".into(),
            max_rounds: 3
        }
    );
    // And it stays refused: a cap that resets is not a cap.
    assert!(l.may_satisfy(ServerAsk::Sampling, granted).is_err());
    assert_eq!(l.rounds(), 3, "the metered count is exactly the cap");
}

/// The bound is PER DISPATCH. A fresh loop for a fresh dispatch starts clean, because there is no
/// connection-scoped state under this revision and a counter that outlived a dispatch would be a
/// session by another name.
#[test]
fn the_bound_is_per_dispatch() {
    let granted = ServerRequestGrants {
        sampling: true,
        ..Default::default()
    };
    let mut a = InputRequiredLoop::new("s", 1);
    assert!(a.may_satisfy(ServerAsk::Sampling, granted).is_ok());
    assert!(a.may_satisfy(ServerAsk::Sampling, granted).is_err());
    let mut b = InputRequiredLoop::new("s", 1);
    assert!(b.may_satisfy(ServerAsk::Sampling, granted).is_ok());
}

/// A cap of zero denies everything. The registration default is one round, but an operator who wants
/// none must get none rather than "one, because zero looked like unset".
#[test]
fn a_cap_of_zero_denies_every_round() {
    let granted = ServerRequestGrants {
        sampling: true,
        ..Default::default()
    };
    let mut l = InputRequiredLoop::new("s", 0);
    assert!(matches!(
        l.may_satisfy(ServerAsk::Sampling, granted),
        Err(AskRefusal::LoopExhausted { .. })
    ));
}
