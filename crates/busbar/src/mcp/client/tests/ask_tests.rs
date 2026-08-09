// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! §14.3 — an upstream's `InputRequiredResult`: deny-by-default, re-checked on every retry, bounded
//! and metered, and never proxied outward.

use crate::mcp::client::jsonrpc::{
    parse_response, AskRefusal, InputRequiredLoop, RpcOutcome, ServerAsk, ServerRequestGrants,
};

fn input_required(request: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"type":"input_required","request":"{request}"}}}}"#
    )
    .into_bytes()
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
            parse_response(&input_required(request)),
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
        parse_response(&input_required("some/future/method")),
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

/// §14.3 part 2: the grant is re-derived on EVERY round. A revocation bites on the next retry.
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

/// §14.3 part 3: the loop is a HARD CAP, refused past it. This is the cost-amplification defence —
/// every satisfied sampling round is a real LLM call against real budget.
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
