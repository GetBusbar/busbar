// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An upstream's `InputRequiredResult`, recognised as an ask and judged against grants that are
//! deny-by-default. A granted ask is relayed to the caller, who answers it; busbar answers none
//! (Law 11). The relay itself, and the per-dispatch round cap, are `crate::call`'s and its tests'.

use crate::client::jsonrpc::{parse_response, RpcOutcome, ServerAsk, ServerRequestGrants};

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
/// judge against the MOST PRIVILEGED grant in the set, not the first key it happens to iterate:
/// judging against the cheapest ask would let an upstream smuggle a sampling request behind a
/// `roots/list` it knows the operator lets it relay.
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
