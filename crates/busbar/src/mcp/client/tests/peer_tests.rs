// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A CHILD SENDS BUSBAR — classification, the deny-by-default gate on the three authority
//! asks, and the two facts that stop a well-behaved child from desynchronising the stream.
//!
//! The paired end-to-end battery is `crate::mcp::tests/stdio_client_leg_tests.rs`: this file proves
//! what the classifier DECIDES, that one proves a real child process's real notifications and real
//! requests reach it. Neither substitutes for the other, and the reason is the one
//! `stdio_dispatch_tests.rs` records: a complete, adversarially tested classifier that nothing calls
//! is what the deleted stdio transport was.

use super::super::jsonrpc::ServerAsk;
use super::super::peer::{
    answer, classify, decide_ask, method_not_found, AskOutcome, NotificationEffect, ServerMessage,
    ServerNotification, ServerRequestVerb,
};
use crate::mcp::config::ServerRequestGrants;

fn line(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).expect("the fixture is JSON")
}

/// EVERY server-originated method in the inventory column is classified, and none of them lands in
/// an "unknown" arm.
///
/// Read from the GENERATED matrix for the reason `verb_tests` gives: a list written from knowledge
/// of the specification is how a column silently ends early.
#[test]
fn every_server_originated_method_in_the_inventory_is_classified() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../qa/method-inventory.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parses");
    let owed: Vec<String> = doc["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .filter(|c| {
            c["protocol"] == "mcp"
                && c["transport"] == "stdio"
                && c["role"] == "client"
                && c["originator"] == "server"
                && c["na_reason"].is_null()
        })
        .map(|c| c["method"].as_str().expect("method").to_string())
        .collect();
    assert!(
        owed.len() >= 12,
        "only {} server-originated stdio cells found; a filter that matched nothing would report \
         complete handling of nothing",
        owed.len()
    );
    for method in &owed {
        // A NOTIFICATION-SHAPED LINE (no id) and a REQUEST-SHAPED one (with id) are BOTH tried, and
        // exactly one of them must be recognised: `ping` is only ever a request and
        // `notifications/message` is only ever a notification, so requiring both to work would be
        // requiring busbar to accept a shape the specification does not define.
        let as_notification = classify(&line(&format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{{}}}}"#
        )));
        let as_request = classify(&line(&format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{{}}}}"#
        )));
        let known_notification = matches!(as_notification, Some(ServerMessage::Notification(_)));
        let known_request = matches!(as_request, Some(ServerMessage::Request { .. }));
        assert!(
            known_notification || known_request,
            "`{method}` is in the matrix as a message a server sends busbar and the classifier \
             recognises neither shape of it: {as_notification:?} / {as_request:?}"
        );
    }
}

/// A RESPONSE IS NOT A SERVER MESSAGE, and this is the assertion that keeps the stream in sync.
///
/// If a response could be classified as anything, the read loop would consume it as an interleaved
/// message and go on waiting for an answer that has already arrived.
#[test]
fn a_response_is_never_a_server_message() {
    for raw in [
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#,
        // The adversarial one: a line carrying BOTH a result and a method. It must read as the
        // response it claims to be, never be executed as a request the peer did not send.
        r#"{"jsonrpc":"2.0","id":1,"result":{},"method":"sampling/createMessage"}"#,
    ] {
        assert_eq!(
            classify(&line(raw)),
            None,
            "a response must never classify as a server-originated message: {raw}"
        );
    }
}

/// A REQUEST WITH A NULL `id` IS A NOTIFICATION, not a request with a null id.
///
/// Answering it would put a response on the stream that nothing can correlate, which the base
/// protocol reserves for errors about un-parseable requests.
#[test]
fn a_null_id_is_read_as_a_notification() {
    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","id":null,"method":"notifications/message","params":{}}"#
        )),
        Some(ServerMessage::Notification(ServerNotification::Message))
    );
}

/// AN UNKNOWN REQUEST IS ANSWERED `-32601`. AN UNKNOWN NOTIFICATION IS NOT ANSWERED AT ALL.
///
/// The asymmetry is the whole point: a dropped request is a child blocked on a reply forever, and a
/// hang is a worse diagnosis than a refusal. A notification, by definition, has nobody listening.
#[test]
fn an_unknown_request_is_answered_and_an_unknown_notification_is_not() {
    let Some(ServerMessage::UnknownRequest { id, method }) = classify(&line(
        r#"{"jsonrpc":"2.0","id":5,"method":"totally/unknown","params":{}}"#,
    )) else {
        panic!("an unrecognised request must be classified as one");
    };
    assert_eq!(method, "totally/unknown");
    let reply = method_not_found(&id, &method);
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["error"]["code"], -32601);

    assert_eq!(
        classify(&line(
            r#"{"jsonrpc":"2.0","method":"totally/unknown","params":{}}"#
        )),
        Some(ServerMessage::UnknownNotification("totally/unknown".into())),
        "an unrecognised notification is counted and dropped, never answered"
    );
}

/// `ping` IS ANSWERED UNCONDITIONALLY, and it is the ONLY request that is.
///
/// A ping carries no authority and its whole purpose is to let a peer tell a live process from a
/// wedged one; gating it would make busbar look dead to every child that probes.
#[test]
fn ping_is_answered_with_an_empty_result_under_no_grants() {
    let id = serde_json::json!(9);
    let reply = answer(
        &id,
        ServerRequestVerb::Ping,
        &ServerRequestGrants::default(),
        "fs",
    );
    assert_eq!(reply["id"], 9);
    assert_eq!(reply["result"], serde_json::json!({}));
    assert!(
        reply.get("error").is_none(),
        "a ping is never refused: {reply}"
    );
    assert_eq!(
        ServerRequestVerb::Ping.ask(),
        None,
        "a ping spends no authority, so it must name no grant"
    );
}

/// THE THREE AUTHORITY ASKS ARE DENY-BY-DEFAULT, and the refusal NAMES THE GRANT TO SET.
///
/// All three, not a sample. A gate proven on one kind is a gate whose other two arms have never been
/// executed, and the arm that is never executed is the arm that says yes.
#[test]
fn the_three_authority_asks_are_denied_by_default_and_name_their_grant() {
    let none = ServerRequestGrants::default();
    for (verb, kind) in [
        (ServerRequestVerb::RootsList, "roots"),
        (ServerRequestVerb::SamplingCreateMessage, "sampling"),
        (ServerRequestVerb::ElicitationCreate, "elicitation"),
    ] {
        let ask = verb.ask().expect("an authority ask names a grant");
        assert_eq!(ask.key(), kind);
        assert_eq!(
            decide_ask(ask, &none),
            AskOutcome::Ungranted,
            "{kind} must be denied when the operator granted nothing"
        );
        let reply = answer(&serde_json::json!(3), verb, &none, "fs");
        let message = reply["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("tools.fs.grants.{kind}: true")),
            "the refusal must name the exact key an operator sets: {message}"
        );
        assert!(
            reply.get("result").is_none(),
            "a refused ask carries no result: {reply}"
        );
    }
}

/// GRANTED AND UNGRANTED ARE DIFFERENT ANSWERS, because they send an operator to different places.
///
/// A single word for both would make an operator debug the grant matrix for a decision the grant
/// matrix did not take — and, worse, would leave `Ungranted` looking identical to a grant that IS
/// held and simply cannot be satisfied.
#[test]
fn a_held_grant_produces_a_different_refusal_than_a_missing_one() {
    let all = ServerRequestGrants {
        sampling: true,
        elicitation: true,
        roots: true,
    };
    for ask in [
        ServerAsk::Sampling,
        ServerAsk::Elicitation,
        ServerAsk::Roots,
    ] {
        assert_eq!(
            decide_ask(ask, &all),
            AskOutcome::Unsatisfiable,
            "{} is granted here, so the refusal must not blame the grant",
            ask.key()
        );
        assert_eq!(
            decide_ask(ask, &ServerRequestGrants::default()),
            AskOutcome::Ungranted
        );
    }
    let granted = answer(
        &serde_json::json!(1),
        ServerRequestVerb::SamplingCreateMessage,
        &all,
        "fs",
    );
    let ungranted = answer(
        &serde_json::json!(1),
        ServerRequestVerb::SamplingCreateMessage,
        &ServerRequestGrants::default(),
        "fs",
    );
    assert_ne!(
        granted["error"]["message"], ungranted["error"]["message"],
        "the two refusals must be distinguishable; they have different remedies"
    );
    assert!(
        granted["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no satisfier"),
        "a held grant must say the satisfier is missing, not that the grant is: {granted}"
    );
}

/// ONE GRANT DOES NOT OPEN THE OTHER TWO. The three are independent authorities and a table that
/// leaked between them would let `roots: true` buy an LLM completion.
#[test]
fn each_grant_opens_only_its_own_ask() {
    let roots_only = ServerRequestGrants {
        roots: true,
        ..ServerRequestGrants::default()
    };
    assert_eq!(
        decide_ask(ServerAsk::Roots, &roots_only),
        AskOutcome::Unsatisfiable
    );
    assert_eq!(
        decide_ask(ServerAsk::Sampling, &roots_only),
        AskOutcome::Ungranted
    );
    assert_eq!(
        decide_ask(ServerAsk::Elicitation, &roots_only),
        AskOutcome::Ungranted
    );
}

/// THE FOUR "SOMETHING CHANGED" NOTIFICATIONS CAN ONLY BRING A REFRESH FORWARD, and no others can.
///
/// The set matters in both directions. A fifth notification mapped to `BringRefreshForward` would
/// give a peer another lever on busbar's outbound fetch rate; one of these four mapped to `Log`
/// would silently stop rug-pull detection reacting to the signal that exists to trigger it.
#[test]
fn only_the_change_notifications_trigger_a_refresh() {
    let expected = [
        (ServerNotification::ToolsListChanged, true),
        (ServerNotification::PromptsListChanged, true),
        (ServerNotification::ResourcesListChanged, true),
        (ServerNotification::ResourcesUpdated, true),
        (ServerNotification::Cancelled, false),
        (ServerNotification::Message, false),
        (ServerNotification::SubscriptionsAcknowledged, false),
        (ServerNotification::Tasks, false),
        (ServerNotification::Progress, false),
    ];
    assert_eq!(
        expected.len(),
        9,
        "all nine server notifications must be covered; a shrinking denominator is the failure mode"
    );
    for (n, triggers) in expected {
        assert_eq!(
            n.effect() == NotificationEffect::BringRefreshForward,
            triggers,
            "{n:?} maps to the wrong effect"
        );
    }
    assert_eq!(
        ServerNotification::Progress.effect(),
        NotificationEffect::RelayProgress,
        "progress is the one notification a caller is entitled to see relayed"
    );
}
