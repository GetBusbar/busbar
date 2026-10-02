// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK AXIS, BOTH WAYS (THE DESIGN §11.4; the SWITCH-OVER card, hook root axis): the hook
//! kind's fixture (`hook_door_plugin`) reached through [`HookRows`] as a LINKED row (its door) and as
//! a DROPPED-IN row (its example `cdylib`'s bytes, admitted against the rendering its door states),
//! probed, opened and called through the contract's [`HookAxis`] / [`HookCalls`] on the one
//! dispatcher. The two transcripts must be equal, line for line: the axis loads both doors through
//! the one loader path and reads nothing of which door a row came in by.
//!
//! RED ARM, KEPT: [`a_hook_that_breaks_the_kind_contract_is_broken_through_both_doors`] opens the
//! fixture's broken door (`decide` answering two verbs) the same two ways: the axis answers
//! [`Answered::Broken`] on both, where the conforming door answers one verb.
//!
//! RED ARM (ARCHITECT Q-SO8): [`a_hook_statement_without_its_kind_tail_is_refused_at_load`] — the
//! conforming plugin with no hook tail does not load; the refusal names the missing tail.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::hook_calls::{Answered, HookAxis, HookFacts};
use busbar_contract::hooks::{RoutingContext, RoutingRequest};
use busbar_contract::SignalBag;
use serde_json::json;

use super::HookRows;
use crate::boot::{Candidate, Origin};
use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher};

use crate::hook_door_conformance_tests::hook_door_plugin;

use hook_door_plugin::{BROKEN_NAME, NAME, REJECT_STATUS, UNTAILED_NAME};

/// Every call's budget.
const BUDGET: Duration = Duration::from_secs(5);

/// A request of `messages` messages.
fn request(messages: usize) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: messages,
        tool_count: 0,
        has_tools: false,
        total_chars: 11,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
    }
}

/// The `decide` frame of a request of `messages` messages over no candidates.
fn frame(messages: usize) -> Arc<DecideFrame> {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::first(DecideView::build(&request(messages), &[], &ctx))
}

/// How a row reaches the axis.
#[derive(Debug, Clone, Copy)]
enum Way {
    Linked,
    Dropped,
}

/// The axis over `door`, its one row reached `way`. `None` for a dropped-in row whose example
/// `cdylib` (`example`) a scoped, non-CI run did not build.
fn rows(door: DoorFn, example: &str, way: Way) -> Option<HookRows> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    match way {
        Way::Linked => Some(HookRows::new(&[door], None, dispatcher).expect("the linked row")),
        Way::Dropped => {
            let path = crate::both_ways::example_cdylib(example)?;
            let bytes = std::fs::read(&path).expect("the example cdylib reads");
            let row = Candidate::from_rendering(
                rendering_of(door).expect("the door renders its Statement"),
                None,
                Origin::Dropped {
                    file: format!("{example}.tar.gz"),
                    bytes: Arc::new(bytes),
                },
            )
            .expect("the rendering states a candidate");
            Some(HookRows::of(vec![row], dispatcher))
        }
    }
}

/// One `decide` answer, as a line.
fn decided(messages: usize, a: &Answered<busbar_contract::abi::hook::DecideOut>) -> String {
    match a {
        Answered::Answer {
            outcome,
            out,
            error,
            ..
        } => format!(
            "decide {messages}: {outcome:?} verbs={:#x} reject_status={} error={error:?}",
            out.verbs, out.reject_status
        ),
        Answered::TimedOut => format!("decide {messages}: timed out"),
        Answered::Broken(why) => format!("decide {messages}: broken ({why})"),
    }
}

/// THE SCRIPT through the axis, one line per answer.
async fn script(rows: &HookRows, module: &str) -> Vec<String> {
    let probed = |settings: serde_json::Value| rows.probe(module, "gate", &settings);
    let mut lines = vec![
        format!(
            "probe bad: {:?}",
            probed(json!({"reject_over_messages": "three"}))
        ),
        format!(
            "probe good: {:?}",
            probed(json!({"reject_over_messages": 3}))
        ),
        format!(
            "probe nobody: {:?}",
            rows.probe("nobody", "gate", &json!({}))
        ),
    ];
    let calls = rows
        .open(
            module,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .expect("the hook opens through the axis");
    lines.push(format!("name: {}", calls.name()));
    for messages in [2, 5] {
        lines.push(decided(
            messages,
            &calls.decide(frame(messages), BUDGET).await,
        ));
    }
    lines.push(format!("status: {:?}", calls.status(BUDGET).await));
    lines.push(format!(
        "configure: {:?}",
        calls.configure("gate", "{}", 2, BUDGET).await
    ));
    lines
}

#[tokio::test]
async fn a_linked_and_a_dropped_in_hook_open_through_the_axis_and_decide_identically() {
    let door = hook_door_plugin::conforming::door;
    let linked_rows = rows(door, "hook_door", Way::Linked).expect("linked");
    let linked = script(&linked_rows, NAME).await;
    let Some(dropped_rows) = rows(door, "hook_door", Way::Dropped) else {
        eprintln!("skip: the hook fixture's cdylib is not built in this scoped run");
        return;
    };
    let dropped = script(&dropped_rows, NAME).await;
    assert_eq!(linked, dropped, "the same table, whichever door");
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    let facts = HookFacts {
        name: NAME.to_string(),
        class: CLASS_GATE,
        prompt: PROMPT_NO,
        user: USER_NO,
        infallible: false,
        words: Vec::new(),
    };
    assert!(
        linked[0].contains(&format!("{facts:?}")) && linked[0].contains("must be a number"),
        "{}",
        linked[0]
    );
    assert!(linked[1].ends_with("[]))"), "{}", linked[1]);
    assert_eq!(linked[2], "probe nobody: None");
    assert_eq!(linked[3], format!("name: {NAME}"));
    assert!(
        linked[4].contains("Ready") && linked[4].contains("verbs=0x2 "),
        "{}",
        linked[4]
    );
    assert!(
        linked[5].contains("Ready")
            && linked[5].contains("verbs=0x14 ")
            && linked[5].contains(&format!("reject_status={REJECT_STATUS}")),
        "{}",
        linked[5]
    );
    assert_eq!(linked[6], "status: None", "the fixture refuses `status`");
    assert!(linked[7].starts_with("configure: Err("), "{}", linked[7]);
}

/// THE RED ARM, KEPT: a `decide` answering two verbs at once breaks the hook kind's contract.
/// Through either door the axis answers BROKEN, never a verdict.
#[tokio::test]
async fn a_hook_that_breaks_the_kind_contract_is_broken_through_both_doors() {
    let run = |rows: HookRows| async move {
        let calls = rows
            .open(
                BROKEN_NAME,
                "hooks.gate",
                &json!({"reject_over_messages": 3}),
                BUDGET,
            )
            .expect("the broken hook still opens");
        decided(2, &calls.decide(frame(2), BUDGET).await)
    };
    let broken = hook_door_plugin::broken::door;
    let linked = run(rows(broken, "hook_broken_door", Way::Linked).expect("linked")).await;
    assert!(
        linked.contains("broken (") && linked.contains("FAULT"),
        "{linked}"
    );
    // The conforming door under the broken door's name is not a row: the axis names the module.
    let refused = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked)
        .expect("linked")
        .open(BROKEN_NAME, "hooks.gate", &json!({}), BUDGET)
        .err();
    assert!(
        refused.is_some_and(|e| e.contains(BROKEN_NAME)),
        "an unknown module is refused, named"
    );
    let Some(dropped_rows) = rows(broken, "hook_broken_door", Way::Dropped) else {
        eprintln!("skip: the broken hook fixture's cdylib is not built in this scoped run");
        return;
    };
    assert_eq!(
        linked,
        run(dropped_rows).await,
        "the same refusal, whichever door"
    );
}

#[test]
fn a_linked_row_is_linked_and_first_party_and_a_dropped_in_unsigned_row_is_neither() {
    let door = hook_door_plugin::conforming::door;
    let linked = rows(door, "hook_door", Way::Linked).expect("linked");
    assert!(linked.linked(NAME) && linked.first_party(NAME));
    assert!(!linked.linked("nobody") && !linked.first_party("nobody"));
    let Some(dropped) = rows(door, "hook_door", Way::Dropped) else {
        eprintln!("skip: the hook fixture's cdylib is not built in this scoped run");
        return;
    };
    assert!(!dropped.linked(NAME) && !dropped.first_party(NAME));
}

/// RED ARM (Q-SO8): a hook Statement with no kind tail is refused at load, named; nothing assumes
/// a class or grants for it. The conforming door, which states its tail, opens.
#[test]
fn a_hook_statement_without_its_kind_tail_is_refused_at_load() {
    let untailed = rows(hook_door_plugin::untailed::door, "hook_door", Way::Linked)
        .expect("the row states its name");
    assert_eq!(
        untailed.probe(UNTAILED_NAME, "gate", &json!({"reject_over_messages": 3})),
        Some((None, Vec::new())),
        "an untailed hook states no facts"
    );
    let refused = untailed
        .open(
            UNTAILED_NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        )
        .err()
        .expect("an untailed hook is refused at load");
    assert!(
        refused.contains(crate::dispatch::kinds::hook::NO_TAIL) && refused.contains(UNTAILED_NAME),
        "{refused}"
    );
    let tailed = rows(hook_door_plugin::conforming::door, "hook_door", Way::Linked)
        .expect("linked")
        .open(
            NAME,
            "hooks.gate",
            &json!({"reject_over_messages": 3}),
            BUDGET,
        );
    assert!(tailed.is_ok(), "the tailed door opens");
}
