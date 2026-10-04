// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: hook`, BOTH WAYS, THROUGH THE ONE DISPATCHER** (TODO ABI-b4).
//! The hook kind's fixture (`hook_door_plugin`) loaded LINKED and DROPPED IN (`door_both_ways`) and
//! driven over one script of the kind's table: `validate` and `open` over bad and good settings,
//! `decide` over a request inside the gate (ABSTAIN) and one over it (REJECT with its status), an op
//! the plugin refuses (`status`), and `close`. The two transcripts must be equal, line for line.
//!
//! RED ARM, KEPT: [`a_hook_that_answers_two_verbs_is_refused_through_both_doors`] loads the
//! fixture's [`broken`](hook_door_plugin::broken) door — `decide` answering PREFER and REJECT at
//! once — the same two ways: the dispatcher answers FAULT on both, where the conforming door answers
//! one verb.
//!
//! The fixture stands in for the kind's real plugins: none is a row of the both-ways table on this
//! SDK yet, so the proof holds the kind's table, not one plugin.

use busbar_contract::abi::hook::{slot, DecideIn, DecideOut, StatusOut};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};

use super::door_both_ways::{self as both, close, input, line, octets, open, output, same};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{Frame, Plugin};

#[path = "../../tests/fixtures/hook_door_plugin.rs"]
pub(crate) mod hook_door_plugin;

/// The instance's settings: reject a request of more than three messages.
const SETTINGS: &[u8] = br#"{"reject_over_messages": 3}"#;

/// `validate` over `settings`.
fn validate(p: &Plugin<Hook>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = octets(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

/// `decide` over a request of `messages` messages: the host's line and the verdict it read.
fn decide(p: &Plugin<Hook>, messages: u64) -> String {
    let mut d: Frame<DecideIn, DecideOut> = Frame::new(input(), output());
    d.input.request.request_id = 7;
    d.input.request.message_count = messages;
    let c = p.call(slot::DECIDE, &mut d);
    format!(
        "{} verbs={:#x} reject_status={}",
        line(&format!("decide {messages}"), &c),
        d.out.verbs,
        d.out.reject_status
    )
}

/// `status`, which the fixture refuses.
fn status(p: &Plugin<Hook>) -> String {
    let mut s: Frame<InHead, StatusOut> = Frame::new(input(), output());
    line("status", &p.call(slot::STATUS, &mut s))
}

/// THE SCRIPT, one line per answer.
fn script(p: &Plugin<Hook>) -> Vec<String> {
    vec![
        validate(p, br#"{"reject_over_messages": "three"}"#),
        validate(p, SETTINGS),
        line("open, bad settings", &open(p, b"[]")),
        line("open", &open(p, SETTINGS)),
        decide(p, 2),
        decide(p, 5),
        status(p),
        line("close", &close(p)),
    ]
}

#[test]
fn a_linked_and_a_dropped_in_hook_decide_identically() {
    let door = hook_door_plugin::conforming::door;
    let linked = script(&both::linked::<Hook>(door).plugin);
    let Some(dropped) = both::dropped::<Hook>(door, "hook_door") else {
        eprintln!("skip: the hook fixture's cdylib is not built in this scoped run");
        return;
    };
    same(&linked, &script(&dropped.plugin));
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    assert!(linked[0].contains("Failed"), "{}", linked[0]);
    assert!(linked[3].contains("Ready"), "{}", linked[3]);
    assert!(
        linked[4].contains("Ready") && linked[4].contains("verbs=0x2"),
        "{}",
        linked[4]
    );
    assert!(
        linked[5].contains("Ready")
            && linked[5].contains("verbs=0x14")
            && linked[5].contains("reject_status=429"),
        "{}",
        linked[5]
    );
    assert!(linked[6].contains("Refused"), "{}", linked[6]);
}

/// THE RED ARM, KEPT: a `decide` answering two verbs at once breaks the hook kind's contract
/// (exactly one verb). Through either door the dispatcher answers FAULT, never the verdict.
#[test]
fn a_hook_that_answers_two_verbs_is_refused_through_both_doors() {
    let broken = hook_door_plugin::broken::door;
    let run = |p: &Plugin<Hook>| vec![line("open", &open(p, SETTINGS)), decide(p, 2)];
    let linked = run(&both::linked::<Hook>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let conforming = run(&both::linked::<Hook>(hook_door_plugin::conforming::door).plugin);
    assert!(conforming[1].contains("Ready"), "{}", conforming[1]);
    let Some(dropped) = both::dropped::<Hook>(broken, "hook_broken_door") else {
        eprintln!("skip: the broken hook fixture's cdylib is not built in this scoped run");
        return;
    };
    same(&linked, &run(&dropped.plugin));
}
