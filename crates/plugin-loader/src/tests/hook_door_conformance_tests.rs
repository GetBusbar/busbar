// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::hook::{slot, DecideIn, DecideOut, StatusOut};
use busbar_contract::abi::mechanism::call::{InHead, OutHead};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};

use super::door_both_ways::{self as both, close, input, line, octets, open, output, same};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{Frame, Plugin};

#[path = "../../tests/fixtures/hook_door_plugin.rs"]
pub(crate) mod hook_door_plugin;

const SETTINGS: &[u8] = br#"{"reject_over_messages": 3}"#;

fn validate(p: &Plugin<Hook>, settings: &[u8]) -> String {
    let mut v: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    v.input.settings = octets(settings);
    line("validate", &p.call(life::VALIDATE, &mut v))
}

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

#[allow(unsafe_code)]
fn status(p: &Plugin<Hook>) -> String {
    use busbar_contract::abi::mechanism::call::{Outcome, BLOB_JSON};
    let mut s: Frame<InHead, StatusOut> = Frame::new(input(), output());
    let called = p.call(slot::STATUS, &mut s);
    assert_eq!(called.outcome, Outcome::Ready);
    assert_ne!(
        called.lease, 0,
        "the SDK owns its status answer under a lease"
    );
    assert_eq!(s.out.status.fmt, BLOB_JSON);
    assert_eq!(s.out.status.len, 2);
    assert!(!s.out.status.ptr.is_null());
    // SAFETY: the dispatcher validated this READY blob, and its lease remains live here.
    let bytes = unsafe { std::slice::from_raw_parts(s.out.status.ptr, s.out.status.len) }.to_vec();

    assert_eq!(bytes, b"{}");
    let released = both::release(p, called.lease);
    assert_eq!(released.outcome, Outcome::Ready);
    format!(
        "{} bytes={bytes:?} {}",
        line("status", &called),
        line("release status", &released)
    )
}

fn script(p: &Plugin<Hook>) -> Vec<String> {
    vec![
        validate(p, br#"{"reject_over_messages":"invalid"}"#),
        validate(p, SETTINGS),
        line("open, bad settings", &open(p, b"[]")),
        line("open", &open(p, SETTINGS)),
        decide(p, 2),
        decide(p, 4),
        status(p),
        line("close", &close(p)),
    ]
}

#[test]
fn a_linked_and_a_dropped_in_hook_decide_identically() {
    let linked = script(&both::linked::<Hook>(hook_door_plugin::conforming::door).plugin);
    let dropped = both::dropped::<Hook>(hook_door_plugin::conforming::door, "hook_door");
    same(&linked, &script(&dropped.plugin));
    assert!(linked[0].contains("Failed"), "{}", linked[0]);
    assert!(linked[1].contains("Ready"), "{}", linked[1]);
    assert!(linked[2].contains("Failed"), "{}", linked[2]);
    assert!(linked[3].contains("Ready"), "{}", linked[3]);
    assert!(linked[4].contains("Ready"), "{}", linked[4]);
    assert!(linked[5].contains("Ready"), "{}", linked[5]);
    assert!(
        linked[6].contains("Ready") && linked[6].contains("bytes=[123, 125]"),
        "{}",
        linked[6]
    );
    assert!(linked[7].contains("Ready"), "{}", linked[7]);
}

#[test]
fn a_hook_that_answers_two_verbs_is_refused_through_both_doors() {
    let broken = hook_door_plugin::broken::door;
    let run = |p: &Plugin<Hook>| vec![line("open", &open(p, SETTINGS)), decide(p, 2)];
    let linked = run(&both::linked::<Hook>(broken).plugin);
    assert!(linked[0].contains("Ready"), "{}", linked[0]);
    assert!(linked[1].contains("Fault"), "{}", linked[1]);
    let conforming = run(&both::linked::<Hook>(hook_door_plugin::conforming::door).plugin);
    assert!(conforming[1].contains("Ready"), "{}", conforming[1]);
    let dropped = both::dropped::<Hook>(broken, "hook_broken_door");
    same(&linked, &run(&dropped.plugin));
}
