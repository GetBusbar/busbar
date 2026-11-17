// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STORE-COMMIT (ABI-MIN3-INTERFACE §14): STORE-TRANSACTIONS §8 item 18 and `decode_decision` (round 30). Each
//! store's arm runs in its repo.
//!
//! Core's arm is `decode_decision` over a real parsed OK answer: COMMITTED code 1..=6 map to the decisions, code
//! 0 and 7 are refused, and the answer is exactly one COMMITTED record. Item 18's slot-mechanic, fence, closure,
//! lock and decode cases are the SDK store cases every store runs against its own backend in its own repository.

use busbar_contract::persistence::{ClockObservation, Decision};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::kinds::store::store as wire;
use busbar_plugin_abi::records::{RecErr, Reply, Writer};
use busbar_plugin_abi::types::Status;
use busbar_ports::codec::store::decode_decision;

const AUTHORITY: [u8; 16] = [6; 16];

fn committed(code: u32) -> Reply {
    let mut w = Reply::new();
    let rec = wire::Committed {
        code,
        _r: 0,
        observed_at: 21,
        authority: AUTHORITY,
    };
    w.put_pod(wire::tag::COMMITTED, &rec).unwrap();
    w
}

fn decide(w: &Reply) -> Result<Decision, RecErr> {
    let answer = Answer::parse(Status::OK, w.as_bytes()).expect("a well-formed OK answer");
    decode_decision(&answer)
}

#[test]
fn decode_decision_and_the_sdk_store_cases() {
    assert!(matches!(decide(&committed(1)), Ok(Decision::Applied(_))));
    assert!(matches!(
        decide(&committed(2)),
        Ok(Decision::ConditionConflict)
    ));
    let at = ClockObservation {
        authority: AUTHORITY,
        unix_seconds: 21,
    };
    assert!(matches!(
        decide(&committed(3)),
        Ok(Decision::TimeGuardFailed { observed_at }) if observed_at == at
    ));
    assert!(matches!(decide(&committed(4)), Ok(Decision::OpIdConflict)));
    assert!(matches!(decide(&committed(5)), Ok(Decision::Fenced)));
    assert!(matches!(decide(&committed(6)), Ok(Decision::Stale)));
    assert_eq!(decide(&committed(0)).err(), Some(RecErr::Size));
    assert_eq!(decide(&committed(7)).err(), Some(RecErr::Size));

    // Exactly one COMMITTED record: an extra record, none, or two are all malformed.
    let mut extra = committed(1);
    extra.put(wire::tag::RESULT, b"echoed").unwrap();
    assert!(decide(&extra).is_err());
    assert!(decide(&Reply::new()).is_err());
    let mut twice = committed(1);
    let again = wire::Committed {
        code: 1,
        _r: 0,
        observed_at: 21,
        authority: AUTHORITY,
    };
    twice.put_pod(wire::tag::COMMITTED, &again).unwrap();
    assert!(decide(&twice).is_err());
    // An unregistered (all-zero) authority is never a store observation.
    let mut zero = Reply::new();
    let rec = wire::Committed {
        code: 1,
        _r: 0,
        observed_at: 21,
        authority: [0; 16],
    };
    zero.put_pod(wire::tag::COMMITTED, &rec).unwrap();
    assert_eq!(decide(&zero).err(), Some(RecErr::Size));
}
