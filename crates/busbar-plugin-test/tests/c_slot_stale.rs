// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-STALE (ABI-MIN3-INTERFACE §14): A stale token after FAULT: no-op cancel, BadToken resume, the GLOBAL
//! slab, `tok` zeroed, a panic in Drop (Miri, loom).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::slots::{unpack, Slots};

use crate::bridge_fixture::{self as fx, Status};

/// Arm (a), single-threaded: a chain NEEDs once (inserted at `(i, g)`), its next poll is Pending with no NEED
/// (FAULT `AwaitedForeign`, slot freed, the host's token zeroed); the next NEEDing chain takes slot `i` under a
/// newer generation and answers its own value. On the table: a remove with the stale `(i, g)` is a no-op and
/// leaves the new occupant in place. (The concurrent arm and its negative controls are busbar-ffi's loom test,
/// `slots::loom_tests`; the GLOBAL-slab arm needs an async `open`, which `plugin!` wires, W1-A4.)
#[test]
fn stale_tokens_never_reach_another_chain() {
    let instance = fx::instance();
    let mut faulted = fx::parked(&instance, b"foreign");
    let (_, index, generation) = unpack(faulted.token());
    assert_eq!(
        fx::resume_secret(&mut faulted, b"one", &mut fx::lease()),
        Some(Status::FAULT),
        "Pending with no NEED: AwaitedForeign"
    );
    assert_eq!(
        faulted.token(),
        0,
        "the host's token is zeroed: its Drop cancels nothing"
    );
    drop(faulted);
    let mut next = fx::parked(&instance, b"secret");
    let (_, again, newer) = unpack(next.token());
    assert_eq!(again, index, "the freed slot is reused");
    assert_ne!(newer, generation);
    let mut lease = fx::lease();
    assert_eq!(
        fx::resume_secret(&mut next, b"mine", &mut lease),
        Some(Status::OK)
    );
    assert_eq!(fx::texts(&lease), [b"mine".to_vec()]);

    let slots: Slots<String> = Slots::new();
    let Some(first) = slots.insert("first".to_string()) else {
        panic!("insert");
    };
    let (index, generation) = first.identity().expect("live");
    assert!(first.take().is_some());
    let Some(mut second) = slots.insert("second".to_string()) else {
        panic!("insert");
    };
    let (again, newer) = second.identity().expect("live");
    assert_eq!((again, newer == generation), (index, false));
    assert_eq!(second.take_if(generation), None, "stale: a no-op");
    assert_eq!(slots.count_live(), 1, "the new occupant stays");
    assert_eq!(second.take().as_deref(), Some("second"));
}
