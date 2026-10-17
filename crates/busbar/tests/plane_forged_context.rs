// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #74 ON THE CALLER'S THREAD: a forged context handed to the host from inside a NON-lifecycle op
//! (a plane's `arrive`, crossed on the calling thread, not on the FFI worker) quarantines the
//! instance, and the forging op itself answers FAULT.
//!
//! The plane is the plane-driver test plane, LINKED: its `/forge-context` arrival hands the host's
//! `wake` its own context one tag bit off, then answers as the plane does.

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome};
use busbar_contract::abi::mechanism::lifecycle::OpenIn;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneOpenIn, PlaneOpenOut, UnitCount,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::{
    kinds::plane::Plane, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, NO_BLOB,
};

#[test]
fn a_forged_context_in_a_non_lifecycle_op_answers_fault_and_quarantines() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(plane::door).expect("the plane states its Statement");
    let plugin = load_linked::<Plane>(&row, bind).expect("the linked door loads");
    let mut open_frame = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                settings: NO_BLOB,
                generation: 1,
                ..blank_in()
            },
            owned: NO_BLOB,
            ..blank_in()
        },
        blank_out::<PlaneOpenOut>(),
    );
    assert_eq!(plugin.open(&mut open_frame).0.outcome, AbiOutcome::Ready);

    let mut units = vec![
        UnitCount {
            class: 0,
            source: 0,
            amount: 0
        };
        16
    ];
    let mut arrive_frame = Frame::new(
        ArriveIn {
            target: AbiStr::over(b"/forge-context"),
            method: AbiStr::over(b"POST"),
            body: NO_BLOB,
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            ..blank_in()
        },
        blank_out::<ArriveOut>(),
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut arrive_frame).outcome,
        AbiOutcome::Fault,
        "the forging arrive answered other than FAULT"
    );
    assert!(
        plugin.is_faulted(),
        "the forging instance was not quarantined"
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut arrive_frame).outcome,
        AbiOutcome::Fault,
        "a quarantined instance was called again"
    );
}
