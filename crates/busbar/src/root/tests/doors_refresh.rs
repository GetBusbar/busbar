// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{ConnIn, ConnOut, DialIn, ShutIn};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::carrier::Carry;
use busbar_core_connector::framer::FramerDoor;

use busbar_core_connector::doors::{refresh_named, row_bind, Dispatched};

use busbar_test_kit::root_door_fixtures::held_down;

fn opened(row: &str, settings: &TransportSettings) -> Arc<Dispatched> {
    let plugin = crate::root::test_plugins::linked_transport(
        held_down::door,
        row_bind(row).expect("the row binds"),
    );
    Arc::new(Dispatched::open(plugin, settings).expect("the carrier opens"))
}

fn dial(door: &Dispatched) -> Outcome {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<DialIn>(), blank_out::<ConnOut>());
    door.carry(side.as_ref(), false, Carry::Dial(&mut i, &mut o))
        .outcome
}

fn end(door: &Dispatched) {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<ShutIn>(), blank_out::<OutHead>());
    let shut = door.carry(side.as_ref(), false, Carry::Shut(&mut i, &mut o));
    assert_eq!(shut.outcome, Outcome::Ready, "the program's end is taken");
}

fn holds(door: &Dispatched, secs: u64) -> bool {
    let side = door.side().expect("a carrier crosses on a side");
    let mut i = blank_in::<ConnIn>();
    i.conn = secs;
    let mut o = blank_out::<OutHead>();
    door.carry(side.as_ref(), false, Carry::Flush(&mut i, &mut o))
        .outcome
        == Outcome::Ready
}

#[test]
fn an_apply_refreshes_a_live_transport_and_its_next_dial_spawns() {
    let settings = TransportSettings::default();
    let door = opened("row159-apply-clears", &settings);
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "a fresh member's program spawns"
    );
    end(&door);
    assert_eq!(
        dial(&door),
        Outcome::Failed,
        "a program that ended is held down by its carrier"
    );

    let refused = refresh_named(&settings, |name| name.starts_with("row159-"));
    assert!(
        refused.is_empty(),
        "the carrier took the apply's refresh: {refused:?}"
    );
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "after the apply the carrier's refresh released the hold, and the next dial spawns"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refresh handed it the applied timeout"
    );
}

#[test]
fn a_refused_refresh_keeps_the_prior_settings() {
    let settings = TransportSettings::default();
    let door = opened("row159-refused-keeps", &settings);
    assert!(
        holds(&door, settings.request_timeout_secs),
        "it opened with the deployment's timeout"
    );
    let refusing = TransportSettings {
        request_timeout_secs: held_down::REFUSED_TIMEOUT_SECS,
        ..settings
    };
    let why = door
        .refresh(&refusing)
        .expect_err("the sentinel timeout is refused");
    assert!(
        why.contains("did not refresh"),
        "the refusal says so: {why}"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refused refresh left the prior timeout in place"
    );
    assert!(
        !holds(&door, held_down::REFUSED_TIMEOUT_SECS),
        "the refused value was not taken"
    );
    assert_eq!(dial(&door), Outcome::Ready, "the instance keeps serving");
}
