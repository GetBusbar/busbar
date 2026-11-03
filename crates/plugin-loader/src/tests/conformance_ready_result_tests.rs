// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The former transcript readiness assertions, exercised at the production READY boundary.

use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::ready::ready_plugins::with_ready;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

fn ready(settings: &'static [u8]) -> (Result<(), String>, u64) {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let row =
        LinkedRow::of(with_ready::door).expect("the existing READY boundary witness states itself");
    let plugin = load_linked::<Secret>(
        &row,
        Bind {
            instance: Arc::from("ready-result"),
            max_inflight_cap: 16,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the READY boundary witness loads");
    let mut input: OpenIn = blank_in();
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut frame = Frame::new(input, blank_out::<OpenOut>());
    assert_eq!(plugin.call(slot::OPEN, &mut frame).outcome, Outcome::Ready);
    assert!(plugin.has_ready());
    let before = plugin.inner.crossings.load(Ordering::Relaxed);
    let answer = plugin.ready(&dispatcher, Duration::from_secs(5));
    let crossed = plugin.inner.crossings.load(Ordering::Relaxed) - before;
    (answer, crossed)
}

#[test]
fn honest_failed_ready_is_rejected_even_at_its_exact_crossing_count() {
    let (answer, crossed) = ready(b"err:discovery answered 503");
    assert_eq!(
        crossed, 1,
        "one immediate READY crossing, despite its refusal"
    );
    assert_eq!(
        answer,
        Err("plugin 'ready-witness' ready failed: discovery answered 503".into())
    );
}

#[test]
fn the_same_door_with_successful_ready_passes_at_its_exact_count() {
    let (answer, crossed) = ready(b"{}");
    assert_eq!(crossed, 1, "one immediate READY crossing");
    assert_eq!(answer, Ok(()));
}
