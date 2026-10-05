// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DISCOVERY AT BOOT (ARCHITECT 2026-10-02): the mechanism's optional `ready`, awaited after `open`
//! on a real ticket before any listener binds.
//!
//! RED before this: no door could state `ready`, so a plugin that must reach the network before it
//! serves had nowhere to do it but its first op (the lazy discovery the ruling refuses), and no
//! refusal of it could stop the boot.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};

use super::ready_plugins::{with_ready, without_ready};
use crate::dispatch::kinds::secret::Secret;
use crate::dispatch::load::validate_door;
use crate::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin,
};

const WITHIN: Duration = Duration::from_secs(5);

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 16,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

/// `door` loaded on `d` and opened with `settings`.
fn opened(d: &Dispatcher, door: DoorFn, settings: &'static [u8]) -> Plugin<Secret> {
    let row = LinkedRow::of(door).expect("the witness states its Statement");
    let plugin = load_linked::<Secret>(&row, bind(d)).expect("the witness loads");
    let mut i: OpenIn = blank_in();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut f = Frame::new(i, blank_out::<OpenOut>());
    assert_eq!(plugin.call(slot::OPEN, &mut f).outcome, Outcome::Ready);
    plugin
}

fn crossings(p: &Plugin<Secret>) -> u64 {
    p.inner.crossings.load(Ordering::Relaxed)
}

#[test]
fn red_a_ready_that_answers_err_refuses_the_boot_with_its_text() {
    let d = dispatcher();
    let p = opened(&d, with_ready::door, b"err:discovery answered 503");
    assert!(p.has_ready());
    assert_eq!(
        p.ready(&d, WITHIN),
        Err("plugin 'ready-witness' ready failed: discovery answered 503".to_string())
    );
}

#[test]
fn a_ready_that_pends_serves_after_its_wake() {
    let d = dispatcher();
    let p = opened(&d, with_ready::door, b"pend");
    let before = crossings(&p);
    assert_eq!(p.ready(&d, WITHIN), Ok(()));
    // It pended once and was resumed once, on its ticket, by the wake it fired.
    assert_eq!(
        crossings(&p),
        before + 2,
        "one PENDING crossing, then its RESUME"
    );
}

#[test]
fn a_ready_that_answers_at_once_serves() {
    let d = dispatcher();
    let p = opened(&d, with_ready::door, b"{}");
    let before = crossings(&p);
    assert_eq!(p.ready(&d, WITHIN), Ok(()));
    assert_eq!(crossings(&p), before + 1);
}

#[test]
fn a_plugin_without_ready_is_opened_exactly_as_before() {
    let d = dispatcher();
    // Its settings would refuse a `ready`: it is never called.
    let p = opened(&d, without_ready::door, b"err:never read");
    assert!(!p.has_ready());
    let before = crossings(&p);
    assert_eq!(p.ready(&d, WITHIN), Ok(()));
    assert_eq!(
        crossings(&p),
        before,
        "no crossing for a door that states no ready"
    );
}

#[test]
fn ready_before_open_is_refused_without_a_crossing() {
    let d = dispatcher();
    let row = LinkedRow::of(with_ready::door).expect("the witness states its Statement");
    let p = load_linked::<Secret>(&row, bind(&d)).expect("the witness loads");
    assert_eq!(
        p.ready(&d, WITHIN),
        Err("plugin 'ready-witness' ready failed: Refused".to_string())
    );
    assert_eq!(crossings(&p), 0);
}

/// APPEND-ONLY: a door built before the `ready` tail (its `size` ends at `ops`) still loads, and the
/// host never reads past its size — whatever lies there.
#[test]
fn a_door_that_ends_before_ready_loads_with_none() {
    // SAFETY: the witness's door is `'static`.
    let real: Door = unsafe { *with_ready::door() };
    assert!(real.ready.is_some(), "the witness states ready");
    let older: &'static Door = Box::leak(Box::new(Door {
        size: std::mem::offset_of!(Door, ready) as u32,
        ..real
    }));
    let v = validate_door::<Secret>(older).unwrap_or_else(|e| panic!("an older door loads: {e}"));
    assert!(
        v.ready.is_none(),
        "a tail the door's size does not cover is absent"
    );
    let whole = validate_door::<Secret>(&real).unwrap_or_else(|e| panic!("the door loads: {e}"));
    assert!(whole.ready.is_some());
}
