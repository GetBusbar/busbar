// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::mem::MaybeUninit;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, ReleaseIn};

use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Called, DispatchConfig,
    Dispatcher, Frame, InFrame, Kind, LinkedRow, NoSink, OutFrame, Plugin,
};

pub(crate) struct Loaded<K: Kind> {
    pub(crate) plugin: Plugin<K>,

    pub(crate) dispatcher: Arc<Dispatcher>,
}

pub(crate) fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("both-ways"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

pub(crate) fn linked<K: Kind>(door: DoorFn) -> Loaded<K> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(door).expect("the door states its Statement");
    let plugin = load_linked::<K>(&row, bind(&dispatcher)).expect("the linked door loads");
    Loaded { plugin, dispatcher }
}

pub(crate) fn dropped<K: Kind>(door: DoorFn, example: &str) -> Loaded<K> {
    let path = crate::both_ways::example_cdylib(example);
    dropped_from(door, &path)
}

pub(crate) fn dropped_from<K: Kind>(door: DoorFn, path: &std::path::Path) -> Loaded<K> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let stated = rendering_of(door).expect("the door renders its Statement");
    let plugin =
        load_dropped::<K>(path, &stated, bind(&dispatcher)).expect("the dropped-in door loads");
    Loaded { plugin, dispatcher }
}

pub(crate) fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

pub(crate) fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, floats, raw pointers and unions of those, for
    // which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

pub(crate) fn output<T: OutFrame>() -> T {
    // SAFETY: as `input`, with an `OutHead` first.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: OutFrame` leads with an `OutHead`.
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}

pub(crate) fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    o.input.settings = octets(settings);
    o.input.generation = 1;
    p.call(slot::OPEN, &mut o)
}

pub(crate) fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut r: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    r.input.lease = lease;
    p.call(slot::RELEASE, &mut r)
}

pub(crate) fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut c: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(slot::CLOSE, &mut c)
}

pub(crate) fn line(step: &str, c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{step}: {:?} lease={} error={error:?}", c.outcome, c.lease)
}

pub(crate) fn same(linked: &[String], dropped: &[String]) {
    for (i, (a, b)) in linked.iter().zip(dropped).enumerate() {
        assert_eq!(
            a, b,
            "the two doors diverge at line {i}:\n linked:     {a}\n dropped in: {b}"
        );
    }
    assert_eq!(
        linked.len(),
        dropped.len(),
        "the two doors ran different scripts"
    );
}
