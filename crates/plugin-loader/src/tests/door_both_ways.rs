// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE BOTH-WAYS HARNESS ON THE MEMORY ABI** (TODO ABI-b4: compiled in or
//! dropped in, the same table). One door is loaded TWICE through the one dispatcher:
//!
//! * LINKED — the door function, compiled into this test build, through [`load_linked`];
//! * DROPPED IN — the same source built as an example `cdylib`, `dlopen`ed through
//!   [`load_dropped`] against the rendering the linked door states (what a signed manifest
//!   carries).
//!
//! Each is bound to a dispatcher of its own. A kind's conformance test then runs ONE script of
//! that kind's ops against each and requires the two transcripts to be equal, line for line
//! ([`same`]). Its RED arm loads a door that breaks the kind's contract the same two ways and
//! shows the dispatcher refusing it on both.

use std::mem::MaybeUninit;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, ReleaseIn};

use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Called, DispatchConfig,
    Dispatcher, Frame, InFrame, Kind, LinkedRow, NoSink, OutFrame, Plugin,
};

/// One door loaded one way, with the dispatcher that adopted it.
pub(crate) struct Loaded<K: Kind> {
    /// The instance.
    pub(crate) plugin: Plugin<K>,
    /// Its dispatcher.
    pub(crate) dispatcher: Arc<Dispatcher>,
}

/// What every door is bound to: its own dispatcher's adopter, no envelope sink, no connections.
pub(crate) fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("both-ways"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

/// `door` LINKED, through [`load_linked`] on a fresh dispatcher.
pub(crate) fn linked<K: Kind>(door: DoorFn) -> Loaded<K> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(door).expect("the door states its Statement");
    let plugin = load_linked::<K>(&row, bind(&dispatcher)).expect("the linked door loads");
    Loaded { plugin, dispatcher }
}

/// The example `cdylib` `example` exporting the same `door`, DROPPED IN through [`load_dropped`]
/// against the rendering `door` states. `None` only in a scoped, non-CI run that did not build it
/// (`both_ways::example_cdylib` refuses to skip under CI).
pub(crate) fn dropped<K: Kind>(door: DoorFn, example: &str) -> Option<Loaded<K>> {
    let path = crate::both_ways::example_cdylib(example)?;
    Some(dropped_from(door, &path))
}

/// The `cdylib` at `path` exporting the same `door`, DROPPED IN through [`load_dropped`] against
/// the rendering `door` states: the real plugin's pinned build, found by `both_ways::cdylib`.
pub(crate) fn dropped_from<K: Kind>(door: DoorFn, path: &std::path::Path) -> Loaded<K> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let stated = rendering_of(door).expect("the door renders its Statement");
    let plugin =
        load_dropped::<K>(path, &stated, bind(&dispatcher)).expect("the dropped-in door loads");
    Loaded { plugin, dispatcher }
}

/// `bytes` as an octets blob, lent for one call.
pub(crate) fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

/// An `in` of `T`, every field zero but its head.
pub(crate) fn input<T: InFrame>() -> T {
    // SAFETY: every kind's `in` is plain integers, floats, raw pointers and unions of those, for
    // which the all-zero pattern is valid; `T` leads with an `InHead`, written below.
    let mut v: T = unsafe { MaybeUninit::zeroed().assume_init() };
    // SAFETY: `T: InFrame` leads with an `InHead`.
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}

/// An `out` of `T`, every field zero but its head (the host's FAULT pre-fill).
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

/// `open` over `settings`, ticket-less, through the dispatcher's crossing.
pub(crate) fn open<K: Kind>(p: &Plugin<K>, settings: &[u8]) -> Called {
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    o.input.settings = octets(settings);
    o.input.generation = 1;
    p.call(slot::OPEN, &mut o)
}

/// `release` of `lease`.
pub(crate) fn release<K: Kind>(p: &Plugin<K>, lease: u64) -> Called {
    let mut r: Frame<ReleaseIn, OutHead> = Frame::new(input(), output());
    r.input.lease = lease;
    p.call(slot::RELEASE, &mut r)
}

/// `close`.
pub(crate) fn close<K: Kind>(p: &Plugin<K>) -> Called {
    let mut c: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(slot::CLOSE, &mut c)
}

/// One transcript line: the step, then what the host was handed (outcome, error text, lease).
pub(crate) fn line(step: &str, c: &Called) -> String {
    let error = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{step}: {:?} lease={} error={error:?}", c.outcome, c.lease)
}

/// The two transcripts are equal, line for line; a divergence names its first line.
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
