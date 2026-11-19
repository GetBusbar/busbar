// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A transport door's READY answers that lease (a framer's `framer.retained_input` report) are
//! released as the connector's crossing ends: the plugin holds no answer after `go` or `go_inline`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::{abi_str, blank_in, blank_out, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Leases, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::receive;
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::*;
use busbar_contract::plugin::markers::TransportKind;
use busbar_contract::services::codes::SCHEME_PLAIN;
use busbar_contract::transport::TransportSettings;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{load_linked, DispatchConfig, Dispatcher, LinkedRow};

use crate::carrier::Side;
use crate::doors::{bind_on, Dispatched};
use crate::framer::{Call, FramerDoor};

const CLAIMS: &[AbiStr] = &[abi_str("lease-witness-wire")];
const ROWS: &[Claim] = &[Claim::EMPTY];
const FRAMER: TransportTail = {
    let mut tail = TransportTail::EMPTY.with_claim_rows(ROWS);
    tail.role = ROLE_FRAMER;
    tail.framing = FRAMING_STREAM;
    tail.frame_piece_size = FRAME_PIECE_SIZE;
    tail
};

/// How many leases the instance held when its last slot body began: every body records it on entry,
/// so a crossing reads the count the connector left behind once the previous crossing ended.
/// `usize::MAX` until a body runs (reset before each crossing so a stale count never passes).
static HELD_AT_ENTRY: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Record the instance's held leases as a slot body begins.
fn observe(leases: &Leases) {
    HELD_AT_ENTRY.store(leases.held(), Ordering::Release);
}

/// The count the last slot body saw on entry, and reset it for the next crossing.
fn held_at_entry() -> usize {
    HELD_AT_ENTRY.swap(usize::MAX, Ordering::AcqRel)
}

struct Witness;
impl Life for Witness {
    type Kind = TransportKind;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

struct Refuses<I, O>(std::marker::PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refuses<I, O> {
    type Kind = TransportKind;
    type In = I;
    type Out = O;
    type State = Held<Witness>;
    fn call(_: Instance<'_, Self::State, Self::Kind>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}
type Refuse<I, O> = busbar_contract::abi::sdk::Safe<Refuses<I, O>>;

struct Begin;
impl SafeSlot for Begin {
    type Kind = TransportKind;
    type In = BeginIn;
    type Out = FramerOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        _: Lent<'_, BeginIn>,
        mut out: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        observe(held.leases());
        out.set(|o| &o.framing, 1);
        Outcome::Ready
    }
}

/// Answer READY with a leased retained-input report of at most the `consumed` bytes.
fn report(held: &Held<Witness>, consumed: usize, out: &mut Out<'_, FramerOut>) -> Outcome {
    out.lease(
        |o| &o.head.extensions,
        held.leases(),
        receive::encode(consumed as u64),
        BLOB_OCTETS,
    );
    Outcome::Ready
}

struct Ingest;
impl SafeSlot for Ingest {
    type Kind = TransportKind;
    type In = IngestIn;
    type Out = FramerOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        input: Lent<'_, IngestIn>,
        mut out: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        observe(held.leases());
        report(held, input.get().len, &mut out)
    }
}

struct Emit;
impl SafeSlot for Emit {
    type Kind = TransportKind;
    type In = EmitIn;
    type Out = FramerOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        _: Lent<'_, EmitIn>,
        mut out: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        observe(held.leases());
        report(held, 0, &mut out)
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: statement("lease-witness", "1.6.0", 64).with_claims(CLAIMS).with_kind_tail(&FRAMER),
    lifecycle: life(Witness),
    kind_ops: {
        listen: Refuse<ListenIn, ListenOut>, accept: Refuse<AcceptIn, AcceptOut>,
        dial: Refuse<DialIn, ConnOut>, read: Refuse<ReadIn, IoOut>, write: Refuse<WriteIn, IoOut>,
        flush: Refuse<ConnIn, OutHead>, shut: Refuse<ShutIn, OutHead>,
        arrival: Refuse<ArrivalIn, ArrivalOut>, locate: Refuse<LocateIn, LocateOut>,
        begin: busbar_contract::abi::sdk::Safe<Begin>,
        ingest: busbar_contract::abi::sdk::Safe<Ingest>,
        emit: busbar_contract::abi::sdk::Safe<Emit>,
        encode: Refuse<EncodeIn, FramerOut>, refuse: Refuse<RefuseIn, FramerOut>,
        finish: Refuse<FinishIn, FramerOut>, detach: Refuse<FramingIn, FramerOut>,
        adopt: Refuse<AdoptIn, FramerOut>, timer: Refuse<FramingIn, FramerOut>,
    },
}

/// Open the witness, BEGIN under a real framing context, then 8 x (INGEST, EMIT), on `side`'s
/// inline ticket when `inline` (`go_inline`) or ticket-less (`go`).
fn every_answer_is_released(inline: bool) {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    let _serial = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let plugin = load_linked::<Transport>(&LinkedRow::of(door).unwrap(), bind_on(&dispatcher))
        .expect("the witness loads");
    let door = Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
        .expect("the witness opens");
    let cx = door
        .framing_context(0, 0)
        .expect("a framing context")
        .expect("a dispatched door scopes its framing");
    let side: Option<Box<dyn Side>> = inline.then(|| door.framing_side().expect("an inline side"));
    let side = side.as_deref();

    let mut wire = [0u8; 256];
    let mut frame = [0u8; 256];
    let sink = FramerSink {
        wire: wire.as_mut_ptr(),
        wire_cap: wire.len(),
        frame: frame.as_mut_ptr(),
        frame_cap: frame.len(),
        pieces: std::ptr::null_mut(),
        pieces_cap: 0,
        now_monotonic_ns: 1,
        now_unix_ns: 1,
        heads: std::ptr::null_mut(),
        heads_cap: 0,
    };

    let mut begin: BeginIn = blank_in();
    begin.side = SIDE_ACCEPT;
    begin.scheme = SCHEME_PLAIN;
    let mut begun: FramerOut = blank_out();
    let crossed = door.cross_scoped(Some(&cx), side, false, Call::Begin(&mut begin, &mut begun));
    assert_eq!(crossed.outcome, Outcome::Ready, "{crossed:?}");
    cx.confirm(begun.framing).expect("the framing confirms");
    assert_eq!(held_at_entry(), 0, "the instance opens holding nothing");

    // Each body records the held count on entry, so the crossing after an answer reads what the
    // connector left once that answer's crossing ended.
    let bytes = [b'x'; 16];
    let ingest = |exchange: usize| {
        let mut i: IngestIn = blank_in();
        i.framing = begun.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = sink;
        let mut o: FramerOut = blank_out();
        let crossed = door.cross_scoped(Some(&cx), side, false, Call::Ingest(&mut i, &mut o));
        assert_eq!(
            crossed.outcome,
            Outcome::Ready,
            "ingest {exchange}: {crossed:?}"
        );
    };
    let emit = |exchange: usize| {
        let mut i: EmitIn = blank_in();
        i.framing = begun.framing;
        i.sink = sink;
        let mut o: FramerOut = blank_out();
        let crossed = door.cross_scoped(Some(&cx), side, false, Call::Emit(&mut i, &mut o));
        assert_eq!(
            crossed.outcome,
            Outcome::Ready,
            "emit {exchange}: {crossed:?}"
        );
    };

    ingest(1);
    assert_eq!(held_at_entry(), 0, "BEGIN leases nothing");
    for exchange in 1..=8 {
        emit(exchange);
        assert_eq!(
            held_at_entry(),
            0,
            "ingest {exchange}: the answer's lease was released"
        );
        ingest(exchange + 1);
        assert_eq!(
            held_at_entry(),
            0,
            "emit {exchange}: the answer's lease was released"
        );
    }
}

#[test]
fn go_releases_every_leased_answer() {
    every_answer_is_released(false);
}

#[test]
fn go_inline_releases_every_leased_answer() {
    every_answer_is_released(true);
}
