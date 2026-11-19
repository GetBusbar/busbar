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

use crate::carrier::Side;
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

