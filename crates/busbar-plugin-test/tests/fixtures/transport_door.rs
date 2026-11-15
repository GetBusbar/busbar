// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's own transport fixture: an SDK-authored carrier whose `write` answers the bytes it
//! was lent plus the connection it names, and refuses every other kind op.

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::*;

type Marker = busbar_contract::plugin::markers::TransportKind;

const CLAIMS: &[AbiStr] = &[abi_str("host-fixture-wire")];
const ROWS: &[Claim] = &[Claim::EMPTY];
const TAIL: TransportTail = {
    let mut tail = TransportTail::EMPTY.with_claim_rows(ROWS);
    tail.role = ROLE_CARRIER;
    tail.framing = FRAMING_STREAM;
    tail.frame_piece_size = FRAME_PIECE_SIZE;
    tail
};

struct Fixture;
impl Life for Fixture {
    type Kind = Marker;
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
    type Kind = Marker;
    type In = I;
    type Out = O;
    type State = Held<Fixture>;
    fn call(_: Instance<'_, Self::State, Marker>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

struct Echo;
impl SafeSlot for Echo {
    type Kind = Marker;
    type In = WriteIn;
    type Out = IoOut;
    type State = Held<Fixture>;
    fn call(
        _: Instance<'_, Self::State, Marker>,
        i: Lent<'_, WriteIn>,
        mut o: Out<'_, IoOut>,
    ) -> Outcome {
        o.set(|o| &o.len, i.bytes().len() as u64 + i.conn());
        Outcome::Ready
    }
}

type No<I, O> = Safe<Refuses<I, O>>;
busbar_contract::plugin_door! {
    ops: Ops,
    statement: statement("host-fixture-transport", "1.6.0", 16).with_claims(CLAIMS).with_kind_tail(&TAIL),
    lifecycle: life(Fixture),
    kind_ops: {
        listen: No<ListenIn, ListenOut>, accept: No<AcceptIn, AcceptOut>,
        dial: No<DialIn, ConnOut>, read: No<ReadIn, IoOut>, write: Safe<Echo>,
        flush: No<ConnIn, OutHead>, shut: No<ShutIn, OutHead>,
        arrival: No<ArrivalIn, ArrivalOut>, locate: No<LocateIn, LocateOut>,
        begin: No<BeginIn, FramerOut>, ingest: No<IngestIn, FramerOut>, emit: No<EmitIn, FramerOut>,
        encode: No<EncodeIn, FramerOut>, refuse: No<RefuseIn, FramerOut>,
        finish: No<FinishIn, FramerOut>, detach: No<FramingIn, FramerOut>,
        adopt: No<AdoptIn, FramerOut>, timer: No<FramingIn, FramerOut>,
    },
}
