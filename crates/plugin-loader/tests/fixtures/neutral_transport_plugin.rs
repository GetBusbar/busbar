// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! SDK transport witness with declarations and lifecycle, without networking or a wire protocol.
use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::*;

pub const CLAIM: &str = "witness-wire";
const CLAIMS: &[AbiStr] = &[abi_str(CLAIM)];
const ROWS: &[Claim] = &[Claim::EMPTY];
const CARRIER: TransportTail = {
    let mut tail = TransportTail::EMPTY.with_claim_rows(ROWS);
    tail.role = ROLE_CARRIER;
    tail.framing = FRAMING_STREAM;
    tail.frame_piece_size = FRAME_PIECE_SIZE;
    tail
};
const FRAMER: TransportTail = TransportTail {
    role: ROLE_FRAMER,
    facts: FACT_DIALS | FACT_ADOPTS,
    ..CARRIER
};

pub struct Witness;
impl Life for Witness {
    type Kind = busbar_contract::plugin::markers::TransportKind;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}
pub struct Refuses<I, O>(std::marker::PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refuses<I, O> {
    type Kind = busbar_contract::plugin::markers::TransportKind;
    type In = I;
    type Out = O;
    type State = Held<Witness>;
    fn call(_: Instance<'_, Self::State, Self::Kind>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}
pub struct Begin;
impl SafeSlot for Begin {
    type Kind = busbar_contract::plugin::markers::TransportKind;
    type In = BeginIn;
    type Out = FramerOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        _: Lent<'_, BeginIn>,
        mut out: Out<'_, FramerOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        out.set(|o| &o.framing, 1);
        Outcome::Ready
    }
}
type Refuse<I, O> = busbar_contract::abi::sdk::Safe<Refuses<I, O>>;
macro_rules! transport {
    ($name:literal, $tail:expr, $begin:ty) => {
        busbar_contract::plugin_door! {
            ops: Ops,
            statement: statement($name, "1.6.0", 64).with_claims(CLAIMS).with_kind_tail($tail),
            lifecycle: life(Witness),
            kind_ops: {
                listen: Refuse<ListenIn, ListenOut>, accept: Refuse<AcceptIn, AcceptOut>,
                dial: Refuse<DialIn, ConnOut>, read: Refuse<ReadIn, IoOut>, write: Refuse<WriteIn, IoOut>,
                flush: Refuse<ConnIn, OutHead>, shut: Refuse<ShutIn, OutHead>,
                arrival: Refuse<ArrivalIn, ArrivalOut>, locate: Refuse<LocateIn, LocateOut>,
                begin: $begin, ingest: Refuse<IngestIn, FramerOut>, emit: Refuse<EmitIn, FramerOut>,
                encode: Refuse<EncodeIn, FramerOut>, refuse: Refuse<RefuseIn, FramerOut>,
                finish: Refuse<FinishIn, FramerOut>, detach: Refuse<FramingIn, FramerOut>,
                adopt: Refuse<AdoptIn, FramerOut>, timer: Refuse<FramingIn, FramerOut>,
            },
        }
    };
}
transport!("neutral-carrier-witness", &CARRIER, Refuse<BeginIn, FramerOut>);
#[allow(dead_code)]
pub mod framer {
    use super::*;
    transport!(
        "neutral-framer-witness",
        &FRAMER,
        busbar_contract::abi::sdk::Safe<Begin>
    );
}
