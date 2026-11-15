// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's own media fixture: an SDK-authored datagram framer (`FRAMING_DATAGRAM`,
//! `FACT_ACCEPTS`) whose `emit` answers the six datagrams of [`DATAGRAMS`] in one answer, in order,
//! each to [`PATH`]: a STUN Binding success, RTP, RTP, a DTLS record, RTP, and a `LANE_SECURED`
//! plaintext whose first byte also lies in the RTP/RTCP range (RFC 7983), so only its lane tells it
//! apart from media. It is what `Mutant::dropping_media` is pinned against (r7.2 erratum §6, the
//! boundary row). Every other kind op is refused.

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::*;

type Marker = busbar_contract::plugin::markers::TransportKind;

const CLAIMS: &[AbiStr] = &[abi_str("host-fixture-media")];
/// As a datagram framer's claim: no selector forms, a session whose first unit opens on its first
/// datagram.
const ROWS: &[Claim] = &[{
    let mut c = Claim::EMPTY;
    c.selector_forms = abi_str("");
    c.egress_selector_forms = abi_str("");
    c.session = 1;
    c.session_bound = 1;
    c.unit0_trigger = UNIT0_FIRST_DATAGRAM;
    c
}];
const TAIL: TransportTail = {
    let mut tail = TransportTail::EMPTY.with_claim_rows(ROWS);
    tail.role = ROLE_FRAMER;
    tail.framing = FRAMING_DATAGRAM;
    tail.frame_piece_size = FRAME_PIECE_SIZE;
    tail.facts = FACT_ACCEPTS;
    tail
};

/// The path every route goes to.
pub const PATH: u32 = 1;

/// The datagrams `emit` answers, in order: each one's bytes and lane.
pub const DATAGRAMS: [(&[u8], u32); 6] = [
    // A STUN Binding success response (RFC 7983: 0..=3).
    (&[0x01, 0x01, 0x00, 0x00], LANE_CLEAR),
    // RTP, version 2 (128..=191), sequence 1.
    (&[0x80, 0x6f, 0x00, 0x01], LANE_CLEAR),
    // RTP, sequence 2.
    (&[0x80, 0x6f, 0x00, 0x02], LANE_CLEAR),
    // A DTLS handshake record (20..=63).
    (&[0x16, 0xfe, 0xfd, 0x00], LANE_CLEAR),
    // RTP, sequence 3.
    (&[0x80, 0x6f, 0x00, 0x03], LANE_CLEAR),
    // Plaintext for the host's secure layer, starting in the RTP range: its lane keeps it.
    (&[0x90, 0x00, 0x00, 0x04], LANE_SECURED),
];

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

/// `emit`: the six datagrams of [`DATAGRAMS`], one route each, whatever bytes it was lent.
struct Emit;
impl SafeSlot for Emit {
    type Kind = Marker;
    type In = EmitIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return o.fail(Refusal::refused(
                "emit: the fixture emits on an open instance only",
            ));
        }
        let Some(lane) = i.lane() else {
            return o.fail(Refusal::failed("emit: a datagram framer reads its lane"));
        };
        let mut wire = i.sink().wire();
        let mut routes = lane.routes();
        for (bytes, on) in DATAGRAMS {
            let at = wire.extend(bytes);
            routes.push(DatagramRoute {
                offset: at as u64,
                len: bytes.len() as u64,
                path: PATH,
                lane: on,
            });
        }
        if !wire.fits() || !routes.fits() {
            return o.fail(Refusal::failed(
                "emit: the datagrams do not fit the host's buffers",
            ));
        }
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        o.set(|x| &x.datagram.routes_len, routes.written() as u32);
        Outcome::Ready
    }
}

type No<I, O> = Safe<Refuses<I, O>>;
busbar_contract::plugin_door! {
    ops: Ops,
    statement: statement("host-fixture-media", "1.6.0", 16).with_claims(CLAIMS).with_kind_tail(&TAIL),
    lifecycle: life(Fixture),
    kind_ops: {
        listen: No<ListenIn, ListenOut>, accept: No<AcceptIn, AcceptOut>,
        dial: No<DialIn, ConnOut>, read: No<ReadIn, IoOut>, write: No<WriteIn, IoOut>,
        flush: No<ConnIn, OutHead>, shut: No<ShutIn, OutHead>,
        arrival: No<ArrivalIn, ArrivalOut>, locate: No<LocateIn, LocateOut>,
        begin: No<BeginIn, FramerOut>, ingest: No<IngestIn, FramerOut>, emit: Safe<Emit>,
        encode: No<EncodeIn, FramerOut>, refuse: No<RefuseIn, FramerOut>,
        finish: No<FinishIn, FramerOut>, detach: No<FramingIn, FramerOut>,
        adopt: No<AdoptIn, FramerOut>, timer: No<FramingIn, FramerOut>,
    },
}
