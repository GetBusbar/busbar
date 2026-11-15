// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's own transport fixture: an SDK-authored carrier whose `write` takes every byte it
//! was lent on connection 7 (refusing any other connection), whose `locate` answers SHORT on its
//! instance's first call and READY on the re-call (the facade's one SHORT re-call, end to end),
//! whose `emit` echoes the bytes it was lent into its sink's wire, and which refuses every other
//! kind op.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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

struct Fixture {
    /// `locate` crossings on this instance so far.
    locates: AtomicU64,
    /// The authority buffer the SHORT `locate` was lent, as an address: the re-call must lend
    /// the same one (a pending crossing owns its loans; moving it moves none of them).
    short_lent: AtomicUsize,
}
impl Life for Fixture {
    type Kind = Marker;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            locates: AtomicU64::new(0),
            short_lent: AtomicUsize::new(0),
        })
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
        if i.conn() != 7 {
            return Outcome::Refused;
        }
        o.set(|o| &o.len, i.bytes().len() as u64);
        Outcome::Ready
    }
}

/// `locate`: the instance's first call answers SHORT, needing one byte more authority than it
/// was lent; the re-call, lent the same buffer, writes the target as the authority.
struct ShortOnce;
impl SafeSlot for ShortOnce {
    type Kind = Marker;
    type In = LocateIn;
    type Out = LocateOut;
    type State = Held<Fixture>;
    fn call(
        instance: Instance<'_, Self::State, Marker>,
        i: Lent<'_, LocateIn>,
        mut o: Out<'_, LocateOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return o.fail(Refusal::refused(
                "locate: the fixture locates on an open instance only",
            ));
        };
        let f = held.life();
        let mut authority = i.authority_buf();
        let lent = i.authority_buf.addr();
        if f.locates.fetch_add(1, Ordering::SeqCst) == 0 {
            f.short_lent.store(lent, Ordering::SeqCst);
            o.set(|x| &x.authority_needed, authority.cap() as u64 + 1);
            return o.fail(Refusal::failed("locate: the fixture answers SHORT once"));
        }
        if f.short_lent.load(Ordering::SeqCst) != lent {
            return o.fail(Refusal::failed(
                "locate: the re-call lent another authority buffer than the SHORT call",
            ));
        }
        authority.extend(i.target().bytes());
        if !authority.fits() {
            return o.fail(Refusal::failed(
                "locate: the target is longer than the authority buffer",
            ));
        }
        o.set(|x| &x.authority_written, authority.written() as u64);
        Outcome::Ready
    }
}

/// `emit`: the bytes it was lent, written whole to its sink's wire.
struct EchoEmit;
impl SafeSlot for EchoEmit {
    type Kind = Marker;
    type In = EmitIn;
    type Out = FramerOut;
    type State = Held<Fixture>;
    fn call(
        _: Instance<'_, Self::State, Marker>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let mut wire = i.sink().wire();
        wire.extend(i.bytes());
        if !wire.fits() {
            return o.fail(Refusal::failed(
                "emit: the echo is longer than the wire buffer",
            ));
        }
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
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
        arrival: No<ArrivalIn, ArrivalOut>, locate: Safe<ShortOnce>,
        begin: No<BeginIn, FramerOut>, ingest: No<IngestIn, FramerOut>, emit: Safe<EchoEmit>,
        encode: No<EncodeIn, FramerOut>, refuse: No<RefuseIn, FramerOut>,
        finish: No<FinishIn, FramerOut>, detach: No<FramingIn, FramerOut>,
        adopt: No<AdoptIn, FramerOut>, timer: No<FramingIn, FramerOut>,
    },
}
