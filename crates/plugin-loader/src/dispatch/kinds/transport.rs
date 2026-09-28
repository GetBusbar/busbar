// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND: `abi/transport/`. Every answer is judged by its kind's own check:
//!
//! * carrier: `listen` by `check_listen` (`addr_cap` from `ListenIn`), `accept` by `check_accept`
//!   (`peer_cap` from `AcceptIn`), `read` by `check_io` (`cap` from `ReadIn`), `write` by
//!   `check_io` (the `len` offered in `WriteIn`), `arrival` by `check_arrival` (`peer_cap` from
//!   `ArrivalIn`);
//! * framer: `locate` by `check_locate` (`authority_cap`/`name_cap` from `LocateIn`), and every op
//!   answering a `FramerOut` (`begin`, `ingest`, `emit`, `encode`, `refuse`, `finish`, `detach`,
//!   `adopt`, `timer`) by `check_framer`, its pieces over the host's `sink.pieces` and every cap
//!   from the op's `sink`;
//! * a READY `cancel` by `check_cancel` on its disposition.
//!
//! `dial` (a connection token), `flush` and `shut` (a bare `OutHead`) have no per-answer rule
//! beyond the mechanism's: a token is a name, not a result.
//!
//! SHORT ANSWERS: only `arrival` and `locate` have the short path. `listen` and `accept` have none
//! (the host's cap is at least `MAX_ADDR`), `read`/`write` partial I/O is not short, and a
//! framer's full sink is backpressure (`YIELD_MORE`), never short.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::{reported, Fault};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::check::{
    check_accept, check_arrival, check_cancel, check_framer, check_io, check_listen, check_locate,
};
use busbar_contract::abi::transport::{
    self, slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut,
    DialIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
};

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The transport kind.
#[derive(Debug, Clone, Copy)]
pub struct Transport;

// SAFETY: `#[repr(C)]` in `abi/transport/`, each leading with its head; their pointers are host
// buffers or host-borrowed inputs.
unsafe impl InFrame for ListenIn {}
unsafe impl InFrame for AcceptIn {}
unsafe impl InFrame for DialIn {}
unsafe impl InFrame for ReadIn {}
unsafe impl InFrame for WriteIn {}
unsafe impl InFrame for ConnIn {}
unsafe impl InFrame for ShutIn {}
unsafe impl InFrame for ArrivalIn {}
unsafe impl InFrame for LocateIn {}
unsafe impl InFrame for BeginIn {}
unsafe impl InFrame for IngestIn {}
unsafe impl InFrame for EmitIn {}
unsafe impl InFrame for EncodeIn {}
unsafe impl InFrame for RefuseIn {}
unsafe impl InFrame for FinishIn {}
unsafe impl InFrame for FramingIn {}
unsafe impl InFrame for AdoptIn {}
unsafe impl OutFrame for ListenOut {}
unsafe impl OutFrame for AcceptOut {}
unsafe impl OutFrame for ConnOut {}
unsafe impl OutFrame for IoOut {}
unsafe impl OutFrame for ArrivalOut {}
unsafe impl OutFrame for LocateOut {}
unsafe impl OutFrame for FramerOut {}

impl Kind for Transport {
    const CODE: KindCode = KindCode::Transport;
    type Ops = transport::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::LISTEN => "listen",
            slot::ACCEPT => "accept",
            slot::DIAL => "dial",
            slot::READ => "read",
            slot::WRITE => "write",
            slot::FLUSH => "flush",
            slot::SHUT => "shut",
            slot::ARRIVAL => "arrival",
            slot::LOCATE => "locate",
            slot::BEGIN => "begin",
            slot::INGEST => "ingest",
            slot::EMIT => "emit",
            slot::ENCODE => "encode",
            slot::REFUSE => "refuse",
            slot::FINISH => "finish",
            slot::DETACH => "detach",
            slot::ADOPT => "adopt",
            slot::TIMER => "timer",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::LISTEN => check_listen(
                a.out::<ListenOut>()?,
                a.input::<ListenIn>()?.addr_cap as u64,
            ),
            slot::ACCEPT => check_accept(
                a.out::<AcceptOut>()?,
                a.input::<AcceptIn>()?.peer_cap as u64,
            ),
            slot::READ => check_io(a.out::<IoOut>()?, a.input::<ReadIn>()?.cap as u64),
            slot::WRITE => check_io(a.out::<IoOut>()?, a.input::<WriteIn>()?.len as u64),
            slot::ARRIVAL => check_arrival(
                a.outcome,
                a.out::<ArrivalOut>()?,
                a.input::<ArrivalIn>()?.peer_cap as u64,
            ),
            slot::LOCATE => {
                let i = a.input::<LocateIn>()?;
                check_locate(
                    a.outcome,
                    a.out::<LocateOut>()?,
                    i.authority_cap as u64,
                    i.name_cap as u64,
                )
            }
            slot::BEGIN => framer(a, a.input::<BeginIn>()?.sink),
            slot::INGEST => framer(a, a.input::<IngestIn>()?.sink),
            slot::EMIT => framer(a, a.input::<EmitIn>()?.sink),
            slot::ENCODE => framer(a, a.input::<EncodeIn>()?.sink),
            slot::REFUSE => framer(a, a.input::<RefuseIn>()?.sink),
            slot::FINISH => framer(a, a.input::<FinishIn>()?.sink),
            slot::DETACH | slot::TIMER => framer(a, a.input::<FramingIn>()?.sink),
            slot::ADOPT => framer(a, a.input::<AdoptIn>()?.sink),
            life::CANCEL if a.outcome == Outcome::Ready => {
                check_cancel(a.out::<CancelOut>()?.disposition)
            }
            // `dial`, `flush`, `shut` and the other lifecycle answers: no per-answer rule beyond
            // the mechanism's.
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::ARRIVAL => a.out::<ArrivalOut>().is_ok_and(|o| o.peer_needed != 0),
            slot::LOCATE => a
                .out::<LocateOut>()
                .is_ok_and(|o| o.authority_needed != 0 || o.name_needed != 0),
            _ => false,
        }
    }
}

/// A framer answer: its pieces over the host's `sink.pieces`, every cap from the op's `sink`.
fn framer(a: &Answer, sink: FramerSink) -> Result<(), Fault> {
    let o = a.out::<FramerOut>()?;
    let pieces_cap = sink.pieces_cap as u64;
    // SAFETY: `sink.pieces` is the host's own buffer of `pieces_cap` `FramePiece`s, named by this
    // op's `in`.
    let pieces = unsafe {
        reported(
            sink.pieces.cast_const(),
            u64::from(o.yielded.pieces_len),
            pieces_cap,
            "framer.pieces_len",
        )
    }?;
    check_framer(
        a.outcome,
        o,
        pieces,
        sink.wire_cap as u64,
        sink.frame_cap as u64,
        pieces_cap,
    )
}
