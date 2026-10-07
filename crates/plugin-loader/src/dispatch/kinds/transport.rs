// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND: `abi/transport/`. Every answer is judged by its kind's own check:
//!
//! * carrier: `listen` by `check_listen` (`addr_cap` from `ListenIn`), `accept` by `check_accept`
//!   (`peer_cap` from `AcceptIn`), `read` by `check_io` (`cap` from `ReadIn`), `write` by
//!   `check_io` (the `len` offered in `WriteIn`), `arrival` by `check_arrival` (`peer_cap` from
//!   `ArrivalIn`);
//! * framer: `locate` by `check_locate` (`authority_cap`/`name_cap`/`alpn_cap` from `LocateIn`), and every op
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

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::check::{reported, Fault};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::check::{
    check_accept, check_arrival, check_cancel, check_claims, check_composes_over,
    check_fault_cover, check_fault_rows, check_framer, check_framer_fields, check_head_slots,
    check_io, check_listen, check_locate, check_settings, check_status_rows, check_tail,
};
use busbar_contract::abi::transport::{
    self, slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn,
    ConnOut, DialIn, EmitIn, EncodeIn, FaultRow, FinishIn, FramerOut, FramerSink, FramingIn,
    IngestIn, IoOut, ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, SettingDecl,
    ShutIn, StatusRow, TransportTail, WriteIn,
};

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// The transport tail's last frozen size, before the fault table was appended (THE KIND TAIL
/// GROWTH RULE, `abi::mechanism::door::tail_read_len`): a tail that predates the fault table loads
/// and reads it as absent, and is then judged by [`check_fault_cover`] like any other.
const TRANSPORT_TAIL_FROZEN: usize = std::mem::offset_of!(TransportTail, fault_rows);

/// WHAT A TRANSPORT STATES, read once at bind and checked by the kind's own `check_tail`,
/// `check_claims`, `check_claim_rows` and `check_composes_over`: its role, every scheme it answers
/// for (the Statement's `claims`, the first its own) and the claims it composes over. The host's registry view reads it through
/// [`crate::dispatch::Plugin::context`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFacts {
    /// `ROLE_CARRIER` | `ROLE_FRAMER`.
    pub role: u32,
    /// Every scheme the entry answers for, in order (interned: one allocation per distinct name for
    /// the process).
    pub claims: Vec<&'static str>,
    /// The claims whose unit 0 opens at an UPGRADE (their row's `unit0_trigger` is
    /// `UNIT0_UPGRADE`): the host's upgrade lines, read off the claim rows and never off a layer
    /// list (ARCHITECT ruling Q128 U7). The handoff target on an upgrade is the claim that owns the
    /// requested scheme.
    pub upgrades: Vec<&'static str>,
    /// The claims whose row carries a session (`session = 1`): a duplex line, never one request
    /// and its response.
    pub sessions: Vec<&'static str>,
    /// The claims it composes over; empty = directly over the host's socket (a framer) or the
    /// bottom of its stack (a carrier).
    pub composes_over: Vec<&'static str>,
    /// The customer settings it reads, by their 1.5.5 config paths (`TransportTail::settings`), in
    /// its order: the host deals each one's value to its `open`.
    pub settings: Vec<&'static str>,
    /// Its own claim (row `0`) selects on the local PORT a connection arrived on
    /// (`SelectorForm::Port` among its selector forms): a carrier of network addresses.
    pub ported: bool,
    /// Its status table, row by row: `(claim, lo, hi)`, the code ranges each claim's numbering
    /// has (`TransportTail::status_rows`); a stream's final status is judged against them.
    pub status_rows: Vec<(u32, u32, u32)>,
}

/// A plugin string, interned.
fn owned(s: AbiStr, field: &str) -> Result<&'static str, String> {
    if s.len == 0 {
        return Ok("");
    }
    // SAFETY: a tail string is `'static` plugin data; `check_tail`/`check_claims` refused a NULL
    // pointer with a count before this reads it.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(bytes)
        .map(crate::intern_name)
        .map_err(|_| format!("the transport tail's {field} is not UTF-8"))
}

/// The transport's tail, read from the Statement and checked.
fn tail_facts(st: &Statement) -> Result<TransportFacts, String> {
    // SAFETY: `TransportTail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid);
    // a non-NULL kind tail is `'static` plugin data of its stated size.
    let tail: TransportTail =
        unsafe { crate::dispatch::plugin::kind_tail(st, "a transport", TRANSPORT_TAIL_FROZEN) }?;
    let broke = |f: Fault| format!("the transport tail breaks {:?} at {}", f.rule, f.field);
    check_tail(&tail).map_err(broke)?;
    // SAFETY: `check_tail` refused a NULL list with a count; both lists are `'static` plugin data.
    let rows: &[Claim] =
        unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    check_claims(rows).map_err(broke)?;
    // The scheme NAMES are the Statement's alone (signed, and byte-compared at admit); the tail has
    // one row per name.
    busbar_contract::abi::transport::check::check_claim_rows(st.claims_len, &tail)
        .map_err(broke)?;
    let names: &[AbiStr] = if st.claims_len == 0 {
        &[]
    } else {
        // SAFETY: the loader's Statement check refused a NULL `claims` with a count; the list is
        // `'static` plugin data.
        unsafe { std::slice::from_raw_parts(st.claims, st.claims_len) }
    };
    let under: &[AbiStr] = if tail.composes_over_len == 0 {
        &[]
    } else {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(tail.composes_over, tail.composes_over_len) }
    };
    check_composes_over(under).map_err(broke)?;
    let settings: &[SettingDecl] = if tail.settings_len == 0 {
        &[]
    } else {
        // SAFETY: `check_tail` refused a NULL list with a count; the list is `'static` plugin data.
        unsafe { std::slice::from_raw_parts(tail.settings, tail.settings_len) }
    };
    check_settings(settings).map_err(broke)?;
    let claims: Vec<&'static str> = names
        .iter()
        .map(|c| owned(*c, "claim"))
        .collect::<Result<_, _>>()?;
    // Row `i` describes `claims[i]` (`check_claim_rows` held the counts equal).
    let upgrades = claims
        .iter()
        .zip(rows)
        .filter(|(_, row)| row.unit0_trigger == busbar_contract::abi::transport::UNIT0_UPGRADE)
        .map(|(name, _)| *name)
        .collect();
    let sessions = claims
        .iter()
        .zip(rows)
        .filter(|(_, row)| row.session == 1)
        .map(|(name, _)| *name)
        .collect();
    // THE TWO TABLES: the status class (the fee decision's leg) and the fault reading (the
    // breaker's). A claim that classes its answers reads them for the breaker too.
    let status: &[StatusRow] = if tail.status_rows_len == 0 {
        &[]
    } else {
        // SAFETY: `check_tail` refused a NULL list with a count; the list is `'static` plugin data.
        unsafe { std::slice::from_raw_parts(tail.status_rows, tail.status_rows_len) }
    };
    let faults: &[FaultRow] = if tail.fault_rows_len == 0 {
        &[]
    } else {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts(tail.fault_rows, tail.fault_rows_len) }
    };
    check_status_rows(status, tail.claim_rows_len as u64).map_err(broke)?;
    check_fault_rows(faults, tail.claim_rows_len as u64).map_err(broke)?;
    check_fault_cover(status, faults).map_err(broke)?;
    Ok(TransportFacts {
        status_rows: status.iter().map(|r| (r.claim, r.lo, r.hi)).collect(),
        role: tail.role,
        claims,
        upgrades,
        sessions,
        composes_over: under
            .iter()
            .map(|s| owned(*s, "composes_over"))
            .collect::<Result<_, _>>()?,
        settings: settings
            .iter()
            .map(|s| owned(s.path, "settings"))
            .collect::<Result<_, _>>()?,
        ported: rows.first().is_some_and(|row| {
            let port = busbar_contract::abi::hot::transport::code::selector_form(
                busbar_contract::SelectorForm::Port,
            );
            row.selector_forms.len > 0
                // SAFETY: `check_claims` refused a NULL list with a count; `'static` plugin data.
                && unsafe {
                    std::slice::from_raw_parts(row.selector_forms.ptr, row.selector_forms.len)
                }
                .contains(&port)
        }),
    })
}

/// WHAT A COMPILED-IN TRANSPORT DOOR STATES, read off its Statement through the same door and tail
/// checks a load runs, without binding or opening it: the boot seal registers every scheme an entry
/// claims under its own key (`BUSBAR-1.6.0.md` TRANSPORT-STACK: ONE ENTRY PER PLUGIN, the schemes
/// are its claims).
///
/// # Errors
///
/// The door, its Statement or its transport tail is refused.
pub fn linked_facts(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Result<TransportFacts, String> {
    let v = crate::dispatch::load::validate::<Transport>(door).map_err(|e| e.to_string())?;
    tail_facts(&v.statement)
}

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

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(tail_facts(st)?)))
    }

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
                let o = a.out::<LocateOut>()?;
                let offer: &[u8] = if a.outcome == Outcome::Ready {
                    // SAFETY: `alpn_buf` is the host's own buffer of `alpn_cap` bytes, named by
                    // this op's `in`.
                    unsafe {
                        reported(
                            i.alpn_buf.cast_const(),
                            o.alpn_written,
                            i.alpn_cap as u64,
                            "locate.alpn",
                        )
                    }?
                } else {
                    &[]
                };
                check_locate(
                    a.outcome,
                    o,
                    i.authority_cap as u64,
                    i.name_cap as u64,
                    i.alpn_cap as u64,
                    offer,
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
            life::CANCEL => check_cancel(a.outcome, a.out::<CancelOut>()?.disposition),
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
                .is_ok_and(|o| o.authority_needed != 0 || o.name_needed != 0 || o.alpn_needed != 0),
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
    )?;
    // Only a field block's bytes are read here; payload never is.
    if pieces
        .iter()
        .any(|p| p.flags & transport::PIECE_FIELDS != 0)
    {
        // SAFETY: `sink.frame` is the host's own buffer of `frame_cap` bytes; `check_framer` held
        // `frame_len` within it.
        let frame = unsafe {
            reported(
                sink.frame.cast_const(),
                o.yielded.frame_len,
                sink.frame_cap as u64,
                "framer.frame_len",
            )
        }?;
        check_framer_fields(pieces, frame)?;
    }
    let heads_cap = sink.heads_cap as u64;
    // SAFETY: `sink.heads` is the host's own buffer of `heads_cap` `HeadSlots`s (NULL with a
    // capacity of `0` on a host that takes none).
    let heads = unsafe {
        reported(
            sink.heads.cast_const(),
            u64::from(o.yielded.heads_len),
            heads_cap,
            "framer.heads_len",
        )
    }?;
    check_head_slots(o, heads, heads_cap)
}
