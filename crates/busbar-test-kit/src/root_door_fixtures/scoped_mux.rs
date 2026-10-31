// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A loaded SDK framer whose streams pend on the real auth service independently.

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::Mutex;
use std::task::Poll;

use busbar_contract::abi::auth::POINT_HEAD;
use busbar_contract::abi::host::service::{AuthRef, UnitRef, FLOW_CONTINUE, SCHEME_PLAIN};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refusal};
use busbar_contract::abi::sdk::services::HeadViewArgs;
use busbar_contract::abi::sdk::transport::sink::{fill, Owed, Piece};
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport as t;

busbar_contract::own_seal!(Own);

/// The local token, intentionally reused by different host connections.
pub const TOKEN: u64 = 41;
const CLAIM_NAMES: &[AbiStr] = &[abi_str("http")];
const CLAIMS: &[t::Claim] = &[t::Claim {
    session: 1,
    session_bound: 1,
    unit0_trigger: t::UNIT0_FIRST_LINE,
    ..t::Claim::ZERO
}];
const TAIL: t::TransportTail = t::TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<t::TransportTail>() as u32,
        ..KindTailHead::ZERO
    },
    role: t::ROLE_FRAMER,
    framing: t::FRAMING_STREAM,
    facts: t::FACT_ACCEPTS,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    frame_piece_size: t::FRAME_PIECE_SIZE,
    ..t::TransportTail::ZERO
};
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const t::TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement("scoped-mux-fixture", "0.0.1", 64)
};

/// Per-instance fixture state; no callback blocks a plugin crossing.
pub struct Mux {
    auth: Mutex<AuthRef>,
    pending: Mutex<HashMap<Ticket, Pending>>,
    owed: Mutex<HashMap<Ticket, Queue>>,
    finished: Mutex<Vec<u64>>,
}

#[derive(Clone, Copy)]
struct Pending {
    stream: u64,
    probe: bool,
}

impl Life for Mux {
    const CANCEL: u32 = t::CANCEL_NOTHING_MOVED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            auth: Mutex::new(AuthRef::NONE),
            pending: Mutex::default(),
            owed: Mutex::default(),
            finished: Mutex::default(),
        })
    }

    fn close(&self, host: Option<&busbar_contract::abi::sdk::conn::Host>) {
        if let Some(services) = host.and_then(|h| h.services()) {
            let request = HeadViewArgs {
                method: "GET",
                target: "/close",
                scheme: SCHEME_PLAIN,
                ..HeadViewArgs::default()
            };
            let _ = services.unit_refuse(
                CompletionHandle::ZERO,
                UnitRef::NONE,
                busbar_contract::abi::host::service::REFUSE_NO_ROUTE,
                busbar_contract::abi::host::service::LINE_NONE,
                TOKEN,
                0,
                &request,
            );
        }
    }
}

#[derive(Default)]
struct Queue(VecDeque<Piece<Vec<u8>>>);
impl Owed<Vec<u8>> for Queue {
    fn wire_into(&mut self, _: &mut HostBuf<'_, u8>) {}
    fn wire_pending(&self) -> bool {
        false
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece<Vec<u8>>> {
        &mut self.0
    }
    fn next_deadline(&self) -> Option<u64> {
        None
    }
    fn ended(&self) -> bool {
        false
    }
    fn rest(bytes: &mut Vec<u8>, at: usize) {
        bytes.drain(..at);
    }
}

type State = Held<Mux>;

fn authenticate(held: &State, ticket: Ticket, stream: u64) -> Poll<Result<(), ()>> {
    authenticate_at(held, ticket, stream, 0, false)
}

fn authenticate_at(
    held: &State,
    ticket: Ticket,
    stream: u64,
    seq: u32,
    resumed: bool,
) -> Poll<Result<(), ()>> {
    let Some(services) = held.host().and_then(|h| h.services()) else {
        return Poll::Ready(Err(()));
    };
    let auth = *held.life().auth.lock().unwrap();
    let target = format!("/tickets/{}/{}", ticket.slot, ticket.generation);
    let request = HeadViewArgs {
        method: "POST",
        target: &target,
        authority: "fixture",
        query: resumed.then_some("resumed=1"),
        scheme: SCHEME_PLAIN,
        ..HeadViewArgs::default()
    };
    match services.auth_call::<Own>(
        CompletionHandle {
            ticket,
            seq,
            _reserved: 0,
        },
        auth,
        UnitRef::NONE,
        POINT_HEAD,
        TOKEN,
        stream,
        &request,
        None,
    ) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(answer)) if answer.flow == FLOW_CONTINUE => Poll::Ready(Ok(())),
        Poll::Ready(_) => Poll::Ready(Err(())),
    }
}

/// Copy the lent line and optionally claim a deliberately mismatching opening token.
pub struct Begin;
impl SafeSlot for Begin {
    type In = t::BeginIn;
    type Out = t::FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, Self::In>,
        mut o: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = inst.get() else {
            return Outcome::Fault;
        };
        let Some(line) = i.lines().get(0) else {
            return Outcome::Refused;
        };
        *held.life().auth.lock().unwrap() = line.auth;
        let mismatch = i.target().as_str() == Ok("mismatch");
        if mismatch {
            match authenticate(held, i.head.ticket, 7) {
                Poll::Pending => return Outcome::Pending,
                Poll::Ready(Err(())) => return Outcome::Refused,
                Poll::Ready(Ok(())) => {}
            }
        }
        o.set(|o| &o.framing, TOKEN + u64::from(mismatch));
        Outcome::Ready
    }
}

/// Decode one fixture stream or resume its stored auth completion.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = t::IngestIn;
    type Out = t::FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, Self::In>,
        mut o: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = inst.get() else {
            return Outcome::Fault;
        };
        let state = held.life();
        let ticket = i.head.ticket;
        if !state.owed.lock().unwrap().contains_key(&ticket) {
            let Pending { stream, probe } = {
                let mut pending = state.pending.lock().unwrap();
                match pending.get(&ticket).copied().or_else(|| {
                    i.bytes().first().map(|v| Pending {
                        stream: u64::from(*v),
                        probe: i.bytes().get(1) == Some(&1),
                    })
                }) {
                    Some(request) => {
                        pending.insert(ticket, request);
                        request
                    }
                    None => return Outcome::Refused,
                }
            };
            let bytes = if stream == 9 {
                state
                    .finished
                    .lock()
                    .unwrap()
                    .last()
                    .copied()
                    .unwrap_or(0)
                    .to_le_bytes()
                    .to_vec()
            } else {
                match authenticate(held, ticket, stream) {
                    Poll::Pending => return Outcome::Pending,
                    Poll::Ready(Err(())) => return Outcome::Refused,
                    Poll::Ready(Ok(())) => {}
                }
                if probe {
                    let resumed =
                        i.head.flags & busbar_contract::abi::mechanism::call::FLAG_RESUME != 0;
                    if !resumed {
                        if let Some(host) = held.host() {
                            host.wake(ticket);
                        }
                        return Outcome::Pending;
                    }
                    match authenticate_at(held, ticket, stream + 10, 1, resumed) {
                        Poll::Pending => return Outcome::Pending,
                        Poll::Ready(Err(())) => return Outcome::Refused,
                        Poll::Ready(Ok(())) => {}
                    }
                    state.pending.lock().unwrap().remove(&ticket);
                    return Outcome::Ready;
                }
                [ticket.slot.to_le_bytes(), ticket.generation.to_le_bytes()].concat()
            };
            state.pending.lock().unwrap().remove(&ticket);
            let mut queue = Queue::default();
            queue.0.push_back(Piece::data(stream, bytes));
            state.owed.lock().unwrap().insert(ticket, queue);
        }
        let mut owed = state.owed.lock().unwrap();
        let queue = owed
            .get_mut(&ticket)
            .expect("this op owns its queued answer");
        fill(queue, i.field(|i| &i.sink), &mut o, |_| 0, |_| 0);
        if queue.0.is_empty() {
            owed.remove(&ticket);
        }
        Outcome::Ready
    }
}

/// Retire a framing and retain its token for the fixture's wire observation.
pub struct Finish;
impl SafeSlot for Finish {
    type In = t::FinishIn;
    type Out = t::FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
        let Some(held) = inst.get() else {
            return Outcome::Fault;
        };
        held.life().finished.lock().unwrap().push(i.framing);
        Outcome::Ready
    }
}

/// An operation this fixture does not serve.
pub struct Refused<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refused<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

busbar_contract::plugin_door! {
    ops: t::Ops,
    statement: STATEMENT,
    lifecycle: life(Mux),
    kind_ops: {
        listen: Safe<Refused<t::ListenIn, t::ListenOut>>,
        accept: Safe<Refused<t::AcceptIn, t::AcceptOut>>,
        dial: Safe<Refused<t::DialIn, t::ConnOut>>,
        read: Safe<Refused<t::ReadIn, t::IoOut>>,
        write: Safe<Refused<t::WriteIn, t::IoOut>>,
        flush: Safe<Refused<t::ConnIn, busbar_contract::abi::mechanism::call::OutHead>>,
        shut: Safe<Refused<t::ShutIn, busbar_contract::abi::mechanism::call::OutHead>>,
        arrival: Safe<Refused<t::ArrivalIn, t::ArrivalOut>>,
        locate: Safe<Refused<t::LocateIn, t::LocateOut>>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Refused<t::EmitIn, t::FramerOut>>,
        encode: Safe<Refused<t::EncodeIn, t::FramerOut>>,
        refuse: Safe<Refused<t::RefuseIn, t::FramerOut>>,
        finish: Safe<Finish>,
        detach: Safe<Refused<t::FramingIn, t::FramerOut>>,
        adopt: Safe<Refused<t::AdoptIn, t::FramerOut>>,
        timer: Safe<Refused<t::FramingIn, t::FramerOut>>,
    },
}
