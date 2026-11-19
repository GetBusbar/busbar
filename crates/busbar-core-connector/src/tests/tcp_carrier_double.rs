// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A KIND-LEVEL TCP CARRIER DOUBLE, in-tree: a transport door of role CARRIER claiming `tcp`, built
//! from the contract's SDK door macros over the HOST'S I/O, so core's connector tests drive a
//! carrier through the loader, the dispatcher and the dispatched door with no plugin built or
//! loaded (owner ruling: "core knows nothing about plugins just kinds, plugins test themselves").
//!
//! It keeps the carrier rules any byte-stream carrier states: `listen`/`accept` over the host's
//! listener; `dial` opens the ONE literal address it is lent (never a name: the host's destination
//! judge already pinned it); `flush` settles the dial; `read` answers what the socket has, each
//! read that moves bytes a frame of the stream; `write` hands the host what it is offered; `shut`
//! closes and forgets; `arrival` reads the far end off the socket. Every framer op is refused.
//! Include it with `#[path]` and load it with [`row`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::io::{Io, IoFailure, DIR_WRITE, MAX_ADDR};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::{form_codes, settings_reading};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, FRAME_PIECE_SIZE, FRAMING_STREAM, UNIT0_FIRST_BYTES,
};
use busbar_contract::plugin::markers::TransportKind;
use busbar_contract::transport::codes::{DEST_AUTHORITY, READ_END_OF_FRAME, ROLE_CARRIER};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

/// The claim this carrier answers for.
pub const KEY: &str = "tcp";

const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);
const FACTS: &[AbiStr] = &[abi_str(tfacts::PEER)];
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

const CLAIMS: &[Claim] = &[{
    let mut c = Claim::EMPTY.with_facts(FACTS);
    c.selector_forms = AbiStr::of_bytes(&SELECTOR_CODES);
    c.egress_selector_forms = abi_str("");
    c.status_namespace = AbiStr::ABSENT;
    c.session = 1;
    c.session_bound = 0;
    c.unit0_trigger = UNIT0_FIRST_BYTES;
    c.status_at = 0;
    c
}];

const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY.with_claim_rows(CLAIMS);
    t.role = ROLE_CARRIER;
    t.framing = FRAMING_STREAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};

const STATEMENT: Statement = statement("tcp-carrier-double", "1.6.0", 64)
    .with_kind_tail(&TAIL)
    .with_claims(CLAIM_NAMES);

/// What one instance carries: its listeners and its connections, each by the token it minted.
pub struct Carried {
    listeners: Mutex<HashMap<u64, u64>>,
    conns: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
}

/// One connection: the host's handle, and whether its dial has settled.
#[derive(Clone, Copy)]
struct Conn {
    io: u64,
    settled: bool,
}

type State = Held<Carried>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Carried {
    fn mint(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    fn handle(&self, conn: u64) -> Option<u64> {
        lock(&self.conns).get(&conn).map(|c| c.io)
    }
}

/// The settings this carrier reads: none.
fn no_settings(settings: &[u8]) -> Result<(), Refusal> {
    settings_reading(settings, &[]).map(drop)
}

impl Life for Carried {
    type Kind = TransportKind;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        no_settings(settings)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        no_settings(settings)?;
        Ok(Self {
            listeners: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        no_settings(settings)?;
        Ok(Refreshed::default())
    }

    /// Every host handle this instance still holds is closed.
    fn close(&self, host: Option<&Host<TransportKind>>) {
        let Some(mut io) = host.map(|h| h.io(Ticket::NONE)).filter(Io::armed) else {
            return;
        };
        let listeners = std::mem::take(&mut *lock(&self.listeners));
        let conns = std::mem::take(&mut *lock(&self.conns));
        for h in listeners
            .into_values()
            .chain(conns.into_values().map(|c| c.io))
        {
            let _ = io.close(h);
        }
    }
}

/// Host refusals and failures as the op's outcome, in the host's words.
fn refusal(e: IoFailure) -> Refusal {
    match e {
        IoFailure::Refused(t) => Refusal::refused(t),
        IoFailure::Failed(t) => Refusal::failed(t),
        IoFailure::Unarmed => Refusal::failed("the instance was handed no host I/O"),
        IoFailure::NoTicket => Refusal::failed("the call runs on no ticket and cannot pend"),
        IoFailure::Fault => Refusal::failed("the host I/O faulted"),
    }
}

/// Whether a close leaves nothing to retry.
fn let_go(closed: &Result<(), IoFailure>) -> bool {
    matches!(closed, Ok(()) | Err(IoFailure::Refused(_)))
}

/// Run `body` over the instance and its I/O, failing the op without either.
macro_rules! over {
    ($op:literal, $inst:expr, $o:expr, |$c:ident, $io:ident| $body:block) => {
        match busbar_contract::carried!($inst, $op) {
            Ok(($c, mut $io)) => $body,
            Err(r) => return $o.fail(r),
        }
    };
}

busbar_contract::not_served! {
    state: State, role: "tcp carrier double";
    NoLocate(LocateIn => LocateOut) "locate";
    NoBegin(BeginIn => FramerOut) "begin";
    NoIngest(IngestIn => FramerOut) "ingest";
    NoEmit(EmitIn => FramerOut) "emit";
    NoEncode(EncodeIn => FramerOut) "encode";
    NoRefuse(RefuseIn => FramerOut) "refuse";
    NoFinish(FinishIn => FramerOut) "finish";
    NoDetach(FramingIn => FramerOut) "detach";
    NoAdopt(AdoptIn => FramerOut) "adopt";
    NoTimer(FramingIn => FramerOut) "timer";
}

/// `listen`: bind the address, answering the address bound.
pub struct Listen;
impl SafeSlot for Listen {
    type Kind = TransportKind;
    type In = ListenIn;
    type Out = ListenOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, ListenIn>,
        mut o: Out<'_, ListenOut>,
    ) -> Outcome {
        let Ok(bind) = i.bind().as_str() else {
            return o.fail(Refusal::failed("listen: the bind address is not UTF-8"));
        };
        over!("listen", inst, o, |c, io| {
            let mut addr = i.addr_buf();
            match io.listen_host(bind, &mut addr) {
                Ok(h) => {
                    let token = c.mint();
                    lock(&c.listeners).insert(token, h);
                    o.set(|o| &o.listener, token);
                    o.set(|o| &o.addr_written, addr.asked() as u64);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(e)),
            }
        })
    }
}

/// `accept`: the next connection off the listener.
pub struct Accept;
impl SafeSlot for Accept {
    type Kind = TransportKind;
    type In = AcceptIn;
    type Out = AcceptOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, AcceptIn>,
        mut o: Out<'_, AcceptOut>,
    ) -> Outcome {
        over!("accept", inst, o, |c, io| {
            let Some(l) = lock(&c.listeners).get(&i.listener()).copied() else {
                return o.fail(Refusal::failed("accept: no such listener"));
            };
            let mut peer = i.peer_buf();
            match io.accept_host(l, &mut peer) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(h)) => {
                    let token = c.mint();
                    lock(&c.conns).insert(
                        token,
                        Conn {
                            io: h,
                            settled: true,
                        },
                    );
                    o.set(|o| &o.conn, token);
                    o.set(|o| &o.peer_written, peer.asked() as u64);
                    Outcome::Ready
                }
                Poll::Ready(Err(IoFailure::Refused(t))) => {
                    lock(&c.listeners).remove(&i.listener());
                    o.fail(Refusal::failed(t))
                }
                Poll::Ready(Err(e)) => o.fail(refusal(e)),
            }
        })
    }
}

/// `dial`: open the authority's one literal address; `flush` settles the connect.
pub struct Dial;
impl SafeSlot for Dial {
    type Kind = TransportKind;
    type In = DialIn;
    type Out = ConnOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, DialIn>,
        mut o: Out<'_, ConnOut>,
    ) -> Outcome {
        let Some(dest) = i.dest() else {
            return o.fail(Refusal::failed("dial: no destination"));
        };
        if dest.kind() != DEST_AUTHORITY {
            return o.fail(Refusal::refused(
                "dial: a tcp carrier reaches an authority, never a program",
            ));
        }
        let Ok(authority) = dest.authority().as_str() else {
            return o.fail(Refusal::failed("dial: the authority is not UTF-8"));
        };
        let literal = authority.starts_with("unix:/")
            || authority
                .parse::<busbar_contract::net::SocketAddr>()
                .is_ok();
        if !literal {
            return o.fail(Refusal::refused(
                "dial: the authority is not an IP literal or unix: path; the carrier never resolves a name",
            ));
        }
        over!("dial", inst, o, |c, io| {
            match io.open(authority) {
                Ok(h) => {
                    let token = c.mint();
                    lock(&c.conns).insert(
                        token,
                        Conn {
                            io: h,
                            settled: false,
                        },
                    );
                    o.set(|o| &o.conn, token);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(e)),
            }
        })
    }
}

/// `flush`: a dial settles, connected or refused.
pub struct Flush;
impl SafeSlot for Flush {
    type Kind = TransportKind;
    type In = ConnIn;
    type Out = OutHead;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, ConnIn>,
        mut o: Out<'_, OutHead>,
    ) -> Outcome {
        over!("flush", inst, o, |c, io| {
            let Some(conn) = lock(&c.conns).get(&i.conn()).copied() else {
                return o.fail(Refusal::failed("flush: no such connection"));
            };
            if conn.settled {
                return Outcome::Ready;
            }
            match io.ready(conn.io, DIR_WRITE) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(())) => {
                    if let Some(conn) = lock(&c.conns).get_mut(&i.conn()) {
                        conn.settled = true;
                    }
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => {
                    if let_go(&io.close(conn.io)) {
                        lock(&c.conns).remove(&i.conn());
                    }
                    o.fail(refusal(e))
                }
            }
        })
    }
}

/// `read`: what the socket has, straight into the host's buffer.
pub struct Read;
impl SafeSlot for Read {
    type Kind = TransportKind;
    type In = ReadIn;
    type Out = IoOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, ReadIn>,
        mut o: Out<'_, IoOut>,
    ) -> Outcome {
        over!("read", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("read: no such connection"));
            };
            let mut buf = i.buf();
            match io.read_host(h, &mut buf) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(n)) => {
                    o.set(|o| &o.len, n as u64);
                    if n > 0 {
                        o.set(|o| &o.flags, READ_END_OF_FRAME);
                    }
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(e)),
            }
        })
    }
}

/// `write`: what the socket takes of the bytes offered.
pub struct Write;
impl SafeSlot for Write {
    type Kind = TransportKind;
    type In = WriteIn;
    type Out = IoOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, WriteIn>,
        mut o: Out<'_, IoOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        over!("write", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("write: no such connection"));
            };
            match io.write(h, bytes) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(n)) => {
                    o.set(|o| &o.len, n as u64);
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(e)),
            }
        })
    }
}

/// `shut`: close and forget the connection (kept if the host could not close it).
pub struct Shut;
impl SafeSlot for Shut {
    type Kind = TransportKind;
    type In = ShutIn;
    type Out = OutHead;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, ShutIn>,
        mut o: Out<'_, OutHead>,
    ) -> Outcome {
        over!("shut", inst, o, |c, io| {
            let conn = lock(&c.conns).remove(&i.conn());
            if let Some(conn) = conn {
                let closed = io.close(conn.io);
                if !let_go(&closed) {
                    lock(&c.conns).insert(i.conn(), conn);
                }
                if let Err(e) = closed {
                    return o.fail(refusal(e));
                }
            }
            Outcome::Ready
        })
    }
}

/// `arrival`: the far end's address and the local port, as the host reads them.
pub struct Arrival;
impl SafeSlot for Arrival {
    type Kind = TransportKind;
    type In = ArrivalIn;
    type Out = ArrivalOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, ArrivalIn>,
        mut o: Out<'_, ArrivalOut>,
    ) -> Outcome {
        over!("arrival", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("arrival: no such connection"));
            };
            let mut peer = [0_u8; MAX_ADDR];
            match io.ends(h, &mut peer) {
                Ok((port, n)) => {
                    let mut buf = i.peer_buf();
                    buf.extend(&peer[..n.min(peer.len())]);
                    o.set(|o| &o.local_port, port);
                    o.set(|o| &o.peer_written, buf.written() as u64);
                    o.set(|o| &o.peer_needed, buf.needed() as u64);
                    if buf.fits() {
                        Outcome::Ready
                    } else {
                        o.fail(Refusal::failed("arrival: the peer buffer is too small"))
                    }
                }
                Err(e) => o.fail(refusal(e)),
            }
        })
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Carried),
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<NoLocate>,
        begin: Safe<NoBegin>,
        ingest: Safe<NoIngest>,
        emit: Safe<NoEmit>,
        encode: Safe<NoEncode>,
        refuse: Safe<NoRefuse>,
        finish: Safe<NoFinish>,
        detach: Safe<NoDetach>,
        adopt: Safe<NoAdopt>,
        timer: Safe<NoTimer>,
    },
}

