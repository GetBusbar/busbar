// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` CARRIER, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2 and §5;
//! TRANSPORT-STACK (2)): the carrier ops over the HOST'S I/O (`busbar_contract::abi::host::io`,
//! `io.*`), and the framer ops refused. The host owns every socket; this carrier holds only the
//! host's opaque handles and owns the policy over them:
//!
//! * `listen` binds the address it is asked to, and `accept` takes each connection off it;
//! * `dial` reads the authority it is lent (`ip:port`, `[v6]:port` or `unix:` and an absolute path,
//!   byte for byte) as its ONE address — never a name, which it does not resolve: the host's one
//!   destination judge already pinned the address it may dial (THE DESIGN §5, "dials exactly the
//!   pinned judged address") — and opens it, one attempt; the connect is bounded by the open the host runs it
//!   under;
//! * `read` answers what the socket has, straight into the host's buffer: a byte stream, so every
//!   read completes a frame (`READ_END_OF_FRAME`); `write` hands the host what it is offered, and
//!   a frame's end means nothing to a stream;
//! * `flush` settles the dial (connected, or the far end's refusal);
//! * `shut` closes the connection whatever the reason, and forgets it; `arrival` answers the far
//!   end's address and the local port, as the host reads them off the socket.
//!
//! No op holds a byte of its own: a PENDING op moved nothing, so a cancel finds nothing moved.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::io::{Io, IoFailure, DIR_WRITE, MAX_ADDR};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn, IoOut, ListenIn,
    ListenOut, ReadIn, ShutIn, WriteIn, CANCEL_NOTHING_MOVED, DEST_AUTHORITY, READ_END_OF_FRAME,
};

/// What one instance carries: its listeners and its connections, each by the token it minted.
pub struct Carried {
    listeners: Mutex<HashMap<u64, u64>>,
    conns: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
}

/// One connection: the host's handle, and whether its dial has settled.
struct Conn {
    io: u64,
    settled: bool,
}

/// What every slot reads: the SDK's lifecycle state over [`Carried`].
type State = Held<Carried>;

impl Life for Carried {
    /// A PENDING carrier op moved nothing, so a cancel finds nothing moved.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This carrier reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            listeners: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Carried {
    fn conns(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.conns.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn listeners(&self) -> MutexGuard<'_, HashMap<u64, u64>> {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn mint(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// The host handle of connection `conn`.
    fn handle(&self, conn: u64) -> Option<u64> {
        self.conns().get(&conn).map(|c| c.io)
    }
}

/// The open instance and the host's I/O for this op, or the refusal a call on none earns.
fn carried<'a>(i: &Instance<'a, State>) -> Result<(&'a Carried, Io<'a>), Refusal> {
    let held = i.get().ok_or_else(|| Refusal::failed("no open instance"))?;
    let io = held
        .host()
        .map(|h| h.io(i.ticket()))
        .filter(Io::armed)
        .ok_or_else(|| Refusal::failed("the host lent this carrier no I/O"))?;
    Ok((held.life(), io))
}

/// The host's answer, as this op's refusal: the host's policy is REFUSED, the system's FAILED, each
/// with the host's own words.
fn refusal(e: &IoFailure) -> Refusal {
    match e {
        IoFailure::Refused(t) => Refusal::refused(t.clone()),
        other => Refusal::failed(other.text().to_owned()),
    }
}

/// Run `body` over the instance and its I/O, failing the op without one.
macro_rules! over {
    ($inst:expr, $o:expr, |$c:ident, $io:ident| $body:block) => {
        match carried(&$inst) {
            Ok(($c, mut $io)) => $body,
            Err(r) => return $o.fail(r),
        }
    };
}

/// A framer op: REFUSED. A carrier frames nothing (`abi::transport`: a transport fills the slots of
/// the role it does not play with a stub that answers REFUSED).
pub struct NotAFramer<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotAFramer<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

/// `listen`: bind the address, and answer the address bound into the host's buffer.
pub struct Listen;
impl SafeSlot for Listen {
    type In = ListenIn;
    type Out = ListenOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ListenIn>,
        mut o: Out<'_, ListenOut>,
    ) -> Outcome {
        let Ok(bind) = i.field(|x| &x.bind).as_str() else {
            return o.fail(Refusal::failed("listen: the bind address is not UTF-8"));
        };
        over!(inst, o, |c, io| {
            let mut addr = i.addr_buf();
            match io.listen_host(bind, &mut addr) {
                Ok(h) => {
                    let token = c.mint();
                    c.listeners().insert(token, h);
                    o.set(|o| &o.listener, token);
                    o.set(|o| &o.addr_written, addr.asked() as u64);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `accept`: the next connection off the listener, its far end into the host's buffer.
pub struct Accept;
impl SafeSlot for Accept {
    type In = AcceptIn;
    type Out = AcceptOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, AcceptIn>,
        mut o: Out<'_, AcceptOut>,
    ) -> Outcome {
        over!(inst, o, |c, io| {
            let Some(l) = c.listeners().get(&i.listener).copied() else {
                return o.fail(Refusal::failed("accept: no such listener"));
            };
            let mut peer = i.peer_buf();
            match io.accept_host(l, &mut peer) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(h)) => {
                    let token = c.mint();
                    c.conns().insert(
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
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// THE ADDRESS A DIAL OPENS, byte for byte: an IP literal (`v4:port` or `[v6]:port`) or a `unix:`
/// absolute path, and nothing else. A name (`localhost` included) and a scheme prefix are not read
/// here: the host's one destination judge resolves and pins the address a dial may reach and hands
/// this carrier that pinned address, which the carrier dials exactly (THE DESIGN §5; CONNECTOR-19).
#[must_use]
pub fn resolve(authority: &str) -> Option<String> {
    let literal = authority.starts_with("unix:/") || authority.parse::<SocketAddr>().is_ok();
    literal.then(|| authority.to_owned())
}

/// `dial`: the authority's one address, opened once; the connection's token at once, its connect
/// settling under `flush`. A program is not this carrier's destination: REFUSED.
pub struct Dial;
impl SafeSlot for Dial {
    type In = DialIn;
    type Out = ConnOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, DialIn>, mut o: Out<'_, ConnOut>) -> Outcome {
        let Some(dest) = i.dest() else {
            return o.fail(Refusal::failed("dial: no destination"));
        };
        if dest.kind != DEST_AUTHORITY {
            return o.fail(Refusal::refused(
                "dial: a tcp carrier reaches an authority, never a program",
            ));
        }
        let Ok(authority) = dest.field(|d| &d.authority).as_str() else {
            return o.fail(Refusal::failed("dial: the authority is not UTF-8"));
        };
        let Some(addr) = resolve(authority) else {
            return o.fail(Refusal::refused(format!(
                "`{authority}` is not an address the carrier dials without resolving a name"
            )));
        };
        over!(inst, o, |c, io| {
            match io.open(&addr) {
                Ok(h) => {
                    let token = c.mint();
                    c.conns().insert(
                        token,
                        Conn {
                            io: h,
                            settled: false,
                        },
                    );
                    o.set(|o| &o.conn, token);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `flush`: a dial settles — connected; or refused, and the dial answers the far end's refusal.
/// Nothing is held to write.
pub struct Flush;
impl SafeSlot for Flush {
    type In = ConnIn;
    type Out = busbar_contract::abi::mechanism::call::OutHead;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ConnIn>,
        mut o: Out<'_, busbar_contract::abi::mechanism::call::OutHead>,
    ) -> Outcome {
        over!(inst, o, |c, io| {
            let (h, settled) = match c.conns().get(&i.conn) {
                Some(conn) => (conn.io, conn.settled),
                None => return o.fail(Refusal::failed("flush: no such connection")),
            };
            if settled {
                return Outcome::Ready;
            }
            match io.ready(h, DIR_WRITE) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(())) => {
                    if let Some(conn) = c.conns().get_mut(&i.conn) {
                        conn.settled = true;
                    }
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => {
                    let _ = io.close(h);
                    c.conns().remove(&i.conn);
                    o.fail(refusal(&e))
                }
            }
        })
    }
}

/// `read`: what the socket has, straight into the host's buffer; every read a frame of the stream.
pub struct Read;
impl SafeSlot for Read {
    type In = ReadIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ReadIn>, mut o: Out<'_, IoOut>) -> Outcome {
        over!(inst, o, |c, io| {
            let Some(h) = c.handle(i.conn) else {
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
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `write`: what the socket takes of the bytes offered.
pub struct Write;
impl SafeSlot for Write {
    type In = WriteIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, WriteIn>, mut o: Out<'_, IoOut>) -> Outcome {
        let bytes = i.bytes();
        over!(inst, o, |c, io| {
            let Some(h) = c.handle(i.conn) else {
                return o.fail(Refusal::failed("write: no such connection"));
            };
            match io.write(h, bytes) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(n)) => {
                    o.set(|o| &o.len, n as u64);
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `shut`: the connection is closed, whatever the reason, and forgotten. An unknown connection is
/// already closed.
pub struct Shut;
impl SafeSlot for Shut {
    type In = ShutIn;
    type Out = busbar_contract::abi::mechanism::call::OutHead;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ShutIn>,
        mut o: Out<'_, busbar_contract::abi::mechanism::call::OutHead>,
    ) -> Outcome {
        over!(inst, o, |c, io| {
            if let Some(conn) = c.conns().remove(&i.conn) {
                let _ = io.close(conn.io);
            }
            Outcome::Ready
        })
    }
}

/// `arrival`: the far end's address and the local port, as the host reads them off the socket.
pub struct Arrival;
impl SafeSlot for Arrival {
    type In = ArrivalIn;
    type Out = ArrivalOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ArrivalIn>,
        mut o: Out<'_, ArrivalOut>,
    ) -> Outcome {
        over!(inst, o, |c, io| {
            let Some(h) = c.handle(i.conn) else {
                return o.fail(Refusal::failed("arrival: no such connection"));
            };
            let mut peer = [0_u8; MAX_ADDR];
            match io.ends(h, &mut peer) {
                Ok((port, n)) => {
                    let mut buf = i.peer_buf();
                    buf.extend(&peer[..n]);
                    o.set(|o| &o.local_port, port);
                    o.set(|o| &o.peer_written, buf.written() as u64);
                    o.set(|o| &o.peer_needed, buf.needed() as u64);
                    if buf.fits() {
                        Outcome::Ready
                    } else {
                        o.fail(Refusal::failed("arrival: the peer buffer is too small"))
                    }
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}
