// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S CARRIER SCRIPT (TRANSPORT-STACK (2): a carrier listens, accepts, dials,
//! reads, writes, closes and reports its far end, poll-shaped with the host's wake), driven as the
//! connector drives a carrier: `open`, the awaited `ready`, then every carrier op INLINE on one of a
//! connection's two tickets (`Plugin::call_inline`), over the suite's host I/O ([`super::host_io`]),
//! which moves real bytes and admits only what the script admits. Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings it opens over>,
//!   "transport": { "carrier": {
//!     "listen":   true | false,                          // does it listen (an `ip:port` bind)?
//!     "dial":     "authority" | { "program": "<absolute path>", "args": [..], <env> },
//!     "exchange": [{ "write": "<a frame>", "read": "<the frame the far end answers>" },
//!                  { "write": "<a frame it refuses to carry>", "refused": true }],
//!     "pending":  { "write": "<a frame>", "read": "<its answer>" } } } }
//! ```
//!
//! `<env>` is the program's optional environment: the key `env`, its value `[name, value]` string
//! pairs.
//!
//! A dialled AUTHORITY's far end is an echo server the script runs; a PROGRAM is the far end
//! itself. What the script proves, both legs, the folds equal step for step:
//!
//! * every framer op is REFUSED, one crossing each (a carrier frames nothing);
//! * a listening carrier binds what was admitted, accepts the script's connection, answers its far
//!   end and local port, reads what the far end sent, writes what the far end reads, and its shut
//!   is the far end's end of stream; a carrier that listens on nothing REFUSES `listen`;
//! * a dial reaches its far end; each `exchange` frame written is answered by the frame read back,
//!   a frame a read completes carrying `READ_END_OF_FRAME`; a frame the carrier refuses to carry is
//!   FAILED;
//! * a read with nothing to read answers PENDING and moves nothing; the host's wake for the ticket
//!   fires once the far end answers, and the RESUMED read answers the frame;
//! * THE HOST'S GUARD (RED arm): a dial to what the host did not admit is refused, and so is the
//!   destination kind the carrier does not reach.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead, Outcome};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut,
    Destination, DialIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn, CLOSE_NORMAL,
    DEST_AUTHORITY, DEST_PROGRAM, MAX_ADDR, READ_END_OF_FRAME, WRITE_END_OF_FRAME,
};

use super::host_io::{Admit, SuiteIo};
use super::transport::{facts_line, loaded, lossy};
use super::{
    abi_bytes as abi, asis, bind, closed, crossings, dispatcher, input, opened, output, Fold, Leg,
    Script, Subject, Want,
};
use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{Called, Frame, InFrame, InlineTicket, OutFrame, Plugin};

/// What the script's waker saw: whether the host woke the ticket it was registered on.
#[derive(Default)]
struct Woken(AtomicBool);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// One side of a connection: its inline ticket and the waker the script registered on it.
struct Side {
    ticket: InlineTicket,
    woken: Arc<Woken>,
}

impl Side {
    fn new(d: &crate::dispatch::Dispatcher) -> Self {
        let ticket = d.inline_ticket().expect("an inline ticket");
        let woken = Arc::new(Woken::default());
        ticket.register(&Waker::from(Arc::clone(&woken)));
        Self { ticket, woken }
    }
}

/// One inline crossing of op `s` on `side`.
fn go<I: InFrame, O: OutFrame>(
    p: &Plugin<Transport>,
    side: &Side,
    resume: bool,
    s: u32,
    i: I,
) -> (Called, O) {
    let mut f = Frame::new(i, output::<O>());
    let c = p.call_inline(side.ticket.ticket(), resume, s, &mut f);
    (c, f.out)
}

fn err(c: &Called) -> String {
    c.error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .into_owned()
}

/// An address with its port blanked: the two legs bind and dial different ports.
fn unported(a: &str) -> String {
    a.rsplit_once(':')
        .map_or_else(|| a.to_owned(), |(h, _)| format!("{h}:*"))
}

fn text(v: &serde_json::Value, what: &str) -> String {
    v.as_str()
        .unwrap_or_else(|| panic!("conformance.json: transport.carrier.{what} must be a string"))
        .to_owned()
}

/// The ops of the role a carrier does not play, in slot order: each REFUSED, one crossing each.
fn framer_ops(p: &Plugin<Transport>, side: &Side) -> String {
    let outcomes = [
        go::<_, LocateOut>(p, side, false, slot::LOCATE, input::<LocateIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::BEGIN, input::<BeginIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::INGEST, input::<IngestIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::EMIT, input::<EmitIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::ENCODE, input::<EncodeIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::REFUSE, input::<RefuseIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::FINISH, input::<FinishIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::DETACH, input::<FramingIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::ADOPT, input::<AdoptIn>()).0,
        go::<_, FramerOut>(p, side, false, slot::TIMER, input::<FramingIn>()).0,
    ];
    let names = [
        "locate", "begin", "ingest", "emit", "encode", "refuse", "finish", "detach", "adopt",
        "timer",
    ];
    names
        .iter()
        .zip(outcomes)
        .map(|(n, c)| format!("{n}={:?}", c.outcome))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A destination, with the storage its pointers name.
struct Dest {
    authority: String,
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    arg_strs: Vec<AbiStr>,
    env_fields: Vec<Field>,
    kind: u32,
}

impl Dest {
    fn authority(a: &str) -> Box<Self> {
        Box::new(Self {
            authority: a.to_owned(),
            program: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            arg_strs: Vec::new(),
            env_fields: Vec::new(),
            kind: DEST_AUTHORITY,
        })
    }

    fn program(v: &serde_json::Value) -> Box<Self> {
        let program = text(&v["program"], "dial.program");
        let args = v["args"]
            .as_array()
            .map(|a| a.iter().map(|x| text(x, "dial.args")).collect())
            .unwrap_or_default();
        /// The program's environment, read by field name: `[name, value]` pairs, absent for none.
        #[derive(serde::Deserialize)]
        struct Environment {
            #[serde(default)]
            env: Vec<(String, String)>,
        }
        let env = serde_json::from_value::<Environment>(v.clone())
            .unwrap_or_else(|e| panic!("conformance.json: transport.carrier.dial.env: {e}"))
            .env;
        let mut d = Box::new(Self {
            authority: String::new(),
            program,
            args,
            env,
            arg_strs: Vec::new(),
            env_fields: Vec::new(),
            kind: DEST_PROGRAM,
        });
        d.arg_strs = d.args.iter().map(abi).collect();
        d.env_fields = d
            .env
            .iter()
            .map(|(k, v)| Field {
                name: abi(k),
                value: abi(v),
            })
            .collect();
        d
    }

    fn raw(&self) -> Destination {
        Destination {
            kind: self.kind,
            _reserved: 0,
            authority: abi(&self.authority),
            program: abi(&self.program),
            args: self.arg_strs.as_ptr(),
            args_len: self.arg_strs.len(),
            env: self.env_fields.as_ptr(),
            env_len: self.env_fields.len(),
        }
    }
}

fn dial(p: &Plugin<Transport>, side: &Side, d: &Dest) -> (String, u64) {
    let raw = d.raw();
    let mut i: DialIn = input();
    i.dest = &raw;
    let (c, o) = go::<_, ConnOut>(p, side, false, slot::DIAL, i);
    let line = match c.outcome {
        Outcome::Ready => "Ready".to_owned(),
        other => format!("{other:?} err={:?}", err(&c)),
    };
    (line, o.conn)
}

fn flush(p: &Plugin<Transport>, side: &Side, conn: u64) -> String {
    let mut i: ConnIn = input();
    i.conn = conn;
    let (c, _) = go::<_, OutHead>(p, side, false, slot::FLUSH, i);
    format!("{:?} err={:?}", c.outcome, err(&c))
}

fn write(p: &Plugin<Transport>, side: &Side, conn: u64, bytes: &[u8]) -> String {
    let mut i: WriteIn = input();
    i.conn = conn;
    i.bytes = bytes.as_ptr();
    i.len = bytes.len();
    i.flags = WRITE_END_OF_FRAME;
    let (c, o) = go::<_, IoOut>(p, side, false, slot::WRITE, i);
    match c.outcome {
        Outcome::Ready => format!("Ready len={}", o.len),
        other => format!("{other:?} err={:?}", err(&c)),
    }
}

fn read(p: &Plugin<Transport>, side: &Side, conn: u64, resume: bool) -> String {
    let mut buf = vec![0_u8; 64 * 1024];
    let mut i: ReadIn = input();
    i.conn = conn;
    i.buf = buf.as_mut_ptr();
    i.cap = buf.len();
    let (c, o) = go::<_, IoOut>(p, side, resume, slot::READ, i);
    match c.outcome {
        Outcome::Ready => format!(
            "Ready bytes={:?} end_of_frame={}",
            lossy(&buf[..o.len as usize]),
            o.flags & READ_END_OF_FRAME != 0
        ),
        other => format!("{other:?} err={:?}", err(&c)),
    }
}

fn shut(p: &Plugin<Transport>, side: &Side, conn: u64) -> String {
    let mut i: ShutIn = input();
    i.conn = conn;
    i.reason = CLOSE_NORMAL;
    let (c, _) = go::<_, OutHead>(p, side, false, slot::SHUT, i);
    format!("{:?}", c.outcome)
}

/// Wait (up to five seconds) for the host to wake `side`, pumping its sockets' readiness.
fn woken(host: &SuiteIo, side: &Side) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        host.pump();
        if side.woken.0.swap(false, Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

/// An echo far end: every connection it accepts answers what it reads, until its end.
fn echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").expect("the echo far end binds");
    let at = l.local_addr().expect("bound").to_string();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0_u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    at
}

/// The script, one leg.
pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = &s.kind_inputs("transport")["carrier"];
    assert!(
        k.is_object(),
        "conformance.json has no `transport.carrier` inputs"
    );
    let settings = s.settings();
    let d = dispatcher();
    let host = Arc::new(SuiteIo::default());
    assert!(
        d.install_io(Arc::clone(&host) as _),
        "the suite's host I/O installs"
    );
    let (p, facts) = loaded(s, leg, bind(&d, "transport"));
    let mut sc = Script::new(crossings(&p));
    let (rd, wr) = (Side::new(&d), Side::new(&d));
    let is = |line: &str| Want::Is(line.into());

    sc.line("facts", 0, || facts_line(&p, &facts));
    // 0: the dispatcher refuses an op on an instance that is not open, without a crossing.
    sc.judged("dial unopened", 0, Want::Starts("Refused "), || {
        dial(&p, &wr, &Dest::authority("127.0.0.1:1")).0
    });
    opened(&mut sc, (s, &p, &d), &settings, &asis);

    // ── the role it does not play ──
    let want = is(
        "locate=Refused begin=Refused ingest=Refused emit=Refused encode=Refused \
                   refuse=Refused finish=Refused detach=Refused adopt=Refused timer=Refused",
    );
    sc.judged("framer ops", 10, want, || framer_ops(&p, &wr));

    // ── listen, accept, and the accepted connection both ways ──
    let listens = k["listen"].as_bool().unwrap_or(false);
    let ls = Side::new(&d);
    let bind_at = "127.0.0.1:0";
    host.admit(ls.ticket.ticket(), Admit::Bind(bind_at.into()));
    let mut addr = vec![0_u8; MAX_ADDR as usize];
    let want = if listens {
        is("Ready addr=127.0.0.1:*")
    } else {
        Want::Starts("Refused")
    };
    let (listener, bound) = sc.step_judged("listen", 1, want, || {
        let mut i: ListenIn = input();
        i.bind = abi(bind_at);
        i.addr_buf = addr.as_mut_ptr();
        i.addr_cap = addr.len();
        let (c, o) = go::<_, ListenOut>(&p, &ls, false, slot::LISTEN, i);
        let bound = lossy(&addr[..(o.addr_written as usize).min(addr.len())]);
        let line = match c.outcome {
            Outcome::Ready => format!("Ready addr={}", unported(&bound)),
            other => format!("{other:?}"),
        };
        (line, (o.listener, bound))
    });
    if listens {
        let mut far = TcpStream::connect(&bound).expect("the script reaches the listener");
        let _ = far.set_read_timeout(Some(Duration::from_secs(5)));
        // The connection is in the backlog once `connect` answered: the accept answers at once.
        let mut peer = vec![0_u8; MAX_ADDR as usize];
        let accepted = sc.step_judged("accept", 1, is("Ready peer=127.0.0.1:*"), || {
            let mut i: AcceptIn = input();
            i.listener = listener;
            i.peer_buf = peer.as_mut_ptr();
            i.peer_cap = peer.len();
            let (c, o) = go::<_, AcceptOut>(&p, &ls, false, slot::ACCEPT, i);
            let at = lossy(&peer[..(o.peer_written as usize).min(peer.len())]);
            (format!("{:?} peer={}", c.outcome, unported(&at)), o.conn)
        });
        let want = is("Ready peer=127.0.0.1:* local_port_is_bound=true");
        sc.judged("arrival", 1, want, || {
            let mut peer = vec![0_u8; MAX_ADDR as usize];
            let mut i: ArrivalIn = input();
            i.conn = accepted;
            i.peer_buf = peer.as_mut_ptr();
            i.peer_cap = peer.len();
            let (c, o) = go::<_, ArrivalOut>(&p, &rd, false, slot::ARRIVAL, i);
            let at = lossy(&peer[..(o.peer_written as usize).min(peer.len())]);
            let port_is_bound = bound.ends_with(&format!(":{}", o.local_port));
            format!(
                "{:?} peer={} local_port_is_bound={port_is_bound}",
                c.outcome,
                unported(&at)
            )
        });
        far.write_all(b"from the far end")
            .expect("the far end writes");
        // Loopback: the bytes are at the accepted socket well inside this.
        std::thread::sleep(Duration::from_millis(100));
        let want = is("Ready bytes=\"from the far end\" end_of_frame=true");
        sc.judged("accepted read", 1, want, || read(&p, &rd, accepted, false));
        sc.judged("accepted write", 1, is("Ready len=14"), || {
            write(&p, &wr, accepted, b"to the far end")
        });
        let mut got = [0_u8; 14];
        let ok = far.read_exact(&mut got).is_ok() && &got == b"to the far end";
        sc.judged("far end read", 0, is("true"), || format!("{ok}"));
        sc.judged("accepted shut", 1, is("Ready"), || shut(&p, &wr, accepted));
        let mut rest = Vec::new();
        let ended = far.read_to_end(&mut rest).is_ok() && rest.is_empty();
        sc.judged("far end saw the end", 0, is("true"), || format!("{ended}"));
    }

    // ── the dial, its exchange, a pending read resumed by the host's wake ──
    let (dest, other) = match &k["dial"] {
        serde_json::Value::String(a) if a == "authority" => {
            let at = echo();
            host.admit(wr.ticket.ticket(), Admit::Addr(at.clone()));
            (
                Dest::authority(&at),
                Dest::program(&serde_json::json!({ "program": "/bin/cat" })),
            )
        }
        v => {
            let d = Dest::program(v);
            host.admit(wr.ticket.ticket(), Admit::Program(d.program.clone()));
            (d, Dest::authority("127.0.0.1:1"))
        }
    };
    let conn = sc.step_judged("dial", 1, is("Ready"), || dial(&p, &wr, &dest));
    sc.judged("flush", 1, Want::Starts("Ready "), || flush(&p, &wr, conn));
    let made = host.made(wr.ticket.ticket());
    for (n, x) in k["exchange"]
        .as_array()
        .expect("conformance.json: transport.carrier.exchange must be an array")
        .iter()
        .enumerate()
    {
        let frame = text(&x["write"], "exchange.write");
        let refused = x["refused"].as_bool().unwrap_or(false);
        let want = if refused {
            Want::Starts("Failed ")
        } else {
            Want::Is(format!("Ready len={}", frame.len()))
        };
        sc.judged(&format!("write #{n}"), 1, want, || {
            write(&p, &wr, conn, frame.as_bytes())
        });
        if refused {
            continue;
        }
        if let Some(h) = made {
            host.wait_readable(h);
        }
        let answer = text(&x["read"], "exchange.read");
        let want = Want::Is(format!("Ready bytes={answer:?} end_of_frame=true"));
        sc.judged(&format!("read #{n}"), 1, want, || {
            read(&p, &rd, conn, false)
        });
    }
    let pend = &k["pending"];
    let (frame, answer) = (
        text(&pend["write"], "pending.write"),
        text(&pend["read"], "pending.read"),
    );
    rd.woken.0.store(false, Ordering::SeqCst);
    sc.judged("read pending", 1, Want::Starts("Pending "), || {
        read(&p, &rd, conn, false)
    });
    let want = Want::Is(format!("Ready len={}", frame.len()));
    sc.judged("write while a read pends", 1, want, || {
        write(&p, &wr, conn, frame.as_bytes())
    });
    sc.judged("the host woke the read", 0, is("true"), || {
        format!("{}", woken(&host, &rd))
    });
    // The pending read's RESUME on its ticket: the op's one first invocation was "read pending", so
    // this re-invocation is counted apart and reported, never pinned (Q-P4-5: one op, one crossing,
    // however often it pends).
    let want = Want::Is(format!("Ready bytes={answer:?} end_of_frame=true"));
    sc.judged("read resumed", 0, want, || read(&p, &rd, conn, true));
    sc.judged("shut", 1, is("Ready"), || shut(&p, &wr, conn));
    sc.judged("shut again", 1, is("Ready"), || shut(&p, &wr, conn));

    // ── THE HOST'S GUARD (RED arm): nothing the host did not admit is reached ──
    let guarded = Side::new(&d);
    let unadmitted = match dest.kind {
        DEST_AUTHORITY => Dest::authority("127.0.0.1:9"),
        _ => Dest::program(&serde_json::json!({ "program": "/bin/false" })),
    };
    sc.judged("dial not admitted", 1, Want::Starts("Refused "), || {
        dial(&p, &guarded, &unadmitted).0
    });
    sc.judged("dial the other kind", 1, Want::Starts("Refused "), || {
        dial(&p, &guarded, &other).0
    });
    drop(guarded);

    closed(&mut sc, &p, &asis);
    // 0: a closed instance answers FAULT without a crossing.
    sc.judged("dial after close", 0, Want::Starts("Fault "), || {
        dial(&p, &wr, &Dest::authority("127.0.0.1:1")).0
    });
    // What the carrier did not close itself is the host's to reap: the script's own listener.
    sc.judged("handles held after close", 0, is("true"), || {
        format!("{}", host.held() <= 1)
    });
    sc.fold()
}
