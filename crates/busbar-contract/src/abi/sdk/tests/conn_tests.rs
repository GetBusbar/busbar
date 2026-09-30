// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector through a scripted host: every service pends once and completes on the host's
//! side, the op's re-entry re-issues each handle and reads the stored result, and no service ever
//! runs twice.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use super::*;

/// One scripted reply piece: `(kind, code, reason, fields, body)`.
type Scripted = (u32, u32, &'static [u8], &'static [u8], &'static [u8]);

/// What the scripted host stored per handle `seq`, how many times it ran each, and the reply it
/// plays.
#[derive(Default)]
struct Script {
    stored: HashMap<u32, (Outcome, u64, u64)>,
    runs: HashMap<u32, u32>,
    reads: usize,
    reply: Vec<Scripted>,
}

/// A scripted piece (the byte strings coerce to slices here).
fn piece(
    kind: u32,
    code: u32,
    reason: &'static [u8],
    fields: &'static [u8],
    body: &'static [u8],
) -> Scripted {
    (kind, code, reason, fields, body)
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One test at a time: the script is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *out };
    out.outcome = RawOutcome::of(o);
    out.value = value;
    out.len = len;
    RawOutcome::of(o)
}

/// Write one reply piece the way a connector host does: its bytes (reason, then the field block,
/// or the body) into the plugin's buffer, its descriptor into the plugin's slot.
fn play(io: ReplyIn, (kind, code, reason, fields, body): Scripted) -> u64 {
    let mut bytes = Vec::new();
    let mut piece = ReplyPiece {
        kind,
        code,
        ..ReplyPiece::default()
    };
    if kind == REPLY_BODY {
        bytes.extend_from_slice(body);
    } else {
        piece.reason = FrameSpan {
            offset: 0,
            len: reason.len() as u64,
        };
        bytes.extend_from_slice(reason);
        piece.fields = FrameSpan {
            offset: bytes.len() as u64,
            len: fields.len() as u64,
        };
        bytes.extend_from_slice(fields);
    }
    assert!(bytes.len() <= io.len);
    // SAFETY: `io.buf` holds `io.len` writable bytes and `io.piece` a writable descriptor, both
    // the SDK's parked ones, until the read completes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), io.buf, bytes.len());
        io.piece.write(piece);
    }
    bytes.len() as u64
}

/// One scripted service: the first issue of a handle runs it (and pends); a re-issue answers the
/// stored result.
fn serve(op: u32, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`.
    let head = unsafe { *input.cast::<ServiceHead>() };
    assert_eq!(head.op, op);
    let seq = head.handle.seq;
    let mut g = SCRIPT.lock().unwrap();
    let s = g.as_mut().expect("a script");
    if let Some(&(o, v, l)) = s.stored.get(&seq) {
        return answer(out, o, v, l);
    }
    *s.runs.entry(seq).or_default() += 1;
    let (value, len) = match op {
        service::ESTABLISH => (7, 0),
        service::WRITE => {
            // SAFETY: an `IoIn`.
            let io = unsafe { *input.cast::<IoIn>() };
            (0, io.len as u64)
        }
        service::READ_REPLY => {
            // SAFETY: a `ReplyIn`.
            let io = unsafe { *input.cast::<ReplyIn>() };
            let piece = s.reply[s.reads.min(s.reply.len() - 1)];
            s.reads += 1;
            (0, play(io, piece))
        }
        _ => (0, 0),
    };
    s.stored.insert(seq, (Outcome::Ready, value, len));
    answer(out, Outcome::Pending, 0, 0)
}

extern "C" fn establish(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::ESTABLISH, i, o)
}
extern "C" fn write(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::WRITE, i, o)
}
extern "C" fn read_reply(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::READ_REPLY, i, o)
}
extern "C" fn close(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::CLOSE, i, o)
}

static SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: crate::abi::host::conn::connector::SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: Some(write),
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
};

fn host(conns: *const ConnectorSlots) -> Host {
    Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns,
        services: std::ptr::null(),
    })
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

/// Run the op to completion under `reply`: `(what it answered, entries, runs per service)`.
fn run<T>(
    reply: Vec<Scripted>,
    body: impl Fn(&mut Connector<'_>, &mut Exchange) -> Answer<T>,
) -> (Result<T, ConnFailure>, u32, HashMap<u32, u32>) {
    *SCRIPT.lock().unwrap() = Some(Script {
        reply,
        ..Script::default()
    });
    let h = host(&SLOTS);
    let mut state = Exchange::new(b"ping".to_vec());
    let mut entries = 0;
    let answered = loop {
        entries += 1;
        assert!(entries < 30, "the op never completed");
        // One entry of the op: a fresh connector, the same parked state.
        let mut c = h.connector(TICKET);
        if let Poll::Ready(r) = body(&mut c, &mut state) {
            break r;
        }
    };
    let runs = SCRIPT.lock().unwrap().take().unwrap().runs;
    (answered, entries, runs)
}

/// RED: the reply's reason crosses exactly as the peer sent it, a non-canonical phrase included.
#[test]
fn an_exchange_reads_the_reply_as_sent_and_no_service_runs_twice() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply: Vec<Scripted> = vec![
        (
            REPLY_HEAD,
            200,
            b"Totally Fine",
            b"x-a: 1\r\nx-b: two\r\n",
            b"",
        ),
        piece(REPLY_BODY, 0, b"", b"", b"hello "),
        piece(REPLY_BODY, 0, b"", b"", b"world"),
        piece(REPLY_END, 0, b"", b"", b""),
    ];
    let (answered, entries, runs) = run(reply, |c, st| exchange(c, st, 0, Some("far")));
    let r = answered.expect("the exchange completes");
    assert_eq!(r.status, 200);
    assert_eq!(r.reason.as_deref(), Some(&b"Totally Fine"[..]));
    assert_eq!(
        r.fields,
        vec![
            (b"x-a".to_vec(), b"1".to_vec()),
            (b"x-b".to_vec(), b"two".to_vec())
        ]
    );
    assert_eq!(r.body, b"hello world");
    // establish, write, four reads, close: seven services, each run once.
    assert_eq!(runs.len(), 7);
    assert!(runs.values().all(|&n| n == 1), "{runs:?}");
    // Every service pended once, so the op entered once more than it made services.
    assert_eq!(entries, 8);
}

/// RED: a pure-send transport's ack FAILURE (a code and the peer's text) reaches the plugin
/// verbatim, as an answer, never as a lost request.
#[test]
fn a_pure_send_acks_its_failure_with_a_code_and_the_peers_text() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply: Vec<Scripted> = vec![piece(REPLY_ACK, 550, b"mailbox unavailable", b"", b"")];
    let (answered, _, runs) = run(reply, |c, st| send_and_ack(c, st, 0, None));
    assert_eq!(
        answered,
        Ok(Ack {
            code: 550,
            reason: b"mailbox unavailable".to_vec()
        })
    );
    assert!(runs.values().all(|&n| n == 1));
}

/// RED: a transport that answers a read with no reply piece breaks the every-request-is-acked
/// rule: the plugin is told so, never left without an answer.
#[test]
fn a_transport_that_never_acks_is_a_conformance_failure() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply: Vec<Scripted> = vec![piece(0, 0, b"", b"", b"")];
    let (answered, _, _) = run(reply, |c, st| send_and_ack(c, st, 0, None));
    assert!(
        matches!(&answered, Err(ConnFailure::Failed(t)) if t.contains("every request is acked")),
        "{answered:?}"
    );
}

#[test]
fn an_instance_handed_no_connector_is_unarmed_and_no_ticket_cannot_pend() {
    let unarmed = host(std::ptr::null());
    let mut c = unarmed.connector(TICKET);
    assert_eq!(c.establish(0, None), Poll::Ready(Err(ConnFailure::Unarmed)));
    let h = host(&SLOTS);
    let mut c = h.connector(Ticket::NONE);
    assert_eq!(
        c.establish(0, None),
        Poll::Ready(Err(ConnFailure::NoTicket))
    );
}
