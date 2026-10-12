// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `stdio` carrier, driven through its own table the way the host's connector drives it, over a
//! SCRIPTED host I/O table (`abi::host::io`): one frame per line in (a line split across reads, a
//! blank line, the final unterminated line, the line ceiling), one line per frame out (gathered to
//! its end, refused when it cannot be one line), the spawn of exactly the program it is lent, and
//! every op of a role it does not play refused. An integration test, so the crate itself keeps
//! `#![deny(unsafe_code)]`: driving a raw table is the host's side. The real host's I/O is driven by
//! busbar's conformance suite (`tests/conformance.rs`).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;

use busbar_contract::abi::host::io::{
    HandleIn, IoSlots, ReadIn as IoReadIn, SpawnIn, WriteIn as IoWriteIn, SLOTS,
};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, Op, OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::check::check_tail;
use busbar_contract::abi::transport::{
    slot, ConnIn, ConnOut, Destination, DialIn, IoOut, ListenIn, ListenOut, Ops, ReadIn, ShutIn,
    TransportTail, WriteIn, DEST_AUTHORITY, DEST_PROGRAM, READ_END_OF_FRAME, ROLE_CARRIER,
    WRITE_END_OF_FRAME,
};
use busbar_transport_stdio::door::{door, MAX_LINE_BYTES, NOT_ONE_LINE, STATEMENT, TOO_LONG};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(t: &str) -> AbiStr {
    AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    }
}

fn text(t: AbiStr) -> String {
    if t.len == 0 {
        return String::new();
    }
    // SAFETY: the carrier's string, live for the call.
    String::from_utf8(unsafe { std::slice::from_raw_parts(t.ptr, t.len) }.to_vec()).unwrap()
}

fn ops() -> &'static Ops {
    let d: *const Door = door();
    // SAFETY: the door answers a `'static` door whose table is this kind's `Ops`.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*ih).ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    )
    .outcome()
}

// ── the scripted host ────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Script {
    /// The program `io.spawn` was asked for, with its arguments.
    spawned: Vec<(String, Vec<String>)>,
    /// What `io.read` answers next, in order: `None` = PENDING; an empty chunk = the end.
    reads: Vec<Option<Vec<u8>>>,
    /// Every byte `io.write` took.
    written: Vec<u8>,
    /// Handles closed.
    closed: Vec<u64>,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
static ONE: Mutex<()> = Mutex::new(());

fn with<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    f(SCRIPT.lock().unwrap().get_or_insert_with(Script::default))
}

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the carrier's `out`, live for the call.
    unsafe {
        (*out).outcome = RawOutcome::of(o);
        (*out).value = value;
        (*out).len = len;
    }
    RawOutcome::of(o)
}

extern "C" fn io_spawn(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<SpawnIn>().read() };
    // SAFETY: the host-lent list the carrier passed through.
    let args = unsafe { std::slice::from_raw_parts(i.args, i.args_len) };
    let args = args.iter().map(|a| text(*a)).collect();
    with(|sc| sc.spawned.push((text(i.program), args)));
    answer(out, Outcome::Ready, 7, 0)
}

extern "C" fn io_read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<IoReadIn>().read() };
    match with(|sc| (!sc.reads.is_empty()).then(|| sc.reads.remove(0))) {
        None | Some(None) => answer(out, Outcome::Pending, 0, 0),
        Some(Some(bytes)) => {
            assert!(bytes.len() <= i.cap);
            // SAFETY: the carrier's buffer, `cap` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.buf, bytes.len()) };
            answer(out, Outcome::Ready, 0, bytes.len() as u64)
        }
    }
}

extern "C" fn io_write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<IoWriteIn>().read() };
    // SAFETY: the carrier's bytes.
    let bytes = unsafe { std::slice::from_raw_parts(i.bytes, i.len) };
    with(|sc| sc.written.extend_from_slice(bytes));
    answer(out, Outcome::Ready, 0, bytes.len() as u64)
}

extern "C" fn io_close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<HandleIn>().read() };
    with(|sc| sc.closed.push(i.handle));
    answer(out, Outcome::Ready, 0, 0)
}

static IO: IoSlots = IoSlots {
    size: size_of::<IoSlots>() as u32,
    slots: SLOTS,
    open: None,
    listen: None,
    accept: None,
    read: Some(io_read),
    write: Some(io_write),
    ready: None,
    shut: None,
    close: Some(io_close),
    spawn: Some(io_spawn),
    ends: None,
};

struct Host {
    inst: *mut c_void,
    _tables: Box<HostTables>,
    conn: u64,
}

impl Host {
    fn new(reads: Vec<Option<Vec<u8>>>) -> Self {
        *SCRIPT.lock().unwrap() = Some(Script {
            reads,
            ..Script::default()
        });
        let tables = Box::new(HostTables {
            size: size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx {
                ptr: std::ptr::null_mut(),
            },
            wake: None,
            conns: std::ptr::null(),
            services: std::ptr::null(),
            io: &IO,
        });
        let mut i: OpenIn = z();
        i.host = &*tables;
        let mut o: OpenOut = z();
        let r = call(
            ops().head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        assert_eq!(r, Outcome::Ready);
        let args = [s("--stdio")];
        let mut dest: Destination = z();
        dest.kind = DEST_PROGRAM;
        dest.program = s("/usr/bin/server");
        dest.args = args.as_ptr();
        dest.args_len = args.len();
        let mut di: DialIn = z();
        di.dest = &dest;
        let mut co: ConnOut = z();
        assert_eq!(
            call(ops().dial, o.instance, &mut di, &mut co, slot::DIAL),
            Outcome::Ready
        );
        Self {
            inst: o.instance,
            _tables: tables,
            conn: co.conn,
        }
    }

    fn read(&self, cap: usize) -> (Outcome, Vec<u8>, bool, String) {
        let mut buf = vec![0_u8; cap];
        let mut i: ReadIn = z();
        i.conn = self.conn;
        i.buf = buf.as_mut_ptr();
        i.cap = cap;
        let mut o: IoOut = z();
        let r = call(ops().read, self.inst, &mut i, &mut o, slot::READ);
        buf.truncate(o.len as usize);
        (r, buf, o.flags & READ_END_OF_FRAME != 0, text(o.head.error))
    }

    fn write(&self, bytes: &[u8], end: bool) -> (Outcome, String) {
        let mut i: WriteIn = z();
        i.conn = self.conn;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.flags = if end { WRITE_END_OF_FRAME } else { 0 };
        let mut o: IoOut = z();
        let r = call(ops().write, self.inst, &mut i, &mut o, slot::WRITE);
        (r, text(o.head.error))
    }
}

// ── the tests ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_tail_is_a_carrier_composing_over_nothing() {
    // SAFETY: the Statement's kind tail is this crate's `'static` `TransportTail`.
    let tail = unsafe { &*STATEMENT.kind_tail.cast::<TransportTail>() };
    assert_eq!(tail.role, ROLE_CARRIER);
    assert_eq!(tail.composes_over_len, 0);
    assert_eq!(check_tail(tail), Ok(()));
}

#[test]
fn a_dial_spawns_exactly_the_program_it_is_lent() {
    let _one = ONE.lock().unwrap();
    let _h = Host::new(Vec::new());
    with(|sc| {
        assert_eq!(
            sc.spawned,
            [("/usr/bin/server".to_owned(), vec!["--stdio".to_owned()])]
        );
    });
}

#[test]
fn each_line_is_one_frame_whatever_the_reads_cut() {
    let _one = ONE.lock().unwrap();
    let h = Host::new(vec![
        Some(b"{\"a\":".to_vec()),
        None,
        Some(b"1}\r\n\nsecond".to_vec()),
        Some(b" line\nlast".to_vec()),
        Some(Vec::new()),
    ]);
    // Half a line, then nothing ready: PENDING, nothing moved.
    assert_eq!(h.read(64).0, Outcome::Pending);
    assert_eq!(
        h.read(64),
        (Outcome::Ready, b"{\"a\":1}".to_vec(), true, String::new())
    );
    // A blank line is an empty frame.
    assert_eq!(
        h.read(64),
        (Outcome::Ready, Vec::new(), true, String::new())
    );
    // A line longer than the host's buffer comes in several reads; the last carries the frame.
    assert_eq!(
        h.read(4),
        (Outcome::Ready, b"seco".to_vec(), false, String::new())
    );
    assert_eq!(
        h.read(64),
        (Outcome::Ready, b"nd line".to_vec(), true, String::new())
    );
    // The final unterminated line is a frame at the end, then the clean end.
    assert_eq!(
        h.read(64),
        (Outcome::Ready, b"last".to_vec(), true, String::new())
    );
    assert_eq!(
        h.read(64),
        (Outcome::Ready, Vec::new(), false, String::new())
    );
}

#[test]
fn a_line_past_the_ceiling_fails_the_read() {
    let _one = ONE.lock().unwrap();
    let long = vec![b'x'; MAX_LINE_BYTES + 1];
    let mut reads: Vec<Option<Vec<u8>>> =
        long.chunks(16 * 1024).map(|c| Some(c.to_vec())).collect();
    reads.push(None);
    let h = Host::new(reads);
    let (r, _, _, why) = h.read(64);
    assert_eq!((r, why.as_str()), (Outcome::Failed, TOO_LONG));
}

#[test]
fn a_frame_goes_out_as_one_line_and_one_that_cannot_be_one_is_refused() {
    let _one = ONE.lock().unwrap();
    let h = Host::new(Vec::new());
    assert_eq!(h.write(b"{\"id\":", false).0, Outcome::Ready);
    with(|sc| {
        assert!(
            sc.written.is_empty(),
            "nothing leaves before the frame ends"
        )
    });
    assert_eq!(h.write(b"1}", true).0, Outcome::Ready);
    assert_eq!(h.write(b"", true).0, Outcome::Ready);
    with(|sc| assert_eq!(sc.written, b"{\"id\":1}\n\n"));
    assert_eq!(
        h.write(b"two\nlines", true),
        (Outcome::Failed, NOT_ONE_LINE.to_owned())
    );
    assert_eq!(
        h.write(b"a return\r", true),
        (Outcome::Failed, NOT_ONE_LINE.to_owned())
    );
    with(|sc| {
        assert_eq!(
            sc.written, b"{\"id\":1}\n\n",
            "a refused frame writes nothing"
        )
    });
    let mut i: ConnIn = z();
    i.conn = h.conn;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().flush, h.inst, &mut i, &mut o, slot::FLUSH),
        Outcome::Ready
    );
}

#[test]
fn shut_closes_the_program_and_an_authority_or_a_listen_is_refused() {
    let _one = ONE.lock().unwrap();
    let h = Host::new(Vec::new());
    let mut i: ShutIn = z();
    i.conn = h.conn;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().shut, h.inst, &mut i, &mut o, slot::SHUT),
        Outcome::Ready
    );
    with(|sc| assert_eq!(sc.closed, [7]));
    assert_eq!(
        call(ops().shut, h.inst, &mut i, &mut o, slot::SHUT),
        Outcome::Ready
    );

    let mut dest: Destination = z();
    dest.kind = DEST_AUTHORITY;
    dest.authority = s("127.0.0.1:1");
    let mut di: DialIn = z();
    di.dest = &dest;
    let mut co: ConnOut = z();
    assert_eq!(
        call(ops().dial, h.inst, &mut di, &mut co, slot::DIAL),
        Outcome::Refused
    );
    let mut li: ListenIn = z();
    let mut lo: ListenOut = z();
    assert_eq!(
        call(ops().listen, h.inst, &mut li, &mut lo, slot::LISTEN),
        Outcome::Refused
    );
}
