// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TABLE'S RETENTION ACROSS A RACING CLOSE, and the out-slot preflight (B3-C04, B3-C03).

use super::*;
use crate::conn::ConnSlab;
use crate::transport::wire::CertFacts;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const NEED: NeedId = NeedId(0);
const LONG: Duration = Duration::from_secs(10);
/// What an out-slot holds before the call: a value no success answer writes.
const UNWRITTEN: u32 = 0x00BA_D5EE;

type Gate = (mpsc::Sender<()>, mpsc::Receiver<()>);

/// A backend that counts its effects, can be parked after building an answer, can fail or panic
/// once, can answer `close` with a scripted refusal, and can close a connection through the raw
/// slot from inside its own `read`.
#[derive(Default)]
struct Backend {
    slab: ConnSlab<()>,
    opens: AtomicUsize,
    writes: AtomicUsize,
    waits: AtomicUsize,
    reads: AtomicUsize,
    facts_calls: AtomicUsize,
    namespace: Mutex<Option<String>>,
    facts: Mutex<ConnFacts>,
    read_gate: Mutex<Option<Gate>>,
    facts_gate: Mutex<Option<Gate>>,
    fail: Mutex<Option<ConnError>>,
    panic_next: AtomicBool,
    close_as: Mutex<Option<ConnError>>,
    reenter: Mutex<Option<(usize, ConnId)>>,
    reentered: Mutex<Option<Result<(), ConnError>>>,
}

/// The gate, if one is armed, taken OUT of its mutex before anyone waits on it (so an overlapping

fn park(gate: &Mutex<Option<Gate>>) {
    let armed = gate.lock().unwrap().take();
    if let Some((entered, release)) = armed {
        entered.send(()).unwrap();
        let _ = release.recv();
    }
}

impl Conns for Backend {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        _: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.slab.insert(caller, need, ())
    }
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.slab.get(caller, conn)?;
        Ok(bytes.len())
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: Ticket,
        _: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let failing = self.fail.lock().unwrap().take();
        if let Some(error) = failing {
            return Err(error);
        }
        self.slab.get(caller, conn)?;
        if self.panic_next.swap(false, Ordering::SeqCst) {
            panic!("the backend's read panicked");
        }
        let piece = Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: 0,
            end: true,
            status: None,
            status_code: None,
            status_namespace: self.namespace.lock().unwrap().clone(),
            retry_after_secs: None,
            declared_len: None,
            fault: None,
            reason: None,
        };
        let reentrant = self.reenter.lock().unwrap().take();
        if let Some((addr, id)) = reentrant {
            let ctx = ConnCtx {
                ptr: addr as *mut c_void,
            };
            *self.reentered.lock().unwrap() = Some(close_slot(ctx, id));
        }
        park(&self.read_gate);
        Ok(piece)
    }
    fn wait(&self, caller: InstanceId, set: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        self.waits.fetch_add(1, Ordering::SeqCst);
        for conn in set {
            self.slab.get(caller, *conn)?;
        }
        Ok(0)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.facts_calls.fetch_add(1, Ordering::SeqCst);
        let failing = self.fail.lock().unwrap().take();
        if let Some(error) = failing {
            return Err(error);
        }
        self.slab.get(caller, conn)?;
        if self.panic_next.swap(false, Ordering::SeqCst) {
            panic!("the backend's facts panicked");
        }
        let answer = self.facts.lock().unwrap().clone();
        park(&self.facts_gate);
        Ok(answer)
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let scripted = *self.close_as.lock().unwrap();
        if let Some(error) = scripted {
            return Err(error);
        }
        self.slab.remove(caller, conn).map(|_| ())
    }
}

/// A backend for instances 1 and 2 and a boxed host for each.
fn rig() -> (Arc<Backend>, Box<ConnHost>, Box<ConnHost>) {
    let backend = Arc::new(Backend::default());
    backend.slab.declare(InstanceId(1), NEED);
    backend.slab.declare(InstanceId(2), NEED);
    let conns: Arc<dyn Conns> = backend.clone();
    (
        backend,
        Box::new(ConnHost::new(Arc::clone(&conns), InstanceId(1))),
        Box::new(ConnHost::new(conns, InstanceId(2))),
    )
}

/// A connection the instance behind `host` opened, through the raw `open` slot.
fn open_conn(host: &ConnHost) -> ConnId {
    let mut conn = 0_u64;
    assert_eq!(
        open_slot(host.ctx(), &descriptor(), &mut conn),
        Ok(()),
        "the backend opens"
    );
    ConnId(conn)
}

fn descriptor() -> WireOpenDesc {
    WireOpenDesc {
        size: core::mem::size_of::<WireOpenDesc>() as u32,
        _reserved: 0,
        target: DeclStr::new("scripted.test"),
        fields: std::ptr::null(),
        fields_len: 0,
        body: std::ptr::null(),
        body_len: 0,
        timeout_ms: 0,
        method: DeclStr::NONE,
        head_target: DeclStr::NONE,
    }
}

fn open_slot(ctx: ConnCtx, desc: &WireOpenDesc, out: *mut u64) -> Result<(), ConnError> {
    // SAFETY: this private fixture keeps ctx/desc live; out is its exclusive initialized slot
    // or NULL, which this host rejects before opening anything.
    unsafe { (host_slots().open.unwrap())(ctx, NEED.0, desc, out) }.result()
}

fn write_slot(ctx: ConnCtx, conn: ConnId, out: *mut usize) -> Result<(), ConnError> {
    let bytes = b"x";
    // SAFETY: ctx stays live, bytes is immutable, and out is exclusive or intentionally NULL
    // for this host's rejection path. The host validates numeric conn.
    unsafe { (host_slots().write.unwrap())(ctx, conn.0, bytes.as_ptr(), bytes.len(), 0, out) }
        .result()
}

fn wait_slot(ctx: ConnCtx, conn: ConnId, out: *mut usize) -> Result<(), ConnError> {
    let set = [conn.0];
    // SAFETY: ctx/set stay live; out is exclusive or NULL for this host's rejection path.
    unsafe { (host_slots().wait.unwrap())(ctx, set.as_ptr(), set.len(), 0, out) }.result()
}

/// A piece slot holding a sentinel no success answer writes.
fn unwritten_piece() -> WirePiece {
    // SAFETY: an all-zero `WirePiece` is a valid out-slot (integers, NULL ranges).
    let mut piece: WirePiece = unsafe { core::mem::zeroed() };
    piece.size = UNWRITTEN;
    piece
}

fn read_slot(ctx: ConnCtx, conn: ConnId, out: *mut WirePiece) -> Result<(), ConnError> {
    let mut buf = [0_u8; 1];
    // SAFETY: ctx stays live and buf is exclusive; out is an initialized exclusive piece or
    // NULL, rejected by this host before any backend operation.
    unsafe { (host_slots().read.unwrap())(ctx, conn.0, 0, buf.as_mut_ptr(), buf.len(), out) }
        .result()
}

/// A facts slot holding a sentinel no success answer writes.
fn unwritten_facts() -> WireConnFacts {
    // SAFETY: an all-zero `WireConnFacts` is a valid out-slot (integers, NULL ranges).
    let mut facts: WireConnFacts = unsafe { core::mem::zeroed() };
    facts.size = UNWRITTEN;
    facts
}

fn facts_slot(ctx: ConnCtx, conn: ConnId, out: *mut WireConnFacts) -> Result<(), ConnError> {
    // SAFETY: ctx stays live; out is initialized/exclusive or NULL for this host's rejection.
    unsafe { (host_slots().facts.unwrap())(ctx, conn.0, out) }.result()
}

fn close_slot(ctx: ConnCtx, conn: ConnId) -> Result<(), ConnError> {
    // SAFETY: this fixture keeps ctx live; the host validates numeric conn.
    unsafe { (host_slots().close.unwrap())(ctx, conn.0) }.result()
}

/// How many connections the host's table holds an entry for (scaffolding included).
fn entries(host: &ConnHost) -> usize {
    host.state.held().len()
}

/// A copy of the string the connection's retention CURRENTLY owns at exactly `d`'s address and

fn owner(host: &ConnHost, conn: ConnId, d: DeclStr) -> Option<String> {
    host.state.held().get(&conn).and_then(|held| {
        held.retention
            .iter()
            .find(|s| s.as_ptr() == d.ptr && s.len() == d.len)
            .cloned()
    })
}

/// A successful answer on a fresh connection of `host`: the numbering and the sni are published and

fn assert_a_fresh_connection_serves(backend: &Backend, host: &ConnHost) {
    *backend.namespace.lock().unwrap() = Some("fresh-numbering".into());
    *backend.facts.lock().unwrap() = ConnFacts {
        sni: Some("fresh.sni.test".into()),
        ..ConnFacts::default()
    };
    let fresh = open_conn(host);
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(host.ctx(), fresh, &mut piece), Ok(()));
    assert_eq!(
        owner(host, fresh, piece.ns).as_deref(),
        Some("fresh-numbering")
    );
    let mut facts = unwritten_facts();
    assert_eq!(facts_slot(host.ctx(), fresh, &mut facts), Ok(()));
    assert_eq!(
        owner(host, fresh, facts.sni).as_deref(),
        Some("fresh.sni.test")
    );
    assert_eq!(close_slot(host.ctx(), fresh), Ok(()));
    assert_eq!(entries(host), 0);
}

/// RED before the epoch: the read's backend answered `Ok` and was parked with its answer built; the

#[test]
fn a_read_resumed_after_a_raw_close_answers_closed_publishes_nothing_and_keeps_nothing() {
    let (backend, a, _b) = rig();
    let conn = open_conn(&a);
    *backend.namespace.lock().unwrap() = Some("late-numbering".into());
    let (entered_tx, entered) = mpsc::channel();
    let (release, held_back) = mpsc::channel();
    *backend.read_gate.lock().unwrap() = Some((entered_tx, held_back));
    let addr = a.ctx().ptr as usize;

    let (answer, marker) = std::thread::scope(|scope| {
        let release = release;
        let reader = scope.spawn(move || {
            let ctx = ConnCtx {
                ptr: addr as *mut c_void,
            };
            let mut piece = unwritten_piece();
            let answer = read_slot(ctx, conn, &mut piece);
            (answer, piece.size)
        });
        entered
            .recv_timeout(LONG)
            .expect("the backend answered and parked");
        assert_eq!(entries(&a), 1, "the operation's epoch is the table's");
        assert_eq!(close_slot(a.ctx(), conn), Ok(()));
        assert_eq!(entries(&a), 0, "the close retired the entry");
        release.send(()).unwrap();
        reader.join().unwrap()
    });

    assert_eq!(answer, Err(ConnError::Closed));
    assert_eq!(marker, UNWRITTEN, "a success out-slot was published");
    assert_eq!(entries(&a), 0, "the late read recreated a retention");
    assert_a_fresh_connection_serves(&backend, &a);
}

/// The same race for `facts`: the six strings are neither interned nor published after the close.
#[test]
fn a_facts_resumed_after_a_raw_close_answers_closed_publishes_nothing_and_keeps_nothing() {
    let (backend, a, _b) = rig();
    let conn = open_conn(&a);
    *backend.facts.lock().unwrap() = ConnFacts {
        sni: Some("late.sni.test".into()),
        alpn: Some("h2".into()),
        peer_cert: Some(CertFacts {
            subject: "CN=late".into(),
            issuer: "CN=issuer".into(),
            fingerprint: "sha256:late".into(),
        }),
        claim: Some("late-claim".into()),
        ..ConnFacts::default()
    };
    let (entered_tx, entered) = mpsc::channel();
    let (release, held_back) = mpsc::channel();
    *backend.facts_gate.lock().unwrap() = Some((entered_tx, held_back));
    let addr = a.ctx().ptr as usize;

    let (answer, marker) = std::thread::scope(|scope| {
        let release = release;
        let asker = scope.spawn(move || {
            let ctx = ConnCtx {
                ptr: addr as *mut c_void,
            };
            let mut facts = unwritten_facts();
            let answer = facts_slot(ctx, conn, &mut facts);
            (answer, facts.size)
        });
        entered
            .recv_timeout(LONG)
            .expect("the backend answered and parked");
        assert_eq!(entries(&a), 1);
        assert_eq!(close_slot(a.ctx(), conn), Ok(()));
        assert_eq!(entries(&a), 0);
        release.send(()).unwrap();
        asker.join().unwrap()
    });

    assert_eq!(answer, Err(ConnError::Closed));
    assert_eq!(marker, UNWRITTEN, "a success out-slot was published");
    assert_eq!(entries(&a), 0, "the late facts recreated a retention");
    assert_a_fresh_connection_serves(&backend, &a);
}

/// A reentrant backend (its `read` closes the very connection through the raw slot, from inside the

#[test]
fn a_backend_that_closes_through_the_raw_slot_while_reading_does_not_deadlock() {
    let (backend, a, _b) = rig();
    let conn = open_conn(&a);
    *backend.namespace.lock().unwrap() = Some("reentrant-numbering".into());

    let addr = a.ctx().ptr as usize;
    *backend.reenter.lock().unwrap() = Some((addr, conn));
    let (done_tx, done) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut piece = unwritten_piece();
        let answer = read_slot(a.ctx(), conn, &mut piece);

        let _ = done_tx.send((answer, piece.size, a));
    });
    let (answer, marker, a) = done
        .recv_timeout(LONG)
        .expect("a backend that re-enters a slot deadlocked against a host lock");
    worker.join().expect("the worker finished its read");
    assert_eq!(*backend.reentered.lock().unwrap(), Some(Ok(())));
    assert_eq!(answer, Err(ConnError::Closed));
    assert_eq!(marker, UNWRITTEN);
    assert_eq!(entries(&a), 0);
}

/// Overlapping operations that publish nothing cannot prune the entry the other still needs: A is

#[test]
fn overlapping_empty_operations_cannot_prune_a_shared_active_epoch() {
    let (backend, a, _b) = rig();
    let conn = open_conn(&a);
    *backend.namespace.lock().unwrap() = None;
    let (entered_tx, entered) = mpsc::channel();
    let (release, held_back) = mpsc::channel();
    *backend.read_gate.lock().unwrap() = Some((entered_tx, held_back));
    let addr = a.ctx().ptr as usize;

    let (answer, marker) = std::thread::scope(|scope| {
        let release = release;
        let parked = scope.spawn(move || {
            let ctx = ConnCtx {
                ptr: addr as *mut c_void,
            };
            let mut piece = unwritten_piece();
            let answer = read_slot(ctx, conn, &mut piece);
            (answer, piece.size)
        });
        entered.recv_timeout(LONG).expect("A parked in its backend");
        assert_eq!(entries(&a), 1);

        let mut piece = unwritten_piece();
        assert_eq!(read_slot(a.ctx(), conn, &mut piece), Ok(()));
        assert_ne!(piece.size, UNWRITTEN, "B's read published its answer");
        assert_eq!(entries(&a), 1, "B pruned the entry A still needs");
        let mut facts = unwritten_facts();
        assert_eq!(facts_slot(a.ctx(), conn, &mut facts), Ok(()));
        assert_eq!(entries(&a), 1, "B's facts pruned the entry A still needs");

        release.send(()).unwrap();
        parked.join().unwrap()
    });

    assert_eq!(
        answer,
        Ok(()),
        "A lost its epoch to an overlapping operation"
    );
    assert_ne!(marker, UNWRITTEN, "A's answer was not published");
    assert_eq!(entries(&a), 0, "the last operation left its scaffolding");
}

/// Every way an operation can end without publishing prunes its entry: each error, a panic in the

#[test]
fn the_last_operation_prunes_its_empty_entry_on_every_outcome_that_publishes_nothing() {
    let (backend, a, b) = rig();
    let conn = open_conn(&a);

    for error in [
        ConnError::Pending,
        ConnError::Fault,
        ConnError::Closed,
        ConnError::Timeout,
    ] {
        *backend.fail.lock().unwrap() = Some(error);
        let mut piece = unwritten_piece();
        assert_eq!(read_slot(a.ctx(), conn, &mut piece), Err(error));
        assert_eq!(piece.size, UNWRITTEN);
        assert_eq!(entries(&a), 0, "a read that ended {error:?} left an entry");

        *backend.fail.lock().unwrap() = Some(error);
        let mut facts = unwritten_facts();
        assert_eq!(facts_slot(a.ctx(), conn, &mut facts), Err(error));
        assert_eq!(facts.size, UNWRITTEN);
        assert_eq!(entries(&a), 0, "a facts that ended {error:?} left an entry");
    }

    backend.panic_next.store(true, Ordering::SeqCst);
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(a.ctx(), conn, &mut piece), Err(ConnError::Fault));
    assert_eq!(entries(&a), 0, "a panicking read left an entry");
    backend.panic_next.store(true, Ordering::SeqCst);
    let mut facts = unwritten_facts();
    assert_eq!(facts_slot(a.ctx(), conn, &mut facts), Err(ConnError::Fault));
    assert_eq!(entries(&a), 0, "a panicking facts left an entry");

    let mut piece = unwritten_piece();
    assert_eq!(
        read_slot(b.ctx(), conn, &mut piece),
        Err(ConnError::NotOwner)
    );
    let mut facts = unwritten_facts();
    assert_eq!(
        facts_slot(b.ctx(), conn, &mut facts),
        Err(ConnError::NotOwner)
    );
    assert_eq!(entries(&b), 0);

    *backend.namespace.lock().unwrap() = None;
    *backend.facts.lock().unwrap() = ConnFacts::default();
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(a.ctx(), conn, &mut piece), Ok(()));
    assert!(piece.ns.ptr.is_null() && piece.ns.len == 0);
    let mut facts = unwritten_facts();
    assert_eq!(facts_slot(a.ctx(), conn, &mut facts), Ok(()));
    assert!(facts.sni.ptr.is_null() && facts.claim.ptr.is_null());
    assert_eq!(entries(&a), 0, "absent answers left an entry");

    assert_eq!(close_slot(a.ctx(), conn), Ok(()));
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(a.ctx(), conn, &mut piece), Err(ConnError::Closed));
    let mut facts = unwritten_facts();
    assert_eq!(
        facts_slot(a.ctx(), conn, &mut facts),
        Err(ConnError::Closed)
    );
    assert_eq!(entries(&a), 0);
}

/// `close` ends the borrows on success or `Closed` and on nothing else: another instance's close

#[test]
fn only_success_or_closed_retires_and_the_backends_outcome_is_what_the_plugin_is_told() {
    let (backend, a, b) = rig();
    let conn = open_conn(&a);
    *backend.namespace.lock().unwrap() = Some("kept-numbering".into());
    *backend.facts.lock().unwrap() = ConnFacts {
        sni: Some("kept.sni.test".into()),
        ..ConnFacts::default()
    };
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(a.ctx(), conn, &mut piece), Ok(()));
    let mut facts = unwritten_facts();
    assert_eq!(facts_slot(a.ctx(), conn, &mut facts), Ok(()));
    let still_owned = |expected: &str, d: DeclStr| {
        assert_eq!(owner(&a, conn, d).as_deref(), Some(expected));
    };
    still_owned("kept-numbering", piece.ns);
    still_owned("kept.sni.test", facts.sni);

    assert_eq!(close_slot(b.ctx(), conn), Err(ConnError::NotOwner));
    still_owned("kept-numbering", piece.ns);
    still_owned("kept.sni.test", facts.sni);

    *backend.close_as.lock().unwrap() = Some(ConnError::Fault);
    assert_eq!(close_slot(a.ctx(), conn), Err(ConnError::Fault));
    still_owned("kept-numbering", piece.ns);
    still_owned("kept.sni.test", facts.sni);

    *backend.close_as.lock().unwrap() = Some(ConnError::Closed);
    assert_eq!(close_slot(a.ctx(), conn), Err(ConnError::Closed));
    assert_eq!(entries(&a), 0, "a backend Closed left the retention behind");
    *backend.close_as.lock().unwrap() = None;
}

/// Each of `open`/`write`/`wait`/`facts` given a NULL required out-slot answers Fault BEFORE the

#[test]
fn a_null_out_slot_faults_before_any_backend_effect_and_valid_calls_still_work() {
    let (backend, a, _b) = rig();
    let conn = open_conn(&a);
    let ctx = a.ctx();
    assert_eq!(backend.opens.load(Ordering::SeqCst), 1);

    assert_eq!(
        open_slot(ctx, &descriptor(), std::ptr::null_mut()),
        Err(ConnError::Fault)
    );
    assert_eq!(
        backend.opens.load(Ordering::SeqCst),
        1,
        "a connection was opened"
    );

    assert_eq!(
        write_slot(ctx, conn, std::ptr::null_mut()),
        Err(ConnError::Fault)
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0, "a byte was taken");

    assert_eq!(
        wait_slot(ctx, conn, std::ptr::null_mut()),
        Err(ConnError::Fault)
    );
    assert_eq!(
        backend.waits.load(Ordering::SeqCst),
        0,
        "interest was registered"
    );

    assert_eq!(
        facts_slot(ctx, conn, std::ptr::null_mut()),
        Err(ConnError::Fault)
    );
    assert_eq!(
        backend.facts_calls.load(Ordering::SeqCst),
        0,
        "facts were asked for"
    );
    assert_eq!(entries(&a), 0, "a held entry was made for a refused call");

    assert_eq!(
        read_slot(ctx, conn, std::ptr::null_mut()),
        Err(ConnError::Fault),
        "the read control"
    );
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
    assert_eq!(entries(&a), 0);

    let mut opened = 0_u64;
    assert_eq!(open_slot(ctx, &descriptor(), &mut opened), Ok(()));
    assert_eq!(backend.opens.load(Ordering::SeqCst), 2);
    let mut written = 0_usize;
    assert_eq!(write_slot(ctx, conn, &mut written), Ok(()));
    assert_eq!((written, backend.writes.load(Ordering::SeqCst)), (1, 1));
    let mut ready = usize::MAX;
    assert_eq!(wait_slot(ctx, conn, &mut ready), Ok(()));
    assert_eq!((ready, backend.waits.load(Ordering::SeqCst)), (0, 1));
    let mut facts = unwritten_facts();
    assert_eq!(facts_slot(ctx, conn, &mut facts), Ok(()));
    assert_ne!(facts.size, UNWRITTEN);
    assert_eq!(backend.facts_calls.load(Ordering::SeqCst), 1);
    let mut piece = unwritten_piece();
    assert_eq!(read_slot(ctx, conn, &mut piece), Ok(()));
    assert_ne!(piece.size, UNWRITTEN);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(entries(&a), 0, "valid absent answers left an entry");
}
