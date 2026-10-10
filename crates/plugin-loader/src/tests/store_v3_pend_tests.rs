// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE THAT PENDS (the store SDK's `Step`/`Op`; REVIEWER and ARCHITECT, binding): an op that
//! pends once and resumes answers what the same op answers inline; a reserve cancelled after its
//! write went out and retried with the SAME `op_id` answers the grants it applied, counted once; a
//! RESUME with nothing parked is FAULT, never a fresh run; PENDING on the connector with no service
//! in flight is FAULT.

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpResult, ReserveRefused, Scanned, Step,
    StoreSlots,
};
use busbar_contract::abi::store::{OpId, U64In};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta,
};
use busbar_contract::store_calls::StoreCalls;

use crate::both_ways::store_fixture::MemoryStore;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::wrap::{Hooks, Wrapped};
use crate::store_v3::LoadedStore;

fn now_ns() -> u64 {
    crate::dispatch::now_ns()
}

/// What a pend-once op keeps across its PENDING turn.
struct Kept<T>(T);

/// Pend once, keeping `answer`, then answer it on the RESUME: the op's result is computed in its
/// first entry (the write went out), and the resume only hands it back.
fn pend_once<T: Send + Sync + 'static>(
    cx: &mut Op<'_>,
    answer: impl FnOnce() -> T,
    wake_in_ns: u64,
) -> Step<T> {
    if let Some(Kept(t)) = cx.resume::<Kept<T>>() {
        return Step::Ready(t);
    }
    let t = answer();
    if !cx.can_pend() {
        return Step::Ready(t);
    }
    cx.park(Kept(t));
    Step::Pending {
        wake_at_ns: now_ns().saturating_add(wake_in_ns),
    }
}

/// The ops these tests compare, each pending once (1 ms) before answering.
struct PendsOnce;

impl Hooks for PendsOnce {
    fn reserve<'c>(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let mut d = Op::detached();
        let kept = pend_once(
            cx,
            || {
                let mut g = Vec::new();
                ready(<MemoryStore as StoreSlots>::reserve(
                    inner, &mut d, op, epoch, cells, &mut g,
                ))
                .map(|()| g)
            },
            1_000_000,
        );
        handed_back(kept, grants)
    }
    fn slice_release(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        let mut d = Op::detached();
        let kept = pend_once(
            cx,
            || {
                let mut r = Vec::new();
                ready(<MemoryStore as StoreSlots>::slice_release(
                    inner, &mut d, op, epoch, items, &mut r,
                ))
                .map(|()| r)
            },
            1_000_000,
        );
        handed_back(kept, released)
    }
    fn add_usage_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let mut d = Op::detached();
        pend_once(
            cx,
            || {
                ready(<MemoryStore as StoreSlots>::add_usage_batch(
                    inner, &mut d, op, cells,
                ))
            },
            1_000_000,
        )
    }
    fn window_caps(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        let mut d = Op::detached();
        pend_once(
            cx,
            || {
                ready(<MemoryStore as StoreSlots>::window_caps(
                    inner, &mut d, op, caps,
                ))
            },
            1_000_000,
        )
    }
    fn record_scan(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        let mut d = Op::detached();
        pend_once(
            cx,
            || {
                ready(<MemoryStore as StoreSlots>::record_scan(
                    inner, &mut d, schema, prefix, limit,
                ))
            },
            1_000_000,
        )
    }
    fn list_plane_records(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<busbar_contract::records::RecordStoreResult<Vec<Vec<u8>>>> {
        let mut d = Op::detached();
        pend_once(
            cx,
            || {
                ready(<MemoryStore as StoreSlots>::list_plane_records(
                    inner, &mut d, kind, selector,
                ))
            },
            1_000_000,
        )
    }
    fn sessions_for(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        let mut d = Op::detached();
        pend_once(
            cx,
            || {
                ready(<MemoryStore as StoreSlots>::sessions_for(
                    inner, &mut d, principal,
                ))
            },
            1_000_000,
        )
    }
}

/// A kept answer's items written into the host's array, on `Ok`; the step as it was otherwise.
fn handed_back<T, E>(
    step: Step<Result<Vec<T>, E>>,
    into: &mut impl Extend<T>,
) -> Step<Result<(), E>> {
    match step {
        Step::Ready(r) => Step::Ready(r.map(|items| into.extend(items))),
        Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
    }
}

fn ready<T>(s: Step<T>) -> T {
    match s {
        Step::Ready(t) => t,
        Step::Pending { .. } => panic!("the memory store never pends"),
    }
}

/// The reserve a cancel cuts off after its write went out: it applies on its first entry, then
/// pends for long (a remote store waiting on its commit's answer). Its first retry of an `op_id`
/// is answered at once, from the store's dedupe.
struct CommitsThenPends;

static PENDED: Mutex<Option<HashSet<OpId>>> = Mutex::new(None);

impl Hooks for CommitsThenPends {
    fn reserve<'c>(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let mut d = Op::detached();
        let mut g = Vec::new();
        let answer = ready(<MemoryStore as StoreSlots>::reserve(
            inner, &mut d, op, epoch, cells, &mut g,
        ))
        .map(|()| g);
        let mut pended = PENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only the draw the test cancels (epoch 99) pends, and only its first attempt.
        if epoch == 99 && pended.get_or_insert_with(HashSet::new).insert(op) && cx.can_pend() {
            cx.park(Kept(answer));
            return Step::Pending {
                wake_at_ns: now_ns().saturating_add(60_000_000_000),
            };
        }
        handed_back(Step::Ready(answer), grants)
    }
}

/// Pends on the connector with no service made (`session_remove`), which nothing would wake.
struct PendsOnNothing;

impl Hooks for PendsOnNothing {
    fn session_remove(_: &MemoryStore, _: &mut Op<'_>, _: u64) -> Step<Result<(), String>> {
        Step::Pending { wake_at_ns: 0 }
    }
}

mod pends_once {
    busbar_contract::store_door!(super::Wrapped<super::PendsOnce>, "pends-once", "0", 64);
}
mod commits_then_pends {
    busbar_contract::store_door!(
        super::Wrapped<super::CommitsThenPends>,
        "commits-then-pends",
        "0",
        64
    );
}
mod pends_on_nothing {
    busbar_contract::store_door!(
        super::Wrapped<super::PendsOnNothing>,
        "pends-on-nothing",
        "0",
        64
    );
}

pub(super) fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x9e4d,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn open(door: busbar_contract::abi::mechanism::door::DoorFn) -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the door loads");
    LoadedStore::open(p, d, b"{}", mint).expect("it opens")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn key(bucket: &str) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 1_790_000_000_000,
    }
}

fn plane(id: &str, parent: Option<&str>, seq: u64) -> PlaneRecord {
    PlaneRecord {
        kind: "ev".into(),
        id: id.into(),
        parent: parent.map(str::to_owned),
        seq,
        ts: 7,
        disposition: PlaneDisposition::Active,
        body: vec![b'x'],
    }
}

/// One store's answers to the compared ops, over the same writes.
fn transcript(s: &LoadedStore) -> String {
    rt().block_on(async {
        s.window_caps(
            OpId::from_parts(7, 1),
            &[Cap {
                key: key("g"),
                cap: 10,
                config_gen: 1,
            }],
        )
        .await
        .expect("caps");
        let grants = s
            .reserve(
                OpId::from_parts(7, 2),
                0,
                &[Cell {
                    key: key("g"),
                    amount: 3,
                }],
            )
            .await;
        s.record_put(
            "sch",
            b"a/1",
            &RecordBytes::new(b"one".to_vec()).expect("record"),
        )
        .await
        .expect("put");
        let scan = s.record_scan("sch", b"a/", 10).await;
        let (t, e) = (plane("t", None, 0), plane("e", Some("t"), 1));
        StoreCalls::upsert_plane_record(s, t.view())
            .await
            .expect("upsert");
        StoreCalls::append_plane_record(s, OpId::from_parts(7, 3), e.view())
            .await
            .expect("append");
        let listed =
            StoreCalls::list_plane_records(s, "ev", &PlaneSelector::Parent("t".into())).await;
        s.session_put(1, "n1", "alice").await.expect("session");
        let sessions = s.sessions_for("alice").await;
        // The money ops, pended the same way: a release, a usage batch and its replay.
        let released = match &grants {
            Ok(g) => s.slice_release(OpId::from_parts(7, 4), 0, &[(g[0].slice_id, 1)]).await,
            Err(e) => Err(e.clone()),
        };
        let cells = [(
            "k",
            60u64,
            UsageDelta {
                requests: 2,
                billable_requests: 2,
                models: Vec::new(),
            },
        )];
        let batch = s.add_usage_batch(OpId::from_parts(7, 5), &cells).await;
        let replay = s.add_usage_batch(OpId::from_parts(7, 5), &cells).await;
        let usage = RecordStore::get_usage(s, "k", 60).map(|u| u.requests);
        let after = s.reserve(OpId::from_parts(7, 6), 0, &[Cell { key: key("g"), amount: 8 }]).await;
        format!("{grants:?} | {scan:?} | {listed:?} | {sessions:?} | {released:?} | {batch:?} {replay:?} {usage:?} | {after:?}")
    })
}

#[test]
fn an_op_that_pends_and_resumes_answers_what_the_inline_op_answers() {
    let inline = transcript(&open(crate::both_ways::store_fixture::door));
    let pended = transcript(&open(pends_once::door));
    assert_eq!(pended, inline);
}

/// MONEY: a reserve cancelled after its write went out, retried with the SAME `op_id`, answers the
/// grants the first attempt applied, and the window counts them once.
#[test]
fn a_reserve_cancelled_after_its_write_retries_to_the_same_grants_counted_once() {
    let s = open(commits_then_pends::door);
    let rt = rt();
    let op = mint();
    let cells = [Cell {
        key: key("m"),
        amount: 4,
    }];
    let first = rt.block_on(async {
        s.window_caps(
            mint(),
            &[Cap {
                key: key("m"),
                cap: 10,
                config_gen: 1,
            }],
        )
        .await
        .expect("caps");
        tokio::time::timeout(Duration::from_millis(100), s.reserve(op, 99, &cells)).await
    });
    assert!(
        first.is_err(),
        "the first attempt pends until it is cancelled"
    );
    let retried = rt
        .block_on(s.reserve(op, 99, &cells))
        .expect("the retry of the same op_id answers");
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].granted, 4);
    // Counted once: 6 of the 10 are left, not 2.
    rt.block_on(async {
        s.reserve(
            mint(),
            0,
            &[Cell {
                key: key("m"),
                amount: 6,
            }],
        )
        .await
        .expect("6 are left: the retry drew nothing more");
        assert!(s
            .reserve(
                mint(),
                0,
                &[Cell {
                    key: key("m"),
                    amount: 1
                }]
            )
            .await
            .is_err());
    });
}

/// The raw door: its open, and a `session_remove` entry on `ticket` with `flags`.
fn raw_session_remove(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    ticket: Ticket,
    flags: u32,
) -> Outcome {
    // SAFETY: the SDK's `'static` door and its store table; every call passes the slot's own
    // `in`/`out` shapes, live for the call.
    unsafe {
        let d = &*door();
        let ops = &*d.ops.cast::<busbar_contract::abi::store::Ops>();
        let mut oi: OpenIn = std::mem::zeroed();
        oi.head = in_head();
        oi.head.size = std::mem::size_of::<OpenIn>() as u32;
        oi.head.op = busbar_contract::abi::mechanism::lifecycle::slot::OPEN;
        oi.settings = busbar_contract::abi::mechanism::call::Blob {
            ptr: b"{}".as_ptr(),
            len: 2,
            fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
            flags: 0,
        };
        oi.generation = 1;
        let mut oo: OpenOut = std::mem::zeroed();
        oo.head = out_head();
        oo.head.size = std::mem::size_of::<OpenOut>() as u32;
        let open = ops.head.open.expect("open");
        assert_eq!(
            open(
                std::ptr::null_mut(),
                std::ptr::from_ref(&oi).cast(),
                std::ptr::from_mut(&mut oo).cast()
            )
            .outcome(),
            Outcome::Ready
        );
        let instance: *mut c_void = oo.instance;
        let mut input = U64In {
            head: in_head(),
            value: 1,
        };
        input.head.size = std::mem::size_of::<U64In>() as u32;
        input.head.op = busbar_contract::abi::store::slot::SESSION_REMOVE;
        input.head.ticket = ticket;
        input.head.flags = flags;
        let mut out: OutHead = out_head();
        let call = ops.session_remove.expect("session_remove");
        call(
            instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
        .outcome()
    }
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

#[test]
fn a_resume_with_nothing_parked_is_fault_and_never_a_fresh_run() {
    assert_eq!(
        raw_session_remove(crate::both_ways::store_fixture::door, TICKET, FLAG_RESUME),
        Outcome::Fault
    );
    // The same op, fresh, runs.
    assert_eq!(
        raw_session_remove(crate::both_ways::store_fixture::door, TICKET, 0),
        Outcome::Ready
    );
}

#[test]
fn pending_on_the_connector_with_no_service_in_flight_is_fault() {
    assert_eq!(
        raw_session_remove(pends_on_nothing::door, TICKET, 0),
        Outcome::Fault
    );
}

// ── the governance bridge on a ticket (ARCHITECT ruling 2026-10-03 on Q-L14-1) ────────────────

/// A remote store's `list_denylist`: on a ticket it pends once (its round trip in flight) and
/// answers on the resume; on no ticket it cannot reach its backend at all, so it refuses.
struct RemoteDenylist;

impl Hooks for RemoteDenylist {
    fn list_denylist(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
    ) -> Step<busbar_contract::records::RecordStoreResult<Vec<String>>> {
        if !cx.can_pend() {
            return Step::Ready(Err(busbar_contract::records::RecordStoreError(
                "a remote store answers only on a ticket".into(),
            )));
        }
        let mut d = Op::detached();
        pend_once(
            cx,
            || ready(<MemoryStore as StoreSlots>::list_denylist(inner, &mut d)),
            1_000_000,
        )
    }
}

mod remote_denylist {
    busbar_contract::store_door!(
        super::Wrapped<super::RemoteDenylist>,
        "remote-denylist",
        "0",
        64
    );
}

/// RED (Q-L14-1 (a)): the kernel's governance store reaches every slot through the synchronous
/// bridge; a store that answers PENDING there and READY on its wake completes the op, as a
/// remote store's every round trip must.
#[test]
fn a_store_that_pends_then_answers_completes_a_governance_op_on_the_bridge() {
    let s = open(remote_denylist::door);
    RecordStore::add_denylist(&s, "alice", "test").expect("the denylist write");
    assert_eq!(
        RecordStore::list_denylist(&s).expect("the pended read completes"),
        vec!["alice".to_string()]
    );
}

/// THE HOST'S CONNECTION TABLE, as a store's needs reach it: it serves `tcp`, records each
/// declaration and each open.
#[derive(Default)]
struct Table {
    slab: busbar_contract::conn::ConnSlab<()>,
    declared: Mutex<Vec<(u32, String)>>,
    opened: Mutex<Vec<(u32, String)>>,
    /// Every open is refused (an unreachable backend).
    refuse: std::sync::atomic::AtomicBool,
    closed: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::conn::Conns for Table {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        if self.refuse.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(busbar_contract::conn::ConnError::Refused);
        }
        let id = self.slab.insert(caller, need, ())?;
        self.opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((need.0, desc.target.to_owned()));
        Ok(id)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        caller: busbar_contract::conn::InstanceId,
        conn: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.slab.remove(caller, conn).map(|_| ())
    }
}

impl busbar_contract::conn::DeclaredConns for Table {
    fn declare(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((need.0, spec.transport.clone()));
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "tcp"
    }
}

/// A store that reaches its backend over one `tcp` need: its `list_denylist` checks out the op's
/// one connection to the backend and answers what it got.
struct OverTcp;

impl Hooks for OverTcp {
    fn list_denylist(
        _: &MemoryStore,
        cx: &mut Op<'_>,
    ) -> Step<busbar_contract::records::RecordStoreResult<Vec<String>>> {
        let got = match cx.checkout(0, Some("db.internal:5432")) {
            std::task::Poll::Ready(Ok(stream)) => format!("stream {stream}"),
            std::task::Poll::Ready(Err(e)) => format!("refused: {e}"),
            std::task::Poll::Pending => "pending".to_string(),
        };
        Step::Ready(Ok(vec![got]))
    }
}

pub(super) const NO_TEXT: busbar_contract::abi::mechanism::call::AbiStr =
    busbar_contract::abi::mechanism::call::AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };

/// One outbound `tcp` need, its target named by the store.
pub(super) const TCP: &[busbar_contract::abi::host::conn::connector::Need] =
    &[busbar_contract::abi::host::conn::connector::Need {
        direction: busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: busbar_contract::abi::sdk::door::abi_str("tcp"),
        auth: NO_TEXT,
        target_from: NO_TEXT,
        trust_from: NO_TEXT,
        details: crate::dispatch::NO_BLOB,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }];

mod over_tcp {
    busbar_contract::store_door!(
        super::Wrapped<super::OverTcp>,
        "over-tcp",
        "0",
        64,
        needs: super::TCP
    );
}

/// RED (Q-L14-1 (b)): a store whose door declares a `tcp` need is handed the connector, its need
/// declared on the host's connection table, exactly as every other kind; its op on the bridge
/// checks out a stream there.
#[test]
fn a_store_declaring_a_tcp_need_receives_a_connector() {
    let table = Arc::new(Table::default());
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = table.clone();
    let p = load_linked::<Store>(
        &LinkedRow::of(over_tcp::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    let s = LoadedStore::open(p, d, b"{}", mint).expect("it opens");
    assert_eq!(
        *table.declared.lock().expect("declared"),
        vec![(0, "tcp".to_string())],
        "the need is declared on the host's table under its Statement index"
    );
    let got = RecordStore::list_denylist(&s).expect("the op answers");
    assert!(
        got.len() == 1 && got[0].starts_with("stream "),
        "the op checked out a stream over the connector: {got:?}"
    );
    assert_eq!(
        *table.opened.lock().expect("opened"),
        vec![(0, "db.internal:5432".to_string())]
    );
}

/// A store door with no needs states none: the Statement the base arm builds is unchanged.
#[test]
fn a_store_door_without_needs_states_none() {
    // SAFETY: the SDK's `'static` door and Statement.
    let st = unsafe { *(*remote_denylist::door()).statement };
    assert!(st.needs.is_null());
    assert_eq!(st.needs_len, 0);
    // SAFETY: as above.
    let st = unsafe { *(*over_tcp::door()).statement };
    assert_eq!(st.needs_len, 1);
}

// ── open on a ticket, with a connect step (ARCHITECT ruling 2026-10-03 on Q-L16-2) ────────────

/// How many times `PendsInOpen`'s `open` ran.
static PENDS_IN_OPEN_OPENS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// A store whose connect step pends once (its backend's first round trip in flight) and then
/// answers it reached the backend.
struct PendsInOpen;

impl Hooks for PendsInOpen {
    fn open(
        settings: &[u8],
        host: Option<busbar_contract::abi::sdk::conn::Host>,
    ) -> Result<Arc<MemoryStore>, String> {
        let _ = (settings, host);
        PENDS_IN_OPEN_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Arc::new(MemoryStore::new()))
    }
    fn connect(_: &MemoryStore, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        // A remote backend's round trip needs the ticket to pend on.
        if !cx.can_pend() {
            return Step::Ready(Err(
                "pends-in-open reaches its backend only on a ticket".into()
            ));
        }
        pend_once(cx, || Ok(()), 1_000_000)
    }
}

mod pends_in_open {
    busbar_contract::store_door!(super::Wrapped<super::PendsInOpen>, "pends-in-open", "0", 64);
}

/// RED (Q-L16-2): a store whose connect step PENDS in `open` completes its open (the boot's
/// store load) on the wake, `open` itself running once, and serves.
#[test]
fn a_store_pending_in_open_completes_the_load_and_serves() {
    let before = PENDS_IN_OPEN_OPENS.load(std::sync::atomic::Ordering::SeqCst);
    let s = open(pends_in_open::door);
    assert_eq!(
        PENDS_IN_OPEN_OPENS.load(std::sync::atomic::Ordering::SeqCst) - before,
        1,
        "the RESUME hands back the instance `open` answered; `open` runs once"
    );
    RecordStore::add_denylist(&s, "carol", "test").expect("the opened store serves");
    assert_eq!(
        RecordStore::list_denylist(&s).expect("it reads back"),
        vec!["carol".to_string()]
    );
}

/// A store whose connect step reaches its backend over its `tcp` need: a checkout at `open`.
struct ConnectsOverTcp;

impl Hooks for ConnectsOverTcp {
    fn connect(_: &MemoryStore, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        match cx.checkout(0, Some("db.internal:5432")) {
            std::task::Poll::Ready(Ok(_)) => Step::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => Step::Ready(Err(format!(
                "connects-over-tcp plugin: failed to connect to db.internal:5432: {e}"
            ))),
            std::task::Poll::Pending => Step::Pending { wake_at_ns: 0 },
        }
    }
}

mod connects_over_tcp {
    busbar_contract::store_door!(
        super::Wrapped<super::ConnectsOverTcp>,
        "connects-over-tcp",
        "0",
        64,
        needs: super::TCP
    );
}

/// `door` loaded over `table` (the host's connection table) and opened.
fn open_over(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    table: &Arc<Table>,
) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = table.clone();
    let p = load_linked::<Store>(
        &LinkedRow::of(door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    LoadedStore::open(p, d, b"{}", mint)
}

/// RED (Q-L16-2): the connect step reaches the backend over the host's connection table at `open`
/// (a ticketed open; a ticket-less one has no connector), and closes that connection when it
/// answers.
#[test]
fn a_store_connects_over_the_hosts_table_at_open() {
    let table = Arc::new(Table::default());
    let s = open_over(connects_over_tcp::door, &table).expect("the reachable backend opens");
    assert_eq!(
        *table.opened.lock().expect("opened"),
        vec![(0, "db.internal:5432".to_string())]
    );
    assert_eq!(
        table.closed.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the connect step's connection is closed when it answers"
    );
    RecordStore::add_denylist(&s, "dave", "test").expect("it serves");
}

/// RED (Q-L16-2): an unreachable backend fails the LOAD, at `open`, in the store's own words.
#[test]
fn an_unreachable_backend_fails_the_load_with_the_stores_message() {
    let table = Arc::new(Table::default());
    table
        .refuse
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let err = open_over(connects_over_tcp::door, &table).expect_err("the load fails");
    assert_eq!(
        err,
        format!(
            "plugin 'connects-over-tcp' open failed: connects-over-tcp plugin: failed to connect \
             to db.internal:5432: {}",
            busbar_contract::conn::ConnError::Refused.text()
        )
    );
}

// ── a store op's body as a future over its one raw connection (store SDK `wire`) ──────────────

/// A store whose `list_denylist` is a wire protocol: it connects to the backend its settings name
/// (`{"addr": ...}`), sends a line and answers the line the backend sends back.
struct OverWire;

static WIRE_ADDR: Mutex<String> = Mutex::new(String::new());

impl Hooks for OverWire {
    fn list_denylist(
        _: &MemoryStore,
        cx: &mut Op<'_>,
    ) -> Step<busbar_contract::records::RecordStoreResult<Vec<String>>> {
        use busbar_contract::abi::sdk::store::wire::{drive, Wire};
        let addr = WIRE_ADDR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        drive(cx, move |w: Wire| {
            Box::pin(async move {
                let err = |e: busbar_contract::abi::sdk::conn::ConnFailure| {
                    busbar_contract::records::RecordStoreError(format!("over-wire: {e}"))
                };
                w.connect(0, Some(&addr)).await.map_err(err)?;
                w.write_all(b"hello\n").await.map_err(err)?;
                loop {
                    if let Some(line) = w.input(|i| {
                        let at = i.iter().position(|b| *b == b'\n')?;
                        let line: Vec<u8> = i.drain(..=at).collect();
                        Some(String::from_utf8_lossy(&line[..at]).into_owned())
                    }) {
                        return Ok(vec![line]);
                    }
                    if w.fill().await.map_err(err)? == 0 {
                        return Err(busbar_contract::records::RecordStoreError(
                            "over-wire: the backend closed".into(),
                        ));
                    }
                }
            })
        })
    }
}

mod over_wire {
    busbar_contract::store_door!(
        super::Wrapped<super::OverWire>,
        "over-wire",
        "0",
        64,
        needs: super::TCP
    );
}

/// A backend that answers each line, after `delay`, as `echo <line>`, in two writes (so the op's
/// reads pend, and a reply arrives in pieces).
fn line_backend(delay: Duration) -> String {
    use std::io::{BufRead, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            std::thread::spawn(move || {
                let mut r = std::io::BufReader::new(s.try_clone().expect("clone"));
                let mut w = s;
                let mut line = String::new();
                while r.read_line(&mut line).is_ok_and(|n| n > 0) {
                    std::thread::sleep(delay);
                    let _ = w.write_all(b"echo ");
                    let _ = w.flush();
                    std::thread::sleep(delay);
                    let _ = w.write_all(format!("{}\n", line.trim_end()).as_bytes());
                    line.clear();
                }
            });
        }
    });
    addr
}

/// The store's wire body runs across PENDING entries over the host's connection table (a real
/// TCP backend that answers late, in two pieces) and answers the backend's reply.
#[test]
fn a_wire_body_pends_on_its_reads_and_answers_the_backends_reply() {
    let addr = line_backend(Duration::from_millis(30));
    *WIRE_ADDR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = addr;
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
        Arc::new(crate::tcp_conns::TcpConns::new(d.conn_waker()));
    let p = load_linked::<Store>(
        &LinkedRow::of(over_wire::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    let s = LoadedStore::open(p, d, b"{}", mint).expect("it opens");
    assert_eq!(
        RecordStore::list_denylist(&s).expect("the wire op answers"),
        vec!["echo hello".to_string()]
    );
    // A second op is its own connection, and answers the same.
    assert_eq!(
        RecordStore::list_denylist(&s).expect("again"),
        vec!["echo hello".to_string()]
    );
}
