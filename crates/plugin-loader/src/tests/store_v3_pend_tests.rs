// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::store::{Op, OpResult, Scanned, Step, StoreSlots};
use busbar_contract::abi::store::{IdIn, OpId};
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

struct Kept<T>(T);

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

struct PendsOnce;

impl Hooks for PendsOnce {
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
}

fn ready<T>(s: Step<T>) -> T {
    match s {
        Step::Ready(t) => t,
        Step::Pending { .. } => panic!("the memory store never pends"),
    }
}

struct CommitsThenPends;

static PENDED: Mutex<Option<HashSet<OpId>>> = Mutex::new(None);

const CANCELLED: &str = "m";

impl Hooks for CommitsThenPends {
    fn add_usage_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let mut d = Op::detached();
        let answer = ready(<MemoryStore as StoreSlots>::add_usage_batch(
            inner, &mut d, op, cells,
        ));
        let mut pended = PENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cells.iter().any(|(b, ..)| *b == CANCELLED)
            && pended.get_or_insert_with(HashSet::new).insert(op)
            && cx.can_pend()
        {
            cx.park(Kept(answer));
            return Step::Pending {
                wake_at_ns: now_ns().saturating_add(60_000_000_000),
            };
        }
        Step::Ready(answer)
    }
}

struct PendsOnNothing;

impl Hooks for PendsOnNothing {
    fn delete_key(
        _: &MemoryStore,
        _: &mut Op<'_>,
        _: &str,
    ) -> Step<busbar_contract::records::RecordStoreResult<()>> {
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

pub(super) fn open(door: busbar_contract::abi::mechanism::door::DoorFn) -> LoadedStore {
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

fn transcript(s: &LoadedStore) -> String {
    rt().block_on(async {
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
        format!("{scan:?} | {listed:?} | {batch:?} {replay:?} {usage:?}")
    })
}

#[test]
fn an_op_that_pends_and_resumes_answers_what_the_inline_op_answers() {
    let inline = transcript(&open(crate::both_ways::store_fixture::door));
    let pended = transcript(&open(pends_once::door));
    assert_eq!(pended, inline);
}

#[test]
fn a_usage_batch_cancelled_after_its_write_retries_counted_once() {
    let s = open(commits_then_pends::door);
    let rt = rt();
    let op = mint();
    let cells = [(
        CANCELLED,
        60u64,
        UsageDelta {
            requests: 4,
            billable_requests: 4,
            models: Vec::new(),
        },
    )];
    let first = rt.block_on(async {
        tokio::time::timeout(Duration::from_millis(100), s.add_usage_batch(op, &cells)).await
    });
    assert!(
        first.is_err(),
        "the first attempt pends until it is cancelled"
    );
    rt.block_on(s.add_usage_batch(op, &cells))
        .expect("the retry of the same op_id answers");
    let counted = RecordStore::get_usage(&s, CANCELLED, 60).expect("read");
    assert_eq!(counted.requests, 4, "counted once, not twice");
}

fn raw_delete_key(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    ticket: Ticket,
    flags: u32,
) -> Outcome {
    // SAFETY: the SDK's `'static` door and its store table; every call passes the slot's own
    // `in`/`out` shapes, live for the call.
    unsafe {
        let d = door();
        let ops = &*d.ops().cast::<busbar_contract::abi::store::Ops>();
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
        let mut input = IdIn {
            head: in_head(),
            id: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: b"absent".as_ptr(),
                len: 6,
            },
        };
        input.head.size = std::mem::size_of::<IdIn>() as u32;
        input.head.op = busbar_contract::abi::store::slot::DELETE_KEY;
        input.head.ticket = ticket;
        input.head.flags = flags;
        let mut out: OutHead = out_head();
        let call = ops.delete_key.expect("delete_key");
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
        raw_delete_key(crate::both_ways::store_fixture::door, TICKET, FLAG_RESUME),
        Outcome::Fault
    );

    assert_eq!(
        raw_delete_key(crate::both_ways::store_fixture::door, TICKET, 0),
        Outcome::Failed
    );
}

#[test]
fn pending_on_the_connector_with_no_service_in_flight_is_fault() {
    assert_eq!(
        raw_delete_key(pends_on_nothing::door, TICKET, 0),
        Outcome::Fault
    );
}

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

#[test]
fn a_store_door_without_needs_states_none() {
    // SAFETY: the SDK's `'static` door and Statement.
    let st = unsafe { *remote_denylist::door().statement() };
    assert!(st.needs.is_null());
    assert_eq!(st.needs_len, 0);
    // SAFETY: as above.
    let st = unsafe { *over_tcp::door().statement() };
    assert_eq!(st.needs_len, 1);
}

static PENDS_IN_OPEN_OPENS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

struct PendsInOpen;

impl Hooks for PendsInOpen {
    fn open(
        settings: &[u8],
        _: &[&[u8]],
        host: Option<busbar_contract::abi::sdk::conn::Host>,
    ) -> Result<Arc<MemoryStore>, String> {
        let _ = (settings, host);
        PENDS_IN_OPEN_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Arc::new(MemoryStore::new()))
    }
    fn connect(_: &MemoryStore, cx: &mut Op<'_>) -> Step<Result<(), String>> {
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

    assert_eq!(
        RecordStore::list_denylist(&s).expect("again"),
        vec!["echo hello".to_string()]
    );
}
