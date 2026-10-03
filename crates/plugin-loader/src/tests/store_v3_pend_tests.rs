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

fn mint() -> OpId {
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
            conns: None,
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
