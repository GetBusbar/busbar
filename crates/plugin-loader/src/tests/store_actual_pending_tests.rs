// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Actual Store operations preceded by the former suite's one hostile pending crossing.
use crate::actual_store;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, RawOutcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::store::{OpId, Ops};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta,
};
use busbar_contract::store_calls::StoreCalls;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

fn open(door: busbar_contract::abi::mechanism::door::DoorFn) -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(door).expect("actual SQLite statement");
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: "pending-store".into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("actual SQLite links");
    LoadedStore::open(p, d, &actual_store::settings(), actual_store::mint)
        .expect("actual isolated SQLite opens")
}
mod pends_once {
    use super::*;
    static INJECTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    pub(super) fn injected() -> usize {
        INJECTED.load(std::sync::atomic::Ordering::Acquire)
    }
    use std::ffi::c_void;
    extern "C" fn add_usage_batch(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        static ACTIVE: OnceLock<Mutex<HashMap<(u64, Ticket), bool>>> = OnceLock::new();
        // SAFETY: the dispatcher supplies this exact slot's ABI input and output. Every
        // nested pointer remains lent by its production frame across the injected wait.
        unsafe {
            let original = &*input.cast::<busbar_contract::abi::store::AddUsageBatchIn>();
            let head = &*input.cast::<InHead>();
            let key = (head.host.handle, head.ticket);
            let active = ACTIVE.get_or_init(Default::default);
            if head.flags & FLAG_RESUME == 0 {
                INJECTED.fetch_add(1, std::sync::atomic::Ordering::Release);
                active.lock().unwrap().insert(key, false);
                let output = &mut *out.cast::<OutHead>();
                output.outcome = RawOutcome::of(Outcome::Pending);
                output.wake_at_ns = crate::dispatch::now_ns().saturating_add(1_000_000);
                return RawOutcome::of(Outcome::Pending);
            }
            let first_resume = {
                let mut held = active.lock().unwrap();
                let was = held.entry(key).or_insert(true);
                let first = !*was;
                *was = true;
                first
            };
            let mut forwarded = std::ptr::read(original);
            if first_resume {
                (&mut *std::ptr::from_mut(&mut forwarded).cast::<InHead>()).flags &= !FLAG_RESUME;
            }
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.add_usage_batch.expect("actual SQLite slot"))(
                instance,
                std::ptr::from_ref(&forwarded).cast(),
                out,
            );
            if answer != RawOutcome::of(Outcome::Pending) {
                active.lock().unwrap().remove(&key);
            }
            answer
        }
    }
    extern "C" fn record_scan(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        static ACTIVE: OnceLock<Mutex<HashMap<(u64, Ticket), bool>>> = OnceLock::new();
        // SAFETY: the dispatcher supplies this exact slot's ABI input and output. Every
        // nested pointer remains lent by its production frame across the injected wait.
        unsafe {
            let original = &*input.cast::<busbar_contract::abi::store::RecordScanIn>();
            let head = &*input.cast::<InHead>();
            let key = (head.host.handle, head.ticket);
            let active = ACTIVE.get_or_init(Default::default);
            if head.flags & FLAG_RESUME == 0 {
                INJECTED.fetch_add(1, std::sync::atomic::Ordering::Release);
                active.lock().unwrap().insert(key, false);
                let output = &mut *out.cast::<OutHead>();
                output.outcome = RawOutcome::of(Outcome::Pending);
                output.wake_at_ns = crate::dispatch::now_ns().saturating_add(1_000_000);
                return RawOutcome::of(Outcome::Pending);
            }
            let first_resume = {
                let mut held = active.lock().unwrap();
                let was = held.entry(key).or_insert(true);
                let first = !*was;
                *was = true;
                first
            };
            let mut forwarded = std::ptr::read(original);
            if first_resume {
                (&mut *std::ptr::from_mut(&mut forwarded).cast::<InHead>()).flags &= !FLAG_RESUME;
            }
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.record_scan.expect("actual SQLite slot"))(
                instance,
                std::ptr::from_ref(&forwarded).cast(),
                out,
            );
            if answer != RawOutcome::of(Outcome::Pending) {
                active.lock().unwrap().remove(&key);
            }
            answer
        }
    }
    extern "C" fn list_plane_records(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        static ACTIVE: OnceLock<Mutex<HashMap<(u64, Ticket), bool>>> = OnceLock::new();
        // SAFETY: the dispatcher supplies this exact slot's ABI input and output. Every
        // nested pointer remains lent by its production frame across the injected wait.
        unsafe {
            let original = &*input.cast::<busbar_contract::abi::store::ListPlaneRecordsIn>();
            let head = &*input.cast::<InHead>();
            let key = (head.host.handle, head.ticket);
            let active = ACTIVE.get_or_init(Default::default);
            if head.flags & FLAG_RESUME == 0 {
                INJECTED.fetch_add(1, std::sync::atomic::Ordering::Release);
                active.lock().unwrap().insert(key, false);
                let output = &mut *out.cast::<OutHead>();
                output.outcome = RawOutcome::of(Outcome::Pending);
                output.wake_at_ns = crate::dispatch::now_ns().saturating_add(1_000_000);
                return RawOutcome::of(Outcome::Pending);
            }
            let first_resume = {
                let mut held = active.lock().unwrap();
                let was = held.entry(key).or_insert(true);
                let first = !*was;
                *was = true;
                first
            };
            let mut forwarded = std::ptr::read(original);
            if first_resume {
                (&mut *std::ptr::from_mut(&mut forwarded).cast::<InHead>()).flags &= !FLAG_RESUME;
            }
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.list_plane_records.expect("actual SQLite slot"))(
                instance,
                std::ptr::from_ref(&forwarded).cast(),
                out,
            );
            if answer != RawOutcome::of(Outcome::Pending) {
                active.lock().unwrap().remove(&key);
            }
            answer
        }
    }
    pub(super) extern "C" fn door() -> &'static Door {
        static HELD: OnceLock<usize> = OnceLock::new();
        let ptr = *HELD.get_or_init(|| {
            let real = *actual_store::door();
            // SAFETY: actual_store retains the validated real product mapping.
            let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            ops.add_usage_batch = Some(add_usage_batch);
            ops.record_scan = Some(record_scan);
            ops.list_plane_records = Some(list_plane_records);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: retain real lifecycle and all operations except the three existing
            // adversarial scheduling boundaries, with a permanent copied ops table.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            })) as usize
        });
        // SAFETY: permanently retained immutable descriptor.
        unsafe { &*(ptr as *const Door) }
    }
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
    let inline = transcript(&open(actual_store::door));
    let before = pends_once::injected();
    let pended = transcript(&open(pends_once::door));
    assert_eq!(
        pends_once::injected() - before,
        4,
        "all four selected crossings really suspended before the actual Store operation"
    );
    assert_eq!(pended, inline);
}

use crate::dispatch::{in_head, out_head};
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::store::IdIn;
use std::ffi::c_void;
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
        let settings = actual_store::settings();
        let mut oi: OpenIn = std::mem::zeroed();
        oi.head = in_head();
        oi.head.size = std::mem::size_of::<OpenIn>() as u32;
        oi.head.op = busbar_contract::abi::mechanism::lifecycle::slot::OPEN;
        oi.settings = busbar_contract::abi::mechanism::call::Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
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
        let answer = call(
            instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
        .outcome();
        let mut close_in = in_head();
        close_in.op = busbar_contract::abi::mechanism::lifecycle::slot::CLOSE;
        let mut close_out = out_head();
        (ops.head.close.expect("actual SQLite closes"))(
            instance,
            std::ptr::from_ref(&close_in).cast(),
            std::ptr::from_mut(&mut close_out).cast(),
        );
        answer
    }
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

#[test]
fn a_resume_with_nothing_parked_is_fault_and_never_a_fresh_run() {
    assert_eq!(
        raw_delete_key(actual_store::door, TICKET, FLAG_RESUME),
        Outcome::Fault
    );

    assert_eq!(
        raw_delete_key(actual_store::door, TICKET, 0),
        Outcome::Failed
    );
}

mod remote_denylist {
    use super::*;
    use std::ffi::c_void;
    extern "C" fn list_denylist(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        static ACTIVE: OnceLock<Mutex<HashMap<(u64, Ticket), bool>>> = OnceLock::new();
        // SAFETY: the dispatcher supplies this exact slot's ABI input and output. Every
        // nested pointer remains lent by its production frame across the injected wait.
        unsafe {
            let original = &*input.cast::<InHead>();
            let head = &*input.cast::<InHead>();
            let key = (head.host.handle, head.ticket);
            let active = ACTIVE.get_or_init(Default::default);
            if head.flags & FLAG_RESUME == 0 {
                active.lock().unwrap().insert(key, false);
                let output = &mut *out.cast::<OutHead>();
                output.outcome = RawOutcome::of(Outcome::Pending);
                output.wake_at_ns = crate::dispatch::now_ns().saturating_add(1_000_000);
                return RawOutcome::of(Outcome::Pending);
            }
            let first_resume = {
                let mut held = active.lock().unwrap();
                let was = held.entry(key).or_insert(true);
                let first = !*was;
                *was = true;
                first
            };
            let mut forwarded = std::ptr::read(original);
            if first_resume {
                (&mut *std::ptr::from_mut(&mut forwarded).cast::<InHead>()).flags &= !FLAG_RESUME;
            }
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.list_denylist.expect("actual SQLite slot"))(
                instance,
                std::ptr::from_ref(&forwarded).cast(),
                out,
            );
            if answer != RawOutcome::of(Outcome::Pending) {
                active.lock().unwrap().remove(&key);
            }
            answer
        }
    }
    pub(super) extern "C" fn door() -> &'static Door {
        static HELD: OnceLock<usize> = OnceLock::new();
        let ptr = *HELD.get_or_init(|| {
            let real = *actual_store::door();
            // SAFETY: actual_store retains the genuine validated descriptor and image.
            let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            ops.list_denylist = Some(list_denylist);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: preserve actual lifecycle and all business slots except one hostile scheduling boundary.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            })) as usize
        });
        // SAFETY: immutable descriptor/table retained permanently above.
        unsafe { &*(ptr as *const Door) }
    }
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

mod commits_then_pends {
    use super::*;
    use std::collections::HashSet;
    use std::ffi::c_void;
    static PENDED: OnceLock<Mutex<HashSet<OpId>>> = OnceLock::new();
    extern "C" fn batch(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: the production dispatcher supplies this actual SQLite batch frame;
        // only the old adversarial timing boundary after a real commit is changed.
        unsafe {
            let request = &*input.cast::<busbar_contract::abi::store::AddUsageBatchIn>();
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.add_usage_batch.expect("actual SQLite batch"))(instance, input, out);
            if answer != RawOutcome::of(Outcome::Ready) || (*out.cast::<OutHead>()).lease != 0 {
                return answer;
            }
            if PENDED
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .insert(request.op_id)
            {
                let head = &mut *out.cast::<OutHead>();
                head.outcome = RawOutcome::of(Outcome::Pending);
                head.wake_at_ns = crate::dispatch::now_ns().saturating_add(60_000_000_000);
                return RawOutcome::of(Outcome::Pending);
            }
            answer
        }
    }
    pub(super) extern "C" fn door() -> &'static Door {
        static HELD: OnceLock<usize> = OnceLock::new();
        let ptr = *HELD.get_or_init(|| {
            let real = *actual_store::door();
            // SAFETY: actual_store retains the genuine validated descriptor and image.
            let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            ops.add_usage_batch = Some(batch);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: actual Store lifecycle and all operations retained except one hostile
            // post-commit timing result; table/descriptor are permanent.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            })) as usize
        });
        // SAFETY: immutable permanent descriptor allocation.
        unsafe { &*(ptr as *const Door) }
    }
}
#[test]
fn a_usage_batch_cancelled_after_its_write_retries_counted_once() {
    let s = open(commits_then_pends::door);
    let rt = rt();
    let op = actual_store::mint();
    let cells = [(
        "m",
        60u64,
        UsageDelta {
            requests: 4,
            billable_requests: 4,
            models: Vec::new(),
        },
    )];
    let first = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            s.add_usage_batch(op, &cells),
        )
        .await
    });
    assert!(
        first.is_err(),
        "the first attempt pends until it is cancelled"
    );
    assert_eq!(
        RecordStore::get_usage(&s, "m", 60)
            .expect("the committed first attempt is visible")
            .requests,
        4,
        "the original attempt committed before its reply was cancelled"
    );
    rt.block_on(s.add_usage_batch(op, &cells))
        .expect("the retry of the same op_id answers");
    let counted = RecordStore::get_usage(&s, "m", 60).expect("read");
    assert_eq!(counted.requests, 4, "counted once, not twice");
}

#[test]
fn a_store_door_without_needs_states_none() {
    // SAFETY: actual_store retains the validated SQLite descriptor and statement.
    let no_needs = unsafe { &*actual_store::door().statement() };
    assert!(no_needs.needs.is_null());
    assert_eq!(no_needs.needs_len, 0);

    let path = std::env::var_os("BUSBAR_TEST_MYSQL_CDYLIB")
        .map(std::path::PathBuf::from)
        .expect("BUSBAR_TEST_MYSQL_CDYLIB names the qualified actual MySQL product");
    assert!(path.is_absolute() && path.is_file());
    let library = crate::dlopen_on_worker(path.as_os_str()).expect("load qualified MySQL image");
    // SAFETY: the qualified image exports the ABI symbol, and library remains live
    // through every descriptor and statement loan below.
    let entry = unsafe {
        *library
            .get::<busbar_contract::abi::sdk::door::RawDoorFn>(
                busbar_contract::abi::mechanism::DOOR_SYMBOL,
            )
            .expect("MySQL ABI entry")
    };
    let raw = crate::dispatch::load::enter_door(entry);
    crate::dispatch::load::validate_door::<Store>(raw).expect("actual MySQL Store descriptor");
    // SAFETY: validation established a live descriptor/Statement within retained library.
    let statement = unsafe { &*(*raw).statement() };
    let rendering = unsafe { busbar_contract::abi::mechanism::rendering::render(statement) }
        .expect("MySQL statement renders");
    let stated = busbar_contract::abi::mechanism::rendering::read(&rendering)
        .expect("MySQL statement reads");
    assert_eq!(
        stated.name, "busbar-store-mysql",
        "require the actual need-declaring product"
    );
    assert_eq!(statement.needs_len, 1);
}
