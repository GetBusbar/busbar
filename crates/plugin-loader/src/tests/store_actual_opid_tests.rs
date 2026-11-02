// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, UsageDelta};
use busbar_contract::store_calls::{OpIdMint, StoreCalls};
use std::sync::Arc;
#[path = "actual_store.rs"]
mod actual_store;

fn settings_for(db: &str) -> String {
    static DATABASES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    DATABASES
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(db.into())
        .or_insert_with(|| {
            String::from_utf8(actual_store::settings()).expect("SQLite settings are JSON UTF-8")
        })
        .clone()
}

/// One boot's allocator: its node half (the kernel draws it from the CSPRNG once per process) and
/// its one counter.
macro_rules! boot {
    ($name:ident, $node:expr) => {
        fn $name() -> OpId {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            OpId::from_parts(
                $node,
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            )
        }
    };
}

fn open(db: &str, mint: OpIdMint) -> LoadedStore {
    open_door(db, mint, actual_store::door)
}

fn open_door(
    db: &str,
    mint: OpIdMint,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> LoadedStore {
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
    let settings = settings_for(db);
    LoadedStore::open(p, d, settings.as_bytes(), mint).expect("it opens")
}

fn one() -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: Vec::new(),
    }
}

fn requests(s: &LoadedStore) -> i64 {
    RecordStore::get_usage(s, "k", 60).expect("usage").requests as i64
}

#[test]
fn two_handles_on_one_durable_store_both_land_their_writes() {
    boot!(this_boot, 0xb007_0001);
    let (a, b) = (
        open("two-handles", this_boot),
        open("two-handles", this_boot),
    );
    a.add_usage("k", 60, &one())
        .expect("the first handle's write");
    b.add_usage("k", 60, &one())
        .expect("the second handle's write");
    assert_eq!(
        requests(&b),
        2,
        "the second handle's write is not a replay of the first's"
    );
}

#[test]
fn a_write_after_a_restart_lands() {
    boot!(before, 0xb007_0002);
    boot!(after, 0xb007_0003);
    open("restart", before)
        .add_usage("k", 60, &one())
        .expect("the earlier boot's write");
    let restarted = open("restart", after);
    restarted
        .add_usage("k", 60, &one())
        .expect("the new boot's write");
    assert_eq!(
        requests(&restarted),
        2,
        "the new boot's counter 1 is a new id"
    );
}

#[test]
fn a_true_replay_is_deduped() {
    boot!(this_boot, 0xb007_0004);
    let s = open("replay", this_boot);
    let op = this_boot();
    let cells = [("k", 60u64, one())];
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(async {
            s.add_usage_batch(op, &cells).await.expect("the write");
            s.add_usage_batch(op, &cells).await.expect("its replay");
        });
    assert_eq!(requests(&s), 1, "the same op_id applies once");
}

fn must_not_mint() -> OpId {
    panic!("a provided-id batch must never mint a replacement identity")
}

#[test]
fn provided_id_batches_replay_across_handles_and_refuse_a_different_body() {
    const PROVIDED_ID: OpId = OpId([0x71; 16]);
    let first = open("provided-id-batch", must_not_mint);
    let cells = [("k", 60, one()), ("group", 60, one())];
    RecordStore::add_usage_batch_deduped(&first, PROVIDED_ID, &cells).unwrap();
    let reopened = open("provided-id-batch", must_not_mint);
    RecordStore::add_usage_batch_deduped(&reopened, PROVIDED_ID, &cells).unwrap();
    let changed = [
        (
            "k",
            60,
            UsageDelta {
                requests: 2,
                ..one()
            },
        ),
        ("group", 60, one()),
    ];
    let error = RecordStore::add_usage_batch_deduped(&reopened, PROVIDED_ID, &changed).unwrap_err();
    assert!(error
        .0
        .contains(busbar_contract::abi::store::DIAG_OPID_CONFLICT));
    assert_eq!(requests(&reopened), 1);
    assert_eq!(
        RecordStore::get_usage(&reopened, "group", 60)
            .unwrap()
            .requests,
        1
    );
}

#[test]
fn provided_metering_id_replays_across_handles_and_refuses_changed_counts() {
    use busbar_contract::records::MeteringDelta;
    const ID: OpId = OpId([0x79; 16]);
    let first = open("provided-metering-id", must_not_mint);
    let delta = MeteringDelta {
        key_id: "metered".into(),
        bucket: 60,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: 3,
        tokens_output: 5,
        tokens_cache_read: 7,
        tokens_cache_write: 11,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "historical-group".into(),
        pricing_version: "historical-version".into(),
        priced_from_ms: 123,
        usage_units: std::collections::BTreeMap::from([("bytes".into(), 13)]),
    };
    assert!(RecordStore::supports_metering_batch_deduped(&first));
    RecordStore::add_metering_batch_deduped(&first, ID, std::slice::from_ref(&delta)).unwrap();
    let reopened = open("provided-metering-id", must_not_mint);
    RecordStore::add_metering_batch_deduped(&reopened, ID, std::slice::from_ref(&delta)).unwrap();
    let mut changed = delta.clone();
    changed.tokens_input += 1;
    let error = RecordStore::add_metering_batch_deduped(&reopened, ID, &[changed]).unwrap_err();
    assert!(error
        .0
        .contains(busbar_contract::abi::store::DIAG_OPID_CONFLICT));
    let rows = RecordStore::list_metering(&reopened, 60).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 1);
    assert_eq!(rows[0].tokens_input, 3);
    assert_eq!(rows[0].tokens_output, 5);
    assert_eq!(rows[0].usage_units.get("bytes"), Some(&13));
    assert_eq!(rows[0].priced_from_ms, 123);
    assert_eq!(rows[0].pricing_version, "historical-version");
    assert_eq!(rows[0].key_group_at_use, "historical-group");
}

// The original unknown-commit adversary wraps only the actual SQLite batch slot:
// the real database commits first, one host ticket resumes, and its first settled
// reply is lost. No record or usage business implementation is supplied here.
mod pending_lost {
    use super::*;
    use busbar_contract::abi::mechanism::call::{
        AbiStr, InHead, OutHead, Outcome, RawOutcome, FLAG_RESUME,
    };
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::store::Ops;
    use std::ffi::c_void;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    };
    static LOST: AtomicBool = AtomicBool::new(false);
    static PENDED: AtomicBool = AtomicBool::new(false);

    extern "C" fn batch(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: this is the unchanged real Store ADD_USAGE_BATCH frame. The
        // dispatcher retains its request and output through the resumed ticket.
        unsafe {
            let head = &*input.cast::<InHead>();
            if head.flags & FLAG_RESUME != 0 {
                let output = &mut *out.cast::<OutHead>();
                *output = crate::dispatch::out_head();
                let answer = if !LOST.swap(true, Ordering::AcqRel) {
                    output.error = AbiStr::over(b"lost batch commit reply");
                    Outcome::Failed
                } else {
                    Outcome::Ready
                };
                output.outcome = RawOutcome::of(answer);
                return RawOutcome::of(answer);
            }
            let ops = &*actual_store::door().ops().cast::<Ops>();
            let answer = (ops.add_usage_batch.expect("SQLite batch slot"))(instance, input, out);
            if answer != RawOutcome::of(Outcome::Ready) {
                return answer;
            }
            PENDED.store(true, Ordering::Release);
            let output = &mut *out.cast::<OutHead>();
            output.outcome = RawOutcome::of(Outcome::Pending);
            output.wake_at_ns = crate::dispatch::now_ns().saturating_add(1);
            RawOutcome::of(Outcome::Pending)
        }
    }

    pub(super) extern "C" fn door() -> &'static Door {
        static HELD: OnceLock<usize> = OnceLock::new();
        let ptr = *HELD.get_or_init(|| {
            let real = *actual_store::door();
            // SAFETY: the validated real SQLite mapping is retained by actual_store.
            let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            ops.add_usage_batch = Some(batch);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: only the existing adversarial result/ticket boundary above
            // differs; all actual Store lifecycle and remaining operations are retained.
            Box::into_raw(Box::new(unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            })) as usize
        });
        // SAFETY: HELD names a permanent immutable descriptor allocation.
        unsafe { &*(ptr as *const Door) }
    }

    pub(super) fn pended() -> bool {
        PENDED.load(Ordering::Acquire)
    }
}

#[test]
fn provided_id_batch_retains_exact_identity_after_pending_and_unknown_commit() {
    const PROVIDED_ID: OpId = OpId([0x72; 16]);
    let store = open_door("provided-id-unknown", must_not_mint, pending_lost::door);
    let cells = [("k", 60, one())];
    let error = RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &cells).unwrap_err();
    assert!(error.0.contains("lost batch commit reply"));
    assert!(
        pending_lost::pended(),
        "the actual committed batch resumed a pending ticket"
    );
    assert_eq!(requests(&store), 1, "the failed answer followed a commit");
    RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &cells).unwrap();
    assert_eq!(
        requests(&store),
        1,
        "the caller retained the committed operation identity"
    );
}
