// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::both_ways::store_fixture::MemoryStore;
use crate::store_v3::wrap::{Hooks, Wrapped};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Step, StoreSlots};
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, UsageDelta};
use busbar_contract::store_calls::{OpIdMint, StoreCalls};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

struct Shared;

type Databases = std::collections::HashMap<Vec<u8>, Arc<MemoryStore>>;

static BACKING: std::sync::Mutex<Option<Databases>> = std::sync::Mutex::new(None);

impl Hooks for Shared {
    fn open(settings: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        let mut dbs = BACKING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(dbs
            .get_or_insert_with(Default::default)
            .entry(settings.to_vec())
            .or_insert_with(|| Arc::new(MemoryStore::new()))
            .clone())
    }
}

mod shared {
    busbar_contract::store_door!(super::Wrapped<super::Shared>, "shared", "0", 64);
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
    open_door(db, mint, shared::door)
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
    let settings = format!("{{\"db\":\"{db}\"}}");
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

struct PendingLostReply;
impl Hooks for PendingLostReply {
    fn add_usage_batch(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        static LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if let Some(answer) = cx.resume::<OpResult<()>>() {
            return if !LOST.swap(true, std::sync::atomic::Ordering::AcqRel) {
                Step::Ready(Err(OpRefused::Failed("lost batch commit reply".into())))
            } else {
                Step::Ready(answer)
            };
        }
        let answer = match <MemoryStore as StoreSlots>::add_usage_batch(
            inner,
            &mut Op::detached(),
            op,
            cells,
        ) {
            Step::Ready(answer) => answer,
            Step::Pending { .. } => panic!("the memory backing answers inline"),
        };
        assert!(
            cx.can_pend(),
            "the synchronous bridge submits a real ticket"
        );
        cx.park(answer);
        Step::Pending {
            wake_at_ns: crate::dispatch::now_ns().saturating_add(1),
        }
    }
}

mod pending_lost {
    busbar_contract::store_door!(
        super::Wrapped<super::PendingLostReply>,
        "provided-id-lost-reply",
        "0",
        64
    );
}

#[test]
fn provided_id_batch_retains_exact_identity_after_pending_and_unknown_commit() {
    const PROVIDED_ID: OpId = OpId([0x72; 16]);
    let store = open_door("provided-id-unknown", must_not_mint, pending_lost::door);
    let cells = [("k", 60, one())];
    let error = RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &cells).unwrap_err();
    assert!(error.0.contains("lost batch commit reply"));
    assert_eq!(requests(&store), 1, "the failed answer followed a commit");
    RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &cells).unwrap();
    assert_eq!(
        requests(&store),
        1,
        "the caller retained the committed operation identity"
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
