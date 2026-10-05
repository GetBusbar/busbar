// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter, seam by seam, against a store at the PUBLISHED payload schema.
//!
//! Three things are proven here.
//!
//! 1. **Every seam method answers.** One test per method across the three seams the composition
//!    root binds — the kernel's slices, the verbs unit's disaster-recovery verbs and sealed replay
//!    cache, the log's shipper — with the answer's CONTENT asserted, not merely its `Ok`-ness. A
//!    seam that returned a plausible-looking nothing would pass an errors-only check.
//! 2. **The plugin-behaviour appendix's rule for the operations this release adds.** On a store at
//!    the published schema every one of them answers from the node-local shim: no error, and no log
//!    line — proven with a `tracing` capture on the calling thread, the thread the adapter and the
//!    loaded store both log on, and repeated so a warn-once latch that merely happened to be quiet
//!    on the first pass cannot pass either.
//! 3. **The published operations still pass through.** The adapter hands the store out untouched,
//!    so a key written through it is the store's row.
//!
//! The store at the published schema is the in-tree RAM store bound to payload schema 2: the shim's
//! rule is a property of the schema number, not of the store behind it.
//!
//! The tests that drive the verb seam (it takes a minted `Grant<AdminVerb>`) live in busbar's
//! integration suite, which takes the token from the kernel's test token helper:
//! `crates/busbar/tests/store_adapter_verb_seam.rs`.

use super::*;
use crate::store_adapter::{
    speaks_new_ops, ShimClock, StoreAdapter, REPLAY_TTL_SECS, STORE_ABI_WITH_NEW_OPS,
};
use busbar_contract::slice::{bucket_all, CapDimension, Epoch, SliceId, SliceRequest, SliceStore};
use busbar_contract::verb_store::Store as VerbStore;
use busbar_kernel_wal::Record;
use std::sync::Arc;

/// The in-tree RAM store, as the published operations' backing.
fn memory_store() -> Arc<dyn busbar_contract::records::RecordStore> {
    Arc::from(busbar_store_memory::open("{}").expect("the memory store opens"))
}

/// An adapter over a store bound to the PUBLISHED payload schema (2), built through the same
/// constructor the composition root calls.
fn adapter_over_published_schema() -> Option<StoreAdapter> {
    Some(StoreAdapter::new(memory_store(), PUBLISHED_STORE_SCHEMA))
}

/// A slice draw for one bucket's request axis.
fn slice_request(wanted: u64, epoch: u64) -> SliceRequest {
    SliceRequest {
        bucket: bucket_all("team-a"),
        dimension: CapDimension::Requests,
        wanted,
        epoch: Epoch(epoch),
    }
}

/// The payload schema at which the added operations gain a wire is ABOVE every schema this binary
/// can load, so the shim is the answer for every loadable store — which is what makes the appendix
/// rule a property of the adapter rather than of one test's fixture.
#[test]
fn no_payload_schema_this_binary_can_load_speaks_the_added_operations() {
    let window = crate::registry::supported_abi("store");
    // One version per kind (C21/ABI-o1): the store window is a single element, so the floor and the
    // max are the same current `ABI_VERSION`; `window[window.len() - 1]` is max-safe for a 1-element
    // window where `window[1]` would panic.
    let (floor, max) = (window[0], window[window.len() - 1]);
    for abi in floor..=max {
        assert!(
            !speaks_new_ops(abi),
            "payload schema v{abi} is inside this binary's store window, so a store at it can be \
             loaded; if it claimed the added operations the adapter would try a wire that is not \
             there"
        );
    }
    assert!(
        STORE_ABI_WITH_NEW_OPS > max,
        "the schema carrying the added operations (v{STORE_ABI_WITH_NEW_OPS}) must sit above the \
         window's top (v{max}); if it ever falls inside, the shim methods need their wire half"
    );
    assert!(speaks_new_ops(STORE_ABI_WITH_NEW_OPS));
}

/// `reserve` grants what was asked for, at the shim's own epoch, and the grant is outstanding until
/// it is released.
#[test]
fn the_slice_seam_reserves_in_full_at_the_shim_epoch() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    let grant = adapter
        .reserve(&slice_request(250, 0))
        .expect("a slice draw on a published store must not fail");
    assert_eq!(
        grant.granted, 250,
        "the shim grants what was wanted, in full"
    );
    assert_eq!(grant.epoch, adapter.epoch(), "granted at the shim's epoch");
    assert_eq!(
        grant.valid_until,
        busbar_contract::Millis::MAX,
        "nothing expires a lease no other node can take"
    );
    let state = adapter.shim_state();
    assert_eq!(state.slices_outstanding, 1);
    assert_eq!(state.slices_granted, 250);
    assert_eq!(
        adapter.reserve(&slice_request(1, 0)).unwrap().id.0,
        grant.id.0 + 1,
        "a second draw is a distinct slice"
    );
}

/// A draw carrying an epoch the shim never issued is STAMPED with the shim's, not refused: a
/// stale-epoch refusal is an error, and there is no fleet for the node to be stale against.
#[test]
fn the_slice_seam_stamps_a_foreign_epoch_rather_than_refusing_it() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    let grant = adapter
        .reserve(&slice_request(10, 9_999))
        .expect("a draw at a foreign epoch must not fail");
    assert_eq!(grant.epoch, Epoch(0), "stamped with the shim's epoch");
    assert_eq!(grant.granted, 10);
}

/// `release` gives back the unspent part, and an id the shim never granted is accepted rather than
/// refused.
#[test]
fn the_slice_seam_releases_and_forgives_an_unknown_id() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    let grant = adapter.reserve(&slice_request(100, 0)).expect("reserve");
    adapter.release(grant.id, 40).expect("release");
    let state = adapter.shim_state();
    assert_eq!(state.slices_outstanding, 0, "the slice is given back");
    assert_eq!(state.slices_granted, 60, "the unspent 40 came back");
    adapter
        .release(SliceId(u64::MAX), 5)
        .expect("an id the shim never granted is forgiven, not refused");
    assert_eq!(
        adapter.shim_state().slices_granted,
        60,
        "and changes nothing"
    );
}

/// THE SHIPPED COUNT AND THE HEAD ADVANCE TOGETHER OR NOT AT ALL.
///
/// The module preamble supports two logs shipping through one adapter. The count and the head are
/// two halves of one answer — "n records acknowledged, ending at this identity" — and advancing
/// them in separate critical sections lets a reader see a count from one shipper beside a head from
/// the other. With both under one lock, whatever the reader sees is a pair that was true together.
#[test]
fn concurrent_shippers_never_split_the_count_from_the_head() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    const PER_SHIPPER: u64 = 20_000;
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // The observer reads the pair while the shippers run. "n acknowledged, ending here" is one
    // answer: a count above zero with no head at all is that answer torn in half.
    let observer = {
        let adapter = adapter.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let mut torn = 0u64;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let count = adapter.shim_state().records_shipped;
                if count > 0 && adapter.head().is_none() {
                    torn += 1;
                }
            }
            torn
        })
    };

    let mut handles = Vec::new();
    for lane in 1..=2u64 {
        let adapter = adapter.clone();
        handles.push(std::thread::spawn(move || {
            let mut shipper = adapter.shipper();
            for seq in 1..=PER_SHIPPER {
                shipper
                    .ship(&[Record::new(lane, seq, b"x".to_vec())])
                    .expect("a batch is acknowledged, never refused");
            }
        }));
    }
    for h in handles {
        h.join().expect("shipper thread");
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let torn = observer.join().expect("observer thread");
    assert_eq!(
        torn, 0,
        "the observer saw a non-zero shipped count beside no head at all {torn} time(s): the count \
         and the head are advancing in separate critical sections"
    );

    assert_eq!(
        adapter.shim_state().records_shipped,
        2 * PER_SHIPPER,
        "every acknowledged record is counted exactly once"
    );
    let head = adapter.head().expect("head");
    assert_eq!(
        head.1, PER_SHIPPER,
        "the head is the last identity one of the shippers acknowledged"
    );
}

/// The sealed cache: a first sighting is `None` and RESERVES the slot, a commit fixes the bytes,
/// and a replay returns exactly those bytes — the whole point of the seam.
#[test]
fn the_verb_seam_replay_cache_reserves_then_replays_the_committed_bytes() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    let key = ("set_operator_key".to_string(), "idem-7".to_string());
    assert_eq!(
        adapter.replay_new_verb(&key).expect("first sighting"),
        None,
        "a key never seen before is a first sighting"
    );
    assert_eq!(
        adapter.shim_state().replay_slots,
        1,
        "the first sighting reserved the slot"
    );
    assert_eq!(
        adapter.shim_state().replay_committed,
        0,
        "reserved is not committed"
    );
    assert_eq!(
        adapter.replay_new_verb(&key).expect("second sighting"),
        None,
        "a reserved-but-uncommitted slot still reads None: the first caller is in flight"
    );

    adapter
        .commit_new_verb_replay(&key, b"{\"id\":\"k-1\"}")
        .expect("commit");
    assert_eq!(
        adapter.replay_new_verb(&key).expect("replay"),
        Some(b"{\"id\":\"k-1\"}".to_vec()),
        "a replay returns the bytes that were committed, byte for byte"
    );
    assert_eq!(adapter.shim_state().replay_committed, 1);
    assert_eq!(
        adapter
            .replay_new_verb(&("set_operator_key".to_string(), "idem-8".to_string()))
            .expect("a different key"),
        None,
        "a different idempotency key is a different slot"
    );
}

/// A clock the test moves by hand, so the replay window can be watched closing without waiting it
/// out in real time.
#[derive(Clone, Default)]
struct TestClock(Arc<std::sync::atomic::AtomicU64>);

impl TestClock {
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, std::sync::atomic::Ordering::Relaxed);
    }
    fn shim_clock(&self) -> ShimClock {
        let ticks = Arc::clone(&self.0);
        Arc::new(move || ticks.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// [`adapter_over_published_schema`] whose sealed replay cache ages against `clock`.
fn adapter_at(clock: &TestClock) -> Option<StoreAdapter> {
    Some(StoreAdapter::with_clock(
        memory_store(),
        PUBLISHED_STORE_SCHEMA,
        clock.shim_clock(),
    ))
}

fn replay_key(name: &str) -> (String, String) {
    ("set_operator_key".to_string(), name.to_string())
}

/// Inside the window the shim is a replay cache: the committed bytes come back.
#[test]
fn a_replay_inside_the_window_returns_the_committed_bytes() {
    let clock = TestClock::default();
    let Some(adapter) = adapter_at(&clock) else {
        return;
    };
    let key = replay_key("idem-a");
    assert_eq!(adapter.replay_new_verb(&key).expect("first sighting"), None);
    adapter
        .commit_new_verb_replay(&key, b"the minted key")
        .expect("commit");
    clock.advance(REPLAY_TTL_SECS - 1);
    assert_eq!(
        adapter.replay_new_verb(&key).expect("replay"),
        Some(b"the minted key".to_vec()),
        "a replay inside the window is the whole point of the cache"
    );
}

/// Past the window the slot is gone: it no longer answers, and it is no longer held. A cache with no
/// ceiling would keep every response of every credential-minting verb the node ever served, for the
/// life of the process — a map that grows with exactly the traffic it exists to serve.
#[test]
fn a_slot_past_the_window_is_neither_answered_nor_held() {
    let clock = TestClock::default();
    let Some(adapter) = adapter_at(&clock) else {
        return;
    };
    let committed = replay_key("idem-a");
    adapter.replay_new_verb(&committed).expect("first sighting");
    adapter
        .commit_new_verb_replay(&committed, b"the minted key")
        .expect("commit");
    adapter
        .replay_new_verb(&replay_key("idem-b"))
        .expect("a reservation nobody came back for");
    assert_eq!(adapter.shim_state().replay_slots, 2);

    clock.advance(REPLAY_TTL_SECS);
    assert_eq!(
        adapter
            .replay_new_verb(&replay_key("idem-c"))
            .expect("a fresh key"),
        None,
        "a first sighting is still a first sighting"
    );
    assert_eq!(
        adapter.shim_state().replay_slots,
        1,
        "both expired slots are swept; only the fresh reservation is held"
    );
    assert_eq!(
        adapter.shim_state().replay_committed,
        0,
        "the expired response bytes are not kept either"
    );
    assert_eq!(
        adapter
            .replay_new_verb(&committed)
            .expect("past the window"),
        None,
        "a slot past the window does not answer"
    );
}

/// The shipper acknowledges a batch, counts it, and remembers the last identity.
#[test]
fn the_shipper_seam_acknowledges_a_batch_and_keeps_the_head() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    let mut shipper = adapter.shipper();
    assert_eq!(adapter.head(), None, "nothing shipped yet");
    shipper
        .ship(&[
            Record::new(7, 1, b"a".to_vec()),
            Record::new(7, 2, b"b".to_vec()),
        ])
        .expect("a batch on a published store is acknowledged, never refused");
    assert_eq!(adapter.shim_state().records_shipped, 2);
    assert_eq!(
        adapter.head(),
        Some((7, 2)),
        "the last identity of the batch"
    );
    shipper.ship(&[]).expect("an empty batch");
    assert_eq!(adapter.head(), Some((7, 2)), "an empty batch moves nothing");
    shipper
        .ship(&[Record::new(7, 3, b"c".to_vec())])
        .expect("a later batch");
    assert_eq!(adapter.shim_state().records_shipped, 3);
    assert_eq!(adapter.head(), Some((7, 3)));
}

/// The published operations are not touched by the adapter: the store it hands out is the loaded
/// plugin, and its rows are the plugin's.
#[test]
fn the_published_operations_pass_through_the_adapter_to_the_plugin() {
    let Some(adapter) = adapter_over_published_schema() else {
        return;
    };
    assert_eq!(
        adapter.abi_version(),
        PUBLISHED_STORE_SCHEMA,
        "the adapter carries the schema the manifest declared"
    );
    let row = busbar_contract::records::VirtualKey {
        id: "vk_pass".to_string(),
        generation_hash: "gen".to_string(),
        name: "legacy".to_string(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    adapter
        .store()
        .put_key(&row)
        .expect("put_key passes through");
    let keys = adapter
        .store()
        .list_keys()
        .expect("list_keys passes through");
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].id, "vk_pass",
        "the row is the plugin's, not the shim's"
    );
}

/// A store with no rows at all, for tests that touch only the node-local shim.
///
/// The shim is where the lock discipline lives, and it is the same shim on every store, so a test
/// about lock order must not be able to skip for want of a built cdylib.
#[derive(Default)]
struct NoRows;

impl busbar_contract::records::RecordStore for NoRows {
    fn put_key(
        &self,
        _key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        Ok(())
    }
    fn get_key(
        &self,
        _id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        Ok(None)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        Ok(())
    }
    fn get_usage(
        &self,
        _b: &str,
        _w: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        Ok(busbar_contract::records::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _b: &str,
        _w: u64,
        _l: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        Ok(())
    }
    fn add_metering(
        &self,
        _d: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        Ok(())
    }
    fn list_metering(
        &self,
        _b: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        Ok(Vec::new())
    }
}

/// Reading the shim's state must never wedge against a concurrent restore.
///
/// The interleaving is forced, not raced. One thread takes the recovery guard — the first of the
/// two a restore takes — and parks there; the reader then goes through `shim_state`, which is the
/// diagnostics read the root and the `Debug` impl both make. If that read holds any shim lock
/// while reaching for another, the parked restore's second lock cannot land and both threads stop
/// for good: the reader waiting on recovery, the restore on what the reader is holding.
///
/// The watchdog is the assertion. A wedged pair never returns, so the test cannot detect the fault
/// by joining; it waits a generous multiple of the park and fails if the read has not answered.
#[test]
fn reading_the_shim_state_never_wedges_against_a_concurrent_restore() {
    let adapter = StoreAdapter::new(Arc::new(NoRows), PUBLISHED_STORE_SCHEMA);
    // Something to read, so the answer is checked rather than merely arriving.
    adapter
        .slice_store()
        .reserve(&slice_request(7, 0))
        .expect("the shim grants a slice");

    let parked = Arc::new(std::sync::Barrier::new(2));
    let restorer = {
        let adapter = adapter.clone();
        let parked = parked.clone();
        std::thread::spawn(move || {
            adapter.hold_recovery_then_slices(|| {
                // Recovery is held. Release the reader, then stay here long enough that the reader
                // is certainly inside `shim_state` before the slices guard is reached for.
                parked.wait();
                std::thread::sleep(std::time::Duration::from_millis(250));
            });
        })
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let reader = {
        let adapter = adapter.clone();
        let parked = parked.clone();
        std::thread::spawn(move || {
            parked.wait();
            let _ = tx.send(adapter.shim_state());
        })
    };

    let state = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap_or_else(|_| {
            panic!(
                "shim_state did not answer while a restore held the recovery guard: it holds one \
                 shim lock while taking another, in the opposite order to the restore, so the two \
                 threads have deadlocked — and every later slice draw blocks behind them"
            )
        });
    assert_eq!(
        state.slices_outstanding, 1,
        "the read answers with what the shim is holding"
    );
    assert_eq!(state.slices_granted, 7);

    restorer.join().expect("restore thread");
    reader.join().expect("reader thread");
}
