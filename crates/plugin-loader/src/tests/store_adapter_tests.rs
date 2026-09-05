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
//! 3. **The published operations still pass through.** The adapter hands the loaded store out
//!    untouched, so a key written through it is the plugin's row, and on the published sqlite store
//!    it is the same row after a fresh handle onto the same database.
//!
//! The store at the published schema is modelled two ways, on purpose. The fast one is the in-tree
//! example plugin with its call seam faked, bound to payload schema 2 — the same double the
//! appendix-rule tests next door use, so this file needs no artifact that is not built by
//! `cargo test --workspace`. The real one is the PUBLISHED sqlite store, fetched by digest into the
//! oracle cache by `testing/shadow-oracle/fetch-plugin.sh`; that test skips when the cache is cold,
//! because a machine with no cached tarball is not evidence of a broken adapter.

use super::abi2_store_ops_tests::EventLog;
use super::*;
use crate::store_adapter::{speaks_new_ops, StoreAdapter, STORE_ABI_WITH_NEW_OPS};
use busbar_caps::{AdminToken, KernelSeal};
use busbar_kernel::slice::{bucket_all, CapDimension, Epoch, SliceId, SliceRequest, SliceStore};
use busbar_unit_verbs::store::Store as VerbStore;
use busbar_unit_wal::Record;
use std::sync::Arc;

/// The verbs unit's admin token. Minting one is what the kernel does for the length of an admin
/// verb; a test standing in for the kernel mints its own.
fn admin() -> AdminToken {
    AdminToken::mint(&KernelSeal::acquire_for_kernel())
}

/// An adapter over a store bound to the PUBLISHED payload schema (2), built through the same
/// constructor the composition root calls.
fn adapter_over_published_schema() -> Option<StoreAdapter> {
    let store = dyn_example_store_with_fake_call_at_abi(crate::registry::STORE_ABI_FLOOR)?;
    Some(StoreAdapter::over_loaded_store(store))
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
    let (floor, max) = (window[0], window[1]);
    assert_eq!(floor, 2, "the published store schema is the floor");
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
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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
        busbar_kernel::Millis::MAX,
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
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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

/// `epoch` is the one generation a node-local shim has, and it stays put.
#[test]
fn the_slice_seam_epoch_is_constant() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    assert_eq!(adapter.epoch(), Epoch(0));
    adapter.reserve(&slice_request(1, 0)).expect("reserve");
    adapter
        .reseal_epoch_floor(&admin())
        .expect("reseal_epoch_floor");
    assert_eq!(
        adapter.epoch(),
        Epoch(0),
        "nothing on a node-local shim can advance the epoch"
    );
}

/// `chain_break` is recorded: the journal on such a deployment is the node's own, so the break is
/// a node-local fact and the seam says it happened.
#[test]
fn the_verb_seam_records_a_chain_break() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    assert_eq!(adapter.shim_state().chain_breaks, 0);
    adapter.chain_break(&admin()).expect("chain_break");
    adapter.chain_break(&admin()).expect("chain_break again");
    assert_eq!(adapter.shim_state().chain_breaks, 2);
}

/// `store_restore` records the backup it was asked for and drops the outstanding slices, and it
/// does NOT drop a committed replay slot — that is how a credential-minting verb would re-mint.
#[test]
fn the_verb_seam_records_a_restore_and_keeps_the_sealed_replay_slots() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let key = ("export_keyset".to_string(), "idem-1".to_string());
    adapter.replay_new_verb(&key).expect("first sighting");
    adapter
        .commit_new_verb_replay(&key, b"the-sealed-answer")
        .expect("commit");
    adapter.reserve(&slice_request(5, 0)).expect("reserve");

    adapter
        .store_restore(&admin(), "backup-2026-09-05")
        .expect("store_restore");

    let state = adapter.shim_state();
    assert_eq!(state.restores, 1);
    assert_eq!(
        adapter.last_restore().as_deref(),
        Some("backup-2026-09-05"),
        "the seam records which backup was named"
    );
    assert_eq!(
        state.slices_outstanding, 0,
        "slices do not survive a restore"
    );
    assert_eq!(
        adapter.replay_new_verb(&key).expect("replay after restore"),
        Some(b"the-sealed-answer".to_vec()),
        "a committed replay slot DOES survive a restore, or the verb re-mints"
    );
}

/// A RESTORE LEAVES THE TWO SLICE FIGURES DESCRIBING THE SAME THING.
///
/// `slices_granted` is "units granted and not given back", and `slices_outstanding` is the map
/// those units live in. Clearing the map without zeroing the counter leaves a figure that describes
/// reservations that no longer exist — a diagnostic that reads as 100 units held by nobody. The two
/// are also resealed under ONE lock order (recovery then slices, held across the reseal), so a draw
/// landing mid-restore cannot be half-erased: either it is in both figures or in neither.
#[test]
fn a_restore_reseals_both_slice_figures_together() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    adapter.reserve(&slice_request(100, 0)).expect("reserve");
    assert_eq!(adapter.shim_state().slices_granted, 100);

    adapter
        .store_restore(&admin(), "backup-2026-09-05")
        .expect("store_restore");

    let state = adapter.shim_state();
    assert_eq!(
        state.slices_outstanding, 0,
        "slices do not survive a restore"
    );
    assert_eq!(
        state.slices_granted, 0,
        "and neither does the count of what they granted — a counter describing an empty map is a \
         figure with nothing behind it"
    );
    // The seam still works after the reseal: a fresh draw is counted from zero.
    adapter.reserve(&slice_request(7, 0)).expect("reserve");
    assert_eq!(adapter.shim_state().slices_granted, 7);
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
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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

/// `reseal_epoch_floor` moves the floor to the shim's epoch.
#[test]
fn the_verb_seam_reseals_the_epoch_floor() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    adapter
        .reseal_epoch_floor(&admin())
        .expect("reseal_epoch_floor");
    assert_eq!(adapter.shim_state().epoch_floor, adapter.epoch().0);
}

/// The sealed cache: a first sighting is `None` and RESERVES the slot, a commit fixes the bytes,
/// and a replay returns exactly those bytes — the whole point of the seam.
#[test]
fn the_verb_seam_replay_cache_reserves_then_replays_the_committed_bytes() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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

/// The shipper acknowledges a batch, counts it, and remembers the last identity.
#[test]
fn the_shipper_seam_acknowledges_a_batch_and_keeps_the_head() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
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

/// Run every seam method once, collecting failures rather than stopping at the first.
fn sweep_every_seam_method(adapter: &StoreAdapter, failures: &mut Vec<String>) {
    let mut note = |what: &str, err: String| failures.push(format!("{what}: {err}"));

    match adapter.reserve(&slice_request(3, 0)) {
        Ok(grant) => {
            if let Err(e) = adapter.release(grant.id, 1) {
                note("release", format!("{e:?}"));
            }
        }
        Err(e) => note("reserve", format!("{e:?}")),
    }
    if adapter.epoch() != Epoch(0) {
        note("epoch", format!("{:?}", adapter.epoch()));
    }
    if let Err(e) = adapter.chain_break(&admin()) {
        note("chain_break", format!("{e:?}"));
    }
    if let Err(e) = adapter.store_restore(&admin(), "b-1") {
        note("store_restore", format!("{e:?}"));
    }
    if let Err(e) = adapter.reseal_epoch_floor(&admin()) {
        note("reseal_epoch_floor", format!("{e:?}"));
    }
    let key = ("export_keyset".to_string(), "sweep".to_string());
    if let Err(e) = adapter.replay_new_verb(&key) {
        note("replay_new_verb", format!("{e:?}"));
    }
    if let Err(e) = adapter.commit_new_verb_replay(&key, b"ok") {
        note("commit_new_verb_replay", format!("{e:?}"));
    }
    if let Err(e) = adapter.shipper().ship(&[Record::new(1, 1, b"r".to_vec())]) {
        note("ship", format!("{e:?}"));
    }
}

/// The appendix's rule, on the adapter's own surface: every operation this release adds, invoked on
/// a store at the published schema, answers from the shim with NO error and NO log line. Repeated,
/// so the silence is the rule and not a warn-once latch's first pass.
#[test]
fn every_added_operation_on_a_published_schema_store_is_silent_and_never_errors() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    assert!(
        !adapter.speaks_new_ops(),
        "the fixture must be a store that predates the added operations"
    );
    let log = EventLog::default();
    let mut failures: Vec<String> = Vec::new();
    tracing::subscriber::with_default(log.clone(), || {
        for _ in 0..25 {
            sweep_every_seam_method(&adapter, &mut failures);
        }
    });
    assert!(
        failures.is_empty(),
        "no seam method may error on a store at the published payload schema; failures:\n{}",
        failures.join("\n")
    );
    let lines = log.lines();
    assert!(
        lines.is_empty(),
        "no log line may fire for an added operation on a store at the published schema; \
         captured:\n{}",
        lines.join("\n")
    );
}

/// The published operations are not touched by the adapter: the store it hands out is the loaded
/// plugin, and its rows are the plugin's.
#[test]
fn the_published_operations_pass_through_the_adapter_to_the_plugin() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    assert_eq!(
        adapter.abi_version(),
        crate::registry::STORE_ABI_FLOOR,
        "the adapter carries the schema the manifest declared"
    );
    let row = VirtualKey {
        id: "vk_pass".to_string(),
        generation_hash: "gen".to_string(),
        name: "legacy".to_string(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    let body = serde_json::to_vec(&StoreResponse::Keys(vec![row])).expect("serialize");
    let leaked: &'static [u8] = Box::leak(body.into_boxed_slice());
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_OK, leaked)));
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

/// Two handles onto one adapter are one shim: the kernel's slice draw and the verbs unit's restore
/// see each other, because the root binds all three seams to the SAME store.
#[test]
fn the_three_seams_share_one_shim() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let slices: Arc<dyn SliceStore> = adapter.slice_store();
    let verbs: Arc<dyn VerbStore + Send + Sync> = adapter.verb_store();
    let mut shipper = adapter.shipper();

    slices.reserve(&slice_request(9, 0)).expect("reserve");
    shipper
        .ship(&[Record::new(2, 1, b"x".to_vec())])
        .expect("ship");
    assert_eq!(adapter.shim_state().slices_outstanding, 1);
    assert_eq!(adapter.shim_state().records_shipped, 1);
    verbs.store_restore(&admin(), "b-2").expect("store_restore");
    assert_eq!(
        adapter.shim_state().slices_outstanding,
        0,
        "the verbs unit's restore is visible to the kernel's slice seam: one shim, one node"
    );
}

// ---------------------------------------------------------------------------------------------
// The round trip through the PUBLISHED sqlite store.
// ---------------------------------------------------------------------------------------------

/// The published sqlite store tarball, fetched by pinned digest into the oracle cache by
/// `testing/shadow-oracle/fetch-plugin.sh`. `None` when the cache is cold — the script downloads on
/// demand and a unit test must not, so this reads the cache the oracle already fills.
pub(super) fn cached_published_sqlite_tarball() -> Option<std::path::PathBuf> {
    let asset_triple = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        _ => return None,
    };
    let root = match std::env::var_os("BUSBAR_ORACLE_CACHE") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::path::PathBuf::from(std::env::var_os("HOME")?).join(".cache/busbar-oracle"),
    };
    let versions = std::fs::read_dir(root.join("plugins/store-sqlite")).ok()?;
    versions
        .flatten()
        .filter_map(|tag| {
            std::fs::read_dir(tag.path())
                .ok()?
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains(asset_triple) && n.ends_with(".tar.gz"))
                })
        })
        .max()
}

/// A round trip through the REAL published store: the adapter hands out the loaded plugin, a key
/// written through it comes back from sqlite, and every added operation is still the shim's silent
/// answer on the same handle.
///
/// This is the artifact the oracle's store-persist cell drives — the same tarball, by the same
/// pinned digest — so what it proves about the published wire and what this proves about the
/// adapter are about one binary.
#[test]
fn a_round_trip_through_the_published_sqlite_store() {
    let Some(tarball_path) = cached_published_sqlite_tarball() else {
        eprintln!(
            "skip: no published store-sqlite tarball in the oracle cache (run \
             `testing/shadow-oracle/fetch-plugin.sh store-sqlite`)"
        );
        return;
    };
    let bytes = std::fs::read(&tarball_path).expect("read the cached published tarball");
    let unpacked = tarball::unpack(&bytes).expect("the published tarball unpacks");
    assert_eq!(unpacked.manifest.kind, "store");
    assert_eq!(
        unpacked.manifest.abi_version,
        crate::registry::STORE_ABI_FLOOR,
        "the published sqlite store is a store at the published payload schema"
    );

    let db = std::env::temp_dir().join(format!(
        "busbar-store-adapter-roundtrip-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db);
    let cfg = serde_json::json!({ "db_path": db.to_string_lossy() }).to_string();
    let store = match load_dyn_store_from_bytes_at_abi(
        &unpacked.lib_bytes,
        &cfg,
        "published-store-sqlite",
        &unpacked.manifest.kind,
        unpacked.manifest.abi_version,
    ) {
        Ok(store) => store,
        Err(e) => panic!("the published sqlite store must load on this binary: {e}"),
    };
    let adapter = StoreAdapter::over_loaded_store(store);
    assert!(
        !adapter.speaks_new_ops(),
        "a published store predates the added operations"
    );

    // The published wire: write a key through the adapter's pass-through handle and read it back
    // out of sqlite.
    let key = VirtualKey {
        id: "vk_roundtrip".to_string(),
        generation_hash: "gen".to_string(),
        name: "adapter-roundtrip".to_string(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    adapter
        .store()
        .put_key(&key)
        .expect("the published wire takes a key");
    let read_back = adapter
        .store()
        .get_key("vk_roundtrip")
        .expect("the published wire reads a key")
        .expect("the row is there");
    assert_eq!(read_back.id, "vk_roundtrip");
    assert_eq!(read_back.name, "adapter-roundtrip");

    // And on the same handle, every added operation is the shim's silent answer.
    let log = EventLog::default();
    let mut failures: Vec<String> = Vec::new();
    tracing::subscriber::with_default(log.clone(), || {
        sweep_every_seam_method(&adapter, &mut failures);
    });
    assert!(
        failures.is_empty(),
        "on the published sqlite store no seam method may error; failures:\n{}",
        failures.join("\n")
    );
    assert!(
        log.lines().is_empty(),
        "on the published sqlite store no seam method may log; captured:\n{}",
        log.lines().join("\n")
    );
    assert_eq!(adapter.shim_state().records_shipped, 1);

    drop(adapter);
    let _ = std::fs::remove_file(&db);
}
