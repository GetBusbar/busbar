// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter's seams that take a minted token, against a store at the PUBLISHED payload
//! schema, from `busbar-plugin-loader`'s `src/tests/store_adapter_tests.rs` (whose module doc
//! states the three things that file and this one prove together). The verb seam takes a
//! `Grant<AdminVerb>`; this suite takes it from the kernel's test token helper, and drives the
//! loader's fake-call store harness and oracle-cache locator through its `test-support` feature.
//!
//! It lives in the composition root's integration suite, not in busbar-kernel (ARCHITECT C4B-1,
//! 2026-10-03): the store proof it loads is `busbar-store-memory`'s cold door, and the root is the
//! crate that links that store as the shipped plugin; the kernel names no store crate.

use busbar_contract::caps::{AdminVerb, Grant};
use busbar_contract::records::VirtualKey;
use busbar_contract::slice::{bucket_all, CapDimension, Epoch, SliceRequest, SliceStore};
use busbar_contract::verb_store::Store as VerbStore;
use busbar_kernel_wal::Record;
use busbar_plugin_loader::store_adapter::{ShimClock, StoreAdapter, REPLAY_TTL_SECS};
use busbar_plugin_loader::test_support::{self, dyn_proof_store_with_fake_call_at_abi};
use std::sync::Arc;

/// The published store payload schema (v2), the value `registry::STORE_ABI_FLOOR` held before C21
/// (ruling C21/ABI-o1) deleted it: the loader now refuses v2 at scan, so this suite loads it directly.
const PUBLISHED_STORE_SCHEMA: u32 = 2;

/// The `tracing` capture the store-adapter tests assert silence with, carried from
/// `busbar-plugin-loader`'s `src/tests/abi2_store_ops_tests.rs` (where it stays for its own tests).
mod event_log {
    use std::sync::{Arc, Mutex};

    /// Every `tracing` event that fired on this thread while a subscriber built from this was
    /// installed, rendered as `LEVEL message field=value ...`.
    #[derive(Clone, Default)]
    pub struct EventLog(Arc<Mutex<Vec<String>>>);

    impl EventLog {
        pub fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    impl tracing::Subscriber for EventLog {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Render(String);
            impl tracing::field::Visit for Render {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={:?}", field.name(), value));
                }
            }
            let mut r = Render(format!("{}", event.metadata().level()));
            event.record(&mut r);
            self.0.lock().unwrap_or_else(|p| p.into_inner()).push(r.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
}
use event_log::EventLog;

/// The verbs unit's admin token. Minting one is what the kernel does for the length of an admin
/// verb; a test standing in for the kernel takes one from the kernel's test token helper.
fn admin() -> Grant<AdminVerb> {
    busbar_kernel::test_support::tokens::grant::<AdminVerb>()
}

/// An adapter over a store bound to the PUBLISHED payload schema (2), built through the same
/// constructor the composition root calls.
fn adapter_over_published_schema() -> Option<StoreAdapter> {
    let store = dyn_proof_store_with_fake_call_at_abi(PUBLISHED_STORE_SCHEMA)?;
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
    // The schema the store is bound to is the one handed to the harness: `DynStore`'s own field is
    // the loader's, so the test names the value it passed rather than reading it back.
    let abi_version = PUBLISHED_STORE_SCHEMA;
    let store = dyn_proof_store_with_fake_call_at_abi(abi_version)?;
    Some(StoreAdapter::with_clock(
        Arc::new(store),
        abi_version,
        clock.shim_clock(),
    ))
}

fn replay_key(name: &str) -> (String, String) {
    ("set_operator_key".to_string(), name.to_string())
}

/// `epoch` is the one generation a node-local shim has, and it stays put.
#[test]
fn the_slice_seam_epoch_is_constant() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: the store proof's cdylib is not built");
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
        eprintln!("skip: the store proof's cdylib is not built");
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
        eprintln!("skip: the store proof's cdylib is not built");
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
        eprintln!("skip: the store proof's cdylib is not built");
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

/// `reseal_epoch_floor` moves the floor to the shim's epoch.
#[test]
fn the_verb_seam_reseals_the_epoch_floor() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: the store proof's cdylib is not built");
        return;
    };
    adapter
        .reseal_epoch_floor(&admin())
        .expect("reseal_epoch_floor");
    assert_eq!(adapter.shim_state().epoch_floor, adapter.epoch().0);
}

/// A restore keeps the sealed slots — and keeps them ageing, so surviving a restore is not a way for
/// a slot to outlive its window.
#[test]
fn a_slot_that_survives_a_restore_still_expires() {
    let clock = TestClock::default();
    let Some(adapter) = adapter_at(&clock) else {
        eprintln!("skip: the store proof's cdylib is not built");
        return;
    };
    let key = replay_key("idem-a");
    adapter.replay_new_verb(&key).expect("first sighting");
    adapter
        .commit_new_verb_replay(&key, b"the minted key")
        .expect("commit");
    adapter
        .store_restore(&admin(), "a-backup")
        .expect("store_restore");
    assert_eq!(adapter.shim_state().replay_slots, 1);

    clock.advance(REPLAY_TTL_SECS);
    assert_eq!(
        adapter.replay_new_verb(&key).expect("past the window"),
        None
    );
    assert_eq!(
        adapter.shim_state().replay_committed,
        0,
        "the slot that survived the restore did not survive its TTL"
    );
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
        eprintln!("skip: the store proof's cdylib is not built");
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

/// Two handles onto one adapter are one shim: the kernel's slice draw and the verbs unit's restore
/// see each other, because the root binds all three seams to the SAME store.
#[test]
fn the_three_seams_share_one_shim() {
    let Some(adapter) = adapter_over_published_schema() else {
        eprintln!("skip: the store proof's cdylib is not built");
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

/// A round trip through the REAL published store: the adapter hands out the loaded plugin, a key
/// written through it comes back from sqlite, and every added operation is still the shim's silent
/// answer on the same handle.
///
/// This is the artifact the oracle's store-persist cell drives — the same tarball, by the same
/// pinned digest — so what it proves about the published wire and what this proves about the
/// adapter are about one binary.
#[test]
fn a_round_trip_through_the_published_store() {
    let Some(tarball_path) = test_support::cached_published_store_tarball() else {
        let id = test_support::artifact("published_store_plugin_id");
        eprintln!(
            "skip: no published {id} tarball in the oracle cache (run \
             `testing/shadow-oracle/fetch-plugin.sh {id}`)"
        );
        return;
    };
    let bytes = std::fs::read(&tarball_path).expect("read the cached published tarball");
    let unpacked =
        busbar_plugin_loader::tarball::unpack(&bytes).expect("the published tarball unpacks");
    assert_eq!(unpacked.manifest.kind, "store");
    assert_eq!(
        unpacked.manifest.abi_version, PUBLISHED_STORE_SCHEMA,
        "the published store is at the published payload schema"
    );

    let db = std::env::temp_dir().join(format!(
        "busbar-store-adapter-roundtrip-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db);
    let cfg = serde_json::json!({ "db_path": db.to_string_lossy() }).to_string();
    let store = match test_support::load_dyn_store_from_bytes_at_abi(
        &unpacked.lib_bytes,
        &cfg,
        "published-store",
        &unpacked.manifest.kind,
        unpacked.manifest.abi_version,
    ) {
        Ok(store) => store,
        Err(e) => panic!("the published store must load on this binary: {e}"),
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
        "on the published store no seam method may error; failures:\n{}",
        failures.join("\n")
    );
    assert!(
        log.lines().is_empty(),
        "on the published store no seam method may log; captured:\n{}",
        log.lines().join("\n")
    );
    assert_eq!(adapter.shim_state().records_shipped, 1);

    drop(adapter);
    let _ = std::fs::remove_file(&db);
}
