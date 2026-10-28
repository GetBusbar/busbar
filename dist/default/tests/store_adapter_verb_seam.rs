// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store adapter's node-memory seams — the kernel's slices and the sealed new-verb replay cache
//! the root's verb store answers through it — against a store at the PUBLISHED payload schema, from
//! `busbar-plugin-loader`'s `src/tests/store_adapter_tests.rs` (whose module doc states the three
//! things that file and this one prove together).
//!
//! The disaster-recovery verbs are not the adapter's (status row 187): the root's verb store answers
//! them over the node's journal and the store's record slots, and its cells are the root's
//! `durability_recovery` tests.
//!
//! It lives in the composition root's integration suite (ARCHITECT C4B-1, 2026-10-03), beside the
//! root that binds the adapter.

use busbar_contract::slice::{bucket_all, CapDimension, Epoch, SliceRequest, SliceStore};
use busbar_plugin_loader::store_adapter::{ShimClock, StoreAdapter, REPLAY_TTL_SECS};
use std::sync::Arc;

/// The published store payload schema (v2). The loader refuses v2 at scan (ruling C21/ABI-o1); the
/// adapter's shim rule is a property of the schema number, so this suite binds an adapter at it.
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

/// An adapter over a store bound to the PUBLISHED payload schema (2), built through the same
/// constructor the composition root calls.
fn adapter_over_published_schema() -> StoreAdapter {
    StoreAdapter::new(backing(), PUBLISHED_STORE_SCHEMA)
}

/// The kernel's universal test double (the build's default store), as the published operations'
/// backing.
fn backing() -> Arc<dyn busbar_contract::records::RecordStore> {
    Arc::new(busbar_kernel::governance::MemoryStore::new())
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
fn adapter_at(clock: &TestClock) -> StoreAdapter {
    StoreAdapter::with_clock(backing(), PUBLISHED_STORE_SCHEMA, clock.shim_clock())
}

fn replay_key(name: &str) -> (String, String) {
    ("set_operator_key".to_string(), name.to_string())
}

/// `epoch` is the one generation a node-local shim has, and it stays put.
#[test]
fn the_slice_seam_epoch_is_constant() {
    let adapter = adapter_over_published_schema();
    assert_eq!(adapter.epoch(), Epoch(0));
    adapter.reserve(&slice_request(1, 0)).expect("reserve");
    assert_eq!(
        adapter.epoch(),
        Epoch(0),
        "nothing on a node-local shim can advance the epoch"
    );
}

/// A committed sealed replay slot answers its bytes for the window and is gone after it.
#[test]
fn a_committed_slot_answers_inside_the_window_and_expires_after_it() {
    let clock = TestClock::default();
    let adapter = adapter_at(&clock);
    let key = replay_key("idem-a");
    adapter.replay_new_verb(&key).expect("first sighting");
    adapter
        .commit_new_verb_replay(&key, b"the minted key")
        .expect("commit");
    assert_eq!(
        adapter.replay_new_verb(&key).expect("inside the window"),
        Some(b"the minted key".to_vec())
    );

    clock.advance(REPLAY_TTL_SECS);
    assert_eq!(
        adapter.replay_new_verb(&key).expect("past the window"),
        None
    );
    assert_eq!(
        adapter.shim_state().replay_committed,
        0,
        "the slot did not survive its TTL"
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
    let key = ("export_keyset".to_string(), "sweep".to_string());
    if let Err(e) = adapter.replay_new_verb(&key) {
        note("replay_new_verb", format!("{e:?}"));
    }
    if let Err(e) = adapter.commit_new_verb_replay(&key, b"ok") {
        note("commit_new_verb_replay", format!("{e:?}"));
    }
}

/// On the adapter's own surface: every seam it answers from node memory, invoked on a store at the
/// published schema, answers with NO error and NO log line. Repeated, so the silence is the rule
/// and not a warn-once latch's first pass. (The journal is not among them: the adapter is no
/// shipper; the node's journal is kept by the store's record slots.)
#[test]
fn every_added_operation_on_a_published_schema_store_is_silent_and_never_errors() {
    let adapter = adapter_over_published_schema();
    assert_eq!(
        adapter.abi_version(),
        PUBLISHED_STORE_SCHEMA,
        "the fixture must be a store at the published payload schema"
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
