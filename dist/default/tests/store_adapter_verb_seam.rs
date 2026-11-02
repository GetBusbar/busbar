// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_loader::store_adapter::{ShimClock, StoreAdapter, REPLAY_TTL_SECS};
use std::sync::Arc;

const PUBLISHED_STORE_SCHEMA: u32 = 2;

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

fn adapter_over_published_schema() -> StoreAdapter {
    StoreAdapter::new(backing(), PUBLISHED_STORE_SCHEMA)
}

fn backing() -> Arc<dyn busbar_contract::records::RecordStore> {
    Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new())
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

fn adapter_at(clock: &TestClock) -> StoreAdapter {
    StoreAdapter::with_clock(backing(), PUBLISHED_STORE_SCHEMA, clock.shim_clock())
}

fn replay_key(name: &str) -> (String, String) {
    ("set_operator_key".to_string(), name.to_string())
}

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

fn sweep_every_seam_method(adapter: &StoreAdapter, failures: &mut Vec<String>) {
    let mut note = |what: &str, err: String| failures.push(format!("{what}: {err}"));

    let key = ("export_keyset".to_string(), "sweep".to_string());
    if let Err(e) = adapter.replay_new_verb(&key) {
        note("replay_new_verb", format!("{e:?}"));
    }
    if let Err(e) = adapter.commit_new_verb_replay(&key, b"ok") {
        note("commit_new_verb_replay", format!("{e:?}"));
    }
}

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
