// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::export_calls::{ExportCustodyLevel, ExportDropReason};
use busbar_contract::export_stream::ExportStream;
use std::sync::atomic::{AtomicU64, Ordering};

fn dropped(lines: u64) -> ExportObservation {
    ExportObservation::Dropped {
        reason: ExportDropReason::QueueFull,
        lines,
    }
}

#[test]
fn export_reservation_refuses_whole_candidate_at_shared_capacity() {
    let owner = ExportObservers::new();
    let active = owner
        .reserve((0..MAX_PENDING_AUDIT).map(|i| format!("active-{i}")))
        .unwrap()
        .commit();
    let refusal = owner.reserve(["active-0".into(), "new-name".into()]);
    assert!(
        refusal.is_err(),
        "all retained names share the native audit capacity"
    );
    assert_eq!(owner.state.lock().unwrap().cells.len(), MAX_PENDING_AUDIT);
    active.observer("active-0").unwrap().observe(dropped(4));
    assert_eq!(
        owner.unresolved()[0].count,
        4,
        "existing generation remains usable"
    );
}

#[test]
fn export_first_loss_survives_churn_and_atomic_reservation_refusal() {
    let owner = ExportObservers::new();
    for i in 0..MAX_PENDING_AUDIT {
        let name = format!("removed-{i}");
        let generation = owner.reserve([name.clone()]).unwrap().commit();
        generation.observer(&name).unwrap().observe(dropped(3));
    }
    assert_eq!(owner.unresolved().len(), MAX_PENDING_AUDIT);
    assert!(owner.reserve(["overflow".into()]).is_err());
    assert_eq!(owner.state.lock().unwrap().cells.len(), MAX_PENDING_AUDIT);
    let original = owner.reserve(["removed-0".into()]).unwrap();
    original
        .observer("removed-0")
        .unwrap()
        .observe(ExportObservation::IntegrityFailed);
    assert_eq!(
        owner
            .unresolved()
            .iter()
            .find(|f| f.instance == "removed-0")
            .unwrap()
            .count,
        3
    );
}

#[test]
fn same_name_generations_share_a_cell_and_rollback_preserves_losses() {
    let owner = ExportObservers::new();
    let first = owner.reserve(["same".into()]).unwrap().commit();
    let second = owner.reserve(["same".into(), "unused".into()]).unwrap();
    assert!(Arc::ptr_eq(
        &first.observers["same"].cell,
        &second.observers["same"].cell
    ));
    let never_published = second.observer("unused").unwrap();
    never_published.observe(ExportObservation::IntegrityFailed);
    drop(never_published);
    drop(second);
    assert_eq!(
        owner.state.lock().unwrap().cells.len(),
        2,
        "unpublished loss remains owned"
    );
    let clean = owner.reserve(["clean".into()]).unwrap();
    drop(clean);
    assert!(!owner.state.lock().unwrap().cells.contains_key("clean"));
    assert_eq!(owner.unresolved()[0].instance, "unused");
}

fn facts(count: u64) -> ExportLossFacts {
    ExportLossFacts {
        instance: "sink".into(),
        observed_at: 41,
        count,
        kind: ExportLossKind::Dropped(ExportDropReason::Stopped),
    }
}

#[test]
fn first_loss_freezes_facts_and_owned_unknown_never_transfers_again() {
    let mut first = FirstLoss::<Arc<AtomicU64>>::default();
    assert!(first.record(facts(7)));
    let mut later = facts(9);
    later.observed_at = 99;
    later.kind = ExportLossKind::IntegrityFailed;
    assert!(!first.record(later));
    let calls = AtomicU64::new(0);
    assert!(
        first.step(
            |seen| {
                assert_eq!(seen, &facts(7));
                None
            },
            |_| false
        ),
        "one retry warning"
    );
    assert!(!first.step(|_| None, |_| false), "retry warning is bounded");
    let confirmed = Arc::new(AtomicU64::new(0));
    assert!(!first.step(
        |seen| {
            assert_eq!(seen, &facts(7));
            calls.fetch_add(1, Ordering::Relaxed);
            Some(confirmed.clone())
        },
        |_| false
    ));
    for _ in 0..5 {
        assert!(!first.step(
            |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                None
            },
            |receipt| receipt.load(Ordering::Acquire) != 0
        ));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!first.settled());
    confirmed.store(1, Ordering::Release);
    assert!(!first.step(
        |_| panic!("owned original must not transfer again"),
        |receipt| receipt.load(Ordering::Acquire) != 0
    ));
    assert!(first.settled());
    assert_eq!(first.facts, Some(facts(7)));
    assert!(
        !first.record(facts(20)),
        "confirmation does not reset first-loss identity"
    );
}

#[test]
fn confirmed_removed_cell_waits_for_the_retiring_producer() {
    let owner = ExportObservers::new();
    let candidate = owner.reserve(["retiring".into()]).unwrap();
    let producer = candidate.observer("retiring").unwrap();
    let generation = candidate.commit();
    producer.observe(dropped(2));
    // Receipt confirmation itself is exercised against real native storage in
    // auditlog_native_tests. Here the reclamation transition receives that confirmed state.
    owner.state.lock().unwrap().cells["retiring"]
        .state
        .lock()
        .unwrap()
        .first
        .confirmed = true;
    drop(generation);
    let new = owner.reserve(["other".into()]).unwrap();
    assert!(owner.state.lock().unwrap().cells.contains_key("retiring"));
    drop(producer);
    let next = owner.reserve(["last".into()]).unwrap();
    assert!(!owner.state.lock().unwrap().cells.contains_key("retiring"));
    drop((new, next));
}

#[test]
fn shutdown_requires_closed_intake_settled_evidence_and_no_late_callback() {
    let owner = ExportObservers::new();
    let generation = owner.reserve(["sink".into()]).unwrap().commit();
    assert!(!owner.is_settled(), "intake still accepts observations");
    owner.stop_intake();
    assert!(owner.is_settled());
    generation
        .observer("sink")
        .unwrap()
        .observe(ExportObservation::Held { lines: 3 });
    assert!(
        !owner.is_settled(),
        "even a non-loss callback violates quiescence"
    );
    assert!(owner.reserve(["late-config".into()]).is_err());
}

#[derive(Default)]
struct Gauge(AtomicU64);
impl metrics::GaugeFn for Gauge {
    fn increment(&self, value: f64) {
        self.set(f64::from_bits(self.0.load(Ordering::Relaxed)) + value);
    }
    fn decrement(&self, value: f64) {
        self.increment(-value);
    }
    fn set(&self, value: f64) {
        self.0.store(value.to_bits(), Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Recorder {
    counters: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    gauges: Mutex<BTreeMap<String, Arc<Gauge>>>,
}
fn metric_key(key: &metrics::Key) -> String {
    let mut labels: Vec<_> = key
        .labels()
        .map(|label| format!("{}={}", label.key(), label.value()))
        .collect();
    labels.sort();
    format!("{}{{{}}}", key.name(), labels.join(","))
}
impl metrics::Recorder for Recorder {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::from_arc(
            self.counters
                .lock()
                .unwrap()
                .entry(metric_key(key))
                .or_default()
                .clone(),
        )
    }
    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::from_arc(
            self.gauges
                .lock()
                .unwrap()
                .entry(metric_key(key))
                .or_default()
                .clone(),
        )
    }
    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

#[test]
fn actual_recorder_distinguishes_lines_occurrences_and_absolute_held() {
    let owner = ExportObservers::new();
    let candidate = owner.reserve(["facts".into()]).unwrap();
    let observer = candidate.observers["facts"].clone();
    let recorder = Recorder::default();
    metrics::with_local_recorder(&recorder, || {
        observer.observe_at(ExportObservation::Held { lines: 20 }, 1);
        observer.observe_at(ExportObservation::Held { lines: 3 }, 2);
        observer.observe_at(
            ExportObservation::Custody {
                stream: ExportStream::Events,
                level: ExportCustodyLevel::Durable,
                lines: 8,
            },
            3,
        );
        observer.observe_at(dropped(0), 4);
        assert!(owner.unresolved().is_empty());
        observer.observe_at(dropped(7), 5);
        observer.observe_at(dropped(2), 6);
        observer.observe_at(ExportObservation::CaptureRefused, 7);
        observer.observe_at(ExportObservation::IntegrityFailed, 8);
    });
    let counters = recorder.counters.lock().unwrap();
    assert_eq!(
        counters["busbar_export_dropped_total{instance=facts,reason=queue_full}"]
            .load(Ordering::Relaxed),
        9
    );
    assert_eq!(
        counters["busbar_export_custody_total{instance=facts,level=durable,stream=events}"]
            .load(Ordering::Relaxed),
        8
    );
    assert_eq!(
        counters["busbar_export_capture_refusals_total{instance=facts,reason=admission_rejected}"]
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        counters["busbar_export_audit_integrity_failures_total{instance=facts}"]
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(counters.len(), 4);
    let gauges = recorder.gauges.lock().unwrap();
    assert_eq!(
        f64::from_bits(
            gauges["busbar_export_held_lines{instance=facts,reason=key_unavailable}"]
                .0
                .load(Ordering::Relaxed)
        ),
        3.0
    );
    let loss = &owner.unresolved()[0];
    assert_eq!(
        (loss.observed_at, loss.count, loss.kind),
        (5, 7, ExportLossKind::Dropped(ExportDropReason::QueueFull))
    );
}

#[test]
fn custody_wire_values_have_only_the_positive_frozen_labels() {
    assert_eq!(ExportCustodyLevel::from_wire(0), None);
    assert_eq!(ExportCustodyLevel::from_wire(4), None);
    assert_eq!(ExportCustodyLevel::from_wire(u32::MAX), None);
    for (wire, token) in [(1, "accepted"), (2, "durable"), (3, "indexed")] {
        assert_eq!(ExportCustodyLevel::from_wire(wire).unwrap().as_str(), token);
    }
}

#[tokio::test(start_paused = true)]
async fn periodic_retry_survives_coalesced_notification_without_another_loss() {
    let owner = ExportObservers::new();
    let generation = owner.reserve(["quiet".into()]).unwrap().commit();
    generation.observer("quiet").unwrap().observe(dropped(6));
    for _ in 0..100 {
        owner.wake.notify_one();
    }
    let (stop, stopping) = watch::channel(false);
    let attempts = Arc::new(AtomicU64::new(0));
    let observed = attempts.clone();
    let worker = tokio::spawn(owner.clone().run_with(stopping, move |owner| {
        assert_eq!(owner.unresolved()[0].count, 6);
        observed.fetch_add(1, Ordering::Relaxed);
    }));
    tokio::task::yield_now().await;
    let before = attempts.load(Ordering::Relaxed);
    assert!(before > 0);
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(
        attempts.load(Ordering::Relaxed) > before,
        "periodic retry needs no later event or notification"
    );
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(
        owner.unresolved()[0].count,
        6,
        "worker stop never discards pending facts"
    );
}
