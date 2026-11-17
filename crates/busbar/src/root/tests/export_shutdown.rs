// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::Fixture;
use super::*;
use crate::root::export_observer::ExportObservers;
use busbar_contract::export_calls::{ExportDropReason, ExportObservation};

#[tokio::test]
async fn clean_shutdown_closes_the_actual_observer_before_retirement() {
    let fixture = Fixture::new(16).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, _) = fixture.post(false, None, &shutdown_tx, None);
    let observers = Arc::clone(&post.export_observers);
    assert!(
        !observers.is_settled(),
        "intake is still open while serving"
    );
    let drain = ShutdownDrain::new(DrainClock::new(Duration::from_secs(5)));
    super::tests::coordinate_test(&drain, &shutdown_tx);

    assert_eq!(finish(post, &drain).await, 0);
    assert!(observers.is_settled());
    assert!(observers.reserve(["after-retirement".into()]).is_err());
}

#[tokio::test]
async fn late_observation_refuses_retirement_and_preserves_native_intake() {
    let fixture = Fixture::new(16).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let observers = Arc::clone(&post.export_observers);
    let generation = observers.reserve(["late-capture".into()]).unwrap().commit();
    observers.stop_intake();
    generation
        .observer("late-capture")
        .unwrap()
        .observe(ExportObservation::Held { lines: 1 });
    let drain = ShutdownDrain::new(DrainClock::new(Duration::from_secs(5)));
    super::tests::coordinate_test(&drain, &shutdown_tx);

    assert_eq!(finish(post, &drain).await, 75);
    assert_eq!(observers.late_callbacks(), 1);
    assert!(!observers.is_settled());
    assert!(export_settlement::failures(&observers)
        .iter()
        .any(|line| line.contains("1 late callbacks")));
    seen.journal
        .stage_run(&[busbar_kernel_wal::Entry::new(
            busbar_kernel_wal::RecordClass::Load,
            vec![4; 24],
        )])
        .expect("unsettled observer cannot close native intake");
    seen.still_admitted().await;
}

#[tokio::test]
async fn observation_during_lease_release_still_refuses_writer_retirement() {
    let fixture = Fixture::new(16).await;
    let gate = Arc::new(super::tests::FlushGate::default());
    *fixture.seen.backend.other.lock().unwrap() = Some(Arc::clone(&gate));
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let observers = Arc::clone(&post.export_observers);
    let generation = observers.reserve(["retiring".into()]).unwrap().commit();
    let drain = ShutdownDrain::new(DrainClock::new(Duration::from_secs(5)));
    super::tests::coordinate_test(&drain, &shutdown_tx);
    let finished = async {
        assert_eq!(finish(post, &drain).await, 75);
    };
    let late = async {
        gate.entered().await;
        assert!(observers.is_settled(), "the earlier receipt check passed");
        generation
            .observer("retiring")
            .unwrap()
            .observe(ExportObservation::Held { lines: 1 });
        gate.release();
    };
    tokio::join!(finished, late);
    assert_eq!(observers.late_callbacks(), 1);
    seen.still_admitted().await;
}

#[tokio::test]
async fn expired_shared_cut_preserves_exact_untransferred_loss() {
    let observers = ExportObservers::new();
    let generation = observers.reserve(["cutoff".into()]).unwrap().commit();
    generation
        .observer("cutoff")
        .unwrap()
        .observe(ExportObservation::Dropped {
            reason: ExportDropReason::Stopped,
            lines: 7,
        });
    let before = observers.unresolved();
    observers.stop_intake();
    let clock = DrainClock::new(Duration::from_secs(20));
    let deadline = Instant::now() - Duration::from_secs(1);
    clock.arm(deadline);

    let result = settle_export_observations(Arc::clone(&observers), Arc::clone(&clock)).await;
    assert!(result.is_err());
    assert_eq!(clock.armed_at(), Some(deadline), "no fresh export budget");
    assert_eq!(observers.unresolved(), before);
    assert!(!observers.is_settled());
    assert!(export_settlement::failures(&observers)
        .iter()
        .any(|line| line.contains("count=7")));
}

#[tokio::test]
async fn forced_shared_cut_does_not_accept_even_an_empty_receipt_pass() {
    let observers = ExportObservers::new();
    observers.stop_intake();
    let clock = DrainClock::new(Duration::from_secs(20));
    clock.arm(Instant::now() + clock.budget());
    clock.expire_now();
    assert!(settle_export_observations(observers, clock).await.is_err());
}

#[tokio::test]
async fn retained_loss_reaches_actual_native_confirmation_before_retry_worker_stops() {
    busbar_kernel::audit::auditlog::ensure_global_audit_stream_registered().await;
    let observers = ExportObservers::new();
    let name = format!(
        "shutdown-receipt-{}",
        busbar_kernel::door::op_id().counter()
    );
    let generation = observers.reserve([name.clone()]).unwrap().commit();
    let retry = ExportRetry::start(Arc::clone(&observers));
    generation
        .observer(&name)
        .unwrap()
        .observe(ExportObservation::Dropped {
            reason: ExportDropReason::Stopped,
            lines: 9,
        });
    observers.stop_intake();
    let clock = DrainClock::new(Duration::from_secs(5));
    clock.arm(Instant::now() + clock.budget());
    let drain = ShutdownDrain::new(Arc::clone(&clock));

    assert!(matches!(
        drain
            .bounded(
                Phase::Audit,
                DrainHandle::spawn(settle_export_observations(Arc::clone(&observers), clock)),
                Cut::Deadline,
            )
            .await,
        Joined::Done(Ok(Ok(())))
    ));
    assert!(observers.is_settled());
    assert!(observers.unresolved().is_empty());
    assert!(matches!(
        drain
            .bounded(
                Phase::Audit,
                DrainHandle::adopt(retry.stop()),
                Cut::Deadline,
            )
            .await,
        Joined::Done(Ok(()))
    ));
    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(0, usize::MAX, None, None);
    let recorded: Vec<_> = rows
        .iter()
        .filter(|row| row.action == "export.loss" && row.instance.as_deref() == Some(name.as_str()))
        .collect();
    assert_eq!(
        recorded.len(),
        1,
        "the retained first loss has one native original"
    );
}
