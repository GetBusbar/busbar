// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::upstreams::{ConfiguredUpstreams, ProgramPin, StdioCommand, UpstreamDef, UpstreamTls};

fn definition(name: &str, command: bool) -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        name: name.into(),
        resource: None,
        allow_private: false,
        url: (!command).then(|| "https://upstream.example".into()),
        command: command.then(|| StdioCommand {
            argv: vec!["/usr/bin/true".into()],
            env: vec![],
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s: 30,
        }),
        tls: UpstreamTls {
            pin_spki: vec![],
            client_identity: None,
            trust: None,
        },
        auth: None,
    })
}

fn table(definitions: &[Arc<UpstreamDef>]) -> Arc<ConfiguredUpstreams> {
    Arc::new(ConfiguredUpstreams::from_definitions(
        definitions
            .iter()
            .map(|d| (d.name.clone(), d.clone()))
            .collect(),
    ))
}

#[test]
fn command_scope_cannot_alias_a_catalog_or_an_unrelated_default_registration() {
    for name in ["p", "m"] {
        assert!(catalog_routes()
            .with_registrations(table(&[definition(name, true)]))
            .is_err());
    }
    let registrations = table(&[definition("seat", true), definition("http", false)]);
    let default = Arc::new(SeatPool::of("seat", &registrations).unwrap());
    assert!(RequestRoutes::new("seat", None, None, Some(default))
        .unwrap()
        .with_registrations(registrations)
        .is_err());
    let routes = RequestRoutes::new("seat", None, None, None)
        .unwrap()
        .with_registrations(table(&[definition("http", false)]))
        .unwrap();
    let (ctx, _lease) = context(31);
    assert!(
        allocation(ctx).registration(&routes, None, "http").is_err(),
        "a URL definition cannot become a command by selection"
    );
}

#[tokio::test]
async fn command_uses_original_pool_chain_and_one_request_count() {
    use crate::config::groups::{ExhaustionMode, GroupCfg};
    use crate::plane_driver::{EndPost, PlaneMoney};
    struct Posted;
    impl EndPost for Posted {
        fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    }
    let root: GroupCfg = busbar_contract::yaml::from_str(
        "limits:\n - {requests: 4, per: total}\n - {budget: 100, per: total}\n",
    )
    .unwrap();
    let leaf: GroupCfg = busbar_contract::yaml::from_str("parent: root\nlimits:\n - {requests: 1, per: total, pool: command}\n - {requests: 9, per: total, pool: other}\n - {budget: 70, per: total, pool: command}\n").unwrap();
    let cost = Arc::new(CostModel::resolve_parts(
        None,
        0,
        &[("root".into(), root), ("leaf".into(), leaf)].into(),
    ));
    let key = Arc::new(VirtualKey {
        id: "payer".into(),
        enabled: true,
        group: Some("leaf".into()),
        ..Default::default()
    });
    let plan = cost.plan_chain(&key).unwrap();
    let command = definition("command", true);
    let other = definition("other", true);
    let registrations = table(&[command.clone(), other]);
    let routes = RequestRoutes::new("seat", Some(Arc::from("server")), None, None)
        .unwrap()
        .with_registrations(registrations.clone())
        .unwrap();
    let (ctx, _lease) = context_with_key(32, key.clone());
    let receipt = RequestAllocation::new(ctx.clone(), cost.clone(), 100)
        .unwrap()
        .registration(&routes, None, "command")
        .unwrap();
    assert_eq!(receipt.pool(), "seat\u{1f}command");
    assert!(!ctx.effects_allowed());
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = PlaneMoney::new(gov.clone(), Arc::new(Posted));
    let admitted = money
        .admit_existing(
            receipt.begin().unwrap(),
            Arc::from([]),
            super::super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert_eq!(admitted.charge().chain(), Some(&plan));
    assert_eq!(admitted.pool(), "seat\u{1f}command");
    assert!(Arc::ptr_eq(
        admitted.registered_command().unwrap(),
        &command
    ));
    assert!(admitted.same_admission(&admitted.clone()));
    assert!(admitted.accepts_forward(&routes, None, Some("command")));
    assert!(!admitted.accepts_forward(&routes, None, Some("other")));
    assert!(!admitted.accepts_forward(&routes, Some("command"), Some("command")));
    let replacement = RequestRoutes::new("seat", Some(Arc::from("server")), None, None)
        .unwrap()
        .with_registrations(registrations)
        .unwrap();
    assert!(
        !admitted.accepts_forward(&replacement, None, Some("command")),
        "even identical definition Arcs cannot replace the request's frozen table"
    );
    let view = gov.admitted_view(&admitted).unwrap();
    assert_eq!(view.rate_headroom, Some(0.0));
    assert!(view
        .budgets
        .iter()
        .any(|b| b.pool.as_deref() == Some("command")));
    assert!(view
        .budgets
        .iter()
        .all(|b| b.pool.as_deref() != Some("other")));
    let (second, _lease2) = context_with_key(33, key.clone());
    let blocked = RequestAllocation::new(second.clone(), cost.clone(), 100)
        .unwrap()
        .registration(&routes, None, "command")
        .unwrap();
    assert!(money
        .admit_existing(
            blocked.begin().unwrap(),
            Arc::from([]),
            super::super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit
        )
        .is_err());
    assert!(!second.effects_allowed());
    let (other, _lease3) = context_with_key(34, key);
    let receipt = RequestAllocation::new(other, cost, 100)
        .unwrap()
        .registration(&routes, None, "other")
        .unwrap();
    let other = money
        .admit_existing(
            receipt.begin().unwrap(),
            Arc::from([]),
            super::super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert!(!admitted.same_admission(&other));
    assert_eq!(
        gov.admitted_view(&other).unwrap().rate_headroom,
        Some(0.5),
        "the refused duplicate must not increment the original shared parent count"
    );
}

#[tokio::test]
async fn same_scalar_unit_and_same_command_do_not_alias_another_real_admission() {
    let command = definition("command", true);
    let first = CommandAdmissionFixture::new(command.clone()).await;
    let second = CommandAdmissionFixture::new(command).await;
    assert_eq!(first.request.unit(), second.request.unit());
    assert!(Arc::ptr_eq(&first.definition, &second.definition));
    assert!(!first.request.same_admission(&second.request));
    let retained = first.request.clone();
    first.request.context().retire();
    assert!(
        first.request.same_admission(&retained),
        "identity stays stable for terminal cleanup"
    );
    assert!(!retained.is_live());
}

/// Ordinary terminal receipt r2 (B1): startup rollback of a native ordinary admission records
/// intent only. It must not settle the original Open before the actual checkpoint R
/// acknowledgement, retire the original registration, or mint a second bill.
#[tokio::test]
async fn native_ordinary_startup_rollback_retains_the_original_open() {
    use crate::config::groups::ExhaustionMode;
    use crate::plane_driver::{EndPost, PlaneMoney};
    struct Posted;
    impl EndPost for Posted {
        fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    }
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &Default::default()));
    let key = Arc::new(VirtualKey {
        id: "ordinary-rollback".into(),
        enabled: true,
        ..Default::default()
    });
    let routes = RequestRoutes::new("seat", None, None, None)
        .unwrap()
        .with_registrations(table(&[definition("command", true)]))
        .unwrap();
    let (ctx, _lease) = context_with_key(41, key);
    let receipt = RequestAllocation::new(ctx.clone(), cost, 100)
        .unwrap()
        .registration(&routes, None, "command")
        .unwrap();
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov, Arc::new(Posted)));
    let process = crate::limits::process_admission::ProcessAdmission::new(0);
    let lease = process
        .try_enter(crate::limits::process_admission::AdmissionClass::Data)
        .unwrap();
    let slot = crate::plane_driver::port_billing::NativeOrdinaryTerminalSlot::reserve(
        &ctx,
        &lease.storage(),
    )
    .unwrap();
    let admitted = money
        .admit_existing_ordinary(
            receipt.begin().unwrap(),
            &slot,
            Arc::from([]),
            super::super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert_eq!(money.open_units(), 1);
    let rollback = money.admission_rollback(&admitted).unwrap();
    drop(rollback);
    assert_eq!(
        money.open_units(),
        1,
        "native ordinary startup rollback destroyed the original Open before its receipt"
    );
}

/// The actual original checkpoint sink with an injectable held/failed R acknowledgement.
#[derive(Default)]
struct GatedCheckpoints {
    held: std::sync::Mutex<Vec<crate::governance::unit_checkpoint::UnitCheckpoint>>,
    refuse_remove: std::sync::atomic::AtomicBool,
    removed: std::sync::atomic::AtomicUsize,
    // Test-only stale-flush hook: change the pending entry while its R is at the sink.
    stale: std::sync::Mutex<Option<std::sync::Weak<GovState>>>,
}

#[async_trait::async_trait]
impl crate::governance::unit_checkpoint::UnitCheckpointSink for GatedCheckpoints {
    async fn persist(
        &self,
        snapshot: &crate::governance::unit_checkpoint::UnitCheckpoint,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        snapshot.validate()?;
        let mut held = self.held.lock().unwrap();
        held.retain(|kept| kept.id != snapshot.id);
        held.push(snapshot.clone());
        Ok(())
    }
    async fn remove(
        &self,
        snapshot: &crate::governance::unit_checkpoint::UnitCheckpoint,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        if self.refuse_remove.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(busbar_contract::records::RecordStoreError(
                "original R acknowledgement held".into(),
            ));
        }
        let stale = self.stale.lock().unwrap().take();
        if let Some(gov) = stale.and_then(|gov| gov.upgrade()) {
            assert!(gov.stale_pending_checkpoint_for_test(snapshot.id));
        }
        self.held
            .lock()
            .unwrap()
            .retain(|kept| kept.id != snapshot.id);
        self.removed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn replay(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<
        Vec<crate::governance::unit_checkpoint::UnitCheckpoint>,
    > {
        Ok(self.held.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct KeptRecovery(std::sync::Mutex<Vec<crate::governance::recovery::RecoveryEvent>>);

#[async_trait::async_trait]
impl crate::governance::recovery::RecoverySink for KeptRecovery {
    async fn persist(
        &self,
        event: &crate::governance::recovery::RecoveryEvent,
    ) -> Result<(), crate::governance::recovery::RecoveryError> {
        let mut held = self.0.lock().unwrap();
        if !held.contains(event) {
            held.push(event.clone());
        }
        Ok(())
    }
    async fn replay(
        &self,
    ) -> Result<
        Vec<crate::governance::recovery::RecoveryEvent>,
        crate::governance::recovery::RecoveryError,
    > {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct OrdinaryRig {
    money: Arc<crate::plane_driver::PlaneMoney>,
    gov: Arc<GovState>,
    sink: Arc<GatedCheckpoints>,
    admitted: AdmittedRequest,
    slot: Arc<crate::plane_driver::port_billing::NativeOrdinaryTerminalSlot>,
    _invocation: (InvocationContext, NativeInvocationAdmission),
    _lease: crate::limits::process_admission::RequestLease,
}

/// One actual native ordinary admission owned by its funded slot, over durable unit custody.
async fn ordinary_rig(unit: u64) -> OrdinaryRig {
    use crate::config::groups::ExhaustionMode;
    use crate::plane_driver::{EndPost, PlaneMoney};
    struct Posted;
    impl EndPost for Posted {
        fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    }
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &Default::default()));
    let key = Arc::new(VirtualKey {
        id: "ordinary-terminal".into(),
        enabled: true,
        ..Default::default()
    });
    let routes = RequestRoutes::new("seat", None, None, None)
        .unwrap()
        .with_registrations(table(&[definition("command", true)]))
        .unwrap();
    let (ctx, owner) = context_with_key(unit, key);
    let receipt = RequestAllocation::new(ctx.clone(), cost, 100)
        .unwrap()
        .registration(&routes, None, "command")
        .unwrap();
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    gov.attach_recovery_sink(Arc::new(KeptRecovery::default()))
        .await
        .unwrap();
    let sink = Arc::new(GatedCheckpoints::default());
    gov.attach_unit_checkpoint_sink(sink.clone()).await.unwrap();
    assert!(gov.unit_checkpoints_enabled());
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Posted)));
    let process = crate::limits::process_admission::ProcessAdmission::new(0);
    let lease = process
        .try_enter(crate::limits::process_admission::AdmissionClass::Data)
        .unwrap();
    let slot = crate::plane_driver::port_billing::NativeOrdinaryTerminalSlot::reserve(
        &ctx,
        &lease.storage(),
    )
    .unwrap();
    let admitted = money
        .admit_existing_ordinary(
            receipt.begin().unwrap(),
            &slot,
            Arc::from([]),
            super::super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    OrdinaryRig {
        money,
        gov,
        sink,
        admitted,
        slot,
        _invocation: (ctx, owner),
        _lease: lease,
    }
}

fn ended(status: u32) -> crate::plane_driver::UnitEnd {
    crate::plane_driver::UnitEnd {
        caller_status: status,
        cut: false,
        refused_unspent: false,
    }
}

/// Held R: the transfer removes Open, but nothing confirms until the actual original sink
/// acknowledges removal. A failed R retains the same pending owner; the pulse retry confirms.
#[tokio::test]
async fn ordinary_receipt_waits_for_the_original_r_acknowledgement() {
    let rig = ordinary_rig(51).await;
    rig.sink
        .refuse_remove
        .store(true, std::sync::atomic::Ordering::SeqCst);
    rig.slot
        .request_terminal(&rig.admitted, ended(200))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    assert_eq!(rig.money.open_units(), 0);
    assert!(!rig.slot.checkpoint_confirmed(&rig.money).unwrap());
    assert!(rig.gov.flush_unit_checkpoints().await.is_err());
    assert!(
        !rig.slot.checkpoint_confirmed(&rig.money).unwrap(),
        "a failed R acknowledgement cannot confirm the original receipt"
    );
    assert_eq!(
        rig.sink.removed.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    rig.sink
        .refuse_remove
        .store(false, std::sync::atomic::Ordering::SeqCst);
    rig.gov.flush_unit_checkpoints().await.unwrap();
    assert!(rig.slot.checkpoint_confirmed(&rig.money).unwrap());
    assert_eq!(
        rig.sink.removed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

/// Explicit finish racing rollback destruction: the first valid intent is elected, the loser
/// cannot replace it, and only one original transfer and one receipt exist.
#[tokio::test]
async fn ordinary_finish_and_rollback_elect_one_original_transfer() {
    let rig = ordinary_rig(52).await;
    let rollback = rig.money.admission_rollback(&rig.admitted).unwrap();
    drop(rollback);
    assert_eq!(rig.money.open_units(), 1, "rollback recorded intent only");
    rig.slot
        .request_terminal(&rig.admitted, ended(200))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    assert_eq!(rig.money.open_units(), 0);
    assert!(
        rig.money.drive_ordinary_terminal(&rig.slot).unwrap(),
        "a later drive observes the retained transfer"
    );
    assert!(
        !rig.money
            .settle_admitted(&rig.admitted, ended(200))
            .unwrap(),
        "the boolean path cannot settle a second time"
    );
    rig.gov.flush_unit_checkpoints().await.unwrap();
    assert!(rig.slot.checkpoint_confirmed(&rig.money).unwrap());
    assert_eq!(
        rig.sink.removed.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

/// The boolean settlement refuses a slot-owned Open instead of destroying it before receipt.
#[tokio::test]
async fn slot_owned_open_refuses_boolean_settlement() {
    let rig = ordinary_rig(53).await;
    assert!(rig
        .money
        .settle_admitted(&rig.admitted, ended(200))
        .is_err());
    rig.money.settle_end_as(rig.admitted.unit(), ended(200));
    assert_eq!(rig.money.open_units(), 1);
    assert!(!rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
}

/// Shutdown: dropping waiters and the money owner without a flush never confirms the receipt;
/// the original pending checkpoint entry remains for drain.
#[tokio::test]
async fn forced_teardown_cannot_confirm_an_ordinary_receipt() {
    let rig = ordinary_rig(54).await;
    rig.slot
        .request_terminal(&rig.admitted, ended(200))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    assert!(!rig.slot.checkpoint_confirmed(&rig.money).unwrap());
    assert_eq!(
        rig.sink.removed.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// FEE-DEBT r1 source-first regression: after the hot refund and the ordinary checkpoint's
/// actual R acknowledgement, the original fee-budget Store operation has not been
/// acknowledged (no budget flush ran). The native fee join must remain unresolved;
/// FeeState.completed alone only proves the hot mutations finished.
#[tokio::test]
async fn native_fee_join_waits_for_the_original_fee_store_operation() {
    let rig = ordinary_rig(55).await;
    rig.slot
        .request_terminal(&rig.admitted, ended(502))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    rig.gov.flush_unit_checkpoints().await.unwrap();
    assert!(rig.slot.checkpoint_confirmed(&rig.money).unwrap());
    assert!(
        !rig.slot.fee_join_complete(),
        "the fee join completed before the original fee-budget Store operation was Applied"
    );
}

/// Stale flush: the pending entry changes while its flushed snapshot is at the sink. The
/// successful R for the old snapshot cannot confirm the receipt; the retained entry's own
/// later flush confirms it once.
#[tokio::test]
async fn a_stale_flush_cannot_confirm_a_changed_ordinary_entry() {
    let rig = ordinary_rig(56).await;
    *rig.sink.stale.lock().unwrap() = Some(Arc::downgrade(&rig.gov));
    rig.slot
        .request_terminal(&rig.admitted, ended(200))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    let _ = rig.gov.flush_unit_checkpoints().await;
    assert!(
        !rig.slot.checkpoint_confirmed(&rig.money).unwrap(),
        "a stale R acknowledged a changed original entry"
    );
    rig.gov.flush_unit_checkpoints().await.unwrap();
    assert!(rig.slot.checkpoint_confirmed(&rig.money).unwrap());
}

/// FEE-DEBT r1 through the actual flusher: the original charge and refund net to zero inside
/// one finite capture, so the honest result is CancelledBeforeSend, never Applied.
#[tokio::test]
async fn a_refunded_native_fee_settles_through_the_original_flusher() {
    let rig = ordinary_rig(57).await;
    rig.slot
        .request_terminal(&rig.admitted, ended(502))
        .unwrap();
    assert!(rig.money.drive_ordinary_terminal(&rig.slot).unwrap());
    rig.gov.flush_unit_checkpoints().await.unwrap();
    assert!(!rig.slot.fee_join_complete());
    // The trusted observer owner (the Node book in production) offers captures to the slot.
    struct SlotOwner(Arc<crate::plane_driver::port_billing::NativeOrdinaryTerminalSlot>);
    impl crate::governance::fee_debt::FeeDebtAssociate for SlotOwner {
        fn associate(
            &self,
            capture: &Arc<crate::governance::fee_debt::FeeCapture>,
            _: crate::governance::fee_debt::FeeCursor,
        ) -> crate::governance::fee_debt::FeeAssociation {
            self.0.offer_fee_capture(capture);
            crate::governance::fee_debt::FeeAssociation::Complete
        }
    }
    let owner: Arc<dyn crate::governance::fee_debt::FeeDebtAssociate> =
        Arc::new(SlotOwner(rig.slot.clone()));
    rig.gov.bind_fee_debt_owner(Arc::downgrade(&owner)).unwrap();
    rig.gov.flush_budgets_final().await;
    match rig.slot.fee_status() {
        Some(crate::governance::fee_debt::FeeDebtStatus::Complete(receipt)) => {
            assert_eq!(receipt.applied + receipt.cancelled_before_send, 1);
        }
        other => panic!("original fee debt not resolved by the flusher: {other:?}"),
    }
    assert!(rig.slot.fee_join_complete());
}

fn pool_scoped(id: &str, pools: &[&str]) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: id.into(),
        enabled: true,
        allowed_scopes: Some(
            pools
                .iter()
                .map(|pool| busbar_contract::records::ScopeRef::pool(*pool))
                .collect(),
        ),
        ..Default::default()
    })
}

/// DES-NATIVE-ROUTE-CLASSES test 3 (#462, D2): root seats pass `scope_kind: None`. That
/// must not let a pool-scoped key walk another pool's members.
#[test]
fn undeclared_scope_kind_never_widens_a_scoped_key_walk() {
    let routes = catalog_routes_with(None);
    for (unit, selector) in [(41, "p"), (42, "q"), (43, "m")] {
        let (ctx, _lease) = context_with_key(unit, pool_scoped("scoped", &["p"]));
        let walk = RequestWalk::new(&ctx).unwrap();
        let resolved = allocation(ctx).forward(&routes, &walk, Some(selector));
        let widened = resolved
            .as_ref()
            .ok()
            .map(|receipt| receipt.member_grants().keys().cloned().collect::<Vec<_>>());
        assert_eq!(
            resolved.err(),
            Some(AdmissionError::Scope),
            "scope_kind None let a pool:p key walk {selector} with grants {widened:?}"
        );
    }
    // Guard: an unrestricted key keeps every configured walk.
    let (ctx, _lease) = context(44);
    let walk = RequestWalk::new(&ctx).unwrap();
    assert!(allocation(ctx).forward(&routes, &walk, Some("q")).is_ok());
}

/// Test 3, registration half: W_UPSTREAM is not admitted for a scoped key under `None`.
#[test]
fn undeclared_scope_kind_never_admits_a_scoped_key_registration() {
    let routes = RequestRoutes::new("seat", None, None, None)
        .unwrap()
        .with_registrations(table(&[definition("command", true)]))
        .unwrap();
    let (ctx, _lease) = context_with_key(45, pool_scoped("scoped", &["a"]));
    assert_eq!(
        allocation(ctx).registration(&routes, None, "command").err(),
        Some(AdmissionError::Scope),
        "scope_kind None admitted upstream `command` for a pool:a key"
    );
    // Guard: an unrestricted key still reaches its configured command.
    let (ctx, _lease) = context(46);
    assert!(allocation(ctx)
        .registration(&routes, None, "command")
        .is_ok());
}
