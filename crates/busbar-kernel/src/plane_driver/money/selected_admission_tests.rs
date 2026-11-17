// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::plane_driver::money::{EndPost, FeeRefund, PlaneMoney, UsageView};
use crate::plane_driver::port_session::{Calls, Effects, RequestDeclaration, Task};
use busbar_ports::plane::{PlaneIn, PlaneOut, TargetIn, UsageClass};
use busbar_ports::PortError;
use std::num::NonZeroU32;

struct Declared(Vec<UsageClass>, Vec<Box<str>>);
impl Declared {
    fn new() -> Self {
        Self(
            vec![
                UsageClass {
                    class: "tokens.custom".into(),
                    unit: busbar_plugin_abi::plane::UNIT_TOKENS,
                    expected_units: None,
                },
                UsageClass {
                    class: "calls.custom".into(),
                    unit: busbar_plugin_abi::plane::UNIT_COUNT,
                    expected_units: None,
                },
            ],
            vec!["tokens.custom".into()],
        )
    }
}
impl Calls for Declared {
    type Session = ();
    fn usage_metadata(&self) -> (u64, &[UsageClass], &[Box<str>]) {
        (busbar_plugin_abi::plane::FB_ATTEMPT_USAGE, &self.0, &self.1)
    }
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }
    fn piece(
        &self,
        _: &mut (),
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!()
    }
    fn rewrite(
        &self,
        _: &mut (),
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!()
    }
    fn end(&self, _: (), _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Ok(())
    }
    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        unreachable!()
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!()
    }
    fn upstream(
        &self,
        _: &mut (),
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!()
    }
}
struct RootEffects(InvocationContext);
impl Effects for RootEffects {
    fn invocation(&self) -> Option<&InvocationContext> {
        Some(&self.0)
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("initial declaration must not emit")
    }
}
fn declaration(context: &InvocationContext) -> RequestDeclaration {
    let calls = Declared::new();
    let effects = RootEffects(context.clone());
    let input = PlaneIn {
        route: 1,
        flags: 0,
        auth: 0,
        method: "POST",
        path: "/",
        query: "",
        headers: &[],
        identity: &[],
        request_id: context.unit(),
        carrier: 0,
        work: "",
        ticket_record: &[],
    };
    let (task, _) = Task::begin(&calls, &input, &[], &effects).unwrap();
    task.request_declaration().unwrap()
}
struct CapturedPost(bool);
impl EndPost for CapturedPost {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    fn checkpoint_facts(&self, _: UnitKey) -> Option<Vec<u8>> {
        self.0.then(|| vec![1])
    }
}
async fn selected_fixture(
    unit: u64,
    audit: bool,
) -> (
    Arc<PlaneMoney>,
    Arc<GovState>,
    InvocationContext,
    NativeInvocationAdmission,
    CommittingRequest,
) {
    let key = Arc::new(VirtualKey {
        id: "selected-payer".into(),
        enabled: true,
        group: Some("g".into()),
        ..Default::default()
    });
    let (context, lease) = context_with_key(unit, key);
    let groups = BTreeMap::from([(
        "g".into(),
        GroupCfg {
            enabled: true,
            ..Default::default()
        },
    )]);
    let cost = Arc::new(CostModel::resolve_parts(None, 5, &groups));
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let request = RequestAllocation::new(context.clone(), cost, 100)
        .unwrap()
        .local(&routes)
        .unwrap()
        .begin()
        .unwrap();
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(CapturedPost(audit))));
    (money, gov, context, lease, request)
}

#[tokio::test]
async fn same_task_declaration_is_installed_before_effects_open() {
    let (money, _, context, _lease, request) = selected_fixture(71, true).await;
    let descriptor = declaration(&context);
    assert!(!context.effects_allowed());
    let selected = money
        .admit_existing_selected(
            request,
            descriptor,
            context.generation().routing_generation().unwrap(),
            NonZeroU32::new(1).unwrap(),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert!(context.effects_allowed());
    assert_eq!(selected.request().unit(), UnitKey::new(71));
    let view = money.usage_view(selected.request().unit()).unwrap();
    let UsageView::Partitioned(snapshot) = view.as_ref() else {
        panic!("selected admission must expose its accepted partition")
    };
    let parts = snapshot.partitions.as_ref().unwrap();
    assert_eq!(
        parts.attempt_classes,
        std::collections::BTreeSet::from(["tokens.custom".to_owned()])
    );
    assert_eq!(parts.physical_classes, parts.attempt_classes);
    assert!(parts.attempts.is_empty());
    assert_eq!(parts.session_origin.lane, "seat\u{1f}");
    assert_eq!(money.open_units(), 1);
}

#[tokio::test]
async fn another_tasks_context_cannot_open_selected_money() {
    let (money, _, context, _lease, request) = selected_fixture(72, true).await;
    let (other, _other_lease) = context_with_key(73, context.principal().unwrap().clone());
    assert!(money
        .admit_existing_selected(
            request,
            declaration(&other),
            context.generation().routing_generation().unwrap(),
            NonZeroU32::new(1).unwrap(),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit
        )
        .is_err());
    assert!(!context.effects_allowed());
    assert_eq!(money.open_units(), 0);
}

#[tokio::test]
async fn missing_initial_audit_custody_refunds_admission_before_return() {
    let (money, gov, context, _lease, request) = selected_fixture(74, false).await;
    let cost = request.cost().clone();
    let key = request.key().clone();
    assert!(money
        .admit_existing_selected(
            request,
            declaration(&context),
            context.generation().routing_generation().unwrap(),
            NonZeroU32::new(1).unwrap(),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit
        )
        .is_err());
    assert!(!context.effects_allowed());
    assert_eq!(money.open_units(), 0);
    let usage = gov
        .derived_bucket_usage_async(&cost, &key.id, crate::governance::WINDOW_TOTAL, true, 100)
        .await
        .unwrap();
    assert_eq!(usage.requests, 0);
    assert_eq!(usage.spend_cents, 0);
}

#[tokio::test]
async fn another_snapshots_generation_cannot_label_selected_custody() {
    let (money, _, context, _lease, request) = selected_fixture(75, true).await;
    let (other, _other_lease) = context_with_key(76, context.principal().unwrap().clone());
    assert!(money
        .admit_existing_selected(
            request,
            declaration(&context),
            other.generation().routing_generation().unwrap(),
            NonZeroU32::new(1).unwrap(),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit
        )
        .is_err());
    assert!(!context.effects_allowed());
    assert_eq!(money.open_units(), 0);
}

#[tokio::test]
async fn retired_receipt_settles_only_its_original_money_open_once() {
    let (money, gov, context, _lease, request) = selected_fixture(77, true).await;
    let cost = request.cost().clone();
    let key = request.key().clone();
    let admitted = money
        .admit_existing(
            request,
            Arc::from([]),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    let (other, _, _, _other_lease, other_request) = selected_fixture(77, true).await;
    let _other_admitted = other
        .admit_existing(
            other_request,
            Arc::from([]),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    let end = crate::plane_driver::UnitEnd {
        caller_status: 500,
        cut: false,
        refused_unspent: true,
    };
    context.retire();
    assert!(other.settle_admitted(&admitted, end).is_err());
    assert_eq!(other.open_units(), 1);
    assert!(money.settle_admitted(&admitted, end).unwrap());
    assert!(!money.settle_admitted(&admitted, end).unwrap());
    let usage = gov
        .derived_bucket_usage_async(&cost, &key.id, crate::governance::WINDOW_TOTAL, true, 100)
        .await
        .unwrap();
    assert_eq!((usage.requests, usage.spend_cents), (0, 0));
}

#[tokio::test]
async fn callback_rollback_owns_only_original_admission_until_handoff_commits() {
    let (money, gov, context, _lease, request) = selected_fixture(78, true).await;
    let cost = request.cost().clone();
    let key = request.key().clone();
    let admitted = money
        .admit_existing(
            request,
            Arc::from([]),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    let (foreign, _, _, _foreign_lease, foreign_request) = selected_fixture(79, true).await;
    let other = foreign
        .admit_existing(
            foreign_request,
            Arc::from([]),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert!(foreign.admission_rollback(&admitted).is_err());
    let guard = money.admission_rollback(&admitted).unwrap();
    assert!(guard.accepts(&admitted));
    assert!(!guard.accepts(&other));
    assert_eq!(money.open_units(), 1);
    drop(guard);
    assert_eq!(money.open_units(), 0);
    assert!(!context.is_live());
    let usage = gov
        .derived_bucket_usage_async(&cost, &key.id, crate::governance::WINDOW_TOTAL, true, 100)
        .await
        .unwrap();
    assert_eq!((usage.requests, usage.spend_cents), (0, 0));

    let (money, _, context, _lease, request) = selected_fixture(80, true).await;
    let admitted = money
        .admit_existing(
            request,
            Arc::from([]),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    money.admission_rollback(&admitted).unwrap().commit();
    assert_eq!(money.open_units(), 1);
    assert!(context.is_live());
}

#[tokio::test]
async fn selected_session_reports_keep_source_precedence_and_reject_attempt_classes_atomically() {
    use crate::plane_driver::usage::SessionUsage;
    use busbar_plugin_abi::plane::{UsageRec, SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED};
    let (money, _, context, _lease, request) = selected_fixture(98, true).await;
    let descriptor = declaration(&context);
    let selected = money
        .admit_existing_selected(
            request,
            descriptor.clone(),
            context.generation().routing_generation().unwrap(),
            NonZeroU32::new(1).unwrap(),
            FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    let mut usage = SessionUsage::new();
    for (amount, source) in [(20, SRC_ESTIMATED), (16, SRC_FLOOR), (8, SRC_REPORTED)] {
        usage
            .answer(
                "calls.custom",
                UsageRec {
                    amount,
                    scale: 0,
                    source,
                },
            )
            .unwrap();
    }
    assert!(!selected.observe_session(&descriptor, &usage).unwrap());
    assert_eq!(
        selected.checkpoint().unwrap(),
        crate::plane_driver::cancel::Checkpoint::Continue
    );
    let before = money.usage_view(selected.request().unit()).unwrap();
    let UsageView::Partitioned(before) = before.as_ref() else {
        panic!("selected view")
    };
    let projected =
        crate::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint::try_from(
            before.as_ref(),
        )
        .unwrap()
        .project()
        .unwrap();
    let class = &projected.partitions[0].classes["calls.custom"];
    assert_eq!(
        class.billed.unwrap().count,
        busbar_contract::Count::from_micros(8_000_000)
    );
    usage
        .answer(
            "tokens.custom",
            UsageRec {
                amount: 100,
                scale: 0,
                source: SRC_REPORTED,
            },
        )
        .unwrap();
    assert!(selected.observe_session(&descriptor, &usage).is_err());
    let after = money.usage_view(selected.request().unit()).unwrap();
    let UsageView::Partitioned(after) = after.as_ref() else {
        panic!("selected view")
    };
    assert_eq!(
        before, after,
        "malformed session answer must publish nothing"
    );
}
