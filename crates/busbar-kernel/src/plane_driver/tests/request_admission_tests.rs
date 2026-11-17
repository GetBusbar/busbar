// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::{
    KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute, ServingGeneration,
};
use crate::host_units::UnitRecord;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::Caller;

#[path = "request_registration_tests.rs"]
mod registration_tests;

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("pre-admission cannot nest");
    }
}

fn context(unit: u64) -> (InvocationContext, NativeInvocationAdmission) {
    context_with_key(
        unit,
        Arc::new(VirtualKey {
            id: "payer".into(),
            enabled: true,
            ..Default::default()
        }),
    )
}

fn context_with_key(
    unit: u64,
    key: Arc<VirtualKey>,
) -> (InvocationContext, NativeInvocationAdmission) {
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        unit,
        &caller,
        UnitRecord {
            principal: Some(key),
            depth: 0,
        }
    ));
    let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
    (
        InvocationContext::new(generation, caller, unit).unwrap(),
        lease,
    )
}

fn allocation(context: InvocationContext) -> RequestAllocation {
    RequestAllocation::new(
        context,
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        100,
    )
    .unwrap()
}

#[test]
fn allocation_is_take_once_and_local_is_explicit() {
    let (context, _lease) = context(1);
    let pending = allocation(context.clone());
    assert!(RequestAllocation::new(
        context.clone(),
        Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
        100
    )
    .is_err());
    assert!(!context.effects_allowed());
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = pending.local(&routes).unwrap();
    assert_eq!(receipt.pool(), "seat\u{1f}");
    assert_eq!(receipt.domain(), &RequestDomain::Local);
    let committing = receipt.begin().unwrap();
    assert!(committing.is_live());
    assert_eq!(committing.key().id, "payer");
    assert!(!context.effects_allowed());
    drop(committing);
    assert!(!context.effects_allowed());
}

#[test]
fn ended_or_reused_record_cannot_admit() {
    let (context, _lease) = context(2);
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    let receipt = allocation(context.clone()).local(&routes).unwrap();
    context.generation().core().units().ended(2);
    assert!(receipt.begin().is_err());
    assert!(!context.effects_allowed());
}

#[test]
fn foreign_seat_and_foreign_walk_cannot_bind_a_route() {
    let (ctx, _lease) = context(3);
    let routes = RequestRoutes::new("other", None, None, None).unwrap();
    assert!(allocation(ctx).local(&routes).is_err());
    let (first, _lease_a) = context(4);
    let (second, _lease_b) = context(5);
    let walk = RequestWalk::new(&second).unwrap();
    assert!(!walk.accepts(&first));
}

#[test]
fn unknown_forward_never_becomes_local_or_registration() {
    let (context, _lease) = context(6);
    let walk = RequestWalk::new(&context).unwrap();
    let routes = RequestRoutes::new("seat", None, None, None).unwrap();
    assert!(allocation(context)
        .forward(&routes, &walk, Some("unknown"))
        .is_err());
}

#[test]
fn pending_registration_does_not_replace_an_existing_unit() {
    let (context, _lease) = context(7);
    let stranger = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    assert!(!context.generation().core().units().pre_admitted_for(
        7,
        &stranger,
        UnitRecord::default()
    ));
    assert_eq!(context.principal().unwrap().id, "payer");
    assert!(!context.effects_allowed());
}

#[test]
fn retiring_old_context_preserves_a_reused_numeric_allocation() {
    let (old, _lease) = context(17);
    let core = old.generation().core();
    core.units().ended(old.unit());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let _new_lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        old.unit(),
        &caller,
        UnitRecord {
            principal: Some(Arc::new(VirtualKey {
                id: "new-payer".into(),
                enabled: true,
                ..Default::default()
            })),
            depth: 0,
        }
    ));
    let new = InvocationContext::new(old.generation().clone(), caller, old.unit()).unwrap();
    old.retire();
    assert!(new.is_live());
    assert_eq!(new.principal().unwrap().id, "new-payer");
    new.retire();
    assert!(!new.is_live());
}

fn catalog_routes() -> RequestRoutes {
    use crate::config::{self, providers, Grammar};
    use crate::plane_driver::provider_catalog::ProviderPlane;
    let grammar = Grammar::empty();
    let definitions = providers::catalog_from_str(
        "provider:\n  protocol: wire\n  base_url: https://upstream.example\n",
        &grammar,
    )
    .unwrap();
    let deployment = config::deploy_from_yaml_str("providers:\n  provider: {}\nmodels:\n  m:\n    provider: provider\n    upstream_model: wire-m\npools:\n  p: {members: [m]}\n  q: {members: [m]}\n", &grammar).unwrap();
    let mut resolved = config::resolve_with_provider_planes(
        &deployment,
        &definitions,
        &[ProviderPlane {
            instance: "seat".into(),
            image: "image".into(),
            dialects: ["wire".into()].into(),
            schema: r#"{"type":"object","additionalProperties":false}"#.into(),
        }],
    )
    .unwrap();
    RequestRoutes::new(
        "seat",
        Some(Arc::from("pool")),
        Some(Arc::new(resolved.catalogs.remove("seat").unwrap())),
        None,
    )
    .unwrap()
}

#[test]
fn named_pool_and_direct_model_have_distinct_admitted_scope() {
    let routes = catalog_routes();
    for (unit, selector, domain, pool) in [
        (11, "p", RequestDomain::NamedPool("p".into()), "seat\u{1f}p"),
        (12, "q", RequestDomain::NamedPool("q".into()), "seat\u{1f}q"),
        (
            13,
            "m",
            RequestDomain::DirectModel("m".into()),
            "seat\u{1f}m",
        ),
    ] {
        let (ctx, _lease) = context(unit);
        let walk = RequestWalk::new(&ctx).unwrap();
        let receipt = allocation(ctx)
            .forward(&routes, &walk, Some(selector))
            .unwrap();
        assert_eq!(receipt.domain(), &domain);
        assert_eq!(receipt.pool(), pool);
        assert_eq!(
            receipt
                .member_grants()
                .get(receipt.walk_key().unwrap())
                .unwrap(),
            &["seat\u{1f}m"]
        );
        assert_ne!(
            receipt.walk_key(),
            Some(pool),
            "internal routing keys are not operator monetary scopes"
        );
    }
    for selector in ["wire-m", "unknown", ""] {
        let (ctx, _lease) = context(14);
        let walk = RequestWalk::new(&ctx).unwrap();
        assert!(allocation(ctx)
            .forward(&routes, &walk, Some(selector))
            .is_err());
    }
}

#[test]
fn pool_grant_cannot_be_used_for_direct_model_or_another_pool() {
    let routes = catalog_routes();
    for (selector, allowed) in [("p", true), ("q", false), ("m", false)] {
        let (ctx, _lease) = context_with_key(
            15,
            Arc::new(VirtualKey {
                id: "payer".into(),
                enabled: true,
                allowed_scopes: Some(vec![busbar_contract::records::ScopeRef::pool("p")]),
                ..Default::default()
            }),
        );
        let walk = RequestWalk::new(&ctx).unwrap();
        let resolved = allocation(ctx).forward(&routes, &walk, Some(selector));
        assert_eq!(resolved.is_ok(), allowed);
        if let Ok(receipt) = resolved {
            assert_eq!(
                receipt.member_grants().len(),
                1,
                "a pool-only grant cannot leak another fallback or direct route"
            );
        }
    }
}

#[test]
fn real_admission_view_keeps_selected_pool_and_rejects_retired_authority() {
    use crate::config::groups::{ExhaustionMode, GroupCfg};
    use crate::governance::{AdmissionViewUnavailable, GovState};
    use crate::plane_driver::{EndPost, PlaneMoney, UnitEnd};
    use crate::teller::{Ended, UnitCtx};
    struct Posted;
    impl EndPost for Posted {
        fn post(&self, _: &UnitCtx, _: Ended) {}
    }
    let group: GroupCfg = busbar_contract::yaml::from_str("limits:\n - {requests: 5, per: total, pool: p}\n - {requests: 9, per: total, pool: q}\n - {budget: 100, per: total}\n").unwrap();
    let cost = Arc::new(CostModel::resolve_parts(
        None,
        0,
        &[("g".into(), group)].into(),
    ));
    let (ctx, _lease) = context_with_key(
        16,
        Arc::new(VirtualKey {
            id: "payer".into(),
            enabled: true,
            group: Some("g".into()),
            ..Default::default()
        }),
    );
    let walk = RequestWalk::new(&ctx).unwrap();
    let routes = catalog_routes();
    let receipt = RequestAllocation::new(ctx.clone(), cost, 100)
        .unwrap()
        .forward(&routes, &walk, Some("p"))
        .unwrap();
    let store = futures::executor::block_on(crate::real_store::core());
    let gov =
        Arc::new(futures::executor::block_on(GovState::new_with_core(store, None, None)).unwrap());
    let money = PlaneMoney::new(gov.clone(), Arc::new(Posted));
    let admitted = money
        .admit_existing(
            receipt.begin().unwrap(),
            Arc::from([]),
            super::super::money::FeeRefund::CallerStatus,
            ExhaustionMode::FinishUnit,
        )
        .unwrap();
    assert!(ctx.effects_allowed());
    assert!(admitted.accepts_walk(&walk));
    assert!(admitted.accepts_route(&routes, Some("p")));
    assert!(!admitted.accepts_route(&routes, Some("q")));
    assert!(
        !admitted.accepts_route(&catalog_routes(), Some("p")),
        "a new generation's lookalike route table cannot replace the captured one"
    );
    let stranger = RequestWalk::new(&ctx).unwrap();
    assert!(
        !admitted.accepts_walk(&stranger),
        "same unit is insufficient to replace the retained walk"
    );
    for _ in 0..2 {
        let view = gov.admitted_view(&admitted).unwrap();
        assert!(view
            .budgets
            .iter()
            .any(|bucket| bucket.pool.as_deref() == Some("p")));
        assert!(view
            .budgets
            .iter()
            .all(|bucket| bucket.pool.as_deref() != Some("q")));
        assert_eq!(view.rate_headroom, Some(0.8));
    }
    let other_store = futures::executor::block_on(crate::real_store::core());
    let other =
        futures::executor::block_on(GovState::new_with_core(other_store, None, None)).unwrap();
    assert!(matches!(
        other.admitted_view(&admitted),
        Err(AdmissionViewUnavailable::ForeignGovernor)
    ));
    let parent = money.parent_money(admitted.unit(), admitted.key()).unwrap();
    let child_caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let _child_lease = ctx
        .generation()
        .core()
        .admit_native_invocation(&child_caller)
        .unwrap();
    assert!(ctx.generation().core().units().pre_admitted_for(
        18,
        &child_caller,
        UnitRecord {
            principal: Some(admitted.key().clone()),
            depth: 1,
        }
    ));
    let child_context = InvocationContext::new(ctx.generation().clone(), child_caller, 18).unwrap();
    let child_walk = RequestWalk::new(&child_context).unwrap();
    let child_receipt = RequestAllocation::new(child_context.clone(), parent.cost().clone(), 101)
        .unwrap()
        .forward(&routes, &child_walk, Some("q"))
        .unwrap();
    let child = money
        .admit_existing_child(
            child_receipt.begin().unwrap(),
            &parent,
            Arc::from([]),
            super::super::money::FeeRefund::CallerStatus,
        )
        .unwrap();
    assert_eq!(child.domain(), &RequestDomain::NamedPool("q".into()));
    assert_eq!(
        child.pool(),
        admitted.pool(),
        "child routing cannot replace the parent's admitted monetary scope"
    );
    assert_eq!(child.arrived(), admitted.arrived());
    let child_view = gov.admitted_view(&child).unwrap();
    assert_eq!(
        child_view.rate_headroom,
        Some(0.8),
        "a child takes no second request admission"
    );
    assert!(child_view
        .budgets
        .iter()
        .any(|bucket| bucket.pool.as_deref() == Some("p")));
    assert!(child_view
        .budgets
        .iter()
        .all(|bucket| bucket.pool.as_deref() != Some("q")));
    money.settle_end_as(
        child.unit(),
        UnitEnd {
            caller_status: 200,
            cut: false,
            refused_unspent: false,
        },
    );
    child_context.retire();
    money.settle_end_as(
        admitted.unit(),
        UnitEnd {
            caller_status: 200,
            cut: false,
            refused_unspent: false,
        },
    );
    ctx.generation().core().units().ended(ctx.unit());
    assert!(matches!(
        gov.admitted_view(&admitted),
        Err(AdmissionViewUnavailable::Stale)
    ));
}

#[test]
fn command_registration_retains_the_real_definition_without_a_url_walk() {
    use crate::upstreams::{
        ConfiguredUpstreams, ProgramPin, StdioCommand, UpstreamDef, UpstreamTls,
    };
    let definition = Arc::new(UpstreamDef {
        name: "command".into(),
        allow_private: false,
        url: None,
        command: Some(StdioCommand {
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
    });
    let table = Arc::new(ConfiguredUpstreams::from_definitions(
        [("command".into(), definition.clone())].into(),
    ));
    let routes = RequestRoutes::new("seat", Some(Arc::from("server")), None, None)
        .unwrap()
        .with_registrations(table)
        .unwrap();
    let (ctx, _lease) = context(19);
    let receipt = allocation(ctx)
        .registration(&routes, None, "command")
        .unwrap();
    assert!(Arc::ptr_eq(
        receipt.registered_command().unwrap(),
        &definition
    ));
    assert_eq!(
        receipt.domain(),
        &RequestDomain::Registration("command".into())
    );
    assert!(
        receipt.walk_key().is_none(),
        "a command cannot masquerade as an HTTP exchange"
    );
    assert!(receipt.member_grants().is_empty());
    for (model, selected) in [(Some("unknown"), "command"), (None, "missing")] {
        let (ctx, _lease) = context(20);
        assert!(allocation(ctx)
            .registration(&routes, model, selected)
            .is_err());
    }
    let (ctx, _lease) = context_with_key(
        21,
        Arc::new(VirtualKey {
            id: "denied".into(),
            enabled: true,
            allowed_scopes: Some(vec![]),
            ..Default::default()
        }),
    );
    assert!(allocation(ctx)
        .registration(&routes, None, "command")
        .is_err());
}
