// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::upstreams::{ConfiguredUpstreams, ProgramPin, StdioCommand, UpstreamDef, UpstreamTls};

fn definition(name: &str, command: bool) -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        name: name.into(), allow_private: false,
        url: (!command).then(|| "https://upstream.example".into()),
        command: command.then(|| StdioCommand { argv: vec!["/usr/bin/true".into()], env: vec![], cwd: None, pin: ProgramPin::Unpinned, idle_s: 30 }),
        tls: UpstreamTls { pin_spki: vec![], client_identity: None, trust: None }, auth: None,
    })
}

fn table(definitions: &[Arc<UpstreamDef>]) -> Arc<ConfiguredUpstreams> {
    Arc::new(ConfiguredUpstreams::from_definitions(definitions.iter().map(|d| (d.name.clone(), d.clone())).collect()))
}

#[test]
fn command_scope_cannot_alias_a_catalog_or_an_unrelated_default_registration() {
    for name in ["p", "m"] {
        assert!(catalog_routes().with_registrations(table(&[definition(name, true)])).is_err());
    }
    let registrations = table(&[definition("seat", true), definition("http", false)]);
    let default = Arc::new(SeatPool::of("seat", &registrations).unwrap());
    assert!(RequestRoutes::new("seat", None, None, Some(default)).unwrap().with_registrations(registrations).is_err());
    let routes = RequestRoutes::new("seat", None, None, None).unwrap().with_registrations(table(&[definition("http", false)])).unwrap();
    let (ctx, _lease) = context(31);
    assert!(allocation(ctx).registration(&routes, None, "http").is_err(), "a URL definition cannot become a command by selection");
}

#[tokio::test]
async fn command_uses_original_pool_chain_and_one_request_count() {
    use crate::config::groups::{ExhaustionMode, GroupCfg};
    use crate::plane_driver::{EndPost, PlaneMoney};
    struct Posted;
    impl EndPost for Posted { fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {} }
    let root: GroupCfg = busbar_contract::yaml::from_str("limits:\n - {requests: 4, per: total}\n - {budget: 100, per: total}\n").unwrap();
    let leaf: GroupCfg = busbar_contract::yaml::from_str("parent: root\nlimits:\n - {requests: 1, per: total, pool: command}\n - {requests: 9, per: total, pool: other}\n - {budget: 70, per: total, pool: command}\n").unwrap();
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &[("root".into(), root), ("leaf".into(), leaf)].into()));
    let key = Arc::new(VirtualKey { id: "payer".into(), enabled: true, group: Some("leaf".into()), ..Default::default() });
    let plan = cost.plan_chain(&key).unwrap();
    let command = definition("command", true);
    let other = definition("other", true);
    let registrations = table(&[command.clone(), other]);
    let routes = RequestRoutes::new("seat", Some(Arc::from("server")), None, None).unwrap().with_registrations(registrations.clone()).unwrap();
    let (ctx, _lease) = context_with_key(32, key.clone());
    let receipt = RequestAllocation::new(ctx.clone(), cost.clone(), 100).unwrap().registration(&routes, None, "command").unwrap();
    assert_eq!(receipt.pool(), "seat\u{1f}command");
    assert!(!ctx.effects_allowed());
    let gov = Arc::new(GovState::new_with_core(crate::real_store::core().await, None, None).await.unwrap());
    let money = PlaneMoney::new(gov.clone(), Arc::new(Posted));
    let admitted = money.admit_existing(receipt.begin().unwrap(), Arc::from([]), super::super::super::money::FeeRefund::CallerStatus, ExhaustionMode::FinishUnit).unwrap();
    assert_eq!(admitted.charge().chain(), Some(&plan));
    assert_eq!(admitted.pool(), "seat\u{1f}command");
    assert!(Arc::ptr_eq(admitted.registered_command().unwrap(), &command));
    assert!(admitted.accepts_forward(&routes, None, Some("command")));
    assert!(!admitted.accepts_forward(&routes, None, Some("other")));
    assert!(!admitted.accepts_forward(&routes, Some("command"), Some("command")));
    let replacement = RequestRoutes::new("seat", Some(Arc::from("server")), None, None).unwrap().with_registrations(registrations).unwrap();
    assert!(!admitted.accepts_forward(&replacement, None, Some("command")), "even identical definition Arcs cannot replace the request's frozen table");
    let view = gov.admitted_view(&admitted).unwrap();
    assert_eq!(view.rate_headroom, Some(0.0));
    assert!(view.budgets.iter().any(|b| b.pool.as_deref() == Some("command")));
    assert!(view.budgets.iter().all(|b| b.pool.as_deref() != Some("other")));
    let (second, _lease2) = context_with_key(33, key.clone());
    let blocked = RequestAllocation::new(second.clone(), cost.clone(), 100).unwrap().registration(&routes, None, "command").unwrap();
    assert!(money.admit_existing(blocked.begin().unwrap(), Arc::from([]), super::super::super::money::FeeRefund::CallerStatus, ExhaustionMode::FinishUnit).is_err());
    assert!(!second.effects_allowed());
    let (other, _lease3) = context_with_key(34, key);
    let receipt = RequestAllocation::new(other, cost, 100).unwrap().registration(&routes, None, "other").unwrap();
    let other = money.admit_existing(receipt.begin().unwrap(), Arc::from([]), super::super::super::money::FeeRefund::CallerStatus, ExhaustionMode::FinishUnit).unwrap();
    assert_eq!(gov.admitted_view(&other).unwrap().rate_headroom, Some(0.5), "the refused duplicate must not increment the original shared parent count");
}
