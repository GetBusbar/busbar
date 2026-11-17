// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

fn routes(pools: &str) -> RequestRoutes {
    use crate::config::{self, providers, Grammar};
    use crate::plane_driver::provider_catalog::ProviderPlane;
    let grammar = Grammar::empty();
    let providers = providers::catalog_from_str("provider:\n  protocol: wire\n  base_url: https://upstream.example\n", &grammar).unwrap();
    let yaml = format!("providers:\n  provider: {{}}\nmodels:\n  m: {{provider: provider}}\n  n: {{provider: provider}}\npools:\n{pools}");
    let deploy = config::deploy_from_yaml_str(&yaml, &grammar).unwrap();
    let mut resolved = config::resolve_with_provider_planes(&deploy, &providers, &[ProviderPlane {
        instance: "seat".into(), image: "image".into(), dialects: ["wire".into()].into(),
        schema: r#"{"type":"object","additionalProperties":false}"#.into(),
    }]).unwrap();
    RequestRoutes::new("seat", Some(Arc::from("pool")), Some(Arc::new(resolved.catalogs.remove("seat").unwrap())), None).unwrap()
}

#[tokio::test]
async fn current_route_preserves_original_domain_and_authorized_fallback_reach() {
    use super::credential_tests::{context, fixture, verified};
    let (gov, token) = fixture().await;
    let original = routes("  p: {members: [m], on_exhausted: {fallback_pool: q}}\n  q: {members: [m]}\n");
    let (ctx, _lease) = context(71, verified(&gov, &token));
    let walk = RequestWalk::new(&ctx).unwrap();
    let receipt = RequestAllocation::new(ctx, Arc::new(CostModel::resolve_parts(None, 0, &Default::default())), 1000).unwrap().forward(&original, &walk, Some("p")).unwrap();
    struct Posted;
    impl super::super::EndPost for Posted { fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {} }
    let money = super::super::PlaneMoney::new(gov, Arc::new(Posted));
    let admitted = money.admit_existing(receipt.begin().unwrap(), Arc::from([]), super::super::money::FeeRefund::CallerStatus, crate::config::groups::ExhaustionMode::FinishUnit).unwrap();
    let current = routes("  p: {members: [m], on_exhausted: {fallback_pool: q}}\n  q: {members: [m]}\n");
    let selected = current.catalog.as_ref().unwrap().select("q").unwrap();
    assert!(current.allows_current_pair(&admitted, admitted.key(), selected, "seat\u{1f}m"));
    let moved = routes("  p: {members: [m]}\n  q: {members: [m]}\n");
    assert!(!moved.allows_current_pair(&admitted, admitted.key(), selected, "seat\u{1f}m"), "a removed fallback cannot be retained by name coincidence");
    let member_changed = routes("  p: {members: [m], on_exhausted: {fallback_pool: q}}\n  q: {members: [n]}\n");
    assert!(!member_changed.allows_current_pair(&admitted, admitted.key(), selected, "seat\u{1f}m"));
    assert!(!member_changed.allows_current_pair(&admitted, admitted.key(), selected, "seat\u{1f}n"), "current policy cannot widen original member authority");
    let removed = routes("  q: {members: [m]}\n");
    assert!(!removed.allows_current_pair(&admitted, admitted.key(), selected, "seat\u{1f}m"));
    let mut narrowed = admitted.key().as_ref().clone();
    narrowed.allowed_scopes = Some(vec![busbar_contract::records::ScopeRef::pool("p")]);
    assert!(!current.allows_current_pair(&admitted, &narrowed, selected, "seat\u{1f}m"));
}
