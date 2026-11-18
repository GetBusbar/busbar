// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::{self, Grammar};
use busbar_kernel::plane_driver::provider_catalog::ProviderPlane;
use busbar_kernel::upstreams::Upstreams;

fn configured() -> (RootCfg, CatalogPlan) {
    configured_resource(None)
}

fn configured_resource(resource: Option<&str>) -> (RootCfg, CatalogPlan) {
    let grammar = Grammar::empty();
    let resource = resource
        .map(|value| format!(", resource: {value}"))
        .unwrap_or_default();
    let source = format!("providers:\n  p: {{api_key: none}}\nmodels:\n  m: {{provider: p, upstream_model: wire-model, max_concurrent: 2, attempt_timeout_ms: 113{resource}}}\npools:\n  fast: {{members: [{{model: m, context_max: 4096, attempt_timeout_ms: 37}}]}}\n  slow: {{members: [m]}}\n");
    let deploy = config::deploy_from_yaml_str(&source, &grammar).unwrap();
    let defs = config::providers::catalog_from_str(
        "p:\n  protocol: wire\n  base_url: https://127.0.0.1/api\n  path: /chat\n",
        &grammar,
    )
    .unwrap();
    let planes = [ProviderPlane {
        instance: "chat".into(),
        image: "actual-image".into(),
        dialects: ["wire".to_owned()].into(),
        schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#.into(),
    }];
    let mut result = config::resolve_with_provider_planes(&deploy, &defs, &planes).unwrap();
    let plan = result.catalogs.remove("chat").unwrap();
    (result.config, plan)
}

#[test]
fn actual_model_definition_and_target_retain_only_the_configured_resource() {
    for resource in [None, Some("shared-model")] {
        let (cfg, plan) = configured_resource(resource);
        let staged = stage(&cfg, &plan, &allocated(&plan)).unwrap();
        for row in staged.rows.values() {
            assert_eq!(row.definition.resource.as_deref(), resource);
            assert_eq!(row.target.resource.as_deref(), resource);
        }
    }
}

#[test]
fn staged_member_policy_keeps_the_resolved_catalog_values() {
    let (cfg, plan) = configured();
    let staged = stage(&cfg, &plan, &allocated(&plan)).unwrap();
    for (key, row) in &staged.rows {
        let target = plan.target(&key.0, &key.1).unwrap();
        assert_eq!(row.attempt_timeout_ms, target.attempt_timeout_ms);
        assert_eq!(row.context_max, target.context_max);
        assert_eq!(row.credential_mode, target.credential_mode);
    }
    let fast = plan.select("fast").unwrap();
    let slow = plan.select("slow").unwrap();
    assert_eq!(
        staged.rows[&(fast.into(), "chat\u{1f}m".into())].attempt_timeout_ms,
        Some(37)
    );
    assert_eq!(
        staged.rows[&(fast.into(), "chat\u{1f}m".into())].context_max,
        Some(4096)
    );
    assert_eq!(
        staged.rows[&(slow.into(), "chat\u{1f}m".into())].attempt_timeout_ms,
        Some(113)
    );
}

fn allocated(plan: &CatalogPlan) -> Allocations {
    plan.targets()
        .keys()
        .enumerate()
        .map(|(i, key)| {
            (
                key.clone(),
                Allocation {
                    destination: DestinationId::new(100 + i as u64),
                    need: NeedId(100 + i as u32),
                    upstream: format!("catalog-{i}").into(),
                },
            )
        })
        .collect()
}

fn empty_registration() -> (ConfiguredUpstreams, SeatPool) {
    let definitions = ConfiguredUpstreams::default();
    let pool = SeatPool::of("chat", &definitions).unwrap();
    (definitions, pool)
}

fn stage(
    cfg: &RootCfg,
    plan: &CatalogPlan,
    allocations: &Allocations,
) -> Result<StagedCatalog, String> {
    let (definitions, registrations) = empty_registration();
    prepare(
        cfg,
        plan,
        allocations,
        &registrations,
        &definitions,
        &ProviderBindings::default(),
        &BTreeMap::new(),
    )
}

#[test]
fn catalog_route_requires_the_actual_roots_allocation_for_every_pair() {
    let (cfg, plan) = configured();
    let mut allocations = allocated(&plan);
    allocations.remove(plan.targets().keys().next().unwrap());
    assert!(
        matches!(stage(&cfg, &plan, &allocations), Err(error) if error.contains("missing allocation"))
    );
    let mut allocations = allocated(&plan);
    allocations.insert(
        ("unowned-pool".into(), "chat\u{1f}m".into()),
        Allocation {
            destination: DestinationId::new(999),
            need: NeedId(999),
            upstream: "unowned".into(),
        },
    );
    assert!(
        matches!(stage(&cfg, &plan, &allocations), Err(error) if error.contains("unowned allocation"))
    );
}

#[test]
fn catalog_destinations_and_needs_do_not_alias_each_other_or_registrations() {
    let (cfg, plan) = configured();
    let keys: Vec<_> = plan.targets().keys().cloned().collect();
    let mut allocations = allocated(&plan);
    let duplicate = allocations[&keys[0]].destination;
    allocations.get_mut(&keys[1]).unwrap().destination = duplicate;
    assert!(
        matches!(stage(&cfg, &plan, &allocations), Err(error) if error.contains("destination collision"))
    );
    let mut allocations = allocated(&plan);
    let duplicate = allocations[&keys[0]].need;
    allocations.get_mut(&keys[1]).unwrap().need = duplicate;
    assert!(
        matches!(stage(&cfg, &plan, &allocations), Err(error) if error.contains("need collision"))
    );
    let mut allocations = allocated(&plan);
    let duplicate = allocations[&keys[0]].upstream.clone();
    allocations.get_mut(&keys[1]).unwrap().upstream = duplicate;
    assert!(
        matches!(stage(&cfg, &plan, &allocations), Err(error) if error.contains("upstream name collision"))
    );
}

#[test]
fn actual_definition_is_retained_in_the_model_table_and_exact_target_association() {
    let (cfg, plan) = configured();
    let allocations = allocated(&plan);
    let staged = stage(&cfg, &plan, &allocations).unwrap();
    for (key, row) in &staged.rows {
        // The staged upstreams table went with its unread fields (d86e447ebb); the target still
        // retains the row's exact definition.
        assert!(Arc::ptr_eq(
            row.target.definition.as_ref().unwrap().as_arc(),
            &row.definition,
        ));
        assert_eq!(row.allocation.destination, allocations[key].destination);
        assert_eq!(
            row.target.registered_upstream.as_deref(),
            Some(row.definition.name.as_ref())
        );
        assert_eq!(row.definition.url.as_deref(), Some("https://127.0.0.1/api"));
        assert!(row.definition.allow_private);
        assert!(row.definition.auth.is_none());
        assert!(
            matches!(&row.target.identity, TargetIdentity::Model {dialect,model} if dialect.as_ref()=="wire" && model.as_ref()=="wire-model")
        );
    }
    // Catalog URL facts do not manufacture an entry in the independently supplied CHANNEL table.
    let (registrations, _) = empty_registration();
    assert!(registrations.is_empty());
}

#[test]
fn keyless_selection_is_explicit_and_same_model_shares_real_capacity_across_pools() {
    let (cfg, plan) = configured();
    let mut staged = stage(&cfg, &plan, &allocated(&plan)).unwrap();
    let rows = staged.take_auth_rows();
    assert_eq!(rows.len(), plan.targets().len());
    assert!(rows
        .iter()
        .all(|row| matches!(row.selection, Selection::None)));
    let mut limits = staged.capacity.values();
    let first = limits.next().unwrap();
    assert_eq!(first.available_permits(), 2);
    assert!(limits.all(|limit| Arc::ptr_eq(first, limit)));
    let one = first.try_acquire().unwrap();
    let two = first.try_acquire().unwrap();
    assert!(first.try_acquire().is_err());
    drop((one, two));
    assert_eq!(first.available_permits(), 2);
}

#[test]
fn required_credential_never_becomes_none_when_the_binding_is_missing() {
    let (mut cfg, plan) = configured();
    cfg.providers.get_mut("p").unwrap().api_key =
        busbar_contract::yaml::from_str("{module: real-configured-secret, settings: {slot: key}}")
            .unwrap();
    assert!(
        matches!(stage(&cfg, &plan, &allocated(&plan)), Err(error) if error.contains("required provider binding"))
    );
}

#[test]
fn a_catalog_url_with_userinfo_does_not_become_a_model_route() {
    let (mut cfg, plan) = configured();
    cfg.providers.get_mut("p").unwrap().base_url =
        "https://user:DO_NOT_ECHO@upstream.example".into();
    let error = match stage(&cfg, &plan, &allocated(&plan)) {
        Ok(_) => panic!("userinfo accepted"),
        Err(error) => error,
    };
    assert!(error.contains("configured provider destination"));
    assert!(!error.contains("DO_NOT_ECHO"));
}

#[test]
fn catalog_allocations_cannot_reuse_an_actual_registration_destination_or_need() {
    let (cfg, plan) = configured();
    let entry = json::parse_value(br#"{"url":"https://registered.example"}"#).unwrap();
    let definition = Arc::new(
        UpstreamDef::from_config(
            "registered",
            &entry,
            &UpstreamCfg::default(),
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .unwrap(),
    );
    let definitions =
        ConfiguredUpstreams::from_definitions([(definition.name.clone(), definition)].into());
    let registrations = SeatPool::of("chat", &definitions).unwrap();
    let first = plan.targets().keys().next().unwrap();
    let mut allocations = allocated(&plan);
    allocations.get_mut(first).unwrap().destination = registrations.members[0].destination;
    assert!(
        matches!(prepare(&cfg,&plan,&allocations,&registrations,&definitions,&ProviderBindings::default(),&BTreeMap::new()), Err(error) if error.contains("destination collision"))
    );
    let mut allocations = allocated(&plan);
    allocations.get_mut(first).unwrap().need = registrations.members[0].need;
    assert!(
        matches!(prepare(&cfg,&plan,&allocations,&registrations,&definitions,&ProviderBindings::default(),&BTreeMap::new()), Err(error) if error.contains("need collision"))
    );
    let mut allocations = allocated(&plan);
    allocations.get_mut(first).unwrap().upstream = "registered".into();
    assert!(
        matches!(prepare(&cfg,&plan,&allocations,&registrations,&definitions,&ProviderBindings::default(),&BTreeMap::new()), Err(error) if error.contains("upstream name collision"))
    );
}
