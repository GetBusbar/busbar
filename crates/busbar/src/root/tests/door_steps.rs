// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_POOL};

use busbar_contract::section::TOOL_CALL_SECTION_KEY;

use super::DoorPools;

fn pools(yaml: &str) -> DoorPools {
    declared_by(yaml, TOOL_CALL_SECTION_KEY)
}

fn declared_by(yaml: &str, declared: &str) -> DoorPools {
    DoorPools::of(&serde_yaml::from_str(yaml).expect("yaml"), declared).expect("the pools")
}

fn routed(p: &DoorPools, class: u8, named: Option<&str>) -> Option<(String, Vec<String>)> {
    p.resolve(class, named.map(str::as_bytes))
}

fn owned(label: &str, members: &[&str]) -> Option<(String, Vec<String>)> {
    Some((
        label.to_string(),
        members.iter().map(|m| (*m).to_string()).collect(),
    ))
}

const SECTION: &str = "a: {}\nb: {}\nhooks: [h]\nupstream_credentials: own\n\
     pools:\n  both:\n    members: [a, {name: b}]";

#[tokio::test]
async fn routing_recipe_preserves_configured_float_prices_before_ranking() {
    use busbar_contract::SignalValue;
    use busbar_kernel::config::RateEntryCfg;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let mut facts = super::door_facts("p", &[], &["input", "output"], &[], "a", Vec::new());
    facts.route_cost = vec![(0, 0.5), (1, 0.5)];
    let p = pools("a: {}");
    let card = BTreeMap::from([(
        super::plane_lane("p", "a"),
        RateEntryCfg {
            input_utok: 0.1,
            output_utok: 0.2,
            ..RateEntryCfg::default()
        },
    )]);
    let mut app = {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-steps-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual store");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        let rules = std::sync::Arc::new(super::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let loaded = crate::root::real_store::store();
        let opened = busbar_contract::store_calls::OpenedStore {
            records: loaded.clone(),
            calls: Some(loaded),
        };
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            crate::root::test_plugins::trusted_config_with_key(
                &directory,
                &crate::root::test_plugins::key(0x5a),
            ),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            false,
        )
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the configured Store boots its rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app
    };
    app.cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        Some(&card),
        0,
        &BTreeMap::new(),
    ));
    let app = Arc::new(app);
    let steps = super::DoorSteps::new(
        &facts,
        &p,
        Arc::new(|_: &str| None),
        app,
        None,
        super::DoorCaller {
            principal: busbar_contract::caps::PrincipalId::new("caller"),
            key: None,
            open: true,
            arrived: 0,
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    let bag = steps.route_cost(&super::plane_lane("p", "a"));
    let floats: Vec<_> = bag
        .iter()
        .filter_map(|(_, value)| match value {
            SignalValue::F64(value) => Some(*value),
            _ => None,
        })
        .collect();
    assert_eq!(floats, vec![0.1, 0.5, 0.2, 0.5]);
}

#[tokio::test]
async fn routing_recipe_uses_the_admitted_planes_card_and_keeps_unknown_prices_unknown() {
    use busbar_contract::signal::route_cost::decode;
    use busbar_kernel::config::RateEntryCfg;
    use busbar_kernel_ledger::cost::UnitRate;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let mut facts = super::door_facts("p", &[], &["frames", "seconds"], &[], "a", Vec::new());
    facts.route_cost = vec![(0, 2.5), (1, 0.0), (0, 1.0)];
    let p = pools("a: {}");
    let app = |price| {
        let entry = RateEntryCfg {
            units: BTreeMap::from([
                ("frames".into(), UnitRate::from_whole_micros(price).unwrap()),
                ("seconds".into(), UnitRate::from_whole_micros(0).unwrap()),
            ]),
            ..RateEntryCfg::default()
        };
        let card = BTreeMap::from([(super::plane_lane("p", "a"), entry)]);
        let mut generation = {
            #[cfg(distribution_root)]
            crate::dist_root_install::install();
            let library_path = crate::root::test_plugins::application_store_library();
            let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual store statement reads")
                .expect("the actual store exports its statement");
            let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual store statement is valid")
                .name;
            let mut manifest = crate::root::test_plugins::manifest(
                "store",
                &module,
                crate::root::test_plugins::FIXTURE_PUBLISHER,
            );
            manifest.statement = Some(hex::encode(statement));
            let release = crate::root::test_plugins::key(0x5a);
            let directory = crate::root::test_plugins::scratch(&format!(
                "door-steps-{}",
                busbar_kernel::door::op_id().counter()
            ));
            let library = std::fs::read(library_path).expect("the actual store library reads");
            let archive = crate::root::test_plugins::signed(&release, manifest, &library);
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual store");
            crate::root::linked::register_stores(&crate::LINKED);
            busbar_kernel::preflight::install_linked_auth(
                crate::LINKED.auths,
                crate::root::auth_bindings::operator_words(),
            );
            let settings = crate::root::test_plugins::application_store_settings(&directory);
            let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                "store": {"module": module, "settings": settings},
            }))
            .expect("the door deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the door deployment resolves");
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let loaded = crate::root::real_store::store();
            let opened = busbar_contract::store_calls::OpenedStore {
                records: loaded.clone(),
                calls: Some(loaded),
            };
            let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
                cfg,
                crate::root::test_plugins::trusted_config_with_key(
                    &directory,
                    &crate::root::test_plugins::key(0x5a),
                ),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
                Some(opened),
                false,
            )
            .expect("the actual root builds the door generation");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, &module)
                .expect("the configured Store boots its rate history before activation");
            limits.keep().expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            app
        };
        generation.cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
            Some(&card),
            0,
            &BTreeMap::new(),
        ));
        Arc::new(generation)
    };
    let steps = |app| {
        super::DoorSteps::new(
            &facts,
            &p,
            Arc::new(|_: &str| None),
            app,
            None,
            super::DoorCaller {
                principal: busbar_contract::caps::PrincipalId::new("caller"),
                key: None,
                open: true,
                arrived: 0,
                records: None,
                depth: 0,
                credential: None,
                ticket: None,
            },
        )
    };
    let old = steps(app(3));
    let new = steps(app(7));
    for (unit, expected) in [(&old, 3.0), (&new, 7.0), (&old, 3.0)] {
        let bag = unit.route_cost(&super::plane_lane("p", "a"));
        let terms = decode(&bag).unwrap().unwrap();
        assert_eq!(
            terms.iter().map(|t| t.price_per_unit).collect::<Vec<_>>(),
            vec![Some(expected), Some(0.0), Some(expected)]
        );
        assert_eq!(
            terms.iter().map(|t| t.expected_units).collect::<Vec<_>>(),
            vec![2.5, 0.0, 1.0]
        );
        for lane in [
            super::plane_lane("q", "a"),
            super::plane_lane("p", "unknown"),
        ] {
            let bag = unit.route_cost(&lane);
            assert!(decode(&bag)
                .unwrap()
                .unwrap()
                .iter()
                .all(|t| t.price_per_unit.is_none()));
        }
    }
    let no_card = steps(Arc::new({
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-steps-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual store");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let loaded = crate::root::real_store::store();
        let opened = busbar_contract::store_calls::OpenedStore {
            records: loaded.clone(),
            calls: Some(loaded),
        };
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            crate::root::test_plugins::trusted_config_with_key(
                &directory,
                &crate::root::test_plugins::key(0x5a),
            ),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            false,
        )
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the configured Store boots its rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app
    }));
    let bag = no_card.route_cost(&super::plane_lane("p", "a"));
    assert!(decode(&bag)
        .unwrap()
        .unwrap()
        .iter()
        .all(|t| t.price_per_unit.is_none()));
}

#[test]
fn a_pool_route_walks_its_named_pools_members_under_its_label() {
    let p = pools(SECTION);
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("both")),
        owned("both", &["a", "b"])
    );
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("a")),
        None,
        "an entry is no pool"
    );
    assert_eq!(routed(&p, ROUTE_POOL, Some("nowhere")), None, "unknown");
    assert_eq!(routed(&p, ROUTE_POOL, None), None, "none named");
}

#[test]
fn an_entrys_timeout_is_its_members_attempt_bound() {
    let p = pools("a: { timeout: 10s }\nb: {}\npools:\n  both:\n    members: [a, b]");
    assert_eq!(p.timeout_ms("a"), Some(10_000));
    assert_eq!(
        p.timeout_ms("b"),
        Some(busbar_contract::section::DEFAULT_ENTRY_TIMEOUT_MS),
        "none written: the core's default"
    );
    assert_eq!(p.timeout_ms("both"), None, "a pool is no entry");
    let m = pools("models:\n  m1: { provider: p, timeout: 2m }\n  m2: { provider: p }");
    assert_eq!(m.timeout_ms("m1"), Some(120_000));
    assert_eq!(m.timeout_ms("m2"), None);
}

#[test]
fn a_registration_that_writes_no_timeout_is_bounded_at_the_core_default() {
    let p = pools("fs: { url: \"http://up.example/rpc\" }\nslow: { timeout: 2m }");
    assert_eq!(
        p.timeout_ms("fs"),
        Some(30_000),
        "none written: the core's 30 s default, not the walk's budget"
    );
    assert_eq!(
        p.timeout_ms("slow"),
        Some(120_000),
        "a written timeout wins"
    );
    let m = pools("models:\n  m: { provider: p }");
    assert_eq!(
        m.timeout_ms("m"),
        None,
        "a model entry keeps 1.5.5's walk budget"
    );
}

#[test]
fn a_registration_that_is_no_tool_server_keeps_the_walk_budget() {
    let p = declared_by(
        "planner: { url: \"http://up.example/a2a\" }\nslow: { timeout: 2m }",
        "agents",
    );
    assert_eq!(
        p.timeout_ms("planner"),
        None,
        "none written on a section that relays no tool calls: the walk's own budget, not 30 s"
    );
    assert_eq!(
        p.timeout_ms("slow"),
        Some(120_000),
        "a written timeout wins"
    );
    let t = pools("fs: { url: \"http://up.example/rpc\" }");
    assert_eq!(
        t.timeout_ms("fs"),
        Some(busbar_contract::section::DEFAULT_ENTRY_TIMEOUT_MS),
        "a tool server that writes none keeps the 30 s default"
    );
}

#[test]
fn a_direct_route_walks_its_entry_alone_under_the_empty_label() {
    let p = pools(SECTION);
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("a")), owned("", &["a"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("both")),
        None,
        "a pool is no entry"
    );
    for reserved in ["hooks", "upstream_credentials", "pools"] {
        assert_eq!(routed(&p, ROUTE_DIRECT, Some(reserved)), None, "{reserved}");
    }
    assert_eq!(routed(&p, ROUTE_DIRECT, None), None, "none named");
}

#[test]
fn a_model_serving_sections_entries_are_its_models() {
    let p = pools("models:\n  m: {provider: p}\nhooks: []");
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("m")), owned("", &["m"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("models")),
        None,
        "the map is no entry"
    );
}

#[test]
fn a_name_that_is_not_text_or_a_class_unknown_routes_nowhere() {
    let p = pools("m: {}");
    assert_eq!(p.resolve(ROUTE_DIRECT, Some(&[0xff, 0xfe])), None);
    assert_eq!(p.resolve(ROUTE_DIRECT + 1, Some(b"m")), None);
}

#[test]
fn the_grant_is_judged_over_the_named_pool_then_its_fallback() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools(
        "a: {}\nb: {}\npools:\n  hot:\n    members: [a]\n    on_exhausted: {fallback_pool: cold}\n\
         \x20 cold:\n    members: [b]",
    );
    let key = |scopes: Option<&[&str]>| VirtualKey {
        allowed_scopes: scopes.map(|s| s.iter().map(|n| ScopeRef::pool(*n)).collect()),
        ..VirtualKey::default()
    };
    let granted = |k: Option<&VirtualKey>, class: u8, named: &str| {
        p.granted(Some("pool"), k, class, Some(named.as_bytes()))
    };
    assert!(
        granted(None, ROUTE_POOL, "hot"),
        "ungoverned: nothing to enforce"
    );
    assert!(
        granted(Some(&key(None)), ROUTE_POOL, "hot"),
        "an omitted grant is every pool"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "hot"),
        "its fallback is not granted"
    );
    assert!(granted(
        Some(&key(Some(&["hot", "cold"]))),
        ROUTE_POOL,
        "hot"
    ));
    assert!(
        !granted(Some(&key(Some(&[]))), ROUTE_POOL, "hot"),
        "an empty grant is none"
    );
    assert!(
        granted(Some(&key(Some(&["a"]))), ROUTE_DIRECT, "a"),
        "a direct route names its entry"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "nowhere"),
        "an unknown pool is refused by its grant first"
    );
    assert!(granted(
        Some(&key(Some(&["nowhere"]))),
        ROUTE_POOL,
        "nowhere"
    ));
    assert!(
        p.granted(None, Some(&key(Some(&["hot"]))), ROUTE_POOL, Some(b"cold")),
        "a plane with no scope kind scopes nothing"
    );
}

#[test]
fn test_adhoc_governance_pool_acl_403_via_router() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools("models:\n  configured-model: {provider: p}\npools:\n  other-pool:\n    members: [configured-model]");
    let elsewhere = VirtualKey {
        allowed_scopes: Some(vec![ScopeRef::pool("other-pool")]),
        ..VirtualKey::default()
    };
    assert!(
        !p.granted(
            Some("pool"),
            Some(&elsewhere),
            ROUTE_DIRECT,
            Some(b"configured-model")
        ),
        "a key allowed only on `other-pool` may not name the configured model directly"
    );
    assert!(
        p.granted(
            Some("pool"),
            Some(&elsewhere),
            ROUTE_POOL,
            Some(b"other-pool")
        ),
        "the same key is served on the pool it is granted"
    );
    assert_eq!(
        busbar_kernel::plane_driver::refusal_status(busbar_contract::caps::ReasonCode::ScopeDenied),
        403,
        "ad-hoc governance pool-ACL => 403"
    );
}

#[test]
fn a_member_granted_pool_route_is_judged_on_the_member_it_is_addressed_to() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools(
        "a: {}\nb: {}\npools:\n  twins:\n    members: [{name: a, tier: 0}, {name: b, tier: 1}]\n\
         \x20   member_granted: true",
    );
    let key = |scopes: &[&str]| VirtualKey {
        allowed_scopes: Some(
            scopes
                .iter()
                .map(|n| ScopeRef {
                    kind: "seat".to_string(),
                    value: (*n).to_string(),
                })
                .collect(),
        ),
        ..VirtualKey::default()
    };
    let granted = |k: &VirtualKey, counterparty: Option<&str>| {
        p.granted_to(
            Some("seat"),
            Some(k),
            (ROUTE_POOL, Some(b"twins".as_slice())),
            counterparty.map(str::as_bytes),
        )
    };
    assert!(
        granted(&key(&["a"]), Some("a")),
        "granted the member it addressed"
    );
    assert!(
        !granted(&key(&["b"]), Some("a")),
        "a twin's grant is not the addressed member's"
    );
    assert!(
        !granted(&key(&[]), Some("b")),
        "an empty grant reaches no member"
    );
    assert!(
        granted(&key(&[]), None),
        "no counterparty stated: the members are the plane's to judge"
    );
    assert!(
        granted(&key(&[]), Some("elsewhere")),
        "a counterparty outside the pool names no member of it"
    );
    assert!(
        p.granted_to(
            None,
            Some(&key(&[])),
            (ROUTE_POOL, Some(b"twins".as_slice())),
            Some(b"a")
        ),
        "a plane with no scope kind scopes nothing"
    );
}

#[test]
fn a_pool_members_tier_is_read_off_its_member() {
    let p = pools(
        "a: {}\nb: {}\nc: {}\nd: {}\npools:\n  t:\n    \
         members: [{name: b, tier: 2}, a, {name: c, tier: 1}, {name: d}]",
    );
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("t")),
        owned("t", &["b", "a", "c", "d"])
    );
    assert_eq!(
        (
            p.tier("t", 0),
            p.tier("t", 1),
            p.tier("t", 2),
            p.tier("t", 3)
        ),
        (2, 0, 1, 0)
    );
    assert_eq!(p.tier("absent", 0), 0);
}

#[test]
fn a_member_with_a_bad_tier_is_refused_at_the_section_build() {
    for (what, member) in [
        ("a word", "{name: a, tier: minus}"),
        ("a negative", "{name: a, tier: -1}"),
        ("a float", "{name: a, tier: 1.5}"),
        ("wider than u32", "{name: a, tier: 4294967296}"),
    ] {
        let section: serde_yaml::Value =
            serde_yaml::from_str(&format!("a: {{}}\npools:\n  u:\n    members: [{member}]"))
                .expect("yaml");
        let refused = DoorPools::of(&section, TOOL_CALL_SECTION_KEY)
            .err()
            .unwrap_or_else(|| panic!("{what}: a member written {member} built"));
        assert!(
            refused.contains("pool 'u'") && refused.contains("member 'a'"),
            "{what}: the refusal names the pool and member: {refused}"
        );
    }
}

#[test]
fn named_definition_pools_are_tiered_in_declared_order_and_the_plane_sees_bare_names() {
    let stated: std::collections::BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg> =
        [(
            "twins".to_string(),
            busbar_kernel::config::pools::CandidatePoolCfg {
                members: vec!["b".to_string(), "a".to_string()],
                repeatable: vec!["read".to_string()],
                breaker: None,
            },
        )]
        .into();
    let mut section: serde_yaml::Value = serde_yaml::from_str("a: {}\nb: {}").expect("yaml");
    crate::root::serve::pools_into(&mut section, &stated);
    let p = DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools");
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("twins")),
        owned("twins", &["b", "a"])
    );
    assert_eq!((p.tier("twins", 0), p.tier("twins", 1)), (0, 1));
    let handed = crate::root::serve::plane_settings(&section);
    let pool = &handed["pools"]["twins"];
    assert_eq!(
        pool["members"],
        serde_yaml::from_str::<serde_yaml::Value>("[b, a]").expect("yaml"),
        "the plane is handed bare names"
    );
    assert_eq!(
        pool["repeatable"],
        serde_yaml::from_str::<serde_yaml::Value>("[read]").expect("yaml")
    );
    assert_eq!(pool["member_granted"], serde_yaml::Value::Bool(true));
    assert_eq!(handed["a"], section["a"], "every other key as written");
}

#[test]
fn a_planes_pool_breaker_block_reaches_its_egress_and_never_the_plane() {
    let block = busbar_kernel::config::BreakerCfg {
        base_cooldown_secs: 30,
        max_cooldown_secs: 300,
        ..Default::default()
    };
    let stated: std::collections::BTreeMap<String, busbar_kernel::failover::CandidatePoolCfg> = [
        (
            "tuned".to_string(),
            busbar_kernel::failover::CandidatePoolCfg {
                members: vec!["a".to_string(), "b".to_string()],
                repeatable: Vec::new(),
                breaker: Some(block.clone()),
            },
        ),
        (
            "plain".to_string(),
            busbar_kernel::failover::CandidatePoolCfg {
                members: vec!["a".to_string(), "b".to_string()],
                repeatable: Vec::new(),
                breaker: None,
            },
        ),
    ]
    .into();
    let mut section: serde_yaml::Value = serde_yaml::from_str("a: {}\nb: {}").expect("yaml");
    crate::root::serve::pools_into(&mut section, &stated);
    let p = DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools");
    assert_eq!(
        p.breaker("tuned"),
        Some(&block),
        "the pool's own block, as stated"
    );
    assert_eq!(p.breaker("plain"), None, "no block: the defaults");
    let handed = crate::root::serve::plane_settings(&section);
    assert_eq!(
        handed["pools"]["tuned"], handed["pools"]["plain"],
        "the plane is handed the same pool whether or not the host tunes its breaker"
    );
}

#[test]
fn an_anonymous_unit_never_reaches_a_billed_path() {
    use super::Admission;
    use busbar_contract::records::VirtualKey;
    let key = std::sync::Arc::new(VirtualKey::default());
    assert_eq!(super::admission(None, true), Admission::Anonymous);
    assert_eq!(super::admission(None, false), Admission::Refused);
    assert_eq!(super::admission(Some(&key), true), Admission::Keyed);
    assert_eq!(super::admission(Some(&key), false), Admission::Keyed);
}

#[test]
fn the_door_facts_index_the_fee_units_among_the_billable_classes() {
    let f = super::door_facts(
        "p",
        &["grant"],
        &["a", "fee", "b"],
        &["fee", "nowhere"],
        "audit",
        Vec::new(),
    );
    assert_eq!(f.plane, "p");
    assert_eq!(f.scope_kind.as_deref(), Some("grant"));
    assert_eq!(&*f.fee_units, &[1]);
    assert_eq!(f.classes.len(), 3);
    assert_eq!(
        super::door_facts("p", &[], &[], &[], "a", Vec::new()).scope_kind,
        None
    );
}

#[test]
fn a_direct_route_walks_its_entrys_own_cell_and_a_pool_route_its_label() {
    let sep = busbar_kernel::governance::PLANE_LANE_SEP;
    assert_eq!(
        super::egress_pool("p", &(String::new(), vec!["m".to_string()])),
        format!("p{sep}m")
    );
    assert_eq!(
        super::egress_pool("p", &("both".to_string(), vec!["a".to_string()])),
        "both"
    );
}

#[test]
fn a_blocked_admission_renders_as_the_budget_units_door_does() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::governance::LimitBlocked;
    let limit = |metric: &'static str, retry_after| LimitBlocked::Limit {
        group: "g".into(),
        metric,
        window: Some("day"),
        pool: None,
        downgrade_to: None,
        retry_after,
    };
    let budget = super::refusal_for(&limit("budget", Some(30)));
    assert_eq!(budget.reason(), ReasonCode::OverBudget);
    assert_eq!(budget.retry_after_secs(), Some(30));
    for metric in ["requests", "tokens", "concurrent"] {
        assert_eq!(
            super::refusal_for(&limit(metric, None)).reason(),
            ReasonCode::RateLimited,
            "{metric}"
        );
    }
    assert_eq!(
        super::refusal_for(&LimitBlocked::Disabled("g".into())).reason(),
        ReasonCode::GroupFrozen
    );
    assert_eq!(
        super::refusal_for(&LimitBlocked::MissingGroup("g".into())).reason(),
        ReasonCode::OverBudget
    );
}

#[test]
fn a_units_principal_is_recorded_from_authenticate_until_its_steps_drop() {
    use busbar_contract::caps::PrincipalId;
    use busbar_kernel::host_units::UnitRecords;
    use busbar_kernel::plane_driver::DriverSteps;
    use busbar_kernel::teller::UnitCtx;
    let facts = super::door_facts("p", &[], &[], &[], "a", Vec::new());
    let pools = DoorPools::default();
    let records = std::sync::Arc::new(UnitRecords::default());
    let key = std::sync::Arc::new(busbar_contract::records::VirtualKey {
        id: "vk_one".into(),
        ..Default::default()
    });
    let ctx = |n: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(n),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let steps = |caller_key: Option<std::sync::Arc<busbar_contract::records::VirtualKey>>| {
        super::DoorSteps::new(
            &facts,
            &pools,
            std::sync::Arc::new(|_: &str| None),
            std::sync::Arc::new({
                #[cfg(distribution_root)]
                crate::dist_root_install::install();
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual store statement reads")
                    .expect("the actual store exports its statement");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual store statement is valid")
                    .name;
                let mut manifest = crate::root::test_plugins::manifest(
                    "store",
                    &module,
                    crate::root::test_plugins::FIXTURE_PUBLISHER,
                );
                manifest.statement = Some(hex::encode(statement));
                let release = crate::root::test_plugins::key(0x5a);
                let directory = crate::root::test_plugins::scratch(&format!(
                    "door-steps-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library = std::fs::read(library_path).expect("the actual store library reads");
                let archive = crate::root::test_plugins::signed(&release, manifest, &library);
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual store");
                crate::root::linked::register_stores(&crate::LINKED);
                busbar_kernel::preflight::install_linked_auth(
                    crate::LINKED.auths,
                    crate::root::auth_bindings::operator_words(),
                );
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                    "store": {"module": module, "settings": settings},
                }))
                .expect("the door deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the door deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let loaded = crate::root::real_store::store();
                let opened = busbar_contract::store_calls::OpenedStore {
                    records: loaded.clone(),
                    calls: Some(loaded),
                };
                let (app, rotate, limits) =
                    busbar_kernel::appbuild::build_app_from_config_with_store(
                        cfg,
                        crate::root::test_plugins::trusted_config_with_key(
                            &directory,
                            &crate::root::test_plugins::key(0x5a),
                        ),
                        None,
                        Default::default(),
                        Default::default(),
                        (None, None),
                        None,
                        &rules,
                        Some(opened),
                        false,
                    )
                    .expect("the actual root builds the door generation");
                limits.stage_boot();
                let _book = crate::root::boot::book(&app, &module)
                    .expect("the configured Store boots its rate history before activation");
                limits.keep().expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                app
            }),
            None,
            super::DoorCaller {
                principal: PrincipalId::new("vk_one"),
                key: caller_key,
                open: false,
                arrived: 0,
                records: Some(std::sync::Arc::clone(&records)),
                depth: 0,
                credential: None,
                ticket: None,
            },
        )
    };
    let keyed = steps(Some(std::sync::Arc::clone(&key)));
    assert!(records.get(7).is_none(), "nothing before authenticate");
    let _ = keyed.authenticate(&ctx(7));
    let held = records.get(7).expect("recorded at authenticate");
    assert_eq!(
        held.principal.as_ref().map(|k| k.id.as_str()),
        Some("vk_one")
    );
    drop(keyed);
    assert!(records.get(7).is_none(), "struck when its steps drop");

    let unkeyed = steps(None);
    let _ = unkeyed.authenticate(&ctx(8));
    assert!(records.get(8).is_none(), "a refused unit writes no record");
}

fn downgrading(pool: &str, amount: u64, to: &str) -> busbar_kernel::config::groups::LimitCfg {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow, OnExhaust};
    LimitCfg {
        metric: LimitMetric::Budget,
        amount,
        per: Some(LimitWindow::Day),
        scope: Some(busbar_contract::records::ScopeRef::pool(pool)),
        on_exhaust: Some(OnExhaust::Downgrade),
        downgrade_to: Some(busbar_contract::records::ScopeRef::pool(to)),
        admission: None,
        on_exhaustion: None,
    }
}

fn downgrade_book(
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    allowed_pools: Option<Vec<String>>,
) -> (
    std::sync::Arc<busbar_kernel::state::App>,
    std::sync::Arc<busbar_contract::records::VirtualKey>,
) {
    let governance_store = crate::root::real_store::store();
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            governance_store.clone(),
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("the real store opens governance"),
    );
    assert!(
        gov.attach_store_calls(governance_store),
        "attach the actual store calls"
    );
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(None, 10, &groups);
    let (key, _secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                allowed_pools,
                group: Some("team".to_string()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("a key");
    let mut app = {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-steps-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual store");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let loaded = crate::root::real_store::store();
        let opened = busbar_contract::store_calls::OpenedStore {
            records: loaded.clone(),
            calls: Some(loaded),
        };
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            crate::root::test_plugins::trusted_config_with_key(
                &directory,
                &crate::root::test_plugins::key(0x5a),
            ),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            false,
        )
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the configured Store boots its rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app
    };
    app.auth = std::sync::Arc::new(
        busbar_kernel::auth::AuthMiddleware::new(
            &busbar_kernel::config::AuthCfg {
                chain: vec![busbar_kernel::config::AuthChainEntry::bare(
                    busbar_kernel::config::KEYS_MODULE,
                )],
                ..busbar_kernel::config::AuthCfg::default_none()
            },
            &app.hook_env.registry,
            &app.secret_resolver,
        )
        .expect("the actual root constructs the keys middleware"),
    );
    gov.hydrate_budgets(&cost, 0)
        .expect("the real governance hydrates its budget");
    app.governance = Some(gov);
    app.groups_registry = groups;
    app.cost = std::sync::Arc::new(cost);
    let app = std::sync::Arc::new(app);
    (app, std::sync::Arc::new(key))
}

struct Charged {
    admitted: Result<(), (busbar_contract::caps::ReasonCode, Option<String>)>,
    routed: Option<(String, Vec<String>)>,
    downgraded: Option<String>,
}

fn charge_once(
    app: &std::sync::Arc<busbar_kernel::state::App>,
    key: &std::sync::Arc<busbar_contract::records::VirtualKey>,
    pools: &DoorPools,
    pool: &str,
    unit: u64,
) -> Charged {
    charge_once_at(app, key, pools, pool, unit, busbar_kernel::store::now())
}

fn charge_once_at(
    app: &std::sync::Arc<busbar_kernel::state::App>,
    key: &std::sync::Arc<busbar_contract::records::VirtualKey>,
    pools: &DoorPools,
    pool: &str,
    unit: u64,
    arrived: u64,
) -> Charged {
    use busbar_kernel::plane_driver::{DriverSteps as _, EndPost, PlaneMoney};
    let facts = super::door_facts("", &["pool"], &[], &[], "door", Vec::new());
    let gov = std::sync::Arc::clone(app.governance.as_ref().expect("a governed generation"));
    let post = std::sync::Arc::new(crate::root::plane_node::NodeEndPost::new(
        std::sync::Arc::new(crate::root::plane_node::Node::new()),
    ));
    let money = PlaneMoney::new(gov, post as std::sync::Arc<dyn EndPost>);
    let steps = super::DoorSteps::new(
        &facts,
        pools,
        std::sync::Arc::new(|_: &str| None),
        std::sync::Arc::clone(app),
        Some(&money),
        super::DoorCaller {
            principal: busbar_contract::caps::PrincipalId::new(key.id.as_str()),
            key: Some(std::sync::Arc::clone(key)),
            open: false,
            arrived,
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    steps.lock().routed = pools.resolve(ROUTE_POOL, Some(pool.as_bytes()));
    let ctx = busbar_kernel::teller::UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(unit),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let admitted = steps
        .charge(&ctx, key)
        .map(|_| ())
        .map_err(|refusal| (refusal.reason(), steps.refused_words().1));
    Charged {
        admitted,
        routed: steps.routed(),
        downgraded: steps.downgraded(),
    }
}

const DOWNGRADE_SECTION: &str = "models:\n  big: {}\n  small: {}\n  tiny: {}\n\
     pools:\n  frontier:\n    members: [big]\n  value:\n    members: [small]\n\
     \x20 first:\n    members: [big]\n  second:\n    members: [small]\n  third:\n    members: [tiny]";

#[test]
fn an_exhausted_budget_re_pools_the_unit_through_its_downgrade_pool() {
    let (app, key) = downgrade_book(vec![downgrading("frontier", 25, "value")], None);
    let pools = pools(DOWNGRADE_SECTION);

    for unit in 1..=2 {
        let charged = charge_once(&app, &key, &pools, "frontier", unit);
        assert_eq!(
            charged.admitted,
            Ok(()),
            "unit {unit} is under the frontier cap"
        );
        assert_eq!(charged.downgraded, None, "no downgrade while under the cap");
        assert_eq!(charged.routed, owned("frontier", &["big"]));
    }
    let charged = charge_once(&app, &key, &pools, "frontier", 3);
    assert_eq!(charged.admitted, Ok(()), "downgraded, not refused");
    assert_eq!(
        charged.downgraded.as_deref(),
        Some("value"),
        "the charge landed on the downgrade pool"
    );
    assert_eq!(
        charged.routed,
        owned("value", &["small"]),
        "the walk follows the charge to the downgrade pool"
    );
}

#[test]
fn a_downgrade_cycle_ends_in_the_plain_refusal_naming_the_last_pool_walked() {
    let (app, key) = downgrade_book(
        vec![
            downgrading("first", 10, "second"),
            downgrading("second", 0, "third"),
            downgrading("third", 0, "second"),
        ],
        None,
    );
    let pools = pools(DOWNGRADE_SECTION);
    let first = charge_once(&app, &key, &pools, "first", 1);
    assert_eq!(first.admitted, Ok(()), "under the first pool's cap");
    assert_eq!(first.downgraded, None);
    let second = charge_once(&app, &key, &pools, "first", 2);
    let (reason, words) = second
        .admitted
        .expect_err("a cyclic downgrade chain ends in a refusal");
    assert_eq!(reason, busbar_contract::caps::ReasonCode::OverBudget);
    let words = words.expect("the plane serving the `pools` map renders 1.5.5's words");
    assert!(
        words.contains("pool 'third'"),
        "the chain walked first -> second -> third before the revisit guard: {words}"
    );
    assert_eq!(
        second.downgraded, None,
        "a refused unit is re-pooled nowhere"
    );
}

#[test]
fn a_downgrade_never_routes_a_key_into_a_pool_it_may_not_use() {
    let (app, key) = downgrade_book(
        vec![downgrading("frontier", 25, "value")],
        Some(vec!["frontier".to_string()]),
    );
    let pools = pools(DOWNGRADE_SECTION);
    for unit in 1..=2 {
        assert_eq!(
            charge_once(&app, &key, &pools, "frontier", unit).admitted,
            Ok(())
        );
    }
    let charged = charge_once(&app, &key, &pools, "frontier", 3);
    assert_eq!(
        charged.admitted.map_err(|(reason, _)| reason),
        Err(busbar_contract::caps::ReasonCode::OverBudget),
        "the plain budget refusal, not a leaked pool"
    );
    assert_eq!(charged.downgraded, None);
    assert_eq!(
        charged.routed,
        owned("frontier", &["big"]),
        "the route is unchanged"
    );
}

fn styled() -> crate::root::loader::dispatch::kinds::plane::ServedFacts {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "bearer")],
        dialects: vec!["d"],
        dialect_auth: vec![(0, "bearer", b"")],
        ..Default::default()
    }
}

fn provider(protocol: &str, style: Option<&str>) -> super::ProviderRoute {
    super::ProviderRoute {
        base_url: "http://127.0.0.1:9".to_string(),
        userinfo: None,
        protocol: protocol.to_string(),
        error_map: Default::default(),
        credential: busbar_contract::secret_ref::SecretRef::none(),
        style: style.map(str::to_string),
        params: super::StyleParams::default(),
        metadata: busbar_kernel::config_validate::MetadataPosture::default(),
    }
}

fn resolve_for(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_over(section, providers, facts)
}

fn resolve_over(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_upgrading(section, providers, served, Vec::new())
}

fn resolve_upgrading(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    upgrades: Vec<&'static str>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let section: serde_yaml::Value = serde_yaml::from_str(section).expect("yaml");
    let providers = providers
        .iter()
        .map(|(n, p)| ((*n).to_string(), p.clone()))
        .collect();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    crate::root::connector::install_io(&dispatcher);

    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let auths = super::OutboundAuths::new(
        dispatcher,
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    );
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: std::sync::Arc::new(auths),
        conns,
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades,
    };
    super::member_routes(
        &section,
        &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
        served,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
}

#[test]
fn a_need_over_an_upgrade_framer_spells_the_base_url_in_its_scheme() {
    let upgrades = ["ws"];
    assert_eq!(
        super::spelled_for("https://api.example/v1", "ws", &upgrades).as_deref(),
        Some("wss://api.example/v1")
    );
    assert_eq!(
        super::spelled_for("http://127.0.0.1:9/v1", "ws", &upgrades).as_deref(),
        Some("ws://127.0.0.1:9/v1")
    );
    assert_eq!(
        super::spelled_for("https://api.example", "http", &upgrades),
        None
    );
    assert_eq!(super::spelled_for("https://api.example", "ws", &[]), None);
    assert_eq!(super::spelled_for("unix:///sock", "ws", &upgrades), None);
}

#[cfg(feature = "auth-header")]
#[test]
fn a_member_bound_over_an_upgrade_need_dials_its_spelled_base() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
        ],
        need_transports: vec!["http", "ws"],
        ..styled()
    };
    let routes = resolve_upgrading(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
        vec!["ws"],
    )
    .expect("the member resolves");
    let route = &routes["m"];
    let base = route.base_url.clone();
    let spelled = base.replacen("http://", "ws://", 1);
    assert!(base.starts_with("http://"), "{base}");
    assert_eq!(route.ride(0).map(|r| r.base_url), Some(base.as_str()));
    assert_eq!(route.ride(2).map(|r| r.base_url), Some(spelled.as_str()));
}

#[cfg(feature = "auth-header")]
#[test]
fn a_member_binds_every_need_its_style_names_one_per_transport() {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_INBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "api-key"),
        ],
        need_transports: vec!["ws", "ws", "http", "ws"],
        ..styled()
    };
    let routes = resolve_over(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
    )
    .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 1, "its first bound need is its own");
    let rides: Vec<u32> = route.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "the http need rides beside it; the api-key need is not its style"
    );
    assert_eq!(route.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(route.ride(0).map(|r| r.need.0), Some(1));
    assert!(
        route.ride(4).is_none(),
        "a need its style does not name is no ride"
    );
}

fn resolve(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_for(&styled(), section, providers)
}

#[cfg(feature = "auth-header")]
#[test]
fn a_member_is_bound_under_its_dialects_default_style_on_the_need_that_style_names() {
    let routes = resolve("models: {m: {provider: p}}", &[("p", provider("d", None))])
        .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 0);
    assert_eq!(route.provider, "p");
    assert_eq!(route.base_url, "http://127.0.0.1:9");
    assert!(
        route.auth.is_some(),
        "its credential is bound by the plugin serving `bearer`"
    );
}

#[test]
fn a_provider_base_url_with_userinfo_is_reached_at_its_stripped_authority() {
    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(
        "{protocol: d, base_url: 'https://svcuser:hunter2-P4ss@api.example.com:8443/v1', \
         api_key: none, error_map: {}}",
    )
    .expect("a provider entry");
    let routes = super::provider_routes(
        &std::collections::HashMap::from([(
            "p".to_string(),
            busbar_kernel::config::ResolvedProvider::from(provider),
        )]),
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let route = &routes["p"];
    assert_eq!(route.base_url, "https://api.example.com:8443/v1");
    assert!(
        route.userinfo.is_some(),
        "the userinfo is held, opaque, for the member's attempts to present as 1.5.5 did"
    );
    let shown = format!("{route:?}");
    assert!(
        !shown.contains("hunter2") && !shown.contains("svcuser"),
        "the route kept the planted spelling: {shown}"
    );
}

#[cfg(feature = "auth-header")]
#[test]
fn a_members_base_url_userinfo_reaches_its_attempts_only_through_its_binding() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_contract::auth_calls::{Fields, FieldsRequest};
    const WRITTEN: &str = "https://svcuser:hunter2-P4ss@api.example.com/v1";
    let key_file =
        std::env::temp_dir().join(format!("busbar-door-steps-row74-{}", std::process::id()));
    std::fs::write(&key_file, "sk-row74").expect("the key");
    let expected = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
        )
    };
    for (style, led) in [("api-key", true), ("bearer", false)] {
        let provider = super::ProviderRoute {
            base_url: busbar_kernel_egress::trust::net::strip_userinfo(WRITTEN).into_owned(),
            userinfo: crate::root::userinfo::UserinfoBasic::of(WRITTEN),
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: busbar_contract::secret_ref::SecretRef::file(
                key_file.display().to_string(),
            ),
            style: Some(style.to_string()),
            params: super::StyleParams::default(),
            metadata: busbar_kernel::config_validate::MetadataPosture::default(),
        };
        let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
            need_auths: vec![(DIRECTION_OUTBOUND, style)],
            dialects: vec!["d"],
            ..Default::default()
        };
        let routes = resolve_for(&facts, "models: {m: {provider: p}}", &[("p", provider)])
            .expect("the member resolves");
        let route = &routes["m"];
        assert_eq!(route.base_url, "https://api.example.com/v1");
        let binding = route.auth.as_ref().expect("its credential is bound");
        let Some(Fields::Ready(fields)) = binding
            .auth
            .fields_now(binding.handle, &FieldsRequest::default())
        else {
            panic!("the {style} binding answers on the spot");
        };
        let fields: Vec<(String, String)> = fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).to_ascii_lowercase(),
                    String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend()))
                        .into_owned(),
                )
            })
            .collect();
        if led {
            assert_eq!(
                fields[0],
                ("authorization".to_string(), expected.clone()),
                "a credential under another field leaves the Basic value first: {fields:?}"
            );
            assert!(fields[1..].iter().all(|(n, _)| n != "authorization"));
        } else {
            assert!(
                fields
                    .iter()
                    .all(|(n, v)| n != "authorization" || !v.starts_with("Basic ")),
                "an authorization credential displaces the Basic value: {fields:?}"
            );
        }
    }
    let _ = std::fs::remove_file(&key_file);
}

#[cfg(feature = "auth-header")]
#[test]
fn a_member_whose_protocol_states_no_default_style_rides_its_providers() {
    let routes = resolve(
        "models: {m: {provider: p, protocol: x-envelope}}",
        &[("p", provider("d", None))],
    )
    .expect("the member resolves under its provider's default style");
    assert!(
        routes["m"].auth.is_some(),
        "bound by the plugin serving `bearer`"
    );
    let styleless = resolve(
        "models: {m: {provider: p, protocol: x-envelope}}",
        &[("p", provider("x", None))],
    );
    assert!(
        styleless.as_ref().is_err_and(|e| e.contains("no `auth:`")),
        "neither the member's protocol nor its provider's states a default: {:?}",
        styleless.err()
    );
}

#[test]
fn a_member_that_cannot_be_reached_refuses_the_load_naming_it() {
    let unknown = resolve("models: {m: {provider: q}}", &[("p", provider("d", None))]);
    assert!(
        unknown
            .as_ref()
            .is_err_and(|e| e.contains("'m'") && e.contains("'q'")),
        "{:?}",
        unknown.err()
    );

    let styleless = resolve("models: {m: {provider: p}}", &[("p", provider("x", None))]);
    assert!(
        styleless.as_ref().is_err_and(|e| e.contains("no `auth:`")),
        "{:?}",
        styleless.err()
    );

    let unmatched = resolve(
        "models: {m: {provider: p}}",
        &[("p", provider("d", Some("api-key")))],
    );
    assert!(
        unmatched.as_ref().is_err_and(|e| e.contains("api-key")),
        "{:?}",
        unmatched.err()
    );
}

#[test]
fn a_members_binding_is_opened_with_its_dialects_parameters_under_the_providers_own() {
    use super::sealed_settings;
    let params = br#"{"service":"svc","content_type":"application/json","region":{"host_label_after":["svc-runtime","svc-runtime-fips","svc"],"default":"us-east-1","unread":"w"}}"#;
    let region = |base_url: &str| {
        sealed_settings(params, base_url, &serde_json::json!({})).expect("the parameters seal")
            ["region"]
            .clone()
    };
    for (base_url, want) in [
        ("https://svc-runtime.eu-west-1.amazonaws.com", "eu-west-1"),
        (
            "https://svc-runtime-fips.us-gov-west-1.amazonaws.com/",
            "us-gov-west-1",
        ),
        (
            "https://vpce-0abc-1xyz.svc-runtime.ap-southeast-2.vpce.amazonaws.com:443/x",
            "ap-southeast-2",
        ),
        ("https://svc.ca-central-1.amazonaws.com", "ca-central-1"),
        ("https://svc-runtime.amazonaws.com", "us-east-1"),
        ("http://127.0.0.1:9000", "us-east-1"),
        ("https://svc-runtime.eu-west.amazonaws.com", "us-east-1"),
    ] {
        assert_eq!(region(base_url), serde_json::json!(want), "{base_url}");
    }
    let sealed = sealed_settings(
        params,
        "https://svc-runtime.eu-west-1.amazonaws.com",
        &serde_json::json!({ "service": "own", "scope": "s" }),
    )
    .expect("the parameters seal");
    assert_eq!(
        sealed["service"], "own",
        "the provider's own setting stands"
    );
    assert_eq!(sealed["scope"], "s");
    assert_eq!(sealed["content_type"], "application/json");
    assert!(
        sealed.get("region_unread").is_none(),
        "a host whose region reads hands on no warning"
    );
    let defaulted = sealed_settings(params, "http://127.0.0.1:9000", &serde_json::json!({}))
        .expect("the parameters seal");
    assert_eq!(defaulted["region"], "us-east-1");
    assert_eq!(
        defaulted["region_unread"], "w",
        "the warning travels with the default"
    );
    let own = serde_json::json!({ "token_url": "https://t" });
    assert_eq!(sealed_settings(b"", "https://x", &own), Ok(own));
    assert!(sealed_settings(b"[1]", "https://x", &serde_json::json!({})).is_err());
}

#[test]
fn the_signing_region_is_read_off_the_host_the_request_dials() {
    use super::sealed_settings;
    let params = br#"{"region":{"host_label_after":["svc-runtime"],"default":"us-east-1"}}"#;
    for base_url in [
        "https://svc-runtime.us-west-2.amazonaws.com\\@svc-runtime.eu-west-1.amazonaws.com/",
        "https://svc-runtime.us-west-2.amazonaws.com\\x@svc-runtime.eu-west-1.amazonaws.com",
    ] {
        let dialled = busbar_contract::net::url_host(base_url).expect("the base URL reads a host");
        assert_eq!(dialled, "svc-runtime.us-west-2.amazonaws.com", "{base_url}");
        let sealed =
            sealed_settings(params, base_url, &serde_json::json!({})).expect("the parameters seal");
        assert_eq!(
            sealed["region"], "us-west-2",
            "{base_url}: the region is the dialled host's"
        );
    }
}

type HeadFields = Vec<(String, Vec<u8>)>;

/// A connection table standing in for the token endpoint: framed needs, each declaration and each
/// open recorded, each open answered by the endpoint's next reply (`expires_in` 2, then 3600), one
/// piece per read.
#[derive(Default)]
pub(crate) struct TokenEndpoint {
    slab: busbar_contract::conn::ConnSlab<()>,
    declared: std::sync::Mutex<Vec<(u32, u32, Option<String>)>>,
    opened: std::sync::Mutex<Vec<Opened>>,
    /// Each open's head fields, as the table received them.
    fields: std::sync::Mutex<Vec<HeadFields>>,
    /// Independent dial, whole-request and secure-delivery requirements seen at the host seam.
    bounds: std::sync::Mutex<Vec<(u64, u64, bool)>>,
    replies: std::sync::Mutex<Replies>,
    /// The reply body to a request body, when the endpoint answers by what it was asked (an RFC
    /// 8693 exchange's token names its scope); `None` = the minted replies above.
    answer: Option<fn(&str) -> String>,
    /// How many exchanges the plugin closed: it closes each one once it has read the token, the
    /// event a test waits on for a mint (never the wall clock, Law 8; row 176).
    closes: std::sync::Mutex<usize>,
    /// Told on each close.
    closing: tokio::sync::Notify,
}

impl TokenEndpoint {
    async fn closed(&self, n: usize) {
        loop {
            let notified = self.closing.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self.closes.lock().unwrap() >= n {
                return;
            }
            notified.await;
        }
    }
}

type Opened = (u32, String, Vec<u8>, String);

type Replies = std::collections::HashMap<
    busbar_contract::conn::ConnId,
    std::collections::VecDeque<(busbar_contract::conn::Piece, Vec<u8>)>,
>;

fn reply_piece(kind: busbar_contract::conn::PieceKind, len: usize) -> busbar_contract::conn::Piece {
    use busbar_contract::conn::PieceKind;
    busbar_contract::conn::Piece {
        kind,
        stream: busbar_contract::ids::StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: (kind == PieceKind::Fields).then_some(200),
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl busbar_contract::conn::DeclaredConns for TokenEndpoint {
    fn open_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        use busbar_contract::conn::Conns as _;
        self.bounds
            .lock()
            .unwrap()
            .push((dial_timeout_ms, desc.timeout_ms, require_secure));
        self.open_with_security(caller, need, desc, require_secure)
    }

    fn declare(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        target: Option<&str>,
        _trust: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((need.0, spec.egress_class, target.map(str::to_owned)));
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(busbar_contract::conn::ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> bool {
        true
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

#[test]
fn presenting_a_request_preserves_its_independent_bounds_and_secure_delivery_requirement() {
    use busbar_contract::conn::{ConnError, DeclaredConns, InstanceId, NeedId, OpenDesc};
    use std::sync::Arc;
    const OWNER: InstanceId = InstanceId(99);
    const NEED: NeedId = NeedId(0);
    const TARGET: &str = "https://user:pass@tokens.test/mint";
    let endpoint = Arc::new(TokenEndpoint::default());
    endpoint.slab.declare(OWNER, NEED);
    let table = super::PresentingConns {
        inner: endpoint.clone(),
        userinfo: crate::root::userinfo::UserinfoBasic::of(TARGET).unwrap(),
    };
    let fields: &[(&str, &[u8])] = &[("x-order", b"last")];
    let desc = OpenDesc {
        target: TARGET,
        fields,
        timeout_ms: 900,
        ..Default::default()
    };
    table.open_request(OWNER, NEED, &desc, false, 123).unwrap();
    assert_eq!(*endpoint.bounds.lock().unwrap(), vec![(123, 900, false)]);
    assert_eq!(
        endpoint.opened.lock().unwrap()[0].1,
        "https://tokens.test/mint"
    );
    let sent = endpoint.fields.lock().unwrap();
    assert_eq!(sent[0][0].0, "authorization");
    assert!(sent[0][0].1.starts_with(b"Basic "));
    assert_eq!(sent[0][1], ("x-order".to_owned(), b"last".to_vec()));
    drop(sent);
    assert_eq!(
        table.open_request(OWNER, NEED, &desc, true, 456),
        Err(ConnError::AuthRefused)
    );
    assert_eq!(endpoint.bounds.lock().unwrap()[1], (456, 900, true));
    assert_eq!(
        endpoint.opened.lock().unwrap().len(),
        1,
        "protected fields never reach an insecure open"
    );
}

impl busbar_contract::conn::Conns for TokenEndpoint {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        use busbar_contract::conn::PieceKind;
        self.slab.check_need(caller, need)?;
        self.fields.lock().unwrap().push(
            desc.fields
                .iter()
                .map(|(n, v)| ((*n).to_string(), v.to_vec()))
                .collect(),
        );
        let mut opened = self.opened.lock().unwrap();
        opened.push((
            need.0,
            desc.target.to_owned(),
            desc.head_target.to_vec(),
            String::from_utf8_lossy(&desc.body).into_owned(),
        ));
        let n = opened.len();
        let body = match self.answer {
            Some(answer) => answer(&opened[n - 1].3),

            None => format!(
                r#"{{"access_token":"oracle-minted-{n}","expires_in":{}}}"#,
                if n == 1 { 10 } else { 3600 }
            ),
        };
        let id = self.slab.insert(caller, need, ())?;
        self.replies.lock().unwrap().insert(
            id,
            std::collections::VecDeque::from([
                (reply_piece(PieceKind::Fields, 0), Vec::new()),
                (reply_piece(PieceKind::Body, body.len()), body.into_bytes()),
                (reply_piece(PieceKind::Completion, 0), Vec::new()),
            ]),
        );
        Ok(id)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Ok(b.len())
    }
    fn read(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.slab.get(c, id)?;
        let (p, bytes) = self
            .replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(std::collections::VecDeque::pop_front)
            .ok_or(busbar_contract::conn::ConnError::Closed)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Pending)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.replies.lock().unwrap().remove(&id);
        let closed = self.slab.remove(c, id).map(|_| ());
        *self.closes.lock().unwrap() += 1;
        self.closing.notify_waiters();
        closed
    }
}

fn presented(answer: Option<&busbar_contract::auth_calls::Fields>) -> Option<String> {
    match answer? {
        busbar_contract::auth_calls::Fields::Ready(fields) => fields.iter().find_map(|f| {
            (f.name == b"authorization").then(|| {
                String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend())).into_owned()
            })
        }),
        _ => None,
    }
}

fn linked_mint_plugin(table: &std::sync::Arc<TokenEndpoint>) -> super::OutboundAuths {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::with_services(
        crate::root::loader::dispatch::DispatchConfig::default(),
        crate::root::serve::LateServices::new().served(),
    ));
    assert!(
        dispatcher.host_services().is_some(),
        "the plugin's clock is the host's: a dispatcher serving no host services answers no \
         `clock.now`"
    );
    crate::root::connector::install_io(&dispatcher);

    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());

    let name = "busbar-auth-oauth";
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] = [(name, name, busbar_auth_oauth::door)];
    super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::Host(std::sync::Arc::clone(table)
            as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_an_oauth_grant_presents_its_minted_then_refreshed_bearer() {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_PROVIDER};
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    let basic = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
        )
    };

    for written in [
        TOKEN_URL.to_string(),
        TOKEN_URL.replacen("://", "://svcuser:hunter2-P4ss@", 1),
    ] {
        let key_file =
            std::env::temp_dir().join(format!("busbar-door-steps-oauth-{}", std::process::id()));
        std::fs::write(&key_file, "oracle-client-0001:oracle:secret:with:colons").expect("key");
        let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
            "p".to_string(),
            super::ProviderRoute {
                base_url: "http://127.0.0.1:9".to_string(),
                userinfo: None,
                protocol: "d".to_string(),
                error_map: Default::default(),
                credential: busbar_contract::secret_ref::SecretRef::file(
                    key_file.display().to_string(),
                ),
                style: Some("oauth-client-credentials".to_string()),
                params: super::StyleParams {
                    token_url: Some(written.clone()),
                    scope: Some("https://cognitiveservices.azure.com/.default".to_string()),
                    ..super::StyleParams::default()
                },
                metadata: busbar_kernel::config_validate::MetadataPosture::default(),
            },
        )]
        .into();
        let table = std::sync::Arc::new(TokenEndpoint::default());
        let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
            std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
        let reach = super::DoorReach {
            providers: &providers,
            secrets: std::sync::Arc::clone(&secrets),
            auths: std::sync::Arc::new(linked_mint_plugin(&table)),
            conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
            stream_ceiling_secs: 1,
            catalog: None,
            models: None,
            upgrades: Vec::new(),
        };
        let section: serde_yaml::Value =
            serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
        let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
            need_auths: vec![(DIRECTION_OUTBOUND, "oauth-client-credentials")],
            dialects: vec!["d"],
            ..Default::default()
        };
        let routes = super::member_routes(
            &section,
            &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
            &facts,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("the member resolves");
        let _ = std::fs::remove_file(&key_file);
        let binding = routes["m"].auth.clone().expect("its credential is bound");
        assert!(
            table.declared.lock().unwrap().contains(&(
                0,
                EGRESS_PROVIDER,
                Some(TOKEN_URL.to_string())
            )),
            "the plugin's provider-class need (security item 3, busbar-auth-oauth #43: a private \
             token endpoint refused unless allowlisted), pinned to the provider's token_url: {:?}",
            table.declared.lock().unwrap()
        );

        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);
        let first = tokio::time::timeout(HANG_GUARD, async {
            table.closed(1).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                match presented(now.as_ref()).as_deref() {
                    Some("Bearer oracle-minted-1") => return,
                    None => {}
                    other => panic!("only the first minted bearer, or none yet: {other:?}"),
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(first.is_ok(), "the first minted bearer is presented");

        let refreshed = tokio::time::timeout(HANG_GUARD, async {
            table.closed(2).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                if presented(now.as_ref()).as_deref() == Some("Bearer oracle-minted-2") {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(refreshed.is_ok(), "the refreshed bearer is presented");
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
        assert!(opened.iter().all(|(need, target, words, _)| *need == 0
            && target == TOKEN_URL
            && words == b"/tenant/oauth2/v2.0/token"));
        assert_eq!(
            opened[1].3,
            "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
             oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
        );
        drop(opened);

        let fields = table.fields.lock().unwrap();
        assert_eq!(fields.len(), 2);
        for head in fields.iter() {
            let lead = head.first().map(|(n, v)| (n.as_str(), v.as_slice()));
            if written == TOKEN_URL {
                assert!(
                    !head
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case("authorization")),
                    "a plain endpoint's mint presents no authorization: {head:?}"
                );
            } else {
                assert_eq!(lead, Some(("authorization", basic.as_bytes())), "{head:?}");
            }
            assert!(
                head.iter()
                    .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
                "the userinfo rides only as its Basic value: {head:?}"
            );
        }
    }
}

const TEST_SA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu2RTBghXyuvqd\n\
v/4AIq1NcPzdRUCr0wyjEH35avOM9vSW+fuira0UtCQcyTHJZswoJqgwcdO2SRav\n\
/QMZhnjB/sCzuvHrbILd/T0nK19Fdld/wKMQlQlqz94OpS5b0J/nEc7/IOTxszbq\n\
4B2geG7lJc5wm3dMjKwr7IPbnWs5fMEVyZFaFsctrejOTURx8duff8eM2L+Lf5No\n\
H2k0h+6blyDTq1Iu+9UM5/AfycgvdhPlcKCL1VZq9+YY5zW5GuXj997TnEWEeiam\n\
ZfaHklhdSX3zzSUkShqayzaxX6YRdlUvE6yEIkjq/AVRVrMZDynyD7J0nsyjykhx\n\
WVh79c5fAgMBAAECggEALHaz2onUPwfhl6AtXadz3s+u3i4wRgHDouwcvQK/sMdU\n\
Z9hmb3YvH6a30EIx0P+9RzCdcMRhjGeFx3dWBHW3282G/624u5+6n+04Ue+rqKRx\n\
l+FLFnpwDKOT2rGS2nJxV3el5iddUUG743rezeISgV9d4jEG44aaegkJdx3PGKz/\n\
E76BIyi9H4oUgiqIyPW2trPEeg5n/1oVMHLGDBhotuM7VPUCegh/J3e1jSxcYvi8\n\
0CutgOLynZAS1xSatbbp8nWrUSRHOUYrgE9OYbS7TSgGz1PjzdcmLEsHEGcor0wm\n\
cT4oePDjZmuxICFBSg96Ffb82t6UGXC7xLQbglsfQQKBgQDlBOBtVQafWVJiEj83\n\
fG2YfKTMx1neGO/6ftBMn7XUt4D/AbL0Kx0/Z5lfxm2cixlxcGWT6e96CmZmEsyA\n\
RFSyuG/bvbTF1c0vaKXcjghtPH5TaB6MjgP3VmjOHR5V5o3JMQX0Xayxf/kBP//f\n\
wfolsPUM5hcB7pMjVDQz0OZacQKBgQDDcm0i42UA1wrh4XUTNAbVHfacTm/zBhVB\n\
zvtEC3WGkBCRdU9JSwFAJitPmxrVS3+w2fxO47IiSngeQEyC2neew/H5FrWSNs+L\n\
xV9Jystubq6oTCulEGBP4gb99FkDY2RToNYOjVrEQDsmiijv3CeZyHnes0/8uMQq\n\
5ekEveH9zwKBgBZvR9zt+1wYz+0zhGXXFpVdgHde//q1zqxnR9h5vMI9x7EzZWht\n\
4MuZRnkPYyV2quNl801uGTuHUUimhsn556IqVyrbhp3qt9LxGW5lq4Wn62gYRwXV\n\
06WjHVkzmQkpMLKIzuCFXKl2s9nffx1YTzzp/Ndqos5ZpKhNU1/QEwDBAoGAfVvA\n\
WldFqmNDbJwCTp3ZIAqG6bx5m4O0ULBkg0FiUTvIFLQMdbMxCycwMnAGpvY04Yb/\n\
iM4MrGfdYXHWYTuk6+U8J4sETNLxDfI7awYysxM03Wd1uvqk+7e6ylpWWZD/gZAw\n\
m8bYh/W2usJ0/VvU3pMyb7/NNwh/chBjBBKSiAsCgYEAsTCMDD6CYdncyFWMtWpK\n\
vaTrTko3xPDigybk5520jK5UkEaZr0meRn1CFYFAnfUs0sKB4EbWkcmkZOayPPtQ\n\
su3l06s8o+WrP8Bp2GikIg+jVz9sdz9Vph0Vr0VOPwdBKbWUT4As0r6Muceq+sH6\n\
oy3z0wnL4GXkIelYmU1zCk0=\n\
-----END PRIVATE KEY-----\n";

fn jwt_bearer_routes(
    token_uri: &str,
    metadata: busbar_kernel::config_validate::MetadataPosture,
    table: &std::sync::Arc<TokenEndpoint>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": TEST_SA_KEY_PEM,
        "token_uri": token_uri,
    });
    let key_file = std::env::temp_dir().join(format!(
        "busbar-door-steps-jwt-{}-{}",
        std::process::id(),
        token_uri.len()
    ));
    std::fs::write(&key_file, sa.to_string()).expect("key");
    let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
        "p".to_string(),
        super::ProviderRoute {
            base_url: "http://127.0.0.1:9".to_string(),
            userinfo: None,
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: busbar_contract::secret_ref::SecretRef::file(
                key_file.display().to_string(),
            ),
            style: Some("jwt-bearer".to_string()),
            params: super::StyleParams::default(),
            metadata,
        },
    )]
    .into();
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: std::sync::Arc::new(linked_mint_plugin(table)),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let section: serde_yaml::Value =
        serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "jwt-bearer")],
        dialects: vec!["d"],
        ..Default::default()
    };
    let routes = super::member_routes(
        &section,
        &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
        &facts,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    );
    let _ = std::fs::remove_file(&key_file);
    routes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_jwt_bearer_mints_at_its_service_accounts_token_uri() {
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let routes = jwt_bearer_routes(
        TOKEN_URI,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("the member resolves");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the plugin's mint need, pinned to the service account's token_uri: {:?}",
        table.declared.lock().unwrap()
    );

    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        minted.is_ok(),
        "a bearer minted at the token_uri is presented"
    );
    let opened = table.opened.lock().unwrap();
    let (_, target, words, body) = &opened[0];
    assert_eq!(target, TOKEN_URI);
    assert_eq!(words, b"/token");
    assert!(
        body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ),
        "1.5.5's RFC 7523 form: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_userinfo_rides_the_mint_as_1_5_5_sent_it() {
    use base64::Engine as _;
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let written = TOKEN_URI.replacen("://", "://svcuser:hunter2-P4ss@", 1);
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let routes = jwt_bearer_routes(
        &written,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("a token_uri spelling a userinfo seals, as 1.5.5 accepted it");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the mint need is pinned to the stripped endpoint: {:?}",
        table.declared.lock().unwrap()
    );
    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(minted.is_ok(), "a bearer minted at the stripped endpoint");
    assert_eq!(table.opened.lock().unwrap()[0].1, TOKEN_URI);
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
    );
    let fields = table.fields.lock().unwrap();
    let head = &fields[0];
    assert_eq!(
        head.first().map(|(n, v)| (n.as_str(), v.as_slice())),
        Some(("authorization", basic.as_bytes())),
        "{head:?}"
    );
    assert!(
        head.iter()
            .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
        "{head:?}"
    );
    drop(fields);

    let route = &routes["m"];
    assert!(
        !route.base_url.contains("svcuser")
            && route
                .spelled
                .iter()
                .all(|(_, url)| !url.contains("svcuser")),
        "the member's route carries no userinfo"
    );
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, target)| !matches!(target, Some(t) if t.contains("svcuser"))),
        "no declared need carries the userinfo: {:?}",
        table.declared.lock().unwrap()
    );

    let body = table.opened.lock().unwrap()[0].3.clone();
    let assertion = body
        .split('&')
        .find_map(|pair| pair.strip_prefix("assertion="))
        .expect("the RFC 7523 form carries the assertion");
    let claims = assertion.split('.').nth(1).expect("a compact JWT");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(
        claims["aud"],
        written.as_str(),
        "the aud is the raw token_uri, as 1.5.5 signed it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_is_judged_at_the_seal_in_1_5_5s_words() {
    use busbar_kernel::config_validate::MetadataPosture;
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let Err(plaintext) = jwt_bearer_routes(
        "http://oauth2.example.com/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("plaintext to a public host is refused");
    };
    assert_eq!(
        plaintext,
        "provider 'p' (jwt-bearer auth): service-account token_uri must use https for a public \
         host (got 'http://oauth2.example.com/token'); it receives the signed JWT assertion, so \
         plaintext http is permitted only for a private/loopback endpoint"
    );
    let Err(metadata) = jwt_bearer_routes(
        "https://169.254.169.254/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("a metadata host is refused");
    };
    assert!(
        metadata.starts_with(
            "provider 'p' (jwt-bearer auth): service-account token_uri \
             'https://169.254.169.254/token' targets a blocked cloud-metadata host"
        ),
        "{metadata}"
    );
    let allowed = MetadataPosture {
        allow_overrides: vec!["169.254.169.254".to_string()],
        ..MetadataPosture::default()
    };
    assert!(
        jwt_bearer_routes("https://169.254.169.254/token", allowed, &table).is_ok(),
        "the provider's allow-override carves the host back out"
    );
}

#[test]
fn a_registration_member_is_reached_at_its_own_target() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "")],
        need_targets: vec!["settings.*.url"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\"}\nlocal: {command: run}\nhooks: [h]\n",
        &[],
    )
    .expect("the registrations resolve");
    assert_eq!(routes.keys().collect::<Vec<_>>(), ["fs"]);
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 0);
    assert_eq!(
        fs.base_url, "http://127.0.0.1:7",
        "its URL's origin; the plane spells the path"
    );
    assert_eq!(fs.provider, "fs");
    assert!(fs.auth.is_none());

    let none = resolve_for(&styled(), "fs: {url: \"http://127.0.0.1:7/rpc\"}\n", &[])
        .expect("nothing to resolve");
    assert!(none.is_empty());
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod tool_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::abi::mechanism::door::DoorFn;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::root::plane_node::{Node, NodeEndPost};
    use crate::root::serve::planes_tests::{composed_services, money, PUBLISHING};
    use crate::root::serve::{compose_planes, door_routes};

    static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
        std::sync::LazyLock::new(|| {
            let holder = crate::root::kernel::RootHistory::default();
            holder.apply(
                crate::root::kernel::card_from_config(
                    std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                    0,
                    true,
                ),
                1_000,
            );
            holder
        });

    pub(crate) const ADMIN_TOKEN: &str = "admintok";

    pub(crate) const PUBLIC_URL: &str = "http://127.0.0.1";

    pub(crate) fn surface(key: &str) -> &'static str {
        include_str!("fixtures/tool_door_wire.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("fixtures/tool_door_wire.txt has no `{key}` row"))
    }

    pub(crate) fn sentence(key: &str) -> String {
        surface(key).replace("{PLANE}", &surface("plane_key").to_ascii_uppercase())
    }

    pub(crate) fn endpoint_section() -> &'static str {
        surface("endpoint_section")
    }

    pub(crate) fn endpoint() -> String {
        format!("/{}", endpoint_section())
    }

    pub(crate) fn protocol_version() -> &'static str {
        surface("protocol_version")
    }

    pub(crate) fn line_door() -> DoorFn {
        static DOOR: std::sync::OnceLock<DoorFn> = std::sync::OnceLock::new();
        *DOOR.get_or_init(|| {
            #[cfg(distribution_root)]
            crate::dist_root_install::install();
            let section = endpoint_section();
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            crate::LINKED
                .plane_doors
                .iter()
                .copied()
                .find(|&door| {
                    let Ok(row) = LinkedRow::of(door) else {
                        return false;
                    };
                    load_linked::<Plane>(
                        &row,
                        Bind {
                            instance: Arc::from("line-door-probe"),
                            max_inflight_cap: 64,
                            sink: Arc::new(NoSink),
                            dispatcher: dispatcher.adopter(),
                            conns: crate::root::loader::dispatch::ConnTable::Probe,
                        },
                    )
                    .is_ok_and(|plane| plane.served().owns.contains(&section))
                })
                .expect("a linked plane door owns the endpoint section")
        })
    }

    pub(crate) const CALL: &str = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    const LIST: &str = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    pub(crate) fn section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
         tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    pub(crate) const TOOL_DESCRIPTION: &str = "reads a file from disk";

    pub(crate) fn tool_schema() -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}})
    }

    pub(crate) fn tool_digest() -> String {
        surface("tool_digest").to_string()
    }

    pub(crate) fn tool_listing() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()}
        ])
    }

    pub(crate) async fn send(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, Vec<u8>) {
        send_as(router, token, body, "tools/call", Some("fs_read_file")).await
    }

    pub(crate) async fn send_as(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = send_headed(router, token, body, method, name).await;
        (status, body)
    }

    pub(crate) async fn send_headed(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(endpoint())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header(surface("protocol_header"), protocol_version())
            .header(surface("method_header"), method);
        if let Some(name) = name {
            req = req.header(surface("name_header"), name);
        }
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, headers, bytes.to_vec())
    }

    pub(crate) async fn tool_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
    }

    pub(crate) async fn tool_server_listing(
        tools: Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(move |request: &str| {
            if request.contains("\"tools/list\"") {
                let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": list}})
                    .to_string()
            } else {
                ANSWER.to_string()
            }
        }))
        .await
    }

    pub(crate) async fn tool_server_answering(
        answer: Arc<dyn Fn(&str) -> String + Send + Sync>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_replying(Arc::new(move |request: &str| (200, answer(request)))).await
    }

    pub(crate) type Replies = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

    pub(crate) const STALL: u16 = 0;

    pub(crate) async fn tool_server_replying(
        answer: Replies,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(tool_connection(socket, sent.clone(), Arc::clone(&answer)));
            }
        });
        (port, heard)
    }

    async fn tool_request<S: tokio::io::AsyncRead + Unpin>(
        socket: &mut S,
        sent: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Option<String> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut got = Vec::new();
        loop {
            let n = socket.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            got.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&got).to_string();
            if let Some(at) = text.find("\r\n\r\n") {
                let length = text[..at]
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if got.len() >= at + 4 + length {
                    let _ = sent.send(text.clone());
                    return Some(text);
                }
            }
        }
    }

    async fn tool_reply<S: tokio::io::AsyncWrite + Unpin>(
        socket: &mut S,
        status: u16,
        answer: String,
    ) {
        if status == STALL {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            return;
        }
        let reply = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{answer}",
            answer.len()
        );
        let _ = socket.write_all(reply.as_bytes()).await;
        let _ = socket.shutdown().await;
    }

    async fn tool_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut socket: S,
        sent: tokio::sync::mpsc::UnboundedSender<String>,
        answer: Replies,
    ) {
        if let Some(request) = tool_request(&mut socket, sent).await {
            let (status, answer) = answer(&request);
            tool_reply(&mut socket, status, answer).await;
        }
    }

    type TlsToolSocket = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type TlsToolHandler = Arc<
        dyn Fn(
                TlsToolSocket,
                tokio::sync::mpsc::UnboundedSender<String>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync,
    >;

    pub(crate) struct TlsToolServer {
        pub(crate) port: u16,
        pub(crate) heard: tokio::sync::mpsc::UnboundedReceiver<String>,
        pub(crate) pin: String,
        tls: Arc<rustls::ClientConfig>,
        ca_der: Vec<u8>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    impl TlsToolServer {
        pub(crate) async fn new() -> Self {
            Self::listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
        }

        pub(crate) async fn answering(answer: Arc<dyn Fn(&str) -> String + Send + Sync>) -> Self {
            Self::replying(Arc::new(move |request| (200, answer(request)))).await
        }

        pub(crate) async fn listing(tools: Arc<std::sync::Mutex<serde_json::Value>>) -> Self {
            Self::answering(Arc::new(move |request| {
                if request.contains("\"tools/list\"") {
                    let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                    serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":list}}).to_string()
                } else {
                    ANSWER.to_string()
                }
            }))
            .await
        }

        pub(crate) async fn replying(answer: Replies) -> Self {
            let handler: TlsToolHandler = Arc::new(move |socket, sent| {
                Box::pin(tool_connection(socket, sent, Arc::clone(&answer)))
            });
            Self::with_handler(handler, None).await
        }

        pub(crate) async fn once() -> Self {
            let handler: TlsToolHandler = Arc::new(|socket, sent| {
                let answer: Replies = Arc::new(|request| {
                    (
                        200,
                        if request.contains("\"tools/list\"") {
                            serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":tool_listing()}}).to_string()
                        } else {
                            ANSWER.to_string()
                        },
                    )
                });
                Box::pin(tool_connection(socket, sent, answer))
            });
            Self::with_handler(handler, Some(1)).await
        }

        pub(crate) async fn gated(
            release: tokio::sync::watch::Receiver<bool>,
            answer: impl Into<String>,
        ) -> Self {
            let answer = answer.into();
            let handler: TlsToolHandler = Arc::new(move |mut socket, sent| {
                let mut release = release.clone();
                let answer = answer.clone();
                Box::pin(async move {
                    let Some(request) = tool_request(&mut socket, sent).await else {
                        return;
                    };
                    let answer = if request.contains("\"tools/list\"") {
                        serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":tool_listing()}}).to_string()
                    } else {
                        let _ = release.wait_for(|ready| *ready).await;
                        answer
                    };
                    tool_reply(&mut socket, 200, answer).await;
                })
            });
            Self::with_handler(handler, None).await
        }

        async fn with_handler(handler: TlsToolHandler, limit: Option<usize>) -> Self {
            use rcgen::PublicKeyData as _;
            busbar_core_connector::tls::install_crypto_provider();
            let ca_key = rcgen::KeyPair::generate().expect("a CA key");
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA params");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).expect("the CA");
            let issuer = rcgen::Issuer::new(ca_params, ca_key);
            let leaf_key = rcgen::KeyPair::generate().expect("a leaf key");
            let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
                .expect("IP SAN")
                .signed_by(&leaf_key, &issuer)
                .expect("the leaf");
            let pin =
                busbar_contract::transport::trust::key_pin(&leaf_key.subject_public_key_info());
            let server = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.der().clone()],
                    rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
                        .expect("leaf key"),
                )
                .expect("the TLS server");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let tls = busbar_core_connector::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: vec![ca.der().to_vec()],
                    ..Default::default()
                },
            )
            .expect("normal certificate verification with the fixture CA added");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a TLS port");
            let port = listener.local_addr().unwrap().port();
            let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                let mut accepted = 0usize;
                while let Ok((socket, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let sent = sent.clone();
                    let handler = Arc::clone(&handler);
                    connections.spawn(async move {
                        if let Ok(tls) = acceptor.accept(socket).await {
                            handler(tls, sent).await;
                        }
                    });
                    accepted += 1;
                    if limit.is_some_and(|bound| accepted >= bound) {
                        break;
                    }
                    while connections.try_join_next().is_some() {}
                }
                drop(listener);
                while connections.join_next().await.is_some() {}
            });
            Self {
                port,
                heard,
                pin,
                tls: Arc::new(tls),
                ca_der: ca.der().to_vec(),
                task: Some(task),
            }
        }

        pub(crate) fn section(&self) -> serde_yaml::Value {
            let mut value = section(self.port);
            value["fs"]["url"] =
                serde_yaml::Value::String(format!("https://127.0.0.1:{}/rpc", self.port));
            value["fs"]["pin"] = serde_yaml::to_value(serde_json::json!({
                "mechanism":"cert_spki", "key":self.pin
            }))
            .unwrap();
            value
        }

        pub(crate) fn footing(&self) -> Footing<'static> {
            Footing {
                tls: Some(Arc::clone(&self.tls)),
                ..Footing::own()
            }
        }

        pub(crate) fn footing_with_peers(&self, peers: &[&Self]) -> Footing<'static> {
            let anchors = std::iter::once(&self.ca_der)
                .chain(peers.iter().map(|p| &p.ca_der))
                .cloned()
                .collect();
            let tls = busbar_core_connector::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: anchors,
                    ..Default::default()
                },
            )
            .expect("normal verification with all fixture CAs added");
            Footing {
                tls: Some(Arc::new(tls)),
                ..Footing::own()
            }
        }

        pub(crate) fn rig(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig(instance, tools, configure)
                .unwrap_or_else(|e| panic!("the TLS door composes: {e}"))
        }

        pub(crate) fn try_rig(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Rig, String> {
            self.try_rig_with_footing(instance, tools, None, self.footing(), configure)
        }

        pub(crate) fn rig_with_footing(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig_with_footing(instance, tools, None, footing, configure)
                .unwrap_or_else(|e| panic!("the TLS door composes: {e}"))
        }

        pub(crate) fn rig_with_grants(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            allowed_pools: Option<Vec<String>>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig_with_footing(instance, tools, allowed_pools, self.footing(), configure)
                .unwrap_or_else(|e| panic!("the granted TLS door composes: {e}"))
        }

        fn try_rig_with_footing(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            allowed_pools: Option<Vec<String>>,
            mut footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Rig, String> {
            if footing.tls.is_none() {
                footing.tls = Some(Arc::clone(&self.tls));
            }
            let row = super::door_boundary::row();
            super::door_boundary::registry(row);
            let slot = super::door_boundary::slot_over(row, tools.clone());
            Rig::try_with(
                instance,
                self.port,
                allowed_pools,
                None,
                Some(tools),
                footing,
                &|app| super::door_boundary::dispatched(configure(app), row, &slot),
            )
        }

        pub(crate) async fn close(mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
                let _ = task.await;
            }
        }
    }

    impl Drop for TlsToolServer {
        fn drop(&mut self) {
            if let Some(task) = &self.task {
                task.abort();
            }
        }
    }

    async fn down_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    pub(crate) struct Rig {
        pub(crate) router: axum::Router,

        pub(crate) admin: axum::Router,
        pub(crate) gov: Arc<GovState>,
        pub(crate) app: Arc<busbar_kernel::state::App>,
        pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
        pub(crate) token: String,
        money_steps: Arc<PlaneMoney>,
        post: Arc<NodeEndPost>,
        pub(crate) book: crate::root::durability::NodeBook,
        pub(crate) plane_key: String,

        pub(crate) audience: Option<String>,

        pub(crate) store: Arc<crate::root::loader::store_v3::LoadedStore>,

        pub(crate) tokens: Arc<super::TokenEndpoint>,

        pub(crate) door_table: Vec<(
            String,
            String,
            busbar_contract::abi::mechanism::route::RouteAuth,
        )>,

        pub(crate) plane: crate::root::boot::DoorPlane,

        pub(crate) clock: Arc<std::sync::atomic::AtomicU64>,

        pub(crate) wall: Arc<std::sync::atomic::AtomicU64>,
        pub(crate) work_observations: Arc<std::sync::Mutex<Vec<ObservedWork>>>,
        pub(crate) instance: &'static str,

        pub(crate) live: Arc<crate::root::serve::DoorApply>,
    }

    impl Rig {
        fn new(instance: &'static str, port: u16, allowed_pools: Option<Vec<String>>) -> Self {
            Self::with(
                instance,
                port,
                allowed_pools,
                None,
                None,
                Footing::own(),
                &|app| app,
            )
        }

        pub(crate) fn with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Self {
            Self::try_with(
                instance,
                port,
                allowed_pools,
                block,
                tools,
                footing,
                configure,
            )
            .unwrap_or_else(|e| panic!("the door plane composes: {e}"))
        }

        pub(crate) fn try_with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Self, String> {
            let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
                block_private_addresses: footing.guarded,
                blocked: vec![BLOCKED_HOST.to_string()],
                ..Default::default()
            })
            .expect("the guard");

            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let governance_store = crate::root::real_store::store();
            let gov = Arc::new(
                GovState::new_with_signer(
                    governance_store.clone(),
                    Some(ADMIN_TOKEN.to_string()),
                    Some(signer),
                )
                .expect("governance"),
            );
            assert!(
                gov.attach_store_calls(governance_store),
                "attach the actual governance store calls",
            );

            let (gov, key, token) = match footing.book {
                Some(first) => (
                    Arc::clone(&first.gov),
                    Arc::clone(&first.key),
                    first.token.clone(),
                ),
                None => {
                    let (key, token) = gov
                        .mint_signed(
                            NewKeySpec {
                                name: "agent".to_string(),
                                allowed_pools,
                                ..Default::default()
                            },
                            4_000_000_000,
                            1_700_000_000,
                        )
                        .expect("mint");
                    gov.hydrate_budgets(&CostModel::flat(1), 0)
                        .expect("hydrate");
                    (
                        gov,
                        Arc::new(key),
                        token.expose(&busbar_kernel::seal::lend()).to_string(),
                    )
                }
            };
            let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let wall = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (late, store) = records_composed(
                footing.ledger,
                Arc::clone(&gov),
                (&clock, &wall),
                Arc::clone(&judge) as Arc<dyn busbar_kernel::host_services::DestJudge>,
            );
            let work_observations = Arc::new(std::sync::Mutex::new(Vec::new()));
            let dispatcher = Arc::new(Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(Clocked {
                    inner: late.served(),
                    wall: Arc::clone(&wall),
                    work_observations: Arc::clone(&work_observations),
                }),
            ));

            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());

            let connector = if let Some(tls) = &footing.tls {
                let entries = crate::root::connector::entries_on(
                    &dispatcher,
                    crate::LINKED_TRANSPORT_DOORS,
                    &busbar_contract::transport::TransportSettings::default(),
                )
                .expect("the linked transport doors open");
                Arc::new(
                    busbar_core_connector::Connector::serving(
                        busbar_core_connector::registry::Transports::new(entries)
                            .expect("the transport view"),
                        busbar_core_connector::process::judge(judge, &[]),
                        Some(Arc::clone(tls)),
                        dispatcher.conn_waker(),
                    )
                    .pooling(busbar_core_connector::pool::PoolPosture::NONE)
                    .proxying(
                        busbar_core_connector::proxy::from_env().expect("the proxy environment"),
                    )
                    .resolving_spawn_secrets(busbar_core_connector::spawn_env::linked_spawn_secret),
                )
            } else {
                busbar_core_connector::process::build_with_secrets(
                    || {
                        crate::root::connector::entries_on(
                            &dispatcher,
                            crate::LINKED_TRANSPORT_DOORS,
                            &busbar_contract::transport::TransportSettings::default(),
                        )
                    },
                    judge,
                    &[],
                    dispatcher.conn_waker(),
                    busbar_core_connector::pool::PoolPosture::NONE,
                    busbar_core_connector::spawn_env::linked_spawn_secret,
                )
                .expect("the connector builds")
            };
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&connector) as Arc<dyn DeclaredConns>
                ),
            );
            let caller = plane.instance();
            let section_key = plane.served().section;
            assert_eq!(
                section_key,
                surface("section"),
                "the door opens with the section its grammar reads"
            );

            let node = Arc::new(Node::new());
            let book = crate::root::durability::node_book();
            node.bind_book(Arc::clone(&book.durability));
            let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
            let site = Arc::clone(&post);
            let book_money = Arc::clone(&gov);
            let plane_money = move || {
                Arc::new(PlaneMoney::new(
                    Arc::clone(&book_money),
                    Arc::clone(&site) as Arc<dyn EndPost>,
                ))
            };

            let mut sections = BTreeMap::new();

            if let Some(block) = block {
                sections.insert(plane.served().owns[0], block);
            }
            sections.insert(section_key, tools.unwrap_or_else(|| section(port)));
            let providers = BTreeMap::new();
            let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
                std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());

            let mut linked = crate::LINKED.auths.to_vec();
            let name = "busbar-auth-oauth";
            linked.push((name, name, busbar_auth_oauth::door));
            let tokens = Arc::new(super::TokenEndpoint {
                answer: Some(|body: &str| {
                    let scope = body
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("scope="))
                        .unwrap_or_default();
                    format!(r#"{{"access_token":"tok-{scope}","expires_in":3600}}"#)
                }),
                ..super::TokenEndpoint::default()
            });
            let auths = crate::root::door_steps::OutboundAuths::new(
                Arc::clone(&dispatcher),
                &linked,
                None,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&tokens) as Arc<dyn DeclaredConns>
                ),
                busbar_kernel::diagnostics::Catalogue::NEUTRAL,
            );
            let reach = crate::root::door_steps::DoorReach {
                providers: &providers,
                secrets: std::sync::Arc::clone(&secrets),
                auths: Arc::new(auths),
                conns: Arc::clone(&connector) as Arc<dyn PollConns>,
                models: None,
                stream_ceiling_secs: 600,
                catalog: None,
                upgrades: Vec::new(),
            };
            let egress = crate::root::serve::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            };
            let doors = [(instance.to_string(), plane)];

            let live_app: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
            let stage = crate::root::serve::HookStage {
                host: {
                    let live_app = Arc::clone(&live_app);
                    Arc::new(move || {
                        busbar_kernel::plane_driver::engine_host(
                            live_app
                                .get()
                                .expect("the rig's App is built before any unit"),
                        )
                    })
                },
                gov: Arc::clone(&gov),
                journal: None,
            };

            let tables = busbar_kernel::plane_driver::serve::ServeTables::default();
            let mut app = {
                #[cfg(distribution_root)]
                crate::dist_root_install::install();
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual store statement reads")
                    .expect("the actual store exports its statement");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual store statement is valid")
                    .name;
                let mut manifest = crate::root::test_plugins::manifest(
                    "store",
                    &module,
                    crate::root::test_plugins::FIXTURE_PUBLISHER,
                );
                manifest.statement = Some(hex::encode(statement));
                let release = crate::root::test_plugins::key(0x5a);
                let directory = crate::root::test_plugins::scratch(&format!(
                    "door-steps-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library = std::fs::read(library_path).expect("the actual store library reads");
                let archive = crate::root::test_plugins::signed(&release, manifest, &library);
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual store");
                crate::root::linked::register_stores(&crate::LINKED);
                busbar_kernel::preflight::install_linked_auth(
                    crate::LINKED.auths,
                    crate::root::auth_bindings::operator_words(),
                );
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                    "store": {"module": module, "settings": settings},
                }))
                .expect("the door deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the door deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let loaded = crate::root::real_store::store();
                let opened = busbar_contract::store_calls::OpenedStore {
                    records: loaded.clone(),
                    calls: Some(loaded),
                };
                let (app, rotate, limits) =
                    busbar_kernel::appbuild::build_app_from_config_with_store(
                        cfg,
                        crate::root::test_plugins::trusted_config_with_key(
                            &directory,
                            &crate::root::test_plugins::key(0x5a),
                        ),
                        None,
                        Default::default(),
                        Default::default(),
                        (None, None),
                        None,
                        &rules,
                        Some(opened),
                        false,
                    )
                    .expect("the actual root builds the door generation");
                limits.stage_boot();
                let _book = crate::root::boot::book(&app, &module)
                    .expect("the configured Store boots its rate history before activation");
                limits.keep().expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                app
            };
            let mut served = compose_planes(
                &doors,
                &dispatcher,
                &late,
                &sections,
                Some(PUBLIC_URL),
                &plane_money,
                Some(&egress),
                Some(&stage),
                &tables,
            )?;
            let _ = caller;
            let composed = &mut served.planes[0];
            assert!(
                composed.live.current().egress.is_some(),
                "its egress is sealed"
            );
            let money_steps = Arc::clone(&composed.money);
            let live = Arc::clone(&composed.live);
            let plane_key = composed.facts.plane.clone();
            let audience = composed.snapshot.audience.clone();
            served.post = Some(Arc::clone(&post));
            app.auth = Arc::new(
                busbar_kernel::auth::AuthMiddleware::new(
                    &busbar_kernel::config::AuthCfg {
                        chain: vec![busbar_kernel::config::AuthChainEntry::bare(
                            busbar_kernel::config::KEYS_MODULE,
                        )],
                        ..busbar_kernel::config::AuthCfg::default_none()
                    },
                    &app.hook_env.registry,
                    &app.secret_resolver,
                )
                .expect("the actual root constructs the keys middleware"),
            );
            app.governance = Some(Arc::clone(&gov));
            app.serve_tables = tables.clone();
            app.cost = Arc::new(CostModel::flat(1));
            let app = Arc::new(configure(app));
            let _ = live_app.set(Arc::clone(&app));

            if let Some(kernel) = late.kernel() {
                let _attached = kernel
                    .attach_standing(busbar_kernel::plane_driver::standing_over(Arc::clone(&app)));
            }

            served.spawn_ticks();
            let [(_, plane)] = doors;

            let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
            let door_table = doors
                .iter()
                .map(|d| (d.path.clone(), d.method.as_str().to_string(), d.auth))
                .collect();
            let (router, admin, _handle) = busbar_kernel::build_split_routers_serving(
                Arc::clone(&app),
                doors,
                1 << 20,
                0,
                false,
            );
            Ok(Rig {
                router,
                admin,
                gov,
                app,
                key,
                token,
                money_steps,
                post,
                book,
                plane_key,
                audience,
                store,
                tokens,
                door_table,
                plane,
                clock,
                wall,
                work_observations,
                instance,
                live,
            })
        }

        pub(crate) fn bound_token(&self) -> String {
            self.bound_token_for(&self.token)
        }

        pub(crate) fn bound_token_for(&self, plain: &str) -> String {
            use busbar_kernel::governance::signing::TokenVerifier;
            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
            let claims = verifier
                .verify(plain, 1_700_000_000, None)
                .expect("plain claims");
            let audience = self.audience.as_deref().expect("the real door's audience");
            signer.mint_for_audience(
                &claims.sub,
                claims.exp,
                claims.generation.as_deref(),
                audience,
                Some("client-1"),
            )
        }

        pub(crate) fn admitted(&self) -> u64 {
            self.gov
                .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
                .expect("a read")
                .expect("the key exists")
                .requests
        }

        pub(crate) fn all_ended(&self) -> bool {
            self.money_steps.open_units() == 0 && self.post.open_units() == 0
        }
    }

    pub(crate) fn rig_with(
        instance: &'static str,
        port: u16,
        allowed_pools: Option<Vec<String>>,
        configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            allowed_pools,
            None,
            None,
            Footing::own(),
            configure,
        )
    }

    pub(crate) fn rig_on(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        footing: Footing<'_>,
    ) -> Rig {
        Rig::with(instance, port, None, None, Some(tools), footing, &|app| app)
    }

    pub(crate) fn rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
    ) -> Rig {
        let row = super::door_boundary::row();
        super::door_boundary::registry(row);
        let slot = super::door_boundary::slot_over(row, tools.clone());
        Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| super::door_boundary::dispatched(configure(app), row, &slot),
        )
    }

    pub(crate) fn try_rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
    ) -> Result<Rig, String> {
        let row = super::door_boundary::row();
        super::door_boundary::registry(row);
        let slot = super::door_boundary::slot_over(row, tools.clone());
        Rig::try_with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| super::door_boundary::dispatched(app, row, &slot),
        )
    }

    fn records_composed(
        ledger: Ledger,
        signer: Arc<GovState>,
        (clock, wall): (
            &Arc<std::sync::atomic::AtomicU64>,
            &Arc<std::sync::atomic::AtomicU64>,
        ),
        dest: Arc<dyn busbar_kernel::host_services::DestJudge>,
    ) -> (
        Arc<crate::root::serve::LateServices>,
        Arc<crate::root::loader::store_v3::LoadedStore>,
    ) {
        let store = crate::root::real_store::store();
        let (origin, ahead) = (std::time::Instant::now(), Arc::clone(clock));
        let wall_ahead = Arc::clone(wall);
        let kernel = busbar_kernel::host_services::KernelServices::new()
            .with_dest_judge(dest)
            .with_mono_clock(Arc::new(move || {
                u64::try_from(origin.elapsed().as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_add(ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_wall_clock(Arc::new(move || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .saturating_add(wall_ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_signer(signer)
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )));
        let kernel = Arc::new(match ledger {
            Ledger::Memory => kernel.with_records(Arc::new(StoreRows(store.clone()))),
            Ledger::Store(claims) => {
                kernel.with_records(Arc::new(ClaimsIn(Arc::new(Rows::default()), claims)))
            }
            Ledger::Rows(rows, max_live) => kernel
                .with_work_bounds(busbar_kernel::host_work::WorkBounds {
                    max_live,
                    ..Default::default()
                })
                .with_records(Arc::new(ClaimsIn(rows, Arc::clone(&store) as _))),
            Ledger::Unbound => kernel,
        });
        let late = crate::root::serve::LateServices::new();
        late.install_kernel(Arc::clone(&kernel), kernel)
            .expect("installed once");
        (late, store)
    }

    /// The host services as the door reads them, the wall clock `clock.now` answers read `wall`
    /// milliseconds ahead, as the kernel's work book reads it: every other service is `inner`'s.
    #[derive(Clone)]
    pub(crate) struct ObservedWork {
        pub(crate) instance: String,
        pub(crate) reference: Vec<u8>,
        pub(crate) observation: busbar_contract::abi::mechanism::inspection::WorkObservation,
    }

    struct Clocked {
        inner: Arc<dyn busbar_contract::services::HostServices>,
        wall: Arc<std::sync::atomic::AtomicU64>,
        work_observations: Arc<std::sync::Mutex<Vec<ObservedWork>>>,
    }

    impl busbar_contract::services::HostServices for Clocked {
        fn inspect(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            query: &busbar_contract::abi::mechanism::inspection::InspectionQuery,
        ) -> busbar_contract::abi::mechanism::inspection::InspectionResult {
            use busbar_contract::abi::mechanism::inspection::{
                InspectionObservation, InspectionQuery,
            };
            let result = self.inner.inspect(caller, unit, query);
            if let (
                InspectionQuery::Work { reference },
                Ok(InspectionObservation::Work(observation)),
            ) = (query, &result)
            {
                self.work_observations
                    .lock()
                    .expect("the observation log")
                    .push(ObservedWork {
                        instance: caller.instance.to_string(),
                        reference: reference.clone(),
                        observation: *observation,
                    });
            }
            result
        }

        fn now(&self) -> busbar_contract::services::Reading {
            let mut reading = self.inner.now();
            let ahead = self.wall.load(std::sync::atomic::Ordering::SeqCst);
            reading.wall_ns = reading
                .wall_ns
                .saturating_add(ahead.saturating_mul(1_000_000));
            reading
        }
        fn dest_judge(
            &self,
            dest: &str,
            class: u32,
            flags: u32,
            later: Option<busbar_contract::services::Later>,
        ) -> busbar_contract::services::Ran {
            self.inner.dest_judge(dest, class, flags, later)
        }
        fn records_get(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_get(caller, kind, key, later)
        }
        fn records_list(
            &self,
            caller: &busbar_contract::services::Caller,
            list: busbar_contract::services::RecordsList,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_list(caller, list, later)
        }
        fn records_claim(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            ttl_ms: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_claim(caller, kind, key, ttl_ms, later)
        }
        fn sign(
            &self,
            caller: &busbar_contract::services::Caller,
            data: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.sign(caller, data)
        }
        fn trust_sight(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            hash: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.trust_sight(caller, counterparty, hash, later)
        }
        fn trust_unreached(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_unreached(caller, counterparty)
        }
        fn trust_sight_item(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: &str,
            digest: &str,
        ) -> busbar_contract::services::Stored {
            self.inner
                .trust_sight_item(caller, counterparty, item, digest)
        }
        fn trust_decide(
            &self,
            caller: &busbar_contract::services::Caller,
            key: busbar_contract::services::TrustKeyRef<'_>,
            expected: Option<&str>,
            approve: bool,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_decide(caller, key, expected, approve)
        }
        fn trust_state(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_state(caller, counterparty)
        }
        fn trust_serves(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: Option<&str>,
            digest: Option<&str>,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_serves(caller, counterparty, item, digest)
        }
        fn trust_due(
            &self,
            caller: &busbar_contract::services::Caller,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_due(caller)
        }
        fn trust_verify(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            payload: &[u8],
            signatures: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner
                .trust_verify(caller, counterparty, payload, signatures)
        }
        fn entitlement_check(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            target: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.entitlement_check(caller, unit, target)
        }
        fn session_emit(
            &self,
            caller: &busbar_contract::services::Caller,
            session: u64,
            bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.session_emit(caller, session, bytes)
        }
        fn ticket_mint(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ttl_secs: u64,
            record: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.ticket_mint(caller, unit, ttl_secs, record)
        }
        fn ticket_take(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
        ) -> busbar_contract::services::Stored {
            self.inner.ticket_take(caller, unit)
        }
        fn random_fill(&self, len: u64) -> busbar_contract::services::Stored {
            self.inner.random_fill(len)
        }
        fn records_secret(
            &self,
            kind: &str,
            id: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_secret(kind, id, later)
        }
        fn unit_nest(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::NestAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.unit_nest(caller, unit, ask, later)
        }
        fn work_open(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            kind: &str,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_open(caller, unit, kind, record, later)
        }
        fn work_find(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            reference: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_find(caller, unit, reference, later)
        }
        fn work_settle(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_settle(caller, unit, handle, record, later)
        }
        fn work_resume(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_resume(caller, unit, handle, later)
        }
        fn disk_append(
            &self,
            dest: &busbar_contract::services::DiskDest,
            bytes: Vec<u8>,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.disk_append(dest, bytes, later)
        }
        fn verify_lookup(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.verify_lookup(caller, key, later)
        }
        fn verify_store(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            entry: &[u8],
            ttl_ms: u64,
        ) -> busbar_contract::services::Stored {
            self.inner.verify_store(caller, key, entry, ttl_ms)
        }
        fn content_scan(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            content: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.content_scan(caller, unit, content, later)
        }
        fn hook_call(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::HookAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.hook_call(caller, unit, ask, later)
        }
        fn snapshot_read(
            &self,
            caller: &busbar_contract::services::Caller,
            scope: u32,
        ) -> busbar_contract::services::Snapshot {
            self.inner.snapshot_read(caller, scope)
        }
    }

    pub(crate) struct Footing<'a> {
        pub(crate) ledger: Ledger,
        pub(crate) book: Option<&'a Rig>,

        pub(crate) guarded: bool,

        pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    }

    impl Footing<'_> {
        pub(crate) fn own() -> Self {
            Footing {
                ledger: Ledger::Memory,
                book: None,
                guarded: false,
                tls: None,
            }
        }
    }

    pub(crate) const BLOCKED_HOST: &str = "blocked.example";

    pub(crate) enum Ledger {
        Memory,

        Store(Arc<dyn busbar_contract::records::RecordStore>),

        Rows(Arc<Rows>, usize),

        Unbound,
    }

    use busbar_kernel::host_records::StoreRows;

    struct ClaimsIn(Arc<Rows>, Arc<dyn busbar_contract::records::RecordStore>);

    impl busbar_kernel::host_records::RecordRows for ClaimsIn {
        fn supports_record_transaction(&self) -> bool {
            busbar_kernel::host_records::RecordRows::supports_record_transaction(&*self.0)
        }

        fn record_transaction(
            &self,
            request: &busbar_contract::abi::sdk::store::conditional::Request,
        ) -> Result<
            busbar_contract::abi::sdk::store::conditional::Decision,
            busbar_contract::store_calls::StoreFailure,
        > {
            busbar_kernel::host_records::RecordRows::record_transaction(&*self.0, request)
        }

        fn claim(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> Result<bool, busbar_contract::kinds::StoreError> {
            if kind == busbar_kernel::host_records::CLAIM_KIND {
                return busbar_kernel::host_records::RecordRows::claim(
                    &*self.0, kind, token, expires_at, now,
                );
            }
            busbar_contract::records::RecordStore::redeem_plane_token(
                &*self.1, kind, token, expires_at, now,
            )
            .map_err(|e| busbar_contract::kinds::StoreError::Rejected(e.0))
        }
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            busbar_kernel::host_records::RecordRows::record_put(&*self.0, schema, key, value)
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            busbar_kernel::host_records::RecordRows::record_get(&*self.0, schema, key)
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            busbar_kernel::host_records::RecordRows::record_scan(&*self.0, schema, prefix, limit)
        }
    }

    /// The actual product store, with a bounded refusal of the next work-settlement writes.
    pub(crate) struct Rows(
        Arc<crate::root::loader::store_v3::LoadedStore>,
        pub(crate) std::sync::atomic::AtomicU32,
    );

    impl Default for Rows {
        fn default() -> Self {
            Self(
                crate::root::real_store::store(),
                std::sync::atomic::AtomicU32::new(0),
            )
        }
    }

    impl busbar_kernel::host_records::RecordRows for Rows {
        fn supports_record_transaction(&self) -> bool {
            busbar_kernel::host_records::RecordRows::supports_record_transaction(&StoreRows(
                self.0.clone(),
            ))
        }

        fn record_transaction(
            &self,
            request: &busbar_contract::abi::sdk::store::conditional::Request,
        ) -> Result<
            busbar_contract::abi::sdk::store::conditional::Decision,
            busbar_contract::store_calls::StoreFailure,
        > {
            busbar_kernel::host_records::RecordRows::record_transaction(
                &StoreRows(self.0.clone()),
                request,
            )
        }

        fn claim(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> Result<bool, busbar_contract::kinds::StoreError> {
            busbar_kernel::host_records::RecordRows::claim(
                &StoreRows(self.0.clone()),
                kind,
                token,
                expires_at,
                now,
            )
        }
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            let settles = schema == busbar_kernel::host_work::WORK_SCHEMA
                && value.as_slice().get(1)
                    == Some(&busbar_contract::abi::host::service::WORK_SETTLED);
            let refused = settles
                && self
                    .1
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| n.checked_sub(1),
                    )
                    .is_ok();
            if refused {
                return Err(busbar_contract::kinds::StoreError::Unavailable);
            }
            busbar_kernel::host_records::RecordRows::record_put(
                &StoreRows(self.0.clone()),
                schema,
                key,
                value,
            )
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            busbar_kernel::host_records::RecordRows::record_get(
                &StoreRows(self.0.clone()),
                schema,
                key,
            )
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            busbar_kernel::host_records::RecordRows::record_scan(
                &StoreRows(self.0.clone()),
                schema,
                prefix,
                limit,
            )
        }
    }

    fn bound(
        instance: &str,
        dispatcher: &Arc<Dispatcher>,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::boot::DoorPlane {
        let row = LinkedRow::of(line_door()).expect("the door states its Statement");
        Arc::new(
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns,
                },
            )
            .expect("the linked door binds"),
        )
    }

    #[test]
    fn an_obsolete_manifest_pin_is_still_refused_before_a_door_opens() {
        let row = super::door_boundary::row();
        let error = (row
            .parse_section
            .expect("the door parses its owned section"))(row, &section(9))
        .expect_err("pinned_pubkey does not authenticate a server in this build");
        assert!(
            error.contains("pinned_pubkey") && error.contains("authenticates nothing"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_peer_key_is_refused_before_the_tls_tool_server_receives_http() {
        use rcgen::PublicKeyData as _;
        let _one = PUBLISHING.lock().await;
        let mut server = TlsToolServer::new().await;
        let mut tools = server.section();
        let another = rcgen::KeyPair::generate().expect("another real key");
        tools["fs"]["pin"]["key"] = serde_yaml::Value::String(
            busbar_contract::transport::trust::key_pin(&another.subject_public_key_info()),
        );
        let rig = server.rig("serve-door-tools-wrong-peer", tools, &|app| app);
        let (status, bytes) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("a shaped failure");
        assert_eq!(
            status,
            StatusCode::OK,
            "the unreachable peer is a tool error: {body}"
        );
        assert_eq!(body["id"], 30, "the caller's own id: {body}");
        assert_eq!(
            body["result"]["isError"], true,
            "the peer was never served: {body}"
        );
        assert!(
            server.heard.try_recv().is_err(),
            "a wrong peer pin must fail before HTTP reaches the server"
        );
        assert!(rig.all_ended(), "the refused unit is closed");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_is_served_through_the_tool_door_and_its_money_posted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-served";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let token = rig.bound_token();
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "served through the door: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "the server's tool result, relayed: {body}"
        );

        let verify = heard
            .recv()
            .await
            .expect("the server was asked for its tool list");
        assert!(verify.starts_with("POST /rpc "), "{verify}");
        assert!(
            verify.contains("\"tools/list\""),
            "the verify fetch: {verify}"
        );

        let head = heard.recv().await.expect("the server was dialled");
        assert!(head.starts_with("POST /rpc "), "{head}");
        assert!(head.contains("\"tools/call\""), "the relayed call: {head}");

        assert_eq!(rig.admitted(), 1, "one admitted request");
        assert!(rig.all_ended(), "its facts closed at its end");

        {
            let (_, chained) = crate::root::serve::planes_tests::chained_records(
                &rig.store,
                surface("record_kind_call"),
                busbar_contract::abi::plane::RecordChain {
                    kind: 0,
                    framing: busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED,
                    flags: busbar_contract::abi::plane::CHAIN_DIGESTS_SCOPE,
                    _reserved: 0,
                },
                1,
            );
            assert_eq!(
                chained.len(),
                1,
                "the call's one chained record: {chained:?}"
            );
        }

        let records = rig
            .book
            .durability
            .lock()
            .expect("unpoisoned")
            .audit_records
            .clone();
        let counted = |class: &str| -> Vec<u64> {
            records
                .iter()
                .flat_map(|r| r.usage.lines.iter())
                .filter(|l| l.class.as_str() == class)
                .map(|l| l.quantity)
                .collect()
        };
        assert_eq!(
            counted(surface("class_tool_calls")),
            vec![1],
            "the one tool call the plane reported, on the unit's one record: {records:?}"
        );

        assert_eq!(
            counted(surface("class_bytes")),
            vec![ANSWER.len() as u64],
            "the bytes of the server's answer the plane reported: {records:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unkeyed_tools_call_is_refused_before_anything_is_charged_or_dialled() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-unkeyed";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, None, CALL).await;
        let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
        assert_eq!(
            status.as_u16(),
            refused,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_that_does_not_decode_is_refused_before_it_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-undecodable";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), "{not json").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the status the plane's decode stated: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON-RPC");
        assert_eq!(
            body["error"]["code"],
            busbar_contract::jsonrpc::PARSE_ERROR,
            "the plane's own words for the arrival it refused (REFUSAL_ARRIVE): {body}"
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-ungranted";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig_with_grants(instance, server.section(), Some(Vec::new()), &|app| app);
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status.as_u16(), 404, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "not_granted", "{body}");
        assert_eq!(body["id"], 30, "the caller's id: {body}");
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_to_a_server_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-down";
        let server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        server.close().await;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["result"]["isError"], true,
            "an upstream failure: {answer}"
        );
        assert!(rig.all_ended(), "the unit ended inside itself");
    }

    pub(crate) fn assert_member_passthrough_refused(error: &str, instance: &str, member: &str) {
        let expected = format!(
            "`tools.{member}`: `upstream_credentials: passthrough` is refused: it would present \
             the caller's own busbar credential (the virtual key or busbar-audience token they \
             authenticated to busbar with) to this MCP server, and a caller's busbar credential \
             never travels upstream. Use `token_exchange:` (busbar exchanges its own subject \
             token for a down-scoped token bound to this server's `aud:`), or `own` (the default: \
             busbar presents no caller credential)."
        );
        assert!(
            error.starts_with(&format!("{instance}: plugin ")),
            "{error}"
        );
        let (_, reason) = error
            .split_once(" open failed: ")
            .expect("the plugin refused its open");
        assert_eq!(
            reason, expected,
            "the registration's exact security refusal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_passthrough_registration_is_refused_before_the_callers_credential_can_leave() {
        let _one = PUBLISHING.lock().await;
        let mut server = TlsToolServer::new().await;
        let mut forwarded = server.section();
        forwarded["fs"]["upstream_credentials"] = "passthrough".into();
        let refusal = server
            .try_rig("door-passthrough-refused", forwarded, &|app| app)
            .err()
            .expect("the plane forbids lending its caller's busbar credential");
        assert_member_passthrough_refused(&refusal, "door-passthrough-refused", "fs");
        assert!(
            server.heard.try_recv().is_err(),
            "a refused configuration sends no upstream request"
        );
        let rig = server.rig("door-own-credential", server.section(), &|app| app);
        let token = rig.bound_token();
        let (status, body) = send(&rig.router, Some(&token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a served answer");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "{body}"
        );
        let (mut call, mut list) = (None, None);
        while let Ok(request) = server.heard.try_recv() {
            if request.contains("\"tools/call\"") {
                call = Some(request);
            } else if request.contains("\"tools/list\"") {
                list = Some(request);
            }
        }
        for (what, request) in [("call", call), ("verify-on-call list", list)] {
            let request = request
                .unwrap_or_else(|| panic!("the server heard the {what}"))
                .to_ascii_lowercase();
            assert!(
                !request.contains("authorization:"),
                "{what}: no credential at all: {request}"
            );
            assert!(
                !request.contains(&token.to_ascii_lowercase()),
                "the caller's token never leaves"
            );
        }
        server.close().await;
    }

    fn grant(rig: &Rig, scopes: &[(&str, &str)]) {
        let mut key = (*rig.key).clone();
        key.allowed_scopes = Some(
            scopes
                .iter()
                .map(|(kind, value)| busbar_contract::records::ScopeRef {
                    kind: surface(kind).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        );
        rig.gov.store().put_key(&key).expect("the key is stored");
        rig.gov.refresh().expect("the book refreshes");
    }

    pub(crate) fn form_value(body: &str, key: &str) -> String {
        body.split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn exchanges(rig: &Rig) -> Vec<(String, String)> {
        rig.tokens
            .opened
            .lock()
            .expect("unpoisoned")
            .iter()
            .map(|(_, target, _, body)| (target.clone(), body.clone()))
            .collect()
    }

    pub(crate) fn three_tools() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()},
            {"name": "write_file", "description": "writes a file to disk", "inputSchema": tool_schema()},
            {"name": "stat", "description": "reads a file's metadata", "inputSchema": tool_schema()},
        ])
    }

    const SUBJECT_VAR: &str = "BUSBAR_DOOR_EXCHANGE_TEST_SUBJECT";

    pub(crate) const TOKEN_URL: &str = "https://as.example/token";

    fn exchange_section(server: &TlsToolServer) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             allow_private: true\n  aud: \"https://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{TOKEN_URL}\"\n    \
             subject_token: {{ env: {SUBJECT_VAR} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
             write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
            tool_digest(),
            surface("write_digest"),
            surface("stat_digest"),
        ))
        .expect("a section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_exchange_registration_presents_the_token_exchanged_for_the_callers_down_scope()
    {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT_VAR, "busbar-own-subject-token");
        let granted: &[(&str, &str)] = &[
            ("scope_server", "fs"),
            ("scope_tool", "fs_read_file"),
            ("scope_tool", "fs_write_file"),
            ("scope_tool", "git_log"),
        ];
        for (instance, grants, down_scope) in [
            (
                "door-exchange-granted",
                Some(granted),
                "fs_read_file+fs_write_file",
            ),
            ("door-exchange-wildcard", None, "fs_read_file"),
        ] {
            let mut server =
                TlsToolServer::listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
            let port = server.port;
            let rig = server.rig(instance, exchange_section(&server), &|app| app);
            let heard = &mut server.heard;
            if let Some(grants) = grants {
                grant(&rig, grants);
            }
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r.to_ascii_lowercase());
                } else if r.contains("\"tools/list\"") {
                    list = Some(r.to_ascii_lowercase());
                }
            }
            let call = call.expect("the server heard the call");
            assert!(
                call.contains(&format!("authorization: bearer tok-{down_scope}")),
                "{instance}: the call presents the token for the caller's down-scope: {call}"
            );
            let list = list.expect("the server heard the verify-on-call list");
            assert!(
                list.contains("authorization: bearer tok-fs_read_file+fs_stat+fs_write_file"),
                "{instance}: the door's own fetch presents the registration's token: {list}"
            );
            let field = busbar_contract::abi::auth::SCOPE_REQUEST_FIELD;
            assert!(
                !call.contains(field) && !list.contains(field),
                "the host's scope field never reaches the server"
            );
            let exchanges = exchanges(&rig);
            let scopes: Vec<String> = exchanges
                .iter()
                .map(|(_, r)| form_value(r, "scope"))
                .collect();
            assert_eq!(
                scopes,
                ["fs_read_file+fs_stat+fs_write_file", down_scope],
                "{instance}: one exchange per scope"
            );
            for (target, r) in &exchanges {
                assert_eq!(target, TOKEN_URL);
                assert_eq!(
                    form_value(r, "grant_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                );
                assert_eq!(
                    form_value(r, "requested_token_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                );
                assert_eq!(form_value(r, "subject_token"), "busbar-own-subject-token");
                assert_eq!(
                    form_value(r, "resource"),
                    format!("https%3A%2F%2F127.0.0.1%3A{port}")
                );
                assert!(
                    !r.contains(&rig.token) && !r.contains(&rig.bound_token()),
                    "the caller's credential never reaches the authorization server"
                );
            }
            assert!(rig.all_ended(), "every unit ended");
            server.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tool_pool_fails_over_through_the_one_walk_and_repeats_only_what_it_names() {
        let _one = PUBLISHING.lock().await;
        let listing = || {
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                .to_string()
        };
        let calls = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut n = 0;
            while let Ok(r) = heard.try_recv() {
                n += usize::from(r.contains("\"tools/call\""));
            }
            n
        };
        let tools = |bad: &TlsToolServer, good: &TlsToolServer, repeatable: &str| {
            let mut value = bad.section();
            value["fs2"] = good.section()["fs"].clone();
            value["pools"] = serde_yaml::to_value(serde_json::json!({
                "twins": { "members": ["fs","fs2"], "repeatable":
                    if repeatable.is_empty() { Vec::<&str>::new() } else { vec![repeatable] },
                    "member_granted": true }
            }))
            .expect("the same pool data");
            value
        };
        let instance = "door-tool-pool";
        for (repeatable, twin_answers) in [("read_file", true), ("", false)] {
            let mut bad = TlsToolServer::replying(Arc::new(move |r: &str| {
                if r.contains("\"tools/list\"") {
                    (200, listing())
                } else {
                    (503, "{}".to_string())
                }
            }))
            .await;
            let mut good = TlsToolServer::new().await;
            let rig = bad.rig_with_footing(
                instance,
                tools(&bad, &good, repeatable),
                bad.footing_with_peers(&[&good]),
                &|app| app,
            );
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(
                body.contains("from the server"),
                twin_answers,
                "repeatable [{repeatable}]: {status} {body}"
            );
            assert_eq!(calls(&mut bad.heard), 1, "the primary is called once");
            assert_eq!(
                calls(&mut good.heard),
                usize::from(twin_answers),
                "the twin hears the call only when the pool repeats the tool"
            );
            assert!(rig.all_ended(), "the unit ended inside itself");
            bad.close().await;
            good.close().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_on_call_judges_the_live_list_reuses_a_fresh_look_and_fails_closed() {
        let _one = PUBLISHING.lock().await;
        let tools = |server: &TlsToolServer, ttl: &str| {
            let mut value = server.section();
            value["fs"]["verify_ttl"] = ttl.into();
            value
        };
        let drain = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut got = Vec::new();
            while let Ok(r) = heard.try_recv() {
                got.push(if r.contains("\"tools/list\"") {
                    "list"
                } else if r.contains("\"tools/call\"") {
                    "call"
                } else {
                    "other"
                });
            }
            got
        };

        let instance = "door-verify-on-call";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, tools(&server, "1h"), &|app| app);
        let heard = &mut server.heard;
        for _ in 0..2 {
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        }
        assert_eq!(
            drain(heard),
            vec!["list", "call", "call"],
            "one fetch, two calls"
        );
        drop(rig);
        server.close().await;

        let listed = Arc::new(std::sync::Mutex::new(tool_listing()));
        let mut server = TlsToolServer::listing(Arc::clone(&listed)).await;
        let rig = server.rig(instance, tools(&server, "0s"), &|app| app);
        let heard = &mut server.heard;
        let (status, _) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the control: the approved list serves"
        );
        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "exfil": {"type": "string"}}}}
        ]);
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
        assert_eq!(
            drain(heard),
            vec!["list", "call", "list"],
            "the drifted call was refused before it was sent"
        );
        drop(rig);
        server.close().await;

        let server = TlsToolServer::new().await;
        let rig = server.rig(instance, tools(&server, "0s"), &|app| app);
        server.close().await;
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_tool_list_re_check_gives_up_at_the_registrations_timeout() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-verify-timeout";
        let server = TlsToolServer::replying(Arc::new(|_| (STALL, String::new()))).await;
        let mut section = server.section();
        section["fs"]["verify_ttl"] = "0s".into();
        section["fs"]["timeout"] = "1s".into();
        let rig = server.rig(instance, section, &|app| app);

        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send(&rig.router, Some(&rig.bound_token()), CALL),
        )
        .await
        .expect("the re-check gave up inside 10s: the registration's `timeout: 1s` is its budget");
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_metadata_url_in_the_arguments_is_refused_before_the_call_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-argguard";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;
        let call = |url: &str| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {
                    "name": "fs_read_file",
                    "arguments": { "path": "notes.txt", "fetch": url },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol_version(),
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string()
        };
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &call("http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["code"], -32000, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"], "tool_argument_refused",
            "{body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("tool argument /fetch carries a URL the schema does not declare"),
            "{message}"
        );
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &call("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    fn fetching(url: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {
                "name": "fs_read_file",
                "arguments": { "path": "notes.txt", "fetch": url },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string()
    }

    async fn refused_in_the_arguments(instance: &'static str, urls: &[&str]) {
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;
        for url in urls {
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), &fetching(url)).await;
            let shown = String::from_utf8_lossy(&body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(body["error"]["code"], -32000, "`{url}`: {body}");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &fetching("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_the_deployment_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-blocked";
        let (plain, secure) = (
            format!("http://{BLOCKED_HOST}/x"),
            format!("https://{BLOCKED_HOST}:8443/y"),
        );
        refused_in_the_arguments(instance, &[&plain, &secure]).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_internal_address_the_guard_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-internal";
        refused_in_the_arguments(
            instance,
            &[
                "http://198.18.0.1/x",
                "http://192.0.0.8/x",
                "http://0.1.2.3/x",
                "http://[::ffff:198.18.0.1]/x",
                "http://[::1%25lo]/x",
                "http://[fe80::1%25eth0]/x",
                "http://224.0.0.1/x",
                "http://255.255.255.255/x",
                "http://[ff02::1]/x",
            ],
        )
        .await;
    }

    const ODD_HOSTS: [(&str, &str); 6] = [
        (
            "\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}",
            "localhost",
        ),
        ("\u{2460}\u{2461}\u{2466}.0.0.1", "127.0.0.1"),
        (
            "\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}.\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}",
            "169.254.169.254",
        ),
        ("LOCALHOST\u{3002}", "localhost"),
        ("\u{ff10}\u{ff58}\u{ff17}\u{ff46}\u{ff0e}\u{ff11}", "0x7f.1"),
        (
            "\u{ff10}\u{ff11}\u{ff17}\u{ff17}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff11}",
            "017700000001",
        ),
    ];

    async fn odd_hosts_refused_as_their_ascii_hosts(
        instance: &'static str,
        spellings: &[fn(&str) -> String],
        zero: &[&str],
    ) {
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;
        let refusal = |status: StatusCode, body: &[u8], url: &str| {
            let shown = String::from_utf8_lossy(body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(body).expect("JSON-RPC");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
            (
                body["error"]["code"].clone(),
                body["error"]["data"]["reason"].clone(),
                body["error"]["message"].clone(),
            )
        };
        for (odd, plain) in ODD_HOSTS {
            for spell in spellings {
                let (odd_url, plain_url) = (spell(odd), spell(plain));
                let (status, body) =
                    send(&rig.router, Some(&rig.bound_token()), &fetching(&odd_url)).await;
                let odd_refusal = refusal(status, &body, &odd_url);
                let (status, body) =
                    send(&rig.router, Some(&rig.bound_token()), &fetching(&plain_url)).await;
                let plain_refusal = refusal(status, &body, &plain_url);
                assert_eq!(
                    odd_refusal, plain_refusal,
                    "`{odd_url}` beside `{plain_url}`"
                );
            }
        }
        for url in zero {
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), &fetching(url)).await;
            refusal(status, &body, url);
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );

        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &fetching("https://b\u{fc}cher.example/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_odd_host_spelling_in_the_arguments_is_refused_as_its_ascii_host() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-odd-hosts";
        odd_hosts_refused_as_their_ascii_hosts(
            instance,
            &[|h| format!("http://{h}/latest/meta-data/")],
            &["http://0x/latest/meta-data/"],
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_is_answered_by_the_plane_with_no_walk_and_no_charge() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-local";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app);
        let heard = &mut server.heard;

        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            LIST,
            "tools/list",
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "answered by the plane: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 9, "{body}");
        assert_eq!(
            body["result"]["tools"][0]["name"], "fs_read_file",
            "the catalogue's one tool: {body}"
        );
        assert_eq!(rig.admitted(), 0, "a local answer charges nothing");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "every unit ended");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metadata_document_is_rendered_from_the_doors_facts_and_is_no_unit() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-metadata";
        let mut server = TlsToolServer::new().await;
        let port = server.port;
        let block: serde_yaml::Value = serde_yaml::from_str(&format!(
            "canonical_uri: \"http://127.0.0.1{}\"\n\
                 authorization_servers: [\"https://login.example.com\"]\n\
                 scopes_supported: [\"tools:call\"]\n",
            endpoint()
        ))
        .expect("a block");
        let rig = Rig::with(
            instance,
            port,
            None,
            Some(block),
            Some(server.section()),
            server.footing(),
            &|app| app,
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/.well-known/oauth-protected-resource{}",
                endpoint()
            ))
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = rig.router.clone().oneshot(req).await.expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON document");
        assert_eq!(
            doc,
            serde_json::json!({
                "resource": format!("http://127.0.0.1{}", endpoint()),
                "authorization_servers": ["https://login.example.com"],
                "scopes_supported": ["tools:call"],
                "bearer_methods_supported": ["header"],
            })
        );
        assert_eq!(rig.admitted(), 0, "nothing admitted");
        assert!(rig.all_ended(), "no unit was opened");
        assert!(server.heard.try_recv().is_err(), "nothing dialled");
        server.close().await;
    }

    #[tokio::test]
    async fn the_tool_door_claims_its_endpoint_only_under_a_public_url() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let compose = |instance: &'static str, public_url: Option<&str>| {
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, server.section());
            compose_planes(
                &[(instance.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                public_url,
                &money,
                None,
                None,
                &busbar_kernel::plane_driver::serve::ServeTables::default(),
            )
            .expect("the door plane composes")
        };
        {
            let bare = "serve-door-tools-claims-bare";
            let served = compose(bare, None);
            assert!(
                served.planes[0].snapshot.claims.is_empty(),
                "no public base URL, no claim"
            );
        }
        {
            let block = "serve-door-tools-claims-block";
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            let plane = bound(
                block,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, server.section());
            assert_eq!(
                plane.served().owns,
                [endpoint_section()],
                "the endpoint block it owns beside"
            );
            sections.insert(
            plane.served().owns[0],
            serde_yaml::from_str(
                &format!("canonical_uri: \"https://gw.example{}\"\nauthorization_servers: [\"https://login.example\"]\n", endpoint()),
            )
            .expect("a block"),
        );
            let served = compose_planes(
                &[(block.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                None,
                &money,
                None,
                None,
                &busbar_kernel::plane_driver::serve::ServeTables::default(),
            )
            .expect("the door plane composes");
            let snapshot = &served.planes[0].snapshot;
            assert_eq!(
                snapshot.audience.as_deref(),
                Some(format!("https://gw.example{}", endpoint()).as_str())
            );
            assert!(
                snapshot
                    .claims
                    .iter()
                    .any(|c| c.verb == "POST" && c.target == endpoint()),
                "the endpoint is claimed under its block"
            );
        }
        let public = "serve-door-tools-claims-public";
        let served = compose(public, Some(PUBLIC_URL));
        assert!(
            served.planes[0]
                .snapshot
                .claims
                .iter()
                .any(|c| c.verb == "POST" && c.target == endpoint()),
            "the endpoint is claimed under the public base URL"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_roots_ask_is_relayed_to_the_caller_and_no_retry_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-mrtr-roots";
        let mut server = TlsToolServer::answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else {
                r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#
                    .to_string()
            }
        }))
        .await;
        let mut tools = server.section();
        tools["fs"]["grants"] = serde_yaml::to_value(serde_json::json!({"roots":true})).unwrap();
        let rig = server.rig(instance, tools, &|app| app);
        let heard = &mut server.heard;
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["r"]["method"], "roots/list",
            "the ask reaches the caller verbatim: {body}"
        );
        assert_ne!(body["result"]["requestState"], "s", "{body}");
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard
            .try_recv()
            .expect("the first round reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar sent no retry of its own: it answers nothing on the caller's behalf"
        );
        assert_eq!(rig.admitted(), 1, "one unit, one charge");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod door_boundary {
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::route::RouteAuth;
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::plane_driver::registry::{BuildCtx, PlaneDecl};
    use busbar_kernel::state::App;

    use super::tool_door::{section, TlsToolServer, ADMIN_TOKEN, PUBLIC_URL};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn row() -> &'static PlaneDecl {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        busbar_kernel::plane_driver::door::fold(
            registration(linked_probe(
                super::tool_door::line_door(),
                "door-boundary-row",
            ))
            .expect("the linked door binds"),
        )
        .expect("the door folds")
    }

    pub(crate) fn registry(row: &'static PlaneDecl) {
        let mut rows = busbar_kernel::plane_driver::registry::plane_decls().to_vec();
        rows.retain(|installed| installed.key != row.key);
        rows.push(row);
        busbar_kernel::plane_driver::registry::publish_planes(&rows);
    }

    pub(crate) fn dispatched(
        mut app: App,
        row: &'static PlaneDecl,
        slot: &Arc<dyn std::any::Any + Send + Sync>,
    ) -> App {
        for (path, wire) in (row.claims)(&**slot) {
            app.planes = Arc::new((*app.planes).clone().mount(row.key, &path, wire));
        }
        if let Some(admission) = (row.admission)(&**slot) {
            app.planes = Arc::new((*app.planes).clone().admit(row.key, admission));
        }
        app.plane_slots.insert(
            busbar_kernel::state::runtime_slot_key(row.key),
            Arc::clone(slot),
        );
        app
    }

    fn slot(row: &'static PlaneDecl, port: u16) -> Arc<dyn std::any::Any + Send + Sync> {
        slot_over(row, section(port))
    }

    pub(crate) fn slot_over(
        row: &'static PlaneDecl,
        value: serde_yaml::Value,
    ) -> Arc<dyn std::any::Any + Send + Sync> {
        let value = crate::root::serve::plane_settings(&value);
        let tools = busbar_kernel::plane_driver::door::DoorSection::new(
            row.door,
            row.config_section,
            value,
        );
        let defs = tools.as_defs();
        (row.build)(
            row,
            &BuildCtx {
                endpoint_slot: None,
                plane_defs: &defs,
                public_url: Some(PUBLIC_URL),
                prior: None,
                providers: None,
            },
        )
        .expect("the door builds from its section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-slot";
        let server = TlsToolServer::new().await;
        let port = server.port;
        let row = row();
        registry(row);
        let slot = slot_over(row, server.section());
        let rig = super::tool_door::Rig::with(
            instance,
            port,
            None,
            None,
            Some(server.section()),
            server.footing(),
            &|app| dispatched(app, row, &slot),
        );
        let held = rig
            .app
            .plane_slot(row.key)
            .expect("the configured door has a slot")
            .clone();
        assert!(Arc::ptr_eq(&held, &slot), "one construction, read back");
        assert!(
            (row.admission)(&*held).is_some(),
            "the slot is the door's own object: its admission reads it"
        );
        let claims = (row.claims)(&*held);
        assert!(!claims.is_empty(), "the door claims its paths");
        for (path, _) in claims {
            assert!(
                rig.door_table.iter().any(|(p, _, _)| *p == path),
                "`{path}`, claimed off the door's slot, must be a route the root mounted: {:?}",
                rig.door_table
            );
        }
        server.close().await;
    }

    #[cfg(linked_driver_proofs)]
    async fn pools_door_walk(audience: &str) -> Vec<String> {
        use crate::root::serve::hook_seat_tests::{rig as pools_rig, RigOpts};
        let instance = "door-boundary-pools";
        let rig = pools_rig(
            instance,
            RigOpts {
                members: &[(1, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key_id,
            4_000_000_000,
            generation.as_deref(),
            audience,
            Some("client-1"),
        );

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "p",
                        "{provider}" => "oai0",
                        "{model}" => "m0",
                        s if s.starts_with("{*") => "probe",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "p",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let mut routes = busbar_kernel::base_data_core_lines(&rig.app)
            .into_iter()
            .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
            .collect::<Vec<_>>();
        routes.extend(rig.door_table.iter().cloned());
        let mut walked: Vec<String> = Vec::new();
        for (pattern, verb, auth) in &routes {
            if *auth == RouteAuth::None {
                continue;
            }
            let path = concrete(pattern);
            let (anon, _, _) = rig.send_bare(verb, &path, Some(body.clone()), &[]).await;
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    verb,
                    &path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let (plain, _, _) = rig.send(verb, &path, Some(body.clone())).await;
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            walked.push(path);
        }

        for path in ["/p/v1/messages", "/oai0/m0/v1/messages"] {
            let (anon, _, _) = rig.send_bare("POST", path, Some(body.clone()), &[]).await;
            assert_eq!(
                anon, 401,
                "an anonymous caller is refused on the convenience route POST {path}"
            );
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    "POST",
                    path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on POST {path}"
            );
            let (plain, _, _) = rig.send("POST", path, Some(body.clone())).await;
            assert!(
                plain != 401 && plain != 403,
                "a keyed caller is admitted on the convenience route POST {path}: {plain}"
            );
            walked.push(path.to_string());
        }
        walked
    }

    #[cfg(linked_driver_proofs)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_audience_bound_token_is_confined_to_its_door_plane_through_the_composition() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-confined";
        let server = TlsToolServer::new().await;
        let port = server.port;
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", upstream_listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            let router = axum::Router::new().fallback(|| async {
                axum::Json(serde_json::json!({
                    "id":"msg-door-boundary", "type":"message", "role":"assistant",
                    "model":"test-model", "content":[{"type":"text","text":"hello"}],
                    "stop_reason":"end_turn", "stop_sequence":null,
                    "usage":{"input_tokens":1,"output_tokens":1}
                }))
            });
            axum::serve(upstream_listener, router).await.unwrap();
        });
        let row = row();
        registry(row);
        let slot = slot_over(row, server.section());
        let (audience, metadata) = (row.admission)(&*slot)
            .map(|a| (a.audience, a.resource_metadata))
            .expect("the door binds an audience under the public base URL");
        let rig = super::tool_door::Rig::with(
            instance,
            port,
            None,
            None,
            Some(server.section()),
            server.footing(),
            &|app| {
                std::env::set_var("BUSBAR_DOOR_BOUNDARY_UPSTREAM_KEY", "busbar-upstream-key");
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .unwrap()
                    .expect("the actual store states itself");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .unwrap()
                    .name;
                let settings = crate::root::test_plugins::application_store_settings(
                    std::path::Path::new(&app.plugins_cfg.dir),
                );
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers":{"anthropic":{"api_key":{"env":"BUSBAR_DOOR_BOUNDARY_UPSTREAM_KEY"}}},
                    "models":{"test-model":{"provider":"anthropic"}},
                    "pools":{"pa":{"members":[{"model":"test-model","weight":1}]}},
                    "auth":{"chain":[],"admin_auth":[]},
                    "store":{"module":module,"settings":settings},
                    "advanced":{"allow_destinations":["127.0.0.1"]}
                })).expect("the actual model deployment parses");
                let defs = std::collections::HashMap::from([(
                    "anthropic".to_string(),
                    serde_yaml::from_str::<busbar_kernel::config::ProviderDef>(&format!(
                        "protocol: anthropic\nbase_url: {base_url}\n"
                    ))
                    .expect("the actual upstream definition parses"),
                )]);
                let cfg = busbar_kernel::config::resolve(&deploy, &defs)
                    .expect("the actual model deployment resolves");
                let rules = Arc::clone(&app.root_rules);
                let (mut next, rotate, limits) = busbar_kernel::build_app_from_config(
                    cfg,
                    app.plugins_cfg.clone(),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    Some(&app),
                    &rules,
                )
                .expect("the actual root installs the model and its pool");
                limits.keep().expect("the model limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                next.auth = Arc::clone(&app.auth);
                next.serve_tables = app.serve_tables.clone();
                next.cost = Arc::clone(&app.cost);
                dispatched(next, row, &slot)
            },
        );

        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound_token = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );

        let mut routes = busbar_kernel::base_data_core_lines(&rig.app)
            .into_iter()
            .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
            .collect::<Vec<_>>();
        routes.extend(rig.door_table.iter().cloned());
        let admissible: Vec<String> = rig
            .door_table
            .iter()
            .filter(|(_, _, auth)| *auth != RouteAuth::None)
            .map(|(p, _, _)| p.clone())
            .collect();
        assert!(!admissible.is_empty(), "the door mounts its endpoint");
        let metadata_path = metadata
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .expect("the metadata document's path");
        let declared_public: Vec<String> = vec![
            "/healthz".to_string(),
            "/auth/token".to_string(),
            metadata_path,
        ];
        for public in &declared_public {
            assert!(
                routes
                    .iter()
                    .any(|(path, _, auth)| path == public && *auth == RouteAuth::None),
                "{public} is declared unauthenticated-by-design but no route mounts it with \
                 RouteAuth::None — the bypass set this names is not the one the router built"
            );
        }
        let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&rig.app);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = rig.router.clone();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "pa",
                        "{provider}" => "anthropic",
                        "{model}" => "test-model",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "pa",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        })
        .to_string();
        let send = |method: reqwest::Method, url: String, bearer: Option<String>| {
            let mut req = client.request(method, url).body(body.clone());
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            req.send()
        };

        let (mut checked, mut door_checked) = (0usize, 0usize);
        for (pattern, verb, auth) in &routes {
            let path = concrete(pattern);
            if *auth == RouteAuth::None {
                assert!(
                    declared_public.contains(pattern),
                    "{pattern} is mounted RouteAuth::None but is not in declared_public — an \
                     unauthenticated route must be a deliberate, reviewed act"
                );
                continue;
            }
            let method = reqwest::Method::from_bytes(verb.as_bytes()).unwrap();
            let url = format!("http://{addr}{path}");
            if admissible.contains(pattern) {
                let anon = send(method.clone(), url.clone(), None).await.unwrap();
                assert_eq!(anon.status(), 401, "anonymous on the door, {verb} {path}");
                assert!(
                    anon.headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(
                            |v| v.starts_with("Bearer ") && v.contains("resource_metadata=")
                        ),
                    "a 401 on an OAuth protected resource carries a Bearer challenge naming its \
                     resource_metadata, {verb} {path}"
                );
                let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                    .await
                    .unwrap();
                assert_ne!(
                    bound.status(),
                    401,
                    "the bound token is admitted, {verb} {path}"
                );
                let plain = send(method.clone(), url.clone(), Some(rig.token.clone()))
                    .await
                    .unwrap();
                assert_eq!(
                    plain.status(),
                    401,
                    "a plain key is inadmissible, {verb} {path}"
                );
                door_checked += 1;
                continue;
            }

            let anon = send(method.clone(), url.clone(), None)
                .await
                .unwrap()
                .status();
            let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let plain = send(method, url, Some(rig.token.clone()))
                .await
                .unwrap()
                .status();
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            checked += 1;
        }
        assert_eq!(
            door_checked,
            routes
                .iter()
                .filter(|(p, _, _)| admissible.contains(p))
                .count(),
            "every admissible mounted route was walked"
        );
        assert!(
            door_checked > 0,
            "the door's half of the boundary was asserted"
        );

        let moved = pools_door_walk(&audience).await;
        checked += moved.len();

        for path in [
            "/v1/models",
            "/v1beta/models",
            "/p/v1/messages",
            "/oai0/m0/v1/messages",
        ] {
            assert!(
                moved.iter().any(|walked| walked == path),
                "{path} moved onto the pools door and must be walked guarded there: {moved:?}"
            );
        }

        assert!(
            checked >= 5,
            "the walk covered only {checked} guarded routes — it is not seeing the router"
        );
        for path in &boot_plugin_paths {
            let url = format!("http://{addr}{path}");
            let anon = client.get(&url).send().await.unwrap().status();
            let bound = client
                .get(&url)
                .header("authorization", format!("Bearer {bound_token}"))
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "a bound token is no credential on plugin route {path}"
            );
        }
        handle.abort();
        upstream.abort();
        let _ = upstream.await;
        server.close().await;
    }

    async fn admin(
        rig: &super::tool_door::Rig,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        admin_on(&rig.app, method, path).await
    }

    async fn admin_on(
        app: &Arc<busbar_kernel::state::App>,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .body(axum::body::Body::empty())
            .expect("a request");
        let router = busbar_core_admin::build_router(Arc::clone(app));
        let response = router.oneshot(req).await.expect("answers");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_trust_verbs_report_the_drift_an_operator_has_to_work() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-trust-verbs";
        let schema =
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let description = "reads a file from disk";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": description, "inputSchema": schema}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(Arc::clone(&listed)).await;
        let digest = super::tool_door::surface("tool_digest");
        let tools = server.section();
        let row = row();
        registry(row);
        let slot = slot_over(row, tools.clone());

        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let rig = server.rig(instance, tools, &|mut app| {
            let auth_cfg = busbar_kernel::config::AuthCfg {
                admin_auth: chain
                    .iter()
                    .map(busbar_kernel::config::AuthChainEntry::bare)
                    .collect(),
                ..busbar_kernel::config::AuthCfg::default_none()
            };
            app.admin_modules = Arc::new(
                busbar_kernel::auth::AdminAuthChain::build(
                    &auth_cfg,
                    &app.hook_env.registry,
                    &app.secret_resolver,
                )
                .expect("the actual root opens the admin chain"),
            );
            app.admin_chain = chain.clone();
            dispatched(app, row, &slot)
        });

        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "connect is mounted and served by the door: {body}"
        );
        assert_eq!(body["state"], "approved", "{body}");
        assert_eq!(body["observed_tools"], 1, "{body}");
        assert_eq!(body["capabilities"][0]["status"], "approved", "{body}");
        assert_eq!(body["capabilities"][0]["approved_digest"], digest, "{body}");
        assert!(
            server
                .heard
                .try_recv()
                .is_ok_and(|r| r.contains("\"tools/list\"")),
            "the server was asked for its tool list"
        );

        let audience = (row.admission)(&*slot).expect("an audience").audience;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let heard_now: Vec<String> = std::iter::from_fn(|| server.heard.try_recv().ok()).collect();
        assert!(
            heard_now.len() == 1 && heard_now[0].contains("\"tools/call\""),
            "the connect's look is fresh, so the call fetches no list: {heard_now:?}"
        );

        let (status, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            (body["serving"].clone(), body["contacted"].clone()),
            (true.into(), true.into()),
            "{body}"
        );

        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": description,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "webhook_url": {"type": "string"}}}}
        ]);
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "a refresh that finds a drift succeeded: {body}"
        );
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]), "{body}");
        let _ = server.heard.try_recv();

        let (status, body) = admin(&rig, "GET", "/tools/fs/changes").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]));
        assert!(
            server.heard.try_recv().is_err(),
            "`changes` contacts nothing"
        );

        let (_, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(body["serving"], false, "{body}");

        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");

        let mut wire = Vec::new();
        while let Ok(r) = server.heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );

        for (method, path) in [
            ("POST", "/tools/nope/connect"),
            ("GET", "/tools/nope/changes"),
            ("GET", "/tools/nope/health"),
        ] {
            let (status, body) = admin(&rig, method, path).await;
            assert_eq!(status, 404, "{method} {path}: {body}");
            assert_eq!(body["error"]["code"], "not_found", "{body}");
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_fetches_with_the_members_binding_and_never_for_a_passthrough_member() {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(
            "BUSBAR_DOOR_CONNECT_TEST_SUBJECT",
            "busbar-own-connect-subject",
        );
        let listed = || {
            Arc::new(std::sync::Mutex::new(serde_json::json!([
                {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
                 "inputSchema": super::tool_door::tool_schema()}
            ])))
        };
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);

        {
            let instance = "door-connect-exchange";
            let mut server = super::tool_door::TlsToolServer::listing(listed()).await;
            let mut tools = connect_section(&server, true);
            tools["fs"]["token_exchange"]["subject_token"]["env"] =
                "BUSBAR_DOOR_CONNECT_TEST_SUBJECT".into();
            let slot = slot_over(row, tools.clone());
            let rig = server.rig(instance, tools, &|mut app| {
                let auth_cfg = busbar_kernel::config::AuthCfg {
                    admin_auth: chain
                        .iter()
                        .map(busbar_kernel::config::AuthChainEntry::bare)
                        .collect(),
                    ..busbar_kernel::config::AuthCfg::default_none()
                };
                app.admin_modules = Arc::new(
                    busbar_kernel::auth::AdminAuthChain::build(
                        &auth_cfg,
                        &app.hook_env.registry,
                        &app.secret_resolver,
                    )
                    .expect("the actual root opens the admin chain"),
                );
                app.admin_chain = chain.clone();
                dispatched(app, row, &slot)
            });
            let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["state"], "approved", "{body}");
            let list = server
                .heard
                .try_recv()
                .expect("the server was asked for its tool list")
                .to_ascii_lowercase();
            assert!(
                list.contains("authorization: bearer tok-fs_read_file"),
                "connect presents the token exchanged for the registration's approved set: {list}"
            );
            let exchanges = super::tool_door::exchanges(&rig);
            assert_eq!(exchanges.len(), 1, "{exchanges:?}");
            assert_eq!(
                super::tool_door::form_value(&exchanges[0].1, "subject_token"),
                "busbar-own-connect-subject",
                "busbar's own subject token"
            );
            server.close().await;
        }

        let mut server = super::tool_door::TlsToolServer::listing(listed()).await;
        let mut tools = server.section();
        tools["fs"]["upstream_credentials"] = "passthrough".into();
        let error = match server.try_rig("door-connect-passthrough", tools, &|mut app| {
            let auth_cfg = busbar_kernel::config::AuthCfg {
                admin_auth: chain
                    .iter()
                    .map(busbar_kernel::config::AuthChainEntry::bare)
                    .collect(),
                ..busbar_kernel::config::AuthCfg::default_none()
            };
            app.admin_modules = Arc::new(
                busbar_kernel::auth::AdminAuthChain::build(
                    &auth_cfg,
                    &app.hook_env.registry,
                    &app.secret_resolver,
                )
                .expect("the actual root opens the admin chain"),
            );
            app.admin_chain = chain.clone();
            app
        }) {
            Ok(_) => panic!("caller credential forwarding must be refused"),
            Err(error) => error,
        };
        super::tool_door::assert_member_passthrough_refused(
            &error,
            "door-connect-passthrough",
            "fs",
        );
        assert!(server.heard.try_recv().is_err(), "connect fetched nothing");
        server.close().await;
    }

    const APPLY_SUBJECT_VAR: &str = "BUSBAR_DOOR_APPLY_CONNECT_TEST_SUBJECT";

    fn connect_section(
        server: &super::tool_door::TlsToolServer,
        exchanged: bool,
    ) -> serde_yaml::Value {
        let mut tools = server.section();
        if exchanged {
            tools["fs"]["aud"] = format!("https://127.0.0.1:{}", server.port).into();
            tools["fs"]["token_exchange"] = serde_yaml::from_str(&format!(
                "token_url: \"{}\"\nsubject_token: {{ env: {APPLY_SUBJECT_VAR} }}\n",
                super::tool_door::TOKEN_URL,
            ))
            .expect("the exchange binding");
        }
        tools
    }

    async fn connect_across_an_apply(
        instance: &'static str,
        server: &mut super::tool_door::TlsToolServer,
        before: serde_yaml::Value,
        after: serde_yaml::Value,
    ) -> (u16, serde_json::Value, String) {
        std::env::set_var(APPLY_SUBJECT_VAR, "busbar-own-apply-subject");
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);
        let booted = slot_over(row, before.clone());
        let rig = server.rig(instance, before, &|mut app| {
            let auth_cfg = busbar_kernel::config::AuthCfg {
                admin_auth: chain
                    .iter()
                    .map(busbar_kernel::config::AuthChainEntry::bare)
                    .collect(),
                ..busbar_kernel::config::AuthCfg::default_none()
            };
            app.admin_modules = Arc::new(
                busbar_kernel::auth::AdminAuthChain::build(
                    &auth_cfg,
                    &app.hook_env.registry,
                    &app.secret_resolver,
                )
                .expect("the actual root opens the admin chain"),
            );
            app.admin_chain = chain.clone();
            dispatched(app, row, &booted)
        });
        let generation = rig.live.current().generation;

        let applied = Arc::new(dispatched((*rig.app).clone(), row, &slot_over(row, after)));
        rig.live.apply(&applied);
        assert_eq!(
            rig.live.current().generation,
            generation + 1,
            "the door took the apply"
        );
        let (status, body) = admin_on(&applied, "POST", "/tools/fs/connect").await;
        let list = server
            .heard
            .try_recv()
            .unwrap_or_default()
            .to_ascii_lowercase();
        (status, body, list)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_presents_the_binding_the_apply_gave_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-added";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(listed).await;
        let before = connect_section(&server, false);
        let after = connect_section(&server, true);
        let (status, body, list) =
            connect_across_an_apply(instance, &mut server, before, after).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the applied binding exchanged: {list}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_that_keeps_the_member_presents_its_binding() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-kept";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(listed).await;
        let before = connect_section(&server, true);
        let after = connect_section(&server, true);
        let (status, body, list) =
            connect_across_an_apply(instance, &mut server, before, after).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the member's binding exchanged: {list}"
        );
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod spent_ledger {
    use std::sync::Arc;

    fn durable_cfg(tag: &str) -> (std::path::PathBuf, serde_json::Value) {
        let directory = crate::root::test_plugins::scratch(&format!(
            "{tag}-{}",
            busbar_kernel::door::op_id().counter(),
        ));
        let file = directory.join("continuations.sqlite");
        let settings = serde_json::json!({"db_path":file});
        (file, settings)
    }

    fn open_durable(
        settings: &serde_json::Value,
    ) -> Arc<dyn busbar_contract::records::RecordStore> {
        use crate::root::loader::dispatch::kinds::store::{Store, StoreFacts};
        use crate::root::loader::dispatch::{
            load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
        };
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
                .expect("BUSBAR_TEST_SQLITE_CDYLIB must name the actual built SQLite product"),
        );
        let stated = rendering_of_library(&path)
            .expect("the actual durable store statement reads")
            .expect("the actual durable store exports its statement");
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load_dropped::<Store>(
            &path,
            &stated,
            Bind {
                instance: format!("door-spent-{}", busbar_kernel::door::op_id().counter()).into(),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the actual durable store loads through the memory ABI");
        assert!(
            !plugin
                .context::<StoreFacts>()
                .expect("the store states its capabilities")
                .ephemeral,
            "the replay and restart cases require a durable product store"
        );
        Arc::new(
            crate::root::loader::store_v3::LoadedStore::open(
                plugin,
                dispatcher,
                &serde_json::to_vec(settings).expect("the durable settings serialize"),
                busbar_kernel::door::op_id,
            )
            .expect("the actual SQLite store opens its shared file"),
        )
    }

    use super::tool_door::{protocol_version, send_as, Footing, Ledger, Rig, TlsToolServer};
    use crate::root::serve::planes_tests::PUBLISHING;

    const INSTANCE: &str = "door-spent-ledger";

    const SERVER: &str = "bank";
    const PROMPT: &str = "transfer";

    const RENDERED: &str = "Transfer 10 to alice";

    const ALREADY_SPENT: &str = "state_already_spent";

    fn tools(server: &TlsToolServer) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "{SERVER}:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             prompts_allow:\n    {PROMPT}:\n      template: \"{RENDERED}\"\n      \
             ask_caller:\n        - confirm: {{ method: \"elicitation/create\", \
             params: {{ message: \"Confirm the transfer\" }} }}\n"
        ))
        .expect("a section")
    }

    fn gated() -> String {
        format!("{SERVER}_{PROMPT}")
    }

    fn node(server: &TlsToolServer, ledger: Ledger, book: Option<&Rig>) -> Rig {
        server.rig_with_footing(
            INSTANCE,
            tools(server),
            Footing {
                ledger,
                book,
                guarded: false,
                tls: None,
            },
            &|app| app,
        )
    }

    type Answer = (u16, serde_json::Value);

    async fn call(rig: &Rig, mut params: serde_json::Value) -> Answer {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": protocol_version(),
            "io.modelcontextprotocol/clientCapabilities":
                { "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } },
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": params,
        });
        let (status, bytes) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &body.to_string(),
            "prompts/get",
            Some(&gated()),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    async fn ask(rig: &Rig) -> String {
        let (status, body) = call(rig, serde_json::json!({ "name": gated() })).await;
        assert_eq!(
            status, 200,
            "the opening round must ask, not refuse: {body}"
        );
        assert!(
            body.pointer("/result/messages").is_none(),
            "the opening round must not render the gated prompt: {body}"
        );
        body.pointer("/result/requestState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("the opening round must issue continuation state: {body}"))
            .to_string()
    }

    async fn redeem(rig: &Rig, state: &str) -> Answer {
        call(
            rig,
            serde_json::json!({
                "name": gated(),
                "requestState": state,
                "inputResponses": { "confirm": { "action": "accept", "content": {} } },
            }),
        )
        .await
    }

    fn proceeded(answer: &Answer) -> bool {
        answer.0 == 200
            && answer.1.pointer("/result/messages/0/content/text") == Some(&RENDERED.into())
    }

    fn refused_as_spent(answer: &Answer) -> bool {
        answer.0 == 400
            && answer
                .1
                .pointer("/error/data/reason")
                .and_then(|r| r.as_str())
                == Some(ALREADY_SPENT)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (file, cfg) = durable_cfg("door-askstate-fleet");
        let node_a = node(&server, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(&server, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            refused_as_spent(&second),
            "a second node of the deployment redeemed an approval already spent: {second:?}; the \
             shared durable database: {}",
            file.display()
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (_file, cfg) = durable_cfg("door-askstate-restart");
        let before = node(&server, Ledger::Store(open_durable(&cfg)), None);
        let state = ask(&before).await;
        let first = redeem(&before, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let after = node(&server, Ledger::Store(open_durable(&cfg)), Some(&before));
        drop(before);
        let second = redeem(&after, &state).await;
        assert!(
            refused_as_spent(&second),
            "a restart handed a spent approval back: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (_file, cfg) = durable_cfg("door-askstate-distinct");
        let node_a = node(&server, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(&server, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let first = ask(&node_a).await;
        let spent = redeem(&node_a, &first).await;
        assert!(
            proceeded(&spent),
            "the first approval dispatches: {spent:?}"
        );
        let second = ask(&node_a).await;
        assert_ne!(first, second, "two mints differ");
        let answer = redeem(&node_b, &second).await;
        assert!(
            proceeded(&answer),
            "a freshly minted approval is not the one spent: {answer:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let solo = node(&server, Ledger::Unbound, None);
        let state = ask(&solo).await;
        let first = redeem(&solo, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&solo, &state).await;
        assert!(
            refused_as_spent(&second),
            "single use per node must hold with no store: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let node_a = node(&server, Ledger::Unbound, None);
        let node_b = node(&server, Ledger::Unbound, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "with no shared ledger node B has nothing to consult: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let node_a = node(&server, Ledger::Memory, None);
        let node_b = node(&server, Ledger::Memory, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "an in-memory store per node keeps nothing the other reads: {second:?}"
        );
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod upstream_ask_relay {
    use std::sync::Arc;

    use super::tool_door::{send, tool_digest, tool_listing, Rig, TlsToolServer, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    const INSTANCE: &str = "door-ask-relay";

    const ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"draft":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":4096}}},"requestState":"s"}}"#;

    async fn asking_server() -> TlsToolServer {
        TlsToolServer::answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                ASK.to_string()
            }
        }))
        .await
    }

    fn tools(server: &TlsToolServer, granted: bool) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             grants: {{ sampling: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    async fn call(rig: &Rig, body: &str) -> (u16, serde_json::Value) {
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), body).await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    fn retry(state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = serde_json::json!({ "draft": { "role": "assistant", "content": { "type": "text", "text": "the caller's own draft" } } });
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_ask_reaches_the_caller_verbatim_and_its_retry_goes_back_to_the_member() {
        let _one = PUBLISHING.lock().await;
        let mut server = asking_server().await;
        let rig = server.rig(INSTANCE, tools(&server, true), &|app| app);
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 200, "{body}");
        let upstream: serde_json::Value = serde_json::from_str(ASK).expect("the ask");
        assert_eq!(
            body["result"]["inputRequests"], upstream["result"]["inputRequests"],
            "the upstream's requests reach the caller byte for byte: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's state")
            .to_string();
        assert_ne!(
            state, "s",
            "the upstream's own state is nested in busbar's sealed one"
        );
        let verify = server
            .heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = server
            .heard
            .try_recv()
            .expect("the call reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            server.heard.try_recv().is_err(),
            "busbar answered nothing upstream on the caller's behalf"
        );

        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered by the caller",
            "{body}"
        );
        let mut sent = None;
        while let Ok(request) = server.heard.try_recv() {
            if request.contains("inputResponses") {
                sent = Some(request);
            }
        }

        let sent = sent.expect("the retry reached the member");
        let body = sent
            .split_once("\r\n\r\n")
            .map_or(sent.as_str(), |(_, b)| b);
        let sent: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(sent["params"]["requestState"], "s", "{sent}");
        assert_eq!(
            sent["params"]["inputResponses"]["draft"]["content"]["text"], "the caller's own draft",
            "{sent}"
        );

        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 400, "a spent state is refused: {body}");

        let (status, body) = call(&rig, &retry("forged")).await;
        assert_eq!(status, 403, "a forged state is refused: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_is_refused_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let server = asking_server().await;
        let rig = server.rig(INSTANCE, tools(&server, false), &|app| app);
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_ungranted", "{body}");
        assert!(body.get("result").is_none(), "{body}");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
#[path = "door_listen.rs"]
mod door_listen;

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod task_continuation {
    use busbar_kernel::governance::NewKeySpec;

    use super::tool_door::{
        protocol_version, send_as, tool_digest, tool_listing, Footing, Ledger, Rig, Rows,
        TlsToolServer, CALL,
    };
    use crate::root::serve::planes_tests::PUBLISHING;

    const TASKS: &str = "io.modelcontextprotocol/tasks";

    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    fn tools(server: &TlsToolServer, support: &str) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: {support} }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    fn declared() -> serde_json::Value {
        serde_json::json!({ "extensions": { TASKS: {} } })
    }

    fn task_call() -> String {
        let mut call: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = declared();
        call.to_string()
    }

    fn verb(method: &str, task_id: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": method,
            "params": {
                "taskId": task_id,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": declared(),
                },
            },
        })
        .to_string()
    }

    async fn ask(rig: &Rig, token: &str, method: &str, task_id: &str) -> (u16, serde_json::Value) {
        let (status, body) = send_as(
            &rig.router,
            Some(token),
            &verb(method, task_id),
            method,
            Some(task_id),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);

    async fn until(rig: &Rig, task_id: &str, status: &str) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + HANG_GUARD;
        while tokio::time::Instant::now() < deadline {
            let (_, body) = ask(rig, &rig.bound_token(), "tasks/get", task_id).await;
            if body["result"]["status"] == status {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("task {task_id} never reached `{status}`");
    }

    async fn gated_server(release: tokio::sync::watch::Receiver<bool>) -> TlsToolServer {
        TlsToolServer::gated(release, ANSWER).await
    }

    async fn next_call(heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        let wait = async {
            loop {
                let request = heard.recv().await.expect("the server hears");
                if request.contains("\"tools/call\"") {
                    return request;
                }
            }
        };
        tokio::time::timeout(HANG_GUARD, wait)
            .await
            .expect("the upstream call ran")
    }

    async fn create(rig: &Rig) -> (serde_json::Value, String) {
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a taskId")
            .to_string();
        (body, task_id)
    }

    fn observed_count(rig: &Rig) -> usize {
        rig.work_observations
            .lock()
            .expect("the host observations")
            .len()
    }

    fn assert_task_ttl(
        rig: &Rig,
        body: &serde_json::Value,
        task_id: &str,
        since: usize,
    ) -> busbar_contract::abi::mechanism::inspection::WorkObservation {
        let result = &body["result"];
        assert_eq!(result["taskId"], task_id, "the exact observed work");
        let stamp = result["createdAt"]
            .as_str()
            .expect("the real task creation timestamp");
        assert_eq!(
            stamp.len(),
            24,
            "the task's UTC millisecond timestamp: {stamp}"
        );
        let number = |range: std::ops::Range<usize>| {
            stamp[range].parse::<u64>().expect("timestamp component")
        };
        let target = (
            number(0..4) as i64,
            number(5..7) as u32,
            number(8..10) as u32,
        );
        let (mut lo, mut hi) = (0i64, 3_000_000i64);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if busbar_contract::civil::civil_from_days(mid) < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        assert_eq!(busbar_contract::civil::civil_from_days(lo), target);
        let seconds = u64::try_from(lo)
            .unwrap()
            .checked_mul(86_400)
            .unwrap()
            .checked_add(number(11..13).checked_mul(3600).unwrap())
            .unwrap()
            .checked_add(number(14..16).checked_mul(60).unwrap())
            .unwrap()
            .checked_add(number(17..19))
            .unwrap();
        let millis = number(20..23);
        let rendered = busbar_contract::civil::rfc3339_from_secs(seconds);
        assert_eq!(
            format!("{}.{millis:03}Z", rendered.trim_end_matches('Z')),
            stamp
        );
        let created_ms = seconds
            .checked_mul(1000)
            .unwrap()
            .checked_add(millis)
            .unwrap();
        let ttl = result["ttlMs"].as_u64().expect("an integer TTL");
        let observations = rig.work_observations.lock().expect("the host observations");
        let candidates: Vec<_> = observations[since..]
            .iter()
            .filter(|seen| seen.reference == task_id.as_bytes() && seen.instance == rig.instance)
            .collect();
        assert!(
            !candidates.is_empty(),
            "the response inspected its own work {task_id}"
        );
        let seen = candidates
            .into_iter()
            .find(|seen| {
                let o = seen.observation;
                o.settled_ms
                    .unwrap_or(o.observed_ms)
                    .checked_add(o.retain_ms)
                    .and_then(|horizon| horizon.checked_sub(created_ms))
                    == Some(ttl)
            })
            .expect("the exact wire TTL is the real host horizon minus task creation");
        assert!(
            seen.observation.opened_ms >= created_ms,
            "work opens after task creation"
        );
        assert_eq!(
            seen.observation.retain_ms, 300_000,
            "the host's actual retention policy"
        );
        seen.observation
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_call_answers_a_task_and_its_upstream_call_runs_without_a_poll() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-runs";
        let (release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rig = server.rig(instance, tools(&server, "optional"), &|app| app);

        let observed_before = observed_count(&rig);
        let (body, task_id) = create(&rig).await;
        let result = &body["result"];
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(result["resultType"], "task", "{body}");
        assert_eq!(result["status"], "working", "{body}");
        let observation = assert_task_ttl(&rig, &body, &task_id, observed_before);
        assert!(
            observation.settled_ms.is_none(),
            "a live task has no established expiry"
        );
        assert_eq!(result["pollIntervalMs"], 250, "{body}");
        assert_eq!(result["content"], serde_json::json!([]), "{body}");
        assert_eq!(
            task_id.len(),
            32,
            "the work handle's 128-bit reference: {task_id}"
        );
        for absent in ["result", "error", "inputRequests", "requestState"] {
            assert!(
                result.get(absent).is_none(),
                "`{absent}` is tasks/get's: {body}"
            );
        }

        let call = next_call(&mut server.heard).await;
        assert!(call.starts_with("POST /rpc "), "{call}");

        let (status, working) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{working}");
        assert_eq!(working["result"]["status"], "working", "{working}");
        assert_eq!(working["result"]["resultType"], "complete", "{working}");
        assert!(working["result"].get("result").is_none(), "{working}");

        release.send_replace(true);
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(done["id"], 41, "{done}");
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        assert!(done["result"].get("error").is_none(), "{done}");

        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
        assert_eq!(rig.admitted(), 2, "the creating unit and its continuation");

        let records = rig
            .book
            .durability
            .lock()
            .expect("unpoisoned")
            .audit_records
            .clone();
        let calls: Vec<_> = records
            .iter()
            .filter(|r| {
                r.usage.lines.iter().any(|l| {
                    l.class.as_str() == super::tool_door::surface("class_tool_calls")
                        && l.quantity > 0
                })
            })
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "the tool call is reported once: {records:?}"
        );
        assert_eq!(
            calls[0].subject,
            busbar_kernel_audit::Subject::PrincipalId(rig.key.id.clone()),
            "on the caller's key"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_task_stays_cancelled_and_carries_no_result() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-cancel";
        let (release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rig = server.rig(instance, tools(&server, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        let _call = next_call(&mut server.heard).await;
        let (status, ack) = ask(&rig, &rig.bound_token(), "tasks/cancel", &task_id).await;
        assert_eq!(status, 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "an empty ack: {ack}"
        );
        let (_, got) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");

        release.send_replace(true);
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("the continuation ended");
        let (_, got) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        assert!(got["result"].get("result").is_none(), "{got}");

        let (status, again) = ask(&rig, &rig.bound_token(), "tasks/cancel", &task_id).await;
        assert_eq!(
            (status, again["result"].clone()),
            (200, ack["result"].clone())
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_required_task_tool_refuses_a_caller_that_declared_no_tasks() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-required";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let server = gated_server(gate).await;
        let rig = server.rig(instance, tools(&server, "required"), &|app| app);
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            CALL,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(
            body["error"]["data"]["requiredCapabilities"],
            declared(),
            "{body}"
        );

        let mut undeclared: serde_json::Value =
            serde_json::from_str(&verb("tasks/get", "x")).expect("a verb");
        undeclared["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &undeclared.to_string(),
            "tasks/get",
            Some("x"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_callers_task_answers_exactly_as_an_unknown_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-foreign";
        let (release, gate) = tokio::sync::watch::channel(true);
        let server = gated_server(gate).await;
        let rig = server.rig(instance, tools(&server, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        until(&rig, &task_id, "completed").await;
        drop(release);
        let (_, other) = rig
            .gov
            .mint_signed(
                NewKeySpec {
                    name: "another".to_string(),
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .expect("mint");
        let other = other.expose(&busbar_kernel::seal::lend()).to_string();
        let other = rig.bound_token_for(&other);
        let foreign = ask(&rig, &other, "tasks/get", &task_id).await;
        let unknown = ask(
            &rig,
            &other,
            "tasks/get",
            "00000000000000000000000000000000",
        )
        .await;
        assert_eq!(foreign.0, 400, "{:?}", foreign.1);
        assert_eq!(foreign.1["error"]["code"], -32602, "{:?}", foreign.1);
        assert_eq!(
            foreign.1["error"]["message"],
            "No task with that `taskId` exists for this caller."
        );
        assert_eq!(
            foreign, unknown,
            "a foreign task is indistinguishable from an unknown one"
        );
        let cancel = ask(&rig, &other, "tasks/cancel", &task_id).await;
        assert_eq!(cancel.1["error"], unknown.1["error"]);

        let (_, mine) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(mine["result"]["status"], "completed", "{mine}");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_parks_on_its_own_ask_until_tasks_update_delivers_the_answer() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-ask";
        let (_release, gate) = tokio::sync::watch::channel(true);
        let mut server = gated_server(gate).await;
        let port = server.port;
        let pin = &server.pin;
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             tools_allow:\n    read_file:\n      schema_hash: \"{}\"\n      task_support: optional\n      \
             task_ask_caller:\n        - confirm: {{ method: elicitation/create, params: {{ message: \"Go?\" }} }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = server.rig(instance, section, &|app| app);
        let mut call: serde_json::Value = serde_json::from_str(&task_call()).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call.to_string(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a task")
            .to_string();
        let parked = until(&rig, &task_id, "input_required").await;
        assert_eq!(
            parked["result"]["inputRequests"]["confirm"]["method"], "elicitation/create",
            "{parked}"
        );

        while let Ok(request) = server.heard.try_recv() {
            assert!(!request.contains("\"tools/call\""), "{request}");
        }
        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "confirm": { "action": "accept" } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        let ack: serde_json::Value = serde_json::from_slice(&ack).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "{ack}"
        );

        let call = next_call(&mut server.heard).await;
        assert!(call.contains("\"confirm\""), "{call}");
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        server.close().await;
    }

    const UPSTREAM_ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"ok":{"method":"elicitation/create","params":{"message":"Publish it?","requestedSchema":{"type":"object","properties":{}}}}},"requestState":"theirs"}}"#;

    async fn asking_member() -> TlsToolServer {
        TlsToolServer::answering(std::sync::Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                UPSTREAM_ASK.to_string()
            }
        }))
        .await
    }

    fn asking_tools(server: &TlsToolServer, granted: bool) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             grants: {{ elicitation: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_members_ask_inside_a_task_reaches_the_caller_and_its_answer_reaches_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay";
        let mut server = asking_member().await;
        let rig = server.rig(instance, asking_tools(&server, true), &|app| app);
        let (_, task_id) = create(&rig).await;
        let parked = until(&rig, &task_id, "input_required").await;
        let sent: serde_json::Value = serde_json::from_str(UPSTREAM_ASK).expect("the ask");
        assert_eq!(
            parked["result"]["inputRequests"], sent["result"]["inputRequests"],
            "the member's requests reach the caller verbatim: {parked}"
        );
        assert!(parked["result"].get("requestState").is_none(), "{parked}");
        let first = next_call(&mut server.heard).await;
        assert!(!first.contains("inputResponses"), "{first}");

        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "ok": { "action": "accept", "content": {} } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&ack));

        let retry = next_call(&mut server.heard).await;
        let body = retry
            .split_once("\r\n\r\n")
            .map_or(retry.as_str(), |(_, b)| b);
        let retry: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(retry["params"]["requestState"], "theirs", "{retry}");
        assert_eq!(
            retry["params"]["inputResponses"]["ok"]["action"], "accept",
            "{retry}"
        );
        assert!(
            retry["params"]["arguments"].get("ok").is_none(),
            "the member's answers never become arguments: {retry}"
        );
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "answered by the caller",
            "{done}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_inside_a_task_is_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay-ungranted";
        let server = asking_member().await;
        let rig = server.rig(instance, asking_tools(&server, false), &|app| app);
        let (_, task_id) = create(&rig).await;
        let failed = until(&rig, &task_id, "failed").await;
        assert!(
            failed["result"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("grants.elicitation")),
            "{failed}"
        );
        assert!(failed["result"].get("inputRequests").is_none(), "{failed}");
        server.close().await;
    }

    fn node(
        instance: &'static str,
        server: &TlsToolServer,
        rows: &std::sync::Arc<Rows>,
        max_live: usize,
        book: Option<&Rig>,
    ) -> Rig {
        server.rig_with_footing(
            instance,
            tools(server, "optional"),
            Footing {
                ledger: Ledger::Rows(std::sync::Arc::clone(rows), max_live),
                book,
                guarded: false,
                tls: None,
            },
            &|app| app,
        )
    }

    async fn ended(rig: &Rig) {
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_task_created_on_one_node_is_answered_by_another() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-fleet";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        let a = node(instance, &server, &rows, 4096, None);
        let b = node(instance, &server, &rows, 4096, Some(&a));
        let (_, task_id) = create(&a).await;
        let _call = next_call(&mut server.heard).await;
        let observed_here = observed_count(&a);
        let (status, here) = ask(&a, &a.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{here}");
        assert_eq!(here["result"]["status"], "working", "{here}");
        let here_observation = assert_task_ttl(&a, &here, &task_id, observed_here);
        let observed_there = observed_count(&b);
        let (status, there) = ask(&b, &b.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{there}");
        let there_observation = assert_task_ttl(&b, &there, &task_id, observed_there);
        assert!(here_observation.settled_ms.is_none() && there_observation.settled_ms.is_none());
        assert_eq!(
            there["result"]["ttlMs"]
                .as_u64()
                .unwrap()
                .checked_sub(here["result"]["ttlMs"].as_u64().unwrap()),
            there_observation
                .observed_ms
                .checked_sub(here_observation.observed_ms),
            "live TTL grows by exactly the host-observed age between nodes"
        );
        let (mut here_fields, mut there_fields) = (here.clone(), there.clone());
        here_fields["result"]
            .as_object_mut()
            .unwrap()
            .remove("ttlMs");
        there_fields["result"]
            .as_object_mut()
            .unwrap()
            .remove("ttlMs");
        assert_eq!(
            there_fields, here_fields,
            "every other field comes from the same host task rows"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_live_handles_a_gone_process_left_are_settled_and_a_new_task_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-restart";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let server = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        let gone = node(instance, &server, &rows, 2, None);
        let (_, first) = create(&gone).await;
        let (_, second) = create(&gone).await;
        let (status, refused) = send_as(
            &gone.router,
            Some(&gone.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            503,
            "at the bound of live work: {}",
            String::from_utf8_lossy(&refused)
        );

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let next = node(instance, &server, &rows, 2, Some(&gone));
        drop(gone);
        next.wall
            .fetch_add(3_600_000, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = send_as(
            &next.router,
            Some(&next.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            200,
            "admitted: {}",
            String::from_utf8_lossy(&body)
        );
        for id in [&first, &second] {
            let (_, got) = ask(&next, &next.bound_token(), "tasks/get", id).await;
            assert_eq!(got["result"]["status"], "cancelled", "{got}");
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_settle_the_store_refuses_is_made_again_until_it_lands() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-settle-retry";
        let (_release, gate) = tokio::sync::watch::channel(true);
        let server = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        rows.1.store(2, std::sync::atomic::Ordering::SeqCst);
        let rig = node(instance, &server, &rows, 4096, None);
        let (_, task_id) = create(&rig).await;
        ended(&rig).await;
        let reference =
            busbar_kernel::host_work::parse_reference(task_id.as_bytes()).expect("a reference");
        let key = (
            busbar_kernel::host_work::WORK_SCHEMA,
            busbar_kernel::host_work::work_key(instance, &reference),
        );
        let state = || {
            busbar_kernel::host_records::RecordRows::record_get(&*rows, key.0, &key.1)
                .expect("the actual store reads the task")
                .and_then(|row| row.as_slice().get(1).copied())
        };
        assert_eq!(
            state(),
            Some(busbar_contract::abi::host::service::WORK_LIVE),
            "the store refused the continuation's settle"
        );
        for _ in 0..2 {
            create(&rig).await;
            ended(&rig).await;
        }
        let mut settled = false;
        for _ in 0..250 {
            if state() == Some(busbar_contract::abi::host::service::WORK_SETTLED) {
                settled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(settled, "the owed settle landed");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod hook_parity {
    use super::tool_door::{send_as, surface, Rig, TlsToolServer};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn gate(
        prompt: &str,
        settings: serde_json::Value,
    ) -> busbar_kernel::config::HookCfg {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("the hook sidecar binds a real listener");
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let router = axum::Router::new().route(
            "/hook",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let settings = settings.clone();
                async move {
                    let rejected = settings
                        .get("reject_if_contains")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|needle| {
                            body["request"]["messages"].to_string().contains(needle)
                        });
                    let reply = if rejected {
                        serde_json::json!({"reject":{
                            "status":settings.get("reject_status")
                                .and_then(serde_json::Value::as_u64).unwrap_or(403),
                            "message":"blocked by test gate"
                        }})
                    } else if body["op"] == "transform" {
                        settings
                            .get("raw_transform_reply")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}))
                    } else {
                        settings
                            .get("raw_decide_reply")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}))
                    };
                    axum::Json(reply)
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("the actual hook sidecar serves");
        });
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB")
                .expect("BUSBAR_TEST_WEBREQUEST_CDYLIB names the actual built webrequest product"),
        );
        let statement = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the actual hook statement reads")
            .expect("the actual hook states itself");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual hook statement is valid")
            .name;
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": module,
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": prompt,
            "user": "ro",
            "priority": 0,
            "settings": {"url":endpoint},
            "global": false,
            "default": false,
            "signals": [],
            "groups": [],
            "phase": [],
        }))
        .expect("a hook document")
    }

    pub(crate) fn hook_env() -> busbar_kernel::hooks::HookEnv {
        let _ = super::tool_door::line_door();
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB")
                .expect("BUSBAR_TEST_WEBREQUEST_CDYLIB names the actual built webrequest product"),
        );
        let statement = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the actual hook statement reads")
            .expect("the actual hook states itself");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual hook statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "hook",
            &module,
            crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
        manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-hooks-{}",
            busbar_kernel::door::op_id().counter(),
        ));
        let library = std::fs::read(path).expect("the actual hook library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("hook.tar.gz"), archive)
            .expect("stage the actual hook archive");
        let registry = crate::root::loader::scan_and_validate(
            &directory,
            &crate::root::test_plugins::release_policy(&release),
        )
        .expect("the actual root loader admits the signed hook");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::hooks::HookEnv::new(
            std::sync::Arc::new(registry),
            std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        )
        .expect("the actual root constructs the hook environment")
    }

    pub(crate) fn rig(
        instance: &'static str,
        server: &TlsToolServer,
        hooks: Vec<(&'static str, busbar_kernel::config::HookCfg)>,
    ) -> Rig {
        let env = hook_env();
        server.rig(instance, server.section(), &move |mut app| {
            if hooks.is_empty() {
                return app;
            }
            app.hook_env = env.clone();
            for (name, cfg) in &hooks {
                app.hook_registry.insert((*name).to_string(), cfg.clone());
            }
            app.requested_signals = busbar_kernel::hooks::requested_signals(&app.hook_registry);
            app.any_content_hook = busbar_kernel::hooks::any_content_hook(&app.hook_registry);
            let attached = hooks
                .iter()
                .map(|(name, _)| (*name).to_string())
                .collect::<Vec<_>>();
            app.plane_gates.insert(
                surface("plane_key"),
                app.resolve_container_gates(std::iter::once(("fs", &[][..])), &attached),
            );
            app.plane_rewrites.insert(
                surface("plane_key"),
                app.resolve_container_rewrites(std::iter::once(("fs", &[][..])), &attached),
            );
            app
        })
    }

    pub(crate) fn call(arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "fs_read_file", "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": surface("protocol_version"),
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string()
    }

    pub(crate) fn calls_heard(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Vec<String> {
        std::iter::from_fn(|| heard.try_recv().ok())
            .filter(|r| r.contains("\"tools/call\""))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tools_hooks_reject_all_rejects_a_tools_call() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-reject-all";
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));

        let mut server = TlsToolServer::new().await;
        let control = rig(instance, &server, Vec::new());
        let (status, answer) = send_as(
            &control.router,
            Some(&control.bound_token()),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut server.heard).len(),
            1,
            "the control reached the server"
        );
        drop(control);

        let gated = rig(
            instance,
            &server,
            vec![(
                "reject-all",
                gate(
                    "ro",
                    serde_json::json!({
                        "raw_decide_reply": {"reject": {"status": 403, "message": "no tool calls today"}}
                    }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &gated.router,
            Some(&gated.bound_token()),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&answer));
        let answer: serde_json::Value = serde_json::from_slice(&answer).expect("JSON-RPC");
        assert_eq!(
            answer["error"]["message"], "no tool calls today",
            "{answer}"
        );
        assert!(
            calls_heard(&mut server.heard).is_empty(),
            "a gate that rejects after the call went out stopped nothing"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_calls_content_reaches_the_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-content";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "screen",
                gate(
                    "ro",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow" }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            403,
            "the gate's verdict was driven by the arguments: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            calls_heard(&mut server.heard).len(),
            1,
            "only the clean call went out"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rewrite";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "rewrite",
                gate(
                    "rw",
                    serde_json::json!({ "raw_transform_reply": {
                        "rewrite": { "messages": [
                            { "role": "user", "content": { "path": "/srv/rewritten-by-hook" } }
                        ] }
                    } }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut server.heard);
        assert_eq!(wire.len(), 1, "one call went out");
        assert!(
            wire[0].contains("/srv/rewritten-by-hook") && !wire[0].contains("/etc/hosts"),
            "the server received the arguments the hook rewrote them to: {}",
            wire[0]
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_gate_can_reject_on_the_arguments_it_screens() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rw-screen";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "screen",
                // Screens only: clean arguments are let through untouched (the double's default
                // answer is a chat rewrite a tool call cannot take, which is refused, never
                // relayed un-rewritten).
                gate(
                    "rw",
                    serde_json::json!({
                        "reject_if_contains": "/etc/shadow",
                        "reject_status": 451,
                        "raw_transform_reply": {},
                    }),
                ),
            )],
        );
        let (status, _) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "clean arguments are served");
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 451, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut server.heard).len(),
            1,
            "the rejected call never went out"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rewrite_failure_outcomes_preserve_the_body_or_refuse_before_the_tool_hop() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-failure-dispositions";
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));
        let mut server = TlsToolServer::new().await;
        let weighted = rig(
            instance,
            &server,
            vec![(
                "optional-outcome",
                gate("rw", serde_json::json!({ "raw_transform_reply": {} })),
            )],
        );
        let (status, answer) = send_as(
            &weighted.router,
            Some(&weighted.bound_token()),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut server.heard);
        assert!(
            wire.len() == 1 && wire[0].contains("/etc/hosts"),
            "served with the caller's original arguments: {wire:?}"
        );
        drop(weighted);

        let mut required = gate(
            "rw",
            serde_json::json!({
                "raw_transform_reply": {
                    "reject": {
                        "status": busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                        "message": busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                    }
                }
            }),
        );
        required.on_error =
            serde_json::from_value(serde_json::json!("reject")).expect("an on_error disposition");
        let required = rig(instance, &server, vec![("required-outcome", required)]);
        let (status, body) = send_as(
            &required.router,
            Some(&required.bound_token()),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
            "the required-hook failure outcome refuses the call: {}",
            String::from_utf8_lossy(&body)
        );
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            answer["error"]["message"],
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
            "the content-free refusal reaches the caller: {answer}",
        );
        assert!(
            calls_heard(&mut server.heard).is_empty(),
            "nothing was dispatched"
        );
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod program_member {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        format!(
            "inits=0; lists=0; calls=0; pongs=0\n\
             L='{listing}'\n\
             while IFS= read -r l; do\n\
               id=$(printf '%s' \"$l\" | sed -n 's/.*\"id\":\\([0-9]\\{{10,\\}}\\).*/\\1/p')\n\
               case \"$l\" in\n\
                 *'\"method\":\"initialize\"'*) inits=$((inits+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"s\",\"version\":\"1\"}}}}}}\\n' \"$id\" ;;\n\
                 *'\"method\":\"tools/list\"'*) lists=$((lists+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"info\",\"data\":\"listing\"}}}}\\n'; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"tools\":%s}}}}\\n' \"$id\" \"$L\" ;;\n\
                 *'\"method\":\"tools/call\"'*) calls=$((calls+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":\"srv-%s\",\"method\":\"ping\"}}\\n' \"$calls\"; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"from the server pid=%s inits=%s lists=%s calls=%s pongs=%s\"}}]}}}}\\n' \"$id\" \"$$\" \"$inits\" \"$lists\" \"$calls\" \"$pongs\" ;;\n\
                 *'\"result\":{{}}'*) pongs=$((pongs+1)) ;;\n\
               esac\n\
             done\n"
        )
    }

    fn section() -> serde_yaml::Value {
        section_running(script())
    }

    pub(crate) fn section_running(script: String) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "cwd".into(),
            std::env::current_dir()
                .expect("an absolute fixture cwd")
                .to_str()
                .expect("a UTF-8 fixture cwd")
                .into(),
        );
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script.into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    fn text(body: &[u8]) -> String {
        let body: serde_json::Value = serde_json::from_slice(body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a tool result: {body}"))
            .to_string()
    }

    fn fact<'t>(text: &'t str, key: &str) -> &'t str {
        text.split(' ')
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("{key} in {text:?}"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_serves_the_call_and_a_second_call_reuses_its_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-member";
        let rig = rig_tools(instance, 0, section(), &|app| app);

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let first = text(&body);
        assert!(first.starts_with("from the server "), "{first}");
        assert_eq!(
            fact(&first, "inits"),
            "1",
            "greeted before the call: {first}"
        );
        assert_eq!(
            fact(&first, "lists"),
            "1",
            "verify-on-call on the child: {first}"
        );
        assert_eq!(fact(&first, "calls"), "1");

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let second = text(&body);
        assert_eq!(
            fact(&second, "pid"),
            fact(&first, "pid"),
            "the second call reached the same child"
        );
        assert_eq!(fact(&second, "inits"), "1", "greeted once: {second}");
        assert_eq!(fact(&second, "calls"), "2");
        assert_eq!(
            fact(&second, "pongs"),
            "1",
            "the child's own request was answered once: {second}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_is_served_on_its_own_rig_whatever_the_process_opened_first() {
        let _one = PUBLISHING.lock().await;
        let _first = crate::root::doors::dispatcher();
        let rig = rig_tools("door-program-member-own", 0, section(), &|app| app);
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let text = text(&body);
        assert!(text.starts_with("from the server "), "{text}");
        assert_eq!(fact(&text, "calls"), "1", "{text}");
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_supervised {
    use super::program_member::section_running;
    use super::tool_door::{rig_tools, send, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    fn section(spawns: &std::path::Path) -> serde_yaml::Value {
        section_running(format!("echo spawned >> '{}'; exit 1", spawns.display()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_that_keeps_ending_is_spawned_five_times_then_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-supervised";
        let spawns =
            std::env::temp_dir().join(format!("busbar-{instance}-{}-spawns", std::process::id()));
        let _ = std::fs::remove_file(&spawns);
        let rig = rig_tools(instance, 0, section(&spawns), &|app| app);

        for _ in 0..24 {
            let _ = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let spawned = std::fs::read_to_string(&spawns)
            .unwrap_or_default()
            .lines()
            .count();
        let _ = std::fs::remove_file(&spawns);
        assert_eq!(
            spawned, 5,
            "five ends inside a minute stop the restarts: spawned {spawned} times"
        );
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_ask {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        r#"calls=0; pending=""
L='__LISTING__'
while IFS= read -r l; do
  id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]\{10,\}\).*/\1/p')
  case "$l" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$L" ;;
    *'"method":"tools/call"'*) calls=$((calls+1)); pending=$id; printf '{"jsonrpc":"2.0","id":"srv-ask-%s","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":64}}\n' "$calls" ;;
    *'"srv-ask-'*) got=$(printf '%s' "$l" | sed -n 's/.*"text":"\([^"]*\)".*/\1/p'); [ -n "$got" ] || got=$(printf '%s' "$l" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"answered with %s"}]}}\n' "$pending" "$got" ;;
  esac
done
"#
        .replace("__LISTING__", &listing)
    }

    fn section(granted: bool) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "cwd".into(),
            std::env::current_dir()
                .expect("an absolute fixture cwd")
                .to_str()
                .expect("a UTF-8 fixture cwd")
                .into(),
        );
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script().into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").unwrap(),
        );
        fs.insert(
            "grants".into(),
            serde_yaml::from_str(&format!("{{ sampling: {granted} }}")).unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    async fn call(
        router: &axum::Router,
        token: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, body) = send(router, Some(token), body).await;
        (
            status,
            serde_json::from_slice(&body).expect("a JSON-RPC answer"),
        )
    }

    fn retry(answers: serde_json::Value, state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = answers;
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    fn draft() -> serde_json::Value {
        serde_json::json!({ "role": "assistant", "content": { "type": "text", "text": "the callers own draft" }, "model": "m" })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_childs_ask_reaches_the_caller_verbatim_and_its_answer_reaches_the_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask";
        let rig = rig_tools(instance, 0, section(true), &|app| app);

        let (status, body) = call(&rig.router, &rig.bound_token(), CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(body["result"]["resultType"], "input_required", "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["srv-ask-1"],
            serde_json::json!({"method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Draft it."}}], "maxTokens": 64}}),
            "the child's request, verbatim: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();

        let answered = retry(serde_json::json!({ "srv-ask-1": draft() }), &state);
        let (status, body) = call(&rig.router, &rig.bound_token(), &answered).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );

        let (status, body) = call(&rig.router, &rig.bound_token(), &answered).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a spent state: {body}");
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({ "srv-ask-1": draft() }), "forged"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a forged state: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );

        let (status, body) = call(&rig.router, &rig.bound_token(), CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();
        assert!(
            body["result"]["inputRequests"].get("srv-ask-2").is_some(),
            "{body}"
        );
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({}), &state),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_unanswered", "{body}");
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({ "srv-ask-2": draft() }), &state),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_childs_ask_is_refused_on_its_input_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask-ungranted";
        let rig = rig_tools(instance, 0, section(false), &|app| app);
        let (status, body) = call(&rig.router, &rig.bound_token(), CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"].get("inputRequests").is_none(), "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with ask_ungranted",
            "the child was refused on its input, by the operator's grant: {body}"
        );
    }
}

#[test]
fn the_limits_a_door_plane_is_handed_carry_the_operators_translate_cap() {
    let handed = |yaml: &str| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(yaml).expect("a deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        super::kernel_sections(&cfg)["limits"]["request_body_max_bytes"].as_u64()
    };
    assert_eq!(
        handed("providers: {}\nmodels: {}\nlimits:\n  request_body_max_bytes: 131072\n"),
        Some(131_072)
    );
    assert_eq!(
        handed("providers: {}\nmodels: {}\n"),
        Some(busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT as u64)
    );
}

static NO_PROVIDERS: std::collections::BTreeMap<String, super::ProviderRoute> =
    std::collections::BTreeMap::new();

fn own_reach() -> super::DoorReach<'static> {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    super::DoorReach {
        providers: &NO_PROVIDERS,
        secrets: std::sync::Arc::new(
            busbar_kernel::config::secret::SecretResolver::builtins_only(),
        ),
        auths: std::sync::Arc::new(super::OutboundAuths::new(
            dispatcher,
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::NoNeeds,
            busbar_kernel::diagnostics::Catalogue::NEUTRAL,
        )),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        upgrades: Vec::new(),
        models: None,
    }
}

fn own_secret(name: &str, value: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-door-steps-cred-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    path
}

fn rotate(path: &std::path::Path, value: &str) {
    let aside = path.with_extension("rotating");
    std::fs::write(&aside, value).expect("write the rotated secret");
    std::fs::rename(&aside, path).expect("swap it in");
}

fn registration(path: &std::path::Path, placement: &str) -> serde_yaml::Value {
    serde_yaml::from_str(&format!(
        "url: 'https://agent.vendor/planner'\nupstream_credential: {{secret: {{file: '{}'}}{placement}, \
         lease_ttl_ms: 60000}}",
        path.display()
    ))
    .expect("yaml")
}

fn presents(
    auth: &dyn busbar_contract::auth_calls::OutboundAuth,
    handle: u64,
) -> Vec<(String, String)> {
    match auth.fields_now(
        handle,
        &busbar_contract::auth_calls::FieldsRequest::default(),
    ) {
        Some(busbar_contract::auth_calls::Fields::Ready(fields)) => fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).to_ascii_lowercase(),
                    String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend()))
                        .into_owned(),
                )
            })
            .collect(),
        other => panic!("a header binding answers on the spot: {other:?}"),
    }
}

fn refused(bound: Result<Option<busbar_kernel::plane_driver::AuthBinding>, String>) -> String {
    match bound {
        Err(why) => why,
        Ok(_) => panic!("the load was not refused"),
    }
}

#[test]
fn a_bearer_placement_presents_the_secret_only_as_the_bearer() {
    let path = own_secret("bearer", "s3cr3t-vendor-token\n");
    let reach = own_reach();
    for placement in [", placement: bearer", ""] {
        let binding = super::upstream_credential_binding(
            "planner",
            &registration(&path, placement),
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("it binds")
        .expect("an upstream credential is a binding");
        assert!(
            !binding.passthrough,
            "busbar's own credential, never the caller's"
        );
        let handle = binding
            .per_request
            .as_ref()
            .expect("a refreshed binding")
            .handle_now()
            .expect("it resolves");
        assert_eq!(
            presents(&*binding.auth, handle),
            vec![(
                "authorization".to_string(),
                "Bearer s3cr3t-vendor-token".to_string()
            )],
            "placement `{placement}`"
        );
    }
    let bare: serde_yaml::Value =
        serde_yaml::from_str("url: 'https://agent.vendor/planner'").expect("yaml");
    assert!(
        super::upstream_credential_binding(
            "planner",
            &bare,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time()
        )
        .expect("no block is no error")
        .is_none(),
        "no upstream_credential: nothing is bound, so nothing is presented"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_named_header_placement_presents_the_secret_verbatim_in_that_header() {
    let path = own_secret("apikey", "abc123");
    let reach = own_reach();
    let binding = super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: X-API-Key}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    let handle = binding
        .per_request
        .as_ref()
        .expect("a refreshed binding")
        .handle_now()
        .expect("it resolves");
    assert_eq!(
        presents(&*binding.auth, handle),
        vec![("x-api-key".to_string(), "abc123".to_string())]
    );
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: ''}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    ));
    assert!(err.contains("member 'planner'"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_unresolvable_credential_fails_closed_and_names_the_member() {
    let reach = own_reach();
    let missing = std::path::Path::new("/nonexistent/busbar/agent/secret");
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(missing, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    ));
    assert!(
        err.contains("member 'planner'") && err.contains("cannot resolve"),
        "{err}"
    );

    let path = own_secret("vanish", "tok");
    for lease in [None, Some(0_u64)] {
        let mut bare = registration(&path, "");
        let block = bare
            .get_mut(busbar_contract::section::UPSTREAM_CREDENTIAL_KEY)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("the block");
        let key = serde_yaml::Value::from(busbar_contract::section::CREDENTIAL_LEASE_TTL_KEY);
        match lease {
            None => {
                block.remove(&key);
            }
            Some(ms) => {
                block.insert(key, serde_yaml::Value::from(ms));
            }
        }
        let err = refused(super::upstream_credential_binding(
            "planner",
            &bare,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        ));
        assert!(
            err.contains("member 'planner'") && err.contains("lease_ttl_ms"),
            "{err}"
        );
    }
    let (_, per) = super::upstream_credential(
        "planner",
        &registration(&path, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let first = per
        .handle_now()
        .expect("it resolves while the file is there");
    std::fs::remove_file(&path).expect("remove it");
    assert_eq!(
        per.handle_now(),
        Some(first),
        "a hop before the next refresh presents what the last refresh left"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    for _ in 0..8 {
        assert_eq!(
            per.handle_now(),
            None,
            "gone: nothing is presented, hop after hop"
        );
    }
    std::fs::write(&path, "tok").expect("put it back");
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert!(
        per.handle_now().is_some(),
        "a refresh that finds it back serves it again"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_expired_lease_is_refused_on_the_next_hop() {
    use std::time::{Duration, Instant};
    let path = own_secret("lease-expiry", "tok");
    let reach = own_reach();
    let bound = Instant::now();
    let (_, per) = super::upstream_credential(
        "planner",
        &registration(&path, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    let lease = Duration::from_millis(60_000);
    let first = per.handle_at(bound).expect("a fresh lease is presented");
    assert_eq!(
        per.handle_at(bound + lease - Duration::from_millis(1)),
        Some(first),
        "inside its lease the credential is presented"
    );
    let resolved = Instant::now();
    for hop in 0..8 {
        assert_eq!(
            per.handle_at(resolved + lease + Duration::from_millis(1 + hop)),
            None,
            "past its lease, with no refresh, the hop is refused, never presented"
        );
    }
    let before = Instant::now();
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    let after = Instant::now();
    assert!(
        per.handle_at(before + lease - Duration::from_millis(1))
            .is_some(),
        "a refresh that re-resolves it renews the lease"
    );
    assert_eq!(
        per.handle_at(after + lease + Duration::from_millis(1)),
        None,
        "and the renewed lease expires on the same clock"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_fresh_lease_is_presented() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("lease-fresh", "tok");
    let reach = own_reach();
    let (binding, per) = super::upstream_credential(
        "planner",
        &registration(&path, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    let handle = per.handle_now().expect("a fresh lease is presented");
    assert_eq!(
        presents(&*binding.auth, handle),
        vec![("authorization".to_string(), "Bearer tok".to_string())]
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_secret_pasted_as_its_reference_is_never_echoed_in_the_refusal() {
    const SECRET: &str = "sk-live-4f9QzX7pL2mV8rT1";
    let reach = own_reach();
    for secret in [
        format!("{{{SECRET}}}"),
        format!("{{{SECRET}: {{file: /x}}}}"),
        SECRET.to_string(),
        format!("'{SECRET}'"),
        format!("{{env: {{{SECRET}: 1}}}}"),
        format!("{{file: [{SECRET}]}}"),
        format!("{{module: file, settings: {SECRET}}}"),
        format!("{{module: [{SECRET}]}}"),
    ] {
        let registration: serde_yaml::Value = serde_yaml::from_str(&format!(
            "url: 'https://agent.vendor/planner'\nupstream_credential: {{secret: {secret}}}"
        ))
        .expect("yaml");
        let err = refused(super::upstream_credential_binding(
            "planner",
            &registration,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        ));
        assert!(
            !err.contains(SECRET),
            "the refusal for `secret: {secret}` echoes the secret: {err}"
        );
        assert!(
            err.contains("member 'planner'") && err.contains("upstream_credential.secret"),
            "the refusal names the binding: {err}"
        );
    }
}

struct CountingOpens {
    inner: std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    opened: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::auth_calls::OutboundAuth for CountingOpens {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.open_outbound(style, credential, settings)
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        self.inner.fields_now(handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        self.inner.fields(handle, request, deadline_ns)
    }
}

fn per_hop(path: &std::path::Path, auth: std::sync::Arc<CountingOpens>) -> super::PerHop {
    per_hop_over(
        path,
        auth,
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
    )
}

fn per_hop_over(
    path: &std::path::Path,
    auth: std::sync::Arc<CountingOpens>,
    secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
) -> super::PerHop {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let secret = busbar_contract::secret_ref::SecretRef::file(path.display().to_string());
    let value = secrets.resolve_string(&secret).expect("it resolves");
    let seal = busbar_kernel::seal::lend();
    let value = value.expose(&seal);
    let settings = serde_json::json!({});
    let handle = {
        use busbar_contract::auth_calls::OutboundAuth as _;
        auth.open_outbound("bearer", value.as_bytes(), &settings)
            .expect("it opens")
    };
    super::PerHop {
        secret,
        secrets,
        auth: auth as std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
        style: "bearer",
        header: None,
        lease: std::time::Duration::from_secs(60),
        held: arc_swap::ArcSwapOption::from_pointee(super::Held {
            digest: busbar_contract::abi::sdk::digest::sha256(value.as_bytes()),
            handle,
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
        }),
        refreshing: std::sync::Mutex::new(()),
        lapsed: std::sync::atomic::AtomicBool::new(false),
    }
}

fn bearer_auth() -> std::sync::Arc<CountingOpens> {
    let (inner, _) = own_reach()
        .auths
        .serving("bearer", &serde_json::json!({}))
        .expect("a lookup")
        .expect("the linked header plugin serves `bearer`");
    std::sync::Arc::new(CountingOpens {
        inner,
        opened: std::sync::atomic::AtomicUsize::new(0),
    })
}

#[test]
fn a_rotated_secret_is_presented_on_the_first_hop_after_the_next_refresh() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("rotate", "old-token");
    let auth = bearer_auth();
    let per = per_hop(&path, std::sync::Arc::clone(&auth));
    let opens = || auth.opened.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(opens(), 1, "the composition's one open");

    let first = per.handle_now().expect("it resolves");
    for _ in 0..16 {
        assert_eq!(
            per.handle_now(),
            Some(first),
            "the same handle hop after hop"
        );
    }
    assert_eq!(opens(), 1, "an unchanged secret never re-opens the binding");
    assert_eq!(
        presents(&*auth, first),
        vec![("authorization".to_string(), "Bearer old-token".to_string())]
    );

    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(
        opens(),
        1,
        "a refresh over an unchanged secret never re-opens the binding"
    );
    rotate(&path, "new-token");
    assert_eq!(
        per.handle_now(),
        Some(first),
        "a hop before the next refresh presents what the last refresh left"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    let next = per.handle_now().expect("it resolves");
    assert_ne!(
        next, first,
        "the refresh re-opened the binding for the rotation"
    );
    assert_eq!(opens(), 2, "one re-open for one rotation");
    assert_eq!(
        presents(&*auth, next),
        vec![("authorization".to_string(), "Bearer new-token".to_string())],
        "the first hop after the refresh presents the new value"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(per.handle_now(), Some(next));
    assert_eq!(
        opens(),
        2,
        "and the new value, unchanged, never re-opens it"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_rotated_header_credential_is_presented_in_the_same_header() {
    let path = own_secret("rotate-header", "key-old");
    let reach = own_reach();
    let (binding, per) = super::upstream_credential(
        "planner",
        &registration(&path, ", placement: {header: X-API-Key}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let first = per.handle_now().expect("it resolves");
    assert_eq!(
        presents(&*binding.auth, first),
        vec![("x-api-key".to_string(), "key-old".to_string())]
    );
    rotate(&path, "key-new");
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    let next = per.handle_now().expect("it resolves");
    assert_ne!(next, first, "the rotation re-opened the binding");
    assert_eq!(
        presents(&*binding.auth, next),
        vec![("x-api-key".to_string(), "key-new".to_string())],
        "the re-open keeps the header placement"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn hops_racing_a_rotation_each_present_one_whole_value() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("race", "value-old-0000000000");
    let auth = bearer_auth();
    let per = std::sync::Arc::new(per_hop(&path, std::sync::Arc::clone(&auth)));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hops: Vec<_> = (0..4)
        .map(|_| {
            let (per, auth, stop) = (
                std::sync::Arc::clone(&per),
                std::sync::Arc::clone(&auth),
                std::sync::Arc::clone(&stop),
            );
            std::thread::spawn(move || {
                let mut seen = std::collections::BTreeSet::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let Some(handle) = per.handle_now() else {
                        continue;
                    };
                    for (_, value) in presents(&*auth, handle) {
                        seen.insert(value);
                    }
                }
                seen
            })
        })
        .collect();
    for i in 0..64 {
        let value = if i % 2 == 0 {
            "value-new-1111111111"
        } else {
            "value-old-0000000000"
        };
        rotate(&path, value);
        per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let whole = [
        "Bearer value-old-0000000000".to_string(),
        "Bearer value-new-1111111111".to_string(),
    ];
    for hop in hops {
        for value in hop.join().expect("a hop thread") {
            assert!(whole.contains(&value), "a mixed or partial value: {value}");
        }
    }
    let _ = std::fs::remove_file(&path);
}

struct CountingResolves {
    inner: busbar_kernel::config::secret::SecretResolver,
    resolved: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::secret::SecretResolve for CountingResolves {
    fn resolve(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve(&self.inner, secret)
    }

    fn resolve_string(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve_string(&self.inner, secret)
    }
}

fn answers_within<T: Send + 'static>(
    budget: std::time::Duration,
    ask: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ask());
    });
    rx.recv_timeout(budget).ok()
}

#[test]
fn a_hop_resolves_nothing_and_takes_no_lock() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("no-resolve", "steady-token");
    let resolver = std::sync::Arc::new(CountingResolves {
        inner: busbar_kernel::config::secret::SecretResolver::builtins_only(),
        resolved: std::sync::atomic::AtomicUsize::new(0),
    });
    let per = std::sync::Arc::new(per_hop_over(
        &path,
        bearer_auth(),
        std::sync::Arc::clone(&resolver)
            as std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
    ));
    let resolved = || resolver.resolved.load(std::sync::atomic::Ordering::SeqCst);
    let built = resolved();
    let first = per.handle_now().expect("it resolved at build");
    for _ in 0..256 {
        assert_eq!(per.handle_now(), Some(first));
    }
    assert_eq!(resolved(), built, "256 hops asked the resolver nothing");

    let held = per
        .refreshing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let hop = std::sync::Arc::clone(&per);
    assert_eq!(
        answers_within(std::time::Duration::from_secs(5), move || hop.handle_now()),
        Some(Some(first)),
        "a hop answers while a refresh holds the binding's lock"
    );
    drop(held);

    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(resolved(), built + 1, "a refresh resolves, once");
    let _ = std::fs::remove_file(&path);
}

struct ParkedOpens {
    inner: std::sync::Arc<CountingOpens>,
    parked: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    entered: std::sync::mpsc::SyncSender<()>,
}

impl busbar_contract::auth_calls::OutboundAuth for ParkedOpens {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let release = self
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(release) = release {
            let _ = self.entered.send(());
            let _ = release.recv();
        }
        busbar_contract::auth_calls::OutboundAuth::open_outbound(
            &*self.inner,
            style,
            credential,
            settings,
        )
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        busbar_contract::auth_calls::OutboundAuth::fields_now(&*self.inner, handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        busbar_contract::auth_calls::OutboundAuth::fields(
            &*self.inner,
            handle,
            request,
            deadline_ns,
        )
    }
}

#[test]
fn an_open_runs_under_no_lock_a_hop_waits_on() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("parked-open", "token-before");
    let counting = bearer_auth();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let parked = std::sync::Arc::new(ParkedOpens {
        inner: std::sync::Arc::clone(&counting),
        parked: std::sync::Mutex::new(None),
        entered: entered_tx,
    });
    let mut per = per_hop(&path, std::sync::Arc::clone(&counting));
    per.auth = std::sync::Arc::clone(&parked)
        as std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>;
    let per = std::sync::Arc::new(per);
    let first = per.handle_now().expect("it resolved at build");

    rotate(&path, "token-after");
    *parked
        .parked
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release_rx);
    let refreshing = std::sync::Arc::clone(&per);
    let refresh = std::thread::spawn(move || {
        refreshing.refresh(&busbar_contract::config_time::ConfigScope::config_time())
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the refresh reached the auth plugin's open");

    let hop = std::sync::Arc::clone(&per);
    assert_eq!(
        answers_within(std::time::Duration::from_secs(5), move || hop.handle_now()),
        Some(Some(first)),
        "a hop answers, with the last refresh's handle, while the open is parked"
    );

    release_tx.send(()).expect("release the open");
    refresh.join().expect("the refresh");
    let next = per.handle_now().expect("the rotation bound");
    assert_ne!(
        next, first,
        "the hop after the open presents the new handle"
    );
    assert_eq!(
        presents(&*counting, next),
        vec![(
            "authorization".to_string(),
            "Bearer token-after".to_string()
        )]
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_per_hop_binding_never_renders_the_secret_in_a_debug_line() {
    let path = own_secret("debug", "SUPER-SECRET-VALUE");
    let per = per_hop(&path, bearer_auth());
    let rendered = format!("{per:?}");
    assert!(
        !rendered.contains("SUPER-SECRET-VALUE"),
        "the binding rendered its secret: {rendered}"
    );
    let digest = busbar_contract::abi::sdk::digest::sha256(b"SUPER-SECRET-VALUE");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&hex) && !rendered.contains(&format!("{:?}", digest[0..4].to_vec())),
        "the binding rendered its digest: {rendered}"
    );
    assert!(rendered.contains("<redacted"), "{rendered}");
    assert!(
        !rendered.contains(&path.display().to_string()),
        "nor where the secret lives: {rendered}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_registration_member_rides_every_member_target_need() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url", "settings.*.alt"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\", alt: \"http://127.0.0.1:8/x\"}\n\
         one: {url: \"http://127.0.0.1:9/rpc\"}\n",
        &[],
    )
    .expect("the registrations resolve");
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 1, "the first member-target need is its own");
    let rides: Vec<u32> = fs.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2, 3],
        "every other member-target need rides beside it"
    );
    assert_eq!(fs.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(
        fs.ride(3).map(|r| r.base_url),
        Some("http://127.0.0.1:7"),
        "the same target, the same origin"
    );
    assert_eq!(
        fs.ride(4).map(|r| r.base_url),
        Some("http://127.0.0.1:8"),
        "a need whose target is another origin dials that origin"
    );
    assert!(fs.ride(1).is_none(), "the open need is no member's");
    let one = &routes["one"];
    let rides: Vec<u32> = one.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "a registration naming no `alt` does not ride its need"
    );
}

/// A connection table that records what the composition seals on it: each need's anchors and
/// private reach, and each auth binding, by need, member and target. It opens nothing.
#[derive(Default)]
struct Sealing {
    anchored: std::sync::Mutex<Vec<(u32, String)>>,
    reached: std::sync::Mutex<Vec<(u32, String, String)>>,
    bound: std::sync::Mutex<Vec<(u32, String, String)>>,
}

impl busbar_contract::conn::Conns for Sealing {
    fn open(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Refused)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
}

impl busbar_contract::conn::PollConns for Sealing {
    fn poll_read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        std::task::Poll::Ready(Err(busbar_contract::conn::ConnError::Closed))
    }
    fn anchor(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        _: &str,
        target: &str,
        _: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.anchored
            .lock()
            .unwrap()
            .push((need.0, target.to_string()));
        Ok(())
    }
    fn seal_reach(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        if reach {
            self.reached
                .lock()
                .unwrap()
                .push((need.0, member.to_string(), target.to_string()));
        }
        Ok(())
    }
}

impl busbar_contract::conn::DeclaredConns for Sealing {
    fn declare(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Ok(())
    }
    fn declared(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        Some(Ok(()))
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
    fn bind_auth(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        origin: &str,
        _: busbar_contract::conn::ConnAuth,
    ) {
        self.bound
            .lock()
            .unwrap()
            .push((need.0, member.to_string(), origin.to_string()));
    }
}

struct Bound;

struct Never;

impl std::future::Future for Never {
    type Output = busbar_contract::auth_calls::Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl busbar_contract::auth_calls::Fielding for Never {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
}

impl busbar_contract::auth_calls::OutboundAuth for Bound {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        Box::new(Never)
    }
}

#[test]
fn a_registration_members_anchors_reach_and_binding_hold_on_every_need_it_rides() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_kernel::plane_driver::{AuthBinding, MemberRoute, ResponseKeep};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url"],
        ..Default::default()
    };
    let route = MemberRoute {
        need: busbar_contract::conn::NeedId(1),
        base_url: "https://far.example".to_string(),
        auth: Some(AuthBinding {
            auth: std::sync::Arc::new(Bound),
            handle: 1,
            style_flags: 0,
            points: busbar_contract::abi::auth::AuthPoints(0),
            passthrough: false,
            per_request: None,
        }),
        provider: "fs".to_string(),
        keep: ResponseKeep::default(),
        rides: vec![(busbar_contract::conn::NeedId(2), ResponseKeep::default())],
        anchors: busbar_contract::transport::trust::Anchors {
            private_reach: true,
            ..Default::default()
        },
        spelled: Vec::new(),
    };
    let routes = std::collections::BTreeMap::from([("fs".to_string(), route)]);
    let table = std::sync::Arc::new(Sealing::default());
    let instance = busbar_contract::conn::InstanceId(7);
    super::bind_member_fetches(
        &served,
        &routes,
        instance,
        &*table,
        &std::sync::Arc::new(busbar_kernel::host_units::UnitRecords::default()),
    );
    assert_eq!(
        *table.bound.lock().unwrap(),
        [
            (1, "fs".to_string(), "https://far.example".to_string()),
            (2, "fs".to_string(), "https://far.example".to_string())
        ],
        "the door's own requests on either need carry the member's binding"
    );
    let section: serde_yaml::Value =
        serde_yaml::from_str("fs: {url: \"https://far.example/rpc\"}").expect("yaml");
    let facts = super::door_facts("p", &[], &[], &[], "audit", Vec::new());
    let node = std::sync::Arc::new(crate::root::plane_node::Node::new());
    let post = std::sync::Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    super::compose_egress(
        &facts,
        &DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("the pools"),
        instance,
        std::sync::Arc::clone(&table) as std::sync::Arc<dyn busbar_contract::conn::PollConns>,
        &routes,
        post as std::sync::Arc<dyn busbar_kernel_egress::ports::Journal>,
        std::sync::Arc::new(crate::root::egress_ports::NodeClock::new()),
        1,
    )
    .expect("the egress composes");
    assert_eq!(
        *table.anchored.lock().unwrap(),
        [
            (1, "https://far.example".to_string()),
            (2, "https://far.example".to_string())
        ],
        "the anchors are sealed on both needs"
    );
    assert_eq!(
        *table.reached.lock().unwrap(),
        [
            (1, "fs".to_string(), "https://far.example".to_string()),
            (2, "fs".to_string(), "https://far.example".to_string())
        ],
        "the registration's private reach is sealed on both needs"
    );
}

#[test]
fn the_configured_error_body_cap_reaches_both_egress_constructors() {
    use crate::root::model_egress::{LiveApp, ModelPools, ModelServing};
    use busbar_kernel::config::limits::{BuildScope, LimitsResolved};
    use std::sync::Arc;

    let facts = super::door_facts("error-cap", &[], &[], &[], "audit", Vec::new());
    let section = serde_yaml::from_str("{}").expect("empty section");
    let pools = DoorPools::of(&section, TOOL_CALL_SECTION_KEY).expect("empty pools");
    let serving = ModelServing {
        pools: ModelPools::default(),
        lanes: Default::default(),
        app: LiveApp::fixed(std::sync::Arc::new({
            #[cfg(distribution_root)]
            crate::dist_root_install::install();
            let library_path = crate::root::test_plugins::application_store_library();
            let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual store statement reads")
                .expect("the actual store exports its statement");
            let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual store statement is valid")
                .name;
            let mut manifest = crate::root::test_plugins::manifest(
                "store",
                &module,
                crate::root::test_plugins::FIXTURE_PUBLISHER,
            );
            manifest.statement = Some(hex::encode(statement));
            let release = crate::root::test_plugins::key(0x5a);
            let directory = crate::root::test_plugins::scratch(&format!(
                "door-steps-{}",
                busbar_kernel::door::op_id().counter()
            ));
            let library = std::fs::read(library_path).expect("the actual store library reads");
            let archive = crate::root::test_plugins::signed(&release, manifest, &library);
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual store");
            crate::root::linked::register_stores(&crate::LINKED);
            busbar_kernel::preflight::install_linked_auth(
                crate::LINKED.auths,
                crate::root::auth_bindings::operator_words(),
            );
            let settings = crate::root::test_plugins::application_store_settings(&directory);
            let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                "store": {"module": module, "settings": settings},
            }))
            .expect("the door deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the door deployment resolves");
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let loaded = crate::root::real_store::store();
            let opened = busbar_contract::store_calls::OpenedStore {
                records: loaded.clone(),
                calls: Some(loaded),
            };
            let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
                cfg,
                crate::root::test_plugins::trusted_config_with_key(
                    &directory,
                    &crate::root::test_plugins::key(0x5a),
                ),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
                Some(opened),
                false,
            )
            .expect("the actual root builds the door generation");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, &module)
                .expect("the configured Store boots its rate history before activation");
            limits.keep().expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            app
        })),
    };
    let build = || {
        let caller = busbar_contract::conn::InstanceId(7);
        let conns: Arc<dyn busbar_contract::conn::PollConns> = Arc::new(Sealing::default());
        let routes = Default::default();
        let journal: Arc<dyn busbar_kernel_egress::ports::Journal> =
            Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::new(
                crate::root::plane_node::Node::new(),
            )));
        let clock: Arc<dyn busbar_kernel_egress::ports::Clock> =
            Arc::new(crate::root::egress_ports::NodeClock::new());
        let ordinary = super::compose_egress(
            &facts,
            &pools,
            caller,
            Arc::clone(&conns),
            &routes,
            Arc::clone(&journal),
            Arc::clone(&clock),
            1,
        )
        .expect("ordinary egress");
        let (models, _) = crate::root::model_egress::compose(
            &facts, &serving, caller, conns, &routes, journal, clock, 1,
        )
        .expect("model egress");
        (ordinary, models)
    };

    let mut limits = LimitsResolved {
        upstream_error_body_max_bytes: 17,
        ..LimitsResolved::default()
    };
    let _outer = BuildScope::enter(&limits);
    let first = build();
    {
        limits.upstream_error_body_max_bytes = 29;
        let _candidate = BuildScope::enter(&limits);
        let next = build();
        assert_eq!((next.0.error_body_max, next.1.error_body_max), (29, 29));
    }
    let restored = build();
    assert_eq!(
        (restored.0.error_body_max, restored.1.error_body_max),
        (17, 17)
    );
    assert_eq!((first.0.error_body_max, first.1.error_body_max), (17, 17));
}

#[test]
fn a_model_shaped_section_takes_the_stated_labels_the_previous_release_counted() {
    use busbar_kernel_egress::ports::StatedLabels;
    let p = pools(
        "models:\n  m-direct: {}\n  m-first: {}\n  m-second: {}\npools:\n  cap-fo:\n    members: [m-first, m-second]\n",
    );
    let bound = super::label_bound("p", &p, &[]);
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };

    let direct = super::egress_pool(
        "p",
        &routed(&p, ROUTE_DIRECT, Some("m-direct")).expect("a direct route"),
    );
    let own = super::plane_lane("p", "m-direct");
    assert_eq!(
        bound.labels(
            &direct,
            (&direct, &own),
            Some(&stated("m-direct", "m-direct"))
        ),
        ("m-direct".to_string(), "m-direct".to_string(), false),
        "the golden direct-route request cell"
    );

    let pooled = super::egress_pool(
        "p",
        &routed(&p, ROUTE_POOL, Some("cap-fo")).expect("a pool route"),
    );
    for member in ["m-first", "m-second"] {
        assert_eq!(
            bound.labels(
                &pooled,
                (&pooled, &super::plane_lane("p", member)),
                Some(&stated("cap-fo", member))
            ),
            ("cap-fo".to_string(), member.to_string(), false),
            "route.529__failover__primary: {member}"
        );
    }

    assert_eq!(
        bound.labels(&direct, (&direct, &own), None),
        (direct.clone(), own.clone(), false)
    );

    assert_eq!(
        bound.labels(&direct, (&direct, &own), Some(&stated("cap-fo", "m-first"))),
        (direct.clone(), own.clone(), true),
        "a direct route reaches no pool and no other entry"
    );
}

#[test]
fn a_pools_reach_follows_its_fallback_and_the_declared_words() {
    use busbar_kernel_egress::ports::StatedLabels;
    let p = pools(
        "a: {}\nb: {}\npools:\n  first:\n    members: [a]\n    on_exhausted: { fallback_pool: spill }\n  spill:\n    members: [b]\n",
    );
    let bound = super::label_bound("p", &p, &["word".to_string()]);
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };
    assert_eq!(
        bound.labels("first", ("first", "own"), Some(&stated("spill", "b"))),
        ("spill".to_string(), "b".to_string(), false)
    );
    assert_eq!(
        bound.labels("first", ("first", "own"), Some(&stated("a", "word"))),
        ("a".to_string(), "word".to_string(), false)
    );
    assert_eq!(
        bound.labels("spill", ("spill", "own"), Some(&stated("first", "a"))),
        ("spill".to_string(), "own".to_string(), true),
        "a fallback pool does not reach back into the pool that spilled into it"
    );
}

#[test]
fn a_scope_local_unit_resolves_the_one_entry_the_grant_reaches_and_routes_nowhere() {
    use busbar_contract::abi::plane::{ROUTE_SCOPE, ROUTE_SCOPE_LOCAL};
    use busbar_contract::caps::{Admittance, Dial, OpClassId, PrincipalId, ReasonCode};
    use busbar_contract::records::{ScopeRef, VirtualKey};
    use busbar_kernel::plane_driver::DriverSteps;
    use busbar_kernel::teller::UnitCtx;
    let facts = super::door_facts("p", &["seat"], &[], &[], "a", Vec::new());
    let p = pools("a: {}\nb: {}\npools:\n  both:\n    members: [a, b]\n    member_granted: true");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let principal = PrincipalId::new("vk_seat");
    let steps = |reach: &[&str]| {
        super::DoorSteps::new(
            &facts,
            &p,
            std::sync::Arc::new(|name: &str| match name {
                "p\u{1f}a" => Some(busbar_contract::LaneId::new("p\u{1f}a")),
                "p\u{1f}b" => Some(busbar_contract::LaneId::new("p\u{1f}b")),
                _ => None,
            }),
            std::sync::Arc::new({
                #[cfg(distribution_root)]
                crate::dist_root_install::install();
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual store statement reads")
                    .expect("the actual store exports its statement");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual store statement is valid")
                    .name;
                let mut manifest = crate::root::test_plugins::manifest(
                    "store",
                    &module,
                    crate::root::test_plugins::FIXTURE_PUBLISHER,
                );
                manifest.statement = Some(hex::encode(statement));
                let release = crate::root::test_plugins::key(0x5a);
                let directory = crate::root::test_plugins::scratch(&format!(
                    "door-steps-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library = std::fs::read(library_path).expect("the actual store library reads");
                let archive = crate::root::test_plugins::signed(&release, manifest, &library);
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual store");
                crate::root::linked::register_stores(&crate::LINKED);
                busbar_kernel::preflight::install_linked_auth(
                    crate::LINKED.auths,
                    crate::root::auth_bindings::operator_words(),
                );
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                    "store": {"module": module, "settings": settings},
                }))
                .expect("the door deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the door deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let loaded = crate::root::real_store::store();
                let opened = busbar_contract::store_calls::OpenedStore {
                    records: loaded.clone(),
                    calls: Some(loaded),
                };
                let (app, rotate, limits) =
                    busbar_kernel::appbuild::build_app_from_config_with_store(
                        cfg,
                        crate::root::test_plugins::trusted_config_with_key(
                            &directory,
                            &crate::root::test_plugins::key(0x5a),
                        ),
                        None,
                        Default::default(),
                        Default::default(),
                        (None, None),
                        None,
                        &rules,
                        Some(opened),
                        false,
                    )
                    .expect("the actual root builds the door generation");
                limits.stage_boot();
                let _book = crate::root::boot::book(&app, &module)
                    .expect("the configured Store binds the boot rate authority");
                limits.keep().expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                app
            }),
            None,
            super::DoorCaller {
                principal: principal.clone(),
                key: Some(std::sync::Arc::new(VirtualKey {
                    id: "vk_seat".into(),
                    allowed_scopes: Some(
                        reach
                            .iter()
                            .map(|n| ScopeRef {
                                kind: "seat".to_string(),
                                value: (*n).to_string(),
                            })
                            .collect(),
                    ),
                    ..VirtualKey::default()
                })),
                open: false,
                arrived: 0,
                records: None,
                depth: 0,
                credential: None,
                ticket: None,
            },
        )
    };
    let verified = |s: &super::DoorSteps<'_>, class: u8| {
        s.decoded(&ctx, OpClassId::new("op"), class, None);
        s.verify(
            &busbar_contract::caps::Grant::<Dial>::mint(&busbar_kernel::seal::acquire()),
            &ctx,
            &principal,
        )
        .expect("verify proceeds")
    };

    let one = steps(&["a"]);
    let sealed = verified(&one, ROUTE_SCOPE_LOCAL);
    assert_eq!(
        sealed.len(),
        1,
        "the granted local entry is sealed for audit"
    );
    assert_eq!(sealed[0].lane().as_str(), "p\u{1f}a");
    assert_eq!(one.resolved(&ctx), Some(b"a".to_vec()), "the one entry");
    assert_eq!(
        one.scope_entry(),
        Some(b"a".to_vec()),
        "its gates bind the one entry"
    );
    assert_eq!(one.routed(), None, "routed nowhere: no pool, no walk");

    let relayed = steps(&["a"]);
    let _ = verified(&relayed, ROUTE_SCOPE);
    assert_eq!(relayed.resolved(&ctx), None);
    assert_eq!(
        relayed.scope_entry(),
        Some(b"a".to_vec()),
        "a relayed scope unit's gates bind the one entry its scope resolved to"
    );
    assert_eq!(
        relayed.routed().map(|(label, _)| label),
        Some("both".to_string()),
        "a relayed unit is widened to its entry's pool"
    );

    for reach in [&[][..], &["a", "b"][..]] {
        let s = steps(reach);
        let sealed = verified(&s, ROUTE_SCOPE_LOCAL);
        assert!(
            sealed.is_empty(),
            "{reach:?}: no unique granted entry is sealed"
        );
        assert_eq!(
            s.routed(),
            None,
            "{reach:?}: local units never acquire a walk"
        );
        assert_eq!(s.resolved(&ctx), None, "{reach:?}");
        assert_eq!(s.scope_entry(), None, "{reach:?}");
        let refused = s.admit(
            &busbar_contract::caps::Grant::<Admittance>::mint(&busbar_kernel::seal::acquire()),
            &ctx,
            &principal,
            &[],
            &busbar_kernel_seams::slice::GroupLeaseSlip::default(),
        );
        let Err(refused) = refused else {
            panic!("{reach:?}: refused at admission");
        };
        assert_eq!(refused.reason(), ReasonCode::NoDestination, "{reach:?}");
        assert_eq!(
            s.refusal_words(ReasonCode::NoDestination),
            Some(reach.join(", ").into_bytes()),
            "the reachable entries named in its words: {reach:?}"
        );
    }
}

#[test]
fn a_models_protocol_override_is_handed_to_the_plane() {
    let def: busbar_kernel::config::ProviderDef =
        serde_yaml::from_str("protocol: dialect-a\nbase_url: http://127.0.0.1:9\n").expect("a def");
    let defs = std::collections::HashMap::from([("p".to_string(), def)]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nproviders:\n  p:\n    api_key: { env: BUSBAR_TEST_KEY }\n\
         models:\n  over:\n    provider: p\n    protocol: dialect-b\n  plain:\n    provider: p\n",
    )
    .expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let sections = super::kernel_sections(&cfg);
    let models = sections
        .get(busbar_contract::section::RESERVED_MODELS_KEY)
        .expect("the models section");
    assert_eq!(
        models["over"]["protocol"].as_str(),
        Some("dialect-b"),
        "{models:?}"
    );
    assert!(
        models["plain"].get("protocol").is_none(),
        "a model naming no protocol states none: {models:?}"
    );
}

fn a_ca_pem() -> String {
    let kp = rcgen::KeyPair::generate().expect("a key");
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&kp).expect("the CA").pem()
}

#[test]
fn an_owned_anchor_the_boot_would_refuse_is_refused_by_the_same_rule() {
    let paths = ["owned.agent_push.ca", "settings.*.client_identity"];
    let with = |ca: Option<&str>| {
        let mut sections: std::collections::BTreeMap<&'static str, serde_yaml::Value> =
            std::collections::BTreeMap::new();
        if let Some(ca) = ca {
            sections.insert(
                "agent_push",
                serde_yaml::from_str(&format!("ca: {}", serde_json::to_string(ca).unwrap()))
                    .expect("yaml"),
            );
        }
        super::owned_anchors_refusal(&paths, &sections)
    };
    for bad in [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
    ] {
        let err = with(Some(bad)).expect_err("refused");
        assert!(
            err.contains("`agent_push.ca` is not a usable trust anchor"),
            "{err}"
        );
    }
    let ca = a_ca_pem();
    assert_eq!(with(Some(&ca)), Ok(()), "a usable CA");
    assert_eq!(
        with(None),
        Ok(()),
        "an owned section the operator did not write"
    );
    assert_eq!(with(Some("")), Ok(()), "an empty anchor is not written");
    assert_eq!(
        super::owned_anchor_refusal("agent_push.ca", &ca),
        Ok(()),
        "the rule itself takes the CA"
    );
}

#[test]
fn an_unopened_door_plane_is_awaiting_restart_once_a_configuration_writes_its_section() {
    use busbar_kernel::appbuild::RootRules as _;
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nmodels: {}\nproviders: {}\n",
    )
    .expect("parses");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("resolves");
    let rules = super::Rules::default();
    assert!(
        rules.planes_awaiting_restart(&cfg).is_empty(),
        "nothing held, nothing pending"
    );
    rules.hold_unopened(["zz-unopened-red", "aa-unopened-red"]);
    assert!(
        rules.planes_awaiting_restart(&cfg).is_empty(),
        "a configuration that writes neither section reports neither"
    );
    cfg.plane_sections.insert("zz-unopened-red");
    cfg.plane_sections.insert("opened-at-boot-red");
    assert_eq!(
        rules.planes_awaiting_restart(&cfg),
        vec!["zz-unopened-red"],
        "the written section of a plane the boot left unopened, and never one it opened"
    );
    cfg.plane_sections.insert("aa-unopened-red");
    assert_eq!(
        rules.planes_awaiting_restart(&cfg),
        vec!["aa-unopened-red", "zz-unopened-red"],
        "sorted"
    );
    assert!(
        rules.check(&cfg).is_ok(),
        "awaiting restart is not a refusal: the configuration is accepted and stored"
    );
}

#[test]
fn a_first_section_of_an_unloaded_plane_is_refused_naming_the_section_and_the_plane() {
    use busbar_kernel::appbuild::RootRules as _;
    let door = crate::root::loader::boot::Candidate {
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
        name: "zz-unloaded-red".to_string(),
        version: "1.0.0".to_string(),
        aliases: Vec::new(),
        sugar: Vec::new(),
        verbs: vec!["zz_tools_red".to_string()],
        selecting: vec!["zz_selects_red".to_string()],
        schemes: Vec::new(),
        needs: Vec::new(),
        stated: Vec::new(),
        origin: crate::root::loader::boot::Origin::Dropped {
            file: "zz-unloaded-red.tar.gz".to_string(),
            bytes: std::sync::Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
    };
    let rules = super::Rules::default();
    assert_eq!(
        rules.unloaded_plane_refusal(&["providers", "zz_tools_red"]),
        None,
        "nothing held, nothing refused"
    );
    rules.hold_unloaded(vec![door]);
    assert_eq!(
        rules.unloaded_plane_refusal(&["providers", "models", "store"]),
        None,
        "a document that uses no unloaded plane is not refused"
    );
    assert_eq!(
        rules
            .unloaded_plane_refusal(&["providers", "zz_tools_red"])
            .as_deref(),
        Some(
            "`zz_tools_red:` is the section of the `zz-unloaded-red` plane, which this process did \
             not load because its configuration did not use it at start; a first `zz_tools_red:` \
             cannot take effect on a running process, so the change was refused and nothing was \
             changed: write it in the config file and restart."
        ),
        "the pinned sentence, naming the section and the plane"
    );
    assert!(
        rules
            .unloaded_plane_refusal(&["zz_selects_red"])
            .is_some_and(
                |r| r.starts_with("`zz_selects_red:` is the section of the `zz-unloaded-red`")
            ),
        "a section that selects the plane uses it as its verb does"
    );
}

#[test]
fn the_doors_admission_check_reads_the_arrival_window_and_not_the_clock() {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use busbar_kernel::governance::SECS_PER_DAY;
    let governance_store = crate::root::real_store::store();
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            governance_store.clone(),
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("the real store opens governance"),
    );
    assert!(
        gov.attach_store_calls(governance_store),
        "attach the actual store calls"
    );
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: 1,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(None, 1, &groups);
    let (key, _secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                group: Some("team".to_string()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("a key");
    let mut app = {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-steps-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual store");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let loaded = crate::root::real_store::store();
        let opened = busbar_contract::store_calls::OpenedStore {
            records: loaded.clone(),
            calls: Some(loaded),
        };
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            crate::root::test_plugins::trusted_config_with_key(
                &directory,
                &crate::root::test_plugins::key(0x5a),
            ),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            false,
        )
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the configured Store boots its rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app
    };
    app.auth = std::sync::Arc::new(
        busbar_kernel::auth::AuthMiddleware::new(
            &busbar_kernel::config::AuthCfg {
                chain: vec![busbar_kernel::config::AuthChainEntry::bare(
                    busbar_kernel::config::KEYS_MODULE,
                )],
                ..busbar_kernel::config::AuthCfg::default_none()
            },
            &app.hook_env.registry,
            &app.secret_resolver,
        )
        .expect("the actual root constructs the keys middleware"),
    );
    gov.hydrate_budgets(&cost, 0)
        .expect("the real governance hydrates its budget");
    app.governance = Some(gov);
    app.groups_registry = groups;
    app.cost = std::sync::Arc::new(cost);
    let app = std::sync::Arc::new(app);
    let key = std::sync::Arc::new(key);
    let gov = std::sync::Arc::clone(app.governance.as_ref().expect("a governed generation"));

    let past_day: u64 = 1_700_000_000;
    assert_ne!(
        past_day / SECS_PER_DAY,
        busbar_kernel::store::now() / SECS_PER_DAY,
        "precondition: the arrival day is not today"
    );
    gov.try_admit(&app.cost, &key, "", past_day)
        .expect("the first request fits the cap exactly");
    assert_eq!(
        gov.derived_bucket_usage(&app.cost, "group:team@day", "day", true, past_day)
            .expect("usage read")
            .spend_cents,
        1,
        "precondition: the arrival day's window is at its cap"
    );

    let pools = pools(DOWNGRADE_SECTION);
    let refused = charge_once_at(&app, &key, &pools, "frontier", 1, past_day);
    let reason = refused
        .admitted
        .map_err(|(reason, _)| reason)
        .expect_err("the unit is refused against the window it arrived in, where the spend lives");
    assert_eq!(reason, busbar_contract::caps::ReasonCode::OverBudget);
    assert_eq!(
        busbar_kernel::plane_driver::refusal_status(reason),
        429,
        "an over-budget refusal answers 429"
    );
    let admitted = charge_once_at(
        &app,
        &key,
        &pools,
        "frontier",
        2,
        busbar_kernel::store::now(),
    );
    assert_eq!(
        admitted.admitted,
        Ok(()),
        "today's window is empty, so a unit arriving now is admitted"
    );
}

#[cfg(not(target_env = "msvc"))]
#[test]
fn asking_whether_a_name_is_configured_allocates_nothing() {
    use busbar_kernel::door::PoolView as _;
    use tikv_jemalloc_ctl::thread as jethread;
    let mut yaml = String::from("m: {}\npools:\n");
    for i in 0..8 {
        yaml.push_str(&format!("  p{i}:\n    members: [m]\n"));
    }
    let p = pools(&yaml);
    let app = std::sync::Arc::new({
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "store",
            &module,
            crate::root::test_plugins::FIXTURE_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-steps-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual store");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let loaded = crate::root::real_store::store();
        let opened = busbar_contract::store_calls::OpenedStore {
            records: loaded.clone(),
            calls: Some(loaded),
        };
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            crate::root::test_plugins::trusted_config_with_key(
                &directory,
                &crate::root::test_plugins::key(0x5a),
            ),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            false,
        )
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, &module)
            .expect("the configured Store boots its rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app
    });
    let view = super::DoorPoolView {
        pools: &p,
        key: None,
        app: &app,
    };
    let allocated = || {
        jethread::allocatedp::read()
            .map(|m| m.get())
            .expect("jemalloc's per-thread counter reads")
    };

    let _ = allocated();
    let before = allocated();
    let pool = view.is_configured(std::hint::black_box("p3"));
    let entry = view.is_configured(std::hint::black_box("m"));
    let miss = view.is_configured(std::hint::black_box("nothing-by-that-name"));
    let after = allocated();
    assert!(pool, "p3 is a configured pool");
    assert!(entry, "m is a configured entry");
    assert!(!miss, "nothing by that name is configured");
    assert_eq!(
        after - before,
        0,
        "a membership probe on the request path allocates nothing"
    );
}

const PEER_KEY_PIN: &[busbar_contract::plane::TrustKeyDecl] =
    &[busbar_contract::plane::TrustKeyDecl {
        key: "pin",
        role: busbar_contract::plane::TrustRole::Pin,
        fingerprint: false,
        default: None,
        mechanisms: &[busbar_contract::plane::PinMechanismDecl {
            token: "peer",
            root: true,
            peer_key: true,
        }],
    }];

fn peer_pinned(key: &str) -> Result<busbar_contract::transport::trust::Anchors, String> {
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        section: "upstreams",
        trust_keys: PEER_KEY_PIN.to_vec(),
        ..Default::default()
    };
    let registration: serde_yaml::Value = serde_yaml::from_str(&format!(
        "url: 'https://far.example/x'\npin: {{mechanism: peer, key: '{key}'}}"
    ))
    .expect("yaml");
    super::registration_anchors(
        "fs",
        &registration,
        busbar_contract::conn::NeedId(0),
        &served,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
}

#[test]
fn red_a_peer_key_pin_naming_no_digest_refuses_the_load_naming_the_field_and_its_form() {
    let canonical = busbar_contract::transport::trust::key_pin(b"a subject public key info");
    let plain = canonical
        .strip_prefix("sha256/")
        .expect("tagged")
        .to_owned();
    for written in [&canonical, &plain] {
        let anchors = peer_pinned(written).expect("a pin of one digest reads");
        assert_eq!(
            anchors.key_pin.as_deref(),
            Some(canonical.as_str()),
            "{written}"
        );
    }
    for bad in ["sha256/BASE=", "sha1/AAAA", "not a pin"] {
        let refused = peer_pinned(bad).expect_err("refused");
        assert_eq!(
            refused,
            "`upstreams.fs`: `pin.key:` is not a key pin. Write `sha256/<base64>`: the standard, \
             padded base64 of the 32-byte SHA-256 digest of the far end's certificate \
             SubjectPublicKeyInfo (the plain `<base64>` of the same digest is also accepted).",
            "{bad}"
        );
        assert!(!refused.contains(bad), "the value is not echoed: {refused}");
    }
}

#[test]
fn serving_a_style_binds_only_the_linked_row_that_states_it() {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let linked = crate::LINKED.auths;
    assert!(
        linked.len() > 1,
        "the default build links more than one auth row: {}",
        linked.len()
    );
    let auths = super::OutboundAuths::new(
        dispatcher,
        linked,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    );
    let served = auths
        .serving("bearer", &serde_json::json!({}))
        .expect("the serving row opens");
    assert!(served.is_some(), "a linked row states `bearer`");
    let bound = auths
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        bound.len(),
        1,
        "only the row serving the style is bound, once: {bound:?}"
    );
}

#[test]
fn a_dropped_rows_styles_are_read_from_its_signed_manifest_with_no_library_load() {
    use crate::root::loader::dispatch::kinds::auth::stated_facts;
    use crate::root::loader::sign::{
        sign, Manifest, SigningKey, TrustPolicy, FIRST_PARTY_PUBLISHER,
    };

    let (style, door) = crate::LINKED
        .auths
        .iter()
        .find_map(|&(_, _, door)| {
            let facts = stated_facts(door).ok()?;
            facts.styles.first().map(|s| (s.name.clone(), door))
        })
        .expect("the default build links an auth row stating an outbound style");
    let stated = crate::root::loader::dispatch::rendering_of(door).expect("the door states itself");
    let key = SigningKey::from_bytes(&[0x4d; 32]);
    let lib: &[u8] = b"not a library: a style read never opens it";
    let m = sign(
        &key,
        Manifest {
            name: "busbar-auth-dropped-styles".into(),
            alias: "dropped-styles".into(),
            kind: "auth".into(),
            version: "1.0.0".into(),
            publisher: FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::root::loader::supported_abi("auth")[0],
            statement: Some(hex::encode(stated)),
            ..Default::default()
        },
        lib,
    );
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-dropped-styles-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("a scratch plugins directory");
    std::fs::write(
        dir.join("dropped-styles.tar.gz"),
        crate::root::loader::tarball::package(&m, "lib.so", lib).expect("it packs"),
    )
    .expect("the tarball is written");
    let policy = TrustPolicy {
        first_party_key: Some(key.verifying_key()),
        ..Default::default()
    };
    let registry = crate::root::loader::scan_and_validate(&dir, &policy).expect("the row scans");
    let _ = std::fs::remove_dir_all(&dir);
    let registry: &'static crate::root::loader::PluginRegistry = Box::leak(Box::new(registry));
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let auths = super::OutboundAuths::new(
        dispatcher,
        &[],
        Some(registry),
        crate::root::loader::dispatch::ConnTable::NoNeeds,
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    );
    let stating: Vec<String> = auths.stating(&style).map(|r| r.name.clone()).collect();
    assert_eq!(
        stating,
        vec!["busbar-auth-dropped-styles".to_string()],
        "the dropped-in row states `{style}` by its signed manifest"
    );
    let bound = auths
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(bound, Vec::<String>::new(), "a style read binds no row");
}

#[test]
fn a_credential_endpoint_is_read_by_the_styles_bit_never_its_name() {
    let account = |uri: &str| {
        format!(r#"{{"client_email":"sa@example.com","private_key":"k","token_uri":"{uri}"}}"#)
    };
    let route = provider("p", Some("jwt-bearer"));
    let good = account("https://oauth2.example.com/token");
    let unread = super::sealed_params("p", "jwt-bearer", false, &route, good.as_bytes())
        .expect("a style stating no bit is never read");
    assert_eq!(unread.token_uri, None, "named jwt-bearer, stating no bit");
    let read = super::sealed_params("p", "x-any-assertion", true, &route, good.as_bytes())
        .expect("a judged endpoint");
    assert_eq!(
        read.token_uri.as_deref(),
        Some("https://oauth2.example.com/token"),
        "any word stating the bit has its credential's endpoint read"
    );
    let plaintext = account("http://oauth2.example.com/token");
    let refused = super::sealed_params("p", "jwt-bearer", true, &route, plaintext.as_bytes())
        .expect_err("a public plaintext token_uri is refused");
    assert!(
        refused.starts_with(
            "provider 'p' (jwt-bearer auth): service-account token_uri must use https for a public host"
        ),
        "1.5.5's words over the style's own word: {refused}"
    );
}
