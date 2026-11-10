// SPDX-License-Identifier: Apache-2.0

fn source_path(value: impl AsRef<str>) -> busbar_contract::secret_ref::SecretRef {
    use busbar_contract::secret::SecretAxis as _;
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    crate::root::linked::secret_rows()
        .sugars()
        .reference_for_role(
            busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
            value.as_ref(),
        )
        .expect("the admitted source declares the fixture's path role")
}
pub(crate) fn isolated_fixture_cases(test: &str, cases: &[&str]) -> Option<String> {
    if std::env::var("BUSBAR_DOOR_STEPS_ISOLATED_TEST").as_deref() == Ok(test) {
        let case = std::env::var("BUSBAR_DOOR_STEPS_ISOLATED_CASE").unwrap();
        assert!(cases.contains(&case.as_str()));
        return Some(case);
    }
    let exact = test.split_once("::").unwrap().1;
    for case in cases {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--nocapture"])
            .env("BUSBAR_DOOR_STEPS_ISOLATED_TEST", test)
            .env("BUSBAR_DOOR_STEPS_ISOLATED_CASE", case)
            .output()
            .expect("run this exact independent native fixture case");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{case}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(&format!("DOOR-STEPS-CASE-DONE {test} {case}")),
            "every subcase must complete its assertions: {stdout}"
        );
    }
    None
}
pub(crate) fn isolated_fixture_done(test: &str, case: &str) {
    println!("DOOR-STEPS-CASE-DONE {test} {case}");
}

pub(crate) async fn boot_fixture_prices(app: &busbar_kernel::state::App) {
    let store = app
        .governance
        .as_ref()
        .expect("native fixture governance")
        .core_store_handle()
        .expect("native fixture authority");
    if let Some(previous) = crate::root::kernel::ROOT_CARD.card_store() {
        assert!(previous.is_bound_to(&store), "independent native deployments require separate fixture processes; never reuse another Store's price holder");
        return;
    }
    crate::root::kernel::ROOT_CARD
        .keep_in_store(store, busbar_kernel::door::op_id().counter())
        .expect("bind this deployment's actual native price Store");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("confirm native opening prices before committing limits");
}

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
        let opened = crate::root::real_store::core().await;
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
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
    let generation_store = crate::root::real_store::core().await;
    let app = async |price| {
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
            let opened = generation_store.clone();
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
            .await
            .expect("the actual root builds the door generation");
            limits.stage_boot();
            crate::root::door_steps::tests::boot_fixture_prices(&app).await;
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
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
    let old = steps(app(3).await);
    let new = steps(app(7).await);
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
        let opened = generation_store.clone();
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
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
    let p = pools(
        "models:\n  configured-model: {provider: p}\npools:\n  other-pool:\n    members: [configured-model]",
    );
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

#[tokio::test]
async fn a_units_principal_is_recorded_from_authenticate_until_its_steps_drop() {
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
    let steps_app = std::sync::Arc::new({
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
        let opened = crate::root::real_store::core().await;
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app
    });
    let steps = |caller_key: Option<std::sync::Arc<busbar_contract::records::VirtualKey>>| {
        super::DoorSteps::new(
            &facts,
            &pools,
            std::sync::Arc::new(|_: &str| None),
            std::sync::Arc::clone(&steps_app),
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

async fn downgrade_book(
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    allowed_pools: Option<Vec<String>>,
) -> (
    std::sync::Arc<busbar_kernel::state::App>,
    std::sync::Arc<busbar_contract::records::VirtualKey>,
) {
    let governance_store = crate::root::real_store::core().await;
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_core(
            governance_store.clone(),
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .await
        .expect("the real store opens governance"),
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
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                allowed_pools,
                group: Some("team".to_string()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
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
            "providers": {"downgrade-upstream": {"api_key": "none"}},
            "models": {
                "big": {"provider": "downgrade-upstream"},
                "small": {"provider": "downgrade-upstream"},
                "tiny": {"provider": "downgrade-upstream"}
            },
            "pools": {
                "frontier": {"members": ["big"]},
                "value": {"members": ["small"]},
                "first": {"members": ["big"]},
                "second": {"members": ["small"]},
                "third": {"members": ["tiny"]}
            },
            "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
        }))
        .expect("the door deployment parses");
        let providers = std::collections::HashMap::from([(
            "downgrade-upstream".to_string(),
            serde_yaml::from_str::<busbar_kernel::config::ProviderDef>(
                "protocol: anthropic\nbase_url: https://api.anthropic.com\n",
            )
            .expect("the actual provider declaration parses"),
        )]);
        let mut cfg = busbar_kernel::config::resolve(&deploy, &providers)
            .expect("the door deployment resolves");

        cfg.per_request_fee = 10;
        cfg.groups = groups.clone();
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let opened = gov
            .core_store_handle()
            .expect("the generation keeps its native governance authority");
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
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
    gov.hydrate_budgets_async(&cost, 0)
        .await
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

#[tokio::test]
async fn a_live_parent_at_the_request_cap_admits_and_ledgers_its_child() {
    use busbar_contract::caps::{Admission, Hold, HoldCell, PrincipalId};
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use busbar_kernel::plane_driver::{DriverSteps as _, EndPost, MoneySeam as _, PlaneMoney};
    use std::sync::Arc;

    let (app, key) = downgrade_book(
        vec![LimitCfg {
            metric: LimitMetric::Requests,
            amount: 1,
            per: Some(LimitWindow::Day),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }],
        None,
    )
    .await;
    let pools = pools(DOWNGRADE_SECTION);
    let facts = super::door_facts(
        "",
        &["pool"],
        &["input", "per_request"],
        &["per_request"],
        "door",
        Vec::new(),
    );
    let gov = Arc::clone(app.governance.as_ref().expect("actual governance"));
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(Arc::new(
        crate::root::plane_node::Node::new(),
    )));
    let money = PlaneMoney::new(Arc::clone(&gov), post as Arc<dyn EndPost>);
    let principal = PrincipalId::new(key.id.as_str());
    let arrived = busbar_kernel::store::now();
    let kernel = busbar_kernel::teller::Kernel::new();
    let context = |unit| busbar_kernel::teller::UnitCtx {
        call: kernel.next_call(),
        key: busbar_contract::UnitKey::new(unit),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let steps = || {
        super::DoorSteps::new(
            &facts,
            &pools,
            Arc::new(|_: &str| None),
            Arc::clone(&app),
            Some(&money),
            super::DoorCaller {
                principal: principal.clone(),
                key: Some(Arc::clone(&key)),
                open: false,
                arrived,
                records: None,
                depth: 0,
                credential: None,
                ticket: None,
            },
        )
    };
    let parent_ctx = context(7001);
    let parent_token = kernel.admit_token_for(parent_ctx.call);
    let parent = steps();
    parent.lock().routed = pools.resolve(ROUTE_POOL, Some(b"frontier"));
    let admitted = parent
        .admit(
            &parent_token,
            &parent_ctx,
            &principal,
            &[],
            &Default::default(),
        )
        .expect("the parent consumes the sole request slot");
    let Admission::Own(parent_hold) = admitted else {
        panic!("parent owns its admission")
    };
    let cell = HoldCell::new(Hold::open(&parent_token, principal.clone()));
    drop(
        cell.admit(parent_hold, &parent_token)
            .expect("actual parent admission enters its cell"),
    );
    let child_ctx = context(7002);
    let unopened = HoldCell::new(Hold::open(&parent_token, principal.clone()));
    assert!(
        parent
            .parent_admission(&parent_ctx, &unopened, &parent_token)
            .is_err(),
        "an arrival cell cannot authorize a free child"
    );
    let foreign = PrincipalId::new("foreign-held-principal");
    let foreign_cell = HoldCell::new(Hold::open(&parent_token, foreign.clone()));
    drop(
        foreign_cell
            .admit(Hold::open(&parent_token, foreign), &parent_token)
            .expect("foreign cell is actually admitted"),
    );
    assert!(
        parent
            .parent_admission(&parent_ctx, &foreign_cell, &parent_token)
            .is_err(),
        "another principal's admitted cell cannot lend this parent's money"
    );
    let other_call = kernel.next_call();
    let other_token = kernel.admit_token_for(other_call);
    let other_cell = HoldCell::new(Hold::open(&other_token, principal.clone()));
    drop(
        other_cell
            .admit(Hold::open(&other_token, principal.clone()), &other_token)
            .expect("same principal's other call is actually admitted"),
    );
    assert!(
        parent
            .parent_admission(&parent_ctx, &other_cell, &parent_token)
            .is_err(),
        "the same principal's other call cannot substitute for this parent's hold"
    );
    let authority = parent
        .parent_admission(&parent_ctx, &cell, &parent_token)
        .expect("actual parent money and hold authorize its child");
    let child = steps().under_admission(&authority);
    child.lock().routed = pools.resolve(ROUTE_POOL, Some(b"frontier"));
    for invalid in [kernel.admit_token(), kernel.admit_token_for(other_call)] {
        let refusal = child
            .admit(&invalid, &child_ctx, &principal, &[], &Default::default())
            .expect_err("a child requires its own bound admission proof");
        assert_eq!(
            refusal.reason(),
            busbar_contract::caps::ReasonCode::Replayed
        );
        assert_eq!(
            money.open_units(),
            1,
            "invalid proof never registers child money"
        );
        assert_eq!(cell.accruals(), 0, "invalid proof never accrues to parent");
        let usage = gov
            .usage_for_async(&app.cost, &key.id, arrived)
            .await
            .expect("actual governor usage reads")
            .expect("parent ledger exists");
        assert_eq!(usage.requests, 1, "invalid proof never charges admission");
    }
    let admission = child
        .admit(
            &kernel.admit_token_for(child_ctx.call),
            &child_ctx,
            &principal,
            &[],
            &Default::default(),
        )
        .expect("a live parent's child does not spend a second request slot");
    assert!(
        matches!(admission, Admission::Accrual(_)),
        "child accrues to its actual parent"
    );
    assert_eq!(
        money.open_units(),
        2,
        "child keeps a money registration for its own usage"
    );
    money.checkpoint(
        &child_ctx,
        &[busbar_contract::abi::plane::UnitCount {
            class: 0,
            source: busbar_contract::abi::plane::UNITS_REPORTED,
            amount: 7,
        }],
    );
    money.settle_end(child_ctx.key, 200);
    let usage = gov
        .usage_for_async(&app.cost, &key.id, arrived)
        .await
        .expect("actual ledger reads")
        .expect("actual caller ledger");
    assert_eq!(usage.requests, 1, "one governor admission");
    assert_eq!(
        usage.tokens, 7,
        "the child's nonzero billable units reach the ledger"
    );
    assert_eq!(
        usage.spend_cents, 10,
        "one parent fee survives child settlement"
    );
    money.settle_end(parent_ctx.key, 200);
    assert!(
        parent
            .parent_admission(&parent_ctx, &cell, &parent_token)
            .is_err(),
        "an admitted cell without a live parent money entry has no authority"
    );
}

const DOWNGRADE_SECTION: &str = "models:\n  big: {}\n  small: {}\n  tiny: {}\n\
     pools:\n  frontier:\n    members: [big]\n  value:\n    members: [small]\n\
     \x20 first:\n    members: [big]\n  second:\n    members: [small]\n  third:\n    members: [tiny]";

#[tokio::test]
async fn an_exhausted_budget_re_pools_the_unit_through_its_downgrade_pool() {
    let (app, key) = downgrade_book(vec![downgrading("frontier", 25, "value")], None).await;
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

#[tokio::test]
async fn a_downgrade_cycle_ends_in_the_plain_refusal_naming_the_last_pool_walked() {
    let (app, key) = downgrade_book(
        vec![
            downgrading("first", 10, "second"),
            // A positive cap smaller than one ten-cent request is already exhausted;
            // unlike zero it is a valid configured budget.
            downgrading("second", 1, "third"),
            downgrading("third", 1, "second"),
        ],
        None,
    )
    .await;
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

#[tokio::test]
async fn a_downgrade_never_routes_a_key_into_a_pool_it_may_not_use() {
    let (app, key) = downgrade_book(
        vec![downgrading("frontier", 25, "value")],
        Some(vec!["frontier".to_string()]),
    )
    .await;
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
        busbar_kernel::host_services::caller_binding(),
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
            credential: source_path(key_file.display().to_string()),
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
    /// Explicit transport facts of this scripted endpoint, never inferred from its URL.
    secure: bool,
    prepared:
        std::sync::Mutex<std::collections::HashMap<busbar_contract::conn::ConnId, PreparedToken>>,
    declared: std::sync::Mutex<Vec<(u32, u32, Option<String>)>>,
    pub(crate) opened: std::sync::Mutex<Vec<Opened>>,
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

struct PreparedToken {
    need: busbar_contract::conn::NeedId,
    target: String,
    timeout_ms: u64,
}

impl TokenEndpoint {
    pub(crate) fn answering(answer: fn(&str) -> String) -> Self {
        Self {
            answer: Some(answer),
            ..Self::secure()
        }
    }

    fn secure() -> Self {
        Self {
            secure: true,
            ..Self::default()
        }
    }

    fn answer_request(
        &self,
        id: busbar_contract::conn::ConnId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) {
        use busbar_contract::conn::PieceKind;
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
        self.replies.lock().unwrap().insert(
            id,
            std::collections::VecDeque::from([
                (reply_piece(PieceKind::Fields, 0), Vec::new()),
                (reply_piece(PieceKind::Body, body.len()), body.into_bytes()),
                (reply_piece(PieceKind::Completion, 0), Vec::new()),
            ]),
        );
    }

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
    fn prepare_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        dial_timeout_ms: u64,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        assert!(desc.fields.is_empty() && desc.body.is_empty() && desc.method.is_empty());
        self.bounds
            .lock()
            .unwrap()
            .push((dial_timeout_ms, desc.timeout_ms, false));
        let id = self.slab.insert(caller, need, ())?;
        self.prepared.lock().unwrap().insert(
            id,
            PreparedToken {
                need,
                target: desc.target.to_owned(),
                timeout_ms: desc.timeout_ms,
            },
        );
        Ok(id)
    }

    fn commit_request(
        &self,
        caller: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        use busbar_contract::conn::ConnError;
        self.slab.get(caller, id)?;
        let mut prepared = self.prepared.lock().unwrap();
        let pending = prepared.get(&id).ok_or(ConnError::Refused)?;
        if pending.target != desc.target || pending.timeout_ms != desc.timeout_ms {
            return Err(ConnError::Refused);
        }
        if require_secure && !self.secure {
            return Err(ConnError::AuthRefused);
        }
        let pending = prepared.remove(&id).expect("the same prepared connection");
        self.answer_request(id, pending.need, desc);
        Ok(())
    }

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
fn token_endpoint_prepares_without_sending_and_commits_only_on_its_secured_connection() {
    use busbar_contract::conn::{ConnError, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc};
    const OWNER: InstanceId = InstanceId(99);
    const NEED: NeedId = NeedId(0);
    let prepared = OpenDesc {
        target: "https://tokens.test/mint",
        timeout_ms: 900,
        ..Default::default()
    };
    let request = OpenDesc {
        method: b"POST",
        body: b"credential=fixture-secret".to_vec().into(),
        ..prepared.clone()
    };
    for secure in [false, true] {
        let endpoint = TokenEndpoint {
            secure,
            ..Default::default()
        };
        endpoint.slab.declare(OWNER, NEED);
        let id = endpoint
            .prepare_request(OWNER, NEED, &prepared, 123)
            .unwrap();
        assert!(
            endpoint.opened.lock().unwrap().is_empty(),
            "prepare sends nothing"
        );
        assert_eq!(
            endpoint.facts(OWNER, id).unwrap().peer_cert.is_some(),
            secure,
            "an https spelling alone grants no secure transport facts"
        );
        assert!(matches!(
            endpoint.commit_request(InstanceId(100), id, &request, true),
            Err(ConnError::NotOwner)
        ));
        let wrong_target = OpenDesc {
            target: "https://other.test/mint",
            ..request.clone()
        };
        assert_eq!(
            endpoint.commit_request(OWNER, id, &wrong_target, true),
            Err(ConnError::Refused)
        );
        let wrong_timeout = OpenDesc {
            timeout_ms: 901,
            ..request.clone()
        };
        assert_eq!(
            endpoint.commit_request(OWNER, id, &wrong_timeout, true),
            Err(ConnError::Refused)
        );
        assert!(endpoint.opened.lock().unwrap().is_empty());
        if secure {
            endpoint.commit_request(OWNER, id, &request, true).unwrap();
            assert_eq!(endpoint.opened.lock().unwrap().len(), 1);
            assert!(
                endpoint.replies.lock().unwrap().contains_key(&id),
                "reply belongs to the prepared connection"
            );
            assert_eq!(
                endpoint.commit_request(OWNER, id, &request, true),
                Err(ConnError::Refused)
            );
            assert_eq!(
                endpoint.opened.lock().unwrap().len(),
                1,
                "no duplicate delivery"
            );
        } else {
            assert_eq!(
                endpoint.commit_request(OWNER, id, &request, true),
                Err(ConnError::AuthRefused)
            );
            assert!(
                endpoint.opened.lock().unwrap().is_empty(),
                "no credential crosses insecure transport"
            );
        }
        endpoint.close(OWNER, id).unwrap();
        assert!(endpoint.prepared.lock().unwrap().is_empty());
        assert!(matches!(endpoint.facts(OWNER, id), Err(ConnError::Closed)));
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
        self.slab.check_need(caller, need)?;
        let id = self.slab.insert(caller, need, ())?;
        self.answer_request(id, need, desc);
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
        caller: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        self.slab.get(caller, id)?;
        Ok(busbar_contract::transport::ConnFacts {
            peer_cert: self
                .secure
                .then(|| busbar_contract::transport::wire::CertFacts {
                    subject: "scripted token endpoint".into(),
                    issuer: "scripted test authority".into(),
                    fingerprint: "ab".repeat(32),
                }),
            ..Default::default()
        })
    }
    fn close(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.slab.get(c, id)?;
        self.prepared.lock().unwrap().remove(&id);
        self.replies.lock().unwrap().remove(&id);
        let closed = self.slab.remove(c, id).map(|_| ());
        *self.closes.lock().unwrap() += 1;
        self.closing.notify_waiters();
        closed
    }
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

#[test]
fn the_limits_a_door_plane_is_handed_carry_the_operators_translate_cap() {
    let handed = |yaml: &str| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(yaml).expect("a deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        super::kernel_sections(&cfg).expect("projectable sections")["limits"]
            ["request_body_max_bytes"]
            .as_u64()
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

fn numeric_projection_config() -> busbar_kernel::config::RootCfg {
    let def: busbar_kernel::config::ProviderDef =
        serde_yaml::from_str("protocol: dialect-a\nbase_url: http://127.0.0.1:9\n")
            .expect("provider");
    let defs = std::collections::HashMap::from([("p".to_string(), def)]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers:\n  p:\n    api_key: {env: BUSBAR_TEST_KEY}\nmodels:\n  over:\n    provider: p\n  plain:\n    provider: p\n",
    ).expect("deployment");
    busbar_kernel::config::resolve(&deploy, &defs).expect("resolved configuration")
}

#[test]
fn kernel_sections_preserve_numeric_scalars_in_every_projected_section() {
    let mut cfg = numeric_projection_config();
    cfg.models.get_mut("over").unwrap().default_max_tokens = Some(u32::MAX);
    let mut pool: busbar_kernel::config::pools::PoolCfg =
        serde_yaml::from_str("members: [{model: over}, {model: plain}]").expect("pool");
    pool.members[0].context_max = Some(usize::MAX);
    cfg.pools.insert("all".into(), pool);
    cfg.limits.default_max_tokens = u32::MAX;
    cfg.limits.request_body_max_bytes = usize::MAX;
    cfg.limits.datagram_line_memory_bytes = Some(usize::MAX - 1);
    cfg.limits.reasoning_effort_budgets = busbar_kernel::config::limits::ReasoningEffortBudgets {
        minimal: 1,
        low: 1024,
        medium: 8192,
        high: u32::MAX,
    };
    cfg.providers.get_mut("p").unwrap().table.insert("numbers".into(),
        serde_json::from_str(r#"{"unsigned":18446744073709551615,"signed":-9007199254740993,"nested":[0.1,null,1.2500,1e2]}"#).expect("exact JSON"));
    let sections = super::kernel_sections(&cfg).expect("projectable configuration");
    let models = &sections[busbar_contract::section::RESERVED_MODELS_KEY];
    assert_eq!(
        models["over"]["default_max_tokens"].as_u64(),
        Some(u64::from(u32::MAX))
    );
    assert!(models["plain"].get("default_max_tokens").is_none());
    let members = &sections[busbar_contract::section::RESERVED_POOLS_KEY]["all"]["members"];
    assert_eq!(members[0]["context_max"].as_u64(), Some(usize::MAX as u64));
    assert!(members[1].get("context_max").is_none());
    let expected: serde_yaml::Value = serde_yaml::from_str(&format!(
        "default_max_tokens: {}\nrequest_body_max_bytes: {}\ndatagram_line_memory_bytes: {}\nreasoning_effort_budgets: {{minimal: 1, low: 1024, medium: 8192, high: {}}}",
        u32::MAX, usize::MAX, usize::MAX - 1, u32::MAX,
    )).expect("exact limits");
    assert_eq!(sections["limits"], expected);
    let numbers = &sections[busbar_contract::plugin::Kind::Transport.root()]["p"]["numbers"];
    assert_eq!(numbers["unsigned"].as_u64(), Some(u64::MAX));
    assert_eq!(numbers["signed"].as_i64(), Some(-9_007_199_254_740_993));
    assert_eq!(numbers["nested"][0].as_f64(), Some(0.1));
    assert!(numbers["nested"][1].is_null());
    assert_eq!(numbers["nested"][2].as_f64(), Some(1.25));
    assert_eq!(numbers["nested"][3].as_f64(), Some(100.0));
    cfg.limits.datagram_line_memory_bytes = None;
    assert!(
        super::kernel_sections(&cfg).unwrap()["limits"]["datagram_line_memory_bytes"].is_null()
    );
}

#[test]
fn kernel_sections_refuse_unrepresentable_provider_numbers_before_application() {
    use busbar_kernel::appbuild::RootRules;
    for number in [
        "18446744073709551617",
        "-9223372036854775809",
        "0.1000000000000000000001",
        "9007199254740993.1",
        "1e400",
        "1e-400",
    ] {
        let mut cfg = numeric_projection_config();
        cfg.providers.get_mut("p").unwrap().table.insert(
            "numbers".into(),
            serde_json::from_str(&format!("[{{\"bad\":{number}}}]"))
                .expect("arbitrary precision JSON"),
        );
        let error = super::kernel_sections(&cfg).expect_err("must not round the provider value");
        assert!(error.contains("providers.p.numbers[0].bad"), "{error}");
        assert_eq!(
            super::Rules::default().check(&cfg),
            Err(error.clone()),
            "root validation refuses before config fetch, construction or persistence"
        );
        let projection = super::door_config(&cfg);
        let projection = projection
            .downcast_ref::<super::DoorConfig>()
            .expect("door projection");
        assert_eq!(projection.sections.as_ref().unwrap_err(), &error);
        assert_eq!(projection.listeners.as_ref().unwrap_err(), &error);
        assert_eq!(super::listener_needs(&cfg).unwrap_err(), error);
    }
}

#[test]
fn provider_decimal_projection_retains_declared_decimal_semantics() {
    for text in ["0.1", "1e2", "1.2500", "-0.0", "1e-300"] {
        let value = serde_json::from_str(text).expect("decimal JSON");
        let projected =
            super::provider_yaml(&value, "providers.p.decimal").expect("ordinary decimal");
        assert!(projected.is_number(), "{text}");
        assert_eq!(projected.as_f64(), value.as_f64(), "{text}");
        if text == "-0.0" {
            assert!(projected.as_f64().unwrap().is_sign_negative());
        }
    }
    for (text, integer) in [
        ("9007199254740993.0", 9_007_199_254_740_993),
        ("9.007199254740993e15", 9_007_199_254_740_993),
        ("18446744073709551615.0", u64::MAX),
        ("27.0", 27),
    ] {
        let value = serde_json::from_str(text).expect("integral decimal JSON");
        let projected =
            super::provider_yaml(&value, "providers.p.decimal").expect("exact integral decimal");
        assert_eq!(projected.as_u64(), Some(integer), "{text}");
    }
    let value = serde_json::from_str("-9223372036854775808.0").expect("signed integral decimal");
    assert_eq!(
        super::provider_yaml(&value, "providers.p.decimal")
            .unwrap()
            .as_i64(),
        Some(i64::MIN)
    );
}

static NO_PROVIDERS: std::collections::BTreeMap<String, super::ProviderRoute> =
    std::collections::BTreeMap::new();

fn own_reach() -> super::DoorReach<'static> {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
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
    let secret = source_path(path.display().to_string());
    let value = secrets
        .resolve_string_at_config(
            &secret,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("it resolves while the binding is built");
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

    fn resolve_at_config(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve_at_config(&self.inner, secret, scope)
    }

    fn resolve_string_at_config(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve_string_at_config(&self.inner, secret, scope)
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

#[tokio::test]
async fn the_configured_error_body_cap_reaches_both_egress_constructors() {
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
            let opened = crate::root::real_store::core().await;
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
            .await
            .expect("the actual root builds the door generation");
            limits.stage_boot();
            crate::root::door_steps::tests::boot_fixture_prices(&app).await;
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
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

#[tokio::test]
async fn a_scope_local_unit_resolves_the_one_entry_the_grant_reaches_and_routes_nowhere() {
    const EXACT: &str = concat!(
        module_path!(),
        "::a_scope_local_unit_resolves_the_one_entry_the_grant_reaches_and_routes_nowhere"
    );
    let Some(case) = isolated_fixture_cases(EXACT, &["one", "relayed", "none", "many"]) else {
        return;
    };
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
        let opened = crate::root::real_store::core().await;
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app
    });
    let steps = async |reach: &[&str]| {
        super::DoorSteps::new(
            &facts,
            &p,
            std::sync::Arc::new(|name: &str| match name {
                "p\u{1f}a" => Some(busbar_contract::LaneId::new("p\u{1f}a")),
                "p\u{1f}b" => Some(busbar_contract::LaneId::new("p\u{1f}b")),
                _ => None,
            }),
            std::sync::Arc::clone(&app),
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

    if case == "one" {
        let one = steps(&["a"]).await;
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
    }
    if case == "relayed" {
        let relayed = steps(&["a"]).await;
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
    }
    if matches!(case.as_str(), "none" | "many") {
        let reach: &[&str] = if case == "none" { &[] } else { &["a", "b"] };
        let s = steps(reach).await;
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
            &busbar_kernel::slice::GroupLeaseSlip::default(),
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
    isolated_fixture_done(EXACT, &case);
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
    let sections = super::kernel_sections(&cfg).expect("projectable sections");
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

#[tokio::test]
async fn the_doors_admission_check_reads_the_arrival_window_and_not_the_clock() {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use busbar_kernel::governance::SECS_PER_DAY;
    let governance_store = crate::root::real_store::core().await;
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new_with_core(
            governance_store.clone(),
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .await
        .expect("the real store opens governance"),
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
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                group: Some("team".to_string()),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
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
        let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the door deployment resolves");
        cfg.per_request_fee = 1;
        cfg.groups = groups.clone();
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let opened = gov
            .core_store_handle()
            .expect("the generation keeps its native governance authority");
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
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
    gov.hydrate_budgets_async(&cost, 0)
        .await
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
        gov.derived_bucket_usage_async(&app.cost, "group:team@day", "day", true, past_day)
            .await
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
#[tokio::test]
async fn asking_whether_a_name_is_configured_allocates_nothing() {
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
        let opened = crate::root::real_store::core().await;
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
        .await
        .expect("the actual root builds the door generation");
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
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
        busbar_kernel::host_services::caller_binding(),
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
        busbar_kernel::host_services::caller_binding(),
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

#[test]
fn settings_only_validation_requires_the_auth_declaration_capability() {
    use crate::root::loader::dispatch::{
        auth_outbound::check_settings,
        kinds::auth::{stated_facts, Auth},
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    let door = crate::LINKED
        .auths
        .iter()
        .find_map(|(_, _, door)| {
            let facts = stated_facts(*door).ok()?;
            (!facts.outbound_settings_check && !facts.styles.is_empty()).then_some(*door)
        })
        .expect("a conventional outbound auth row does not advertise settings-only validation");
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let plugin = load_linked::<Auth>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: std::sync::Arc::from("missing-settings-check"),
            max_inflight_cap: 1,
            sink: std::sync::Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let error = check_settings(&plugin, "foreign-settings", b"{}").unwrap_err();
    assert!(error.contains("no settings-only validator"), "{error}");
    assert!(!plugin.is_open());
}

include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(door_steps);
