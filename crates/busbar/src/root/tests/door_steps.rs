// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The off-path half's configuration projection (kernel sections, provider numbers), and the
//! native fixture price binding other root tests share.

use busbar_contract::yaml::ValueExt;

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

#[test]
fn the_limits_a_door_plane_is_handed_carry_the_operators_translate_cap() {
    let handed = |yaml: &str| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            yaml,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("a deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        super::kernel_sections(&cfg).expect("projectable sections")["limits"]
            .at("request_body_max_bytes")
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
    crate::root::linked::register_stores();
    let def: busbar_kernel::config::ProviderDef =
        busbar_contract::yaml::from_str("protocol: dialect-a\nbase_url: http://127.0.0.1:9\n")
            .expect("provider");
    let defs = std::collections::HashMap::from([("p".to_string(), def)]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers:\n  p:\n    api_key: {env: BUSBAR_TEST_KEY}\nmodels:\n  over:\n    provider: p\n  plain:\n    provider: p\n",
            &crate::root::boot::axis_test_grammar(),
    ).expect("deployment");
    busbar_kernel::config::resolve(&deploy, &defs).expect("resolved configuration")
}

#[test]
fn kernel_sections_preserve_numeric_scalars_in_every_projected_section() {
    let mut cfg = numeric_projection_config();
    cfg.models.get_mut("over").unwrap().default_max_tokens = Some(u32::MAX);
    let mut pool: busbar_kernel::config::pools::PoolCfg =
        busbar_contract::yaml::from_str("members: [{model: over}, {model: plain}]").expect("pool");
    pool.members[0].context_max = Some(usize::MAX);
    cfg.pools.insert("all".into(), pool);
    cfg.limits.default_max_tokens = u32::MAX;
    cfg.limits.request_body_max_bytes = usize::MAX;
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
        models.at("over").at("default_max_tokens").as_u64(),
        Some(u64::from(u32::MAX))
    );
    assert!(models.at("plain").get("default_max_tokens").is_none());
    let members = sections[busbar_contract::section::RESERVED_POOLS_KEY]
        .at("all")
        .at("members");
    assert_eq!(
        members.at(0).at("context_max").as_u64(),
        Some(usize::MAX as u64)
    );
    assert!(members.at(1).get("context_max").is_none());
    let expected: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(&format!(
        "default_max_tokens: {}\nrequest_body_max_bytes: {}\nreasoning_effort_budgets: {{minimal: 1, low: 1024, medium: 8192, high: {}}}",
        u32::MAX, usize::MAX, u32::MAX,
    )).expect("exact limits");
    assert_eq!(sections["limits"], expected);
    let numbers = sections[busbar_contract::plugin::Kind::Transport.root()]
        .at("p")
        .at("numbers");
    assert_eq!(numbers.at("unsigned").as_u64(), Some(u64::MAX));
    assert_eq!(numbers.at("signed").as_i64(), Some(-9_007_199_254_740_993));
    assert_eq!(numbers.at("nested").at(0).as_f64(), Some(0.1));
    assert!(numbers.at("nested").at(1).is_null());
    assert_eq!(numbers.at("nested").at(2).as_f64(), Some(1.25));
    assert_eq!(numbers.at("nested").at(3).as_f64(), Some(100.0));
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

#[test]
fn a_models_protocol_override_is_handed_to_the_plane() {
    crate::root::linked::register_stores();
    let def: busbar_kernel::config::ProviderDef =
        busbar_contract::yaml::from_str("protocol: dialect-a\nbase_url: http://127.0.0.1:9\n")
            .expect("a def");
    let defs = std::collections::HashMap::from([("p".to_string(), def)]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nproviders:\n  p:\n    api_key: { env: BUSBAR_TEST_KEY }\n\
         models:\n  over:\n    provider: p\n    protocol: dialect-b\n  plain:\n    provider: p\n",
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let sections = super::kernel_sections(&cfg).expect("projectable sections");
    let models = sections
        .get(busbar_contract::section::RESERVED_MODELS_KEY)
        .expect("the models section");
    assert_eq!(
        models.at("over").at("protocol").as_str(),
        Some("dialect-b"),
        "{models:?}"
    );
    assert!(
        models.at("plain").get("protocol").is_none(),
        "a model naming no protocol states none: {models:?}"
    );
}
