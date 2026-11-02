// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original provider/model/pool validation assertions, owned by the actual distribution.
use busbar_kernel::config::{self, RootCfg};
use busbar_kernel::config_validate::validate;
use std::collections::HashMap;

fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    crate::dist_root_install::install();
    config::RootCfg {
        plane_defs: Default::default(),
        plane_pools: Default::default(),
        plane_sections: Default::default(),
        listen: busbar_kernel::config::DEFAULT_LISTEN_ADDR.into(),

        endpoint_resources: Default::default(),
        oauth_as: None,
        credentials: Default::default(),
        public_url: None,
        tls: None,
        admin_listen: busbar_kernel::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,

        providers: providers
            .into_iter()
            .map(|(name, p)| (name, p.into()))
            .collect(),
        models,
        pools,
        upstream_credentials: busbar_kernel::auth::UpstreamCreds::Own,
        hooks: HashMap::new(),
        admin_auth: config::default_admin_auth_names(),
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: Some(config::StoreCfg {
            module: {
                let path = std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                    .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store");
                let statement = busbar_plugin_loader::dispatch::rendering_of_library(
                    std::path::Path::new(&path),
                )
                .expect("the actual store statement reads")
                .expect("the actual store exports its statement");
                busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual store statement is valid")
                    .name
            },
            settings: Default::default(),
        }),
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        guard: Default::default(),
        limits: config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

fn make_root_cfg_with_blocked(
    providers: HashMap<String, config::ProviderCfg>,
    blocked_metadata_hosts: Vec<String>,
) -> RootCfg {
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.blocked_metadata_hosts = blocked_metadata_hosts;
    cfg
}

fn make_provider(protocol: &str, base_url: &str, api_key_env: &str) -> config::ProviderCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());

    config::ProviderCfg {
        protocol: protocol.into(),
        base_url: base_url.into(),

        api_key: config::SecretRef::env(api_key_env),
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        options: Default::default(),
    }
}

fn shipped_protocol(nth: usize) -> &'static str {
    crate::dist_root_install::install();
    busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .nth(nth)
        .unwrap_or_else(|| {
            panic!(
                "the actual distribution ships fewer than {} dialects",
                nth + 1
            )
        })
}

fn proto_a() -> &'static str {
    shipped_protocol(0)
}
fn proto_b() -> &'static str {
    shipped_protocol(1)
}

fn make_model(provider: &str, max_concurrent: usize) -> config::ModelCfg {
    let mut m = make_model_unbounded(provider);
    m.max_concurrent = Some(max_concurrent);
    m
}

fn make_model_unbounded(provider: &str) -> config::ModelCfg {
    config::ModelCfg {
        reasoning: None,
        prompt_caching: None,
        protocol: None,
        max_requests: -1,
        provider: provider.into(),
        max_concurrent: None,
        default_max_tokens: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

fn make_pool(members: Vec<config::PoolMember>) -> config::PoolCfg {
    config::PoolCfg {
        upstream_credentials: None,
        members,
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy: config::PoolPolicy::default(),
        gates: Vec::new(),
        base_named: false,
        ..Default::default()
    }
}

fn make_member(model: &str) -> config::PoolMember {
    config::PoolMember {
        reasoning: None,
        model: model.into(),
        weight: 1,
        attempt_timeout_ms: None,
        context_max: None,
        tier: None,
        tags: Vec::new(),
    }
}

#[test]
fn test_validate_rejects_bad_protocol() {
    let mut providers = HashMap::new();
    let bad = make_provider("nope", "https://api.example.com", "API_KEY");
    providers.insert("bad".to_string(), bad);

    let ok = make_provider(
        proto_a(),
        "https://api.vendor-a.example.com",
        "VENDOR_A_KEY",
    );
    providers.insert("good".to_string(), ok);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("unknown protocol must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("unknown protocol 'nope'") && e.contains("'bad'")),
        "expected an unknown-protocol error naming provider 'bad' and 'nope'; got: {errs:?}"
    );

    let msg = errs
        .iter()
        .find(|e| e.contains("unknown protocol 'nope'"))
        .unwrap_or_else(|| panic!("expected unknown-protocol error; got: {errs:?}"));
    for proto in busbar_kernel::plane_driver::dispatch::provider_dialects() {
        assert!(
            msg.contains(proto),
            "allowed-set list must include '{proto}'; got: {msg}"
        );
    }

    let shipped = proto_a();
    assert!(
        !errs
            .iter()
            .any(|e| e.contains(&format!("unknown protocol '{shipped}'"))),
        "'{shipped}' is a valid protocol and must not error; got: {errs:?}"
    );
}

#[test]
fn test_error_map_invalid_class_message_lists_full_valid_set() {
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.example.com", "API_KEY");

    p.error_map.clear();
    p.error_map
        .insert("429".to_string(), "not_a_class".to_string());
    providers.insert("bad".to_string(), p);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("invalid StatusClass must fail validation");

    let msg = errs
        .iter()
        .find(|e| e.contains("invalid StatusClass 'not_a_class'"))
        .unwrap_or_else(|| panic!("expected invalid-StatusClass error; got: {errs:?}"));
    assert!(
            msg.contains("context_length"),
            "valid-values list must include 'context_length' (it is accepted by StatusClass::parse); got: {msg}"
        );

    for class in [
        "rate_limit",
        "overloaded",
        "server_error",
        "timeout",
        "network",
        "auth",
        "billing",
        "client_error",
        "context_length",
    ] {
        assert!(
            busbar_contract::upstream::StatusClass::parse(class).is_some(),
            "test invariant: '{class}' should be a real StatusClass"
        );
        assert!(
            msg.contains(class),
            "valid-values list must include '{class}'; got: {msg}"
        );
    }
}

#[test]
fn test_error_map_context_length_is_a_valid_class() {
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.example.com", "API_KEY");
    p.error_map.clear();
    p.error_map
        .insert("400".to_string(), "context_length".to_string());
    providers.insert("ctx".to_string(), p);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let result = validate(&cfg);
    if let Err(errs) = result {
        assert!(
            !errs.iter().any(|e| e.contains("invalid StatusClass")),
            "'context_length' is a valid StatusClass and must not error; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_rejects_zero_default_max_tokens() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut m = make_model("myprovider", 10);
    m.default_max_tokens = Some(0);
    models.insert("mymodel".to_string(), m);

    let mut ok = make_model("myprovider", 10);
    ok.default_max_tokens = Some(4096);
    models.insert("okmodel".to_string(), ok);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("default_max_tokens: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("mymodel") && e.contains("default_max_tokens: 0")),
        "expected a default_max_tokens:0 error for 'mymodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a positive default_max_tokens must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_zero_request_body_read_timeout() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));

    let mut cfg = make_root_cfg(providers, models, HashMap::new());
    cfg.limits.request_body_read_timeout_secs = 0;
    let errs = validate(&cfg).expect_err("request_body_read_timeout_secs: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("request_body_read_timeout_secs")),
        "expected a request_body_read_timeout_secs guard error; got: {errs:?}"
    );

    cfg.limits.request_body_read_timeout_secs = 30;
    let errs2 = validate(&cfg).err().unwrap_or_default();
    assert!(
        !errs2
            .iter()
            .any(|e| e.contains("request_body_read_timeout_secs")),
        "a positive request_body_read_timeout_secs must not error; got: {errs2:?}"
    );
}

#[test]
fn test_validate_rejects_empty_upstream_model() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();

    let mut bad = make_model("myprovider", 10);
    bad.upstream_model = Some("   ".to_string());
    models.insert("badmodel".to_string(), bad);

    let mut ok = make_model("myprovider", 10);
    ok.upstream_model = Some("acme.model-3-5-20241022-v2:0".to_string());
    models.insert("okmodel".to_string(), ok);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("empty upstream_model must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("badmodel") && e.contains("upstream_model")),
        "expected an empty-upstream_model error for 'badmodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a non-empty upstream_model must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_pool_name_equals_provider_name() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "myprovider".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("myprovider"));
    assert!(errs[0].contains("pool name") && errs[0].contains("conflicts with provider name"));
}

#[test]
fn test_validate_rejects_unknown_member_ref() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let models = HashMap::new();

    let mut pools = HashMap::new();
    pools.insert(
        "mypoool".to_string(),
        make_pool(vec![make_member("unknownmodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("unknownmodel"));
    assert!(errs[0].contains("references unknown model"));
}

#[test]
fn test_validate_token_url_ssrf_and_scheme() {
    let build = |token_url: &str| -> Vec<String> {
        let mut providers = HashMap::new();
        let mut entra = make_provider(
            proto_b(),
            "https://myres.vendor-a.azure.example.com",
            "API_KEY",
        );
        entra.token_url = Some(token_url.to_string());
        entra.scope = Some("api://x/.default".into());
        entra.auth = Some(config::ProviderAuth::named("oauth-client-credentials"));
        providers.insert("entra".to_string(), entra);
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("entra", 10));
        let mut pools = HashMap::new();
        pools.insert("p".to_string(), make_pool(vec![make_member("m")]));
        let cfg = make_root_cfg(providers, models, pools);
        validate(&cfg).err().unwrap_or_default()
    };

    assert!(
        build("https://login.microsoftonline.com/TENANT/oauth2/v2.0/token").is_empty(),
        "a valid https token_url must pass"
    );

    let up = build("HTTPS://login.microsoftonline.com/t/token");
    assert!(
        !up.iter()
            .any(|e| e.contains("token_url") && e.contains("must use")),
        "uppercase HTTPS token_url must not trip the scheme guard; got: {up:?}"
    );

    for scheme in ["http", "HTTP"] {
        let errs = build(&format!("{scheme}://token.example.com/oauth"));
        assert!(
            errs.iter()
                .any(|e| e.contains("token_url") && e.contains("https")),
            "{scheme}:// public token_url must be rejected; got: {errs:?}"
        );
    }

    for tu in [
        "http://10.0.0.5/oauth2/token",
        "http://172.16.4.2/token",
        "http://192.168.1.20:8080/token",
        "http://127.0.0.1:9000/token",
        "http://[::1]:9000/token",
        "http://localhost:9000/token",
    ] {
        let errs = build(tu);
        assert!(
            !errs.iter().any(|e| e.contains("token_url")),
            "http token_url to a private/loopback host must be accepted, as 1.5.5 did ({tu}); got: {errs:?}"
        );
    }

    let errs = build("http://example.com/token");
    let want = "provider 'entra' token_url must use https for a public host (got 'http://example.com/token'); it carries the client secret, so plaintext http is permitted only for a private/loopback token endpoint";
    assert!(
        errs.iter().any(|e| e == want),
        "public http token_url must be refused with the 1.5.5 text; got: {errs:?}"
    );

    for host in ["169.254.169.254", "metadata.google.internal"] {
        let errs = build(&format!("https://{host}/token"));
        assert!(
            errs.iter()
                .any(|e| e.contains("token_url") && e.contains("metadata")),
            "token_url at {host} must be SSRF-blocked; got: {errs:?}"
        );
    }

    let ws = build("   ");
    assert!(
        ws.iter().any(|e| e.contains("token_url")),
        "whitespace-only token_url must be rejected as missing; got: {ws:?}"
    );
}

#[test]
fn test_validate_conflicting_context_max_across_pools() {
    let build = |ca: Option<usize>, cb: Option<usize>| -> Vec<String> {
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            make_provider(proto_b(), "https://api.example.com", "API_KEY"),
        );
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("p", 10));
        let mut a = make_member("m");
        a.context_max = ca;
        let mut b = make_member("m");
        b.context_max = cb;
        let mut pools = HashMap::new();
        pools.insert("poolA".to_string(), make_pool(vec![a]));
        pools.insert("poolB".to_string(), make_pool(vec![b]));
        validate(&make_root_cfg(providers, models, pools))
            .err()
            .unwrap_or_default()
    };
    assert!(
        build(Some(128000), Some(200000))
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "differing context_max across pools must be a validate() error"
    );
    assert!(
        !build(Some(128000), Some(128000))
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "identical context_max must not conflict"
    );
    assert!(
        !build(Some(128000), None)
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "None must not conflict with an explicit value"
    );
}

#[test]
fn test_validate_collects_all_errors() {
    let mut providers = HashMap::new();
    providers.insert(
        "conflict_provider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let mut models = HashMap::new();
    models.insert("model1".to_string(), make_model("conflict_provider", 10));

    let mut pools = HashMap::new();

    pools.insert(
        "conflict_provider".to_string(),
        make_pool(vec![make_member("model1")]),
    );

    pools.insert(
        "otherpool".to_string(),
        make_pool(vec![make_member("nonexistent_model")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();

    assert_eq!(errs.len(), 2);

    let err_text = errs.join(" | ");
    assert!(err_text.contains("conflict_provider"));
    assert!(err_text.contains("nonexistent_model"));
}

#[test]
fn test_validate_heterogeneous_pool_is_ok() {
    let mut providers = HashMap::new();

    providers.insert(
        "acme_provider".to_string(),
        make_provider(proto_a(), "https://api.acme.example.com", "ACME_KEY"),
    );
    providers.insert(
        "vendor_a_provider".to_string(),
        make_provider(
            proto_b(),
            "https://api.vendor-a.example.com",
            "VENDOR_A_KEY",
        ),
    );

    let mut models = HashMap::new();
    models.insert("acme_model".to_string(), make_model("acme_provider", 10));
    models.insert(
        "vendor_a_model".to_string(),
        make_model("vendor_a_provider", 10),
    );

    let mut pools = HashMap::new();

    pools.insert(
        "mixedpool".to_string(),
        make_pool(vec![
            make_member("acme_model"),
            make_member("vendor_a_model"),
        ]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_ok());
}

#[test]
fn test_validate_valid_config_succeeds() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_ok());
}

#[test]
fn test_validate_model_without_provider_error() {
    let providers = HashMap::new();

    let mut models = HashMap::new();
    models.insert(
        "orphan_model".to_string(),
        make_model("nonexistent_provider", 10),
    );

    let pools = HashMap::new();

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();

    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("orphan_model"));
    assert!(errs[0].contains("references unknown provider"));
}
