// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact ordinary config-validation cases under the real distribution registration.
use busbar_kernel::config::{self, RootCfg};
use busbar_kernel::config_validate::*;
use std::collections::HashMap;

const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;
const MAX_DURATION_MS: u64 = MAX_DURATION_SECS * 1_000;

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
                let path = crate::root::test_plugins::application_store_library();
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

fn make_auth_chain(
    modules: &[&str],
    _upstream: busbar_kernel::auth::UpstreamCreds,
) -> config::AuthCfg {
    let mut auth = config::AuthCfg::default_none();
    auth.chain = modules
        .iter()
        .map(|m| config::AuthChainEntry::bare(*m))
        .collect();

    if modules.contains(&busbar_kernel::config::KEYS_MODULE) {
        auth.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));
        auth.admin_auth = vec![];
    }
    auth
}

fn make_breaker(
    base_cooldown_secs: u64,
    max_cooldown_secs: u64,
    trip: Option<config::BreakerTripConfig>,
) -> config::BreakerCfg {
    config::BreakerCfg {
        base_cooldown_secs,
        max_cooldown_secs,
        trip,
    }
}

fn make_trip(
    mode: config::BreakerTripMode,
    window_secs: u64,
    threshold: f64,
    min_requests: usize,
    consecutive_n: u32,
) -> config::BreakerTripConfig {
    config::BreakerTripConfig {
        mode,
        window_secs,
        threshold,
        min_requests,
        consecutive_n,
    }
}

fn valid_maps() -> (
    HashMap<String, config::ProviderCfg>,
    HashMap<String, config::ModelCfg>,
    HashMap<String, config::PoolCfg>,
) {
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
    (providers, models, pools)
}

#[test]
fn test_validate_rejects_non_https_base_url() {
    for (bad, fragment) in [
        ("http://api.example.com", "must use https for a public host"),
        ("file:///etc/shadow", "must use http or https"),
        ("", "must use http or https"),
    ] {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_a(), bad, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("non-https base_url '{bad}' must fail validation"));
        assert!(
            errs.iter()
                .any(|e| e.contains(fragment) && e.contains("provider 'p' base_url")),
            "expected a scheme error ('{fragment}') for '{bad}'; got: {errs:?}"
        );
    }

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(
            proto_a(),
            "http://169.254.169.254/latest/meta-data/",
            "API_KEY",
        ),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs =
        validate(&cfg).unwrap_err_or_default("http IMDS base_url must fail validation".into());
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected a metadata-host error for the http IMDS literal; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_a_private_or_loopback_literal_base_url() {
    for url in [
        "http://127.0.0.1:11434",
        "http://10.1.2.3/",
        "http://192.168.1.5:8080/v1",
        "http://[::1]:8080",
        "https://172.16.0.9",
    ] {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_a(), url, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "a private or loopback literal base_url validates, as in 1.5.5: {url}"
        );
    }
}

#[test]
fn test_validate_accepts_https_base_url() {
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(validate(&cfg).is_ok(), "an https base_url must validate");
}

#[test]
fn test_validate_rejects_zero_max_concurrent() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("zeromodel".to_string(), make_model("myprovider", 0));

    models.insert("okmodel".to_string(), make_model("myprovider", 1));

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("max_concurrent: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zeromodel") && e.contains("max_concurrent: 0")),
        "expected a max_concurrent:0 error for 'zeromodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a positive max_concurrent must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_oversized_max_concurrent() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();

    models.insert(
        "hugemodel".to_string(),
        make_model("myprovider", tokio::sync::Semaphore::MAX_PERMITS + 1),
    );

    models.insert("bigbutok".to_string(), make_model("myprovider", 5_000_000));

    models.insert(
        "boundarymodel".to_string(),
        make_model("myprovider", tokio::sync::Semaphore::MAX_PERMITS),
    );

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("an oversized max_concurrent must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("hugemodel") && e.contains("max_concurrent")),
        "expected an oversized max_concurrent error for 'hugemodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("bigbutok")),
        "a large-but-not-panic-triggering max_concurrent must not newly become an error: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("boundarymodel")),
        "a max_concurrent at the exact Semaphore::MAX_PERMITS boundary must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_omitted_max_concurrent() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("unbounded".to_string(), make_model_unbounded("myprovider"));

    let cfg = make_root_cfg(providers, models, HashMap::new());
    validate(&cfg)
        .expect("a model omitting max_concurrent must validate (unbounded is the default)");
}

#[test]
fn test_validate_rejects_bad_reasoning_effort_budgets() {
    let base = || {
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            make_provider(proto_a(), "https://api.example.com", "K"),
        );
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("p", 10));
        make_root_cfg(providers, models, HashMap::new())
    };

    let mut cfg = base();
    cfg.limits.reasoning_effort_budgets = busbar_kernel::config::ReasoningEffortBudgets {
        minimal: 0,
        low: 4096,
        medium: 8192,
        high: 16384,
    };
    let errs = validate(&cfg).expect_err("zero budget must fail");
    assert!(errs
        .iter()
        .any(|e| e.contains("reasoning_effort_budgets") && e.contains("> 0")));

    let mut cfg2 = base();
    cfg2.limits.reasoning_effort_budgets = busbar_kernel::config::ReasoningEffortBudgets {
        minimal: 4096,
        low: 1024,
        medium: 8192,
        high: 16384,
    };
    let errs2 = validate(&cfg2).expect_err("non-ascending must fail");
    assert!(errs2
        .iter()
        .any(|e| e.contains("reasoning_effort_budgets") && e.contains("ascending")));
}

#[test]
fn test_validate_rejects_zero_attempt_timeout_ms() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut zero = make_model("myprovider", 10);
    zero.attempt_timeout_ms = Some(0);
    models.insert("zerocap".to_string(), zero);
    let mut positive = make_model("myprovider", 10);
    positive.attempt_timeout_ms = Some(5000);
    models.insert("okcap".to_string(), positive);
    models.insert("nocap".to_string(), make_model("myprovider", 10));

    let mut zero_member = make_member("okcap");
    zero_member.attempt_timeout_ms = Some(0);
    let mut ok_member = make_member("nocap");
    ok_member.attempt_timeout_ms = Some(200);
    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![zero_member, ok_member]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("attempt_timeout_ms: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zerocap") && e.contains("attempt_timeout_ms: 0")),
        "expected a model-level attempt_timeout_ms:0 error for 'zerocap'; got: {errs:?}"
    );
    assert!(
            errs.iter().any(|e| e.contains("mypool")
                && e.contains("okcap")
                && e.contains("attempt_timeout_ms: 0")),
            "expected a member-level attempt_timeout_ms:0 error for pool 'mypool' member 'okcap'; got: {errs:?}"
        );
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("attempt_timeout_ms") && e.contains("nocap")),
        "None / positive attempt_timeout_ms must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_zero_max_requests() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut zero = make_model("myprovider", 10);
    zero.max_requests = 0;
    models.insert("zeroreq".to_string(), zero);

    models.insert("unlimited".to_string(), make_model("myprovider", 10));
    let mut positive = make_model("myprovider", 10);
    positive.max_requests = 100;
    models.insert("capped".to_string(), positive);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("max_requests: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zeroreq") && e.contains("max_requests: 0")),
        "expected a max_requests:0 error for 'zeroreq'; got: {errs:?}"
    );

    assert_eq!(
        errs.len(),
        1,
        "only the zero lane must error; got: {errs:?}"
    );
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("'unlimited'") || e.contains("'capped'")),
        "a -1 (unlimited) or positive max_requests must not error; got: {errs:?}"
    );
}

#[test]
fn test_localhost_is_allowed_by_default() {
    for ok in [
        "https://localhost/",
        "https://localhost:11434/",
        "https://LOCALHOST/v1",
        "https://localhost./",
        "https://localhost.:443/api",
        "http://localhost:11434/",
    ] {
        assert!(
            ssrf_blocked_host(ok, &[], false, &[]).is_none(),
            "expected '{ok}' to be allowed (localhost is a local-model target, not metadata)"
        );
    }

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://localhost:11434/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "a localhost base_url must validate with no flag; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_rejects_pool_name_equals_model_name() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();

    pools.insert(
        "mymodel".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("pool name == model name must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("conflicts with model name") && e.contains("mymodel")),
        "expected a pool/model name-collision error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_pool_named_api() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("api".to_string(), make_pool(vec![make_member("mymodel")]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a pool named 'api' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("pool name 'api' is reserved")),
        "expected a reserved-admin-name error for the pool; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_provider_named_api() {
    let mut providers = HashMap::new();
    providers.insert(
        "api".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("a provider named 'api' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("provider name 'api' is reserved")),
        "expected a reserved-admin-name error for the provider; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_model_named_api() {
    let (mut providers, mut models, pools) = valid_maps();
    providers
        .entry("myprovider".to_string())
        .or_insert_with(|| make_provider(proto_a(), "https://api.example.com", "API_KEY"));
    models.insert("api".to_string(), make_model("myprovider", 10));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a model named 'api' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("model name 'api' is reserved")),
        "expected a reserved-admin-name error for the model; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_pool_named_admin_with_legacy_message() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("admin".to_string(), make_pool(vec![make_member("mymodel")]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a pool named 'admin' must fail validation");
    let want = "pool name 'admin' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it";
    assert!(
        errs.iter().any(|e| e == want),
        "expected the exact legacy reserved-name error for the pool; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_provider_named_admin_with_legacy_message() {
    let mut providers = HashMap::new();
    providers.insert(
        "admin".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("a provider named 'admin' must fail validation");
    let want = "provider name 'admin' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a provider reachable via the adhoc /admin/<model> route is unreachable to clients; rename it";
    assert!(
        errs.iter().any(|e| e == want),
        "expected the exact legacy reserved-name error for the provider; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_model_named_admin_with_legacy_message() {
    let (mut providers, mut models, pools) = valid_maps();
    providers
        .entry("myprovider".to_string())
        .or_insert_with(|| make_provider(proto_a(), "https://api.example.com", "API_KEY"));
    models.insert("admin".to_string(), make_model("myprovider", 10));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a model named 'admin' must fail validation");
    let want = "model name 'admin' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a model reachable via /admin/v1/messages is unreachable to clients and bypasses per-model governance; rename it";
    assert!(
        errs.iter().any(|e| e == want),
        "expected the exact legacy reserved-name error for the model; got: {errs:?}"
    );
}

#[test]
fn test_validate_allows_api_prefixed_but_boundary_safe_names() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("apix".to_string(), make_pool(vec![make_member("mymodel")]));
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "an 'apix' pool is boundary-safe and must validate"
    );
}

#[test]
fn test_validate_rejects_bad_breaker_params() {
    let cases: Vec<(&str, config::BreakerCfg, &str)> = vec![
        (
            "min_requests 0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 0, 3)),
            ),
            "trip.min_requests must be >= 1",
        ),
        (
            "window_s 0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 0, 0.5, 5, 3)),
            ),
            "trip.window_secs must be >= 1",
        ),
        (
            "threshold > 1.0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 1.5, 5, 3)),
            ),
            "trip.threshold must be in (0.0, 1.0]",
        ),
        (
            "threshold 0.0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.0, 5, 3)),
            ),
            "trip.threshold must be in (0.0, 1.0]",
        ),
        (
            "consecutive n 0",
            make_breaker(
                15,
                120,
                Some(make_trip(
                    config::BreakerTripMode::Consecutive,
                    30,
                    0.5,
                    5,
                    0,
                )),
            ),
            "trip.consecutive_n must be >= 1",
        ),
        (
            "max_cooldown < base_cooldown",
            make_breaker(
                100,
                50,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "max_cooldown_secs",
        ),
        (
            // A zero base cooldown yields a degenerate breaker that re-admits
            // a tripped backend immediately — must fail loud, mirroring the trip.* zero-floor guards.
            "base_cooldown 0",
            make_breaker(
                0,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "base_cooldown_secs must be >= 1",
        ),
        (
            // The max-cooldown twin of the above.
            "max_cooldown 0",
            make_breaker(
                0,
                0,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "max_cooldown_secs must be >= 1",
        ),
    ];

    for (desc, breaker, expected) in cases {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.breaker = Some(breaker);
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("breaker case '{desc}' must fail validation"));
        assert!(
            errs.iter().any(|e| e.contains(expected)),
            "case '{desc}': expected error containing '{expected}'; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_accepts_good_breaker_params() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.breaker = Some(make_breaker(
        15,
        120,
        Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 1.0, 1, 3)),
    ));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a well-formed breaker config must validate"
    );
}

#[test]
fn test_validate_rejects_zero_cooldown_breaker() {
    for (base, max, expected) in [
        (0u64, 120u64, "base_cooldown_secs must be >= 1"),
        (15, 0, "max_cooldown_secs must be >= 1"),
        (0, 0, "base_cooldown_secs must be >= 1"),
    ] {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.breaker = Some(make_breaker(base, max, None));
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg).unwrap_err_or_default(format!(
            "breaker base={base} max={max} must fail validation"
        ));
        assert!(
            errs.iter()
                .any(|e| e.contains(expected) && e.contains("mypool")),
            "base={base} max={max}: expected error containing '{expected}'; got: {errs:?}"
        );
    }

    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.breaker = Some(make_breaker(1, 1, None));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a breaker with base==max==1 is the minimum well-formed config and must validate"
    );
}

#[test]
fn test_validate_rejects_zero_failover_deadline() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 0,
        exclusions: None,
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("failover.timeout_secs: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("failover.timeout_secs must be >= 1") && e.contains("mypool")),
        "expected a zero-failover-deadline error for 'mypool'; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_positive_failover_deadline_and_zero_cap() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: None,
        max_hops: 0,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a positive failover.timeout_secs with max_hops:0 must validate"
    );
}

#[test]
fn test_validate_rejects_unknown_failover_exclusion() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: Some(vec!["mymodell".to_string()]),
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an unknown failover exclusion must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("failover.exclusions references 'mymodell'")
                && e.contains("not a member of the pool")),
        "expected an unknown-exclusion error naming 'mymodell'; got: {errs:?}"
    );
}

#[test]
fn a_role_binding_grant_of_an_undeclared_kind_is_refused_at_validation() {
    let binding: config::RoleBindingCfg = serde_yaml::from_str("allowed_widgets: [x]\n")
        .expect("`allowed_{kind}s` is a role-binding key");
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    auth.chain = vec![config::AuthChainEntry::bare("keys")];
    auth.role_bindings.insert(
        "keys".to_string(),
        std::collections::BTreeMap::from([("ops".to_string(), binding)]),
    );
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("an undeclared kind must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("role_bindings.keys.ops") && e.contains("allowed_widgets")),
        "expected the undeclared-kind error naming the binding and field; got: {errs:?}"
    );
    for not_a_grant in [
        "grop: x\n",
        "allowed_widgets: x\n",
        "allowed_widgets: [1]\n",
    ] {
        assert!(
            serde_yaml::from_str::<config::RoleBindingCfg>(not_a_grant).is_err(),
            "`{not_a_grant}` is not a role-binding grant"
        );
    }
}

#[test]
fn test_validate_rejects_bad_chain_and_role_binding_scopes() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    let mut entry = config::AuthChainEntry::bare("keys");
    entry.max_admin_scope = Some("superuser".to_string());
    auth.chain = vec![entry];
    auth.role_bindings.insert(
        "keys".to_string(),
        std::collections::BTreeMap::from([(
            "viewers".to_string(),
            config::RoleBindingCfg {
                allowed_pools: None,
                group: None,
                admin_scope: Some("readonly".to_string()),
                verbs: None,
                plane_grants: Default::default(),
            },
        )]),
    );
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("typo'd scope tokens must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("auth chain entry 'keys'")
            && e.contains("unknown max_admin_scope 'superuser'")),
        "expected the chain-entry max_admin_scope error; got: {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("role_bindings.keys.viewers")
            && e.contains("unknown admin_scope 'readonly'")),
        "expected the role_bindings admin_scope error; got: {errs:?}"
    );

    assert!(
        errs.iter()
            .filter(|e| e.contains("superuser") || e.contains("readonly"))
            .all(|e| e.contains("read-only") && e.contains("full")),
        "scope errors must enumerate the valid scope tokens (read-only or full); got: {errs:?}"
    );

    assert!(
        errs.iter()
            .filter(|e| e.contains("superuser") || e.contains("readonly"))
            .all(|e| !e.contains("hooks-register") && !e.contains("mint")),
        "scope errors must not mention the retired hooks-register/mint tokens; got: {errs:?}"
    );
}

#[test]
fn a_verb_allow_list_naming_an_unknown_verb_is_refused_at_validation() {
    let errors_for = |yaml: &str| -> Vec<String> {
        let binding: config::RoleBindingCfg =
            serde_yaml::from_str(yaml).expect("`verbs:` is a role-binding key");
        let (providers, models, pools) = valid_maps();
        let mut cfg = make_root_cfg(providers, models, pools);
        let mut auth = config::AuthCfg::default_none();
        auth.chain = vec![config::AuthChainEntry::bare("keys")];
        auth.role_bindings.insert(
            "keys".to_string(),
            std::collections::BTreeMap::from([("ops".to_string(), binding)]),
        );
        cfg.auth = Some(auth);
        validate(&cfg)
            .err()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.contains("role_bindings.keys.ops.verbs"))
            .collect()
    };

    let unknown = errors_for("verbs: [get_keys, not_a_verb]");
    assert_eq!(
        unknown.len(),
        1,
        "exactly the unknown name is refused: {unknown:?}"
    );
    assert!(
        unknown[0].contains("unknown admin verb 'not_a_verb'") && unknown[0].contains("\"*\""),
        "the refusal names the verb and the valid forms: {unknown:?}"
    );
    let shape = errors_for("verbs: full");
    assert!(
        shape.len() == 1 && shape[0].contains("must be \"*\" or a list of admin verb names"),
        "a scalar other than `*` is refused: {shape:?}"
    );
    for valid in ["verbs: \"*\"", "verbs: [get_keys, post_keys]", "verbs: []"] {
        assert_eq!(
            errors_for(valid),
            Vec::<String>::new(),
            "{valid} is a valid allow-list"
        );
    }
}

#[test]
fn validate_admin_scope_mint_now_errors() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    let mut entry = config::AuthChainEntry::bare("keys");
    entry.max_admin_scope = Some("mint".to_string());
    auth.chain = vec![entry];
    auth.role_bindings.insert(
        "keys".to_string(),
        std::collections::BTreeMap::from([(
            "portal".to_string(),
            config::RoleBindingCfg {
                allowed_pools: None,
                group: None,
                admin_scope: Some("mint".to_string()),
                verbs: None,
                plane_grants: Default::default(),
            },
        )]),
    );
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("`mint` is no longer a valid scope token");
    assert!(
        errs.iter().any(|e| e.contains("role_bindings.keys.portal")
            && e.contains("unknown admin_scope 'mint'")
            && e.contains("read-only or full")),
        "expected the role_bindings mint error naming the two-rung set; got: {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("auth chain entry 'keys'")
            && e.contains("unknown max_admin_scope 'mint'")),
        "expected the chain-entry mint error; got: {errs:?}"
    );
}

#[test]
fn validate_admin_auth_plugin_name_no_longer_rejected() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.admin_auth = vec![
        busbar_kernel::config::operator_provider().to_string(),
        "oidc-admin".to_string(),
    ];
    let res = validate(&cfg);
    if let Err(errs) = res {
        assert!(
            !errs
                .iter()
                .any(|e| e.contains("admin_auth names unknown module")),
            "a non-builtin admin module name must not be statically rejected; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_accepts_known_failover_exclusion() {
    let (mut providers, mut models, _) = valid_maps();
    providers
        .entry("myprovider".to_string())
        .or_insert_with(|| make_provider(proto_a(), "https://api.example.com", "API_KEY"));
    models
        .entry("secondmodel".to_string())
        .or_insert_with(|| make_model("myprovider", 10));
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel"), make_member("secondmodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: Some(vec!["secondmodel".to_string()]),
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a failover exclusion naming a real pool member must validate"
    );
}

#[test]
fn test_validate_operator_token_secret_module_checked() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    let mut entry = config::AuthChainEntry::bare(config::operator_provider());
    entry.token = Some(config::SecretRef {
        module: "env".to_string(),
        settings: serde_json::Map::new(),
    });
    auth.admin_auth = vec![entry];
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("an env secret ref without settings.key must fail");

    let path = format!("auth.admin_auth.{}.token", config::operator_provider());
    assert!(
        errs.iter()
            .any(|e| e.contains(&path) && e.contains("requires settings.key")),
        "expected the env-shape error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_admin_token_without_module() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    let mut entry = config::AuthChainEntry::bare(config::operator_provider());
    entry.token = Some(config::SecretRef::env("BUSBAR_ADMIN_TOKEN"));
    auth.admin_auth = vec![entry];
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("must be a boot error");

    let op = config::operator_provider();
    assert!(
        errs.iter().any(|e| *e
            == format!(
                "an {op} token is configured but this binary was built WITHOUT the \
                 `auth-{op}` feature — the admin API would be silently disabled. Rebuild \
                 with default features or wire an external admin auth module."
            )),
        "{errs:?}"
    );
}

#[test]
fn test_validate_rejects_zero_rate_sweep_interval() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.limits.rate_sweep_interval = 0;
    let err = validate(&cfg).expect_err("rate_sweep_interval: 0 must be rejected at validation");
    assert!(
        err.iter()
            .any(|e| e.contains("advanced.rate_sweep_interval")),
        "the error must name advanced.rate_sweep_interval, got: {err:?}"
    );

    cfg.limits.rate_sweep_interval = busbar_kernel::config::DEFAULT_RATE_SWEEP_INTERVAL;
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("rate_sweep_interval")),
            "the default sweep interval must not error; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_chain_tokens_module_removed_message() {
    for legacy in ["tokens", "static-tokens"] {
        let (providers, models, pools) = valid_maps();
        let mut cfg = make_root_cfg(providers, models, pools);
        cfg.auth = Some(make_auth_chain(
            &[legacy],
            busbar_kernel::auth::UpstreamCreds::Own,
        ));
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("chain module '{legacy}' must fail validation"));
        assert!(
            errs.iter().any(|e| e.contains(&format!("'{legacy}'"))
                && e.contains("REMOVED")
                && e.contains("1.5.0")
                && e.contains("keys")),
            "expected the REMOVED-in-1.5.0 message for '{legacy}' naming `keys`; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_chain_unknown_module_rejected_keys_accepted() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &["okta"],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    assert!(
        validate(&cfg).is_ok(),
        "a plugin-shaped (non-keys, non-removed-legacy) chain module must NOT be rejected at this \
         pre-registry layer; got: {:?}",
        validate(&cfg)
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &["tokens"],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    let errs = validate(&cfg).expect_err("the removed 'tokens' module must still fail validation");
    assert!(
        errs.iter().any(|e| e.contains("was REMOVED in 1.5.0")),
        "expected the removed-module migration message; got: {errs:?}"
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &["keys"],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    assert!(
        validate(&cfg).is_ok(),
        "auth.chain: [keys] must validate; got: {:?}",
        validate(&cfg)
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &[],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    assert!(
        validate(&cfg).is_ok(),
        "an empty auth chain must validate (open front door)"
    );
}

#[test]
fn test_1_5_2_keys_chain_without_mint_path_is_boot_error() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    auth.chain = vec![busbar_kernel::config::AuthChainEntry::bare(
        busbar_kernel::config::KEYS_MODULE,
    )];
    auth.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));
    cfg.auth = Some(auth);
    let errs =
        validate(&cfg).expect_err("keys chain with no usable mint path must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("no admin credential can mint")),
        "expected the mint-path boot error; got: {errs:?}"
    );
}

#[test]
fn test_keys_chain_without_signing_key_is_boot_error() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    auth.chain = vec![busbar_kernel::config::AuthChainEntry::bare(
        busbar_kernel::config::KEYS_MODULE,
    )];
    auth.admin_auth = vec![];
    assert!(
        auth.signing_key.is_none(),
        "the RED case sets no signing_key"
    );
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("keys chain without a signing_key must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.signing_key is required")),
        "expected the signing-key requirement boot error; got: {errs:?}"
    );

    let mut auth_ok = busbar_kernel::config::AuthCfg::default_none();
    auth_ok.chain = vec![busbar_kernel::config::AuthChainEntry::bare(
        busbar_kernel::config::KEYS_MODULE,
    )];
    auth_ok.admin_auth = vec![];
    auth_ok.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));
    cfg.auth = Some(auth_ok);
    assert!(
        validate(&cfg).is_ok(),
        "a keys chain WITH signing_key + a usable mint path must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_1_5_2_oidc_chain_needs_no_mint_path() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &["test-idp-double"],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    let r = validate(&cfg);
    assert!(
        r.is_ok(),
        "an oidc (externally-issued) chain must need no mint path; got: {r:?}"
    );
}

#[test]
fn test_1_5_2_keys_chain_external_admin_needs_full_scope_to_mint() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    auth.chain = vec![busbar_kernel::config::AuthChainEntry::bare(
        busbar_kernel::config::KEYS_MODULE,
    )];
    auth.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));

    auth.admin_auth = vec![busbar_kernel::config::AuthChainEntry::bare(
        "test-external-idp",
    )];
    cfg.auth = Some(auth);
    let errs = validate(&cfg)
        .expect_err("a keys chain whose only admin module cannot mint must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("no admin credential can mint")),
        "expected the mint-path boot error for the github/ldap gap; got: {errs:?}"
    );

    let mut auth_ok = busbar_kernel::config::AuthCfg::default_none();
    auth_ok.chain = vec![busbar_kernel::config::AuthChainEntry::bare(
        busbar_kernel::config::KEYS_MODULE,
    )];
    auth_ok.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));
    let mut admin = busbar_kernel::config::AuthChainEntry::bare("test-external-idp");
    admin.max_admin_scope = Some("full".to_string());
    auth_ok.admin_auth = vec![admin];
    cfg.auth = Some(auth_ok);
    assert!(
        validate(&cfg).is_ok(),
        "an external admin module with max_admin_scope: full is a usable mint path; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_token_on_non_operator_entry_rejected() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    let mut entry = config::AuthChainEntry::bare("keys");
    entry.token = Some(config::SecretRef::env("MISPLACED_SECRET"));
    auth.chain = vec![entry];
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("token on a non-operator entry must fail validation");

    let op = config::operator_provider();
    assert!(
        errs.iter().any(|e| *e
            == format!(
                "auth chain entry 'keys' sets `token:`, which belongs to the built-in \
                 `{op}` module only; move it, e.g.:\n\n    admin_auth:\n      - \
                 {op}: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n"
            )),
        "expected the misplaced-token error with its relocation hint; got: {errs:?}"
    );
}

#[test]
fn test_validate_passthrough_warns_on_nonempty_configured_key() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let leak_env = "BUSBAR_T_R22_PASSTHROUGH_LEAK_KEY";
    let vendor_b_env = "BUSBAR_T_R22_PASSTHROUGH_VENDOR_B_KEY";
    std::env::set_var(leak_env, "sk-busbar-secret-should-not-leak");
    std::env::remove_var(vendor_b_env);

    let mut providers = HashMap::new();
    providers.insert(
        "leaky".to_string(),
        make_provider(proto_a(), "https://api.example.com", leak_env),
    );
    providers.insert(
        "vendor-b".to_string(),
        make_provider(
            shipped_protocol(3),
            "https://vendor-b.example.com",
            vendor_b_env,
        ),
    );
    let mut models = HashMap::new();
    models.insert("leakymodel".to_string(), make_model("leaky", 10));
    models.insert("vendorbmodel".to_string(), make_model("vendor-b", 10));
    let mut cfg = make_root_cfg(providers, models, HashMap::new());
    cfg.auth = Some(make_auth_chain(
        &[],
        busbar_kernel::auth::UpstreamCreds::Passthrough,
    ));

    cfg.upstream_credentials = busbar_kernel::auth::UpstreamCreds::Passthrough;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));

    std::env::remove_var(leak_env);

    assert!(
        result.is_ok(),
        "passthrough + non-empty key is a warning, not a hard error; got: {result:?}"
    );

    let msgs = cap.messages();
    assert!(
        msgs.iter()
            .any(|m| m.contains("inert dead config") && m.contains("leaky")),
        "expected a passthrough inert-configured-key warning naming the 'leaky' provider; got: {msgs:?}"
    );

    assert!(
            !msgs.iter().any(|m| m.contains("vendor-b")),
            "a provider whose api_key_env resolves empty must NOT warn (legit signature-auth passthrough); got: {msgs:?}"
        );
}

#[test]
fn test_validate_passthrough_no_warn_when_all_keys_empty() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let empty_env = "BUSBAR_T_R22_PASSTHROUGH_EMPTY_KEY";
    std::env::remove_var(empty_env);

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://api.example.com", empty_env),
    );
    let mut models = HashMap::new();
    models.insert("m".to_string(), make_model("p", 10));
    let mut cfg = make_root_cfg(providers, models, HashMap::new());
    cfg.auth = Some(make_auth_chain(
        &[],
        busbar_kernel::auth::UpstreamCreds::Passthrough,
    ));

    cfg.upstream_credentials = busbar_kernel::auth::UpstreamCreds::Passthrough;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));

    assert!(result.is_ok(), "passthrough with empty keys must validate");
    let msgs = cap.messages();
    assert!(
        !msgs.iter().any(|m| m.contains("inert dead config")),
        "no inert-configured-key warning may fire when every api_key_env resolves empty — the guard \
         keys off the RESOLVED value, not the presence of passthrough mode; got: {msgs:?}"
    );
}

#[test]
fn test_validate_empty_chain_carries_no_requirement() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &[],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    assert!(
        validate(&cfg).is_ok(),
        "an empty auth chain carries no token requirement"
    );
}

#[test]
fn test_reject_cidr_metadata_entries() {
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://api.vendor-a.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["169.254.0.0/16".to_string()]);
    let errs =
        validate(&cfg).expect_err("a CIDR blocked_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("security.blocked_metadata_hosts")
                && e.contains("169.254.0.0/16")
                && e.contains("CIDR")),
        "expected a CIDR rejection naming the key+value; got: {errs:?}"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://api.vendor-a.example.com", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["10.0.0.0/8".to_string()];
    let errs = validate(&cfg).expect_err("a CIDR allow_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("security.allow_metadata_hosts") && e.contains("10.0.0.0/8")),
        "expected a CIDR rejection naming security.allow_metadata_hosts; got: {errs:?}"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider_allow_hosts("https://api.vendor-a.example.com", &["169.254.169.254/32"]),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg)
        .expect_err("a CIDR per-provider allow_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("provider 'prov' allow_metadata_hosts")
                && e.contains("169.254.169.254/32")),
        "expected a CIDR rejection naming the provider's allow_metadata_hosts; got: {errs:?}"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://api.vendor-a.example.com", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.blocked_metadata_hosts = vec!["169.254.169.254".to_string()];
    cfg.allow_metadata_hosts = vec!["metadata.example.com".to_string()];
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("CIDR")),
            "exact IP/hostname entries must not trip the CIDR guard; got: {errs:?}"
        );
    }
}

const NO_HOST_ENTRIES: [&str; 10] = [
    "b\u{fc}cher\u{ff1c}.example",
    "%6c%6fcalhost",
    "169%2e254%2e169%2e254",
    "1.2.3.4.5",
    "999.1.1.1",
    "foo.127",
    "x.0",
    "db.1",
    "0x",
    "\u{ff11}.\u{ff12}.\u{ff13}.\u{ff14}.\u{ff15}",
];

fn no_host_entries_baseline() -> RootCfg {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &[],
        busbar_kernel::auth::UpstreamCreds::Own,
    ));
    cfg
}

#[test]
fn test_a_metadata_entry_naming_no_host_refuses_startup_naming_the_entry() {
    let entries: Vec<String> = NO_HOST_ENTRIES.iter().map(|e| e.to_string()).collect();
    let mut cfg = no_host_entries_baseline();
    cfg.blocked_metadata_hosts = entries.clone();
    cfg.allow_metadata_hosts = entries.clone();
    cfg.providers
        .get_mut("myprovider")
        .expect("valid_maps names `myprovider`")
        .allow_metadata_hosts = entries.clone();

    let errs = validate(&cfg).expect_err("an entry naming no usable host refuses startup");
    for key in [
        "security.blocked_metadata_hosts",
        "security.allow_metadata_hosts",
        "provider 'myprovider' allow_metadata_hosts",
    ] {
        for entry in NO_HOST_ENTRIES {
            let head = format!("{key} entry '{entry}' names no usable host: ");
            let lines: Vec<&String> = errs.iter().filter(|e| e.starts_with(&head)).collect();
            assert_eq!(lines.len(), 1, "one error for `{entry}` in {key}: {errs:?}");
            assert!(
                lines[0].contains("so it could never match a destination. "),
                "the error says why the entry is refused: {}",
                lines[0]
            );
        }
    }
    assert_eq!(
        errs.iter()
            .filter(|e| e.contains("names no usable host"))
            .count(),
        3 * NO_HOST_ENTRIES.len(),
        "exactly one error per entry per key: {errs:?}"
    );

    for said in [
        "security.blocked_metadata_hosts entry 'db.1' names no usable host: its last label reads \
         as a number but it is no IPv4 address a URL client reads, so it could never match a \
         destination. Write an address as a dotted quad, or a name whose last label is not a \
         number, or remove it",
        "security.allow_metadata_hosts entry '%6c%6fcalhost' names no usable host: it holds a '%' \
         escape outside an IPv6 zone id, which a URL client decodes before it dials, so it could \
         never match a destination. Write the host decoded (the name or address it spells), or \
         remove it",
        "provider 'myprovider' allow_metadata_hosts entry 'b\u{fc}cher\u{ff1c}.example' names no \
         usable host: UTS #46 refuses it, so it is no name a URL client would dial, so it could \
         never match a destination. Write the host in ASCII (an internationalized name as its \
         punycode 'xn--' form), or remove it",
    ] {
        assert!(errs.iter().any(|e| e == said), "{said}: {errs:?}");
    }

    let mut cfg = no_host_entries_baseline();
    cfg.blocked_metadata_hosts = vec![
        "\u{ff11}\u{ff10}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}".to_string(),
        "169.254.169.254".to_string(),
        "2852039166".to_string(),
        "0177.0.0.1".to_string(),
        "fd00:ec2::254".to_string(),
        "fe80::1%eth0".to_string(),
        "metadata.google.internal.".to_string(),
    ];
    cfg.allow_metadata_hosts = vec![
        "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}.example".to_string(),
        "metadata.example.com".to_string(),
    ];
    let result = validate(&cfg);
    assert!(result.is_ok(), "mappable entries boot; got: {result:?}");
}

#[test]
fn test_a_dropped_metadata_entry_lifts_no_real_target() {
    let entries: Vec<String> = NO_HOST_ENTRIES.iter().map(|e| e.to_string()).collect();
    for target in [
        "https://169.254.169.254/latest/meta-data/",
        "https://169.254.170.2/v2/credentials",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://100.100.100.200/latest/meta-data/",
    ] {
        assert!(
            ssrf_blocked_host(target, &entries, false, &entries).is_some(),
            "a dropped allow entry must lift nothing: `{target}` stays blocked"
        );
    }
    let mut cfg = no_host_entries_baseline();
    cfg.blocked_metadata_hosts = entries.clone();
    cfg.allow_metadata_hosts = entries.clone();
    let provider = cfg
        .providers
        .get_mut("myprovider")
        .expect("valid_maps names `myprovider`");
    provider.allow_metadata_hosts = entries.clone();
    provider.base_url = "https://169.254.169.254/".into();
    let errs = validate(&cfg).expect_err("the IMDS address stays refused");
    assert!(
        errs.iter()
            .any(|e| e.contains("targets a blocked cloud-metadata host")),
        "the metadata check still refuses the IMDS base_url: {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("names no usable host")),
        "an entry naming no usable host is refused too: {errs:?}"
    );
}

#[test]
fn test_a_cidr_metadata_entry_is_refused_with_the_1_5_5_text() {
    let mut cfg = no_host_entries_baseline();
    cfg.blocked_metadata_hosts = vec!["169.254.0.0/16".to_string()];
    cfg.allow_metadata_hosts = vec!["10.0.0.0/8".to_string()];
    cfg.providers
        .get_mut("myprovider")
        .expect("valid_maps names `myprovider`")
        .allow_metadata_hosts = vec!["169.254.169.254/32".to_string()];
    let errs = validate(&cfg).expect_err("a CIDR entry is refused at boot, as on 1.5.5");
    for (key, entry) in [
        ("security.blocked_metadata_hosts", "169.254.0.0/16"),
        ("security.allow_metadata_hosts", "10.0.0.0/8"),
        (
            "provider 'myprovider' allow_metadata_hosts",
            "169.254.169.254/32",
        ),
    ] {
        let said = format!(
            "{key} entry '{entry}' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16')"
        );
        assert!(errs.iter().any(|e| e == &said), "{said}: {errs:?}");
    }
    assert!(
        !errs.iter().any(|e| e.contains("names no usable host")),
        "a CIDR entry gets only its 1.5.5 refusal: {errs:?}"
    );
}

#[test]
fn test_global_allow_overrides_blocked_metadata_hosts() {
    let blocked = vec!["10.77.77.77".to_string()];
    let allow = vec!["10.77.77.77".to_string()];
    assert!(
        ssrf_blocked_host("https://10.77.77.77/", &allow, false, &blocked).is_none(),
        "global allow_metadata_hosts must override blocked_metadata_hosts"
    );

    assert!(
        ssrf_blocked_host("https://10.77.77.77/", &[], false, &blocked).is_some(),
        "the host must be blocked when not allow-listed"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://10.77.77.77/", "API_KEY"),
    );
    let mut cfg = make_root_cfg_with_blocked(providers, vec!["10.77.77.77".to_string()]);
    cfg.allow_metadata_hosts = vec!["10.77.77.77".to_string()];
    assert!(
        validate(&cfg).is_ok(),
        "global allow_metadata_hosts must override blocked_metadata_hosts in validate(); got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_allow_all_metadata_beats_nonempty_blocked_list() {
    let blocked = vec!["10.0.0.7".to_string(), "metadata.x.example".to_string()];
    for base in [
        "https://169.254.169.254/",
        "https://10.0.0.7/",
        "https://metadata.x.example/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], true, &blocked).is_none(),
            "allow_all_metadata must unblock '{base}' even with a non-empty blocked list"
        );
    }
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://10.0.0.7/", "API_KEY"),
    );
    let mut cfg = make_root_cfg_with_blocked(providers, vec!["10.0.0.7".to_string()]);
    cfg.allow_all_metadata = true;
    assert!(
        validate(&cfg).is_ok(),
        "allow_all_metadata must win over a non-empty blocked_metadata_hosts; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_ssrf_blocks_backslash_authority_bypass() {
    for blocked in [
        "https://169.254.169.254\\a.b",
        "https://169.254.169.254\\x.allowed.com/v1/messages",
        "https://100.100.100.200\\evil.example.com/",
        "https://metadata.google.internal\\x.allowed.com",
        "https://169.254.169.254\\@allowed.com/path",
    ] {
        assert!(
            ssrf_blocked_host(blocked, &[], false, &[]).is_some(),
            "expected '{blocked}' to be flagged: the backslash terminates the authority \
                 (reqwest rewrites \\ to /), so the real host is the metadata target before it"
        );
    }

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(
            proto_a(),
            "https://169.254.169.254\\x.allowed.com",
            "API_KEY",
        ),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("backslash-authority base_url must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected a metadata-host error naming the real metadata host; got: {errs:?}"
    );
}

#[test]
fn test_ssrf_blocks_embedded_tab_newline_bypass() {
    for blocked in [
        "https://169.254.169\t.254/v1/messages",
        "https://169.254.169.254\t/v1/messages",
        "https://169.254\n.169.254/v1/messages",
        "https://169.254.169\r.254/v1/messages",
    ] {
        assert!(
            ssrf_blocked_host(blocked, &[], false, &[]).is_some(),
            "expected '{blocked}' to be flagged: stripping the embedded tab/newline/CR (as \
                 the WHATWG parser and reqwest's `url` crate do) reveals the real metadata host"
        );
    }

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://169.254.169\t.254", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("embedded-tab base_url must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected a metadata-host error naming the real metadata host; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_path_override_host_fusion() {
    let mut providers = HashMap::new();
    let mut fused = make_provider(proto_b(), "https://api.example.com", "API_KEY");
    fused.path = Some(".evil.com/v1/chat/completions".to_string());
    providers.insert("fused".to_string(), fused);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("a host-fusing path override must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("fused") && e.contains("must begin with '/'")),
        "expected a leading-slash path error for 'fused'; got: {errs:?}"
    );

    let mut providers2 = HashMap::new();
    let mut imds = make_provider(proto_b(), "https://api.example.com", "API_KEY");
    imds.path = Some("@169.254.169.254/latest/meta-data".to_string());
    providers2.insert("imds".to_string(), imds);
    let cfg2 = make_root_cfg(providers2, HashMap::new(), HashMap::new());
    let errs2 = validate(&cfg2).expect_err("a userinfo-flip path override must fail validation");
    assert!(
        errs2
            .iter()
            .any(|e| e.contains("imds") && e.contains("must begin with '/'")),
        "expected a leading-slash path error for the userinfo-flip override; got: {errs2:?}"
    );
}

#[test]
fn test_validate_accepts_well_formed_path_override() {
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_b(), "https://api.example.com/api/paas/v4", "API_KEY");
    p.path = Some("/chat/completions".to_string());
    providers.insert("ok".to_string(), p);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "a leading-slash path override on a public host must validate"
    );
}

#[test]
fn test_validate_rejects_zero_weight_member() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut zero = make_member("mymodel");
    zero.weight = 0;
    pools.insert("mypool".to_string(), make_pool(vec![zero]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a weight:0 pool member must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("weight must be >= 1") && e.contains("mymodel")),
        "expected a weight:0 rejection for 'mymodel'; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_empty_pool_members() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("emptypool".to_string(), make_pool(vec![]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an empty-members pool must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("emptypool") && e.contains("no members")),
        "expected a no-members rejection for 'emptypool'; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_pool_with_at_least_one_member() {
    let (providers, models, pools) = valid_maps();
    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);
    if let Err(errs) = &result {
        assert!(
            !errs.iter().any(|e| e.contains("no members")),
            "a pool with a member must not trip the empty-members guard; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_accepts_positive_weight_member() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut w = make_member("mymodel");
    w.weight = 5;
    pools.insert("mypool".to_string(), make_pool(vec![w]));
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a positive-weight pool member must validate"
    );
}

#[test]
fn test_validate_rejects_https_internal_base_url() {
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://169.254.169.254/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("https IMDS base_url must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected an SSRF/metadata-host error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_unknown_fallback_pool() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool(
        "does_not_exist".to_string(),
    ));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("on_exhausted referencing an unknown pool must fail");
    assert!(
        errs.iter().any(
            |e| e.contains("on_exhausted references unknown fallback pool")
                && e.contains("does_not_exist")
        ),
        "expected a dangling-fallback-pool error; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_existing_fallback_pool() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("backup".to_string()));
    pools.insert("mypool".to_string(), pool);

    pools.insert(
        "backup".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "on_exhausted referencing an existing pool must validate"
    );
}

#[test]
fn test_validate_accepts_queue_within_budget() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);

    pool.on_exhausted = Some(config::OnExhaustedCfg::Queue { max_ms: 250 });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a queue max_ms within the failover budget must validate"
    );
}

#[test]
fn test_validate_rejects_queue_max_ms_zero() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg::Queue { max_ms: 0 });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a 0 max_ms queue must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("queue.max_ms must be > 0") && e.contains("mypool")),
        "expected a max_ms>0 error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_queue_max_ms_exceeding_resolved_budget() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 1,
        exclusions: None,
        max_hops: 3,
    });
    pool.on_exhausted = Some(config::OnExhaustedCfg::Queue { max_ms: 2000 });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg)
        .expect_err("a max_ms above the resolved failover budget must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("exceeds the resolved failover budget")
            && e.contains("mypool")),
        "expected a budget-exceeded error resolved against the pool's own 1s timeout; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_queue_max_ms_equal_to_resolved_budget() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);

    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 1,
        exclusions: None,
        max_hops: 3,
    });
    pool.on_exhausted = Some(config::OnExhaustedCfg::Queue { max_ms: 1000 });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "max_ms EXACTLY equal to the resolved failover budget must be accepted (only > is rejected)"
    );
}

#[test]
fn test_validate_rejects_failover_timeout_secs_over_max() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: config::MAX_FAILOVER_DEADLINE_SECS + 1,
        exclusions: None,
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs =
        validate(&cfg).expect_err("a failover.timeout_secs above the 24h maximum must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("exceeds the maximum") && e.contains("mypool")),
        "expected a timeout_secs-too-large error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_self_referential_fallback_pool() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);

    pool.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("mypool".to_string()));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a self-referential fallback pool must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("references itself as its fallback pool") && e.contains("mypool")),
        "expected a self-referential fallback-pool error; got: {errs:?}"
    );

    assert!(
        !errs
            .iter()
            .any(|e| e.contains("references unknown fallback pool")),
        "a self-reference must not be reported as an unknown fallback pool; got: {errs:?}"
    );

    assert!(
        !errs
            .iter()
            .any(|e| e.contains("fallback_pool cycle detected")),
        "a self-loop must be reported once by Rule 7, not again by Rule 7b's cycle detector; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_two_pool_fallback_cycle() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("pool_b".to_string()));
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("pool_a".to_string()));
    pools.insert("pool_a".to_string(), a);
    pools.insert("pool_b".to_string(), b);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an A<->B fallback cycle must fail validation");
    let cycle_errs: Vec<&String> = errs
        .iter()
        .filter(|e| e.contains("fallback_pool cycle detected"))
        .collect();
    assert_eq!(
        cycle_errs.len(),
        1,
        "an A<->B cycle must be reported exactly once; got: {errs:?}"
    );
    assert!(
        cycle_errs[0].contains("pool_a") && cycle_errs[0].contains("pool_b"),
        "the cycle diagnostic must name both ring members; got: {}",
        cycle_errs[0]
    );
}

#[test]
fn test_validate_rejects_three_pool_fallback_cycle() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    for (name, next) in [("p1", "p2"), ("p2", "p3"), ("p3", "p1")] {
        let mut p = make_pool(vec![make_member("mymodel")]);
        p.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool(next.to_string()));
        pools.insert(name.to_string(), p);
    }
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a 3-pool fallback cycle must fail validation");
    let cycle_errs: Vec<&String> = errs
        .iter()
        .filter(|e| e.contains("fallback_pool cycle detected"))
        .collect();
    assert_eq!(
        cycle_errs.len(),
        1,
        "a 3-pool cycle must be reported exactly once; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_acyclic_fallback_chain() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("chain_b".to_string()));
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("chain_c".to_string()));
    let c = make_pool(vec![make_member("mymodel")]);
    pools.insert("chain_a".to_string(), a);
    pools.insert("chain_b".to_string(), b);
    pools.insert("chain_c".to_string(), c);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "an acyclic A->B->C fallback chain must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_accepts_diamond_fallback_no_cycle() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("dia_c".to_string()));
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg::FallbackPool("dia_c".to_string()));
    let c = make_pool(vec![make_member("mymodel")]);
    pools.insert("dia_a".to_string(), a);
    pools.insert("dia_b".to_string(), b);
    pools.insert("dia_c".to_string(), c);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a converging (diamond) fallback graph must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_accepts_session_affinity_mode() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.affinity = Some(config::AffinityCfg {
        mode: config::AffinityMode::Session,
        header_name: Some("x-session-id".to_string()),
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "the supported 'session' affinity mode must validate"
    );
}

#[test]
fn test_validate_accepts_uppercase_url_scheme() {
    let (mut providers, models, _) = valid_maps();

    if let Some((_, p)) = providers.iter_mut().next() {
        p.base_url = "HTTPS://api.example.com".to_string();
    }
    let cfg = make_root_cfg(providers, models, HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "an uppercase HTTPS:// scheme is RFC-valid and must not be rejected: {:?}",
        validate(&cfg)
    );

    assert!(scheme_is("HTTPS://h", "https"));
    assert!(scheme_is("Http://h", "http"));
    assert!(!scheme_is("httpsx://h", "https"));
}

#[test]
fn a_base_url_userinfo_is_accepted_and_no_validation_error_repeats_it() {
    const PLANTED: &str = "svcuser:hunter2-P4ss@";
    let with_base = |base_url: String, path: Option<&str>, path_base: Option<&str>| {
        let (mut providers, models, _) = valid_maps();
        let p = providers.get_mut("myprovider").expect("the provider");
        p.base_url = base_url;
        p.path = path.map(str::to_string);
        p.path_base = path_base.map(str::to_string);
        validate(&make_root_cfg(providers, models, HashMap::new()))
    };

    let accepted = with_base(format!("https://{PLANTED}api.example.com"), None, None);
    assert!(
        accepted.is_ok(),
        "a base_url spelling user:pass@ validates, as in 1.5.5: {accepted:?}"
    );

    let secure = format!("https://{PLANTED}api.example.com");

    let plaintext = secure.replacen("s://", "://", 1);
    let planted = [
        (
            format!("ftp://{PLANTED}api.example.com"),
            None,
            None,
            "api.example.com",
        ),
        (plaintext, None, None, "api.example.com"),
        (
            format!("https://{PLANTED}169.254.169.254"),
            Some("/v1"),
            Some("/v1beta"),
            "169.254.169.254",
        ),
    ];
    for (base_url, path, path_base, host) in planted {
        let errors = with_base(base_url, path, path_base).expect_err("the planted base is refused");
        let about: Vec<&String> = errors.iter().filter(|e| e.contains("base_url")).collect();
        assert!(
            !about.is_empty(),
            "a base_url refusal was written: {errors:?}"
        );
        for e in &errors {
            assert!(
                !e.contains("hunter2") && !e.contains("svcuser"),
                "a validation error repeated the planted spelling: {e}"
            );
        }
        assert!(
            about.iter().all(|e| e.contains(host)),
            "each refusal still names the host it is about: {about:?}"
        );
    }

    let with_token_url = |token_url: String| {
        let mut providers = HashMap::new();
        let mut p = make_provider(proto_b(), "https://api.example.com", "API_KEY");
        p.token_url = Some(token_url);
        p.scope = Some("api://x/.default".into());

        p.auth = Some(
            serde_yaml::from_str(include_str!("../../../../busbar-kernel/src/config_validate/tests/fixtures/client_credentials_style.yaml"))
                .expect("a provider style"),
        );
        providers.insert("myprovider".to_string(), p);
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("myprovider", 10));
        let mut pools = HashMap::new();
        pools.insert("p".to_string(), make_pool(vec![make_member("m")]));
        validate(&make_root_cfg(providers, models, pools))
    };
    let accepted = with_token_url(format!("https://{PLANTED}login.example.com/token"));
    assert!(
        accepted.is_ok(),
        "a token_url spelling user:pass@ validates, as in 1.5.5: {accepted:?}"
    );
    let plaintext = format!("https://{PLANTED}login.example.com/token").replacen("s://", "://", 1);
    for (token_url, host) in [
        (
            format!("ftp://{PLANTED}login.example.com/token"),
            "login.example.com",
        ),
        (plaintext, "login.example.com"),
        (
            format!("https://{PLANTED}169.254.169.254/token"),
            "169.254.169.254",
        ),
    ] {
        let errors = with_token_url(token_url).expect_err("the planted endpoint is refused");
        let about: Vec<&String> = errors.iter().filter(|e| e.contains("token_url")).collect();
        assert!(
            !about.is_empty(),
            "a token_url refusal was written: {errors:?}"
        );
        for e in &errors {
            assert!(
                !e.contains("hunter2") && !e.contains("svcuser"),
                "a validation error repeated the planted spelling: {e}"
            );
        }
        assert!(
            about.iter().all(|e| e.contains(host)),
            "each refusal still names the host it is about: {about:?}"
        );
    }
}

#[test]
fn test_validate_rejects_empty_affinity_header_name() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.affinity = Some(config::AffinityCfg {
        mode: config::AffinityMode::Session,
        header_name: Some(String::new()),
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let err = validate(&cfg).expect_err("empty header_name must be rejected");
    assert!(
        err.iter().any(|e| e.contains("must not be empty")),
        "the error must name the empty-header-name problem: {err:?}"
    );
}

#[test]
fn test_validate_affinity_header_names_follow_the_http_token_grammar() {
    for (name, accepted) in [
        ("X-Session_1", true),
        ("!#$%&'*+-.^_`|~", true),
        ("X Session", false),
        ("X:Session", false),
        ("X\tSession", false),
        ("X\r\nSession", false),
        ("X\0Session", false),
        ("X/Session", false),
        ("X\u{7f}Session", false),
    ] {
        let (providers, models, _) = valid_maps();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.affinity = Some(config::AffinityCfg {
            mode: config::AffinityMode::Session,
            header_name: Some(name.to_string()),
        });
        let cfg = make_root_cfg(
            providers,
            models,
            HashMap::from([("mypool".to_string(), pool)]),
        );
        let result = validate(&cfg);
        if accepted {
            assert!(result.is_ok(), "valid field-name {name:?}: {result:?}");
        } else {
            let errors = result.expect_err("invalid HTTP field-name must fail validation");
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains("affinity.header_name")),
                "{name:?}: {errors:?}"
            );
        }
    }
}

#[test]
fn test_pool_member_model_with_unresolvable_provider_is_not_unknown_model() {
    let mut providers = HashMap::new();
    providers.insert(
        "realprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let mut models = HashMap::new();
    models.insert("definedmodel".to_string(), make_model("ghostprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("definedmodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).unwrap_err_or_default(
        "a model with an unresolvable provider must fail validation".to_string(),
    );

    assert!(
        errs.iter().any(|e| e.contains("definedmodel")
            && e.contains("references unknown provider")
            && e.contains("ghostprovider")),
        "expected the model-level unknown-provider error; got: {errs:?}"
    );

    assert!(
        !errs
            .iter()
            .any(|e| e.contains("references unknown model 'definedmodel'")),
        "a defined model must not be reported as an unknown model; got: {errs:?}"
    );

    assert!(
        errs.iter().any(|e| e.contains("mypool")
            && e.contains("definedmodel")
            && e.contains("provider is unresolvable")),
        "expected a pool-member 'provider is unresolvable' diagnostic; got: {errs:?}"
    );
}

#[test]
fn test_pool_member_truly_unknown_model_still_reports_unknown_model() {
    let mut providers = HashMap::new();
    providers.insert(
        "realprovider".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );

    let models = HashMap::new();

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("nosuchmodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg)
        .unwrap_err_or_default("an undefined member model must fail validation".to_string());

    assert!(
        errs.iter()
            .any(|e| e.contains("references unknown model") && e.contains("nosuchmodel")),
        "a genuinely undefined model must still be reported as unknown; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("provider is unresolvable")),
        "an undefined model must not get the provider-unresolvable message; got: {errs:?}"
    );
}

fn plugin_pool_cfg(plugin: &str) -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let mut pool = make_pool(vec![make_member("m1")]);
    pool.gates = vec!["h".to_string()];
    let mut pools = HashMap::new();
    pools.insert("p1".to_string(), pool);
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("h".to_string(), gate_hook(plugin, 150));
    cfg
}

fn gate_hook(plugin: &str, timeout_ms: u64) -> config::HookCfg {
    config::HookCfg {
        kind: config::HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms,
        on_error: "weighted".to_string(),
        prompt: config::PromptAccess::No,
        user: config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

fn hooks_test_cfg() -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    make_root_cfg(providers, models, pools)
}

#[test]
fn test_pool_and_all_pools_undefined_hook_ref_rejected() {
    let mut cfg = hooks_test_cfg();

    cfg.pools
        .get_mut("p1")
        .unwrap()
        .gates
        .push("no-such-hook".to_string());

    cfg.global_hooks.push("also-missing".to_string());
    let errs = validate(&cfg).expect_err("undefined hook references must fail validate");
    let joined = errs.join("\n");
    assert!(
        joined.contains("no-such-hook") && joined.contains("unknown hook"),
        "the pool reference to an undefined hook must be named: {joined}"
    );
    assert!(
        joined.contains("also-missing"),
        "the all-pools reference to an undefined hook must be named: {joined}"
    );
}

#[test]
fn test_hook_on_error_unknown_name_rejected() {
    let mut cfg = hooks_test_cfg();
    let mut h = gate_hook("test-hook", 150);
    h.on_error = "nonexistent".to_string();
    cfg.hooks.insert("a".to_string(), h);
    let errs = validate(&cfg).expect_err("an unknown on_error name must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("unknown fallback 'nonexistent'")),
        "{errs:?}"
    );
}

#[test]
fn test_hook_on_error_tap_fallback_rejected() {
    let mut cfg = hooks_test_cfg();
    let mut gate = gate_hook("test-hook", 150);
    gate.on_error = "watcher".to_string();
    let mut tap = gate_hook("test-hook", 150);
    tap.kind = config::HookKind::Tap;
    cfg.hooks.insert("a".to_string(), gate);
    cfg.hooks.insert("watcher".to_string(), tap);
    let errs = validate(&cfg).expect_err("a tap fallback must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("fallback 'watcher' is a tap")),
        "{errs:?}"
    );
}

#[test]
fn test_hook_on_error_cycle_rejected() {
    let mut cfg = hooks_test_cfg();
    let mut a = gate_hook("test-hook", 150);
    a.on_error = "b".to_string();
    let mut b = gate_hook("test-hook", 150);
    b.on_error = "a".to_string();
    cfg.hooks.insert("a".to_string(), a);
    cfg.hooks.insert("b".to_string(), b);
    let errs = validate(&cfg).expect_err("an on_error cycle must be rejected");
    assert!(
        errs.iter().any(|e| e.contains("does not terminate")),
        "{errs:?}"
    );

    let mut cfg = hooks_test_cfg();
    let mut selfy = gate_hook("test-hook", 150);
    selfy.on_error = "s".to_string();
    cfg.hooks.insert("s".to_string(), selfy);
    let errs = validate(&cfg).expect_err("a self-referencing on_error must be rejected");
    assert!(
        errs.iter().any(|e| e.contains("does not terminate")),
        "{errs:?}"
    );
}

#[test]
fn test_hook_on_error_terminating_chain_ok() {
    let mut cfg = hooks_test_cfg();
    let mut a = gate_hook("test-hook", 150);
    a.on_error = "b".to_string();
    let b = gate_hook("test-hook", 150);
    cfg.hooks.insert("a".to_string(), a);
    cfg.hooks.insert("b".to_string(), b);
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("on_error")),
            "a terminating chain must not trip the on_error rule; got: {errs:?}"
        );
    }

    let mut cfg = hooks_test_cfg();
    let mut c = gate_hook("test-hook", 150);
    c.on_error = "cheapest".to_string();
    cfg.hooks.insert("c".to_string(), c);
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("on_error")),
            "a strategy fallback must be accepted when a ranking row is linked; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_reserved_name_rejected() {
    crate::dist_root_install::install();
    for reserved in [
        "weighted",
        "cheapest",
        "fastest",
        "least_busy",
        "usage",
        "tokens",
        config::operator_provider(),
    ] {
        let mut providers = HashMap::new();
        providers.insert(
            "prov".to_string(),
            make_provider(proto_a(), "https://api.example.com", "API_KEY"),
        );
        let mut models = HashMap::new();
        models.insert("m1".to_string(), make_model("prov", 4));
        let pools = {
            let mut p = HashMap::new();
            p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
            p
        };
        let mut cfg = make_root_cfg(providers, models, pools);
        cfg.hooks
            .insert(reserved.to_string(), gate_hook("test-hook", 150));
        let errs = validate(&cfg).expect_err("a reserved hook name must be rejected");
        assert!(
            errs.iter()
                .any(|e| e.contains(&format!("hook '{reserved}'")) && e.contains("reserved")),
            "reserved hook name '{reserved}' must be rejected by name; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_at_most_one_default() {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut two = gate_hook("test-hook", 150);
    two.default = true;
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("rank_a".to_string(), two.clone());
    cfg.hooks.insert("rank_b".to_string(), two);
    let errs = validate(&cfg).expect_err("two defaults must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("default: true") && e.contains("rank_a") && e.contains("rank_b")),
        "the error must name both offending defaults; got: {errs:?}"
    );

    cfg.hooks.remove("rank_b");
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("more than one hook sets")),
            "a single default must not trip the at-most-one rule; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_default_on_tap_rejected() {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut tap = gate_hook("test-hook", 150);
    tap.kind = config::HookKind::Tap;
    tap.default = true;
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("watcher".to_string(), tap);
    let errs = validate(&cfg).expect_err("default tap must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("watcher") && e.contains("default") && e.contains("tap")),
        "error must name the default tap; got: {errs:?}"
    );
}

#[test]
fn test_hook_nonreserved_name_ok() {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks
        .insert("compress".to_string(), gate_hook("test-hook", 150));
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("reserved")),
            "a non-reserved hook name must not trip the reserved-name rule; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_with_plugin_ref_passes_structural_rule() {
    let cfg = plugin_pool_cfg("my-hook-plugin");
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs
                .iter()
                .any(|e| e.contains("hook 'h'") && e.contains("names no plugin")),
            "a hook naming a plugin must pass the structural hook rule; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_requires_plugin_ref() {
    let cfg = plugin_pool_cfg("   ");
    let errs = validate(&cfg)
        .unwrap_err_or_default("a hook with no plugin ref must fail validation".to_string());
    assert!(
        errs.iter()
            .any(|e| e.contains("hook 'h'") && e.contains("names no plugin")),
        "an empty plugin ref must be reported; got: {errs:?}"
    );
}

trait UnwrapErrOrDefault {
    fn unwrap_err_or_default(self, msg: String) -> Vec<String>;
}
impl UnwrapErrOrDefault for Result<(), Vec<String>> {
    fn unwrap_err_or_default(self, msg: String) -> Vec<String> {
        self.err().unwrap_or_else(|| panic!("{msg}"))
    }
}

fn make_provider_allow_hosts(base_url: &str, hosts: &[&str]) -> config::ProviderCfg {
    let mut p = make_provider(proto_b(), base_url, "API_KEY");
    p.allow_metadata_hosts = hosts.iter().map(|s| s.to_string()).collect();
    p
}

#[test]
fn test_local_upstreams_allowed_by_default_no_flag() {
    for base in [
        "http://localhost:11434",
        "http://127.0.0.1",
        "http://127.0.0.1:11434",
        "http://10.0.0.5:8000",
        "http://192.168.1.50:1234",
        "http://172.16.3.4:8000",
        "http://100.64.0.5:8000",
        "http://[::1]:11434",
        "https://localhost",
        "https://localhost:11434",
    ] {
        let mut providers = HashMap::new();
        providers.insert(
            "local".to_string(),
            make_provider(proto_b(), base, "API_KEY"),
        );
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "local base_url '{base}' should validate with no flag, got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_scheme_rule_public_http_rejected_https_allowed() {
    let mut providers = HashMap::new();
    providers.insert(
        "pub".to_string(),
        make_provider(proto_b(), "http://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("public http base_url must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("must use https for a public host")),
        "expected the public-host https diagnostic; got: {errs:?}"
    );

    for ok in ["https://api.example.com", "http://10.0.0.5:8000"] {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_b(), ok, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "'{ok}' must validate (public https / local http); got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_metadata_blocked_by_default_every_form() {
    for base in [
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/",
        "https://169.254.170.2/v2/credentials",
        "https://100.100.100.200/",
        "https://168.63.129.16/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "https://[fd00:ec2::254]/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://metadata.tencentyun.com/",
        "https://instance-data/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::169.254.169.254]/",
        "http://2852039166/",
        "https://169%2E254%2E169%2E254/",
        "https://169.254.169.254./",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "metadata target '{base}' must be blocked by default"
        );

        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_b(), base, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs =
            validate(&cfg).expect_err(&format!("metadata base_url '{base}' must fail validation"));
        assert!(
            errs.iter()
                .any(|e| e.contains("blocked cloud-metadata host")),
            "expected a metadata-host error for '{base}'; got: {errs:?}"
        );
    }
}

#[test]
fn test_per_provider_allow_metadata_hosts_is_surgical_and_scoped() {
    let allow = vec!["169.254.169.254".to_string()];

    assert!(
        ssrf_blocked_host("https://169.254.169.254/", &allow, false, &[]).is_none(),
        "the listed host must be unblocked by the override"
    );
    assert!(
        ssrf_blocked_host("https://100.100.100.200/", &allow, false, &[]).is_some(),
        "a DIFFERENT metadata IP must stay blocked"
    );
    assert!(
        ssrf_blocked_host("https://169.254.170.2/", &allow, false, &[]).is_some(),
        "another link-local metadata IP must stay blocked (override is exact, not the /16)"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "surgical".to_string(),
        make_provider_allow_hosts("https://169.254.169.254/", &["169.254.169.254"]),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "the provider's own allow_metadata_hosts must let its IMDS base_url validate; got: {:?}",
        validate(&cfg)
    );

    let mut providers = HashMap::new();
    providers.insert(
        "other".to_string(),
        make_provider(proto_b(), "https://169.254.169.254/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    validate(&cfg).expect_err("a provider without the override must still block IMDS");
}

#[test]
fn test_global_allow_metadata_hosts_unblocks_all_providers() {
    let mut providers = HashMap::new();
    providers.insert(
        "a".to_string(),
        make_provider(proto_b(), "https://100.100.100.200/", "API_KEY"),
    );
    providers.insert(
        "b".to_string(),
        make_provider(proto_b(), "https://100.100.100.200/", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["100.100.100.200".to_string()];
    assert!(
        validate(&cfg).is_ok(),
        "security.allow_metadata_hosts must unblock the host for ALL providers; got: {:?}",
        validate(&cfg)
    );

    let mut providers = HashMap::new();
    providers.insert(
        "c".to_string(),
        make_provider(proto_b(), "https://169.254.169.254/", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["100.100.100.200".to_string()];
    validate(&cfg).expect_err("a host not in the global allow-list must stay blocked");
}

#[test]
fn test_allow_all_metadata_disables_guard_entirely() {
    for base in [
        "https://169.254.169.254/",
        "https://metadata.google.internal/",
        "https://100.100.100.200/",
        "https://168.63.129.16/",
        "https://[fd00:ec2::254]/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], true, &[]).is_none(),
            "allow_all_metadata must unblock '{base}'"
        );
        let mut providers = HashMap::new();
        providers.insert(
            "meta".to_string(),
            make_provider(proto_b(), base, "API_KEY"),
        );
        let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        cfg.allow_all_metadata = true;
        assert!(
            validate(&cfg).is_ok(),
            "allow_all_metadata must let '{base}' validate; got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_blocked_metadata_hosts_extends_denylist() {
    for base in ["https://10.99.99.99/", "https://[::ffff:10.99.99.99]/"] {
        assert!(
            ssrf_blocked_host(base, &[], false, &["10.99.99.99".to_string()]).is_some(),
            "'{base}' must be blocked once 10.99.99.99 is in blocked_metadata_hosts"
        );
    }

    assert!(
        ssrf_blocked_host(
            "https://10.0.0.1/",
            &[],
            false,
            &["10.99.99.99".to_string()]
        )
        .is_none(),
        "an un-listed private host must stay allowed"
    );

    assert!(
        ssrf_blocked_host(
            "https://metadata.mycloud.example/",
            &[],
            false,
            &["metadata.mycloud.example".to_string()]
        )
        .is_some(),
        "a listed metadata hostname must be blocked"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_b(), "https://10.99.99.99/", "API_KEY"),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["10.99.99.99".to_string()]);
    let errs = validate(&cfg)
        .expect_err("a base_url listed in blocked_metadata_hosts must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("10.99.99.99")),
        "expected a metadata-host error for the listed host; got: {errs:?}"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider_allow_hosts("https://10.99.99.99/", &["10.99.99.99"]),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["10.99.99.99".to_string()]);
    assert!(
        validate(&cfg).is_ok(),
        "allow_metadata_hosts must override an operator-listed blocked host; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_public_targets_unaffected() {
    for base in [
        "https://api.vendor-a.example.com",
        "https://api.acme.example.com/v1/messages",
        "https://8.8.8.8/",
    ] {
        assert!(ssrf_blocked_host(base, &[], false, &[]).is_none());
        assert!(ssrf_blocked_host(base, &[], true, &[]).is_none());
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_b(), base, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "public https '{base}' must validate"
        );
    }
}

#[test]
fn test_path_override_composition_under_metadata_rules() {
    let mut ok = make_provider(proto_b(), "http://localhost:11434", "API_KEY");
    ok.path = Some("/v1/chat/completions".to_string());
    let mut providers = HashMap::new();
    providers.insert("local".to_string(), ok);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "local http base_url + leading-slash path should validate, got: {:?}",
        validate(&cfg)
    );

    let mut evil = make_provider(proto_b(), "https://api.example.com", "API_KEY");
    evil.path = Some(".169.254.169.254/latest".to_string());
    let mut providers = HashMap::new();
    providers.insert("evil".to_string(), evil);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    validate(&cfg).expect_err("authority-fusing path must be rejected");

    let mut p = make_provider(proto_b(), "https://api.example.com/api/paas/v4", "API_KEY");
    p.path = Some("/chat/completions".to_string());
    let mut providers = HashMap::new();
    providers.insert("ok".to_string(), p);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "well-formed leading-slash path on a public host must validate"
    );
}

fn cost_cfg(model_names: &[&str]) -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(proto_a(), "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    for name in model_names {
        models.insert(name.to_string(), make_model("p", 10));
    }
    let mut pools = HashMap::new();
    if let Some(first) = model_names.first() {
        pools.insert("pool1".to_string(), make_pool(vec![make_member(first)]));
    }
    make_root_cfg(providers, models, pools)
}

fn priced_entry() -> config::RateEntryCfg {
    serde_yaml::from_str(
        "input_utok: 3.0\noutput_utok: 15.0\ncache_read_utok: 0.3\ncache_write_utok: 3.75\n",
    )
    .expect("a fully-written entry must parse")
}

fn present_tools_section() -> Box<dyn busbar_kernel::config::plane_sections::PlaneCfg> {
    let key = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
    let written: serde_yaml::Value =
        serde_yaml::from_str("a-tool-server:\n  url: \"https://tools.example.com/rpc\"\n  pin: { mechanism: unpinned }\n")
            .expect("yaml");
    let deploy = config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": { "chain": [], "admin_auth": [] },
        (key): written,
    }))
    .expect("a one-registration tools section must parse through the product grammar");
    let mut cfg = config::resolve(&deploy, &HashMap::new()).expect("the tools deployment resolves");
    let section = cfg.plane_defs.remove(key).expect("the section is carried");
    assert!(
        section.is_present(),
        "the fixture must be a section the operator wrote content for"
    );
    section
}

fn rate_card_for_actual_plane(
    mut card: std::collections::BTreeMap<String, config::RateEntryCfg>,
) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
    )
    .expect("the actual fallback plane is registered");
    let zero = serde_json::from_value(serde_json::json!(0)).expect("an exact free unit rate");
    for entry in card.values_mut() {
        for class in plane.billable_classes {
            if !busbar_contract::records::RESERVED_UNITS.contains(&class.class)
                && !plane.fee_units.contains(&class.class)
            {
                entry.units.entry(class.class.to_owned()).or_insert(zero);
            }
        }
    }
    card
}

fn rate_card_of(entries: &[&str]) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    entries
        .iter()
        .map(|m| (m.to_string(), config::RateEntryCfg::default()))
        .collect()
}

#[test]
fn test_validate_rate_card_completeness_fails_closed_with_paste_stub() {
    let mut cfg = cost_cfg(&["claude-opus-4"]);
    cfg.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&[
        "some-other-model",
    ])));
    let errs =
        validate(&cfg).expect_err("a configured model without a rate entry must fail validation");
    let joined = errs.join("\n");
    assert!(
        joined.contains("rate_card is present but 1 configured model has no rate entry"),
        "must state the completeness rule: {joined}"
    );
    assert!(
        joined.contains(
            "claude-opus-4: { input_utok: 0, output_utok: 0, cache_read_utok: 0, cache_write_utok: 0 }"
        ),
        "must print the paste-ready zeroed stub for exactly the missing model: {joined}"
    );

    assert!(
        joined.contains("rate_card names model 'some-other-model'")
            && joined.contains("not defined under models:"),
        "a card entry for an unknown model must error: {joined}"
    );

    let mut cfg_ok = cost_cfg(&["claude-opus-4"]);
    cfg_ok.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&["claude-opus-4"])));
    assert!(
        validate(&cfg_ok).is_ok(),
        "a complete rate card passes; got: {:?}",
        validate(&cfg_ok)
    );

    let cfg_absent = cost_cfg(&["claude-opus-4"]);
    assert!(validate(&cfg_absent).is_ok());
}

#[test]
fn test_validate_unpriced_class_with_billing_on_refuses_boot() {
    let mut cfg = cost_cfg(&["claude-opus-4"]);
    cfg.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&[
        "some-priced-model",
    ])));
    cfg.models
        .insert("some-priced-model".to_string(), make_model("p", 10));
    let errs = validate(&cfg)
        .expect_err("billing on + an unpriced class must REFUSE boot (unpriced ⇒ boot-refusal)");
    assert!(
        errs.iter()
            .any(|e| e.contains("rate_card is present but") && e.contains("no rate entry")),
        "the refusal must name the completeness rule (unpriced ⇒ boot-refusal): {errs:?}"
    );
}

#[test]
fn test_validate_absent_card_boots_free_no_refusal() {
    let cfg = cost_cfg(&["claude-opus-4", "claude-sonnet-4"]);
    assert!(
        cfg.rate_card.is_none(),
        "the fixture must start with no rate_card (billing off)"
    );
    assert!(
        validate(&cfg).is_ok(),
        "billing off (no rate_card) must NOT refuse boot; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_rate_card_refuses_a_rate_the_card_cannot_hold() {
    for (tier, v) in [
        ("input_utok", 0.0004),
        ("output_utok", 0.000_093_13),
        ("cache_write_utok", 2.0e16),
        ("input_utok", 0.0005),
        ("output_utok", 0.0015),
        ("cache_write_utok", 0.5005),
    ] {
        let mut cfg = cost_cfg(&["m"]);
        let mut entry = priced_entry();
        match tier {
            "input_utok" => entry.input_utok = v,
            "output_utok" => entry.output_utok = v,
            _ => entry.cache_write_utok = v,
        }
        cfg.rate_card = Some(rate_card_for_actual_plane(
            [("m".to_string(), entry)].into_iter().collect(),
        ));
        let errs = validate(&cfg).expect_err("a rate the card cannot hold must refuse boot");
        let want = format!("rate_card['m'].{tier} = {v} micro-units per token is a rate the card");
        assert!(
            errs.iter().any(|e| e.contains(&want)),
            "must name the model, class and rate ({want}): {errs:?}"
        );
    }

    let mut cfg = cost_cfg(&["m"]);
    let mut entry = priced_entry();
    entry.input_utok = 0.001;
    entry.cache_read_utok = 0.0;
    cfg.rate_card = Some(rate_card_for_actual_plane(
        [("m".to_string(), entry)].into_iter().collect(),
    ));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn test_validate_rate_card_stubs_every_missing_model() {
    let mut cfg = cost_cfg(&["alpha", "long-model-name"]);

    cfg.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&[])));
    let errs = validate(&cfg).expect_err("two unpriced models must fail validation");
    let joined = errs.join("\n");
    assert!(
        joined.contains("2 configured models have no rate entry"),
        "the count must be plural and exact: {joined}"
    );
    for m in ["alpha:", "long-model-name:"] {
        assert!(
            joined.contains(m),
            "the stub must name missing model '{m}': {joined}"
        );
    }
}

#[test]
fn test_validate_rate_card_keyed_by_config_name_not_upstream() {
    let mut cfg = cost_cfg(&["smart"]);
    cfg.models.get_mut("smart").unwrap().upstream_model = Some("gpt-5".to_string());

    cfg.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&["smart"])));
    assert!(
        validate(&cfg).is_ok(),
        "the card is keyed by config model name; got: {:?}",
        validate(&cfg)
    );

    cfg.rate_card = Some(rate_card_for_actual_plane(rate_card_of(&["gpt-5"])));
    let errs = validate(&cfg).expect_err("pricing the upstream name must fail");
    let joined = errs.join("\n");
    assert!(
        joined.contains("smart:"),
        "stub names the config model: {joined}"
    );
    assert!(
        joined.contains("rate_card names model 'gpt-5'"),
        "the upstream-keyed entry is flagged unknown: {joined}"
    );
}

#[test]
fn test_validate_rate_card_rejects_nan_and_negative_rates() {
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(rate_card_for_actual_plane(
        std::collections::BTreeMap::from([(
            "m".to_string(),
            config::RateEntryCfg {
                input_utok: f64::NAN,
                output_utok: -1.0,
                cache_read_utok: f64::INFINITY,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]),
    ));
    let errs = validate(&cfg).expect_err("NaN/negative/infinite rates must fail");
    let joined = errs.join("\n");
    assert!(joined.contains("rate_card['m'].input_utok"), "{joined}");
    assert!(joined.contains("rate_card['m'].output_utok"), "{joined}");
    assert!(
        joined.contains("rate_card['m'].cache_read_utok"),
        "{joined}"
    );
    assert!(
        !joined.contains("rate_card['m'].cache_write_utok"),
        "a well-formed tier (0) must not error: {joined}"
    );
}

#[test]
fn test_rate_card_open_class_grammar_is_exact_and_refuses_a_reserved_class() {
    let parse = |y: &str| {
        serde_yaml::from_str::<std::collections::BTreeMap<String, config::RateEntryCfg>>(y)
    };
    let card = parse("m: { units: { search_units: 2000, hops: \"0.5\" } }\n").expect("parses");
    let units = &card["m"].units;
    assert_eq!(units["search_units"].nanos_per_unit(), 2_000_000);
    assert_eq!(units["hops"].nanos_per_unit(), 500);
    let round_trip = serde_yaml::to_string(&card).expect("serializes");
    assert_eq!(
        parse(&round_trip).expect("re-parses"),
        card,
        "exact both ways: {round_trip}"
    );
    assert!(
        parse("m: { units: { hops: 0.5 } }\n").is_err(),
        "a bare float is not exact"
    );
    assert!(
        parse("m: { units: { hops: \"0.0001\" } }\n").is_err(),
        "finer than a nano-unit"
    );
    assert!(parse("m: { units: { hops: -1 } }\n").is_err(), "negative");
    assert!(
        parse("m: { units: { hops: 1 }, typo_utok: 1 }\n").is_err(),
        "deny_unknown_fields stays"
    );

    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(rate_card_for_actual_plane(
        parse("m: { input_utok: 1, units: { output: 5 } }\n").expect("parses"),
    ));
    let joined = validate(&cfg)
        .expect_err("a reserved class under units: must fail")
        .join("\n");
    assert!(
        joined.contains("rate_card['m'].units.output names a reserved class"),
        "{joined}"
    );
}

#[test]
fn test_validate_all_zero_rate_card_warns_but_does_not_fail() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let mut cfg = cost_cfg(&["priced-model", "free-by-accident"]);
    let mut card = std::collections::BTreeMap::new();
    card.insert(
        "priced-model".to_string(),
        config::RateEntryCfg {
            input_utok: 3.0,
            output_utok: 15.0,
            cache_read_utok: 0.3,
            cache_write_utok: 3.75,
            ..Default::default()
        },
    );

    card.insert(
        "free-by-accident".to_string(),
        config::RateEntryCfg::default(),
    );
    cfg.rate_card = Some(rate_card_for_actual_plane(card));

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));

    assert!(
        result.is_ok(),
        "an all-zero rate_card entry is a WARNING, not a hard error (a free model is legal); got: {result:?}"
    );

    let msgs = cap.messages();
    assert!(
        msgs.iter()
            .any(|m| m.contains("free-by-accident") && m.contains("every tier at zero")),
        "an all-zero-priced model must WARN, naming the model: {msgs:?}"
    );

    assert!(
        !msgs.iter().any(|m| m.contains("priced-model")),
        "a model with non-zero rates must NOT warn: {msgs:?}"
    );
}

#[test]
fn test_validate_rate_card_entry_omitting_a_tier_is_accepted_and_bills_that_class_at_zero() {
    let mut cfg = cost_cfg(&["claude-sonnet"]);

    let card: std::collections::BTreeMap<String, config::RateEntryCfg> =
        serde_yaml::from_str("claude-sonnet:\n  input_utok: 3.0\n  output_utok: 15.0\n")
            .expect("the two-tier card must parse");
    cfg.rate_card = Some(rate_card_for_actual_plane(card));

    assert!(
        validate(&cfg).is_ok(),
        "WITNESS: boot ACCEPTS a card that leaves two classes unpriced — #77(5) says it must \
         refuse. If this line starts failing, the refusal has landed and this test should be \
         inverted, not deleted."
    );

    let micros = |card: &std::collections::BTreeMap<String, config::RateEntryCfg>,
                  units: &std::collections::BTreeMap<String, u64>| {
        let model = busbar_kernel::cost::CostModel::resolve_parts(
            Some(card),
            0,
            &std::collections::BTreeMap::new(),
        );
        let entry = units.iter().fold(
            busbar_kernel_ledger::cost::LedgerEntry::new("claude-sonnet", 0),
            |entry, (class, count)| entry.with_whole(class, *count),
        );
        busbar_kernel_ledger::cost::price_ledger(
            &[entry],
            &busbar_kernel_ledger::cost::History::opening(model.card().clone(), 0),
        )
        .expect("the model is on the card")
        .micros_i64()
        .expect("the fixture fits")
    };
    let a_day_of_cache_reads =
        std::collections::BTreeMap::from([("cache_read".to_string(), 10_000_000u64)]);
    assert_eq!(
        micros(cfg.rate_card.as_ref().unwrap(), &a_day_of_cache_reads),
        0,
        "the silent zero, measured: ten million cache-read tokens bill at nothing"
    );

    let priced: config::RateEntryCfg = serde_yaml::from_str(
        "input_utok: 3.0\noutput_utok: 15.0\ncache_read_utok: 0.3\ncache_write_utok: 3.75\n",
    )
    .unwrap();
    assert_eq!(
        micros(
            &std::collections::BTreeMap::from([("claude-sonnet".to_string(), priced)]),
            &a_day_of_cache_reads
        ),
        3_000_000,
        "three whole units (1e6 micro-units each) a day is what the silent zero swallowed"
    );
}

#[test]
fn test_validate_rate_card_entry_with_explicit_zero_tiers_is_free_not_unpriced() {
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    let card: std::collections::BTreeMap<String, config::RateEntryCfg> = serde_yaml::from_str(
        "claude-sonnet:\n  input_utok: 3.0\n  output_utok: 15.0\n  cache_read_utok: 0.0\n  \
         cache_write_utok: 0.0\n",
    )
    .expect("the four-tier card must parse");
    cfg.rate_card = Some(rate_card_for_actual_plane(card));

    assert!(
        validate(&cfg).is_ok(),
        "#77(5): free is an EXPLICIT zero row — a tier the operator WROTE as 0.0 is priced, and \
         priced at nothing is legal: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_rate_card_entry_all_four_explicit_zeros_still_only_warns() {
    let mut cfg = cost_cfg(&["free-on-purpose"]);
    let card: std::collections::BTreeMap<String, config::RateEntryCfg> = serde_yaml::from_str(
        "free-on-purpose:\n  input_utok: 0.0\n  output_utok: 0.0\n  cache_read_utok: 0.0\n  \
         cache_write_utok: 0.0\n",
    )
    .expect("the all-zero card must parse");
    cfg.rate_card = Some(rate_card_for_actual_plane(card));
    assert!(
        validate(&cfg).is_ok(),
        "an EXPLICITLY all-zero entry is a deliberate free model: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_allows_a_flat_card_beside_a_plane_with_no_card_of_its_own() {
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    cfg.rate_card = Some(rate_card_for_actual_plane(
        std::collections::BTreeMap::from([("claude-sonnet".to_string(), priced_entry())]),
    ));
    cfg.plane_defs.insert(
        busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2],
        present_tools_section(),
    );
    assert!(
        validate(&cfg).is_ok(),
        "a plane with no card of its own is unbilled, not refused: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_holds_a_plane_card_to_the_card_shape_and_leaves_the_flat_plane_off() {
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    let bad: config::RateEntryCfg =
        serde_yaml::from_str("input_utok: -1\n").expect("parses; validation refuses");
    let good: config::RateEntryCfg =
        serde_yaml::from_str("units: { calls: 5 }\n").expect("an open-class entry parses");
    let plane_card = std::collections::BTreeMap::from([
        ("bad-lane".to_string(), bad),
        ("good-lane".to_string(), good),
    ]);
    cfg.rate_card = busbar_kernel_ledger::cost::compose_plane_cards(
        None,
        &std::collections::BTreeMap::from([("p".to_string(), plane_card)]),
    );
    let errs = validate(&cfg).expect_err("a negative plane rate is refused");
    assert_eq!(
        errs,
        vec![
            "p.rate_card['bad-lane'].input_utok must be a finite, non-negative number of \
             micro-units per token (got -1)"
                .to_string()
        ],
        "one error, on the plane card's own path; no flat completeness stub, no dead-model entry"
    );
}

#[test]
fn test_validate_allows_a_non_fallback_plane_when_billing_is_off() {
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    assert!(cfg.rate_card.is_none(), "the fixture starts billing-off");
    cfg.plane_defs.insert(
        busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2],
        present_tools_section(),
    );
    assert!(
        validate(&cfg).is_ok(),
        "billing off must never refuse a configured plane: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_rejects_negative_per_request_fee() {
    let mut cfg = cost_cfg(&["m"]);
    cfg.per_request_fee = -1;
    let errs = validate(&cfg).expect_err("a negative per_request_fee must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("per_request_fee must be >= 0") && e.contains("-1")),
        "expected the negative-fee error naming the value; got: {errs:?}"
    );
    for ok in [0, 1, 250] {
        let mut cfg = cost_cfg(&["m"]);
        cfg.per_request_fee = ok;
        assert!(validate(&cfg).is_ok(), "per_request_fee {ok} must validate");
    }
}

#[test]
fn test_validate_rejects_empty_store_module() {
    let mut cfg = cost_cfg(&["m"]);
    cfg.store = Some(config::StoreCfg {
        module: "   ".to_string(),
        settings: serde_json::Map::new(),
    });
    let errs = validate(&cfg).expect_err("an empty store.module must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("store.module must be non-empty")),
        "expected the empty-store-module error; got: {errs:?}"
    );

    let cfg = cost_cfg(&["m"]);
    assert!(validate(&cfg).is_ok(), "store.module: memory must validate");
}

fn group(
    parent: Option<&str>,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
) -> config::GroupCfg {
    config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits,
        ..Default::default()
    }
}

fn limit_requests_per_minute(amount: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Requests,
        amount,
        per: Some(busbar_kernel::config::groups::LimitWindow::Minute),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

#[test]
fn test_validate_groups_faults_are_named_with_fixes() {
    let mut cfg = cost_cfg(&["m"]);
    cfg.groups.insert(
        "bob".to_string(),
        group(Some("growth"), vec![limit_requests_per_minute(500)]),
    );
    let errs = validate(&cfg).expect_err("missing parent must fail");
    let joined = errs.join("\n");
    assert!(
        joined.contains("groups.bob names parent 'growth', which does not exist"),
        "missing parent is named: {joined}"
    );
    assert!(
        joined.contains("Paste this under groups")
            && joined.contains("growth:")
            && joined.contains("- { requests: 0, per: minute }"),
        "missing parent gets a paste-ready stub: {joined}"
    );

    let mut cfg = cost_cfg(&["m"]);
    cfg.groups.insert("a".to_string(), group(Some("b"), vec![]));
    cfg.groups.insert("b".to_string(), group(Some("a"), vec![]));
    let errs = validate(&cfg).expect_err("a groups cycle must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("CYCLIC") && e.contains("a -> b")),
        "the cycle diagnostic must name the path: {errs:?}"
    );

    let mut cfg = cost_cfg(&["m"]);
    for i in 0..10 {
        let parent = if i == 9 {
            None
        } else {
            Some(format!("g{}", i + 1))
        };
        cfg.groups.insert(
            format!("g{i}"),
            config::GroupCfg {
                parent,
                enabled: true,
                limits: vec![],
                ..Default::default()
            },
        );
    }
    validate(&cfg).expect("an acyclic chain of any depth must validate");

    let mut cfg = cost_cfg(&["m"]);
    let mut bad = limit_requests_per_minute(5);
    bad.scope = Some(busbar_contract::records::ScopeRef::pool("nope"));
    cfg.groups
        .insert("team".to_string(), group(None, vec![bad]));
    let errs = validate(&cfg).expect_err("a dangling pool qualifier must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("groups.team.limits") && e.contains("`pool: nope`")),
        "the dangling pool is named: {errs:?}"
    );
    let mut cfg = cost_cfg(&["m"]);
    let mut tmpl = limit_requests_per_minute(5);
    tmpl.scope = Some(busbar_contract::records::ScopeRef::pool("nope"));
    let mut g = group(None, vec![limit_requests_per_minute(5)]);
    g.child_default = Some(config::groups::ChildDefault { limits: vec![tmpl] });
    cfg.groups.insert("team".to_string(), g);
    let errs = validate(&cfg).expect_err("a dangling pool in child_default must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("groups.team.child_default.limits") && e.contains("`pool: nope`")),
        "the dangling child_default pool is named: {errs:?}"
    );
    let mut cfg = cost_cfg(&["m"]);
    let mut ok = limit_requests_per_minute(5);
    ok.scope = Some(busbar_contract::records::ScopeRef::pool("pool1"));
    cfg.groups.insert("team".to_string(), group(None, vec![ok]));
    validate(&cfg).expect("a pool qualifier naming a real pool must pass");

    let mut cfg = cost_cfg(&["m"]);
    cfg.groups.insert(
        "team".to_string(),
        group(None, vec![limit_requests_per_minute(0)]),
    );
    let errs = validate(&cfg).expect_err("a zero-amount limit must fail");
    assert!(
        errs.iter().any(|e| e.contains("groups.team")
            && e.contains("`requests` limit of 0")
            && e.contains("enabled:")),
        "expected the zero-amount limit error with the freeze hint; got: {errs:?}"
    );

    let mut cfg = cost_cfg(&["m"]);
    cfg.groups.insert(
        "acme".to_string(),
        group(None, vec![limit_requests_per_minute(10_000)]),
    );
    cfg.groups.insert(
        "growth".to_string(),
        group(Some("acme"), vec![limit_requests_per_minute(2_000)]),
    );
    cfg.groups.insert(
        "bob".to_string(),
        group(Some("growth"), vec![limit_requests_per_minute(500)]),
    );
    assert!(
        validate(&cfg).is_ok(),
        "a valid nested groups tree must validate; got: {:?}",
        validate(&cfg)
    );
}

fn auth_with_binding(
    chain: &[&str],
    module: &str,
    role: &str,
    binding: config::RoleBindingCfg,
) -> config::AuthCfg {
    let mut auth = make_auth_chain(chain, busbar_kernel::auth::UpstreamCreds::Own);
    auth.role_bindings.insert(
        module.to_string(),
        std::collections::BTreeMap::from([(role.to_string(), binding)]),
    );
    auth
}

#[test]
fn test_validate_role_binding_module_must_be_in_a_chain() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(auth_with_binding(
        &["keys"],
        "test-idp-double",
        "platform",
        config::RoleBindingCfg::default(),
    ));
    let errs = validate(&cfg).expect_err("a binding under an inactive module must fail");
    assert!(
        errs.iter().any(
            |e| e.contains("role_bindings names module 'test-idp-double'")
                && e.contains("neither auth.chain nor auth.admin_auth")
                && e.contains("chain:")
        ),
        "expected the inactive-module error with the chain paste stub; got: {errs:?}"
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(auth_with_binding(
        &["keys"],
        "keys",
        "platform",
        config::RoleBindingCfg::default(),
    ));
    assert!(
        validate(&cfg).is_ok(),
        "a binding under an active chain module must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_role_binding_group_must_exist() {
    let binding = config::RoleBindingCfg {
        allowed_pools: None,
        group: Some("squad".to_string()),
        admin_scope: None,
        verbs: None,
        plane_grants: Default::default(),
    };
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(auth_with_binding(&["keys"], "keys", "dev", binding.clone()));
    let errs = validate(&cfg).expect_err("a binding to a nonexistent group must fail");
    let joined = errs.join("\n");
    assert!(
        joined.contains("role_bindings.keys.dev names group 'squad'")
            && joined.contains("Paste this under groups")
            && joined.contains("squad:"),
        "expected the missing-group error with the paste-ready stub; got: {joined}"
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(auth_with_binding(&["keys"], "keys", "dev", binding));
    cfg.groups.insert(
        "squad".to_string(),
        group(None, vec![limit_requests_per_minute(100)]),
    );
    assert!(
        validate(&cfg).is_ok(),
        "a binding to an existing group must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_role_binding_reserved_role_name_rejected() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(auth_with_binding(
        &["keys"],
        "keys",
        config::operator_principal_id(),
        config::RoleBindingCfg::default(),
    ));
    let reserved = |errs: &[String]| {
        errs.iter()
            .any(|e| e.contains("role_bindings.keys") && e.contains("reserved"))
    };
    assert!(
        validate(&cfg).err().is_some_and(|errs| reserved(&errs)),
        "the operator principal remains reserved without an active operator row: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_secret_module_resolvability() {
    let (mut providers, models, pools) = valid_maps();
    providers.get_mut("myprovider").unwrap().api_key = config::SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    };
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a plugin-backed api_key module must not be rejected by pre-registry validate; got: {:?}",
        validate(&cfg)
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.tls = Some(config::TlsCfg {
        cert: config::SecretRef {
            module: "vault".to_string(),
            settings: serde_json::Map::new(),
        },
        key: config::SecretRef {
            module: "file".to_string(),
            settings: serde_json::Map::new(),
        },
        client_ca: Some(config::SecretRef {
            module: "env".to_string(),
            settings: serde_json::Map::new(),
        }),
    });
    let errs = validate(&cfg).expect_err("structurally-bad tls secret refs must fail validation");

    assert!(
        !errs.iter().any(|e| e.contains("tls.cert")),
        "a plugin-backed tls.cert must not be rejected by pre-registry validate; got: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("tls.key") && e.contains("requires settings.path")),
        "tls.key file ref without settings.path must error; got: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("tls.client_ca") && e.contains("requires settings.key")),
        "tls.client_ca env ref without settings.key must error; got: {errs:?}"
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.tls = Some(config::TlsCfg {
        cert: config::SecretRef::file("/run/secrets/tls-cert.pem"),
        key: config::SecretRef::file("/run/secrets/tls-key.pem"),
        client_ca: Some(config::SecretRef::env("BUSBAR_CLIENT_CA_PEM")),
    });
    assert!(
        validate(&cfg).is_ok(),
        "well-formed tls secret refs must validate; got: {:?}",
        validate(&cfg)
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    auth.signing_key = Some(config::SecretRef {
        module: "vault".to_string(),
        settings: serde_json::Map::new(),
    });
    cfg.auth = Some(auth);
    assert!(
        validate(&cfg).is_ok(),
        "a plugin-backed signing_key module must not be rejected by pre-registry validate; got: {:?}",
        validate(&cfg)
    );
}

fn resolve_yaml(yaml: &str) -> Result<RootCfg, Vec<String>> {
    crate::dist_root_install::install();
    let deploy: config::DeployCfg =
        serde_yaml::from_str(yaml).expect("the test DeployCfg yaml must parse");
    let def: config::ProviderDef = serde_yaml::from_str(&format!(
        "protocol: {}\nbase_url: https://api.acme.example.com\nerror_map:\n  \"400\": client_error\n",
        proto_a()
    ))
    .unwrap();
    let defs = HashMap::from([("acme".to_string(), def)]);
    config::resolve(&deploy, &defs)
}

#[test]
fn test_validate_runs_on_resolved_root_cfg_clean_config() {
    let yaml = r#"
listen: "0.0.0.0:8080"
auth:
  chain:
    - keys
  signing_key: { env: BUSBAR_SIGNING_KEY }
  admin_auth: []
  role_bindings:
    keys:
      platform:
        allowed_pools: [main]
        group: eng
providers:
  acme:
    api_key: { env: ACME_API_KEY }
models:
  claude:
    provider: acme
pools:
  main:
    members:
      - model: claude
groups:
  eng:
    limits:
      - { requests: 500, per: minute }
rate_card:
  claude: { input_utok: 3.0, output_utok: 15.0 }
per_request_fee: 1
store:
  module: memory
advanced:
  rate_sweep_interval: 256
"#;
    let cfg = resolve_yaml(yaml).expect("the clean config must resolve");
    assert!(
        validate(&cfg).is_ok(),
        "the resolved clean config must validate; got: {:?}",
        validate(&cfg)
    );

    assert_eq!(cfg.per_request_fee, 1);
    assert!(cfg.rate_card.as_ref().unwrap().contains_key("claude"));
    assert!(cfg.groups.contains_key("eng"));
    assert_eq!(
        cfg.store.as_ref().unwrap().module,
        config::migrated_store_module()
    );
    assert_eq!(cfg.limits.rate_sweep_interval, 256);
}

#[test]
fn test_undefined_pool_member_is_refused_by_validate_in_1_5_5_words() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers: {}
models: {}
pools:
  oracle-unused:
    members:
      - model: nope
store:
  module: memory
"#;
    let cfg = resolve_yaml(yaml).expect(
        "the resolver must not refuse a pool member nothing defines — the validator owns it",
    );
    let errs = validate(&cfg).expect_err("an undefined pool member must still refuse the config");
    assert!(
        errs.iter()
            .any(|e| e == "pool 'oracle-unused' references unknown model 'nope'"),
        "the 1.5.5 sentence must be the one the operator reads; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_plugin_backed_secret_module_config() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { module: acme-vault, settings: { path: "secret/data/acme#key" } }
models:
  claude:
    provider: acme
pools:
  main:
    members:
      - model: claude
store:
  module: memory
"#;
    let cfg = resolve_yaml(yaml).expect("the vault-api_key config must resolve");
    assert_eq!(
        cfg.providers.get("acme").unwrap().api_key.module,
        "acme-vault",
        "the plugin-backed secret module survived resolution"
    );
    assert!(
        validate(&cfg).is_ok(),
        "a plugin-backed api_key module must pass the shared boot/--validate gate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_runs_on_resolved_root_cfg_collects_new_surface_faults() {
    let yaml = r#"
listen: "0.0.0.0:8080"
auth:
  chain:
    - keys
  role_bindings:
    oidc:
      platform:
        group: ghost-group
providers:
  acme:
    api_key: { env: ACME_API_KEY }
models:
  claude:
    provider: acme
  haiku:
    provider: acme
pools:
  main:
    members:
      - model: claude
groups:
  frozen:
    limits:
      - { requests: 0, per: minute }
rate_card:
  claude: { input_utok: 3.0, output_utok: 15.0 }
per_request_fee: -5
store:
  module: ""
advanced:
  rate_sweep_interval: 0
"#;
    let cfg =
        resolve_yaml(yaml).expect("the faulty config still RESOLVES (faults are validate-time)");
    let errs = validate(&cfg).expect_err("the resolved faulty config must fail validation");
    let joined = errs.join("\n");

    assert!(
        joined.contains("haiku:") && joined.contains("no rate entry"),
        "{joined}"
    );

    assert!(
        joined.contains("role_bindings names module 'oidc'"),
        "{joined}"
    );
    assert!(
        joined.contains("role_bindings.oidc.platform names group 'ghost-group'"),
        "{joined}"
    );

    assert!(joined.contains("groups.frozen"), "{joined}");

    assert!(joined.contains("per_request_fee must be >= 0"), "{joined}");
    assert!(
        joined.contains("store.module must be non-empty"),
        "{joined}"
    );
    assert!(joined.contains("advanced.rate_sweep_interval"), "{joined}");
}

#[test]
fn test_pool_gate_ref_rejects_a_tap() {
    let mut cfg = hooks_test_cfg();
    let mut tap = gate_hook("watcher-plugin", 150);
    tap.kind = config::HookKind::Tap;
    cfg.hooks.insert("watcher".to_string(), tap);
    cfg.pools
        .get_mut("p1")
        .expect("hooks_test_cfg seeds pool p1")
        .gates
        .push("watcher".to_string());
    let errs = validate(&cfg).expect_err("a pool referencing a tap in gates: must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("watcher") && e.contains("must be a gate")),
        "expected a wrong-kind-hook error naming the tap; got: {errs:?}"
    );
}

#[test]
fn test_pool_gate_ref_accepts_a_real_gate() {
    let mut cfg = hooks_test_cfg();
    cfg.hooks
        .insert("real-gate".to_string(), gate_hook("gate-plugin", 150));
    cfg.pools
        .get_mut("p1")
        .expect("hooks_test_cfg seeds pool p1")
        .gates
        .push("real-gate".to_string());
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("must be a gate")),
            "a real gate reference must not be flagged wrong-kind; got: {errs:?}"
        );
    }
}

#[test]
fn test_reasoning_effort_budgets_rejects_a_single_zero_field() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    cfg.limits.reasoning_effort_budgets = config::ReasoningEffortBudgets {
        minimal: 1024,
        low: 0,
        medium: 4096,
        high: 8192,
    };
    let errs = validate(&cfg).expect_err("a single zero budget field must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("reasoning_effort_budgets entries must be > 0")),
        "expected the zero-entry error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_empty_canonical_builtin_secret_ref() {
    let empty_env: config::SecretRef =
        serde_yaml::from_str("{ module: env, settings: { key: \"\" } }")
            .expect("canonical empty-key env ref deserializes (the guard is sugar-only)");
    assert_eq!(
        empty_env.env_var(),
        Some(""),
        "precondition: Some(\"\"), not None"
    );

    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.acme.example.com", "IGNORED");
    p.api_key = empty_env;
    providers.insert("acme".to_string(), p);
    let errs = validate(&make_root_cfg(providers, HashMap::new(), HashMap::new()))
        .expect_err("an empty canonical env secret key must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("providers.acme.api_key")
            && e.contains("'env'")
            && e.to_lowercase().contains("non-empty")),
        "expected a non-empty settings.key error naming providers.acme.api_key; got: {errs:?}"
    );

    let empty_file: config::SecretRef =
        serde_yaml::from_str("{ module: file, settings: { path: \"\" } }")
            .expect("canonical empty-path file ref deserializes");
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.acme.example.com", "IGNORED");
    p.api_key = empty_file;
    providers.insert("acme".to_string(), p);
    let errs = validate(&make_root_cfg(providers, HashMap::new(), HashMap::new()))
        .expect_err("an empty canonical file path must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("providers.acme.api_key")
            && e.contains("'file'")
            && e.to_lowercase().contains("non-empty")),
        "expected a non-empty settings.path error naming providers.acme.api_key; got: {errs:?}"
    );

    let good: config::SecretRef =
        serde_yaml::from_str("{ module: env, settings: { key: REAL_KEY } }")
            .expect("canonical non-empty env ref deserializes");
    let mut providers = HashMap::new();
    let mut p = make_provider(proto_a(), "https://api.acme.example.com", "IGNORED");
    p.api_key = good;
    providers.insert("acme".to_string(), p);
    let errs = validate(&make_root_cfg(providers, HashMap::new(), HashMap::new()))
        .err()
        .unwrap_or_default();
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("providers.acme.api_key") && e.to_lowercase().contains("non-empty")),
        "a non-empty canonical key must not raise the empty-secret error; got: {errs:?}"
    );
}

#[test]
fn test_validate_refuses_per_lane_durations_past_the_runtime_horizon() {
    let mut providers = HashMap::new();
    let mut provider = make_provider(proto_a(), "https://api.example.com", "API_KEY");
    provider.health = Some(busbar_kernel::config::providers::HealthCfg {
        mode: busbar_kernel::config::providers::HealthMode::Active,
        interval_secs: Some(MAX_DURATION_SECS + 1),
        timeout_secs: Some(1u64 << 63),
    });
    providers.insert("myprovider".to_string(), provider);
    let mut models = HashMap::new();
    let mut model = make_model("myprovider", 1);
    model.attempt_timeout_ms = Some(u64::MAX);
    models.insert("m".to_string(), model);
    let mut member = make_member("m");
    member.attempt_timeout_ms = Some(MAX_DURATION_MS + 1);
    let mut pools = HashMap::new();
    pools.insert("p".to_string(), make_pool(vec![member]));
    let mut cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("over-horizon per-lane durations must fail validation");
    for needle in [
        "health.interval_secs (946080001) exceeds",
        "health.timeout_secs (9223372036854775808) exceeds",
        "model 'm' has attempt_timeout_ms: 18446744073709551615, above the maximum",
        "member 'm' has attempt_timeout_ms: 946080000001, above the maximum",
    ] {
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "expected a named refusal containing {needle:?}; got: {errs:?}"
        );
    }

    let p = cfg.providers.get_mut("myprovider").expect("provider");
    p.health = Some(busbar_kernel::config::providers::HealthCfg {
        mode: busbar_kernel::config::providers::HealthMode::Active,
        interval_secs: Some(MAX_DURATION_SECS),
        timeout_secs: Some(MAX_DURATION_SECS),
    });
    cfg.models.get_mut("m").expect("model").attempt_timeout_ms = Some(MAX_DURATION_MS);
    cfg.pools.get_mut("p").expect("pool").members[0].attempt_timeout_ms = Some(MAX_DURATION_MS);
    assert!(
        validate(&cfg).is_ok(),
        "the boundary values must not error: {:?}",
        validate(&cfg)
    );
}

// These values describe classes and fees; they contain no plugin callbacks or registry.
fn plane_card(
    plane: &str,
    lane: &str,
    entry: &str,
) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    let key = format!(
        "{plane}{}{lane}",
        busbar_kernel_ledger::cost::PLANE_LANE_SEP
    );
    [(key, serde_yaml::from_str(entry).expect("an entry parses"))].into()
}

#[test]
fn an_empty_error_map_is_valid_and_an_unknown_class_word_is_not() {
    let cfg_with = |error_map: HashMap<String, String>| {
        let mut p = make_provider(proto_a(), "https://api.example.com", "API_KEY");
        p.error_map = error_map;
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), p);
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("p", 10));
        let mut pools = HashMap::new();
        pools.insert("mypool".to_string(), make_pool(vec![make_member("m")]));
        make_root_cfg(providers, models, pools)
    };
    assert!(
        validate(&cfg_with(HashMap::new())).is_ok(),
        "an empty error_map relies on the HTTP status and is valid"
    );
    let errs = validate(&cfg_with(
        [("1234".to_string(), "not_a_status_class".to_string())].into(),
    ))
    .expect_err("an unknown class word is refused");
    assert!(errs.join(" | ").contains("invalid StatusClass"), "{errs:?}");
}

#[test]
fn test_a_provider_the_destination_guard_will_refuse_is_named_at_validate() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let warned = |base_url: &str, block: bool, allow: &[&str]| -> Vec<String> {
        let mut providers = HashMap::new();
        providers.insert(
            "local".to_string(),
            make_provider(proto_a(), base_url, "API_KEY"),
        );
        let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        cfg.guard.block_private_addresses = block;
        cfg.guard.allow = allow.iter().map(|s| s.to_string()).collect();
        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));
        assert!(result.is_ok(), "it still validates: {base_url}: {result:?}");
        cap.messages()
            .into_iter()
            .filter(|m| m.contains("names the private or loopback host"))
            .collect()
    };
    for (url, host) in [
        ("http://127.0.0.1:11434", "127.0.0.1"),
        ("http://10.1.2.3/", "10.1.2.3"),
        ("http://localhost:8080/v1", "localhost"),
        ("http://[::1]:8080", "::1"),
    ] {
        let lines = warned(url, true, &[]);
        assert_eq!(lines.len(), 1, "one line for {url}: {lines:?}");
        assert!(
            lines[0].starts_with(&format!(
                "provider 'local' base_url names the private or loopback host '{host}': "
            )) && lines[0].contains(&format!("Add '{host}' to advanced.allow_destinations"))
                && lines[0].contains("diag=BUSBAR-3025"),
            "{}",
            lines[0]
        );
    }
    for allow in [&["10.1.2.3"][..], &["10.0.0.0/8"][..], &["10.1.2.3/32"][..]] {
        assert!(
            warned("http://10.1.2.3/", true, allow).is_empty(),
            "{allow:?}"
        );
    }
    for (url, allow) in [
        ("http://localhost/", "LOCALHOST."),
        ("http://service.localhost/", "*.LOCALHOST."),
        ("http://[::1]/", "[::1]"),
        ("http://[::1]/", "[::1]/128"),
    ] {
        assert!(
            warned(url, true, &[allow]).is_empty(),
            "the guard admits {url} through {allow}"
        );
    }
    for (url, allow) in [
        ("http://localhost/", "*.localhost."),
        ("http://other.localhost/", "service.localhost."),
        ("http://[::1]/", "[::2]"),
    ] {
        assert!(
            !warned(url, true, &[allow]).is_empty(),
            "{allow} does not admit {url}"
        );
    }
    assert!(warned("http://10.1.2.3/", true, &["10.2.0.0/16"]).len() == 1);
    assert!(
        warned("http://10.1.2.3/", false, &[]).is_empty(),
        "the guard is off"
    );
    assert!(
        warned("https://api.example.com", true, &[]).is_empty(),
        "a public host"
    );
}

fn base_url_verdict(base: &str) -> Result<(), Vec<String>> {
    let mut providers = HashMap::new();
    providers.insert("p".to_string(), make_provider(proto_b(), base, "API_KEY"));
    validate(&make_root_cfg(providers, HashMap::new(), HashMap::new()))
}

#[test]
fn test_http_container_name_base_url_is_rejected() {
    for base in [
        "http://ollama:11434",
        "http://ollama",
        "http://vllm-server:8000/v1",
        "http://host.docker.internal:11434",
        "http://localhost.example.com:11434",
        "http://notlocalhost:11434",
    ] {
        let errs = base_url_verdict(base).expect_err(&format!(
            "'{base}' names no private literal and must be refused"
        ));
        assert!(
            errs.iter()
                .any(|e| e.contains("must use https for a public host")),
            "'{base}': expected the https-for-public-host diagnostic; got: {errs:?}"
        );
    }

    assert!(base_url_verdict("https://ollama:11434").is_ok());
}

#[test]
fn test_http_localhost_subdomain_base_url_is_accepted() {
    for base in [
        "http://localhost:11434",
        "http://ollama.localhost:11434",
        "http://api.ollama.localhost/v1",
        "http://LOCALHOST:11434",
        "http://Ollama.LocalHost:11434",
    ] {
        assert!(
            base_url_verdict(base).is_ok(),
            "'{base}' is a localhost name and may use http; got: {:?}",
            base_url_verdict(base)
        );
    }
}

#[test]
fn an_env_placeholder_base_url_skips_the_scheme_check_under_validate_only() {
    let unset = vec!["OLLAMA_BASE".to_string()];
    let with_unset = |base: &str| {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider(proto_b(), base, "API_KEY"));
        validate_with_unset(
            &make_root_cfg(providers, HashMap::new(), HashMap::new()),
            &unset,
        )
    };

    assert!(
        with_unset("OLLAMA_BASE").is_ok(),
        "an unset-var placeholder skips the scheme check: {:?}",
        with_unset("OLLAMA_BASE")
    );

    assert!(base_url_verdict("OLLAMA_BASE").is_err());

    assert!(with_unset("http://OLLAMA_BASE.example.com").is_err());
    assert!(with_unset("http://api.example.com").is_err());
}

// Observes actual tracing events; it supplies no application or plugin behavior.
#[derive(Clone, Default)]
struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl WarnCapture {
    fn messages(&self) -> Vec<String> {
        self.0.lock().expect("warning log lock").clone()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        #[derive(Default)]
        struct Fields {
            message: String,
            diag: String,
            context: String,
        }
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                match field.name() {
                    "message" => self.message = format!("{value:?}"),
                    "diag" => self.diag = format!("{value:?}"),
                    _ => self
                        .context
                        .push_str(&format!(" {}={value:?}", field.name())),
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "message" => self.message = value.into(),
                    "diag" => self.diag = value.into(),
                    _ => self
                        .context
                        .push_str(&format!(" {}={value:?}", field.name())),
                }
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        fields.message.push_str(&fields.context);
        if !fields.diag.is_empty() {
            fields.message.push_str(&format!(" diag={}", fields.diag));
        }
        self.0
            .lock()
            .expect("warning log lock")
            .push(fields.message);
    }
}
