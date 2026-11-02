use super::*;

use crate::config;

fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    config::RootCfg {
        plane_defs: Default::default(),
        plane_pools: Default::default(),
        plane_sections: Default::default(),
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),

        endpoint_resources: Default::default(),
        oauth_as: None,
        credentials: Default::default(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,

        providers: providers
            .into_iter()
            .map(|(name, p)| (name, p.into()))
            .collect(),
        models,
        pools,
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        hooks: HashMap::new(),
        admin_auth: config::default_admin_auth_names(),
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: Some(crate::test_support::stand_in_store()),
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
    crate::testkit::neutral_protocols::NEUTRAL_PROTOCOLS
        .iter()
        .filter(|d| d.codec.is_some())
        .nth(nth)
        .map(|d| d.name)
        .unwrap_or_else(|| {
            panic!(
                "the test binary ships fewer than {} codec protocols",
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
fn test_provider_auth_style_is_a_declared_word() {
    for word in [
        "bearer",
        "api-key",
        "jwt-bearer",
        "oauth-client-credentials",
        "x-double-mint",
    ] {
        let style = serde_yaml::from_str::<config::ProviderAuth>(word)
            .unwrap_or_else(|e| panic!("declared style '{word}' must parse: {e}"));
        assert_eq!(style.as_str(), word);
    }
    let refused = serde_yaml::from_str::<config::ProviderAuth>("oauth2")
        .expect_err("'oauth2' is declared by no plugin and must fail to deserialize")
        .to_string();
    assert!(
        refused.starts_with(
            "unknown variant `oauth2`, expected one of `bearer`, `api-key`, `jwt-bearer`, \
             `oauth-client-credentials`, `x-double-mint`"
        ),
        "an undeclared style is refused in serde's words over the declared list: {refused}"
    );
}

#[test]
fn a_token_url_is_judged_for_any_style_declaring_it() {
    crate::test_support::register_neutral_test_plane();
    let build = |word: &str| -> Vec<String> {
        let mut providers = HashMap::new();
        let mut mint = make_provider(proto_b(), "https://api.example.com", "API_KEY");
        mint.auth = Some(config::ProviderAuth::named(word));
        providers.insert("mint".to_string(), mint);
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("mint", 10));
        let mut pools = HashMap::new();
        pools.insert("p".to_string(), make_pool(vec![make_member("m")]));
        validate(&make_root_cfg(providers, models, pools))
            .err()
            .unwrap_or_default()
    };
    let errs = build("x-double-mint");
    for want in [
        "provider 'mint' uses auth: x-double-mint but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to)",
        "provider 'mint' uses auth: x-double-mint but has no `scope`",
    ] {
        assert!(
            errs.iter().any(|e| e == want),
            "a style declaring STYLE_ENDPOINT_TOKEN_URL is judged by the bit: want {want:?} in {errs:?}"
        );
    }
    let errs = build("bearer");
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("token_url") || e.contains("scope")),
        "a style stating no endpoint is not judged for one: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_bad_protocol() {
    crate::test_support::register_neutral_test_plane();

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
    for proto in crate::ingress::protocols::known_protocols() {
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();

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
fn vet_token_uri_takes_http_to_a_private_host_and_refuses_a_public_one() {
    for uri in [
        "http://10.0.0.5/token",
        "http://192.168.1.20/token",
        "http://127.0.0.1:9000/token",
        "http://[::1]/token",
        "https://oauth2.googleapis.com/token",
    ] {
        assert_eq!(
            vet_token_uri(uri, &MetadataPosture::default()),
            Ok(()),
            "token_uri {uri} must be accepted, as 1.5.5 did"
        );
    }
    let uri = "http://oauth2.example.com/token";
    assert_eq!(
        vet_token_uri(uri, &MetadataPosture::default()),
        Err(format!(
            "service-account token_uri must use https for a public host (got '{uri}'); it receives the signed JWT assertion, so plaintext http is permitted only for a private/loopback endpoint"
        )),
        "a public http token_uri must be refused in 1.5.5's words"
    );
    let imds = vet_token_uri("http://169.254.169.254/token", &MetadataPosture::default());
    assert!(
        imds.as_ref().is_err_and(|e| e.contains("cloud-metadata")),
        "a token_uri at the metadata host must be refused as cloud-metadata; got: {imds:?}"
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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

fn make_auth_chain(modules: &[&str], _upstream: crate::auth::UpstreamCreds) -> config::AuthCfg {
    let mut auth = config::AuthCfg::default_none();
    auth.chain = modules
        .iter()
        .map(|m| config::AuthChainEntry::bare(*m))
        .collect();

    if modules.contains(&crate::config::KEYS_MODULE) {
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
    crate::test_support::register_neutral_test_plane();
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
fn test_the_boot_count_shows_eleven_and_the_printed_list_every_enforced_entry() {
    let counted = crate::config_validate::metadata_denylist_entries();
    assert_eq!(counted.len(), 11, "1.5.5's displayed count: {counted:?}");
    let printed = crate::config_validate::metadata_enforced_entries();
    assert_eq!(printed.len(), 13, "every enforced entry: {printed:?}");
    for entry in &counted {
        assert!(printed.contains(entry), "{entry} is printed: {printed:?}");
    }
    for entry in ["fd00:ec2::23", "fe80::/10"] {
        assert!(
            printed.iter().any(|e| e == entry),
            "{entry} is printed: {printed:?}"
        );
    }
    let task: std::net::IpAddr = "fd00:ec2::23".parse().expect("an address");
    assert!(
        busbar_contract::net::ip_is_cloud_metadata(&task),
        "the EC2 task-metadata endpoint is enforced"
    );
    let imds: std::net::IpAddr = "fd00:ec2::254".parse().expect("an address");
    assert!(busbar_contract::net::ip_is_cloud_metadata(&imds));
    assert!(
        busbar_contract::net::host_is_link_local_v6("fe80::1"),
        "IPv6 link-local is refused as metadata is"
    );
}

#[test]
fn test_validate_accepts_https_base_url() {
    crate::test_support::register_neutral_test_plane();
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
fn test_validate_rejects_oversized_inbound_and_webhook_concurrency_limits() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.max_inbound_concurrent = tokio::sync::Semaphore::MAX_PERMITS + 1;

    let errs = validate(&cfg).expect_err("the oversized limit must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("max_inbound_concurrent")),
        "expected an oversized max_inbound_concurrent error; got: {errs:?}"
    );

    cfg.limits.max_inbound_concurrent = 0;
    assert!(
        validate(&cfg).is_ok(),
        "0 (disabled) and the exact boundary value must not error"
    );
}

#[test]
fn test_validate_accepts_omitted_max_concurrent() {
    crate::test_support::register_neutral_test_plane();
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
fn test_minimal_model_config_without_max_concurrent_deserializes() {
    let m: config::ModelCfg = serde_yaml::from_str("provider: myprovider\n")
        .expect("a model config with only `provider` must load (max_concurrent is optional)");
    assert_eq!(m.provider, "myprovider");
    assert_eq!(
        m.max_concurrent, None,
        "an omitted max_concurrent must be None (unbounded)"
    );
    assert_eq!(
        m.max_requests, -1,
        "an omitted max_requests must default to -1 (unlimited)"
    );
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
    cfg.limits.reasoning_effort_budgets = crate::config::ReasoningEffortBudgets {
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
    cfg2.limits.reasoning_effort_budgets = crate::config::ReasoningEffortBudgets {
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

    for name in ["apix", "api-pool", "api_portal", "adminx"] {
        assert!(
            !reserved_admin_name(name),
            "'{name}' is a boundary-safe name and must not be treated as reserved"
        );
        assert!(
            !reserved_legacy_admin_name(name),
            "'{name}' is a boundary-safe name and must not be treated as the legacy reserved name"
        );
    }
    assert!(reserved_admin_name("api"), "'api' must be reserved");
    assert!(
        reserved_legacy_admin_name("admin"),
        "'admin' must stay reserved"
    );
    assert!(
        reserved_legacy_admin_name("admin/x"),
        "'admin/x' puts admin in the first path segment and must stay reserved"
    );
    assert!(
        !reserved_admin_name("admin"),
        "'admin' is not the native-API root; it is refused by the legacy rule, not this one"
    );

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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::install_admin_verb_table_double();
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
        crate::config::operator_provider().to_string(),
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
    crate::test_support::register_neutral_test_plane();

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

    cfg.limits.rate_sweep_interval = crate::config::DEFAULT_RATE_SWEEP_INTERVAL;
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
        cfg.auth = Some(make_auth_chain(&[legacy], crate::auth::UpstreamCreds::Own));
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
    crate::test_support::register_neutral_test_plane();

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(&["okta"], crate::auth::UpstreamCreds::Own));
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
        crate::auth::UpstreamCreds::Own,
    ));
    let errs = validate(&cfg).expect_err("the removed 'tokens' module must still fail validation");
    assert!(
        errs.iter().any(|e| e.contains("was REMOVED in 1.5.0")),
        "expected the removed-module migration message; got: {errs:?}"
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(&["keys"], crate::auth::UpstreamCreds::Own));
    assert!(
        validate(&cfg).is_ok(),
        "auth.chain: [keys] must validate; got: {:?}",
        validate(&cfg)
    );

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(&[], crate::auth::UpstreamCreds::Own));
    assert!(
        validate(&cfg).is_ok(),
        "an empty auth chain must validate (open front door)"
    );
}

#[test]
fn test_1_5_2_keys_chain_without_mint_path_is_boot_error() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = crate::config::AuthCfg::default_none();
    auth.chain = vec![crate::config::AuthChainEntry::bare(
        crate::config::KEYS_MODULE,
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
    crate::test_support::register_neutral_test_plane();
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = crate::config::AuthCfg::default_none();
    auth.chain = vec![crate::config::AuthChainEntry::bare(
        crate::config::KEYS_MODULE,
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

    let mut auth_ok = crate::config::AuthCfg::default_none();
    auth_ok.chain = vec![crate::config::AuthChainEntry::bare(
        crate::config::KEYS_MODULE,
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
    crate::test_support::register_neutral_test_plane();
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(
        &["test-idp-double"],
        crate::auth::UpstreamCreds::Own,
    ));
    let r = validate(&cfg);
    assert!(
        r.is_ok(),
        "an oidc (externally-issued) chain must need no mint path; got: {r:?}"
    );
}

#[test]
fn test_1_5_2_keys_chain_external_admin_needs_full_scope_to_mint() {
    crate::test_support::register_neutral_test_plane();
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);

    let mut auth = crate::config::AuthCfg::default_none();
    auth.chain = vec![crate::config::AuthChainEntry::bare(
        crate::config::KEYS_MODULE,
    )];
    auth.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));

    auth.admin_auth = vec![crate::config::AuthChainEntry::bare("test-external-idp")];
    cfg.auth = Some(auth);
    let errs = validate(&cfg)
        .expect_err("a keys chain whose only admin module cannot mint must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("no admin credential can mint")),
        "expected the mint-path boot error for the github/ldap gap; got: {errs:?}"
    );

    let mut auth_ok = crate::config::AuthCfg::default_none();
    auth_ok.chain = vec![crate::config::AuthChainEntry::bare(
        crate::config::KEYS_MODULE,
    )];
    auth_ok.signing_key = Some(config::SecretRef::env("BUSBAR_SIGNING_KEY"));
    let mut admin = crate::config::AuthChainEntry::bare("test-external-idp");
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
fn test_legacy_auth_keys_are_rejected_at_parse() {
    let yaml = r#"
listen: "0.0.0.0:8080"
auth:
  mode: token
  token: "stale-legacy-secret"
  client_tokens: ["real-secret"]
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  model-1:
    provider: acme
    max_concurrent: 10
"#;
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(yaml)
        .expect_err("a config setting the removed auth keys must fail to parse");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field"),
        "expected serde's unknown-field error at parse; got: {msg}"
    );

    assert!(
        !msg.contains("stale-legacy-secret"),
        "the parse error must not leak the configured token value; got: {msg}"
    );

    let yaml2 = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key_env: ACME_KEY
models:
  model-1:
    provider: acme
"#;
    let err2 = serde_yaml::from_str::<crate::config::DeployCfg>(yaml2)
        .expect_err("the removed api_key_env key must fail to parse");
    assert!(
        err2.to_string().contains("missing field `api_key`"),
        "expected the entry with no credential refused; got: {err2}"
    );
}

use crate::test_support::warn_capture::WarnCapture;

#[test]
fn test_validate_passthrough_warns_on_nonempty_configured_key() {
    crate::test_support::register_neutral_test_plane();

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
        crate::auth::UpstreamCreds::Passthrough,
    ));

    cfg.upstream_credentials = crate::auth::UpstreamCreds::Passthrough;

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
    crate::test_support::register_neutral_test_plane();

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
        crate::auth::UpstreamCreds::Passthrough,
    ));

    cfg.upstream_credentials = crate::auth::UpstreamCreds::Passthrough;

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
    crate::test_support::register_neutral_test_plane();

    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(&[], crate::auth::UpstreamCreds::Own));
    assert!(
        validate(&cfg).is_ok(),
        "an empty auth chain carries no token requirement"
    );
}

#[test]
fn test_ssrf_blocks_metadata_denylist_by_default() {
    for blocked in [
        "https://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/",
        "http://169.254.169.254/",
        "https://169.254.170.2/v2/credentials",
        "https://169.254.0.23/",
        "https://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/",
        "https://168.63.129.16/",
        "https://[fd00:ec2::254]/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://METADATA.INTERNAL/",
        "https://metadata.tencentyun.com/",
        "https://metadata.platformequinix.com/",
        "https://instance-data/latest/meta-data/",
        "https://instance-data.ec2.internal/",
        "https://metadata.google.internal./",
        "https://[::ffff:169.254.169.254]/",
        "https://[::169.254.169.254]/",
        "https://[::ffff:169.254.170.2]/",
        "https://[::ffff:100.100.100.200]/",
        "https://[::ffff:168.63.129.16]/",
        "https://2852039166/",
        "https://0xa9fea9fe/",
        "https://169.254.169.254./",
        "https://169%2E254%2E169%2E254/",
        "https://169.254.169.254:8443/",
        "https://user:pass@169.254.169.254/latest",
        "https://169.254.43518/",
        "https://169.16689662/",
    ] {
        let got = ssrf_blocked_host(blocked, &[], false, &[]);
        let host = got.as_deref().unwrap_or_else(|| {
            panic!("expected '{blocked}' to be flagged as a metadata SSRF target")
        });
        assert!(
            !host.is_empty(),
            "blocked '{blocked}' returned an EMPTY host string"
        );
    }
}

#[test]
fn test_ssrf_blocked_returns_exact_host_string() {
    assert_eq!(
        ssrf_blocked_host("https://169.254.169.254/latest", &[], false, &[]).as_deref(),
        Some("169.254.169.254")
    );
    assert_eq!(
        ssrf_blocked_host("https://user:pass@169.254.169.254:8443/x", &[], false, &[]).as_deref(),
        Some("169.254.169.254"),
        "userinfo and port must be stripped from the returned host"
    );
    assert_eq!(
        ssrf_blocked_host("https://metadata.google.internal/", &[], false, &[]).as_deref(),
        Some("metadata.google.internal")
    );
    assert_eq!(
        ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).as_deref(),
        Some("100.100.100.200")
    );
}

#[test]
fn test_expand_alternate_ipv4_imds_obfuscations() {
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        expand_alternate_ipv4("2852039166"),
        Some(imds),
        "1-part decimal"
    );
    assert_eq!(
        expand_alternate_ipv4("169.16689662"),
        Some(imds),
        "2-part inet_aton"
    );
    assert_eq!(
        expand_alternate_ipv4("169.254.43518"),
        Some(imds),
        "3-part inet_aton"
    );

    assert_eq!(
        expand_alternate_ipv4("169.254.169.254"),
        None,
        "an already-canonical dotted quad must return None from the expander"
    );
    assert_eq!(expand_alternate_ipv4("8.8.8.8"), None);

    for base in [
        "https://2852039166/",
        "https://169.16689662/",
        "https://169.254.43518/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "obfuscated IMDS form '{base}' must be blocked"
        );
    }
}

#[test]
fn test_expand_alternate_ipv4_imds_hex_octal_forms() {
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();

    assert_eq!(
        expand_alternate_ipv4("0xA9FEA9FE"),
        Some(imds),
        "single-integer hex form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0xA9.0xFE.0xA9.0xFE"),
        Some(imds),
        "dotted per-octet hex form of IMDS"
    );

    assert_eq!(
        expand_alternate_ipv4("025177524776"),
        Some(imds),
        "single-integer octal form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0251.0376.0251.0376"),
        Some(imds),
        "dotted per-octet octal form of IMDS"
    );

    for base in [
        "https://0xA9FEA9FE/",
        "https://0xA9.0xFE.0xA9.0xFE/",
        "https://025177524776/",
        "https://0251.0376.0251.0376/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "hex/octal-obfuscated IMDS form '{base}' must be blocked"
        );
    }
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

#[test]
fn test_metadata_list_entries_are_mapped() {
    let full_width_ip = "\u{ff11}\u{ff10}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}";
    let full_width_name = "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}.example";
    for (entry, target) in [
        (full_width_ip, "https://10.99.99.99/v1"),
        (full_width_ip, "https://[::ffff:10.99.99.99]/v1"),
        (full_width_name, "https://meta.example/v1"),
        (full_width_name, "meta.example:443"),
    ] {
        assert!(
            ssrf_blocked_host(target, &[], false, &[entry.to_string()]).is_some(),
            "the entry `{entry}` must block `{target}`"
        );
        assert!(
            ssrf_blocked_host(target, &[entry.to_string()], false, &[entry.to_string()]).is_none(),
            "the allow entry `{entry}` must lift `{target}`"
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
    crate::test_support::register_neutral_test_plane();
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth_chain(&[], crate::auth::UpstreamCreds::Own));
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
fn test_ssrf_allows_private_and_loopback_by_default() {
    for allowed in [
        "https://127.0.0.1/",
        "https://10.0.0.1/v1",
        "https://172.16.0.1/",
        "https://192.168.1.1:8443/",
        "https://[::1]/",
        "https://[::1]:443/",
        "https://[fe80::1]/",
        "https://[fc00::1]/",
        "https://0.0.0.0/",
        "https://user:pass@10.0.0.5/path",
        "https://100.64.0.1/",
        "https://100.127.255.255/",
        "https://[::ffff:10.0.0.1]/",
        "https://[::ffff:100.64.0.1]/",
        "https://[::127.0.0.1]/",
        "https://2130706433/",
        "https://127.1/",
        "https://localhost/",
        "https://api.localhost:11434/v1",
        "https://service.internal.localhost/",
        "https://API.LOCALHOST/",
    ] {
        assert!(
                ssrf_blocked_host(allowed, &[], false, &[]).is_none(),
                "expected '{allowed}' to be ALLOWED (private/loopback is a local-model target, not metadata)"
            );
    }
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
    crate::test_support::register_neutral_test_plane();

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
fn test_ssrf_cgnat_allowed_but_alibaba_literal_blocked() {
    assert!(ssrf_blocked_host("https://100.64.0.0/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.127.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.63.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.128.0.1/", &[], false, &[]).is_none());

    assert!(
            ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).is_some(),
            "the Alibaba metadata literal 100.100.100.200 must stay blocked even though CGNAT is allowed"
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
    crate::test_support::register_neutral_test_plane();

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
fn test_ssrf_blocked_host_allows_public_targets() {
    for ok in [
        "https://api.acme.example.com/v1/messages",
        "https://api.vendor-a.example.com",
        "https://example.com:8443/v1",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
        "https://mylocalhost.com/",
        "https://notlocalhost.example.com/",
        "https://localhost.example.com/",
    ] {
        assert!(
            ssrf_blocked_host(ok, &[], false, &[]).is_none(),
            "expected '{ok}' to be allowed (not an SSRF target)"
        );
    }
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
fn test_on_exhausted_is_structured_and_rejects_malformed_at_parse() {
    assert!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("bogus").is_err(),
        "an unknown on_exhausted keyword must fail to parse"
    );
    assert!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("\"fallback_pool:backup\"").is_err(),
        "the retired string form 'fallback_pool:name' must fail to parse (structured form only)"
    );
    assert!(matches!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("reject").unwrap(),
        config::OnExhaustedCfg::Reject
    ));
    assert!(matches!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("least_bad").unwrap(),
        config::OnExhaustedCfg::LeastBad
    ));
    match serde_yaml::from_str::<config::OnExhaustedCfg>("{ fallback_pool: backup }").unwrap() {
        config::OnExhaustedCfg::FallbackPool(name) => assert_eq!(name, "backup"),
        other => panic!("expected FallbackPool, got {other:?}"),
    }
}

#[test]
fn test_validate_accepts_existing_fallback_pool() {
    crate::test_support::register_neutral_test_plane();
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
fn test_queue_config_parses_and_both_keys_conflict() {
    match serde_yaml::from_str::<config::OnExhaustedCfg>("{ queue: { max_ms: 250 } }").unwrap() {
        config::OnExhaustedCfg::Queue { max_ms } => assert_eq!(max_ms, 250),
        other => panic!("expected Queue, got {other:?}"),
    }
    let both = serde_yaml::from_str::<config::OnExhaustedCfg>(
        "{ fallback_pool: cold, queue: { max_ms: 250 } }",
    );
    let err = format!("{}", both.expect_err("both keys must be a conflict error"));
    assert!(
        err.contains("exactly one of"),
        "both-keys error must say exactly one of fallback_pool | queue; got: {err}"
    );
}

#[test]
fn test_validate_accepts_queue_within_budget() {
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
fn test_affinity_mode_is_a_closed_enum() {
    assert_eq!(
        serde_yaml::from_str::<config::AffinityMode>("session").unwrap(),
        config::AffinityMode::Session
    );
    assert!(
        serde_yaml::from_str::<config::AffinityMode>("sticky").is_err(),
        "'sticky' is not a supported affinity mode and must fail to deserialize"
    );
}

#[test]
fn test_validate_accepts_session_affinity_mode() {
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
            serde_yaml::from_str(include_str!("fixtures/client_credentials_style.yaml"))
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
fn test_allow_override_matches_obfuscated_spellings() {
    let allow = vec!["169.254.169.254".to_string()];
    for base in [
        "https://169.254.169.254/",
        "http://2852039166/",
        "http://[::ffff:169.254.169.254]/",
        "https://169.254.169.254./",
    ] {
        assert!(
            ssrf_blocked_host(base, &allow, false, &[]).is_none(),
            "an allow entry must unblock the obfuscated spelling '{base}'"
        );
    }

    assert!(
        ssrf_blocked_host("https://168.63.129.16/", &allow, false, &[]).is_some(),
        "a non-allowed metadata IP must stay blocked"
    );
}

#[test]
fn test_blocked_metadata_hosts_extends_denylist() {
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();

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
        serde_yaml::from_str("a-tool-server:\n  url: \"https://tools.example.com/rpc\"\n")
            .expect("yaml");
    let section = crate::config::plane_sections::DeclaredSections::parse(key, written)
        .expect("a one-registration tools section must parse")
        .0
        .remove(key)
        .expect("the section is carried");
    assert!(
        section.is_present(),
        "the fixture must be a section the operator wrote content for"
    );
    section
}

fn rate_card_of(entries: &[&str]) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    entries
        .iter()
        .map(|m| (m.to_string(), config::RateEntryCfg::default()))
        .collect()
}

#[test]
fn test_validate_rate_card_completeness_fails_closed_with_paste_stub() {
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["claude-opus-4"]);
    cfg.rate_card = Some(rate_card_of(&["some-other-model"]));
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
    cfg_ok.rate_card = Some(rate_card_of(&["claude-opus-4"]));
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
    cfg.rate_card = Some(rate_card_of(&["some-priced-model"]));
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
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();
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
        cfg.rate_card = Some([("m".to_string(), entry)].into_iter().collect());
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
    cfg.rate_card = Some([("m".to_string(), entry)].into_iter().collect());
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn test_validate_rate_card_stubs_every_missing_model() {
    let mut cfg = cost_cfg(&["alpha", "long-model-name"]);

    cfg.rate_card = Some(rate_card_of(&[]));
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
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["smart"]);
    cfg.models.get_mut("smart").unwrap().upstream_model = Some("gpt-5".to_string());

    cfg.rate_card = Some(rate_card_of(&["smart"]));
    assert!(
        validate(&cfg).is_ok(),
        "the card is keyed by config model name; got: {:?}",
        validate(&cfg)
    );

    cfg.rate_card = Some(rate_card_of(&["gpt-5"]));
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
    cfg.rate_card = Some(std::collections::BTreeMap::from([(
        "m".to_string(),
        config::RateEntryCfg {
            input_utok: f64::NAN,
            output_utok: -1.0,
            cache_read_utok: f64::INFINITY,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]));
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
    cfg.rate_card = Some(parse("m: { input_utok: 1, units: { output: 5 } }\n").expect("parses"));
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
    crate::test_support::register_neutral_test_plane();
    use crate::test_support::warn_capture::WarnCapture;
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
    cfg.rate_card = Some(card);

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
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["claude-sonnet"]);

    let card: std::collections::BTreeMap<String, config::RateEntryCfg> =
        serde_yaml::from_str("claude-sonnet:\n  input_utok: 3.0\n  output_utok: 15.0\n")
            .expect("the two-tier card must parse");
    cfg.rate_card = Some(card);

    assert!(
        validate(&cfg).is_ok(),
        "WITNESS: boot ACCEPTS a card that leaves two classes unpriced — #77(5) says it must \
         refuse. If this line starts failing, the refusal has landed and this test should be \
         inverted, not deleted."
    );

    let micros = |card: &std::collections::BTreeMap<String, config::RateEntryCfg>,
                  units: &std::collections::BTreeMap<String, u64>| {
        let model = crate::cost::CostModel::resolve_parts(
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
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    let card: std::collections::BTreeMap<String, config::RateEntryCfg> = serde_yaml::from_str(
        "claude-sonnet:\n  input_utok: 3.0\n  output_utok: 15.0\n  cache_read_utok: 0.0\n  \
         cache_write_utok: 0.0\n",
    )
    .expect("the four-tier card must parse");
    cfg.rate_card = Some(card);

    assert!(
        validate(&cfg).is_ok(),
        "#77(5): free is an EXPLICIT zero row — a tier the operator WROTE as 0.0 is priced, and \
         priced at nothing is legal: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_rate_card_entry_all_four_explicit_zeros_still_only_warns() {
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["free-on-purpose"]);
    let card: std::collections::BTreeMap<String, config::RateEntryCfg> = serde_yaml::from_str(
        "free-on-purpose:\n  input_utok: 0.0\n  output_utok: 0.0\n  cache_read_utok: 0.0\n  \
         cache_write_utok: 0.0\n",
    )
    .expect("the all-zero card must parse");
    cfg.rate_card = Some(card);
    assert!(
        validate(&cfg).is_ok(),
        "an EXPLICITLY all-zero entry is a deliberate free model: {:?}",
        validate(&cfg).err()
    );
}

#[test]
fn test_validate_allows_a_flat_card_beside_a_plane_with_no_card_of_its_own() {
    crate::test_support::register_neutral_test_plane();
    let mut cfg = cost_cfg(&["claude-sonnet"]);
    cfg.rate_card = Some(std::collections::BTreeMap::from([(
        "claude-sonnet".to_string(),
        priced_entry(),
    )]));
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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

fn group(parent: Option<&str>, limits: Vec<crate::config::groups::LimitCfg>) -> config::GroupCfg {
    config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits,
        ..Default::default()
    }
}

fn limit_requests_per_minute(amount: u64) -> crate::config::groups::LimitCfg {
    crate::config::groups::LimitCfg {
        metric: crate::config::groups::LimitMetric::Requests,
        amount,
        per: Some(crate::config::groups::LimitWindow::Minute),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

#[test]
fn test_validate_groups_faults_are_named_with_fixes() {
    crate::test_support::register_neutral_test_plane();

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

#[test]
fn test_removed_member_keys_rejected_at_parse() {
    let legacy_cost =
        "members:\n  - model: m\n    cost_per_mtok: { input_utok: 1.0, output_utok: 2.0 }\n";
    let err = serde_yaml::from_str::<config::PoolCfg>(legacy_cost)
        .expect_err("the removed cost_per_mtok member key must fail to parse");
    assert!(
        err.to_string().contains("unknown field"),
        "expected an unknown-field error for cost_per_mtok; got: {err}"
    );

    let legacy_target = "members:\n  - target: m\n";
    let err = serde_yaml::from_str::<config::PoolCfg>(legacy_target)
        .expect_err("the retired target: member key must fail to parse");
    assert!(
        err.to_string().contains("unknown field"),
        "expected an unknown-field error for target; got: {err}"
    );

    let ok = serde_yaml::from_str::<config::PoolCfg>("members:\n  - model: m\n").unwrap();
    assert_eq!(ok.members[0].model, "m");
}

fn auth_with_binding(
    chain: &[&str],
    module: &str,
    role: &str,
    binding: config::RoleBindingCfg,
) -> config::AuthCfg {
    let mut auth = make_auth_chain(chain, crate::auth::UpstreamCreds::Own);
    auth.role_bindings.insert(
        module.to_string(),
        std::collections::BTreeMap::from([(role.to_string(), binding)]),
    );
    auth
}

#[test]
fn test_validate_role_binding_module_must_be_in_a_chain() {
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
        !validate(&cfg).err().is_some_and(|errs| reserved(&errs)),
        "no operator row, no operator principal to shadow: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_secret_module_resolvability() {
    crate::test_support::register_neutral_test_plane();

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
    crate::test_support::register_neutral_test_plane();
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
        crate::test_support::store_double::KEY
    );
    assert_eq!(cfg.limits.rate_sweep_interval, 256);
}

#[test]
fn test_undefined_pool_member_is_refused_by_validate_in_1_5_5_words() {
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
fn test_validate_limits_boundary_fields_reject_zero_accept_one() {
    macro_rules! check_floor_one {
        ($field:ident, $needle:expr) => {{
            let mut bad = config::LimitsResolved::default();
            bad.$field = 0;
            let mut errs = Vec::new();
            validate_limits(&bad, &mut errs);
            assert!(
                errs.iter().any(|e| e.contains($needle)),
                "{}=0 must be rejected; got {errs:?}",
                stringify!($field)
            );

            let mut good = config::LimitsResolved::default();
            good.$field = 1;
            let mut errs = Vec::new();
            validate_limits(&good, &mut errs);
            assert!(
                !errs.iter().any(|e| e.contains($needle)),
                "{}=1 (the floor itself) must be ACCEPTED; got {errs:?}",
                stringify!($field)
            );
        }};
    }

    check_floor_one!(tls_handshake_timeout_secs, "tls_handshake_timeout_secs");
    check_floor_one!(
        request_body_read_timeout_secs,
        "request_body_read_timeout_secs"
    );

    check_floor_one!(max_honored_retry_after_secs, "max_honored_retry_after_secs");
    check_floor_one!(hard_down_cooldown_secs, "hard_down_cooldown_secs");
    check_floor_one!(
        upstream_error_body_max_bytes,
        "upstream_error_body_max_bytes"
    );
    check_floor_one!(default_max_tokens, "default_max_tokens");
    check_floor_one!(default_probe_interval_secs, "default_probe_interval_secs");
    check_floor_one!(default_probe_timeout_secs, "default_probe_timeout_secs");

    check_floor_one!(
        upstream_request_timeout_secs,
        "upstream_request_timeout_secs must be >= 1"
    );
    check_floor_one!(
        default_policy_timeout_ms,
        "default_policy_timeout_ms must be >= 1"
    );
}

#[test]
fn test_validate_limits_request_body_max_bytes_floor_and_ceiling_are_exact() {
    use crate::config::{REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR};

    let at_floor = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_FLOOR,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_floor, &mut errs);
    assert!(
        !errs.iter().any(|e| e.contains("below the")),
        "exactly the floor must be accepted; got {errs:?}"
    );

    let below_floor = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_FLOOR - 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&below_floor, &mut errs);
    assert!(
        errs.iter().any(|e| e.contains("below the")),
        "one byte below the floor must be rejected; got {errs:?}"
    );

    let at_ceil = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_CEIL,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_ceil, &mut errs);
    assert!(
        !errs.iter().any(|e| e.contains("exceeds the")),
        "exactly the ceiling must be accepted; got {errs:?}"
    );

    let over_ceil = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_CEIL + 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&over_ceil, &mut errs);
    assert!(
        errs.iter().any(|e| e.contains("exceeds the")),
        "one byte over the ceiling must be rejected; got {errs:?}"
    );
}

#[test]
fn datagram_line_memory_limit_accepts_unset_or_any_positive_usize() {
    for value in [None, Some(1), Some(usize::MAX)] {
        let limits = config::LimitsResolved {
            datagram_line_memory_bytes: value,
            ..config::LimitsResolved::default()
        };
        let mut errors = Vec::new();
        validate_limits(&limits, &mut errors);
        assert!(errors.is_empty(), "{value:?}: {errors:?}");
    }
}

#[test]
fn datagram_line_memory_limit_zero_is_a_config_validation_error() {
    let deploy = crate::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nlimits:\n  datagram_line_memory_bytes: 0\n",
    )
    .expect("zero has the right type; validation must reject it");
    let cfg = crate::config::resolve(&deploy, &HashMap::new()).expect("resolve the config");
    assert_eq!(cfg.limits.datagram_line_memory_bytes, Some(0));
    let mut errors = Vec::new();
    validate_limits(&cfg.limits, &mut errors);
    assert_eq!(
        errors,
        ["limits.datagram_line_memory_bytes must be >= 1 when set (omit it or use null to disable the limit)"],
    );
}

#[test]
fn test_validate_limits_max_inbound_concurrent_ceiling_is_exact() {
    let at_cap = config::LimitsResolved {
        max_inbound_concurrent: MAX_SEMAPHORE_PERMITS,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_cap, &mut errs);
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("max_inbound_concurrent must be <=")),
        "exactly MAX_SEMAPHORE_PERMITS must be accepted; got {errs:?}"
    );

    let over_cap = config::LimitsResolved {
        max_inbound_concurrent: MAX_SEMAPHORE_PERMITS + 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&over_cap, &mut errs);
    assert!(
        errs.iter()
            .any(|e| e.contains("max_inbound_concurrent must be <=")),
        "MAX_SEMAPHORE_PERMITS + 1 must be rejected; got {errs:?}"
    );
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

fn parse_auth(yaml: &str) -> config::AuthCfg {
    #[derive(serde::Deserialize)]
    struct Doc {
        #[serde(default)]
        auth: config::AuthDeployCfg,
        #[serde(default, rename = "identity-providers")]
        identity_providers: config::IdentityProviders,
    }
    let doc: Doc = serde_yaml::from_str(yaml).expect("auth yaml parses");
    let mut errors = Vec::new();
    let out = config::resolve_auth(&doc.auth, &doc.identity_providers, &mut errors);
    assert!(
        errors.is_empty(),
        "auth yaml must resolve cleanly: {errors:?}"
    );
    out
}

#[test]
fn test_public_url_requires_https() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.public_url = Some("http://api.busbar.example".to_string());
    let errs = validate(&cfg).expect_err("public http host must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && e.contains("https")),
        "missing https error: {errs:?}"
    );

    cfg.public_url = Some("http://127.0.0.1:8080".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("public_url")),
        "loopback http must be accepted: {res:?}"
    );

    cfg.public_url = Some("https://api.busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("public_url")),
        "public https must be accepted: {res:?}"
    );
}

#[test]
fn test_public_url_rejects_path_and_metadata() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.public_url = Some("https://api.busbar.example/x".to_string());
    let errs = validate(&cfg).expect_err("public_url with a path must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && (e.contains("path") || e.contains("bare origin"))),
        "missing path error: {errs:?}"
    );

    cfg.public_url = Some("https://169.254.169.254".to_string());
    let errs = validate(&cfg).expect_err("public_url at a metadata host must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && e.contains("metadata")),
        "missing metadata SSRF error: {errs:?}"
    );
}

#[test]
fn test_browser_login_requires_public_url() {
    let auth = parse_auth(
        "identity-providers:\n  oidc:\n    module: oidc-plugin\n    browser_login:\n      client_secret: { env: X }\n",
    );
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg.public_url = None;
    let errs = validate(&cfg).expect_err("browser_login without public_url must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("browser_login") && e.contains("public_url")),
        "error must name both browser_login and public_url: {errs:?}"
    );

    cfg.public_url = Some("https://busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("browser_login")),
        "browser_login error must clear once public_url is set: {res:?}"
    );
}

#[test]
fn test_role_binding_under_browser_method_active() {
    let auth = parse_auth(
        "identity-providers:\n  oidc:\n    module: oidc-plugin\n    browser_login:\n      client_secret: { env: X }\nauth:\n  role_bindings:\n    oidc:\n      member: {}\n",
    );
    assert!(auth.methods["oidc"].browser_login.is_some());
    assert!(auth.role_bindings["oidc"].contains_key("member"));
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg.public_url = Some("https://busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("inactive module") && !e.contains("grants nothing")),
        "methods-only module must not be flagged inactive: {res:?}"
    );
    cfg.auth.as_mut().unwrap().methods.swap_remove("oidc");
    let errs = validate(&cfg).expect_err("without the browser method the binding is inactive");
    assert!(
        errs.iter()
            .any(|e| e.contains("role_bindings names module 'oidc'")
                && e.contains("inactive module")),
        "removing the only active method must be diagnosed: {errs:?}"
    );
}

#[test]
fn test_key_ttl_validates_duration() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    let mut auth = config::AuthCfg::default_none();
    auth.key_ttl = Some("90d".to_string());
    cfg.auth = Some(auth);
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("key_ttl")),
        "valid key_ttl must pass: {res:?}"
    );

    let mut auth = config::AuthCfg::default_none();
    auth.key_ttl = Some("banana".to_string());
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("garbage key_ttl must fail");
    assert!(
        errs.iter().any(|e| e.contains("key_ttl")),
        "missing key_ttl error: {errs:?}"
    );
}

#[test]
fn an_empty_protocol_set_refuses_every_provider_naming_the_build() {
    let mut errors = Vec::new();
    super::validate_provider_protocol_with(&[], "prov-a", proto_a(), &mut errors);
    super::validate_provider_protocol_with(&[], "prov-b", "no-such-protocol", &mut errors);

    assert_eq!(
        errors.len(),
        2,
        "an empty protocol set must refuse EVERY provider (one error each), got: {errors:?}"
    );
    for (err, prov) in errors.iter().zip(["prov-a", "prov-b"]) {
        assert!(err.contains(prov), "the refusal names the provider: {err}");
        assert!(
            err.contains("NO protocol") && err.contains("compiled in"),
            "the refusal must name the BUILD as the cause (no protocol compiled in), not call the \
             protocol unknown against an empty list: {err}"
        );
        assert!(
            !err.contains("must be one of"),
            "the empty set must NOT render the unknown-protocol arm with an empty tail: {err}"
        );
    }

    let mut errors = Vec::new();
    super::validate_provider_protocol_with(&[proto_a(), proto_b()], "prov-c", "nope", &mut errors);
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains(&format!("must be one of: {}, {}", proto_a(), proto_b())),
        "the populated set names the choices: {}",
        errors[0]
    );
}

#[test]
fn an_empty_protocol_set_refuses_every_provider_through_the_real_sweep() {
    let mut providers = HashMap::new();
    providers.insert(
        "prov-a".to_string(),
        make_provider(proto_a(), "https://a.example.com", "KEY_A"),
    );
    providers.insert(
        "prov-b".to_string(),
        make_provider("no-such-protocol", "https://b.example.com", "KEY_B"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());

    let mut errors = Vec::new();
    super::validate_providers_with(&[], &cfg, &[], &mut errors);

    for prov in ["prov-a", "prov-b"] {
        let hits: Vec<&String> = errors.iter().filter(|e| e.contains(prov)).collect();
        assert_eq!(
            hits.len(),
            1,
            "an empty protocol set must refuse '{prov}' exactly once, got: {hits:?}"
        );
        assert!(
            hits[0].contains("NO protocol") && hits[0].contains("compiled in"),
            "the refusal must name the BUILD as the cause: {}",
            hits[0]
        );
    }
    assert!(
        !errors.iter().any(|e| e.contains("must be one of")),
        "the empty set must never render the unknown-protocol arm with an empty tail: {errors:?}"
    );

    let mut errors = Vec::new();
    super::validate_providers_with(&[proto_a(), proto_b()], &cfg, &[], &mut errors);
    assert!(
        !errors.iter().any(|e| e.contains("prov-a")),
        "a provider naming a compiled-in protocol validates: {errors:?}"
    );
    let hits: Vec<&String> = errors.iter().filter(|e| e.contains("prov-b")).collect();
    assert_eq!(hits.len(), 1, "one refusal for the stranger: {hits:?}");
    assert!(
        hits[0].contains(&format!("must be one of: {}, {}", proto_a(), proto_b())),
        "the populated set names the choices: {}",
        hits[0]
    );
}

#[test]
fn the_empty_set_the_validator_refuses_is_the_one_an_empty_registry_produces() {
    let empty_registry = crate::ingress::protocols::Registry::new(
        crate::ingress::protocols::merged_boot_decls(&[], &[]),
    );
    let known: &'static [&'static str] = empty_registry.codec_protocols();
    assert!(
        known.is_empty(),
        "the premise of this test: a registry with no declarations knows no protocols"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "prov-a".to_string(),
        make_provider(proto_a(), "https://a.example.com", "KEY_A"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());

    let mut errors = Vec::new();
    super::validate_providers_with(known, &cfg, &[], &mut errors);
    assert_eq!(
        errors.len(),
        1,
        "the registry-derived empty set refuses the provider, once: {errors:?}"
    );
    assert!(
        errors[0].contains("prov-a")
            && errors[0].contains("NO protocol")
            && errors[0].contains("compiled in"),
        "and names the build: {}",
        errors[0]
    );
}

fn root_with_auth_policy(policy: config::AuthPolicyCfg) -> RootCfg {
    let mut auth = config::AuthCfg::default_none();
    auth.policy = policy;
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg
}

fn policy_errors(cfg: &RootCfg) -> Vec<String> {
    validate(cfg)
        .err()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.contains("auth.policy"))
        .collect()
}

#[test]
fn test_auth_policy_bad_duration_is_rejected() {
    let policy = config::AuthPolicyCfg {
        default_ttl: Some("not-a-duration".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.policy.default_ttl") && e.contains("not a valid duration")),
        "a bad default_ttl must fail validation: {errs:?}"
    );

    let policy = config::AuthPolicyCfg {
        max_ttl: Some("90x".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.policy.max_ttl") && e.contains("not a valid duration")),
        "a bad max_ttl must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_default_exceeding_max_is_rejected() {
    let policy = config::AuthPolicyCfg {
        default_ttl: Some("90d".to_string()),
        max_ttl: Some("24h".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("default_ttl") && e.contains("exceeds") && e.contains("max_ttl")),
        "default_ttl > max_ttl must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_ceiling_max_ttl_rules() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("wat".to_string()),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.max_ttl")
                && e.contains("not a valid duration")
        ),
        "a bad ceiling max_ttl must fail validation: {errs:?}"
    );

    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("30d".to_string()),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        max_ttl: Some("7d".to_string()),
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.max_ttl") && e.contains("exceeds")
        ),
        "a ceiling exceeding the block max must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_role_modes_outside_the_block_modes_fail() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            binding_modes: Some(vec![config::BindingMode::TimeBound]),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        binding_modes: Some(vec![config::BindingMode::UserBound]),
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.binding_modes")
                && e.contains("'time-bound'")
        ),
        "a role mode outside the block modes must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_valid_block_passes() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("7d".to_string()),
            allowed_pools: Some(vec!["growth".to_string()]),
            binding_modes: Some(vec![config::BindingMode::TimeBound]),
        },
    );
    let policy = config::AuthPolicyCfg {
        self_mint: Some(true),
        binding_modes: Some(vec![
            config::BindingMode::TimeBound,
            config::BindingMode::Both,
        ]),
        default_ttl: Some("24h".to_string()),
        max_ttl: Some("90d".to_string()),
        mint_ceilings: ceilings,
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(errs.is_empty(), "a valid policy adds no error: {errs:?}");
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
fn test_validate_refuses_every_duration_past_the_runtime_horizon() {
    let over_s = MAX_DURATION_SECS + 1;
    let over_ms = MAX_DURATION_MS + 1;
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.pool_idle_timeout_secs = 1u64 << 63;
    cfg.limits.upstream_request_timeout_secs = over_s;
    cfg.limits.hard_down_cooldown_secs = over_s;
    cfg.limits.tls_handshake_timeout_secs = over_s;
    cfg.limits.request_body_read_timeout_secs = over_s;
    cfg.limits.max_honored_retry_after_secs = over_s;
    cfg.limits.default_probe_interval_secs = over_s;
    cfg.limits.default_probe_timeout_secs = u64::MAX;
    cfg.limits.usage_flush_interval_ms = over_ms;
    cfg.limits.default_policy_timeout_ms = u64::MAX;

    let errs = validate(&cfg).expect_err("every over-horizon duration must fail validation");
    for name in [
        "limits.pool_idle_timeout_secs (9223372036854775808) exceeds",
        "limits.upstream_request_timeout_secs",
        "limits.hard_down_cooldown_secs",
        "limits.tls_handshake_timeout_secs",
        "limits.request_body_read_timeout_secs",
        "limits.max_honored_retry_after_secs",
        "health.default_probe_interval_secs",
        "health.default_probe_timeout_secs",
        "advanced.usage_flush_interval_ms",
        "routing.default_policy_timeout_ms",
    ] {
        assert!(
            errs.iter()
                .any(|e| e.contains(name) && (e.contains("30-year") || e.contains("30 years"))),
            "expected a named over-horizon refusal for {name}; got: {errs:?}"
        );
    }

    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.pool_idle_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.upstream_request_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.default_probe_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.usage_flush_interval_ms = MAX_DURATION_MS;
    cfg.limits.default_policy_timeout_ms = MAX_DURATION_MS;
    assert!(
        validate(&cfg).is_ok(),
        "the boundary values must not error: {:?}",
        validate(&cfg)
    );

    assert!(std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(MAX_DURATION_MS))
        .is_some());
}

#[test]
fn test_validate_refuses_per_lane_durations_past_the_runtime_horizon() {
    crate::test_support::register_neutral_test_plane();
    let mut providers = HashMap::new();
    let mut provider = make_provider(proto_a(), "https://api.example.com", "API_KEY");
    provider.health = Some(crate::config::providers::HealthCfg {
        mode: crate::config::providers::HealthMode::Active,
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
    p.health = Some(crate::config::providers::HealthCfg {
        mode: crate::config::providers::HealthMode::Active,
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

static CLASS_PLANE: crate::plane_driver::registry::PlaneDecl =
    crate::plane_driver::registry::PlaneDecl {
        declaration: crate::plane_driver::registry::PlaneDeclaration {
            key: "class-plane",
            fallback: false,
            config_section: "tools",
            scope_kinds: &[],
            subject_noun: "class thing",
            admin_noun: "class-thing",
            audit_kind: "class-thing",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[bc("calls", "count"), bc("bytes", "byte")],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            served_op_classes: &[],
            caller_credential_refusal: None,
        },
        wire_format_names: |_| &[],

        provider_dialects: |_| crate::ingress::protocols::known_protocols(),
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };

const fn bc(
    class: &'static str,
    family: &'static str,
) -> crate::plane_driver::registry::BillableClass {
    crate::plane_driver::registry::BillableClass { class, family }
}

static FLAT_PLANE: crate::plane_driver::registry::PlaneDecl =
    crate::plane_driver::registry::PlaneDecl {
        declaration: crate::plane_driver::registry::PlaneDeclaration {
            key: "flat-plane",
            fallback: true,
            config_section: "pools",
            billable_classes: &[
                bc("input", "token"),
                bc("output", "token"),
                bc("cache_read", "token"),
                bc("cache_write", "token"),
                bc("search_units", "count"),
                bc("images", "count"),
            ],
            ..CLASS_PLANE.declaration
        },
        ..CLASS_PLANE
    };

fn card_yaml(y: &str) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    serde_yaml::from_str(y).expect("a card parses")
}

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
fn a_card_missing_a_declared_class_fails_validation_naming_every_missing_class() {
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[&FLAT_PLANE]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(card_yaml("m: { input_utok: 3 }\n"));
    let errs = validate(&cfg).expect_err("a card silent about declared classes must refuse");
    let want = "pools.rate_card does not configure billable unit(s) search_units, images declared \
                by this plane; add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(card_yaml("m: { input_utok: 3, units: { images: 7 } }\n"));
    let errs = validate(&cfg).expect_err("search_units is still unconfigured");
    assert!(
        errs.iter()
            .any(|e| e.contains("billable unit(s) search_units declared")),
        "{errs:?}"
    );
}

#[test]
fn a_card_configuring_every_declared_class_passes_with_explicit_zero() {
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[&FLAT_PLANE]);
    let mut cfg = cost_cfg(&["m", "n"]);
    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0 } }\nn: { units: { images: 0 } }\n",
    ));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn a_non_fallback_planes_card_is_held_to_the_same_rule() {
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[&CLASS_PLANE]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(plane_card(
        "class-plane",
        "srv_read",
        "units: { calls: 10 }",
    ));
    let errs = validate(&cfg).expect_err("bytes is declared and unconfigured");
    let want = "tools.rate_card does not configure billable unit(s) bytes declared by this plane; \
                add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card("class-plane", "", "{}"));
    let errs = validate(&cfg).expect_err("an empty present card configures nothing");
    assert!(
        errs.iter()
            .any(|e| e.contains("billable unit(s) calls, bytes declared")),
        "{errs:?}"
    );

    let full = "units: { calls: 10, bytes: 0 }";
    cfg.rate_card = Some(plane_card("class-plane", "srv_read", full));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));

    cfg.rate_card = None;
    assert!(validate(&cfg).is_ok(), "no card = billing off, no refusal");
}

static DOOR_FEE_PLANE: crate::plane_driver::registry::PlaneDecl =
    crate::plane_driver::registry::PlaneDecl {
        declaration: crate::plane_driver::registry::PlaneDeclaration {
            key: "door-fee-plane",
            billable_classes: &[
                bc("calls", "count"),
                bc("bytes", "byte"),
                bc(busbar_contract::plane::PER_REQUEST, "count"),
            ],
            fee_units: &[busbar_contract::plane::PER_REQUEST],
            ..CLASS_PLANE.declaration
        },
        ..CLASS_PLANE
    };

#[test]
fn a_door_planes_fee_unit_is_no_class_its_card_must_price() {
    let _iso =
        busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[&DOOR_FEE_PLANE]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2, bytes: 3 }",
    ));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));

    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2 }",
    ));
    let errs = validate(&cfg).expect_err("bytes is declared and unpriced");
    let want = "tools.rate_card does not configure billable unit(s) bytes declared by this plane; \
                add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2, bytes: 3, per_request: 1 }",
    ));
    let errs = validate(&cfg).expect_err("a fee unit is no class a card prices");
    let want = "tools.rate_card configures unit(s) per_request not declared by this plane \
                (declared: calls, bytes); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");
}

#[test]
fn a_dropped_in_planes_declared_classes_are_honoured() {
    let names = ["frames".to_string(), "widgets".to_string()];
    let classes: Vec<crate::plane_driver::registry::BillableClass> = names
        .into_iter()
        .map(|s| bc(Box::leak(s.into_boxed_str()), "count"))
        .collect();
    let dropped: &'static crate::plane_driver::registry::PlaneDecl =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDecl {
            declaration: crate::plane_driver::registry::PlaneDeclaration {
                key: "dropped-plane",
                config_section: "agents",
                billable_classes: Box::leak(classes.into_boxed_slice()),
                ..CLASS_PLANE.declaration
            },
            ..CLASS_PLANE
        }));
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[dropped]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(plane_card("dropped-plane", "a", "units: { frames: 1 }"));
    let errs = validate(&cfg).expect_err("widgets is declared by the dropped-in plane");
    let want = "agents.rate_card does not configure billable unit(s) widgets declared by this \
                plane; add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    let full = "units: { frames: 1, widgets: 0 }";
    cfg.rate_card = Some(plane_card("dropped-plane", "a", full));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn a_card_configuring_an_undeclared_class_fails_naming_it_and_the_declared_list() {
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[
        &FLAT_PLANE,
        &CLASS_PLANE,
    ]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0, images: 0, typo_class: 1 } }\n",
    ));
    let errs = validate(&cfg).expect_err("typo_class is declared by no plane");
    let want = "pools.rate_card configures unit(s) typo_class not declared by this plane \
                (declared: input, output, cache_read, cache_write, search_units, images); remove \
                them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card(
        "class-plane",
        "srv_read",
        "units: { calls: 1, bytes: 0, byts: 2 }",
    ));
    let errs = validate(&cfg).expect_err("byts is not a declared tools class");
    let want = "tools.rate_card configures unit(s) byts not declared by this plane (declared: \
                calls, bytes); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0, images: 0 } }\n",
    ));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn a_fee_the_plane_does_not_count_fails_naming_it_and_the_counted_list() {
    use busbar_kernel_ledger::cost::{PlaneFees, PER_SESSION};
    let session: &'static crate::plane_driver::registry::PlaneDecl =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDecl {
            declaration: crate::plane_driver::registry::PlaneDeclaration {
                key: "session-plane",
                config_section: "streams",
                fee_units: &[PER_SESSION],
                ..CLASS_PLANE.declaration
            },
            ..CLASS_PLANE
        }));
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[
        session,
        &CLASS_PLANE,
    ]);
    let fees = |plane: &str, per_request, per_session| {
        let f = PlaneFees {
            per_request,
            per_session,
        };
        config::PlaneFeesMap::from([(plane.to_string(), f)])
    };
    let mut cfg = cost_cfg(&["m"]);
    cfg.plane_fees = fees("session-plane", 2, 40);
    let errs = validate(&cfg).expect_err("the session plane counts no request");
    let want = "streams.fees.per_request is not counted by this plane (counted: per_session); \
                remove it";
    assert_eq!(errs, vec![want.to_string()]);

    cfg.plane_fees = fees("class-plane", 0, 1);
    let errs = validate(&cfg).expect_err("the class plane counts no fee unit");
    let want = "tools.fees.per_session is not counted by this plane (counted: none); remove it";
    assert_eq!(errs, vec![want.to_string()]);

    cfg.plane_fees = fees("session-plane", 0, 40);
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));
}

#[test]
fn a_fee_unit_declared_as_a_class_is_neither_owed_nor_priced_by_the_card() {
    use busbar_kernel_ledger::cost::PER_SESSION;
    const CLASSES: &[crate::plane_driver::registry::BillableClass] =
        &[bc("calls", "count"), bc(PER_SESSION, "count")];
    let session: &'static crate::plane_driver::registry::PlaneDecl =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDecl {
            declaration: crate::plane_driver::registry::PlaneDeclaration {
                key: "session-plane",
                config_section: "live",
                billable_classes: CLASSES,
                fee_units: &[PER_SESSION],
                ..CLASS_PLANE.declaration
            },
            ..CLASS_PLANE
        }));
    let _iso = busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[session]);
    let mut cfg = cost_cfg(&["m"]);
    cfg.rate_card = Some(plane_card("session-plane", "a", "units: { calls: 1 }"));
    assert!(validate(&cfg).is_ok(), "{:?}", validate(&cfg));

    cfg.rate_card = Some(plane_card(
        "session-plane",
        "a",
        "units: { calls: 1, per_session: 5 }",
    ));
    let errs = validate(&cfg).expect_err("a card does not price the fee unit");
    let want = "live.rate_card configures unit(s) per_session not declared by this plane \
                (declared: calls); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");
}

#[test]
fn an_empty_error_map_is_valid_and_an_unknown_class_word_is_not() {
    crate::test_support::register_neutral_test_plane();
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
fn a_service_account_key_file_is_read_through_the_file_source_at_config_time() {
    let json = br#"{"client_email":"a@b","private_key":"k"}"#.to_vec();
    let mut asked = Vec::new();
    let read = super::service_account_json(b"/keys/sa.json\n".to_vec(), |file| {
        asked.push(file.file_path().map(str::to_string));
        Ok(json.clone())
    })
    .expect("the key file reads");
    assert_eq!(read, json);
    assert_eq!(asked, vec![Some("/keys/sa.json".to_string())]);

    let inline = super::service_account_json(json.clone(), |_| {
        panic!("an inline service account opens no file")
    })
    .expect("inline");
    assert_eq!(inline, json);
}

#[test]
fn an_unreadable_service_account_key_file_refuses_in_1_5_5s_words_without_the_path() {
    let refused = super::service_account_json(b"/keys/secret-name.json".to_vec(), |_| {
        Err("secret file:/keys/secret-name.json cannot resolve: No such file or directory (os error 2)".to_string())
    })
    .expect_err("an unreadable key file refuses");
    assert_eq!(
        refused,
        "could not read service-account key file named by this lane's credential: No such file or directory (os error 2)"
    );
    assert!(!refused.contains("secret-name"), "{refused}");
}

#[test]
fn test_a_provider_the_destination_guard_will_refuse_is_named_at_validate() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
    crate::test_support::register_neutral_test_plane();
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
