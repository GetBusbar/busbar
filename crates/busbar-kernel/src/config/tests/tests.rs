use super::*;

#[test]
fn new_pool_strategy_is_structured_and_does_not_rebind_a_bare_hook() {
    let named: PoolCfg = serde_yaml::from_str("hooks: [operator-order]").unwrap();
    assert_eq!(named.policy, PoolPolicy::Weighted);
    assert!(!named.base_named);
    assert_eq!(named.gates, vec!["operator-order"]);

    let strategy: PoolCfg =
        serde_yaml::from_str("hooks: [{strategy: operator-order}, compliance]").unwrap();
    assert_eq!(strategy.policy.native_name(), Some("operator-order"));
    assert!(strategy.base_named);
    assert_eq!(strategy.gates, vec!["compliance"]);
    assert!(!is_reserved_hook_name("operator-order"));
}

#[test]
fn structured_pool_strategy_keeps_the_existing_single_base_rule() {
    for yaml in [
        "hooks: [{strategy: operator-order}, fastest]",
        "hooks: [{strategy: operator-order}, {strategy: other-order}]",
        "hooks: [{strategy: ''}]",
        "hooks: [{strategy: operator-order, typo: true}]",
    ] {
        assert!(serde_yaml::from_str::<PoolCfg>(yaml).is_err(), "{yaml}");
    }
    let weighted: PoolCfg = serde_yaml::from_str("hooks: [{strategy: weighted}]").unwrap();
    assert_eq!(weighted.policy, PoolPolicy::Weighted);
    assert!(weighted.base_named);
}

const CATALOG_PROTOCOL: &str = "proto-a";

fn provider_def(protocol: &str, base_url: &str) -> ProviderDef {
    ProviderDef {
        protocol: protocol.to_string(),
        base_url: base_url.to_string(),
        error_map: HashMap::new(),
        health: None,
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

fn provider_deploy(env_var: &str) -> ProviderDeploy {
    ProviderDeploy {
        api_key: SecretRef::env(env_var),
        protocol: None,
        base_url: None,
        error_map: None,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: None,
        health: None,
        options: Default::default(),
    }
}

pub(crate) fn base_deploy() -> DeployCfg {
    DeployCfg {
        declared: Default::default(),
        listen: DEFAULT_LISTEN_ADDR.into(),

        endpoint: Default::default(),
        oauth_as: None,
        credentials: Default::default(),
        public_url: None,
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_require_mtls: true,
        config: Default::default(),
        providers_file: None,
        auth: None,
        identity_providers: Default::default(),
        providers: HashMap::new(),
        models: HashMap::new(),
        pools: Default::default(),
        hooks: Default::default(),
        groups: Default::default(),
        rate_card: None,
        per_request_fee: 0,
        plane_rate_cards: Default::default(),
        plane_fees: Default::default(),
        plane_raw: Default::default(),
        declared_raw: Default::default(),
        store: None,
        secrets: Default::default(),
        advanced: AdvancedCfg::default(),
        plugins: Default::default(),
        security: None,
        limits: LimitsCfg::default(),
        export: Default::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    }
}

#[test]
fn augment_config_error_adds_auth_mode_migration_hint() {
    let augmented =
        crate::config::augment_config_error("unknown field `mode`, expected one of `chain`");
    assert!(
        augmented.contains("auth.mode:"),
        "hint names the removed key: {augmented}"
    );
    assert!(
        augmented.contains("auth.chain:"),
        "hint points to the new key: {augmented}"
    );
    assert!(
        augmented.contains("upstream_credentials"),
        "hint covers the passthrough migration: {augmented}"
    );

    assert_eq!(
        crate::config::augment_config_error("some other yaml error"),
        "some other yaml error"
    );

    let legacy = "providers: {}\nauth:\n  mode: none\n";
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(legacy)
        .map_err(crate::config::augment_config_error)
        .expect_err("legacy auth.mode must fail to parse");
    assert!(
        err.contains("auth.chain:"),
        "end-to-end error carries the hint: {err}"
    );
}

#[test]
fn augment_config_error_adds_hook_stage_rename_hint() {
    for (old, new) in [
        ("route", "candidate"),
        ("attempt", "routing"),
        ("completion", "response"),
    ] {
        let augmented = crate::config::augment_config_error(format!(
            "unknown variant `{old}`, expected one of `request`, `candidate`, `routing`, `response`"
        ));
        assert!(
            augmented.contains(&format!("`{old}`")) && augmented.contains(&format!("`{new}`")),
            "hint must name the old AND new stage value: {augmented}"
        );
        assert!(
            augmented.contains("--migrate-config"),
            "hint must point at the migrator: {augmented}"
        );
    }

    let legacy = "kind: tap\nmodule: p\nphase: [completion]\n";
    let err = serde_yaml::from_str::<HookCfg>(legacy)
        .map_err(crate::config::augment_config_error)
        .expect_err(
            "an old-form `completion` stage value must fail to parse (HARD rename, no alias)",
        );
    assert!(
        err.contains("`completion`") && err.contains("`response`") && err.contains("1.5.3"),
        "end-to-end error names the rename and version: {err}"
    );
}

#[test]
fn hook_cfg_round_trips_for_overlay_persistence() {
    let src = serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "prompt": "rw",
        "user": "ro",
        "priority": 7,
        "on_error": "reject",
        "global": true,
        "timeout_ms": 25
    });
    let cfg: HookCfg = serde_json::from_value(src).expect("HookCfg deserializes");

    let once = serde_json::to_value(&cfg).expect("HookCfg serializes");
    let cfg2: HookCfg = serde_json::from_value(once.clone()).expect("re-deserializes");
    let twice = serde_json::to_value(&cfg2).expect("re-serializes");
    assert_eq!(once, twice, "HookCfg round-trips stably");

    assert_eq!(once["kind"], "gate");
    assert_eq!(once["prompt"], "rw");
    assert_eq!(once["user"], "ro");
    assert_eq!(once["on_error"], "reject");
}

#[test]
fn test_removed_auth_keys_are_rejected_at_parse() {
    for (yaml, removed_key) in [
        ("mode: token", "mode"),
        ("token: \"sk-bb-legacy\"", "token"),
        ("client_tokens: [\"sk-bb-legacy\"]", "client_tokens"),
        ("modules:\n  sso:\n    allowed_groups: [eng]", "modules"),
        ("upstream_credentials: passthrough", "upstream_credentials"),
        ("methods:\n  oidc:\n    issuer: https://idp", "methods"),
    ] {
        let err = serde_yaml::from_str::<crate::config::AuthDeployCfg>(yaml)
            .expect_err("a removed auth key must be rejected at parse");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(removed_key),
            "expected an unknown-field error naming `{removed_key}`; got: {msg}"
        );
        assert!(
            !msg.contains("sk-bb-legacy"),
            "the parse error must not leak the configured token value; got: {msg}"
        );
    }
}

#[test]
fn test_health_typo_rejected_at_parse() {
    let bad = "default_probe_interval_sec: 5";
    let err = serde_yaml::from_str::<crate::config::HealthDefaultsCfg>(bad)
        .expect_err("a typo under health: must be rejected at parse (deny_unknown_fields)");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("default_probe_interval_sec"),
        "the error names the offending key: {msg}"
    );
}

#[test]
fn test_tls_typo_and_removed_keys_rejected_at_parse() {
    let bad = "cert: { file: /c.pem }\nkey: { file: /k.pem }\nclient_c: { file: /ca.pem }";
    let err = serde_yaml::from_str::<TlsCfg>(bad)
        .expect_err("a typo under tls: must be rejected at parse (deny_unknown_fields)");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("client_c"),
        "expected an unknown-field error naming the typo; got: {msg}"
    );

    let legacy = "cert_file: /c.pem\nkey_file: /k.pem";
    let err = serde_yaml::from_str::<TlsCfg>(legacy)
        .expect_err("the removed cert_file/key_file keys must be rejected");
    assert!(err.to_string().contains("unknown field"), "{err}");

    let good = "cert: { file: /c.pem }\nkey: { env: TLS_KEY_PEM }\nclient_ca: { file: /ca.pem }";
    let cfg = serde_yaml::from_str::<TlsCfg>(good).expect("well-formed tls config parses");
    assert_eq!(cfg.cert.file_path(), Some("/c.pem"));
    assert_eq!(cfg.key.env_var(), Some("TLS_KEY_PEM"));
    assert_eq!(
        cfg.client_ca.as_ref().and_then(|c| c.file_path()),
        Some("/ca.pem")
    );
}

#[test]
fn test_removed_key_aliases_are_rejected() {
    for (yaml, alias) in [
        ("mode: consecutive\nwindow_s: 42", "window_s"),
        ("mode: consecutive\nn: 7", "n"),
    ] {
        let err = serde_yaml::from_str::<BreakerTripConfig>(yaml)
            .expect_err("a removed trip alias must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(alias),
            "expected an unknown-field error naming `{alias}`; got: {msg}"
        );
    }
    let new: BreakerTripConfig =
        serde_yaml::from_str("mode: consecutive\nwindow_secs: 42\nconsecutive_n: 7")
            .expect("canonical trip keys parse");
    assert_eq!(new.window_secs, 42);
    assert_eq!(new.consecutive_n, 7);

    for (yaml, alias) in [("deadline_secs: 30", "deadline_secs"), ("cap: 5", "cap")] {
        let err = serde_yaml::from_str::<FailoverCfg>(yaml)
            .expect_err("a removed failover alias must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(alias),
            "expected an unknown-field error naming `{alias}`; got: {msg}"
        );
    }
    let new: FailoverCfg =
        serde_yaml::from_str("timeout_secs: 30\nmax_hops: 5").expect("canonical failover keys");
    assert_eq!(new.timeout_secs, 30);
    assert_eq!(new.max_hops, 5);
}

#[test]
fn test_retired_observability_export_keys_loud_fail_with_hint() {
    let err = serde_yaml::from_str::<DeployCfg>(
        "observability:\n  request_log_webhook_url: \"https://x.example.com/l\"\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("the retired observability block must be rejected");
    let hint = crate::config::augment_config_error(err);
    assert!(
        hint.contains("observability")
            && hint.contains("request-log-webhook")
            && hint.contains("--migrate-config"),
        "the retired block's error must name the new export home + the migrator; got: {hint}"
    );

    let err = serde_yaml::from_str::<DeployCfg>(
        "metrics:\n  buffer_seconds: 60\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("the retired metrics block must be rejected");
    let hint = crate::config::augment_config_error(err);
    assert!(
        hint.contains("export.prometheus") && hint.contains("--migrate-config"),
        "the retired metrics block must point at export.prometheus + the migrator; got: {hint}"
    );
}

#[test]
fn test_emit_server_timing_moved_to_advanced_response_headers() {
    let err = serde_yaml::from_str::<DeployCfg>(
        "observability:\n  emit_server_timing: true\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("the removed observability block must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("observability"),
        "{msg}"
    );
}

#[test]
fn test_response_headers_cfg_defaults_and_parses() {
    let default = ResponseHeadersCfg::default();
    assert!(!default.server_timing, "server_timing defaults OFF");
    assert!(!default.route_policy, "route_policy defaults OFF");

    let cfg: ResponseHeadersCfg = serde_yaml::from_str("server_timing: true\nroute_policy: true")
        .expect("both toggles parse");
    assert!(cfg.server_timing);
    assert!(cfg.route_policy);

    let err = serde_yaml::from_str::<ResponseHeadersCfg>("server_timing: true\ntypo_field: 1")
        .expect_err("a typo'd field must be rejected, not silently ignored");
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn test_config_without_pools_parses() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  widget:
    provider: acme
    max_concurrent: 10
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("config without pools must parse");
    assert!(deploy.pools.pools.is_empty());
    assert!(deploy.models.contains_key("widget"));
    assert_eq!(deploy.providers["acme"].api_key.env_var(), Some("ACME_KEY"));
}

#[test]
fn test_provider_path_override_resolves() {
    let mut defs = HashMap::new();
    let mut def = provider_def("acme", "https://api.z.ai/api/paas/v4");
    def.path = Some("/chat/completions".to_string());
    defs.insert("zai-payg".to_string(), def);

    let mut dep = provider_deploy("ZAI_KEY");

    dep.health = Some(HealthCfg {
        mode: HealthMode::Dead,
        interval_secs: Some(5),
        timeout_secs: None,
    });
    let mut deploy = base_deploy();
    deploy.providers.insert("zai-payg".to_string(), dep);

    let cfg = resolve(&deploy, &defs).expect("resolve");
    assert_eq!(
        cfg.providers["zai-payg"].path.as_deref(),
        Some("/chat/completions"),
        "catalog path override must resolve into ProviderCfg"
    );

    assert_eq!(
        cfg.providers["zai-payg"].health.as_ref().map(|h| h.mode),
        Some(HealthMode::Dead),
        "config.yaml provider health must resolve into ProviderCfg"
    );

    assert_eq!(cfg.providers["zai-payg"].api_key.env_var(), Some("ZAI_KEY"));
}

#[test]
fn bind_is_loopback_classification() {
    assert!(bind_is_loopback("127.0.0.1:8081"));
    assert!(bind_is_loopback("localhost:8081"));
    assert!(bind_is_loopback("LocalHost:8081"));
    assert!(bind_is_loopback("[::1]:8081"));
    assert!(bind_is_loopback("127.0.0.1"));
    assert!(bind_is_loopback("127.0.0.2:80"));

    assert!(!bind_is_loopback("0.0.0.0:8081"));
    assert!(!bind_is_loopback("10.0.0.5:8081"));
    assert!(!bind_is_loopback("[::]:8081"));
    assert!(!bind_is_loopback("admin.internal:8081"));
}

#[test]
fn admin_plane_boot_guard() {
    fn build(
        admin_listen: &str,
        client_ca: Option<&str>,

        require_mtls: bool,
    ) -> Result<RootCfg, Vec<String>> {
        let mut defs = HashMap::new();
        defs.insert(
            "p".to_string(),
            provider_def("acme", "https://api.example.com/v1"),
        );
        let mut deploy = base_deploy();
        deploy
            .providers
            .insert("p".to_string(), provider_deploy("P_KEY"));
        deploy.admin_listen = admin_listen.to_string();
        deploy.admin_tls = client_ca.map(|ca| TlsCfg {
            cert: SecretRef::file("cert.pem"),
            key: SecretRef::file("key.pem"),
            client_ca: Some(SecretRef::file(ca)),
        });
        deploy.admin_require_mtls = require_mtls;
        resolve(&deploy, &defs)
    }

    assert!(
        build(DEFAULT_ADMIN_LISTEN_ADDR, None, true).is_ok(),
        "the default loopback admin_listen must resolve"
    );

    assert!(build("127.0.0.1:8081", None, true).is_ok());
    assert!(build("[::1]:8081", None, true).is_ok());
    assert!(build("localhost:8081", None, true).is_ok());

    let err = build("0.0.0.0:8081", None, true)
        .expect_err("exposed admin without mTLS must refuse to boot");
    let joined = err.join("\n");
    assert!(joined.contains("admin_listen"), "guard message: {joined}");
    assert!(joined.contains("mTLS"), "guard message: {joined}");
    assert!(
        joined.contains("admin_require_mtls: false"),
        "the guard must name the 1.5.3 waiver spelling (not the retired `admin_insecure`): {joined}"
    );

    assert!(build("0.0.0.0:8081", Some("client-ca.pem"), true).is_ok());

    assert!(build("0.0.0.0:8081", None, false).is_ok());
}

#[test]
fn a_config_naming_a_plane_owned_section_refuses_cleanly_with_no_plane_registered() {
    if std::env::var_os("BUSBAR_CONFIG_EMPTY_REGISTRY_CHILD").is_none() {
        let current = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", current.name().expect("test name"), "--nocapture"])
            .env("BUSBAR_CONFIG_EMPTY_REGISTRY_CHILD", "1")
            .output()
            .expect("run the configuration reader with no planes installed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "empty-registry reader assertions failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    let result = serde_yaml::from_str::<DeployCfg>("providers: {}\nmodels: {}\npools: {}\n");
    let err = result.expect_err(
        "a config with a pools: section must be REFUSED, not silently accepted, when no plane \
         is registered to own that section",
    );
    let message = err.to_string();
    assert!(
        message.contains("no plane is registered"),
        "the refusal must name the actual problem (no plane registered), not merely fail some \
         other way; got: {message}"
    );
}

#[test]
fn test_interpolation_reads_replaced_and_removed_values() {
    const NAME: &str = "BUSBAR_T_INTERPOLATE_REPLACEMENT";
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(value) = &self.0 {
                std::env::set_var(NAME, value);
            } else {
                std::env::remove_var(NAME);
            }
        }
    }
    let _restore = Restore(std::env::var_os(NAME));
    let input = format!("tok: \"${{{NAME}}}\"");
    std::env::set_var(NAME, "first-value");
    assert_eq!(interpolate_env(&input).unwrap(), "tok: \"first-value\"");
    std::env::set_var(NAME, "second-value");
    assert_eq!(interpolate_env(&input).unwrap(), "tok: \"second-value\"");
    std::env::remove_var(NAME);
    let error = interpolate_env(&input).expect_err("a removed variable cannot reuse its old value");
    assert!(error.to_string().contains(NAME), "{error}");
}

#[test]
fn test_pool_policy_strategies_parse() {
    for (name, expected) in [
        ("cheapest", PoolPolicy::Cheapest),
        ("fastest", PoolPolicy::Fastest),
        ("least_busy", PoolPolicy::LeastBusy),
        ("usage", PoolPolicy::Usage),
        ("weighted", PoolPolicy::Weighted),
    ] {
        let yaml = format!("hooks: [{name}]\nmembers: []\n");
        let pool: PoolCfg = serde_yaml::from_str(&yaml).expect("strategy name must parse");
        assert_eq!(pool.policy, expected, "{name} must parse to its strategy");
        assert!(
            pool.gates.is_empty(),
            "a strategy-only list references no hooks"
        );
        assert!(pool.base_named, "a named strategy names the base");
    }

    let absent: PoolCfg = serde_yaml::from_str("members: []\n").expect("absent parses");
    assert_eq!(absent.policy, PoolPolicy::Weighted);
    assert!(absent.gates.is_empty());
    assert!(!absent.base_named, "an absent hooks: did not name the base");
}

#[test]
fn test_pool_retired_keys_rejected() {
    for (yaml, key) in [
        ("policy: cheapest\nmembers: []\n", "policy"),
        ("hook: smart-router\nmembers: []\n", "hook"),
        ("route: cheapest\nmembers: []\n", "route"),
        ("members: []\npolicy:\n  socket: /s\n", "policy"),
    ] {
        let e = serde_yaml::from_str::<PoolCfg>(yaml)
            .expect_err("a retired pool key must be a parse error");
        let msg = e.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(key),
            "expected unknown-field naming `{key}`; got: {msg}"
        );
    }

    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest]\npolicy: fastest\nmembers: []\n")
        .expect_err("a retired key alongside hooks: must error");
    assert!(e.to_string().contains("unknown field"), "{e}");
}

#[test]
fn test_pool_hooks_list_desugars() {
    let pool: PoolCfg = serde_yaml::from_str("hooks: [cheapest, pii]\nmembers: []\n")
        .expect("hooks list must parse");
    assert_eq!(pool.policy, PoolPolicy::Cheapest);
    assert!(pool.base_named, "a named strategy sets base_named");
    assert_eq!(pool.gates, vec!["pii".to_string()]);

    let g: PoolCfg =
        serde_yaml::from_str("hooks: [pii]\nmembers: []\n").expect("name-only list parses");
    assert_eq!(g.policy, PoolPolicy::Weighted);
    assert_eq!(g.gates, vec!["pii".to_string()]);
    assert!(
        !g.base_named,
        "a name-only pool did not name its base ordering"
    );

    let multi: PoolCfg = serde_yaml::from_str("hooks: [cheapest, pii, dlp]\nmembers: []\n")
        .expect("multi-name list parses");
    assert_eq!(multi.policy, PoolPolicy::Cheapest);
    assert_eq!(multi.gates, vec!["pii".to_string(), "dlp".to_string()]);
}

#[test]
fn test_pool_hooks_two_strategies_error() {
    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest, fastest]\nmembers: []\n")
        .expect_err("two strategies must error");
    assert!(
        e.to_string().contains("more than one ordering strategy"),
        "{e}"
    );
}

#[test]
fn test_pool_hooks_bare_name_is_a_reference() {
    let pool: PoolCfg = serde_yaml::from_str("hooks: [pii-guard]\nmembers: []\n")
        .expect("a bare hook name is a reference, not an error");
    assert_eq!(pool.gates, vec!["pii-guard".to_string()]);
    assert_eq!(pool.policy, PoolPolicy::Weighted);
    assert!(!pool.base_named);
}

#[test]
fn test_hook_definition_unknown_key_rejected() {
    let e = serde_yaml::from_str::<crate::config::HookDefCfg>(
        "{ module: busbar-phi, url: \"https://a/\" }",
    )
    .expect_err("a stray url key on a hook definition must error");
    assert!(e.to_string().contains("unknown field"), "{e}");
}

#[test]
fn test_pool_member_model_key_and_removed_keys() {
    let m: PoolMember =
        serde_yaml::from_str("model: widget\nweight: 3\ntier: large\ntags: [opus]\n")
            .expect("member with model: parses");
    assert_eq!(m.model, "widget");
    assert_eq!(m.weight, 3);
    assert_eq!(m.tier.as_deref(), Some("large"));
    assert_eq!(m.tags, ["opus"]);

    for (yaml, key) in [
        ("target: widget\n", "target"),
        ("model: widget\ncost_per_mtok: 15\n", "cost_per_mtok"),
    ] {
        let e = serde_yaml::from_str::<PoolMember>(yaml)
            .expect_err("a removed member key must be rejected");
        let msg = e.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(key),
            "expected unknown-field naming `{key}`; got: {msg}"
        );
    }
}

#[test]
fn test_hook_access_grants_parse() {
    let hook: HookCfg = serde_yaml::from_str("kind: gate\nmodule: p\nprompt: rw\nuser: ro\n")
        .expect("grants must parse");
    assert_eq!(hook.prompt, PromptAccess::Rw);
    assert!(hook.prompt.sends_prompt() && hook.prompt.can_rewrite());
    assert_eq!(hook.user, UserAccess::Ro);
    assert!(hook.user.sends_user());

    let bare: HookCfg =
        serde_yaml::from_str("kind: tap\nmodule: p\n").expect("bare hook must parse");
    assert_eq!(bare.prompt, PromptAccess::No, "prompt defaults to no");
    assert_eq!(bare.user, UserAccess::No, "user defaults to no");
    assert!(!bare.prompt.sends_prompt());
}

#[test]
fn test_interpolate_env_simple() {
    let input = "https://${BUSBAR_T_SIMPLE_HOST}/api";
    std::env::set_var("BUSBAR_T_SIMPLE_HOST", "example.com");
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "https://example.com/api");
    std::env::remove_var("BUSBAR_T_SIMPLE_HOST");
}

#[test]
fn test_interpolate_env_multiple() {
    let input =
            "${BUSBAR_T_MULTI_PROTO}://${BUSBAR_T_MULTI_USER}@${BUSBAR_T_MULTI_HOST}:${BUSBAR_T_MULTI_PORT}/";
    std::env::set_var("BUSBAR_T_MULTI_PROTO", "https");
    std::env::set_var("BUSBAR_T_MULTI_USER", "admin");
    std::env::set_var("BUSBAR_T_MULTI_HOST", "localhost");
    std::env::set_var("BUSBAR_T_MULTI_PORT", "8080");
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "https://admin@localhost:8080/");
    std::env::remove_var("BUSBAR_T_MULTI_PROTO");
    std::env::remove_var("BUSBAR_T_MULTI_USER");
    std::env::remove_var("BUSBAR_T_MULTI_HOST");
    std::env::remove_var("BUSBAR_T_MULTI_PORT");
}

#[test]
fn test_interpolate_env_unset_fails() {
    let input = "https://${UNSET_VAR}/api";
    let result = interpolate_env(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "unset environment variable: UNSET_VAR");
}

#[test]
fn test_interpolate_env_empty_var() {
    let input = "${}";
    let result = interpolate_env(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "empty variable name in ${}");
}

#[test]
fn test_interpolate_env_lenient_collects_unset() {
    use crate::config::{interpolate_env_with, EnvSubst};
    let input =
        "a: \"${BB_LENIENT_UNSET_A}\"\nb: \"${BB_LENIENT_UNSET_A}\"\nc: \"${BB_LENIENT_UNSET_B}\"";
    let mut unset = Vec::new();
    let out = interpolate_env_with(input, EnvSubst::Lenient, &mut unset).unwrap();
    assert!(out.contains("\"BB_LENIENT_UNSET_A\""));
    assert!(out.contains("\"BB_LENIENT_UNSET_B\""));
    assert_eq!(unset, vec!["BB_LENIENT_UNSET_A", "BB_LENIENT_UNSET_B"]);
    let mut sink = Vec::new();
    assert!(interpolate_env_with(input, EnvSubst::Strict, &mut sink).is_err());
    assert!(sink.is_empty());
}

#[test]
fn test_interpolate_env_no_vars() {
    let input = "plain-text-no-vars";
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "plain-text-no-vars");
}

#[test]
fn test_interpolate_env_rejects_newline_yaml_injection() {
    std::env::set_var("BUSBAR_T_INJECT_NL", "real-tok\"\n    - \"injected-tok");
    let input = "allowed:\n    - \"${BUSBAR_T_INJECT_NL}\"";
    let result = interpolate_env(input);
    std::env::remove_var("BUSBAR_T_INJECT_NL");
    assert!(
        result.is_err(),
        "an env value with a newline must be rejected to prevent YAML injection"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("control character") && err.contains("BUSBAR_T_INJECT_NL"),
        "error must name the offending variable and the control-character reason, got: {err}"
    );
}

#[test]
fn test_interpolate_env_rejects_carriage_return() {
    std::env::set_var("BUSBAR_T_INJECT_CR", "tok\r- injected");
    let result = interpolate_env("x: \"${BUSBAR_T_INJECT_CR}\"");
    std::env::remove_var("BUSBAR_T_INJECT_CR");
    assert!(
        result.is_err(),
        "an env value with a carriage return must be rejected"
    );
}

#[test]
fn test_interpolate_env_allows_ordinary_values_with_punctuation() {
    std::env::set_var("BUSBAR_T_OK_TOK", "sk-bb-aB3#9/x.y@z:1234567890abcdef");
    let result = interpolate_env("token: \"${BUSBAR_T_OK_TOK}\"").unwrap();
    std::env::remove_var("BUSBAR_T_OK_TOK");
    assert_eq!(result, "token: \"sk-bb-aB3#9/x.y@z:1234567890abcdef\"");
}

#[test]
fn test_env_injection_cannot_widen_auth_chain() {
    std::env::set_var(
        "BUSBAR_T_CHAIN_INJECT",
        "ldaps://corp\"\n    - smuggled-module",
    );
    let yaml =
        "auth:\n  chain:\n    - ad:\n        settings:\n          server: \"${BUSBAR_T_CHAIN_INJECT}\"";
    let result = interpolate_env(yaml);
    std::env::remove_var("BUSBAR_T_CHAIN_INJECT");
    assert!(
        result.is_err(),
        "newline injection into an auth chain entry must be rejected at interpolation, not parsed"
    );
}

#[test]
fn test_interpolate_env_multi_occurrence_names_only_the_true_culprit() {
    std::env::set_var("BUSBAR_T_GOOD_VAR", "hello");
    std::env::set_var("BUSBAR_T_BAD_VAR", "hi\", c: \"extra");
    let yaml = "obj: {a: \"${BUSBAR_T_GOOD_VAR}\", b: \"${BUSBAR_T_BAD_VAR}\"}";
    let result = interpolate_env(yaml);
    std::env::remove_var("BUSBAR_T_GOOD_VAR");
    std::env::remove_var("BUSBAR_T_BAD_VAR");
    let err = result.expect_err("the flow-mapping comma/quote breakout must be rejected");
    assert!(
        err.contains("BUSBAR_T_BAD_VAR"),
        "the error must name the actual culprit: {err}"
    );
    assert!(
        !err.contains("BUSBAR_T_GOOD_VAR"),
        "the error must NOT name the innocent co-occurring variable: {err}"
    );
}

#[test]
fn structural_shapes_match_compares_tagged_nodes_by_tag_and_inner_shape() {
    use serde_yaml::value::{Tag, TaggedValue};
    use serde_yaml::Value;

    let tagged_str = |tag: &str, inner: &str| {
        Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new(tag),
            value: Value::String(inner.to_string()),
        }))
    };

    assert!(structural_shapes_match(
        &tagged_str("mytag", "a"),
        &tagged_str("mytag", "b"),
        0
    ));

    assert!(!structural_shapes_match(
        &tagged_str("tag_a", "x"),
        &tagged_str("tag_b", "x"),
        0
    ));

    assert!(!structural_shapes_match(
        &tagged_str("mytag", "x"),
        &Value::String("x".to_string()),
        0
    ));

    let mut map = serde_yaml::Mapping::new();
    map.insert(Value::String("k".into()), Value::String("v".into()));
    let tagged_map = Value::Tagged(Box::new(TaggedValue {
        tag: Tag::new("t"),
        value: Value::Mapping(map),
    }));
    let tagged_seq = Value::Tagged(Box::new(TaggedValue {
        tag: Tag::new("t"),
        value: Value::Sequence(vec![Value::String("v".into())]),
    }));
    assert!(!structural_shapes_match(&tagged_map, &tagged_seq, 0));
}

#[test]
fn structural_shapes_match_recurses_into_sequence_elements_with_increasing_depth() {
    let seq_a = serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("a".to_string())]);
    let seq_b = serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("b".to_string())]);
    assert!(structural_shapes_match(&seq_a, &seq_b, 0));
}

#[test]
fn structural_shapes_match_depth_cap_is_a_real_limit_not_an_exact_match() {
    let a = serde_yaml::Value::String("x".to_string());
    let b = serde_yaml::Value::String("y".to_string());
    assert!(
        structural_shapes_match(&a, &b, MAX_STRUCTURAL_COMPARE_DEPTH),
        "at the boundary itself, comparison must still proceed"
    );
    assert!(
        !structural_shapes_match(&a, &b, MAX_STRUCTURAL_COMPARE_DEPTH + 1),
        "one past the cap must fail closed, even for two values that would otherwise match"
    );
}

#[test]
fn structural_placeholder_is_unique_per_occurrence_index() {
    let p0 = structural_placeholder(0);
    let p1 = structural_placeholder(1);
    assert_ne!(p0, p1);
    assert!(!p0.is_empty());
    assert!(p0.contains('0'));
    assert!(p1.contains('1'));
}

#[test]
fn mapping_key_repr_distinguishes_non_string_keys() {
    let n1 = serde_yaml::Value::Number(1.into());
    let n2 = serde_yaml::Value::Number(2.into());
    let s = serde_yaml::Value::String("1".to_string());
    assert_ne!(mapping_key_repr(&n1), mapping_key_repr(&n2));

    assert_eq!(mapping_key_repr(&s), "1");
}

#[test]
fn test_interpolate_env_unclosed_brace_fails() {
    let result = interpolate_env("prefix-${BUSBAR_T_UNCLOSED_UNSET");
    assert!(result.is_err(), "unclosed token must error");
    let err = result.unwrap_err();
    assert!(
        err.contains("unclosed"),
        "error must mention 'unclosed', got: {err}"
    );
    assert!(
        !err.contains("unset environment variable"),
        "must not misreport as an unset-variable error, got: {err}"
    );

    std::env::set_var("BUSBAR_T_UNCLOSED_SET", "leaked-value");
    let result2 = interpolate_env("https://${BUSBAR_T_UNCLOSED_SET/api");
    std::env::remove_var("BUSBAR_T_UNCLOSED_SET");
    assert!(
        result2.is_err(),
        "unclosed token must error even when the var is set"
    );
    let err2 = result2.unwrap_err();
    assert!(
        err2.contains("unclosed"),
        "error must mention 'unclosed', got: {err2}"
    );
}

#[test]
fn test_structural_injection_widens_client_tokens_array_end_to_end() {
    let var = "BUSBAR_T_STRUCT_CLIENT_TOKENS";
    let payload = "real-tok\", \"injected-tok";
    std::env::set_var(var, payload);

    let template = format!(
        "providers: {{}}\nmodels: {{}}\nidentity-providers: {{ tokens: {{ module: tokens, settings: {{ client_tokens: [\"${{{var}}}\"] }} }} }}\n"
    );

    let unguarded_spliced = template.replace(&format!("${{{var}}}"), payload);
    let deploy: DeployCfg = serde_yaml::from_str(&unguarded_spliced)
        .expect("unguarded splice must parse and deserialize");
    let client_tokens = deploy.identity_providers["tokens"]
        .settings
        .get("client_tokens")
        .and_then(|v| v.as_array())
        .expect("client_tokens must deserialize as a JSON array");
    assert_eq!(
        client_tokens.len(),
        2,
        "sanity: an UNGUARDED splice really does widen client_tokens to a second, attacker-chosen \
         entry through full real deserialization — this is the vulnerability the fix must close, \
         not a mechanism-only artifact"
    );

    let result = interpolate_env(&template);
    std::env::remove_var(var);
    assert!(
        result.is_err(),
        "interpolate_env must reject a value that would widen client_tokens via flow-sequence \
         injection, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    assert!(
        err.contains(var),
        "the error should name the offending variable, got: {err}"
    );
}

#[test]
fn test_structural_injection_adds_sibling_settings_key_end_to_end() {
    let var = "BUSBAR_T_STRUCT_SETTINGS_KEY";

    let payload = "ldaps://corp\", \"evil_key\": \"evil_val";
    std::env::set_var(var, payload);

    let template = format!(
        "providers: {{}}\nmodels: {{}}\nidentity-providers: {{ ad: {{ module: ad, settings: {{ server: \"${{{var}}}\" }} }} }}\n"
    );

    let unguarded_spliced = template.replace(&format!("${{{var}}}"), payload);
    let deploy: DeployCfg = serde_yaml::from_str(&unguarded_spliced)
        .expect("unguarded splice must parse and deserialize");
    let settings = &deploy.identity_providers["ad"].settings;
    assert_eq!(
        settings.get("evil_key").and_then(|v| v.as_str()),
        Some("evil_val"),
        "sanity: an UNGUARDED splice really does inject a sibling settings key through full real \
         deserialization"
    );

    let result = interpolate_env(&template);
    std::env::remove_var(var);
    assert!(
        result.is_err(),
        "interpolate_env must reject a value that would inject a sibling settings key, got: {:?}",
        result
    );
    assert!(
        result.unwrap_err().contains(var),
        "the error should name the offending variable"
    );
}

#[test]
fn test_plugins_trust_allow_unsigned_injection_already_fails_via_deny_unknown_fields() {
    let var = "BUSBAR_T_PLUGINS_TRUST_PIN";
    let redirect_via_unknown_field =
        "real-dir\", \"trust\": {\"allow_unsigned\": true}, \"ignore\": \"";
    std::env::set_var(var, redirect_via_unknown_field);
    let template = format!(
        "providers: {{}}\nmodels: {{}}\nplugins: {{ enabled: true, dir: \"${{{var}}}\" }}\n"
    );
    let spliced = template.replace(&format!("${{{var}}}"), redirect_via_unknown_field);
    let result: Result<DeployCfg, _> = serde_yaml::from_str(&spliced);
    std::env::remove_var(var);
    assert!(
        result.is_err(),
        "an `ignore:`-redirect injection of plugins.trust.allow_unsigned must be rejected by \
         PluginsCfg's deny_unknown_fields, but it deserialized: {:?}",
        result.ok()
    );

    let var2 = "BUSBAR_T_PLUGINS_TRUST_PIN_DUP";
    let redirect_via_duplicate_key =
        "real-dir\", \"trust\": {\"allow_unsigned\": true}, \"dir\": \"";
    std::env::set_var(var2, redirect_via_duplicate_key);
    let template2 = format!(
        "providers: {{}}\nmodels: {{}}\nplugins: {{ enabled: true, dir: \"${{{var2}}}\" }}\n"
    );
    let spliced2 = template2.replace(&format!("${{{var2}}}"), redirect_via_duplicate_key);
    let result2: Result<serde_yaml::Value, _> = serde_yaml::from_str(&spliced2);
    std::env::remove_var(var2);
    assert!(
        result2.is_err(),
        "an dir-reuse redirect must be rejected as a duplicate key at the Value layer, got: {:?}",
        result2.ok()
    );
    assert!(
        result2.unwrap_err().to_string().contains("duplicate"),
        "the rejection should be the duplicate-key error"
    );
}

#[test]
fn test_structural_check_allows_real_world_special_char_values() {
    let cases: &[(&str, &str)] = &[
        ("BUSBAR_T_FENCE_LDAP", "cn=busbar,ou=svc,dc=corp,dc=com"),
        (
            "BUSBAR_T_FENCE_JSON",
            "{\"role\":\"svc\",\"scopes\":[\"a\",\"b\"]}",
        ),
        ("BUSBAR_T_FENCE_WINPATH", "C:\\ProgramData\\busbar\\secrets"),
        ("BUSBAR_T_FENCE_URL", "https://host/v1?a=1&b=2"),
    ];
    for (var, value) in cases {
        std::env::set_var(var, value);
        let input = format!("token: '${{{var}}}'");
        let result = interpolate_env(&input);
        std::env::remove_var(var);
        assert!(
            result.is_ok(),
            "legitimate value for {var} must not be rejected as a structural injection: {:?}",
            result
        );
        let expanded = result.unwrap();
        assert_eq!(expanded, format!("token: '{value}'"));
        let parsed: serde_yaml::Value = serde_yaml::from_str(&expanded).unwrap();
        assert_eq!(parsed["token"].as_str(), Some(*value));
    }
}

#[test]
fn test_structural_check_allows_numeric_scalar_type_inference_change() {
    let var = "BUSBAR_T_FENCE_PORT";
    std::env::set_var(var, "8080");
    let input =
        format!("providers: {{}}\nmodels: {{}}\nlisten: \"x\"\nadvanced: {{}}\nport: ${{{var}}}\n");
    let result = interpolate_env(&input);
    std::env::remove_var(var);
    let expanded =
        result.expect("a real numeric value must not be rejected as a structural mismatch");
    let doc: serde_yaml::Value = serde_yaml::from_str(&expanded).unwrap();
    assert_eq!(
        doc.get("port").and_then(|v| v.as_i64()),
        Some(8080),
        "port must deserialize as a real integer, not get rejected or stringified"
    );
}

#[test]
fn test_anchor_alias_static_usage_not_affected_by_interpolation() {
    let var = "BUSBAR_T_ANCHOR_STATIC";
    std::env::set_var(var, "plain-value-no-special-chars");
    let input = format!("defaults: &shared orig\nfoo: \"${{{var}}}\"\nbar: *shared\n");
    let result = interpolate_env(&input);
    std::env::remove_var(var);
    assert!(
        result.is_ok(),
        "a static anchor/alias unrelated to the interpolated value must not be flagged: {:?}",
        result
    );
    let doc: serde_yaml::Value = serde_yaml::from_str(&result.unwrap()).unwrap();
    assert_eq!(doc.get("bar").and_then(|v| v.as_str()), Some("orig"));
}

#[test]
fn test_anchor_redefinition_injection_is_caught_end_to_end() {
    let var = "BUSBAR_T_ANCHOR_INJECT";
    let payload = "x\", b: &shared {hijacked: true}, c: \"y";
    std::env::set_var(var, payload);
    let template =
        format!("defaults: &shared orig-scalar\nfoo: {{ a: \"${{{var}}}\" }}\nbar: *shared\n");

    let unguarded_spliced = template.replace(&format!("${{{var}}}"), payload);
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&unguarded_spliced).expect("unguarded splice parses");
    assert!(
        doc.get("bar").map(|v| v.is_mapping()).unwrap_or(false),
        "sanity: the unguarded anchor-redefinition attack really does turn `bar` into a mapping"
    );

    let result = interpolate_env(&template);
    std::env::remove_var(var);
    assert!(
        result.is_err(),
        "an anchor-redefinition injection must be rejected by the structural check: {:?}",
        result
    );
}

#[test]
fn test_structural_check_does_not_overflow_on_deeply_nested_config() {
    let var = "BUSBAR_T_DEEP_NEST";
    std::env::set_var(var, "leaf-value");
    let depth = 300;
    let mut input = String::new();
    for i in 0..depth {
        input.push_str(&"  ".repeat(i));
        input.push_str("a:\n");
    }
    input.push_str(&"  ".repeat(depth));
    input.push_str(&format!("b: \"${{{var}}}\"\n"));

    let result = interpolate_env(&input);
    std::env::remove_var(var);
    let error = result.expect_err("a document beyond the YAML recursion limit fails closed");
    assert!(
        error.contains(var) && error.contains("refusing to proceed"),
        "{error}"
    );
    assert!(
        !error.contains("leaf-value"),
        "expanded values must not enter the refusal"
    );
}

#[test]
fn test_resolve_provider_from_def() {
    let mut defs = HashMap::new();
    let mut def = provider_def(CATALOG_PROTOCOL, "https://api.z.ai/api/model-1");
    def.error_map
        .insert("1113".to_string(), "billing".to_string());
    def.error_map
        .insert("1302".to_string(), "rate_limit".to_string());
    defs.insert("z.ai".to_string(), def);

    let mut deploy = base_deploy();
    deploy
        .providers
        .insert("z.ai".to_string(), provider_deploy("ZAI_KEY"));

    let result = resolve(&deploy, &defs).expect("resolve should succeed");

    let provider_cfg = result
        .providers
        .get("z.ai")
        .expect("z.ai should be in resolved providers");
    assert_eq!(provider_cfg.dialect(), CATALOG_PROTOCOL);
    assert_eq!(provider_cfg.base_url, "https://api.z.ai/api/model-1");
    assert_eq!(provider_cfg.api_key.env_var(), Some("ZAI_KEY"));
    assert_eq!(error_class(provider_cfg, "1113"), Some("billing"));
    assert_eq!(error_class(provider_cfg, "1302"), Some("rate_limit"));
}

fn error_class<'a>(p: &'a ResolvedProvider, code: &str) -> Option<&'a str> {
    p.error_map()
        .find(|(c, _)| *c == code)
        .map(|(_, class)| class)
}

#[test]
fn test_provider_inline_key_and_removed_env_key_rejected() {
    let yaml = r#"
providers:
  myprov:
    api_key: "sk-inline-not-a-ref"
models: {}
"#;
    assert!(
        serde_yaml::from_str::<DeployCfg>(yaml).is_err(),
        "an inline literal api_key must be rejected at parse"
    );

    let yaml = r#"
providers:
  myprov:
    api_key_env: MYPROV_KEY
models: {}
"#;
    let err = serde_yaml::from_str::<DeployCfg>(yaml)
        .expect_err("the removed api_key_env key must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("missing field `api_key`"), "{msg}");
}

#[test]
fn an_inline_literal_refusal_names_its_config_position() {
    for (literal, line) in [
        ("sk-live-0123456789abcdef", 5),
        ("\"sk-live-0123456789abcdef\"", 5),
        ("483920175534", 5),
        ("true", 5),
    ] {
        let yaml = format!(
            "store: {{module: memory}}\nmodels: {{}}\nproviders:\n  myprov:\n    api_key: {literal}\n"
        );
        let err = deploy_from_yaml_str(&yaml)
            .expect_err("an inline literal secret is refused")
            .to_string();
        let value = literal.trim_matches('"');
        assert!(
            !err.contains(value),
            "the refusal must not echo the value `{value}`: {err}"
        );
        assert!(
            err.contains("REFERENCE") && err.contains("inline literal"),
            "the refusal names the rule: {err}"
        );
        assert!(
            err.contains("providers.myprov.api_key"),
            "the refusal names the key path: {err}"
        );
        assert!(
            err.contains(&format!("at line {line} ")),
            "the refusal names the line: {err}"
        );
    }
}

#[test]
fn test_resolve_unknown_provider_error() {
    let defs = HashMap::new();
    let mut deploy = base_deploy();
    deploy
        .providers
        .insert("nope".to_string(), provider_deploy("NOPE_KEY"));

    let result = resolve(&deploy, &defs);
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("nope"));
    assert!(errs[0].contains("not found in providers.yaml"));
}

#[test]
fn test_resolve_override_wins() {
    let mut defs = HashMap::new();
    defs.insert(
        "custom".to_string(),
        provider_def(CATALOG_PROTOCOL, "https://default.example.com"),
    );

    let mut override_error_map = HashMap::new();
    override_error_map.insert("9999".to_string(), "client_error".to_string());
    let mut dep = provider_deploy("CUSTOM_KEY");
    dep.protocol = Some("acme".to_string());
    dep.base_url = Some("https://override.example.com".to_string());
    dep.error_map = Some(override_error_map);

    let mut deploy = base_deploy();
    deploy.providers.insert("custom".to_string(), dep);

    let result = resolve(&deploy, &defs).expect("resolve should succeed");

    let provider_cfg = result
        .providers
        .get("custom")
        .expect("custom should be in resolved providers");
    assert_eq!(
        provider_cfg.dialect(),
        "acme",
        "protocol override should win"
    );
    assert_eq!(
        provider_cfg.base_url, "https://override.example.com",
        "base_url override should win"
    );
    assert_eq!(provider_cfg.api_key.env_var(), Some("CUSTOM_KEY"));
    assert_eq!(error_class(provider_cfg, "9999"), Some("client_error"));
}

#[test]
fn test_resolve_empty_error_map_allowed_in_def() {
    let mut defs = HashMap::new();
    defs.insert(
        "minimal".to_string(),
        provider_def(CATALOG_PROTOCOL, "https://api.example.com"),
    );
    let mut deploy = base_deploy();
    deploy
        .providers
        .insert("minimal".to_string(), provider_deploy("MINIMAL_KEY"));

    let result = resolve(&deploy, &defs).expect("resolve should succeed");
    let provider_cfg = result
        .providers
        .get("minimal")
        .expect("minimal should exist");
    assert_eq!(provider_cfg.error_map().count(), 0);
}

#[test]
fn test_on_exhausted_parses_keywords_and_fallback_pool() {
    let r: OnExhaustedCfg = serde_yaml::from_str("reject").expect("reject parses");
    assert_eq!(r, OnExhaustedCfg::Reject);
    assert_eq!(r.to_runtime(), OnExhausted::Status503);

    let l: OnExhaustedCfg = serde_yaml::from_str("least_bad").expect("least_bad parses");
    assert_eq!(l, OnExhaustedCfg::LeastBad);
    assert_eq!(l.to_runtime(), OnExhausted::LeastBad);

    let f: OnExhaustedCfg =
        serde_yaml::from_str("fallback_pool: drain").expect("structured fallback parses");
    assert_eq!(f, OnExhaustedCfg::FallbackPool("drain".to_string()));
    assert_eq!(
        f.to_runtime(),
        OnExhausted::FallbackPool("drain".to_string())
    );

    let pool: PoolCfg =
        serde_yaml::from_str("members: []\non_exhausted: { fallback_pool: cold }\n")
            .expect("pool with structured on_exhausted parses");
    assert_eq!(
        pool.on_exhausted,
        Some(OnExhaustedCfg::FallbackPool("cold".to_string()))
    );
}

#[test]
fn test_on_exhausted_rejects_unknown_and_legacy_string_form() {
    let err = serde_yaml::from_str::<OnExhaustedCfg>("invalid_mode")
        .expect_err("unknown keyword must error");
    let msg = err.to_string();
    assert!(msg.contains("unknown on_exhausted keyword"), "{msg}");
    assert!(msg.contains("invalid_mode"), "{msg}");
    assert!(
        msg.contains("fallback_pool"),
        "the error must teach the structured form: {msg}"
    );

    let err = serde_yaml::from_str::<OnExhaustedCfg>("\"fallback_pool:drain\"")
        .expect_err("the retired string form must error");
    assert!(
        err.to_string().contains("unknown on_exhausted keyword"),
        "{err}"
    );

    let err = serde_yaml::from_str::<OnExhaustedCfg>("fallback_pool: \"\"")
        .expect_err("an empty fallback pool name must error");
    assert!(err.to_string().contains("non-empty"), "{err}");

    assert!(serde_yaml::from_str::<OnExhaustedCfg>("fallback_pols: x").is_err());
}

#[test]
fn test_config_parsing_queue_unknown_inner_key_fails() {
    let result: Result<OnExhaustedCfg, _> = serde_yaml::from_str("{ queue: { max_millis: 250 } }");
    assert!(
        result.is_err(),
        "an unknown queue inner key must fail parsing"
    );

    let ok: OnExhaustedCfg =
        serde_yaml::from_str("{ queue: { max_ms: 250 } }").expect("the spelled key parses");
    assert_eq!(ok, OnExhaustedCfg::Queue { max_ms: 250 });
    assert_eq!(ok.to_runtime(), OnExhausted::Queue { max_ms: 250 });
}

#[test]
fn the_total_deadline_the_stream_rides_defaults_to_five_minutes() {
    assert_eq!(DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS, 300);
}

#[test]
fn breaker_cfg_default_matches_serde_default_fns() {
    let d = BreakerCfg::default();
    assert_eq!(
        d.base_cooldown_secs,
        default_cooldown(),
        "base_cooldown_secs default diverged from default_cooldown()"
    );
    assert_eq!(
        d.max_cooldown_secs,
        default_max_cooldown(),
        "max_cooldown_secs default diverged from default_max_cooldown()"
    );
}

#[test]
fn breaker_trip_default_matches_an_empty_config_object() {
    let parsed: BreakerTripConfig = serde_yaml::from_str("{}").unwrap();
    assert_eq!(BreakerTripConfig::default(), parsed);
    let parsed_breaker: BreakerCfg = serde_yaml::from_str("trip: {}").unwrap();
    assert_eq!(BreakerCfg::default(), parsed_breaker);
}

#[test]
fn test_debug_of_full_config_never_shows_resolved_secrets() {
    std::env::set_var("BUSBAR_T_DEBUG_SECRET", "SECRET-resolved-value-zzz");
    let auth = crate::config::AuthDeployCfg {
        signing_key: Some(SecretRef::env("BUSBAR_T_DEBUG_SECRET")),
        chain: vec![KEYS_MODULE.to_string()],
        admin_auth: vec![crate::config::operator_provider().to_string()],
        role_bindings: RoleBindings::new(),
        key_ttl: None,
        policy: Default::default(),
    };
    let mut deploy = base_deploy();
    deploy.auth = Some(auth);

    deploy.identity_providers.insert(
        crate::config::operator_provider().to_string(),
        crate::config::IdentityProviderCfg {
            module: crate::config::operator_provider().to_string(),
            max_admin_scope: None,
            token: Some(SecretRef::env("BUSBAR_T_DEBUG_SECRET")),
            browser_login: None,
            settings: serde_json::Map::new(),
        },
    );
    deploy.tls = Some(TlsCfg {
        cert: SecretRef::file("/run/secrets/cert.pem"),
        key: SecretRef::env("BUSBAR_T_DEBUG_SECRET"),
        client_ca: None,
    });
    deploy
        .providers
        .insert("p".to_string(), provider_deploy("BUSBAR_T_DEBUG_SECRET"));

    let dbg = format!("{deploy:?}");
    std::env::remove_var("BUSBAR_T_DEBUG_SECRET");
    assert!(
        !dbg.contains("SECRET-resolved-value-zzz"),
        "DeployCfg Debug must never contain a resolved secret value: {dbg}"
    );
    assert!(
        dbg.contains("BUSBAR_T_DEBUG_SECRET"),
        "DeployCfg Debug should still show the secret REFERENCE (env var name): {dbg}"
    );
}

#[test]
fn test_limits_absent_block_yields_historical_defaults() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  widget:
    provider: acme
    max_concurrent: 10
"#;
    let deploy: DeployCfg =
        serde_yaml::from_str(yaml).expect("config without a limits block must parse");
    assert_eq!(deploy.limits.datagram_line_memory_bytes, None);
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.advanced,
        &crate::config::resolve_export(&deploy.export, &mut Vec::new()),
        &deploy.health,
        &deploy.routing,
    );
    assert_eq!(l.datagram_line_memory_bytes, None);
    assert_eq!(
        l.upstream_request_timeout_secs,
        DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
    );
    assert_eq!(l.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);
    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.pool_idle_timeout_secs, DEFAULT_POOL_IDLE_TIMEOUT_SECS);
    assert_eq!(
        l.pool_idle_timeout_secs, 300,
        "default must be the explicit 5-minute warm-set retention (not reqwest's implicit 90s)"
    );
    assert_eq!(l.max_inbound_concurrent, DEFAULT_MAX_INBOUND_CONCURRENT);
    assert_eq!(
        l.max_inbound_concurrent, 8192,
        "default must be the bounded admission cap (the only global bound on buffered request memory)"
    );
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
    assert_eq!(
        l.upstream_error_body_max_bytes,
        DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
    );

    assert_eq!(
        DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES, 262_144,
        "256 * 1024 = 256KiB, not 256 + 1024"
    );
    assert_eq!(
        l.tls_handshake_timeout_secs,
        DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
    );
    assert_eq!(
        l.max_honored_retry_after_secs,
        DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
    );
    assert_eq!(l.default_max_tokens, DEFAULT_DEFAULT_MAX_TOKENS);
    assert_eq!(
        l.default_max_tokens,
        crate::config::limits::DEFAULT_MAX_TOKENS
    );

    assert_eq!(l.key_gauge_limit, DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(l.rate_sweep_interval, DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(l.usage_flush_interval_ms, DEFAULT_USAGE_FLUSH_INTERVAL_MS);
    assert_eq!(l.default_probe_interval_secs, DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.default_policy_timeout_ms, DEFAULT_POLICY_TIMEOUT_MS);
}

#[test]
fn datagram_line_memory_limit_is_opt_in_and_resolves_to_root() {
    assert_eq!(LimitsCfg::default().datagram_line_memory_bytes, None);
    assert_eq!(LimitsResolved::default().datagram_line_memory_bytes, None);
    for (yaml, expected) in [
        ("{}", None),
        ("datagram_line_memory_bytes: null", None),
        ("datagram_line_memory_bytes: 1", Some(1)),
        ("datagram_line_memory_bytes: 12345", Some(12345)),
    ] {
        let document = format!("providers: {{}}\nmodels: {{}}\nlimits:\n  {yaml}\n");
        let deploy =
            deploy_from_yaml_str(&document).expect("boot parser accepts the optional limit");
        assert_eq!(deploy.limits.datagram_line_memory_bytes, expected);
        let cfg = resolve(&deploy, &HashMap::new()).expect("resolve the real config");
        assert_eq!(cfg.limits.datagram_line_memory_bytes, expected);
    }

    assert!(serde_json::to_value(LimitsCfg::default())
        .unwrap()
        .get("datagram_line_memory_bytes")
        .is_none());
}

#[test]
fn datagram_line_memory_limit_refuses_invalid_types_and_out_of_range_values() {
    for value in [
        "-1",
        "1.5",
        "true",
        "'1024'",
        "[]",
        "{}",
        "18446744073709551616",
    ] {
        let yaml = format!("datagram_line_memory_bytes: {value}");
        assert!(serde_yaml::from_str::<LimitsCfg>(&yaml).is_err(), "{yaml}");
    }
    for value in [
        "-1",
        "1.5",
        "true",
        "\"1024\"",
        "[]",
        "{}",
        "18446744073709551616",
    ] {
        let json = format!(r#"{{"datagram_line_memory_bytes":{value}}}"#);
        assert!(serde_json::from_str::<LimitsCfg>(&json).is_err(), "{json}");
    }
}

#[test]
fn test_limits_resolved_default_matches_from_sections_defaults() {
    let a = LimitsResolved::default();
    let b = LimitsResolved::from_sections(
        &LimitsCfg::default(),
        &AdvancedCfg::default(),
        &ExportCfg::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    );
    assert_eq!(a.request_body_max_bytes, b.request_body_max_bytes);
    assert_eq!(
        a.upstream_request_timeout_secs,
        b.upstream_request_timeout_secs
    );
    assert_eq!(a.rate_sweep_interval, b.rate_sweep_interval);
    assert_eq!(a.usage_flush_interval_ms, b.usage_flush_interval_ms);
    assert_eq!(a.default_policy_timeout_ms, b.default_policy_timeout_ms);
    assert_eq!(a.key_gauge_limit, b.key_gauge_limit);
}

#[test]
fn test_limits_set_value_overrides_default() {
    crate::export::scrape::tests::installed_axis();
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  widget:
    provider: acme
    max_concurrent: 10
limits:
  upstream_request_timeout_secs: 42
  max_inbound_concurrent: 256
  request_body_max_bytes: 1048576
  pool_idle_timeout_secs: 77
export:
  metrics:
    module: prometheus
    settings:
      buffer_seconds: 30
      key_gauge_limit: 9
advanced:
  rate_sweep_interval: 64
  usage_flush_interval_ms: 5
health:
  default_probe_interval_secs: 7
routing:
  default_policy_timeout_ms: 99
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("limits override must parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.advanced,
        &crate::config::resolve_export(&deploy.export, &mut Vec::new()),
        &deploy.health,
        &deploy.routing,
    );
    assert_eq!(l.upstream_request_timeout_secs, 42);
    assert_eq!(l.max_inbound_concurrent, 256);
    assert_eq!(l.request_body_max_bytes, 1_048_576);
    assert_eq!(l.pool_idle_timeout_secs, 77);
    assert_eq!(l.key_gauge_limit, 9);
    assert_eq!(l.rate_sweep_interval, 64);
    assert_eq!(l.usage_flush_interval_ms, 5);
    assert_eq!(l.default_probe_interval_secs, 7);
    assert_eq!(l.default_policy_timeout_ms, 99);

    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
}

#[test]
fn test_request_body_size_couples_ingress_and_translate() {
    let d = LimitsResolved::default();
    assert_eq!(d.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);

    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  widget:
    provider: acme
    max_concurrent: 10
limits:
  request_body_max_bytes: 5242880
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &AdvancedCfg::default(),
        &ExportCfg::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    );
    assert_eq!(l.request_body_max_bytes, 5 * 1024 * 1024);
}

#[test]
fn test_secret_ref_sugar_desugars_to_builtin_modules() {
    let e: SecretRef = serde_yaml::from_str("env: MY_KEY").expect("env sugar parses");
    assert_eq!(e, SecretRef::env("MY_KEY"));
    assert_eq!(e.module, "env");
    assert_eq!(e.env_var(), Some("MY_KEY"));
    assert_eq!(e.file_path(), None);
    assert_eq!(e.describe(), "env:MY_KEY");

    let f: SecretRef =
        serde_yaml::from_str("file: /run/secrets/tls.pem").expect("file sugar parses");
    assert_eq!(f, SecretRef::file("/run/secrets/tls.pem"));
    assert_eq!(f.module, "file");
    assert_eq!(f.file_path(), Some("/run/secrets/tls.pem"));
    assert_eq!(f.env_var(), None);
    assert_eq!(f.describe(), "file:/run/secrets/tls.pem");
}

#[test]
fn test_secret_ref_canonical_form_parses() {
    let v: SecretRef = serde_yaml::from_str("module: vault\nsettings:\n  path: kv/prod/api\n")
        .expect("canonical form parses");
    assert_eq!(v.module, "vault");
    assert_eq!(
        v.settings.get("path").and_then(|p| p.as_str()),
        Some("kv/prod/api")
    );
    assert_eq!(v.env_var(), None, "a non-env module has no env_var");
    assert_eq!(v.describe(), "secret module 'vault'");

    let bare: SecretRef = serde_yaml::from_str("module: vault").expect("settings default empty");
    assert!(bare.settings.is_empty());
}

#[test]
fn test_secret_ref_malformed_shapes_rejected() {
    let err = serde_yaml::from_str::<SecretRef>("module: env\nenv: FOO")
        .expect_err("module + sugar must error");
    assert!(err.to_string().contains("not both"), "{err}");

    let err = serde_yaml::from_str::<SecretRef>("env: FOO\nfile: /p")
        .expect_err("two sugar keys must error");
    assert!(err.to_string().contains("exactly one"), "{err}");

    let err = serde_yaml::from_str::<SecretRef>("env: FOO\nsettings: { a: 1 }")
        .expect_err("sugar with settings must error");
    assert!(err.to_string().contains("no `settings:`"), "{err}");

    let err =
        serde_yaml::from_str::<SecretRef>("keyring: FOO").expect_err("unknown key must error");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("keyring"),
        "{msg}"
    );

    let err =
        serde_yaml::from_str::<SecretRef>("env: \"\"").expect_err("empty sugar value must error");
    assert!(err.to_string().contains("non-empty"), "{err}");

    let err =
        serde_yaml::from_str::<SecretRef>("module: \"\"").expect_err("empty module must error");
    assert!(err.to_string().contains("non-empty"), "{err}");

    let err = serde_yaml::from_str::<SecretRef>("{}").expect_err("empty map must error");
    assert!(err.to_string().contains("needs `module:`"), "{err}");

    assert!(serde_yaml::from_str::<SecretRef>("\"sk-raw-secret\"").is_err());
}

#[test]
fn test_secret_ref_builtin_resolution_fail_closed() {
    use crate::config::secret::{resolve_linked_string, SecretResolver};

    std::env::set_var("BUSBAR_T_SECRET_ENV_OK", "s3cr3t-value");
    assert_eq!(
        SecretResolver::builtins_only()
            .resolve(&SecretRef::env("BUSBAR_T_SECRET_ENV_OK"))
            .unwrap(),
        busbar_contract::redacted::Secret::new(b"s3cr3t-value".to_vec())
    );
    std::env::remove_var("BUSBAR_T_SECRET_ENV_OK");

    let err = SecretResolver::builtins_only()
        .resolve(&SecretRef::env("BUSBAR_T_SECRET_ENV_UNSET"))
        .unwrap_err();
    assert!(
        err.contains("BUSBAR_T_SECRET_ENV_UNSET") && err.contains("unset"),
        "{err}"
    );

    std::env::set_var("BUSBAR_T_SECRET_ENV_EMPTY", "");
    let err = SecretResolver::builtins_only()
        .resolve(&SecretRef::env("BUSBAR_T_SECRET_ENV_EMPTY"))
        .unwrap_err();
    std::env::remove_var("BUSBAR_T_SECRET_ENV_EMPTY");
    assert!(err.contains("EMPTY"), "{err}");

    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-secret-test-{}", std::process::id()));
    std::fs::write(&path, "file-secret\n").unwrap();
    let sref = SecretRef::file(path.to_str().unwrap());
    assert_eq!(
        SecretResolver::builtins_only().resolve(&sref).unwrap(),
        busbar_contract::redacted::Secret::new(b"file-secret\n".to_vec())
    );
    assert_eq!(
        resolve_linked_string(&sref).unwrap(),
        busbar_contract::redacted::Secret::new("file-secret".to_string())
    );
    std::fs::remove_file(&path).unwrap();

    let missing = SecretRef::file("/nonexistent/busbar-secret-test");
    assert!(SecretResolver::builtins_only().resolve(&missing).is_err());

    let mut settings = serde_json::Map::new();
    settings.insert("path".to_string(), serde_json::Value::String("x".into()));
    let unknown = SecretRef {
        module: "vault".to_string(),
        settings,
    };
    let err = SecretResolver::builtins_only()
        .resolve(&unknown)
        .unwrap_err();
    assert!(
        err.contains("vault") && err.contains("fail-closed"),
        "{err}"
    );
}

#[test]
fn test_inline_auth_chain_entry_is_rejected() {
    let err = serde_yaml::from_str::<crate::config::AuthDeployCfg>(
        "chain:\n  - ad: { settings: { server: \"ldaps://corp\" } }\n",
    )
    .expect_err("the retired inline chain entry must be rejected");
    assert!(
        err.to_string().contains("string"),
        "the error should say a chain entry is a bare NAME; got: {err}"
    );
}

#[test]
fn test_identity_provider_typo_rejected_at_parse() {
    let err = serde_yaml::from_str::<crate::config::IdentityProviders>(
        "ad: { module: ad, max_admin_scop: full }\n",
    )
    .expect_err("a typo'd definition key must error");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[test]
fn on_error_cfg_as_name_unwraps_both_variants() {
    assert_eq!(OnErrorCfg::Terminal("fail".to_string()).as_name(), "fail");
    assert_eq!(OnErrorCfg::Hook("my-hook".to_string()).as_name(), "my-hook");
}

#[test]
fn serde_default_fns_return_their_documented_constants() {
    assert_eq!(default_min_requests(), 5);
    assert_eq!(default_max_cooldown(), 120);
    assert_eq!(default_failover_timeout(), 120);
    assert_eq!(default_max_hops(), 3);
    assert_eq!(default_listen(), "0.0.0.0:8080");
    assert_eq!(default_max_keys_per_principal(), 0);

    assert!(!default_response_headers_server_timing());
    assert!(!default_response_headers_route_policy());
}

#[test]
fn an_omitted_provider_protocol_names_no_dialect_in_the_kernel() {
    let p: ProviderCfg =
        serde_yaml::from_str("base_url: https://x.example\napi_key: {env: K}\nerror_map: {}\n")
            .expect("a provider entry with no protocol parses");
    assert_eq!(
        p.protocol, "",
        "an omitted `protocol:` is left to the plane, never filled with a kernel-chosen dialect"
    );
}

#[test]
fn warn_invalid_floors_warns_only_on_a_non_empty_malformed_floor() {
    use std::sync::{Arc, Mutex};

    struct CapturingSubscriber(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0
                    .lock()
                    .unwrap()
                    .push(event.metadata().name().to_string());
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    let run = |floor: &str| -> usize {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sub = CapturingSubscriber(events.clone());
        let mut cfg = PluginsCfg::default();
        cfg.min_versions.insert("p".to_string(), floor.to_string());
        tracing::subscriber::with_default(sub, || {
            cfg.warn_invalid_floors();
        });
        let n = events.lock().unwrap().len();
        n
    };

    assert_eq!(run(""), 0, "an omitted floor (empty string) must not warn");
    assert_eq!(run("1.2.3"), 0, "a well-formed floor must not warn");
    assert_eq!(
        run("v1.2.3"),
        1,
        "a malformed (leading-'v') floor must warn exactly once"
    );
}

#[test]
fn test_auth_role_bindings_nested_map_parses() {
    let yaml = r#"
chain: [keys, ad]
role_bindings:
  ad:
    platform:
      allowed_pools: [smart, overflow]
      group: eng
      admin_scope: read-only
    contractors:
      allowed_pools: []
    everyone: {}
"#;
    let auth: crate::config::AuthDeployCfg =
        serde_yaml::from_str(yaml).expect("role_bindings parse");

    assert_eq!(auth.chain, ["keys", "ad"]);

    let ad = auth.role_bindings.get("ad").expect("ad provider bindings");
    let platform = ad.get("platform").expect("platform role");
    assert_eq!(
        platform.allowed_pools,
        Some(vec!["smart".to_string(), "overflow".to_string()])
    );
    assert_eq!(platform.group.as_deref(), Some("eng"));
    assert_eq!(platform.admin_scope.as_deref(), Some("read-only"));

    assert_eq!(ad["contractors"].allowed_pools, Some(vec![]));
    assert_eq!(ad["everyone"].allowed_pools, None, "omitted = ALL pools");

    assert_eq!(auth.admin_auth, [crate::config::operator_provider()]);
}

#[test]
fn test_group_limits_each_metric_parses() {
    let yaml = r#"
parent: root
limits:
  - { requests: 500, per: minute }
  - { tokens: 100000, per: hour }
  - { budget: 1000000, per: month }
  - { concurrent: 5 }
  - { requests: 9, per: total }
  - { budget: 7, per: day }
"#;
    let g: GroupCfg = serde_yaml::from_str(yaml).expect("group parses");
    assert_eq!(g.parent.as_deref(), Some("root"));
    assert!(g.enabled, "enabled defaults to true");
    use crate::config::groups::{LimitMetric, LimitWindow};
    let expect = [
        (LimitMetric::Requests, 500, Some(LimitWindow::Minute)),
        (LimitMetric::Tokens, 100_000, Some(LimitWindow::Hour)),
        (LimitMetric::Budget, 1_000_000, Some(LimitWindow::Month)),
        (LimitMetric::Concurrent, 5, None),
        (LimitMetric::Requests, 9, Some(LimitWindow::Total)),
        (LimitMetric::Budget, 7, Some(LimitWindow::Day)),
    ];
    assert_eq!(g.limits.len(), expect.len(), "order preserved");
    for (i, (metric, amount, per)) in expect.into_iter().enumerate() {
        assert_eq!(g.limits[i].metric, metric, "limit {i}");
        assert_eq!(g.limits[i].amount, amount, "limit {i}");
        assert_eq!(g.limits[i].per, per, "limit {i}");
    }

    let frozen: GroupCfg = serde_yaml::from_str("enabled: false\nlimits: []\n").expect("parses");
    assert!(!frozen.enabled);
}

#[test]
fn test_group_limits_malformed_rejected() {
    use crate::config::groups::LimitCfg;

    let err = serde_yaml::from_str::<LimitCfg>("{ concurrent: 5, per: minute }")
        .expect_err("concurrent + per must error");
    assert!(err.to_string().contains("takes NO `per:`"), "{err}");

    let err = serde_yaml::from_str::<LimitCfg>("{ requests: 5 }")
        .expect_err("a windowed metric without per must error");
    assert!(
        err.to_string().contains("requires a `per:` window"),
        "{err}"
    );

    let err = serde_yaml::from_str::<LimitCfg>("{ requests: 5, tokens: 2, per: minute }")
        .expect_err("two metric keys must error");
    assert!(err.to_string().contains("exactly ONE metric key"), "{err}");

    let err = serde_yaml::from_str::<LimitCfg>("{ requests: 5, per: fortnight }")
        .expect_err("an unknown window must error");
    assert!(err.to_string().contains("unknown variant"), "{err}");

    let err = serde_yaml::from_str::<LimitCfg>("{ reqs: 5, per: minute }")
        .expect_err("an unknown metric key must error");
    assert!(err.to_string().contains("unknown field"), "{err}");

    let err = serde_yaml::from_str::<LimitCfg>("{ per: minute }")
        .expect_err("a limit with no metric must error");
    assert!(err.to_string().contains("exactly one metric key"), "{err}");

    let err =
        serde_yaml::from_str::<GroupCfg>("limitz: []").expect_err("a typo'd group key must error");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[test]
fn test_group_limit_pool_qualifier() {
    use crate::config::groups::LimitCfg;

    let l: LimitCfg = serde_yaml::from_str("{ budget: 5000, per: month, pool: frontier }")
        .expect("pool-qualified budget parses");
    assert_eq!(l.scope.as_ref().map(|s| s.value.as_str()), Some("frontier"));

    let plain: LimitCfg = serde_yaml::from_str("{ tokens: 9, per: day }").expect("parses");
    for orig in [&l, &plain] {
        let yaml = serde_yaml::to_string(orig).expect("serializes");
        let back: LimitCfg = serde_yaml::from_str(&yaml).expect("reparses");
        assert_eq!(&back, orig, "round-trip must be exact: {yaml}");
    }

    let err = serde_yaml::from_str::<LimitCfg>("{ concurrent: 5, pool: frontier }")
        .expect_err("concurrent + pool must error");
    assert!(err.to_string().contains("takes NO `pool:`"), "{err}");

    let err = serde_yaml::from_str::<LimitCfg>("{ budget: 5, per: month, pool: a, pool: b }")
        .expect_err("a duplicate pool key must error");
    assert!(err.to_string().contains("duplicate"), "{err}");
}

#[test]
fn test_group_limit_on_exhaust_qualifier() {
    use crate::config::groups::{LimitCfg, OnExhaust};

    let l: LimitCfg = serde_yaml::from_str(
        "{ budget: 5000, per: month, pool: frontier, on_exhaust: downgrade, downgrade_to: value }",
    )
    .expect("a full downgrade limit parses");
    assert_eq!(l.on_exhaust, Some(OnExhaust::Downgrade));
    assert_eq!(
        l.downgrade_to.as_ref().map(|s| s.value.as_str()),
        Some("value")
    );
    let yaml = serde_yaml::to_string(&l).expect("serializes");
    let back: LimitCfg = serde_yaml::from_str(&yaml).expect("reparses");
    assert_eq!(back, l, "overlay round-trip must be exact: {yaml}");

    let b: LimitCfg = serde_yaml::from_str("{ budget: 5, per: month, pool: p, on_exhaust: block }")
        .expect("explicit block parses");
    let byaml = serde_yaml::to_string(&b).expect("serializes");
    assert_eq!(
        serde_yaml::from_str::<LimitCfg>(&byaml).expect("reparses"),
        b
    );

    for (yaml, needle) in [
        (
            "{ budget: 5, per: month, pool: p, on_exhaust: downgrade }",
            "requires `downgrade_to",
        ),
        (
            "{ budget: 5, per: month, pool: p, downgrade_to: q }",
            "only makes sense with",
        ),
        (
            "{ requests: 5, per: month, pool: p, on_exhaust: downgrade, downgrade_to: q }",
            "BUDGET-exhaustion",
        ),
        (
            "{ budget: 5, per: month, on_exhaust: downgrade, downgrade_to: q }",
            "requires a `pool:` scope",
        ),
        (
            "{ budget: 5, per: month, pool: p, on_exhaust: downgrade, downgrade_to: p }",
            "DIFFERENT pool",
        ),
    ] {
        let err = serde_yaml::from_str::<LimitCfg>(yaml).expect_err(yaml);
        assert!(err.to_string().contains(needle), "{yaml}: {err}");
    }
}

#[test]
fn test_removed_top_level_blocks_rejected() {
    for (block, key) in [
        ("governance:\n  store: memory\n", "governance"),
        ("group_map:\n  eng:\n    group: eng\n", "group_map"),
        ("admin_auth: [admin-tokens]\n", "admin_auth"),
    ] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\n{block}");
        let err = serde_yaml::from_str::<DeployCfg>(&yaml)
            .expect_err("a removed top-level block must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains(key),
            "expected unknown-field naming `{key}`; got: {msg}"
        );
    }
}

#[test]
fn test_new_top_level_blocks_parse() {
    let yaml = r#"
providers: {}
models: {}
store:
  module: acme-durable
  settings:
    db_path: /var/lib/busbar/gov.db
    busy_timeout_ms: 250
rate_card:
  widget:
    input_utok: 3.0
    output_utok: 15.0
per_request_fee: 2
groups:
  eng:
    limits:
      - { requests: 500, per: minute }
  eng-batch:
    parent: eng
    limits:
      - { budget: 1000, per: month }
advanced:
  rate_sweep_interval: 64
  usage_flush_interval_ms: 5
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("new top-level blocks parse");
    let store = deploy.store.as_ref().expect("store block");
    assert_eq!(store.module, "acme-durable");

    assert_eq!(
        store.settings.get("db_path").and_then(|v| v.as_str()),
        Some("/var/lib/busbar/gov.db")
    );
    assert_eq!(
        store
            .settings
            .get("busy_timeout_ms")
            .and_then(|v| v.as_i64()),
        Some(250)
    );
    let rc = deploy.rate_card.as_ref().expect("rate_card");
    let widget = rc.get("widget").expect("widget rate entry");
    assert_eq!(widget.input_utok, 3.0);
    assert_eq!(widget.output_utok, 15.0);
    assert_eq!(widget.cache_read_utok, 0.0, "omitted tier prices at 0");

    assert_eq!(rate_entry_per_mtok(widget), 9.0);
    assert_eq!(deploy.per_request_fee, 2);
    assert_eq!(deploy.groups.len(), 2);
    assert_eq!(deploy.groups["eng-batch"].parent.as_deref(), Some("eng"));
    assert_eq!(deploy.advanced.rate_sweep_interval, 64);
    assert_eq!(deploy.advanced.usage_flush_interval_ms, 5);

    let bare: DeployCfg =
        serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("bare deploy parses");
    assert!(bare.store.is_none());
    assert!(bare.rate_card.is_none());
    assert_eq!(bare.per_request_fee, 0, "per_request_fee defaults to 0");
    assert!(bare.groups.is_empty());
    assert_eq!(
        bare.advanced.rate_sweep_interval,
        DEFAULT_RATE_SWEEP_INTERVAL
    );
    assert_eq!(
        bare.advanced.usage_flush_interval_ms,
        DEFAULT_USAGE_FLUSH_INTERVAL_MS
    );
}

#[test]
fn test_resolve_builds_registry_from_named_defs() {
    let mut deploy = base_deploy();

    deploy.hooks = serde_yaml::from_str(
        "pii-eng:\n  module: busbar-phi\n  kind: gate\n  groups: [engineering]\n  settings: { team: alpha }\n\
         pii-all:\n  module: busbar-phi\n  kind: gate\n\
         audit:\n  module: busbar-audit\n  kind: tap\n  phase: [response]\n",
    )
    .unwrap();
    let pool_a: PoolCfg =
        serde_yaml::from_str("members: []\nhooks: [cheapest, pii-eng]\n").unwrap();
    let pool_b: PoolCfg = serde_yaml::from_str("members: []\nhooks: [pii-all]\n").unwrap();
    deploy.pools.pools.insert("a".to_string(), pool_a);
    deploy.pools.pools.insert("b".to_string(), pool_b);
    deploy.pools.all_pool_hooks = vec!["audit".to_string()];

    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");

    let mut names: Vec<&String> = cfg.hooks.keys().collect();
    names.sort();
    assert_eq!(names, ["audit", "pii-all", "pii-eng"]);

    assert_eq!(cfg.hooks["pii-eng"].plugin, "busbar-phi");
    assert_eq!(cfg.hooks["pii-all"].plugin, "busbar-phi");
    assert_eq!(cfg.hooks["pii-eng"].groups, ["engineering"]);
    assert!(
        cfg.hooks["pii-all"].groups.is_empty(),
        "pii-all is unscoped (all callers)"
    );

    assert_eq!(
        cfg.hooks["pii-eng"]
            .settings
            .get("team")
            .and_then(|v| v.as_str()),
        Some("alpha")
    );
    assert_eq!(cfg.hooks["pii-all"].kind, HookKind::Gate);

    assert_eq!(cfg.hooks["audit"].kind, HookKind::Tap);
    assert!(cfg.hooks["audit"].fires_at_stage(crate::config::HookStage::Response));
    assert!(!cfg.hooks["audit"].fires_at_stage(crate::config::HookStage::Request));

    assert_eq!(cfg.pools["a"].gates, ["pii-eng"]);
    assert_eq!(cfg.pools["a"].policy, PoolPolicy::Cheapest);
    assert_eq!(cfg.pools["b"].gates, ["pii-all"]);
    assert_eq!(cfg.global_hooks, ["audit"]);
}

#[test]
fn test_resolve_rejects_bad_hook_defs() {
    let mut deploy = base_deploy();
    deploy.hooks = serde_yaml::from_str("bad:\n  module: \"  \"\n").unwrap();
    let errs = resolve(&deploy, &HashMap::new()).expect_err("empty module must fail resolve");
    let joined = errs.join("\n");
    assert!(
        joined.contains("hooks.bad") && joined.contains("non-empty"),
        "{joined}"
    );

    let mut deploy = base_deploy();
    deploy.hooks = serde_yaml::from_str("cheapest:\n  module: busbar-phi\n").unwrap();
    let errs = resolve(&deploy, &HashMap::new()).expect_err("reserved def name must fail");
    assert!(errs.join("\n").contains("reserved name"), "{errs:?}");
}

#[test]
fn test_caller_in_hook_groups_scope() {
    use crate::config::caller_in_hook_groups;

    let tree: std::collections::BTreeMap<String, crate::config::GroupCfg> = serde_yaml::from_str(
        "acme: {}\n\
         engineering: { parent: acme }\n\
         sales: { parent: acme }\n\
         'user:bob': { parent: engineering }\n\
         'user:sue': { parent: sales }\n",
    )
    .expect("groups tree parses");
    let eng = ["engineering".to_string()];

    assert!(caller_in_hook_groups(Some("user:bob"), &eng, &tree));
    assert!(!caller_in_hook_groups(Some("user:sue"), &eng, &tree));

    assert!(caller_in_hook_groups(Some("engineering"), &eng, &tree));
    assert!(!caller_in_hook_groups(Some("sales"), &eng, &tree));

    assert!(caller_in_hook_groups(Some("user:sue"), &[], &tree));
    assert!(caller_in_hook_groups(None, &[], &tree));

    assert!(!caller_in_hook_groups(None, &eng, &tree));
}

#[test]
fn test_resolve_projects_admin_auth_names() {
    let cfg = resolve(&base_deploy(), &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [crate::config::operator_provider()]);

    let mut deploy = base_deploy();
    let op = crate::config::operator_provider();
    let auth: crate::config::AuthDeployCfg =
        serde_yaml::from_str(&format!("chain: [keys]\nadmin_auth: [{op}, ad]\n"))
            .expect("auth parses");
    deploy.auth = Some(auth);

    deploy.identity_providers = serde_yaml::from_str(&format!(
        "{op}: {{ module: {op}, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         ad: {{ module: ad, max_admin_scope: read-only }}\n",
    ))
    .expect("identity-providers parse");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [crate::config::operator_provider(), "ad"]);

    assert_eq!(
        cfg.auth
            .as_ref()
            .and_then(|a| a.admin_token_ref())
            .and_then(|t| t.env_var()),
        Some("BUSBAR_ADMIN_TOKEN")
    );

    let mut deploy = base_deploy();
    deploy.auth = Some(serde_yaml::from_str("chain: [keys]\n").expect("auth parses"));
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [crate::config::operator_provider()]);
}

#[test]
fn test_public_url_parses_top_level() {
    let yaml = "\
listen: 0.0.0.0:8080
public_url: https://api.busbar.example
providers: {}
models: {}
";
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("public_url must parse");
    assert_eq!(
        deploy.public_url.as_deref(),
        Some("https://api.busbar.example")
    );

    let deploy2: DeployCfg =
        serde_yaml::from_str("listen: 0.0.0.0:8080\nproviders: {}\nmodels: {}\n")
            .expect("absent public_url ⇒ default None");
    assert_eq!(deploy2.public_url, None);
}

#[test]
fn test_auth_method_browser_login_parses() {
    let yaml = "\
test-idp-double:
  module: oidc-plugin
  browser_login:
    client_secret: { env: BUSBAR_OIDC_SECRET }
    client_id: busbar-web
  settings:
    issuer: https://idp.example/
    audience: busbar
";
    let providers: crate::config::IdentityProviders =
        serde_yaml::from_str(yaml).expect("the provider definition must parse");
    let mut errors = Vec::new();
    let auth = crate::config::resolve_auth(
        &serde_yaml::from_str("chain: [test-idp-double]\n").expect("auth parses"),
        &providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    let method = auth
        .methods
        .get("test-idp-double")
        .expect("test-idp-double method present");
    assert_eq!(
        method.module, "oidc-plugin",
        "the method carries the definition's MODULE, distinct from its NAME"
    );
    let bl = method
        .browser_login
        .as_ref()
        .expect("browser_login present");
    assert_eq!(bl.client_id.as_deref(), Some("busbar-web"));

    assert_eq!(
        bl.client_secret.as_ref().and_then(|s| s.env_var()),
        Some("BUSBAR_OIDC_SECRET")
    );

    assert_eq!(
        method.settings.get("issuer").and_then(|v| v.as_str()),
        Some("https://idp.example/")
    );
    assert_eq!(
        method.settings.get("audience").and_then(|v| v.as_str()),
        Some("busbar")
    );

    assert!(!method.settings.contains_key("browser_login"));
}

#[test]
fn test_browser_login_deny_unknown_field() {
    let yaml = "\
oidc:
  module: oidc-plugin
  browser_login:
    client_secret: { env: X }
    client_idd: oops
";
    let err = serde_yaml::from_str::<crate::config::IdentityProviders>(yaml)
        .expect_err("typo under browser_login must be rejected");
    assert!(
        err.to_string().contains("client_idd") || err.to_string().contains("unknown field"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_plugins_fetch_three_shapes_parse() {
    use crate::config::{PluginFetch, PluginsCfg};
    let yaml = "\
enabled: true
dir: plugins
fetch:
  - github: org/repo@v1.2.3
    sha256: abc123
  - url: https://host/plugin.tar.gz
  - env: BUSBAR_PLUGIN_URL
";
    let cfg: PluginsCfg = serde_yaml::from_str(yaml).expect("three fetch shapes must parse");
    assert_eq!(cfg.fetch.len(), 3);
    assert!(
        matches!(&cfg.fetch[0], PluginFetch::Github(g) if g.github == "org/repo@v1.2.3" && g.sha256.as_deref() == Some("abc123"))
    );
    assert!(
        matches!(&cfg.fetch[1], PluginFetch::Url(u) if u.url == "https://host/plugin.tar.gz" && u.sha256.is_none())
    );
    assert!(matches!(&cfg.fetch[2], PluginFetch::Env(e) if e.env == "BUSBAR_PLUGIN_URL"));

    let bad = "enabled: true\nfetch:\n  - github: org/repo@v1\n    shaa: nope\n";
    assert!(
        serde_yaml::from_str::<PluginsCfg>(bad).is_err(),
        "typo'd fetch key must be rejected"
    );
}

#[test]
fn test_fetch_specs_maps_github_and_url() {
    use crate::config::PluginsCfg;
    let yaml = "\
enabled: true
fetch:
  - github: acme/widget@v2.0.1
    sha256: deadbeef
  - url: https://host/plugins/store-durable.tar.gz
";
    let cfg: PluginsCfg = serde_yaml::from_str(yaml).unwrap();
    let specs = cfg.fetch_targets().expect("fetch_targets resolves");
    assert_eq!(specs.len(), 2);

    assert_eq!(specs[0].filename, "widget.tar.gz");
    assert_eq!(
        specs[0].url,
        "https://github.com/acme/widget/releases/download/v2.0.1/widget.tar.gz"
    );
    assert_eq!(specs[0].sha256.as_deref(), Some("deadbeef"));

    assert_eq!(specs[1].url, "https://host/plugins/store-durable.tar.gz");
    assert_eq!(specs[1].filename, "store-durable.tar.gz");
    assert_eq!(specs[1].sha256, None);
}

#[test]
fn test_fetch_url_filename_requires_a_path_segment() {
    for url in [
        "https://host",
        "https://host?next=/plugin.tar.gz",
        "https://host#plugin.tar.gz",
        "https://user:pass@host:443",
        "https://user:pass@host:443/",
        "https://[::1]:443",
        "https://host/",
        "https://host/plugins/?download=1",
    ] {
        let cfg = PluginsCfg {
            fetch: vec![PluginFetch::Url(UrlFetch {
                url: url.to_string(),
                sha256: None,
            })],
            ..PluginsCfg::default()
        };
        let error = cfg.fetch_targets().expect_err("URL has no path basename");
        assert!(
            !error.contains("user:pass"),
            "URL credentials must not be echoed"
        );
    }
    for url in [
        "https://host/plugin.tar.gz",
        "https://host/plugins/plugin.tar.gz?next=/ignored#ignored",
        "https://[::1]:443/plugin.tar.gz",
    ] {
        let cfg = PluginsCfg {
            fetch: vec![PluginFetch::Url(UrlFetch {
                url: url.to_string(),
                sha256: Some("deadbeef".to_string()),
            })],
            ..PluginsCfg::default()
        };
        let targets = cfg.fetch_targets().expect("URL has a path basename");
        assert_eq!(targets[0].filename, "plugin.tar.gz");
        assert_eq!(targets[0].url, url);
        assert_eq!(targets[0].sha256.as_deref(), Some("deadbeef"));
    }
}

#[test]
fn test_fetch_env_spec_reads_var() {
    use crate::config::PluginsCfg;
    std::env::set_var("BUSBAR_T_FETCH_URL", "https://host/p/thing.tar.gz@abc123");
    let cfg: PluginsCfg =
        serde_yaml::from_str("enabled: true\nfetch:\n  - env: BUSBAR_T_FETCH_URL\n").unwrap();
    let specs = cfg.fetch_targets().expect("env spec resolves");
    assert_eq!(specs[0].url, "https://host/p/thing.tar.gz");
    assert_eq!(specs[0].sha256.as_deref(), Some("abc123"));
    assert_eq!(specs[0].filename, "thing.tar.gz");
    std::env::remove_var("BUSBAR_T_FETCH_URL");
}

#[test]
fn test_fetch_env_spec_unset_is_error() {
    use crate::config::PluginsCfg;
    std::env::remove_var("BUSBAR_T_FETCH_UNSET");
    let cfg: PluginsCfg =
        serde_yaml::from_str("enabled: true\nfetch:\n  - env: BUSBAR_T_FETCH_UNSET\n").unwrap();
    let err = cfg.fetch_targets().expect_err("unset env var must error");
    assert!(
        err.contains("BUSBAR_T_FETCH_UNSET") && err.contains("not set"),
        "{err}"
    );
}

#[test]
fn config_consolidation_keys_parse_into_deploy_cfg() {
    let yaml = "\
providers: {}
models: {}
providers_file: catalog.yaml
config:
  locked: true
  overlay:
    file: my-overlay.json
advanced:
  worker_threads: 3
  upstream_http1_only: true
  upstream_h2_prior_knowledge: true
";
    let d: crate::config::DeployCfg = serde_yaml::from_str(yaml).expect("1.5.3 keys parse");
    assert!(d.config.locked);
    assert_eq!(d.providers_file.as_deref(), Some("catalog.yaml"));
    assert_eq!(d.advanced.worker_threads, Some(3));
    assert!(d.advanced.upstream_http1_only);
    assert!(d.advanced.upstream_h2_prior_knowledge);
    match d.config.overlay {
        Some(crate::config::OverlayCfg::Backend(b)) => {
            assert_eq!(b.file.as_deref(), Some("my-overlay.json"))
        }
        other => panic!("expected a file backend, got {other:?}"),
    }

    let mut deploy = base_deploy();
    deploy.advanced.upstream_http1_only = true;
    deploy.advanced.upstream_h2_prior_knowledge = true;
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert!(
        cfg.limits.upstream_http1_only,
        "advanced.upstream_http1_only must reach cfg.limits"
    );
    assert!(
        cfg.limits.upstream_h2_prior_knowledge,
        "advanced.upstream_h2_prior_knowledge must reach cfg.limits"
    );

    let yaml2 = "providers: {}\nmodels: {}\nconfig:\n  locked: true\n  overlay: false\n";
    let d2: crate::config::DeployCfg = serde_yaml::from_str(yaml2).expect("overlay:false parses");
    assert!(matches!(
        d2.config.overlay,
        Some(crate::config::OverlayCfg::Disabled(false))
    ));

    let yaml3 = "providers: {}\nmodels: {}\n";
    let d3: crate::config::DeployCfg = serde_yaml::from_str(yaml3).expect("absent config parses");
    assert!(!d3.config.locked);
    assert!(d3.config.overlay.is_none());
    assert!(d3.providers_file.is_none());
    assert_eq!(d3.advanced.worker_threads, None);
}

#[test]
fn reserved_hook_names_are_frozen() {
    let mut frozen: Vec<&str> = crate::config::FROZEN_HOOK_NAME_WORD_SPACE.to_vec();
    frozen.sort_unstable();

    assert_eq!(
        frozen,
        [
            "cheapest",
            "fastest",
            "first",
            "least_busy",
            "nothing",
            "reject",
            "tokens",
            "usage",
            "weighted",
        ],
        "the 1.5.3 hook-name word space is FROZEN: a new bare terminal would retroactively \
         invalidate a legal 1.5.3 config. Add the new behavior as a STRUCTURED value instead \
         (e.g. `{{ hook: x }}`) — see RESERVED_HOOK_NAMES' doc comment."
    );

    let mut runtime: Vec<&str> = crate::config::RESERVED_HOOK_NAMES.to_vec();
    for word in crate::config::FROZEN_HOOK_NAME_WORD_SPACE {
        assert!(
            crate::config::RESERVED_HOOK_NAMES.contains(word) || super::is_strategy_name(word),
            "'{word}' is declared frozen but is neither reserved nor a strategy keyword"
        );
    }
    runtime.sort_unstable();
    runtime.dedup();
    assert_eq!(
        runtime, frozen,
        "RESERVED_HOOK_NAMES and FROZEN_HOOK_NAME_WORD_SPACE must not drift"
    );

    let mut deploy = base_deploy();
    deploy.hooks.insert(
        "cheapest".to_string(),
        serde_yaml::from_str("module: some-hook-plugin").expect("hook def parses"),
    );
    let errs = resolve(&deploy, &HashMap::new())
        .expect_err("a hook named with a reserved word must refuse to boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("cheapest") && e.contains("reserved")),
        "the error must name the reserved word: {errs:?}"
    );

    let operator = crate::config::operator_provider();
    assert!(crate::config::is_reserved_hook_name(operator));
    let mut deploy = base_deploy();
    deploy.hooks.insert(
        operator.to_string(),
        serde_yaml::from_str("module: some-hook-plugin").expect("hook def parses"),
    );
    let errs = resolve(&deploy, &HashMap::new())
        .expect_err("a hook named with the operator credential's provider must refuse to boot");
    assert!(
        errs.iter()
            .any(|e| e.contains(operator) && e.contains("reserved")),
        "the error must name the reserved word: {errs:?}"
    );
}

#[test]
fn omitted_phase_is_exactly_the_four_core_stages() {
    use crate::config::HookStage;

    assert_eq!(
        crate::config::CORE_HOOK_PHASES,
        &[
            HookStage::Request,
            HookStage::Candidate,
            HookStage::Routing,
            HookStage::Response
        ],
        "the omitted-phase default is FROZEN at the four core stages; a stage added later must NOT \
         join this list, or it would retroactively widen every existing unscoped hook"
    );

    let def: crate::config::HookDefCfg =
        serde_yaml::from_str("module: h\nkind: tap").expect("hook def parses");
    let cfg = super::hook_cfg_from_def(&def).expect("lowers");
    assert!(cfg.phase.is_empty(), "the definition names no phase");
    for stage in crate::config::CORE_HOOK_PHASES {
        assert!(
            cfg.fires_at_stage(*stage),
            "an omitted phase must fire at the core stage {stage:?}"
        );
    }

    let def: crate::config::HookDefCfg =
        serde_yaml::from_str("module: h\nkind: tap\nphase: [response]").expect("parses");
    let cfg = super::hook_cfg_from_def(&def).expect("lowers");
    assert!(cfg.fires_at_stage(HookStage::Response));
    assert!(!cfg.fires_at_stage(HookStage::Request));
    assert!(!cfg.fires_at_stage(HookStage::Candidate));
    assert!(!cfg.fires_at_stage(HookStage::Routing));
}

#[test]
fn export_named_map_allows_two_instances_of_one_module() {
    crate::export::scrape::tests::installed_axis();
    let defs: crate::config::ExportDefs = serde_yaml::from_str(
        "req-log:  { module: k9-tail, settings: { url: \"https://logs.example.com/a\" } }\n\
         req-siem: { module: k9-tail, settings: { url: \"https://siem.internal/b\", delivery_timeout_secs: 9 } }\n",
    )
    .expect("two instances of one module parse");
    let mut errors = Vec::new();
    let export = crate::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(export.plugins.len(), 2);
    assert_eq!(export.plugins[0].name, "req-log");
    assert_eq!(export.plugins[1].name, "req-siem");

    assert_eq!(
        export.plugins[0].def.settings.get("delivery_timeout_secs"),
        None
    );
    assert_eq!(
        export.plugins[1].def.settings["delivery_timeout_secs"],
        serde_json::json!(9)
    );

    let defs: crate::config::ExportDefs = serde_yaml::from_str(
        "one: { module: prometheus, settings: { buffer_seconds: 60 } }\n\
         two: { module: prometheus, settings: { buffer_seconds: 60 } }\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let export = crate::config::resolve_export(&defs, &mut errors);
    assert_eq!(
        errors,
        vec!["export.two: the scrape double takes one instance, and 'one' is it".to_string()],
        "the module's own words, verbatim"
    );
    assert_eq!(
        export.plugins.len(),
        1,
        "the extra instance is not resolved"
    );

    let defs: crate::config::ExportDefs =
        serde_yaml::from_str("x: { module: nope }\n").expect("parses");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_export(&defs, &mut errors);
    assert!(
        errors.iter().any(|e| e.starts_with(
            "export.x.module: unknown exporter 'nope'; the built-in export modules are "
        )),
        "an unknown export module must name the modules this build serves; got {errors:?}"
    );
}

#[test]
fn failover_pools_are_absent_by_default() {
    let deploy = base_deploy();
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert!(
        cfg.plane_pools.is_empty(),
        "no plane failover unless asked for"
    );
}

#[test]
fn test_auth_policy_rejects_bad_input_at_parse() {
    let doc = |policy_body: &str| {
        format!("auth:\n  policy:\n{policy_body}providers: {{}}\nmodels: {{}}\n")
    };

    let bad_mode = doc("    binding_modes: [forever]\n");
    let err = crate::config::deploy_from_yaml_str(&bad_mode)
        .expect_err("an unknown binding mode must be rejected at parse");
    assert!(
        err.to_string().contains("forever") || err.to_string().contains("unknown variant"),
        "got: {err}"
    );

    let typo = doc("    slef_mint: true\n");
    let err = crate::config::deploy_from_yaml_str(&typo)
        .expect_err("a typo'd policy key must be rejected (deny_unknown_fields)");
    assert!(err.to_string().contains("unknown field"), "got: {err}");

    let ceiling_typo = doc("    mint_ceilings:\n      app-admin: { max_tll: \"7d\" }\n");
    let err = crate::config::deploy_from_yaml_str(&ceiling_typo)
        .expect_err("a typo'd ceiling key must be rejected (deny_unknown_fields)");
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn the_auth_block_refusals_are_pinned() {
    let refusal = |auth: &str| {
        crate::config::deploy_from_yaml_str(&format!("providers: {{}}\nmodels: {{}}\n{auth}"))
            .expect_err("refused")
            .to_string()
    };
    let frozen = "unknown field `bogus_key`, expected one of `signing_key`, `chain`, \
                  `admin_auth`, `role_bindings`, `key_ttl`";
    assert_eq!(
        refusal("auth:\n  bogus_key: 1\n"),
        format!("auth: {frozen} at line 4 column 3")
    );
    assert_eq!(
        refusal("auth:\n  policy: {}\n  bogus_key: 1\n"),
        format!("auth: {frozen} at line 5 column 3")
    );
    assert_eq!(
        refusal("auth:\n  policy:\n    slef_mint: true\n"),
        "auth.policy: unknown field `slef_mint`, expected one of `self_mint`, `binding_modes`, \
         `default_ttl`, `max_ttl`, `mint_ceilings` at line 5 column 5"
    );
    assert_eq!(
        refusal("auth: 5\n"),
        "auth: invalid type: integer `5`, expected a configuration section at line 3 column 7"
    );
    let empty = crate::config::deploy_from_yaml_str("providers: {}\nmodels: {}\nauth:\n")
        .expect("an empty auth block parses");
    assert!(empty.auth.is_none());
}

#[test]
fn a_flat_rate_card_resolves_to_itself() {
    for text in [
        "providers: {}\nmodels: {}\nrate_card: {}\n",
        "providers: {}\nmodels: {}\nrate_card:\n  m: { input_utok: 3, output_utok: 15 }\n",
    ] {
        let deploy = crate::config::deploy_from_yaml_str(text).expect("parses");
        assert!(deploy.plane_rate_cards.is_empty());
        let root = resolve(&deploy, &HashMap::new()).expect("resolves");
        assert_eq!(root.rate_card, deploy.rate_card, "{text}");
    }
}

#[test]
fn warn_invalid_floors_keeps_both_warnings_byte_for_byte() {
    use crate::diagnostics::{CONFIG_ANTIDOWNGRADE_FLOOR_INVALID, CONFIG_FIRSTPARTY_FLOOR_INVALID};
    use tracing_subscriber::layer::SubscriberExt as _;
    let mut cfg = PluginsCfg::default();
    cfg.min_versions.insert("p".into(), "v1.2.3".into());
    cfg.first_party_floors.insert("q".into(), "1.2".into());
    let path = std::env::temp_dir().join(format!(
        "busbar-config-floor-warnings-{}-{}",
        std::process::id(),
        hex::encode(crate::door::op_id().0)
    ));
    let file = std::fs::File::create(&path).expect("warning capture file");
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_ansi(false)
            .with_writer(move || file.try_clone().expect("warning capture writer")),
    );
    tracing::subscriber::with_default(subscriber, || cfg.warn_invalid_floors());
    let min = "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading 'v'); it \
               cannot be satisfied, so this plugin will be refused. Fix or remove the entry.";
    let first =
        "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading 'v'); it \
                 cannot be satisfied, so this plugin will be refused — and this pin REPLACES the \
                 binary-version floor, so the plugin is refused unconditionally until this is \
                 fixed. Fix or remove the entry.";
    let captured = std::fs::read_to_string(&path).expect("captured warnings");
    let _ = std::fs::remove_file(path);
    let m: Vec<&str> = captured.lines().collect();
    assert_eq!(m.len(), 2, "{m:?}");
    assert!(
        m[0].starts_with(min)
            && m[0].contains("plugins.min_versions['p']")
            && m[0].contains(&CONFIG_ANTIDOWNGRADE_FLOOR_INVALID.banner().to_string()),
        "{m:?}"
    );
    assert!(
        m[1].starts_with(first)
            && m[1].contains("plugins.first_party_floors['q']")
            && m[1].contains(&CONFIG_FIRSTPARTY_FLOOR_INVALID.banner().to_string()),
        "{m:?}"
    );
}

/// A `providers:` section read the way boot reads it.
#[derive(serde::Deserialize)]
struct ProvidersDoc {
    #[serde(deserialize_with = "crate::config::providers::deployments")]
    providers: HashMap<String, ProviderDeploy>,
}

#[test]
fn a_deployments_options_ride_the_resolved_table_under_their_wire_names() {
    let doc: ProvidersDoc = serde_yaml::from_str(
        "providers:\n  p:\n    api_key: {env: K}\n    OpenAI-Organization: org-abc\n    \
         api-version: 2024-10-21\n    path: /v1/x\n    organization: o\n",
    )
    .expect("reads");
    let dep = &doc.providers["p"];
    assert_eq!(dep.path.as_deref(), Some("/v1/x"));
    let mut names: Vec<&String> = dep.options.keys().collect();
    names.sort();
    assert_eq!(
        names,
        ["OpenAI-Organization", "api-version", "organization"]
    );
    let merged = merge_provider_fallback(&provider_def("openai", "https://api.example.com"), dep);
    assert_eq!(
        merged.table.get("OpenAI-Organization"),
        Some(&serde_json::json!("org-abc"))
    );
    assert_eq!(
        merged.table.get("api-version"),
        Some(&serde_json::json!("2024-10-21"))
    );

    assert_eq!(
        crate::config::providers::judge_options("p", &merged),
        Err(
            "providers.p: unknown field `OpenAI-Organization`: no loaded plane speaks this \
             provider's dialect, so it takes no option"
                .to_string()
        )
    );

    let plain: ProvidersDoc =
        serde_yaml::from_str("providers:\n  p:\n    api_key: {env: K}\n").expect("reads");
    let plain = merge_provider_fallback(
        &provider_def("openai", "https://api.example.com"),
        &plain.providers["p"],
    );
    assert_eq!(crate::config::providers::judge_options("p", &plain), Ok(()));
}

#[test]
fn a_catalog_entrys_stray_key_is_refused_at_resolve() {
    let defs = crate::config::providers::catalog_from_str(
        "p:\n  protocol: openai\n  base_url: https://api.example.com\n  bogus_key: true\n\
         q:\n  protocol: openai\n  base_url: https://api.example.com\n  stray: 1\n",
    )
    .expect("the catalog reads; its options are judged at resolve");
    assert_eq!(defs["p"].options.keys().collect::<Vec<_>>(), ["bogus_key"]);
    let mut deploy = base_deploy();
    deploy
        .providers
        .insert("p".to_string(), provider_deploy("K"));
    let errors = resolve(&deploy, &defs).expect_err("a stray catalog key is refused");
    let no_plane = |name: &str, key: &str| {
        format!(
            "providers.yaml: providers.{name}: unknown field `{key}`: no loaded plane speaks this \
             provider's dialect, so it takes no option"
        )
    };
    assert!(errors.contains(&no_plane("p", "bogus_key")), "{errors:?}");
    assert!(
        errors.contains(&no_plane("q", "stray")),
        "an entry config.yaml does not reference is judged too: {errors:?}"
    );
    let e = crate::config::providers::catalog_from_str("p:\n  protocol: [1]\n  base_url: x\n")
        .expect_err("a typed key of the wrong type")
        .to_string();
    assert!(e.starts_with("p.protocol: invalid type: sequence"), "{e}");
}

#[test]
fn an_unowned_catalog_is_deferred_only_while_no_provider_is_deployed() {
    let defs = crate::config::providers::catalog_from_str(
        "p:\n  protocol: catalog-deletion-qualification\n  base_url: https://p.example.invalid\n\
         q:\n  protocol: catalog-deletion-qualification\n  base_url: https://q.example.invalid\n  request_capability: {modes: [future]}\n",
    )
    .expect("core catalog fields are valid");
    let mut deploy = base_deploy();
    deploy.providers.clear();
    let cfg = resolve(&deploy, &defs).expect("no provider consumes the unowned options");
    assert!(cfg.providers.is_empty());
    assert_eq!(
        defs["q"].options["request_capability"],
        serde_json::json!({"modes": ["future"]}),
        "deferring a check must not delete or rewrite the catalog data"
    );

    deploy.providers.insert("p".into(), provider_deploy("K"));
    let errors = resolve(&deploy, &defs).expect_err("deployment restores whole-catalog validation");
    assert!(
        errors.iter().any(|e| e.contains("providers.q: unknown field `request_capability`")),
        "even an unreferenced catalog row is judged before a provider becomes effective: {errors:?}"
    );
}

#[test]
fn an_unused_catalog_still_requires_valid_core_fields() {
    let error = crate::config::providers::catalog_from_str(
        "p:\n  protocol: catalog-deletion-qualification\n  base_url: [not, a, string]\n",
    )
    .expect_err("the core field is typed even for an unused catalog")
    .to_string();
    assert!(
        error.starts_with("p.base_url: invalid type: sequence"),
        "{error}"
    );
}

#[test]
fn an_option_written_twice_is_refused() {
    let e = serde_yaml::from_str::<ProvidersDoc>(
        "providers:\n  p:\n    api_key: {env: K}\n    x-a: 1\n    x-a: 2\n",
    )
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(e.contains("x-a"), "{e}");
}

#[test]
fn the_catalog_keys_are_the_typed_grammars() {
    assert_eq!(
        crate::config::providers::catalog_grammar_keys(),
        crate::config::providers::CATALOG_KEYS,
    );
}

#[test]
fn the_deploy_keys_are_the_typed_grammars() {
    assert_eq!(
        crate::config::providers::deploy_grammar_keys(),
        crate::config::providers::DEPLOY_KEYS,
    );
}

#[test]
fn an_on_exhausted_naming_both_a_fallback_and_a_queue_is_refused() {
    let err =
        serde_yaml::from_str::<OnExhaustedCfg>("{ fallback_pool: cold, queue: { max_ms: 250 } }")
            .expect_err("both keys present is an error");
    assert!(
        err.to_string().contains("exactly one of"),
        "must reject both fallback_pool and queue; got: {err}"
    );
}
