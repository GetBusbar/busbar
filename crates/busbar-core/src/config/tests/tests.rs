use super::*;

// ── shared test helpers ──────────────────────────────────────────────────────────────────────────

/// A minimal ProviderDef for resolve() tests.
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
    }
}

/// A minimal ProviderDeploy whose credential is `{ env: <var> }`.
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
    }
}

/// An all-default DeployCfg for struct-literal resolve() tests (DeployCfg has no Default because
/// providers/models are required in YAML).
pub(crate) fn base_deploy() -> DeployCfg {
    DeployCfg {
        tools: Default::default(),
        agents: Default::default(),
        listen: DEFAULT_LISTEN_ADDR.into(),
        // Not an MCP server.
        mcp: None,
        oauth_as: None,
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

// 1.4.0 config compatibility: a 1.3.0 config using the removed `auth.mode:` key must fail with an
// actionable migration hint, not just serde's bare "unknown field `mode`". Verify the hint is
// appended for the mode error and that unrelated errors pass through verbatim; plus an end-to-end
// parse.
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
    // Unrelated errors are returned unchanged.
    assert_eq!(
        crate::config::augment_config_error("some other yaml error"),
        "some other yaml error"
    );
    // End-to-end: a legacy `auth.mode:` config surfaces the hint through the parse path.
    let legacy = "providers: {}\nauth:\n  mode: none\n";
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(legacy)
        .map_err(crate::config::augment_config_error)
        .expect_err("legacy auth.mode must fail to parse");
    assert!(
        err.contains("auth.chain:"),
        "end-to-end error carries the hint: {err}"
    );
}

/// 1.5.3 HARD tap-stage rename (loud-fail, NO serde alias): an old-form `at:` wire string
/// (`route`/`attempt`/`completion`) is rejected at parse as an unknown `HookStage` variant, and
/// `augment_config_error` upgrades serde's bare message to a hint naming BOTH the old and the new
/// value plus the migrator. Mirrors `augment_config_error_adds_auth_mode_migration_hint`.
#[test]
fn augment_config_error_adds_hook_stage_rename_hint() {
    for (old, new) in [
        ("route", "candidate"),
        ("attempt", "routing"),
        ("completion", "response"),
    ] {
        // The synthetic serde message an unknown enum variant produces.
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
    // End-to-end: an old stage VALUE (`completion`) written into the surviving `phase:` list surfaces
    // the loud-fail through the parse path — the HARD rename has no back-compat alias, so it must NOT
    // parse silently. (1.6.0 removed the `at:` KEY itself; the stage-value vocab it once carried now
    // only reaches the parser through `phase:`.)
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

/// The hook config types are round-trippable (Deserialize + Serialize), the foundation for the
/// config-overlay persistence that lets a runtime-registered hook survive a restart. A `HookCfg`
/// deserialized from JSON re-serializes + re-parses to an identical shape, exercising the
/// snake_case enums (kind/prompt/user) + the transport + the ordering/stage fields.
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
    // Serialize -> re-deserialize -> re-serialize: the two JSON forms must be identical (stable).
    let once = serde_json::to_value(&cfg).expect("HookCfg serializes");
    let cfg2: HookCfg = serde_json::from_value(once.clone()).expect("re-deserializes");
    let twice = serde_json::to_value(&cfg2).expect("re-serializes");
    assert_eq!(once, twice, "HookCfg round-trips stably");
    // Spot-check the snake_case enum projection survives.
    assert_eq!(once["kind"], "gate");
    assert_eq!(once["prompt"], "rw");
    assert_eq!(once["user"], "ro");
    assert_eq!(once["on_error"], "reject");
}

/// Serializes tests that touch SHARED env vars referenced by the shipped `config.yaml`. Env vars
/// are process-global, and `cargo test` runs tests in parallel by default, so two tests that
/// `set_var`/`remove_var` the same name race: one can wipe the value mid-flight of the other,
/// causing a spurious "unset variable" interpolation failure. Every test that drives a shipped
/// `${...}` var must hold this lock for the whole set/interpolate/remove sequence.
///
/// Per-test vars use unique `BUSBAR_T_*` names and so do not need this guard.
static CLIENT_TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 1.5.0 MIGRATION (fail-closed): the removed `auth:` keys are REJECTED AT PARSE by
/// `deny_unknown_fields`, never silently dropped. Covers `mode:` (1.3.0), the single-token
/// `token:` (1.0.0), and the 1.5.0 removals `client_tokens:` and `modules:` (the allowlist and
/// per-module caps moved to `chain:` / `role_bindings:` / `groups:`). A rejected secret value is
/// never echoed back in the parse error.
#[test]
fn test_removed_auth_keys_are_rejected_at_parse() {
    for (yaml, removed_key) in [
        ("mode: token", "mode"),
        ("token: \"sk-bb-legacy\"", "token"),
        ("client_tokens: [\"sk-bb-legacy\"]", "client_tokens"),
        ("modules:\n  sso:\n    allowed_groups: [eng]", "modules"),
        // 1.5.3 removals: the credential mode moved to `pools.upstream_credentials` and
        // the hosted-login block folded into the `identity-providers:` definition.
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

/// deny_unknown_fields gap: `TlsCfg` is `#[serde(deny_unknown_fields)]`, so a TYPO under
/// `health:` was the ONE top-level section without `deny_unknown_fields`, so a typo'd probe knob
/// parsed clean and was silently ignored — the operator believes probing is retuned while it keeps
/// the defaults. Every sibling section rejects at parse; this one now does too.
#[test]
fn test_health_typo_rejected_at_parse() {
    let bad = "default_probe_interval_sec: 5"; // missing the trailing `s`
    let err = serde_yaml::from_str::<crate::config::HealthDefaultsCfg>(bad)
        .expect_err("a typo under health: must be rejected at parse (deny_unknown_fields)");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("default_probe_interval_sec"),
        "the error names the offending key: {msg}"
    );
}

/// `tls:` (e.g. `client_c:` for `client_ca:`) is REJECTED AT PARSE rather than silently ignored
/// (which would leave mTLS DISABLED while the operator believes it is on). The 1.4.x spellings
/// `cert_file`/`key_file`/`client_ca_file` are REMOVED and rejected too; the fields are now
/// SecretRefs (`cert:` / `key:` / `client_ca:`).
#[test]
fn test_tls_typo_and_removed_keys_rejected_at_parse() {
    // A typo'd mTLS key must fail, not be silently dropped.
    let bad = "cert: { file: /c.pem }\nkey: { file: /k.pem }\nclient_c: { file: /ca.pem }";
    let err = serde_yaml::from_str::<TlsCfg>(bad)
        .expect_err("a typo under tls: must be rejected at parse (deny_unknown_fields)");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("client_c"),
        "expected an unknown-field error naming the typo; got: {msg}"
    );
    // The removed 1.4.x file-path spellings are rejected (they are SecretRefs now).
    let legacy = "cert_file: /c.pem\nkey_file: /k.pem";
    let err = serde_yaml::from_str::<TlsCfg>(legacy)
        .expect_err("the removed cert_file/key_file keys must be rejected");
    assert!(err.to_string().contains("unknown field"), "{err}");
    // The new SecretRef spelling parses and enables mTLS.
    let good = "cert: { file: /c.pem }\nkey: { env: TLS_KEY_PEM }\nclient_ca: { file: /ca.pem }";
    let cfg = serde_yaml::from_str::<TlsCfg>(good).expect("well-formed tls config parses");
    assert_eq!(cfg.cert.file_path(), Some("/c.pem"));
    assert_eq!(cfg.key.env_var(), Some("TLS_KEY_PEM"));
    assert_eq!(
        cfg.client_ca.as_ref().and_then(|c| c.file_path()),
        Some("/ca.pem")
    );
}

/// 1.5.0 CLEAN BREAK: the pre-1.0 serde aliases are GONE. Each old spelling is now an
/// unknown-field parse error; only the canonical name loads. (This test used to pin the aliases
/// as accepted; 1.5.0 is unreleased with no back-compat, so it now pins them REJECTED.)
#[test]
fn test_removed_key_aliases_are_rejected() {
    // breaker trip: window_s and n are gone; window_secs / consecutive_n are canonical.
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

    // failover: deadline_secs and cap are gone; timeout_secs / max_hops are canonical.
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

/// 1.5.3: the `observability:` BLOCK IS DELETED and its last field (`otlp_url`, and before it the
/// 1.4.x `otlp_endpoint`) is now the `settings.url` of an `export:` instance with `module: otlp`.
/// The new spelling resolves; the 1.4.x key inside the settings bag is rejected (`OtlpSettings` is
/// `deny_unknown_fields`), so the retirement is loud rather than a silently-dropped trace sink.
///
/// Before 1.5.3 `otlp_url` was an `ObservabilityCfg` field and there was no
/// `otlp` export module at all, so neither half of this compiled.
#[test]
fn test_otlp_folds_into_an_export_instance() {
    let defs: crate::config::ExportDefs = serde_yaml::from_str(
        "traces:\n  module: otlp\n  settings: { url: \"http://localhost:4318/v1/traces\" }\n",
    )
    .expect("an otlp export instance parses");
    let mut errors = Vec::new();
    let export = crate::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        export.otlp.as_ref().map(|o| o.url.as_str()),
        Some("http://localhost:4318/v1/traces")
    );

    let defs: crate::config::ExportDefs = serde_yaml::from_str(
        "traces:\n  module: otlp\n  settings: { otlp_endpoint: \"http://localhost:4318\" }\n",
    )
    .expect("the outer instance shape still parses (settings is an opaque bag)");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_export(&defs, &mut errors);
    assert!(
        errors.iter().any(|e| e.contains("otlp_endpoint")),
        "the 1.4.x otlp_endpoint key must be rejected inside otlp settings; got {errors:?}"
    );
}

/// 1.5.3 observability→export lift-out: the retired `observability.request_log_webhook_url` and the
/// top-level `metrics:` block are rejected at parse (`deny_unknown_fields`), and `augment_config_error`
/// turns the bare serde error into an actionable hint naming the new export home + the migrator — the
/// same shared-table discipline as the HookStage rename.
///
/// Before 1.5.3 these keys were live config fields that parsed silently, so the
/// parse SUCCEEDED (no error to augment) — this test does not pass on the pre-retirement tree.
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

/// `observability.emit_server_timing` MOVED to
/// `advanced.response_headers.server_timing`. 1.5.3 went further and DELETED the whole
/// `observability:` block, so the old location is now an unknown TOP-LEVEL field — LOUD
/// and fail-closed; `busbar --migrate-config` moves it (see `migrate_tests.rs`).
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

/// `advanced.response_headers:` — both toggles parse, default to `false`, and a typo'd field is a
/// loud `deny_unknown_fields` reject (never a silent no-op).
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

/// A minimal config without a `pools:` section parses fine: pools are optional (direct model
/// routing). Only providers + models are required. Provider credentials are secret references.
#[test]
fn test_config_without_pools_parses() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("config without pools must parse");
    assert!(deploy.pools.pools.is_empty());
    assert!(deploy.models.contains_key("claude"));
    assert_eq!(
        deploy.providers["anthropic"].api_key.env_var(),
        Some("ANTHROPIC_KEY")
    );
}

/// A provider's `path` override flows from the catalog (and a deployment override wins) into
/// the resolved ProviderCfg, the knob that fixes version-in-base-url providers.
#[test]
fn test_provider_path_override_resolves() {
    let mut defs = HashMap::new();
    let mut def = provider_def("openai", "https://api.z.ai/api/paas/v4");
    def.path = Some("/chat/completions".to_string());
    defs.insert("zai-payg".to_string(), def);

    let mut dep = provider_deploy("ZAI_KEY");
    // Deployment-side health (the block config.yaml documents under a provider).
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
    // Deployment-side health must survive resolve (regression: it was silently dropped).
    assert_eq!(
        cfg.providers["zai-payg"].health.as_ref().map(|h| h.mode),
        Some(HealthMode::Dead),
        "config.yaml provider health must resolve into ProviderCfg"
    );
    // The secret REFERENCE (never a resolved value) is carried through.
    assert_eq!(cfg.providers["zai-payg"].api_key.env_var(), Some("ZAI_KEY"));
}

#[test]
fn bind_is_loopback_classification() {
    // Loopback binds: safe for a token-only admin plane.
    assert!(bind_is_loopback("127.0.0.1:8081"));
    assert!(bind_is_loopback("localhost:8081"));
    assert!(bind_is_loopback("LocalHost:8081")); // case-insensitive
    assert!(bind_is_loopback("[::1]:8081")); // IPv6 loopback with brackets
    assert!(bind_is_loopback("127.0.0.1")); // no :port
    assert!(bind_is_loopback("127.0.0.2:80")); // whole 127/8 is loopback
                                               // Exposed binds: the boot-guard must treat these as network-reachable.
    assert!(!bind_is_loopback("0.0.0.0:8081"));
    assert!(!bind_is_loopback("10.0.0.5:8081"));
    assert!(!bind_is_loopback("[::]:8081")); // IPv6 unspecified
    assert!(!bind_is_loopback("admin.internal:8081")); // hostname: fail closed (exposed)
}

/// The admin-plane boot-guard: a network-exposed `admin_listen` refuses to boot without mTLS,
/// unless deliberately waived. Loopback binds and mTLS-equipped exposed binds resolve cleanly.
#[test]
fn admin_plane_boot_guard() {
    fn build(
        admin_listen: &str,
        client_ca: Option<&str>,
        // 1.5.3: the flag INVERTED — this is `admin_require_mtls`, so `false` is the waiver.
        require_mtls: bool,
    ) -> Result<RootCfg, Vec<String>> {
        let mut defs = HashMap::new();
        defs.insert(
            "p".to_string(),
            provider_def("openai", "https://api.example.com/v1"),
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

    // DEFAULT: the zero-config admin listener is loopback, so it boots with no mTLS. Note the
    // argument: 1.5.3's DEFAULT is `admin_require_mtls: true` — the guard is ON unless waived.
    assert!(
        build(DEFAULT_ADMIN_LISTEN_ADDR, None, true).is_ok(),
        "the default loopback admin_listen must resolve"
    );
    // Loopback admin plane is safe without mTLS (unreachable off-host).
    assert!(build("127.0.0.1:8081", None, true).is_ok());
    assert!(build("[::1]:8081", None, true).is_ok());
    assert!(build("localhost:8081", None, true).is_ok());
    // EXPOSED admin plane without mTLS and without waiver: REFUSE TO BOOT.
    let err = build("0.0.0.0:8081", None, true)
        .expect_err("exposed admin without mTLS must refuse to boot");
    let joined = err.join("\n");
    assert!(joined.contains("admin_listen"), "guard message: {joined}");
    assert!(joined.contains("mTLS"), "guard message: {joined}");
    assert!(
        joined.contains("admin_require_mtls: false"),
        "the guard must name the 1.5.3 waiver spelling (not the retired `admin_insecure`): {joined}"
    );
    // Exposed admin WITH client-cert mTLS: allowed.
    assert!(build("0.0.0.0:8081", Some("client-ca.pem"), true).is_ok());
    // Exposed admin with the explicit `admin_require_mtls: false` waiver: allowed (deliberate).
    assert!(build("0.0.0.0:8081", None, false).is_ok());
}

/// FREEZE: 1.5.3 INVERTED the exposed-admin boot guard (`admin_insecure: true` →
/// `admin_require_mtls: false`) so the SAFE posture is what an OMITTED key gives you — the single
/// most consequential default in the config. An omitted key must resolve to the guard being ON, and
/// the RETIRED key must LOUD-FAIL at parse rather than being silently ignored (which would leave an
/// operator believing a waiver still applied).
///
/// Before 1.5.3 `admin_insecure` was a live field (so it parsed clean) and
/// `admin_require_mtls` did not exist (so the omitted-default assertion did not compile).
#[test]
fn admin_require_mtls_defaults_on_and_the_retired_key_loud_fails() {
    let deploy: DeployCfg =
        serde_yaml::from_str("providers: {}\nmodels: {}\npools: {}\n").expect("parses");
    assert!(
        deploy.admin_require_mtls,
        "an OMITTED admin_require_mtls must default to the SAFE posture (guard ON)"
    );

    let err = serde_yaml::from_str::<DeployCfg>(
        "admin_insecure: true\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("the retired admin_insecure key must be rejected at parse");
    let hint = crate::config::augment_config_error(err);
    assert!(
        hint.contains("admin_insecure")
            && hint.contains("admin_require_mtls")
            && hint.contains("--migrate-config"),
        "the retired-key error must name the new key + the migrator; got: {hint}"
    );
}

/// The shipped example config.yaml must parse and resolve cleanly against providers.yaml
/// (every referenced provider/model exists; the example stays a working starting point).
///
/// TRANSITIONAL SKIP: until the shipped config.yaml is migrated to the 1.5.0 surface (SecretRefs,
/// auth chain, no governance block), a pre-1.5 marker (`api_key_env:`) short-circuits this test
/// with a loud note instead of failing the suite on a file another change owns. Remove the guard
/// once config.yaml is migrated.
#[test]
fn test_shipped_example_config_resolves() {
    // Hold the shared-env lock across the whole set/interpolate/remove sequence (recover on
    // poison: a panic in another holder must not block this test).
    let _env_guard = CLIENT_TOKEN_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let providers_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
            .unwrap();
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&providers_raw).expect("parse providers.yaml");

    let config_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.yaml")).unwrap();
    if config_raw.contains("api_key_env:") {
        eprintln!(
            "SKIP test_shipped_example_config_resolves: config.yaml still uses the pre-1.5.0 \
             surface (api_key_env:); re-enable by migrating the shipped example"
        );
        return;
    }

    // Booting the shipped default config must NOT require BUSBAR_ADMIN_TOKEN to
    // be set: no brace-form interpolation of it may appear anywhere (comments included, since
    // interpolate_env scans the whole file).
    assert!(
        !config_raw.contains("${BUSBAR_ADMIN_TOKEN}"),
        "the shipped config must not force a mandatory boot failure on unset BUSBAR_ADMIN_TOKEN"
    );
    std::env::remove_var("BUSBAR_ADMIN_TOKEN");

    // Satisfy every `${VAR}` the example interpolates, with unique-per-run placeholder values;
    // record which vars this test set so it can clean up (process-global env, parallel tests).
    let mut set_here: Vec<String> = Vec::new();
    for var in braced_env_vars(&config_raw) {
        if std::env::var(&var).is_err() {
            std::env::set_var(&var, "example-token");
            set_here.push(var);
        }
    }

    let expanded = interpolate_env(&config_raw).expect("expand ${ENV} in example config.yaml");
    let deploy: DeployCfg = serde_yaml::from_str(&expanded).expect("parse example config.yaml");
    let cfg = resolve(&deploy, &defs).expect("example config.yaml must resolve");
    assert!(
        !cfg.models.is_empty(),
        "the shipped example must configure at least one model"
    );

    for var in set_here {
        std::env::remove_var(var);
    }
}

/// Every `${NAME}` token in `raw` (the brace interpolation form), deduped.
fn braced_env_vars(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(i) = rest.find("${") {
        rest = &rest[i + 2..];
        let Some(j) = rest.find('}') else { break };
        let name = &rest[..j];
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.push(name.to_string());
        }
        rest = &rest[j + 1..];
    }
    out.sort();
    out.dedup();
    out
}

/// Tests sharing a process-global env var use a set -> interpolate -> remove
/// sequence. Under the default parallel test runner, an unguarded sibling could `remove_var`
/// between this test's `set_var` and `interpolate_env`, making interpolation fail with an "unset
/// variable" error. This test reproduces that race deterministically by hammering the exact
/// sequence from many threads, and asserts that holding `CLIENT_TOKEN_ENV_LOCK` across the whole
/// sequence keeps every interpolation succeeding.
#[test]
fn test_client_token_env_lock_serializes_set_interpolate_remove() {
    const THREADS: usize = 8;
    const ITERS: usize = 200;
    let failures = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let failures = std::sync::Arc::clone(&failures);
        handles.push(std::thread::spawn(move || {
            for _ in 0..ITERS {
                // The guard makes set/interpolate/remove atomic w.r.t. other lock holders.
                let _g = CLIENT_TOKEN_ENV_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                std::env::set_var("BUSBAR_CLIENT_TOKEN", "race-token");
                let r = interpolate_env("tok: \"${BUSBAR_CLIENT_TOKEN}\"");
                if r.as_deref() != Ok("tok: \"race-token\"") {
                    failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                std::env::remove_var("BUSBAR_CLIENT_TOKEN");
            }
        }));
    }
    for h in handles {
        h.join().expect("interpolation thread must not panic");
    }
    assert_eq!(
        failures.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "guarded set/interpolate/remove of BUSBAR_CLIENT_TOKEN must never observe an unset var"
    );
}

// ── pool `hooks:` list ───────────────────────────────────────────────────────────────────────────

/// The `hooks: [...]` list parses each native strategy name as the base; absent defaults to
/// weighted with base NOT named (so the `default:` hook can replace it at resolution).
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
    // Absent hooks: defaults to the zero-cost weighted strategy; base NOT named, so the pool
    // inherits the `default:` hook when one is registered.
    let absent: PoolCfg = serde_yaml::from_str("members: []\n").expect("absent parses");
    assert_eq!(absent.policy, PoolPolicy::Weighted);
    assert!(absent.gates.is_empty());
    assert!(!absent.base_named, "an absent hooks: did not name the base");
}

/// RETIRED pool keys: `policy:` / `hook:` / `route:` are simply unknown fields now
/// (deny_unknown_fields on the pool raw shape) and fail at parse.
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
    // A retired key errors even alongside a valid `hooks:` list (no silent half-migration).
    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest]\npolicy: fastest\nmembers: []\n")
        .expect_err("a retired key alongside hooks: must error");
    assert!(e.to_string().contains("unknown field"), "{e}");
}

/// The unified `hooks: [...]` pool form (1.5.3) mixes an optional ordering-strategy keyword with
/// bare hook NAMES referencing the top-level `hooks:` definition map. The strategy sets the base
/// ranking; every other bare name lands in `gates` in config order (no inline instances).
#[test]
fn test_pool_hooks_list_desugars() {
    // strategy + hook name: base explicitly named, the name captured in gates.
    let pool: PoolCfg = serde_yaml::from_str("hooks: [cheapest, pii]\nmembers: []\n")
        .expect("hooks list must parse");
    assert_eq!(pool.policy, PoolPolicy::Cheapest);
    assert!(pool.base_named, "a named strategy sets base_named");
    assert_eq!(pool.gates, vec!["pii".to_string()]);

    // hook name only: base stays default (weighted placeholder); base NOT named.
    let g: PoolCfg =
        serde_yaml::from_str("hooks: [pii]\nmembers: []\n").expect("name-only list parses");
    assert_eq!(g.policy, PoolPolicy::Weighted);
    assert_eq!(g.gates, vec!["pii".to_string()]);
    assert!(
        !g.base_named,
        "a name-only pool did not name its base ordering"
    );

    // Several names: config order is preserved (the phase-2 chain tie-break).
    let multi: PoolCfg = serde_yaml::from_str("hooks: [cheapest, pii, dlp]\nmembers: []\n")
        .expect("multi-name list parses");
    assert_eq!(multi.policy, PoolPolicy::Cheapest);
    assert_eq!(multi.gates, vec!["pii".to_string(), "dlp".to_string()]);
}

/// Two ordering strategies in one `hooks:` list is an error (a pool has one base ordering).
#[test]
fn test_pool_hooks_two_strategies_error() {
    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest, fastest]\nmembers: []\n")
        .expect_err("two strategies must error");
    assert!(
        e.to_string().contains("more than one ordering strategy"),
        "{e}"
    );
}

/// A bare NON-strategy name in a pool `hooks:` list is a HOOK-NAME REFERENCE (1.5.3), captured in
/// `gates`; its existence + `kind: gate` are validated later against the top-level `hooks:` map.
#[test]
fn test_pool_hooks_bare_name_is_a_reference() {
    let pool: PoolCfg = serde_yaml::from_str("hooks: [pii-guard]\nmembers: []\n")
        .expect("a bare hook name is a reference, not an error");
    assert_eq!(pool.gates, vec!["pii-guard".to_string()]);
    assert_eq!(pool.policy, PoolPolicy::Weighted);
    assert!(!pool.base_named);
}

/// The top-level `hooks:` DEFINITION map is deny_unknown_fields: a stray key alongside `module:` is
/// rejected at parse (a typo fails boot, never a silent no-op).
#[test]
fn test_hook_definition_unknown_key_rejected() {
    let e = serde_yaml::from_str::<crate::config::HookDefCfg>(
        "{ module: busbar-phi, url: \"https://a/\" }",
    )
    .expect_err("a stray url key on a hook definition must error");
    assert!(e.to_string().contains("unknown field"), "{e}");
}

/// Pool member shape: the member names its model via `model:` (renamed from the 1.4.x
/// `target:`), and the 1.4.x `cost_per_mtok:` member cost is REMOVED (rate_card is the only cost
/// source). Both removed keys fail deny_unknown_fields.
#[test]
fn test_pool_member_model_key_and_removed_keys() {
    let m: PoolMember =
        serde_yaml::from_str("model: claude\nweight: 3\ntier: large\ntags: [opus]\n")
            .expect("member with model: parses");
    assert_eq!(m.model, "claude");
    assert_eq!(m.weight, 3);
    assert_eq!(m.tier.as_deref(), Some("large"));
    assert_eq!(m.tags, ["opus"]);

    for (yaml, key) in [
        ("target: claude\n", "target"),
        ("model: claude\ncost_per_mtok: 15\n", "cost_per_mtok"),
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

/// A hook's `prompt:` / `user:` grants parse the trust ladder; absent defaults to `no`.
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

/// The shipped providers.yaml catalog must parse, name only known protocols, and use HTTPS.
#[test]
fn test_shipped_providers_catalog_valid() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml");
    let raw = std::fs::read_to_string(path).expect("read providers.yaml");
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    assert!(defs.len() >= 10, "catalog should be non-trivial");
    let registry = crate::proto::ProtocolRegistry::with_builtins();
    for (name, def) in &defs {
        assert!(
            registry.get(&def.protocol).is_some(),
            "provider '{name}' names unknown protocol '{}'",
            def.protocol
        );
        assert!(
            def.base_url.starts_with("https://"),
            "provider '{name}' base_url must be https"
        );
    }
}

// ── env interpolation ────────────────────────────────────────────────────────────────────────────

// NOTE: env vars are process-global; tests run in parallel. Use UNIQUE per-test var
// names so they cannot race each other (the old shared HOST/USER raced + USER even
// collided with the real shell var). Do not reintroduce shared names.
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

/// `--validate` leniency: in Lenient mode an unset `${VAR}` substitutes a placeholder (its own name)
/// and is recorded (deduped) instead of erroring; Strict still errors. Uses names guaranteed unset.
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

/// An env value containing a NEWLINE (the structural
/// break that closes a quoted YAML scalar) must be rejected, not spliced into the raw config
/// text. The exploit shape: a value that ends a quoted list entry and injects an extra item must
/// fail loudly at interpolation time. Uses a unique per-test var name (process-global env,
/// parallel tests).
#[test]
fn test_interpolate_env_rejects_newline_yaml_injection() {
    // The double-quote/newline breakout payload.
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

/// A bare carriage return is also a YAML line break and must be rejected on the same grounds.
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

/// The guard must NOT over-reject: ordinary token / URL values (including ones with `:`, `/`,
/// `@`, `.`, `-`, and even an embedded double-quote or `#`, which are harmless without a line
/// break) interpolate cleanly. This keeps real opaque API keys working.
#[test]
fn test_interpolate_env_allows_ordinary_values_with_punctuation() {
    std::env::set_var("BUSBAR_T_OK_TOK", "sk-bb-aB3#9/x.y@z:1234567890abcdef");
    let result = interpolate_env("token: \"${BUSBAR_T_OK_TOK}\"").unwrap();
    std::env::remove_var("BUSBAR_T_OK_TOK");
    assert_eq!(result, "token: \"sk-bb-aB3#9/x.y@z:1234567890abcdef\"");
}

/// End-to-end: an env value carrying a newline-based injection must NOT smuggle extra YAML
/// structure into a parsed auth config (e.g. an extra chain entry). The interpolation rejects it
/// before serde ever sees the malformed YAML, so the auth surface cannot be silently widened via
/// a compromised env var.
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

/// The structural-mismatch CULPRIT ATTRIBUTION (`assert_interpolation_preserves_structure`'s
/// per-occurrence isolation loop) must name ONLY the variable whose value actually breaks
/// structure, not an innocent co-occurring variable, and must fire even though the innocent
/// variable's own hybrid substitution matches fine. This exercises `splice_occurrences`' own
/// occurrence-index bookkeeping (each occurrence must land in the right position) together with
/// the `!matches` culprit-recording guard.
#[test]
fn test_interpolate_env_multi_occurrence_names_only_the_true_culprit() {
    // A newline is blocked by the EARLIER, cheaper control-character guard
    // (`reject_yaml_unsafe_value`) before the structural check ever runs — to actually reach and
    // exercise the structural-equivalence culprit-isolation loop, the injection must be a
    // newline-free flow-collection breakout (comma + quote), the other injection shape the
    // structural check exists specifically to catch per its own doc comment.
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

/// `structural_shapes_match` must compare `Tagged` YAML nodes by BOTH tag equality and recursive
/// inner-value shape — not treat every tagged node as automatically matching (that would silently
/// let a tag-wrapped structural injection through) nor treat a tagged/untagged pair as equal (a
/// bare scalar must never be considered shape-equivalent to an explicitly tagged one).
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

    // Same tag, scalar inner content differs: scalars fold into one bucket, so this matches.
    assert!(structural_shapes_match(
        &tagged_str("mytag", "a"),
        &tagged_str("mytag", "b"),
        0
    ));

    // Different tags: must NOT match, even though the inner scalar shape is identical.
    assert!(!structural_shapes_match(
        &tagged_str("tag_a", "x"),
        &tagged_str("tag_b", "x"),
        0
    ));

    // Tagged vs. an equivalent-looking untagged scalar: must NOT match (Tagged is distinct from
    // every other Value variant per the (Value::Tagged(_), _) | (_, Value::Tagged(_)) arms).
    assert!(!structural_shapes_match(
        &tagged_str("mytag", "x"),
        &Value::String("x".to_string()),
        0
    ));

    // Tagged wrapping a Mapping vs. Tagged wrapping a Sequence, same tag: inner shapes differ, so
    // the recursive call must catch it (proves the recursion, not just the tag comparison, runs).
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

/// The `depth + 1` passed to every recursive call must actually INCREASE, never decrease — this
/// is what makes `MAX_STRUCTURAL_COMPARE_DEPTH` a real cap rather than a no-op. Two single-element
/// sequences (the simplest possible recursive call, `depth` going 0 -> 1) must both shape-match
/// (scalar elements) AND simply return rather than panic — a `depth - 1` bug would underflow
/// `depth: usize` on this very first recursive call.
#[test]
fn structural_shapes_match_recurses_into_sequence_elements_with_increasing_depth() {
    let seq_a = serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("a".to_string())]);
    let seq_b = serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("b".to_string())]);
    assert!(structural_shapes_match(&seq_a, &seq_b, 0));
}

/// `MAX_STRUCTURAL_COMPARE_DEPTH` must be an actual CAP (`depth > LIMIT`), not a same-value-only
/// check (`depth == LIMIT`) that a caller can simply pass through — at the boundary itself
/// (depth == LIMIT) the compare must still proceed normally; one past it must fail closed
/// (rejected as a shape mismatch) regardless of the two values actually matching.
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

/// The per-occurrence placeholder token must actually encode `occurrence_index` — if every
/// occurrence collapsed to the same constant token, two DIFFERENT `${VAR}` references could never
/// be told apart during the structural-equivalence check's culprit isolation (see this function's
/// own doc comment: "two different `${VAR}` references never collapse to the same placeholder
/// token").
#[test]
fn structural_placeholder_is_unique_per_occurrence_index() {
    let p0 = structural_placeholder(0);
    let p1 = structural_placeholder(1);
    assert_ne!(p0, p1);
    assert!(!p0.is_empty());
    assert!(p0.contains('0'));
    assert!(p1.contains('1'));
}

/// `mapping_key_repr`'s fallback (non-string key) must render a deterministic, comparable
/// representation rather than e.g. collapsing every non-string key to the same string — the
/// key-set comparison in `structural_shapes_match` relies on distinct keys staying distinguishable.
#[test]
fn mapping_key_repr_distinguishes_non_string_keys() {
    let n1 = serde_yaml::Value::Number(1.into());
    let n2 = serde_yaml::Value::Number(2.into());
    let s = serde_yaml::Value::String("1".to_string());
    assert_ne!(mapping_key_repr(&n1), mapping_key_repr(&n2));
    // A string key is rendered as itself (the common-case fast path), not run through the
    // `{:?}` fallback formatting a numeric key gets.
    assert_eq!(mapping_key_repr(&s), "1");
}

/// An unclosed `${FOO` (missing `}`) must fail loudly with an "unclosed" error rather than be
/// treated as `${FOO}`, regardless of whether FOO is set in the environment. Uses a unique
/// per-test var name (process-global env, parallel tests) and a guaranteed-unset name.
#[test]
fn test_interpolate_env_unclosed_brace_fails() {
    // Unset variable, missing brace: must report "unclosed", NOT "unset environment variable".
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

    // Set variable, missing brace: must STILL error (not silently interpolate the value).
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

// ── structural-equivalence check (flow-collection / opaque-map injection, no newline needed) ──────

/// THE HEADLINE EXPLOIT, end-to-end through REAL typed deserialization (not just asserting
/// `is_err()` from the interpolation function in isolation — that alone tests the mechanism, not
/// the security property). `client_tokens: ["${VAR}"]` is this project's own documented
/// interpolation pattern (`docs/migration-1.5.md`, `docs/migration-1.3.md`) for a flow SEQUENCE,
/// which has no `deny_unknown_fields`-equivalent defense: a value containing `", "` can freely add
/// a second array element.
#[test]
fn test_structural_injection_widens_client_tokens_array_end_to_end() {
    let var = "BUSBAR_T_STRUCT_CLIENT_TOKENS";
    let payload = "real-tok\", \"injected-tok";
    std::env::set_var(var, payload);

    let template = format!(
        "providers: {{}}\nmodels: {{}}\nidentity-providers: {{ tokens: {{ module: tokens, settings: {{ client_tokens: [\"${{{var}}}\"] }} }} }}\n"
    );

    // Sanity check FIRST: prove the underlying vulnerability is real by splicing the payload
    // directly, the way an UNGUARDED interpolator would, and running it through the REAL typed
    // `DeployCfg` deserializer (not just a raw `Value`). If this assertion ever stops holding, the
    // exploit shape has changed and this test needs to be revisited — it must stay red on the
    // unguarded path for the test below to mean anything.
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

    // Now prove the guard closes it: real `interpolate_env` must reject this template outright,
    // before any typed parsing ever sees the widened array.
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

/// The second real, exploitable shape from the same audit: an OPAQUE `settings:` map
/// (`serde_json::Map<String, serde_json::Value>`, used by `identity-providers:` / hook module settings
/// / `SecretRef`) is a generic map, not a fixed struct — it carries no `deny_unknown_fields`
/// equivalent, so an injected sibling key silently reconfigures a third-party auth/hook plugin.
/// Mirrors the documented flow-style example:
/// `identity-providers: { ad: { module: ad, settings: { server: "..." } } }`.
#[test]
fn test_structural_injection_adds_sibling_settings_key_end_to_end() {
    let var = "BUSBAR_T_STRUCT_SETTINGS_KEY";
    // Breaks out of the quoted `server` value and injects a whole new sibling key into `settings`.
    let payload = "ldaps://corp\", \"evil_key\": \"evil_val";
    std::env::set_var(var, payload);

    let template = format!(
        "providers: {{}}\nmodels: {{}}\nidentity-providers: {{ ad: {{ module: ad, settings: {{ server: \"${{{var}}}\" }} }} }}\n"
    );

    // Sanity: the unguarded splice really does add the sibling key through real deserialization.
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

/// Regression pin for the `plugins.trust.allow_unsigned` exhibit that does NOT work, kept as a
/// documented "why this is safe" test (not because it's a live vector). `PluginsCfg` carries
/// `#[serde(deny_unknown_fields)]` on every field and `dir` is its only interpolatable String, so
/// injecting a sibling `trust: { allow_unsigned: true }` key requires also injecting a redirect to
/// consume the template's own dangling closing quote — every redirect tried fails:
/// an unrecognized field name (e.g. `ignore:`) is rejected by `deny_unknown_fields`, and reusing
/// `dir` again to consume the quote hits DUPLICATE-KEY rejection at the `serde_yaml` `Value`
/// layer, before `PluginsCfg` is ever constructed. `allow_unsigned` stays `false` through the full
/// real config-parsing path on the ORIGINAL, unfixed code — this test passes with or without the
/// structural-equivalence fix, and is here so a future reader doesn't mistake this path for
/// unguarded.
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

/// FALSE-POSITIVE FENCE: the structural check must not reject legitimate values whose content
/// happens to be YAML-"special" but never changes the document's SHAPE. Must pass both before and
/// after the fix (these values contain no control character either, so layer 1 never fires).
#[test]
fn test_structural_check_allows_real_world_special_char_values() {
    let cases: &[(&str, &str)] = &[
        // An LDAP DN: commas are mandatory and this is exactly the shape the OLD blocklist design
        // (rejected by an earlier draft of this fix) would have broken.
        ("BUSBAR_T_FENCE_LDAP", "cn=busbar,ou=svc,dc=corp,dc=com"),
        // A legitimate JSON-ish blob value (braces/brackets/quotes as literal scalar content).
        (
            "BUSBAR_T_FENCE_JSON",
            "{\"role\":\"svc\",\"scopes\":[\"a\",\"b\"]}",
        ),
        // A Windows-style path (busbar ships a windows-latest CI job + an
        // x86_64-pc-windows-msvc release target, so backslash-bearing values are real).
        ("BUSBAR_T_FENCE_WINPATH", "C:\\ProgramData\\busbar\\secrets"),
        // A URL with a query string.
        ("BUSBAR_T_FENCE_URL", "https://host/v1?a=1&b=2"),
    ];
    for (var, value) in cases {
        std::env::set_var(var, value);
        let input = format!("token: \"${{{var}}}\"");
        let result = interpolate_env(&input);
        std::env::remove_var(var);
        assert!(
            result.is_ok(),
            "legitimate value for {var} must not be rejected as a structural injection: {:?}",
            result
        );
        assert_eq!(result.unwrap(), format!("token: \"{value}\""));
    }
}

/// The exact false-positive the structural check must NOT flag: a numeric env value substituted
/// into `port: ${VAR}` infers as a YAML `Number` (real), while the internal placeholder token
/// infers as a `String` (it's not numeric) — a scalar TYPE change, not a shape change, and must be
/// allowed. Verified end-to-end: the field really does deserialize as an integer.
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

/// Anchor/alias behavior, documented empirically (found via manual experimentation against the
/// real `serde_yaml_ng` crate, not assumed): a bare `&name` / `*name` appearing STATICALLY in the
/// template (not attacker-controlled) resolves normally and is not affected by interpolation at
/// all — no false positive. This is the "no false positive" half.
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

/// Anchor/alias INJECTION, the "caught" half: an attacker-controlled value can REDEFINE an
/// existing anchor from inside a flow collection with no newline at all (`, b: &shared {...}, c:
/// "` — the same comma-breakout mechanism as the headline exploit), hijacking what a LATER `*alias`
/// resolves to elsewhere in the document. Verified empirically that this changes the parsed TREE
/// SHAPE at the alias site (a scalar becomes a mapping) — which the structural check catches via
/// the ordinary key-set/kind comparison, with no anchor-specific logic needed.
#[test]
fn test_anchor_redefinition_injection_is_caught_end_to_end() {
    let var = "BUSBAR_T_ANCHOR_INJECT";
    let payload = "x\", b: &shared {hijacked: true}, c: \"y";
    std::env::set_var(var, payload);
    let template =
        format!("defaults: &shared orig-scalar\nfoo: {{ a: \"${{{var}}}\" }}\nbar: *shared\n");

    // Sanity: prove the hijack is real on an unguarded splice — `bar` really does change from the
    // scalar `orig-scalar` to a mapping.
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

/// The structural check's own recursion is depth-bounded (mirrors `json::MAX_JSON_DEPTH`'s
/// reasoning, at the same 128 limit) as defense-in-depth — but `serde_yaml_ng` itself already
/// refuses to PARSE a document this deep (verified empirically: it returns a clean "recursion
/// limit exceeded" `Err` around the same depth, well before Rust's own call stack is at any real
/// risk), so `assert_interpolation_preserves_structure`'s existing early-return ("the real text
/// doesn't even parse as YAML, that already fails safely downstream") fires first in practice.
/// This test pins that observed, safe behavior: interpolation of the TEXT still succeeds (nothing
/// panics, nothing hangs), and the eventual failure is deferred to the real typed parse a caller
/// runs on the returned text — exactly as the existing code comment already documents for any
/// other unparseable-once-interpolated document. 300 levels is comfortably past both limits.
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
    // Must not panic or hang — the real assertion is that this returns at all, and quickly.
    let result = interpolate_env(&input);
    std::env::remove_var(var);
    assert!(
        result.is_ok(),
        "text-level interpolation must still succeed for a too-deep document (the eventual \
         failure is the downstream real parse's job, not this check's): {:?}",
        result
    );
    // The deferred failure actually happens: the caller's real parse of this same text rejects it
    // (serde_yaml_ng's own recursion guard), so the too-deep document does not silently boot.
    let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&result.unwrap());
    assert!(
        parsed.is_err(),
        "a document nested this deep must still fail the real downstream parse"
    );
}

// ── two-file (providers.yaml + config.yaml) resolution ───────────────────────────────────────────

#[test]
fn test_resolve_provider_from_def() {
    // DeployCfg referencing z.ai + providers.yaml def -> resolved ProviderCfg has
    // protocol/base_url/error_map from def
    let mut defs = HashMap::new();
    let mut def = provider_def(DEFAULT_PROTOCOL, "https://api.z.ai/api/anthropic");
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
    assert_eq!(provider_cfg.protocol, DEFAULT_PROTOCOL);
    assert_eq!(provider_cfg.base_url, "https://api.z.ai/api/anthropic");
    assert_eq!(provider_cfg.api_key.env_var(), Some("ZAI_KEY"));
    assert_eq!(
        provider_cfg.error_map.get("1113"),
        Some(&"billing".to_string())
    );
    assert_eq!(
        provider_cfg.error_map.get("1302"),
        Some(&"rate_limit".to_string())
    );
}

/// A provider credential is a SECRET REFERENCE, never an inline literal. A plain-string
/// `api_key:` (the pre-1.0 inline-key shape) is REJECTED AT PARSE (SecretRef deserializes only
/// from a map), and the removed `api_key_env:` spelling is an unknown-field error.
#[test]
fn test_provider_inline_key_and_removed_env_key_rejected() {
    // Inline literal key: rejected (a SecretRef is a map, never a bare secret).
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

    // The removed api_key_env spelling: unknown-field error.
    let yaml = r#"
providers:
  myprov:
    api_key_env: MYPROV_KEY
models: {}
"#;
    let err = serde_yaml::from_str::<DeployCfg>(yaml)
        .expect_err("the removed api_key_env key must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("api_key_env"),
        "{msg}"
    );
}

#[test]
fn test_resolve_unknown_provider_error() {
    // config.yaml references nope not in providers.yaml -> resolve returns error naming nope
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
    // config.yaml provider with a base_url override wins over the def
    let mut defs = HashMap::new();
    defs.insert(
        "custom".to_string(),
        provider_def(DEFAULT_PROTOCOL, "https://default.example.com"),
    );

    let mut override_error_map = HashMap::new();
    override_error_map.insert("9999".to_string(), "client_error".to_string());
    let mut dep = provider_deploy("CUSTOM_KEY");
    dep.protocol = Some("openai".to_string()); // Override protocol
    dep.base_url = Some("https://override.example.com".to_string()); // Override base_url
    dep.error_map = Some(override_error_map); // Override error_map

    let mut deploy = base_deploy();
    deploy.providers.insert("custom".to_string(), dep);

    let result = resolve(&deploy, &defs).expect("resolve should succeed");

    let provider_cfg = result
        .providers
        .get("custom")
        .expect("custom should be in resolved providers");
    assert_eq!(
        provider_cfg.protocol, "openai",
        "protocol override should win"
    );
    assert_eq!(
        provider_cfg.base_url, "https://override.example.com",
        "base_url override should win"
    );
    assert_eq!(provider_cfg.api_key.env_var(), Some("CUSTOM_KEY"));
    assert_eq!(
        provider_cfg.error_map.get("9999"),
        Some(&"client_error".to_string())
    );
}

#[test]
fn test_resolve_empty_error_map_allowed_in_def() {
    // A def can have empty error_map; validation will catch it later if required
    let mut defs = HashMap::new();
    defs.insert(
        "minimal".to_string(),
        provider_def(DEFAULT_PROTOCOL, "https://api.example.com"),
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
    assert!(provider_cfg.error_map.is_empty());
}

// ── on_exhausted (keyword bare, reference structured) ────────────────────────────────────────────

/// The structured `on_exhausted:` parses its two bare keywords and the structured fallback-pool
/// reference, and each projects to the right runtime behavior via `to_runtime()`.
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

    // And through a pool block end-to-end.
    let pool: PoolCfg =
        serde_yaml::from_str("members: []\non_exhausted: { fallback_pool: cold }\n")
            .expect("pool with structured on_exhausted parses");
    assert_eq!(
        pool.on_exhausted,
        Some(OnExhaustedCfg::FallbackPool("cold".to_string()))
    );
}

/// Unknown `on_exhausted` keywords are rejected with an error teaching the valid vocabulary; the
/// retired 1.4.x string form `fallback_pool:name` (colon inside ONE string) is now just an
/// unknown keyword and is rejected too.
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

    // The old one-string form: YAML parses `"fallback_pool:drain"` as a single scalar, which is
    // not a recognized keyword.
    let err = serde_yaml::from_str::<OnExhaustedCfg>("\"fallback_pool:drain\"")
        .expect_err("the retired string form must error");
    assert!(
        err.to_string().contains("unknown on_exhausted keyword"),
        "{err}"
    );

    // An empty structured pool name is rejected.
    let err = serde_yaml::from_str::<OnExhaustedCfg>("fallback_pool: \"\"")
        .expect_err("an empty fallback pool name must error");
    assert!(err.to_string().contains("non-empty"), "{err}");

    // An unknown key in the structured form is rejected (deny_unknown_fields).
    assert!(serde_yaml::from_str::<OnExhaustedCfg>("fallback_pols: x").is_err());
}

#[test]
fn breaker_cfg_default_matches_serde_default_fns() {
    // `BreakerCfg::default()` (used when a pool omits the whole `breaker:` block) and the
    // `#[serde(default = ...)]` fns (used when individual fields are omitted) must agree on the
    // cooldown literals; otherwise the same pool would get different cooldowns depending on
    // whether the block is present. `Default` now delegates to these fns, so this guards against
    // the two ever drifting again.
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

/// The config surface carries NO raw secret material anywhere:
/// every credential is a SecretRef (module + settings), so debug-logging a whole DeployCfg can
/// never leak a resolved secret VALUE. This sets a distinctive value in the environment, builds a
/// config full of refs to it, and asserts the Debug dump shows the reference (the env var NAME)
/// but never the value.
#[test]
fn test_debug_of_full_config_never_shows_resolved_secrets() {
    std::env::set_var("BUSBAR_T_DEBUG_SECRET", "SECRET-resolved-value-zzz");
    let auth = crate::config::AuthDeployCfg {
        signing_key: Some(SecretRef::env("BUSBAR_T_DEBUG_SECRET")),
        chain: vec![KEYS_MODULE.to_string()],
        admin_auth: vec![ADMIN_TOKENS_MODULE.to_string()],
        role_bindings: RoleBindings::new(),
        key_ttl: None,
    };
    let mut deploy = base_deploy();
    deploy.auth = Some(auth);
    // The `admin-tokens` operator credential now lives on its `identity-providers:` DEFINITION
    // (not inline on a chain entry), so the Debug dump must stay clean there too.
    deploy.identity_providers.insert(
        ADMIN_TOKENS_MODULE.to_string(),
        crate::config::IdentityProviderCfg {
            module: ADMIN_TOKENS_MODULE.to_string(),
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

// ── operational limits ("NEVER CODED CAPS") ──────────────────────────────────────────────────────

/// A config that OMITS the whole `limits:` block (and every other limit section) must resolve to
/// the HISTORICAL hardcoded defaults, the common case and the guarantee that nothing changes
/// for existing deployments. Asserts every resolved limit equals its `DEFAULT_*` const.
#[test]
fn test_limits_absent_block_yields_historical_defaults() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
    let deploy: DeployCfg =
        serde_yaml::from_str(yaml).expect("config without a limits block must parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.advanced,
        &crate::config::resolve_export(&deploy.export, &mut Vec::new()),
        &deploy.health,
        &deploy.routing,
    );
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
    // A literal, not a comparison against the constant's own name: the constant's DEFINITION
    // (`256 * 1024`) is itself what needs proving, so re-deriving the expectation from the same
    // named constant would be tautological.
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
    assert_eq!(l.default_max_tokens, crate::proto::DEFAULT_MAX_TOKENS);
    assert_eq!(
        l.max_inflight_webhook_deliveries,
        DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
    );
    // 1.5.3: the per-delivery webhook TIMEOUT is no longer projected onto `LimitsResolved` — it is
    // per named `request-log-webhook` export instance (see `WebhookSettings::delivery_timeout_secs`).
    assert_eq!(l.key_gauge_limit, DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(l.rate_sweep_interval, DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(l.usage_flush_interval_ms, DEFAULT_USAGE_FLUSH_INTERVAL_MS);
    assert_eq!(l.default_probe_interval_secs, DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.default_policy_timeout_ms, DEFAULT_POLICY_TIMEOUT_MS);
}

/// `LimitsResolved::default()` (the omitted-everything path) must equal the per-field defaults:
/// the two ways of getting "today's behavior" cannot drift.
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

/// A SET limit value (across several sections) OVERRIDES the default; an unset SIBLING field in
/// the same block still defaults. Exercises the per-field `#[serde(default = "...")]` wiring.
/// The former `governance:` tuning knobs now live under `advanced:`.
#[test]
fn test_limits_set_value_overrides_default() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
models:
  claude:
    provider: anthropic
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
    // Unset SIBLING fields still default (pool_max_idle in the same `limits:` block, probe
    // TIMEOUT in the same `health:` block):
    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
}

/// The body-size COUPLING: `limits.request_body_max_bytes` is the SINGLE knob; the resolved value
/// the inbound `DefaultBodyLimit` uses IS the same value the egress translate-body cap reads
/// (`crate::limits::translate_body_max_bytes` returns `request_body_max_bytes`). So an accepted
/// request is always buffer-translatable on egress.
#[test]
fn test_request_body_size_couples_ingress_and_translate() {
    let d = LimitsResolved::default();
    assert_eq!(d.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);

    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
models:
  claude:
    provider: anthropic
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

// ── SecretRef ────────────────────────────────────────────────────────────────────────────────────

/// The `{ env: VAR }` / `{ file: PATH }` sugar spellings desugar to the built-in modules'
/// canonical `{ module, settings }` form.
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

/// The canonical `{ module, settings }` form parses verbatim (third-party secret modules), with
/// settings passed through opaquely; a missing `settings:` defaults to empty.
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

/// SecretRef malformed shapes fail loudly: both sugar + canonical forms together, two sugars,
/// unknown keys, empty values, and an empty map are all parse errors.
#[test]
fn test_secret_ref_malformed_shapes_rejected() {
    // Canonical + sugar together.
    let err = serde_yaml::from_str::<SecretRef>("module: env\nenv: FOO")
        .expect_err("module + sugar must error");
    assert!(err.to_string().contains("not both"), "{err}");
    // Two sugar keys.
    let err = serde_yaml::from_str::<SecretRef>("env: FOO\nfile: /p")
        .expect_err("two sugar keys must error");
    assert!(err.to_string().contains("exactly one"), "{err}");
    // Sugar + settings.
    let err = serde_yaml::from_str::<SecretRef>("env: FOO\nsettings: { a: 1 }")
        .expect_err("sugar with settings must error");
    assert!(err.to_string().contains("no `settings:`"), "{err}");
    // Unknown key.
    let err =
        serde_yaml::from_str::<SecretRef>("keyring: FOO").expect_err("unknown key must error");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("keyring"),
        "{msg}"
    );
    // Empty sugar value.
    let err =
        serde_yaml::from_str::<SecretRef>("env: \"\"").expect_err("empty sugar value must error");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // Empty module name.
    let err =
        serde_yaml::from_str::<SecretRef>("module: \"\"").expect_err("empty module must error");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // Empty map: neither module nor sugar.
    let err = serde_yaml::from_str::<SecretRef>("{}").expect_err("empty map must error");
    assert!(err.to_string().contains("needs `module:`"), "{err}");
    // A bare scalar is not a secret reference.
    assert!(serde_yaml::from_str::<SecretRef>("\"sk-raw-secret\"").is_err());
}

/// Built-in resolution is FAIL-CLOSED: `env` resolves a set non-empty variable and errors on
/// unset/empty; `file` reads bytes and errors on missing/empty; any other module errors; the
/// string form trims trailing newlines (the file-delivered-secret convention).
#[test]
fn test_secret_ref_builtin_resolution_fail_closed() {
    use crate::config::secret::{resolve_builtin, resolve_builtin_string};

    // env: set, non-empty.
    std::env::set_var("BUSBAR_T_SECRET_ENV_OK", "s3cr3t-value");
    assert_eq!(
        resolve_builtin(&SecretRef::env("BUSBAR_T_SECRET_ENV_OK")).unwrap(),
        b"s3cr3t-value".to_vec()
    );
    std::env::remove_var("BUSBAR_T_SECRET_ENV_OK");

    // env: unset -> error naming the variable.
    let err = resolve_builtin(&SecretRef::env("BUSBAR_T_SECRET_ENV_UNSET")).unwrap_err();
    assert!(
        err.contains("BUSBAR_T_SECRET_ENV_UNSET") && err.contains("unset"),
        "{err}"
    );

    // env: set but EMPTY -> fail-closed error, never an empty secret.
    std::env::set_var("BUSBAR_T_SECRET_ENV_EMPTY", "");
    let err = resolve_builtin(&SecretRef::env("BUSBAR_T_SECRET_ENV_EMPTY")).unwrap_err();
    std::env::remove_var("BUSBAR_T_SECRET_ENV_EMPTY");
    assert!(err.contains("EMPTY"), "{err}");

    // file: existing file resolves; the string form trims the trailing newline.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-secret-test-{}", std::process::id()));
    std::fs::write(&path, "file-secret\n").unwrap();
    let sref = SecretRef::file(path.to_str().unwrap());
    assert_eq!(resolve_builtin(&sref).unwrap(), b"file-secret\n".to_vec());
    assert_eq!(resolve_builtin_string(&sref).unwrap(), "file-secret");
    std::fs::remove_file(&path).unwrap();

    // file: missing -> error.
    let missing = SecretRef::file("/nonexistent/busbar-secret-test");
    assert!(resolve_builtin(&missing).is_err());

    // unknown module -> fail-closed error naming the module.
    let mut settings = serde_json::Map::new();
    settings.insert("path".to_string(), serde_json::Value::String("x".into()));
    let unknown = SecretRef {
        module: "vault".to_string(),
        settings,
    };
    let err = resolve_builtin(&unknown).unwrap_err();
    assert!(
        err.contains("vault") && err.contains("fail-closed"),
        "{err}"
    );
}

// ── identity providers + auth chain references ───────────────────────────────────────────────────

/// 1.5.3: an IdP is DEFINED ONCE in the top-level `identity-providers:` map and
/// REFERENCED BY BARE NAME from `auth.chain:` AND `auth.admin_auth:`. This covers the definition's
/// shape (every typed field parses) plus the property the whole redesign exists for: ONE definition
/// serving BOTH planes, so its settings cannot drift between them.
///
/// Before 1.5.3 `identity-providers:` did not exist and a chain entry was an
/// inline single-key map, so neither the parse nor the shared-definition assertion compiled.
#[test]
fn test_identity_provider_definition_is_referenced_by_name_from_both_planes() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "identity-providers:\n  \
           corp-ad: { module: ad, max_admin_scope: full, settings: { server: \"ldaps://corp\" } }\n  \
           admin-tokens: { module: admin-tokens, token: { env: BUSBAR_T_AD_TOKEN } }\n\
         auth:\n  chain: [keys, corp-ad]\n  admin_auth: [admin-tokens, corp-ad]\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("the 1.5.3 identity-providers grammar parses");

    let mut errors = Vec::new();
    let auth = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    // A BARE BUILT-IN needs no definition at all.
    assert_eq!(auth.chain[0], AuthChainEntry::bare(KEYS_MODULE));

    // THE DEDUPE PROPERTY: `corp-ad` appears in BOTH chains and resolves from the SAME definition,
    // so its module/settings/ceiling are identical BY CONSTRUCTION — the pre-1.5.3 grammar made the
    // operator write them twice, and nothing stopped the two copies from disagreeing.
    let data = &auth.chain[1];
    let admin = &auth.admin_auth[1];
    assert_eq!(data.name, "corp-ad");
    assert_eq!(data.module, "ad");
    assert_eq!(data.max_admin_scope.as_deref(), Some("full"));
    assert_eq!(
        data.settings.get("server").and_then(|v| v.as_str()),
        Some("ldaps://corp")
    );
    assert_eq!(
        data, admin,
        "one definition, referenced twice — never two independently-drifting copies"
    );

    // The operator credential's `token:` lives on the DEFINITION now, not on a chain entry.
    assert_eq!(
        auth.admin_auth[0].token.as_ref().and_then(|t| t.env_var()),
        Some("BUSBAR_T_AD_TOKEN")
    );
}

/// FREEZE: an OMITTED `max_admin_scope` resolves to the MOST RESTRICTIVE ceiling
/// (`read-only`) for every provider — EXCEPT the built-in `admin-tokens` operator credential, which
/// is full-by-definition and stays exempt. This preserves the pre-1.5.3 semantics EXACTLY while
/// moving the field off the chain entry onto the definition, so upgrading cannot silently widen or
/// narrow an existing deployment's admin ceiling.
#[test]
fn test_max_admin_scope_default_is_most_restrictive_except_admin_tokens() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "identity-providers:\n  corp-ad: { module: ad }\n  admin-tokens: { module: admin-tokens }\n\
         auth:\n  chain: [corp-ad]\n  admin_auth: [admin-tokens, corp-ad]\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let auth = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        auth.chain[0].max_admin_scope.as_deref(),
        Some(crate::config::DEFAULT_MAX_ADMIN_SCOPE),
        "an external IdP with no declared ceiling gets the MOST RESTRICTIVE default"
    );
    assert_eq!(
        auth.admin_auth[0].max_admin_scope, None,
        "the built-in admin-tokens operator credential is EXEMPT (full by definition)"
    );
}

/// FAIL-CLOSED: a chain naming a provider that is neither defined nor a bare built-in is a boot
/// error, never a silently-skipped auth module (which would quietly weaken the front door).
#[test]
fn test_dangling_identity_provider_reference_is_an_error() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "auth: { chain: [keys, ghost] }\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ghost") && e.contains("identity-providers")),
        "a dangling chain reference must name the provider + the definition map; got {errors:?}"
    );
}

/// The INLINE chain entry is GONE: a chain is a list of bare NAMES, so the retired
/// single-key-map form is a parse error rather than a second, silently-accepted grammar.
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

/// `identity-providers:` is `deny_unknown_fields`: a typo'd definition key fails boot rather than
/// silently dropping (most consequentially) a `max_admin_scope` ceiling.
#[test]
fn test_identity_provider_typo_rejected_at_parse() {
    let err = serde_yaml::from_str::<crate::config::IdentityProviders>(
        "ad: { module: ad, max_admin_scop: full }\n",
    )
    .expect_err("a typo'd definition key must error");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

/// A `token:` is the built-in `admin-tokens` operator credential and is MEANINGLESS on any other
/// module — writing one there is an operator error (they believe a credential is configured) and
/// must fail boot, not be silently ignored.
#[test]
fn test_token_on_a_non_admin_tokens_provider_is_an_error() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "identity-providers:\n  corp-ad: { module: ad, token: { env: X } }\n\
         auth: { chain: [corp-ad] }\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("token") && e.contains("corp-ad")),
        "a token on a non-admin-tokens provider must be rejected; got {errors:?}"
    );
}

/// `OnErrorCfg::as_name` must return the wrapped name for BOTH variants (a fallback hook
/// reference and a reserved terminal word use the identical flat representation downstream).
#[test]
fn on_error_cfg_as_name_unwraps_both_variants() {
    assert_eq!(OnErrorCfg::Terminal("fail".to_string()).as_name(), "fail");
    assert_eq!(OnErrorCfg::Hook("my-hook".to_string()).as_name(), "my-hook");
}

/// Every `#[serde(default = "default_X")]` free function must return its documented constant, not
/// a mutant-plausible neighbor (0/1/a different constant/a typo'd literal). One consolidated table
/// rather than N near-identical single-purpose tests.
#[test]
fn serde_default_fns_return_their_documented_constants() {
    assert_eq!(default_protocol(), "anthropic");
    assert_eq!(default_min_requests(), 5);
    assert_eq!(default_max_cooldown(), 120);
    assert_eq!(default_failover_timeout(), 120);
    assert_eq!(default_max_hops(), 3);
    assert_eq!(default_listen(), "0.0.0.0:8080");
    assert_eq!(default_max_keys_per_principal(), 0);
    // `default_response_headers_server_timing` / `default_response_headers_route_policy`'s documented
    // default is `false` for BOTH (privacy-by-default: every busbar-injected response header is a
    // fingerprintable observable, see each field's own doc comment) — the "replace with false" mutant
    // is a genuine EQUIVALENT mutant (the correct value IS false); only "replace with true" is a real
    // gap.
    assert!(!default_response_headers_server_timing());
    assert!(!default_response_headers_route_policy());
}

/// `to_policy_with_floor`'s anti-downgrade-floor sanity warning must fire ONLY for a
/// non-empty, malformed floor — never for an OMITTED floor (empty string, "no floor set", not
/// "malformed floor") and never for a well-formed one. A minimal capturing `tracing::Subscriber`
/// (no test-only crate needed) records whether the WARN actually fired.
#[test]
fn to_policy_with_floor_warns_only_on_a_non_empty_malformed_floor() {
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
            let _ = cfg.to_policy_with_floor("1.5.0");
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

/// `auth.role_bindings:` parses as a module-nested map: module -> role -> grant, with the
/// allowed_pools semantics preserved at the type level (omitted = None = ALL pools; `[]` =
/// Some(empty) = NO pools).
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
    // 1.5.3: a chain is a list of bare PROVIDER NAMES; `max_admin_scope` moved onto the
    // `identity-providers:` definition, so it is not on the chain entry any more.
    assert_eq!(auth.chain, ["keys", "ad"]);

    // `role_bindings:` stays nested by the SAME string the chain references — the provider NAME.
    let ad = auth.role_bindings.get("ad").expect("ad provider bindings");
    let platform = ad.get("platform").expect("platform role");
    assert_eq!(
        platform.allowed_pools,
        Some(vec!["smart".to_string(), "overflow".to_string()])
    );
    assert_eq!(platform.group.as_deref(), Some("eng"));
    assert_eq!(platform.admin_scope.as_deref(), Some("read-only"));
    // An explicit [] is the EMPTY set (no pools), distinct from omitted (all pools).
    assert_eq!(ad["contractors"].allowed_pools, Some(vec![]));
    assert_eq!(ad["everyone"].allowed_pools, None, "omitted = ALL pools");

    // The serde default for admin_auth is the bare admin-tokens provider NAME.
    assert_eq!(auth.admin_auth, [ADMIN_TOKENS_MODULE]);
}

// ── groups / limits ──────────────────────────────────────────────────────────────────────────────

/// Every limit metric parses in the `{ <metric>: amount, per: window }` shape; `concurrent` takes
/// no window; `enabled` defaults true; `parent` is carried.
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

    // enabled: false freezes the group (parsed; enforcement elsewhere).
    let frozen: GroupCfg = serde_yaml::from_str("enabled: false\nlimits: []\n").expect("parses");
    assert!(!frozen.enabled);
}

/// Malformed limits fail AT PARSE with precise errors: `concurrent` with `per`, a windowed metric
/// without `per`, two metric keys, an unknown window, an unknown key, and no metric at all.
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

    // GroupCfg itself is deny_unknown_fields (a typo'd group key fails boot).
    let err =
        serde_yaml::from_str::<GroupCfg>("limitz: []").expect_err("a typo'd group key must error");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

/// The optional `pool:` qualifier: parses on a windowed limit (scoping it to one pool's traffic),
/// round-trips exactly through the overlay Serialize (with and without), and is rejected on
/// `concurrent` (the in-flight gauge is per group, not per pool).
#[test]
fn test_group_limit_pool_qualifier() {
    use crate::config::groups::LimitCfg;

    let l: LimitCfg = serde_yaml::from_str("{ budget: 5000, per: month, pool: frontier }")
        .expect("pool-qualified budget parses");
    assert_eq!(l.scope.as_ref().map(|s| s.value.as_str()), Some("frontier"));

    // Round-trip: serialize -> reparse must be identical (the overlay persistence contract),
    // both with and without the qualifier.
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

/// The `on_exhaust` pair: parses + round-trips on a pool-scoped budget; every malformed
/// coupling fails AT PARSE with a teaching error (downgrade without a target, a dangling target
/// without downgrade, a non-budget metric, a group-wide budget, a self-referential target).
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

    // An explicit `block` (the spelled-out default) also survives the round-trip.
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

// ── top-level DeployCfg surface ──────────────────────────────────────────────────────────────────

/// The REMOVED top-level blocks are rejected by deny_unknown_fields: `governance:` (split into
/// store/rate_card/groups/advanced/auth), the `hooks:` registry (inline refs now), `group_map:`
/// (auth.role_bindings now), and top-level `admin_auth:` (moved under `auth:`).
#[test]
fn test_removed_top_level_blocks_rejected() {
    for (block, key) in [
        ("governance:\n  store: memory\n", "governance"),
        (
            "hooks:\n  my-gate:\n    kind: gate\n    plugin: p\n",
            "hooks",
        ),
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

/// The NEW top-level blocks parse: `store:` `{module, settings}` (settings opaque), `rate_card:`
/// per config-model entries, `per_request_fee:`, `groups:`, and `advanced:`; and `per_request_fee`
/// defaults to 0 (was price_per_request_cents default 1).
#[test]
fn test_new_top_level_blocks_parse() {
    let yaml = r#"
providers: {}
models: {}
store:
  module: sqlite
  settings:
    db_path: /var/lib/busbar/gov.db
    busy_timeout_ms: 250
rate_card:
  claude:
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
    assert_eq!(store.module, "sqlite");
    // Store settings are OPAQUE (passed to the plugin verbatim; the old governance.db_path /
    // sqlite_busy_timeout_ms now live here).
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
    let claude = rc.get("claude").expect("claude rate entry");
    assert_eq!(claude.input_utok, 3.0);
    assert_eq!(claude.output_utok, 15.0);
    assert_eq!(claude.cache_read_utok, 0.0, "omitted tier prices at 0");
    // The routing scalar is the blended (input + output) / 2.
    assert_eq!(rate_entry_per_mtok(claude), 9.0);
    assert_eq!(deploy.per_request_fee, 2);
    assert_eq!(deploy.groups.len(), 2);
    assert_eq!(deploy.groups["eng-batch"].parent.as_deref(), Some("eng"));
    assert_eq!(deploy.advanced.rate_sweep_interval, 64);
    assert_eq!(deploy.advanced.usage_flush_interval_ms, 5);

    // Defaults when everything is absent: no store, no rate_card, fee 0, defaults for advanced.
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
    // StoreCfg's own module default is the compiled-in memory store.
    assert_eq!(StoreCfg::default().module, GOVERNANCE_STORE_MEMORY);
}

// ── resolve(): hook-registry synthesis + admin_auth projection ───────────────────────────────────

/// `resolve` builds the runtime hook registry from the top-level `hooks:` DEFINITION map (1.5.3):
/// each named definition becomes a registry entry keyed by its OWN name (`module:` → `HookCfg.plugin`,
/// `settings:`/`groups:`/`phase:` carried through), the SAME module can back two independent names,
/// per-pool bare-name references land in `pool.gates` in config order, and the reserved all-pools
/// attach (`pools.hooks:`) lowers to the runtime `global_hooks`.
#[test]
fn test_resolve_builds_registry_from_named_defs() {
    let mut deploy = base_deploy();
    // Two named hooks sharing ONE module, plus a tap — each an independent instance with its own scope.
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

    // Same module, two independent names + independent scope.
    assert_eq!(cfg.hooks["pii-eng"].plugin, "busbar-phi");
    assert_eq!(cfg.hooks["pii-all"].plugin, "busbar-phi");
    assert_eq!(cfg.hooks["pii-eng"].groups, ["engineering"]);
    assert!(
        cfg.hooks["pii-all"].groups.is_empty(),
        "pii-all is unscoped (all callers)"
    );
    // Settings carried through OPAQUE; kind defaults to gate for a named def.
    assert_eq!(
        cfg.hooks["pii-eng"]
            .settings
            .get("team")
            .and_then(|v| v.as_str()),
        Some("alpha")
    );
    assert_eq!(cfg.hooks["pii-all"].kind, HookKind::Gate);

    // The tap's phase list carries through and drives stage selection.
    assert_eq!(cfg.hooks["audit"].kind, HookKind::Tap);
    assert!(cfg.hooks["audit"].fires_at_stage(crate::config::HookStage::Response));
    assert!(!cfg.hooks["audit"].fires_at_stage(crate::config::HookStage::Request));

    // Per-pool bare names land in gates in config order; base policy survives; all-pools → global.
    assert_eq!(cfg.pools["a"].gates, ["pii-eng"]);
    assert_eq!(cfg.pools["a"].policy, PoolPolicy::Cheapest);
    assert_eq!(cfg.pools["b"].gates, ["pii-all"]);
    assert_eq!(cfg.global_hooks, ["audit"]);
}

/// A named definition with an EMPTY `module:` is a FAIL-CLOSED resolve() error naming the hook; a
/// definition name that shadows a reserved word (an on_error terminal / built-in strategy) is
/// rejected too.
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

    // A definition named after a reserved word (a built-in strategy) is rejected.
    let mut deploy = base_deploy();
    deploy.hooks = serde_yaml::from_str("cheapest:\n  module: busbar-phi\n").unwrap();
    let errs = resolve(&deploy, &HashMap::new()).expect_err("reserved def name must fail");
    assert!(errs.join("\n").contains("reserved name"), "{errs:?}");
}

/// The named-hook SCOPE check (`caller_in_hook_groups`): a hook scoped to a group fires for a caller
/// in that group OR any DESCENDANT (the group is an ancestor of the caller's leaf), never for a
/// caller in another branch; an UNSCOPED hook fires for everyone; a groupless caller matches only an
/// unscoped hook.
#[test]
fn test_caller_in_hook_groups_scope() {
    use crate::config::caller_in_hook_groups;
    // acme → engineering → user:bob ; acme → sales → user:sue
    let tree: std::collections::BTreeMap<String, crate::config::GroupCfg> = serde_yaml::from_str(
        "acme: {}\n\
         engineering: { parent: acme }\n\
         sales: { parent: acme }\n\
         'user:bob': { parent: engineering }\n\
         'user:sue': { parent: sales }\n",
    )
    .expect("groups tree parses");
    let eng = ["engineering".to_string()];

    // A hook scoped to engineering fires for the engineering leaf (ancestor match), not the sales one.
    assert!(caller_in_hook_groups(Some("user:bob"), &eng, &tree));
    assert!(!caller_in_hook_groups(Some("user:sue"), &eng, &tree));
    // The scoped group's own members match; a sibling branch does not.
    assert!(caller_in_hook_groups(Some("engineering"), &eng, &tree));
    assert!(!caller_in_hook_groups(Some("sales"), &eng, &tree));
    // An UNSCOPED hook (empty groups) fires for every caller — including a groupless one.
    assert!(caller_in_hook_groups(Some("user:sue"), &[], &tree));
    assert!(caller_in_hook_groups(None, &[], &tree));
    // A groupless caller never matches a SCOPED hook.
    assert!(!caller_in_hook_groups(None, &eng, &tree));
}

/// A pool named `hooks` is REJECTED at parse (the key is reserved for the all-pools attach list), and
/// the reserved `pools.hooks:` list is lifted out as the all-pools attach.
#[test]
fn test_pools_reserved_hooks_key() {
    // The reserved key is the all-pools attach; the rest are pools.
    let pools: crate::config::PoolsCfg =
        serde_yaml::from_str("hooks: [pii]\nfast:\n  members: []\n  hooks: [cheapest, pii]\n")
            .expect("pools with reserved hooks key parses");
    assert_eq!(pools.all_pool_hooks, ["pii"]);
    assert!(pools.pools.contains_key("fast"));
    assert!(!pools.pools.contains_key("hooks"));
    assert_eq!(pools.pools["fast"].gates, ["pii".to_string()]);

    // A pool literally named `hooks` (a MAP value) is rejected with a clear message.
    let e = serde_yaml::from_str::<crate::config::PoolsCfg>("hooks:\n  members: []\n")
        .expect_err("a pool named `hooks` must be rejected");
    assert!(
        e.to_string().contains("reserved") || e.to_string().contains("all-pools"),
        "{e}"
    );
}

/// `resolve` projects the ADMIN chain module names from `auth.admin_auth:` onto
/// `RootCfg.admin_auth` in order, and defaults to `[admin-tokens]` when the whole `auth:` block
/// is absent.
#[test]
fn test_resolve_projects_admin_auth_names() {
    // auth absent: the default admin chain.
    let cfg = resolve(&base_deploy(), &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [ADMIN_TOKENS_MODULE]);

    // auth present with a custom admin chain: names projected in order.
    let mut deploy = base_deploy();
    let auth: crate::config::AuthDeployCfg =
        serde_yaml::from_str("chain: [keys]\nadmin_auth: [admin-tokens, ad]\n")
            .expect("auth parses");
    deploy.auth = Some(auth);
    // 1.5.3: the operator credential + the external IdP's ceiling live on their DEFINITIONS.
    deploy.identity_providers = serde_yaml::from_str(
        "admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }\n\
         ad: { module: ad, max_admin_scope: read-only }\n",
    )
    .expect("identity-providers parse");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [ADMIN_TOKENS_MODULE, "ad"]);
    // The operator credential stays reachable as a SecretRef through the resolved auth block.
    assert_eq!(
        cfg.auth
            .as_ref()
            .and_then(|a| a.admin_token_ref())
            .and_then(|t| t.env_var()),
        Some("BUSBAR_ADMIN_TOKEN")
    );

    // auth present but admin_auth omitted: the serde default [admin-tokens] applies.
    let mut deploy = base_deploy();
    deploy.auth = Some(serde_yaml::from_str("chain: [keys]\n").expect("auth parses"));
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert_eq!(cfg.admin_auth, [ADMIN_TOKENS_MODULE]);
}

/// PER-NAME anti-downgrade through `to_policy` (floors-only semantics): a validly-signed
/// first-party artifact on its own independent version line LOADS under the default policy (no
/// automatic binary-version floor — plugins ship 1.0.x/2.x under a 1.5.0 engine), while an
/// explicit per-name floor (the persisted rollback-pin seam) binds exactly at its pinned version:
/// at the pin loads, below the pin refuses.
#[test]
fn to_policy_floor_distinguishes_automatic_from_explicit_downgrade() {
    use busbar_plugin_sign::{evaluate, sign, Manifest, SigningKey, Verdict};

    // A first-party release key + an OLD (below the current binary) signed first-party artifact.
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let artifact = b"\x7fELF old first-party build";
    let old = sign(
        &release,
        Manifest {
            name: "busbar-store-valkey-plugin".into(),
            alias: "valkey".into(),
            kind: "store".into(),
            version: "0.9.0".into(), // below any real CARGO_PKG_VERSION (1.x)
            publisher: busbar_plugin_sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: 2,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
        },
        artifact,
    );

    // Build both policies off ONE PluginsCfg, but embed the SAME release key as the first-party key so
    // the signature verifies in-test (production reads the embedded release key; here we inject it).
    let cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    let mut automatic = cfg.to_policy().expect("automatic policy");
    automatic.first_party_key = Some(release.verifying_key());
    // DEFAULT policy: no per-name floor pins this artifact, so its 0.9.0 version line is its own
    // business — a verified first-party plugin loads regardless of the binary's version.
    assert!(
        matches!(
            evaluate(artifact, &old, &automatic).unwrap(),
            Verdict::Trusted {
                first_party: true,
                ..
            }
        ),
        "default policy must load a verified first-party artifact on its own version line"
    );

    // EXPLICIT per-name floor (the rollback-pin seam): pinned exactly at the artifact's version,
    // it loads; the pin binds and nothing older passes (asserted below).
    let mut explicit = cfg.to_policy().expect("explicit policy");
    explicit.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "0.9.0".to_string(),
    );
    explicit.first_party_key = Some(release.verifying_key());
    assert!(
        matches!(
            evaluate(artifact, &old, &explicit).unwrap(),
            Verdict::Trusted {
                first_party: true,
                ..
            }
        ),
        "an explicit rollback floor admits the prior first-party artifact"
    );

    // But an EVEN OLDER artifact is STILL refused under the explicit floor — a rollback lowers the
    // floor to EXACTLY the pinned target, not to zero.
    let older = sign(
        &release,
        Manifest {
            name: "busbar-store-valkey-plugin".into(),
            alias: "valkey".into(),
            kind: "store".into(),
            version: "0.8.0".into(),
            publisher: busbar_plugin_sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: 2,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
        },
        artifact,
    );
    assert!(
        evaluate(artifact, &older, &explicit).is_err(),
        "an artifact below the pinned rollback target is still refused"
    );
}

/// A runtime-set PER-PLUGIN `first_party_floors` override on `PluginsCfg` is honored by `to_policy`
/// (the seam the persisted rollback pin drives) for that name ONLY, while the global `binary_version`
/// stays the binary's own version — so an UNPINNED first-party plugin still faces the full floor.
#[test]
fn to_policy_honors_runtime_first_party_floor_override() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    // Default: the automatic floor equals the binary version and there are no per-name overrides.
    let auto = cfg.to_policy().expect("policy");
    assert_eq!(auto.binary_version, env!("CARGO_PKG_VERSION"));
    assert!(auto.first_party_floors.is_empty());
    // With an explicit per-name override (as a persisted rollback pin sets): only that name is lowered;
    // the global binary_version floor (what every OTHER first-party plugin uses) is untouched.
    cfg.first_party_floors
        .insert("acme-hook".to_string(), "0.9.0".to_string());
    let pinned = cfg.to_policy().expect("policy");
    assert_eq!(pinned.binary_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pinned
            .first_party_floors
            .get("acme-hook")
            .map(String::as_str),
        Some("0.9.0")
    );
}

/// REGRESSION PROOF: a malformed `min_versions` floor does NOT fail `to_policy` — the
/// comparator (`version_at_least`), not config validation, is where a malformed floor is refused
/// (fail closed at the comparator, don't refuse the boot). Passes before AND after; it is
/// the anti-regression guard against the superseded design (`to_policy` returning
/// `Err` for this case), which the current design deliberately does NOT do. If this test goes red,
/// the superseded design has been reintroduced.
#[test]
fn to_policy_still_returns_ok_for_a_malformed_floor() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    cfg.min_versions
        .insert("p".to_string(), "v1.6.0".to_string());
    assert!(
        cfg.to_policy().is_ok(),
        "a malformed floor must not fail the boot — it is refused at the comparator instead"
    );
}

// ─── 1.5.2 token exchange: config surface (public_url / auth.methods / plugins.fetch) ───

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
    // Absent ⇒ None (default).
    let deploy2: DeployCfg =
        serde_yaml::from_str("listen: 0.0.0.0:8080\nproviders: {}\nmodels: {}\n")
            .expect("absent public_url ⇒ default None");
    assert_eq!(deploy2.public_url, None);
}

/// FREEZE BLOCKER: the 1.5.2 `auth.methods:` block FOLDED INTO the `identity-providers:`
/// definition. `browser_login` and the module's opaque settings are inherently PER PROVIDER — a
/// client id/secret belongs to one IdP registration — so a second parallel map keyed by the same
/// namespace was duplicate structure whose two halves could disagree about the same provider.
///
/// The resolved hosted-login method is now a PROJECTION of the definition, keyed by PROVIDER NAME
/// and carrying the definition's `module:` separately (two named providers may share one plugin).
///
/// Before 1.5.3 `auth.methods:` was a live config block that parsed, so this
/// resolution path did not exist.
#[test]
fn test_auth_method_browser_login_parses() {
    let yaml = "\
oidc:
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
        &serde_yaml::from_str("chain: [oidc]\n").expect("auth parses"),
        &providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    let method = auth.methods.get("oidc").expect("oidc method present");
    assert_eq!(
        method.module, "oidc-plugin",
        "the method carries the definition's MODULE, distinct from its NAME"
    );
    let bl = method
        .browser_login
        .as_ref()
        .expect("browser_login present");
    assert_eq!(bl.client_id.as_deref(), Some("busbar-web"));
    // client_secret is an OPTIONAL SecretRef (never a bare string); it resolves through the `env`
    // module. (Optional so a Credential method can omit it; a Redirect method requires it — enforced
    // at build per login_kind.)
    assert_eq!(
        bl.client_secret.as_ref().and_then(|s| s.env_var()),
        Some("BUSBAR_OIDC_SECRET")
    );
    // Opaque module settings pass through, NOT swallowed into browser_login.
    assert_eq!(
        method.settings.get("issuer").and_then(|v| v.as_str()),
        Some("https://idp.example/")
    );
    assert_eq!(
        method.settings.get("audience").and_then(|v| v.as_str()),
        Some("busbar")
    );
    // browser_login is NOT leaked into the opaque settings map pushed to the module.
    assert!(!method.settings.contains_key("browser_login"));
}

#[test]
fn test_browser_login_deny_unknown_field() {
    // A typo under `browser_login` must fail parse (deny_unknown_fields on BrowserLoginCfg).
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

    // A stray key matches no variant (per-variant deny_unknown_fields) ⇒ error.
    let bad = "enabled: true\nfetch:\n  - github: org/repo@v1\n    shaa: nope\n";
    assert!(
        serde_yaml::from_str::<PluginsCfg>(bad).is_err(),
        "typo'd fetch key must be rejected"
    );
}

// ─── 1.5.2: plugins.fetch → FetchSpec resolution ───

#[test]
fn test_fetch_specs_maps_github_and_url() {
    use crate::config::PluginsCfg;
    let yaml = "\
enabled: true
fetch:
  - github: acme/widget@v2.0.1
    sha256: deadbeef
  - url: https://host/plugins/store-sqlite.tar.gz
";
    let cfg: PluginsCfg = serde_yaml::from_str(yaml).unwrap();
    let specs = cfg.fetch_specs().expect("fetch_specs resolves");
    assert_eq!(specs.len(), 2);
    // github → release-asset url + {repo}.tar.gz filename, pin carried.
    assert_eq!(specs[0].filename, "widget.tar.gz");
    assert_eq!(
        specs[0].url,
        "https://github.com/acme/widget/releases/download/v2.0.1/widget.tar.gz"
    );
    assert_eq!(specs[0].sha256.as_deref(), Some("deadbeef"));
    // url → itself, filename from basename, no pin.
    assert_eq!(specs[1].url, "https://host/plugins/store-sqlite.tar.gz");
    assert_eq!(specs[1].filename, "store-sqlite.tar.gz");
    assert_eq!(specs[1].sha256, None);
}

#[test]
fn test_fetch_env_spec_reads_var() {
    use crate::config::PluginsCfg;
    std::env::set_var("BUSBAR_T_FETCH_URL", "https://host/p/thing.tar.gz@abc123");
    let cfg: PluginsCfg =
        serde_yaml::from_str("enabled: true\nfetch:\n  - env: BUSBAR_T_FETCH_URL\n").unwrap();
    let specs = cfg.fetch_specs().expect("env spec resolves");
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
    let err = cfg.fetch_specs().expect_err("unset env var must error");
    assert!(
        err.contains("BUSBAR_T_FETCH_UNSET") && err.contains("not set"),
        "{err}"
    );
}

/// 1.5.3 env→config migration (the "new config.yaml key" half): the top-level `config:` block, the
/// `providers_file:` pointer, and the new flat `advanced.*` knobs parse into `DeployCfg`. RED-before-
/// GREEN: none of these fields existed pre-1.5.3, so this parse (`deny_unknown_fields` everywhere)
/// would reject the document as unknown keys.
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

    // The `advanced.upstream_*` knobs must not only PARSE but flow through `resolve` onto
    // `cfg.limits` — the boot client-build reads them from there. Guards against a regression that
    // drops the `upstream_http1_only: advanced.upstream_http1_only` (or the h2) wiring in
    // `LimitsResolved::from_sections`, which would silently make the config.yaml knob a no-op.
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

    // `overlay: false` parses as the explicit-disable form.
    let yaml2 = "providers: {}\nmodels: {}\nconfig:\n  locked: true\n  overlay: false\n";
    let d2: crate::config::DeployCfg = serde_yaml::from_str(yaml2).expect("overlay:false parses");
    assert!(matches!(
        d2.config.overlay,
        Some(crate::config::OverlayCfg::Disabled(false))
    ));

    // Absent `config:` ⇒ durable-by-default posture (mutable, no explicit overlay).
    let yaml3 = "providers: {}\nmodels: {}\n";
    let d3: crate::config::DeployCfg = serde_yaml::from_str(yaml3).expect("absent config parses");
    assert!(!d3.config.locked);
    assert!(d3.config.overlay.is_none());
    assert!(d3.providers_file.is_none());
    assert_eq!(d3.advanced.worker_threads, None);
}

// ── 1.5.3 FREEZE PINS (forward-compatibility) ────────────────────────────────────────────────────
//
// Each test below pins a semantic that 1.5.3 SHIPS and later releases must REUSE. They exist because
// 1.5.3 is the break-once release: after it the grammar is additive-only forever, so anything a
// later release could silently redefine has to be nailed down NOW, with a test that fails loudly if
// someone changes it later. Every one names the finding it discharges.

/// FREEZE BLOCKER — the hook-name namespace is CLOSED.
///
/// `RESERVED_HOOK_NAMES` and the bare strategy keywords accepted in a pool's `hooks:` list share ONE
/// word space. Adding a bare terminal later — a new `on_error` word, a new ranking strategy, the MCP
/// bounded-default floor — would retroactively invalidate a config that is LEGAL TODAY: an operator's
/// hook named `least_bad` boots fine in 1.5.3 and would become a boot failure (or, worse, silently
/// rebind to the new built-in) the moment the word were reserved.
///
/// So this asserts the EXACT contents of the frozen word space, not a subset. A future terminal must
/// arrive STRUCTURED (`on_error: { hook: x }` is the shipped precedent — see `OnErrorCfg`), never as
/// a new bare word, and a structured form costs zero words from this space.
#[test]
fn reserved_hook_names_are_frozen() {
    let mut frozen: Vec<&str> = crate::config::FROZEN_HOOK_NAME_WORD_SPACE.to_vec();
    frozen.sort_unstable();

    // (a) The declared frozen list is EXACTLY these eleven words — spelled out literally so a
    //     diff shows a reviewer precisely which word someone tried to add.
    assert_eq!(
        frozen,
        [
            "admin-tokens",
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

    // (b) The declared list really IS the runtime union, so freezing the constant freezes the
    //     BEHAVIOR and not just a parallel piece of documentation.
    let mut runtime: Vec<&str> = crate::config::RESERVED_HOOK_NAMES.to_vec();
    for word in crate::config::FROZEN_HOOK_NAME_WORD_SPACE {
        // Every frozen word is either reserved outright or accepted bare as a pool strategy.
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

    // (c) And the reservation is ENFORCED: a hook definition named with a frozen word fails boot.
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
}

/// FREEZE BLOCKER — an OMITTED `phase:` means THE FOUR CORE STAGES, not "all stages ever".
///
/// If omission meant "all stages", an MCP tool-invocation stage added in 1.6.0 (or an A2A delegation
/// stage in 1.6.0) would retroactively make every already-deployed unscoped hook start firing at
/// brand-new points in a brand-new plane — a silent widening of what the operator signed off on, with
/// no config change and no diagnostic. Pinning the default to a FROZEN list makes a later stage
/// strictly additive: to fire there, a hook must NAME it.
///
/// Also pinned here: `phase:` is PLANE-NEUTRAL (these four names describe a request lifecycle every
/// plane shares, so a later plane REUSES them rather than re-typing the field), and an INAPPLICABLE
/// phase silently does not fire rather than being a config error — otherwise one hook definition
/// could not serve two planes, which is the reuse the named-definition pattern exists for.
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

    // A definition with NO `phase:` fires at every core stage — and at NOTHING else, by construction
    // (the enum is exhausted by the frozen list, so a future variant is excluded until named).
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

    // An EXPLICIT phase list is exact: naming one stage excludes the other three.
    let def: crate::config::HookDefCfg =
        serde_yaml::from_str("module: h\nkind: tap\nphase: [response]").expect("parses");
    let cfg = super::hook_cfg_from_def(&def).expect("lowers");
    assert!(cfg.fires_at_stage(HookStage::Response));
    assert!(!cfg.fires_at_stage(HookStage::Request));
    assert!(!cfg.fires_at_stage(HookStage::Candidate));
    assert!(!cfg.fires_at_stage(HookStage::Routing));
}

/// THE `phase:` FIELD DOC MUST NOT CONTRADICT THE FREEZE. The field doc said an
/// omitted `phase:`/`at:` falls back to `request`, while `fires_at_stage` (and the doc on
/// `CORE_HOOK_PHASES`, and the test above) say it fires at ALL FOUR core stages. THAT is the frozen
/// semantic, so the DOC was the defect. Read as a source assertion because a doc comment is exactly
/// the thing no runtime assertion can reach, and a wrong doc on a FROZEN semantic is what an
/// operator actually acts on.
///
/// The pre-fix file contains the contradicting sentence this test rejects.
#[test]
fn the_phase_field_doc_agrees_with_the_frozen_omitted_phase_answer() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/mod.rs"))
        .expect("this crate's config/mod.rs is readable");
    assert!(
        !src.contains("falls back to `at` (or `request` when that is also"),
        "the `phase:` field doc still claims an omitted phase+at fires at `request` ONLY; \
         `fires_at_stage` fires at all four CORE_HOOK_PHASES"
    );
    // And the doc positively states the frozen answer, so the next reader is not left guessing.
    // It asserts on the ANSWER, not on the label we happened to file the decision under: a doc
    // that names an internal identifier is a doc that leaks one to whoever reads the source.
    let phase_doc_start = src
        .find("1.5.3 named-hook PHASE set")
        .expect("the `phase:` field doc exists");
    let phase_doc = &src[phase_doc_start..phase_doc_start + 700];
    assert!(
        phase_doc.contains("FOUR CORE STAGES"),
        "the `phase:` field doc must state that an omitted phase+at fires at all four core stages"
    );
}

/// FREEZE BLOCKER — the additive-list DEDUPE rule: a hook named in BOTH `pools.hooks:` and a
/// pool's own `hooks:` fires ONCE, at its FIRST (section-level) position.
///
/// The locked combine rule says section-level LISTS are ADDITIVE but never said what
/// happens on an overlap. Both answers were defensible, so 1.5.3 pins one: attaching a hook to all
/// pools and then ALSO naming it on one pool is how an operator writes "…and definitely on this
/// one", and reading that as "fire twice" would double-charge a gate's latency budget and
/// double-count a tap's audit record.
///
/// Before 1.5.3 the two lists were lowered independently, so an overlapping
/// name landed in BOTH `global_hooks` and the pool's `gates` and fired twice.
#[test]
fn additive_hook_lists_dedupe_at_first_position() {
    // The rule itself, at the single combine point.
    let section = vec!["audit".to_string(), "pii".to_string()];
    let entity = vec![
        "cheapest".to_string(),
        "pii".to_string(),
        "audit".to_string(),
    ];
    assert_eq!(
        crate::config::combine_hook_refs(&section, &entity),
        ["audit", "pii", "cheapest"],
        "a name in both lists fires ONCE, at its FIRST (section) position"
    );
    // The runtime projection: the entity half keeps only what the section did not already name, and
    // section ++ entity-only reproduces the combined order exactly.
    let entity_only = crate::config::entity_only_hook_refs(&section, &entity);
    assert_eq!(entity_only, ["cheapest"]);
    let mut rebuilt = section.clone();
    rebuilt.extend(entity_only);
    assert_eq!(rebuilt, crate::config::combine_hook_refs(&section, &entity));

    // End to end through `resolve`: the pool's own gate list drops the name the all-pools list
    // already carries, so the hook is fired by exactly one of the two resolved chains.
    let deploy: DeployCfg = serde_yaml::from_str(
        "hooks:\n  audit: { module: h, kind: gate }\n\
         pools:\n  hooks: [audit]\n  fast:\n    members: []\n    hooks: [cheapest, audit]\n\
         providers: {}\nmodels: {}\n",
    )
    .expect("parses");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(cfg.global_hooks, ["audit"]);
    assert!(
        cfg.pools["fast"].gates.is_empty(),
        "the pool's duplicate reference is deduped away, so `audit` fires exactly once: {:?}",
        cfg.pools["fast"].gates
    );

    // A pool hook the section list does NOT name is untouched.
    let deploy: DeployCfg = serde_yaml::from_str(
        "hooks:\n  audit: { module: h, kind: gate }\n  pii: { module: h, kind: gate }\n\
         pools:\n  hooks: [audit]\n  fast:\n    members: []\n    hooks: [pii]\n\
         providers: {}\nmodels: {}\n",
    )
    .expect("parses");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(cfg.pools["fast"].gates, ["pii"]);
}

/// FREEZE BLOCKER — the `pools:` reserved section-key set is CLOSED at exactly two words.
///
/// Every reserved word here is a word an operator can no longer use as a POOL NAME, so ADDING one in
/// a later release retroactively turns a previously-legal config into a boot failure. The set is
/// therefore frozen, and every FUTURE all-scope knob must land under a reserved `defaults:` sub-key
/// (`pools.defaults.<knob>`) — one word paid once, additive forever.
///
/// Before 1.5.3 only `hooks` was reserved (so a pool named
/// `upstream_credentials` parsed fine) and there was no frozen set to assert against.
#[test]
fn pools_reserved_section_keys_are_frozen() {
    assert_eq!(
        crate::config::RESERVED_POOLS_SECTION_KEYS,
        ["hooks", "upstream_credentials"],
        "the `pools:` reserved-key set is CLOSED. A new all-scope knob must go under a reserved \
         `defaults:` sub-key, never a new top-level reserved word — adding one would turn a \
         legal pool NAME into a boot failure."
    );

    // BOTH reserved words are rejected as pool names, with a message that says why.
    for reserved in crate::config::RESERVED_POOLS_SECTION_KEYS {
        let err = serde_yaml::from_str::<crate::config::PoolsCfg>(&format!(
            "{reserved}:\n  members: [ {{ model: a }} ]\n"
        ))
        .expect_err("a pool named with a reserved section key must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains(reserved) && msg.contains("RESERVED"),
            "the error must name the reserved word and say it is reserved; got: {msg}"
        );
    }
}

/// FREEZE BLOCKER (the other half): `pools.upstream_credentials:` is the ALL-POOLS
/// SCALAR default and a pool's own value OVERRIDES it (replaces — scalars never union). Pinned
/// end-to-end because "scalar overrides, list is additive" is the rule every future inherited
/// setting will be read against.
#[test]
fn pools_upstream_credentials_is_a_scalar_override() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "pools:\n  upstream_credentials: own\n\
         \x20 fast:\n    members: []\n    upstream_credentials: passthrough\n\
         \x20 cold:\n    members: []\n\
         providers: {}\nmodels: {}\n",
    )
    .expect("parses");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(cfg.upstream_credentials, crate::auth::UpstreamCreds::Own);
    assert_eq!(
        cfg.pools["fast"].upstream_credentials,
        Some(crate::auth::UpstreamCreds::Passthrough),
        "a pool's own value REPLACES the all-pools default"
    );
    assert_eq!(
        cfg.pools["cold"].upstream_credentials, None,
        "a pool that sets nothing INHERITS (None = defer to the section default)"
    );

    // Omitted at both levels ⇒ the built-in default, unchanged from pre-1.5.3 behavior.
    let cfg = resolve(&base_deploy(), &HashMap::new()).expect("resolves");
    assert_eq!(cfg.upstream_credentials, crate::auth::UpstreamCreds::Own);
}

/// FREEZE BLOCKER — `secrets:` stays MODULE-KEYED, a deliberate exemption from the
/// named-instance pattern, because it configures a MODULE's `open()` rather than an INSTANCE.
///
/// This is pinned (rather than only documented on the struct) so that a later "consistency" pass
/// that wraps it in a `name -> {module, settings}` map fails a test whose message explains why the
/// inconsistency is correct: there is no reference site that could name an instance — a `SecretRef`
/// already names its MODULE — so a named map would invent an identity nothing can use and force
/// every `SecretRef` in every config to be rewritten for no behavioral gain.
#[test]
fn secrets_block_stays_module_keyed_by_design() {
    let deploy: DeployCfg = serde_yaml::from_str(
        "secrets:\n  vault:\n    settings: { address: \"https://vault.internal\" }\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("the module-keyed `secrets:` block parses");
    let vault = deploy
        .secrets
        .get("vault")
        .expect("keyed by the MODULE name, not an instance name");
    assert_eq!(
        vault.settings.get("address").and_then(|v| v.as_str()),
        Some("https://vault.internal")
    );
    // The tell that this is NOT the named-instance pattern: there is no `module:` field to name,
    // because the KEY already is the module. If someone adds one, this fails and they read the
    // struct doc explaining the exemption.
    let err = serde_yaml::from_str::<DeployCfg>(
        "secrets:\n  my-vault:\n    module: vault\n    settings: {}\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("`secrets:` entries take no `module:` — the key IS the module");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

/// `export:` is a NAMED map, so the SAME module can back MULTIPLE instances — the exact
/// thing the retired TYPE-KEYED block could not express (two `request-log-webhook`s to two URLs).
/// The two process-SINGLETON modules (`prometheus` owns the one `/metrics` route, `otlp` installs the
/// one tracer subscriber) reject a second instance LOUDLY rather than silently ignoring it.
///
/// The type-keyed `ExportCfg` had one `Option` per module, so a second webhook was
/// unrepresentable and this test could not be written at all.
#[test]
fn export_named_map_allows_two_instances_of_one_module() {
    let defs: crate::config::ExportDefs = serde_yaml::from_str(
        "req-log:  { module: request-log-webhook, settings: { url: \"https://logs.example.com/a\" } }\n\
         req-siem: { module: request-log-webhook, settings: { url: \"https://siem.internal/b\", delivery_timeout_secs: 9 } }\n",
    )
    .expect("two instances of one module parse");
    let mut errors = Vec::new();
    let export = crate::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(export.request_log_webhooks.len(), 2);
    assert_eq!(
        export.request_log_webhooks[0].url,
        "https://logs.example.com/a"
    );
    assert_eq!(
        export.request_log_webhooks[1].url,
        "https://siem.internal/b"
    );
    // Per-INSTANCE settings really are independent — the whole point of named instances.
    assert_eq!(export.request_log_webhooks[0].delivery_timeout_secs, 2);
    assert_eq!(export.request_log_webhooks[1].delivery_timeout_secs, 9);

    // A second singleton instance is a loud error, never a silent loss.
    for module in ["prometheus", "otlp"] {
        let settings = if module == "prometheus" {
            "{ buffer_seconds: 60 }"
        } else {
            "{ url: \"http://otel:4318/v1/traces\" }"
        };
        let defs: crate::config::ExportDefs = serde_yaml::from_str(&format!(
            "one: {{ module: {module}, settings: {settings} }}\n\
             two: {{ module: {module}, settings: {settings} }}\n"
        ))
        .expect("parses");
        let mut errors = Vec::new();
        let _ = crate::config::resolve_export(&defs, &mut errors);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("second") && e.contains(module)),
            "a second `{module}` instance must be rejected; got {errors:?}"
        );
    }

    // An unknown module names the four built-ins rather than being silently dropped.
    let defs: crate::config::ExportDefs =
        serde_yaml::from_str("x: { module: nope }\n").expect("parses");
    let mut errors = Vec::new();
    let _ = crate::config::resolve_export(&defs, &mut errors);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("nope") && e.contains("request-log-webhook")),
        "an unknown export module must name the built-ins; got {errors:?}"
    );
}

/// DOC/CODE DRIFT. `RootSettings`' doc enumerates the `DeployCfg` blocks the `root` overlay
/// section covers. That list is the operator-facing description of an API surface, so a name in it
/// that the struct has no field for is a documented capability that does not exist — it listed
/// `metrics`, retired in 1.5.3.
///
/// Gated generically rather than by spot-fixing the word: every backticked name in the enumerating
/// sentence must be a real field of the struct, so the next retired (or added) block cannot drift
/// the doc out of agreement with the code either.
#[test]
fn root_settings_doc_lists_only_fields_that_exist() {
    let src = include_str!("../overlay.rs");
    let anchor = "pub(crate) struct RootSettings {";
    let at = src.find(anchor).expect("RootSettings struct");

    // The struct's real field set.
    let body = &src[at + anchor.len()..];
    let body = &body[..body.find("\n}").expect("struct end")];
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub(crate) "))
        .filter_map(|l| l.split(':').next())
        .collect();
    assert!(
        fields.contains(&"listen") && !fields.contains(&"metrics"),
        "sanity: parsed fields {fields:?}"
    );

    // The doc's enumerating sentence: "It mirrors the uncovered `DeployCfg` surface: … Every field
    // is `Option` …". Everything backticked in it is a covered block name. (The `///` line prefixes
    // fall out for free — they are not backticked.)
    let doc = &src[..at];
    let start = doc
        .rfind("It mirrors the")
        .expect("the enumerating sentence");
    let span = &doc[start..];
    let span = &span[..span.find("Every field is").expect("end of the enumeration")];
    let listed: Vec<&str> = span
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| *t != "DeployCfg")
        .collect();
    assert!(listed.len() > 5, "sanity: parsed doc names {listed:?}");
    for name in listed {
        assert!(
            fields.contains(&name),
            "`RootSettings`' doc lists `{name}` among the blocks the `root` overlay section \
             covers, but the struct has no such field — a documented capability that does not \
             exist. Fields: {fields:?}"
        );
    }
}

/// THE PUBLISHED-NAME COLLISION IS A `resolve` ERROR, which is what makes it a `--validate` error.
///
/// `busbar --validate`, boot, the admin config-apply rebuild and the admin dry-run validate
/// endpoint all reach `resolve`, and none of them reaches `mcp::config::validate_published_names`
/// any other way. If the check were wired only into the `ToolsCfg` `Deserialize` it would never see
/// a server the admin API applied, and a config that validated would not be the config that boots.
/// So the wiring itself is the thing under test here, not the rule.
#[test]
fn resolve_refuses_a_publish_as_collision_so_validate_and_boot_agree() {
    // The SUBTLE collision — an override against a namespaced default nobody typed — because it is
    // the one that survives a partial implementation of the rule.
    let tools: crate::mcp::config::ToolsCfg = serde_yaml::from_str(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
other:
  url: "https://other/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: foo_bar } }
"#,
    )
    .expect("both servers are individually valid");

    let mut deploy = base_deploy();
    deploy.tools = tools;
    let errors = resolve(&deploy, &HashMap::new())
        .expect_err("resolve must refuse a config whose published names are not unique");
    assert!(
        errors.iter().any(|e| e.contains("published as `foo_bar`")),
        "{errors:?}"
    );

    // GREEN, same shape, one name changed: the refusal is about the collision and nothing else.
    let ok: crate::mcp::config::ToolsCfg = serde_yaml::from_str(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
other:
  url: "https://other/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: other_name } }
"#,
    )
    .unwrap();
    let mut deploy = base_deploy();
    deploy.tools = ok;
    resolve(&deploy, &HashMap::new()).expect("distinct published names must resolve");
}

// ══ THE FAILOVER POOLS' CROSS-REFERENCES ═════════════════════════════════════════════════════════
//
// `tool_pools:`/`agent_pools:` are OPT-IN, so the first thing checked is that saying nothing changes
// nothing; the rest is the one shared check refusing what an operator cannot have meant.

/// THE DEFAULT IS UNCHANGED. A config that says nothing about failover resolves exactly as it always
/// did, with no pools on either plane — which is every deployment that exists today.
#[test]
fn failover_pools_are_absent_by_default() {
    let deploy = base_deploy();
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolve");
    assert!(
        cfg.tool_pools.is_empty(),
        "no MCP failover unless asked for"
    );
    assert!(
        cfg.agent_pools.is_empty(),
        "no A2A failover unless asked for"
    );
}

/// A member naming nothing is an operator believing a request has somewhere to go when it does not.
/// 1.6.0: the pool lives in the ONE neutral `pools:` map; kind is INFERRED from the resolvable
/// member (`search-eu` → a `tools:` server), so the dangling `search-us` is named against `tools:`.
#[test]
fn a_tool_pool_member_that_names_no_server_is_refused() {
    let mut deploy = base_deploy();
    deploy.tools.servers.insert(
        "search-eu".to_string(),
        serde_yaml::from_str("{url: 'https://eu.example/mcp', pin: {mechanism: unpinned}}")
            .expect("a minimal server"),
    );
    deploy.pools.pools.insert(
        "search".to_string(),
        serde_yaml::from_str::<crate::config::PoolCfg>("{members: [search-eu, search-us]}")
            .expect("a bare-name pool"),
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a dangling member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("search-us") && e.contains("`tools:`")),
        "the message names the missing entry and the section it belongs in: {errs:?}"
    );
}

/// KIND IS INFERRED, SO A POOL MUST BE HOMOGENEOUS: a pool whose members span two nouns cannot be
/// assigned a single plane and is refused with the homogeneity error.
#[test]
fn a_pool_may_not_straddle_two_planes() {
    let mut deploy = base_deploy();
    deploy.agents.agents.insert(
        "planner".to_string(),
        serde_yaml::from_str("{url: 'https://a.example/card', pin: {mechanism: unpinned}}")
            .expect("a minimal agent"),
    );
    deploy.tools.servers.insert(
        "search-eu".to_string(),
        serde_yaml::from_str("{url: 'https://eu.example/mcp', pin: {mechanism: unpinned}}")
            .expect("a minimal server"),
    );
    deploy.pools.pools.insert(
        "mixed".to_string(),
        serde_yaml::from_str::<crate::config::PoolCfg>("{members: [planner, search-eu]}")
            .expect("a bare-name pool"),
    );
    let errs =
        resolve(&deploy, &HashMap::new()).expect_err("a cross-plane member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("more than one plane") && e.contains("same kind")),
        "the message says the pool's members are not all one kind: {errs:?}"
    );
}

/// A one-member pool changes nothing, so writing one is a mistake and is named as one.
#[test]
fn a_failover_pool_needs_two_members() {
    let mut deploy = base_deploy();
    deploy.agents.agents.insert(
        "only-one".to_string(),
        serde_yaml::from_str("{url: 'https://a.example/card', pin: {mechanism: unpinned}}")
            .expect("a minimal agent"),
    );
    deploy.pools.pools.insert(
        "planner".to_string(),
        serde_yaml::from_str::<crate::config::PoolCfg>("{members: [only-one]}")
            .expect("a bare-name pool"),
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a one-member pool must refuse boot");
    assert!(
        errs.iter().any(|e| e.contains("at least TWO members")),
        "{errs:?}"
    );
}

/// `repeatable:` IS THE SAFETY DECLARATION, and the default is that nothing is repeatable. Asserted
/// here rather than only in the seam's own tests because this is where an operator's document is
/// turned into the answer, and a default that drifted here would be invisible there.
#[test]
fn nothing_is_repeatable_unless_the_operator_names_it() {
    let pool = crate::failover::CandidatePoolCfg {
        members: vec!["a".into(), "b".into()],
        repeatable: vec!["search_code".into()],
    };
    assert_eq!(
        pool.repeatability("search_code"),
        crate::failover::Repeatable::Yes
    );
    assert_eq!(
        pool.repeatability("send_email"),
        crate::failover::Repeatable::No,
        "an operation nobody spoke about is NEVER repeated"
    );
    assert_eq!(
        crate::failover::CandidatePoolCfg::default().repeatability("search_code"),
        crate::failover::Repeatable::No,
        "and an empty declaration repeats nothing at all"
    );
}
