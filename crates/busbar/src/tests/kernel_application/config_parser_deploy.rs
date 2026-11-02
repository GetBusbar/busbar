// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::*;
use std::collections::HashMap;

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
fn admin_require_mtls_defaults_on_and_the_retired_key_loud_fails() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
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
    let hint = busbar_kernel::config::augment_config_error(err);
    assert!(
        hint.contains("admin_insecure")
            && hint.contains("admin_require_mtls")
            && hint.contains("--migrate-config"),
        "the retired-key error must name the new key + the migrator; got: {hint}"
    );
}

#[test]
fn test_identity_provider_definition_is_referenced_by_name_from_both_planes() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let op = busbar_kernel::config::operator_provider();
    let deploy: DeployCfg = serde_yaml::from_str(&format!(
        "identity-providers:\n  \
           corp-ad: {{ module: ad, max_admin_scope: full, settings: {{ server: \"ldaps://corp\" }} }}\n  \
           {op}: {{ module: {op}, token: {{ env: BUSBAR_T_AD_TOKEN }} }}\n\
         auth:\n  chain: [keys, corp-ad]\n  admin_auth: [{op}, corp-ad]\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("the 1.5.3 identity-providers grammar parses");

    let mut errors = Vec::new();
    let auth = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    assert_eq!(auth.chain[0], AuthChainEntry::bare(KEYS_MODULE));

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

    assert_eq!(
        auth.admin_auth[0].token.as_ref().and_then(|t| t.env_var()),
        Some("BUSBAR_T_AD_TOKEN")
    );
}

#[test]
fn test_max_admin_scope_default_is_most_restrictive_except_the_operator_credential() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let op = busbar_kernel::config::operator_provider();
    let deploy: DeployCfg = serde_yaml::from_str(&format!(
        "identity-providers:\n  corp-ad: {{ module: ad }}\n  {op}: {{ module: {op} }}\n\
         auth:\n  chain: [corp-ad]\n  admin_auth: [{op}, corp-ad]\n\
         providers: {{}}\nmodels: {{}}\npools: {{}}\n",
    ))
    .expect("parses");
    let mut errors = Vec::new();
    let auth = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        auth.chain[0].max_admin_scope.as_deref(),
        Some(busbar_kernel::config::DEFAULT_MAX_ADMIN_SCOPE),
        "an external IdP with no declared ceiling gets the MOST RESTRICTIVE default"
    );
    assert_eq!(
        auth.admin_auth[0].max_admin_scope, None,
        "the operator credential is EXEMPT (full by definition)"
    );
}

#[test]
fn test_dangling_identity_provider_reference_is_an_error() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let deploy: DeployCfg = serde_yaml::from_str(
        "auth: { chain: [keys, ghost] }\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let _ = busbar_kernel::config::resolve_auth(
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

#[test]
fn test_token_on_a_non_operator_provider_is_an_error() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let deploy: DeployCfg = serde_yaml::from_str(
        "identity-providers:\n  corp-ad: { module: ad, token: { env: X } }\n\
         auth: { chain: [corp-ad] }\nproviders: {}\nmodels: {}\npools: {}\n",
    )
    .expect("parses");
    let mut errors = Vec::new();
    let _ = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("token") && e.contains("corp-ad")),
        "a token on a non-operator provider must be rejected; got {errors:?}"
    );
}

#[test]
fn test_pools_reserved_hooks_key() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();

    let pools: busbar_kernel::config::PoolsCfg =
        serde_yaml::from_str("hooks: [pii]\nfast:\n  members: []\n  hooks: [cheapest, pii]\n")
            .expect("pools with reserved hooks key parses");
    assert_eq!(pools.all_pool_hooks, ["pii"]);
    assert!(pools.pools.contains_key("fast"));
    assert!(!pools.pools.contains_key("hooks"));
    assert_eq!(pools.pools["fast"].gates, ["pii".to_string()]);

    let e = serde_yaml::from_str::<busbar_kernel::config::PoolsCfg>("hooks:\n  members: []\n")
        .expect_err("a pool named `hooks` must be rejected");
    assert!(
        e.to_string().contains("reserved") || e.to_string().contains("all-pools"),
        "{e}"
    );
}

#[test]
fn test_pools_reserved_name_refusal_is_byte_identical_to_1_5_5() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let e = serde_yaml::from_str::<busbar_kernel::config::PoolsCfg>("hooks:\n  members: []\n")
        .expect_err("a pool named `hooks` must be rejected");
    assert_eq!(
        e.to_string(),
        "a pool may not be named `hooks`: that key is RESERVED at the `pools:` section level \
         (the all-pools `hooks:` attach list and `upstream_credentials:` default). Rename the pool."
    );
}

#[test]
fn test_pools_credential_mode_refusal_is_byte_identical_to_1_5_5() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let e =
        serde_yaml::from_str::<busbar_kernel::config::PoolsCfg>("upstream_credentials: borrowed\n")
            .expect_err("an unknown all-pools credential mode must be rejected");
    assert_eq!(
        e.to_string(),
        "the reserved `pools.upstream_credentials:` all-pools default must be `own` or \
         `passthrough`: unknown variant `borrowed`, expected `own` or `passthrough`"
    );
}

#[test]
fn additive_hook_lists_dedupe_at_first_position() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();

    let section = vec!["audit".to_string(), "pii".to_string()];
    let entity = vec![
        "cheapest".to_string(),
        "pii".to_string(),
        "audit".to_string(),
    ];
    assert_eq!(
        busbar_kernel::config::combine_hook_refs(&section, &entity),
        ["audit", "pii", "cheapest"],
        "a name in both lists fires ONCE, at its FIRST (section) position"
    );

    let entity_only = busbar_kernel::config::entity_only_hook_refs(&section, &entity);
    assert_eq!(entity_only, ["cheapest"]);
    let mut rebuilt = section.clone();
    rebuilt.extend(entity_only);
    assert_eq!(
        rebuilt,
        busbar_kernel::config::combine_hook_refs(&section, &entity)
    );

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

    let deploy: DeployCfg = serde_yaml::from_str(
        "hooks:\n  audit: { module: h, kind: gate }\n  pii: { module: h, kind: gate }\n\
         pools:\n  hooks: [audit]\n  fast:\n    members: []\n    hooks: [pii]\n\
         providers: {}\nmodels: {}\n",
    )
    .expect("parses");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(cfg.pools["fast"].gates, ["pii"]);
}

#[test]
fn pools_reserved_section_keys_are_frozen() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    assert_eq!(
        busbar_contract::section::RESERVED_SECTION_KEYS,
        ["hooks", "upstream_credentials"],
        "the `pools:` reserved-key set is CLOSED. A new all-scope knob must go under a reserved \
         `defaults:` sub-key, never a new top-level reserved word — adding one would turn a \
         legal pool NAME into a boot failure."
    );

    for reserved in busbar_contract::section::RESERVED_SECTION_KEYS {
        let err = serde_yaml::from_str::<busbar_kernel::config::PoolsCfg>(&format!(
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

#[test]
fn pools_upstream_credentials_is_a_scalar_override() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let deploy: DeployCfg = serde_yaml::from_str(
        "pools:\n  upstream_credentials: own\n\
         \x20 fast:\n    members: []\n    upstream_credentials: passthrough\n\
         \x20 cold:\n    members: []\n\
         providers: {}\nmodels: {}\n",
    )
    .expect("parses");
    let cfg = resolve(&deploy, &HashMap::new()).expect("resolves");
    assert_eq!(
        cfg.upstream_credentials,
        busbar_kernel::auth::UpstreamCreds::Own
    );
    assert_eq!(
        cfg.pools["fast"].upstream_credentials,
        Some(busbar_kernel::auth::UpstreamCreds::Passthrough),
        "a pool's own value REPLACES the all-pools default"
    );
    assert_eq!(
        cfg.pools["cold"].upstream_credentials, None,
        "a pool that sets nothing INHERITS (None = defer to the section default)"
    );

    let cfg = resolve(&base_deploy(), &HashMap::new()).expect("resolves");
    assert_eq!(
        cfg.upstream_credentials,
        busbar_kernel::auth::UpstreamCreds::Own
    );
}

#[test]
fn secrets_block_stays_module_keyed_by_design() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
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

    let err = serde_yaml::from_str::<DeployCfg>(
        "secrets:\n  my-vault:\n    module: vault\n    settings: {}\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect_err("`secrets:` entries take no `module:` — the key IS the module");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[test]
fn test_auth_policy_block_parses_and_resolves() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    use busbar_kernel::config::BindingMode;

    let deploy: DeployCfg = busbar_kernel::config::deploy_from_yaml_str(
        "auth:\n  \
           chain: [keys]\n  \
           policy:\n    \
             self_mint: true\n    \
             binding_modes: [time-bound, user-bound, both]\n    \
             default_ttl: \"24h\"\n    \
             max_ttl: \"90d\"\n    \
             mint_ceilings:\n      \
               app-admin:\n        \
                 max_ttl: \"7d\"\n        \
                 allowed_pools: [growth, ops]\n        \
                 binding_modes: [time-bound]\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("the 1.6.0 auth.policy grammar parses");

    let mut errors = Vec::new();
    let auth = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    let p = &auth.policy;
    assert_eq!(p.self_mint, Some(true));
    assert_eq!(
        p.binding_modes.as_deref(),
        Some(
            &[
                BindingMode::TimeBound,
                BindingMode::UserBound,
                BindingMode::Both
            ][..]
        )
    );
    assert_eq!(p.default_ttl.as_deref(), Some("24h"));
    assert_eq!(p.max_ttl.as_deref(), Some("90d"));

    let ceiling = p
        .mint_ceilings
        .get("app-admin")
        .expect("app-admin ceiling present");
    assert_eq!(ceiling.max_ttl.as_deref(), Some("7d"));

    assert_eq!(
        ceiling.allowed_pools.as_deref(),
        Some(&["growth".to_string(), "ops".to_string()][..])
    );
    assert_eq!(
        ceiling.binding_modes.as_deref(),
        Some(&[BindingMode::TimeBound][..])
    );
}

#[test]
fn test_auth_policy_absent_is_default() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let deploy: DeployCfg =
        serde_yaml::from_str("auth:\n  chain: [keys]\nproviders: {}\nmodels: {}\npools: {}\n")
            .expect("an auth block with no policy parses");
    let mut errors = Vec::new();
    let auth = busbar_kernel::config::resolve_auth(
        deploy.auth.as_ref().expect("auth block"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");
    let p = &auth.policy;
    assert_eq!(p.self_mint, None);
    assert!(p.binding_modes.is_none());
    assert!(p.default_ttl.is_none());
    assert!(p.max_ttl.is_none());
    assert!(p.mint_ceilings.is_empty());
    assert_eq!(p, &busbar_kernel::config::AuthPolicyCfg::default());
}

#[test]
fn test_auth_policy_ceiling_allowed_pools_three_state() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let deploy: DeployCfg = busbar_kernel::config::deploy_from_yaml_str(
        "auth:\n  \
           policy:\n    \
             mint_ceilings:\n      \
               all-pools: { max_ttl: \"1h\" }\n      \
               no-pools: { allowed_pools: [] }\n      \
               some-pools: { allowed_pools: [a, b] }\n\
         providers: {}\nmodels: {}\npools: {}\n",
    )
    .expect("three-state allowed_pools parses");
    let policy = &deploy.auth.expect("auth").policy;
    assert!(
        policy.mint_ceilings["all-pools"].allowed_pools.is_none(),
        "omitted allowed_pools = None (all pools)"
    );
    assert_eq!(
        policy.mint_ceilings["no-pools"].allowed_pools.as_deref(),
        Some(&[][..]),
        "explicit [] = the empty set (no pools)"
    );
    assert_eq!(
        policy.mint_ceilings["some-pools"]
            .allowed_pools
            .as_deref()
            .map(<[String]>::len),
        Some(2)
    );
}

#[test]
fn test_otlp_folds_into_an_export_instance() {
    crate::dist_root_install::install();
    let defs: busbar_kernel::config::ExportDefs = serde_yaml::from_str(
        "traces:\n  module: otlp\n  settings: { url: \"http://localhost:4318/v1/traces\" }\n",
    )
    .expect("an otlp export instance parses");
    let mut errors = Vec::new();
    let export = busbar_kernel::config::resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let otlp: Vec<_> = export
        .plugins
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                p.def.module.as_str(),
                p.def.settings.get("url"),
            )
        })
        .collect();
    assert_eq!(
        otlp,
        vec![(
            "traces",
            "otlp",
            Some(&serde_json::json!("http://localhost:4318/v1/traces"))
        )]
    );
}

#[test]
fn root_pools_named_after_a_reserved_sub_key_load_as_in_1_5_5() {
    crate::dist_root_install::install();
    let pools: busbar_kernel::config::PoolsCfg = serde_yaml::from_str(
        "tier:\n  members: [{model: m}]\nwork:\n  members: [{model: m}]\n\
         breaker:\n  members: [{model: m}]\n",
    )
    .expect("a pool named `tier`, `work` or `breaker` is a pool, as in 1.5.5");
    let mut names: Vec<&String> = pools.pools.keys().collect();
    names.sort();
    assert_eq!(names, ["breaker", "tier", "work"]);
    for word in busbar_contract::section::RESERVED_SECTION_KEYS {
        let e = serde_yaml::from_str::<busbar_kernel::config::PoolsCfg>(&format!(
            "{word}:\n  members: []\n"
        ))
        .expect_err(word);
        assert_eq!(
            e.to_string(),
            busbar_contract::section::reserved_name_refusal("pools", "pool", word)
        );
    }
}
