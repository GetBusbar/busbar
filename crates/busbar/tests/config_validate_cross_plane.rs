// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `config_validate::validate_unified_pool_names` AGREEMENT TESTS, relocated here from
//! `src/config_validate/tests/tests.rs`: each hands core's own validator a REAL `tools:` registry
//! (`RootCfg::tool_defs`, `Box<dyn PlaneCfg>`) lifted by whichever test-linked plane declares that
//! section (`tests/linked/mod.rs`), which only type-checks with ONE `busbar_kernel` in the graph —
//! see `plane_integration.rs`'s header. This file names no plane crate and no plane type.
//!
//! `validate_unified_pool_names` was widened from private to `pub` (in `busbar_kernel::config_validate`)
//! for exactly this move — the test still drives the real function directly, not the aggregate
//! `validate`/`validate_with_unset` entry point (one of these three tests asserts `errors.is_empty()`,
//! so routing through the full validator risked an unrelated rule firing on the shared minimal fixture).

mod linked;

use busbar_kernel::config::{self, RootCfg};
use busbar_kernel::config_validate::validate_unified_pool_names;
use busbar_kernel::failover::CandidatePoolCfg;
use std::collections::HashMap;

/// Byte-identical to `src/config_validate/tests/tests.rs::make_root_cfg` (kept private/local there
/// too — this is the one copy an integration test needs).
fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    config::RootCfg {
        tool_defs: busbar_kernel::plane::config::ToolsSection::default().0,
        agent_defs: busbar_kernel::plane::config::AgentsSection::default().0,
        tool_pools: Default::default(),
        agent_pools: Default::default(),
        plane_sections: Default::default(),
        listen: config::DEFAULT_LISTEN_ADDR.into(),
        endpoint_resources: Default::default(),
        oauth_as: None,
        public_url: None,
        tls: None,
        admin_listen: config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models,
        pools,
        upstream_credentials: busbar_kernel::auth::UpstreamCreds::Own,
        hooks: HashMap::new(),
        admin_auth: config::default_admin_auth_names(),
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: Some(busbar_kernel::test_support::stand_in_store()),
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

/// Byte-identical to `src/config_validate/tests/tests.rs::make_model_unbounded`.
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

/// A minimal `tools:` registry holding one server id, for the collision tests below — CONFIG-DRIVEN:
/// the section is parsed through the kernel's own config entry point (`deploy_from_yaml_str`), so the
/// plane that declares `tools:` (a test-linked plane, `tests/linked/mod.rs`) lifts it into its own
/// type-erased config exactly as boot does; this file names no plane type.
fn tools_with(id: &str) -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
    linked::install();
    let text = format!(
        "providers: {{}}\nmodels: {{}}\ntools:\n  {id}: {{ url: \"https://x.example/t\", pin: {{ mechanism: unpinned }} }}\n"
    );
    config::deploy_from_yaml_str(&text)
        .unwrap_or_else(|e| panic!("a minimal server parses: {e}\n{text}"))
        .tools
        .0
}

/// A name defined in TWO nouns makes a bare member ambiguous — the router could not tell which plane
/// `shared` belongs to. Refused so kind inference stays name-only.
#[test]
fn a_name_defined_in_two_nouns_is_refused() {
    let mut models = HashMap::new();
    models.insert("shared".to_string(), make_model_unbounded("prov"));
    let mut cfg = make_root_cfg(HashMap::new(), models, HashMap::new());
    cfg.tool_defs = tools_with("shared");

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(
        errors.iter().any(|e| e.contains("`shared`")
            && e.contains("`models:`")
            && e.contains("`tools:`")
            && e.contains("at most ONE noun")),
        "the collision names the two nouns: {errors:?}"
    );
}

/// A pool name that collides with a registration on the plane it routes to would alias that
/// registration's breaker cell. Refused, cross-checked against every noun (the map is not kind-scoped).
#[test]
fn a_pool_named_like_a_tools_registration_is_refused() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.tool_defs = tools_with("search");
    cfg.tool_pools.insert(
        "search".to_string(),
        CandidatePoolCfg {
            members: vec!["search-eu".into(), "search-us".into()],
            repeatable: Vec::new(),
        },
    );

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("pool name 'search'") && e.contains("`tools:` registration")),
        "a pool sharing a registration name is refused: {errors:?}"
    );
}

/// The clean case: distinct names across every noun and pool, no collision — zero errors.
#[test]
fn distinct_names_across_nouns_and_pools_pass() {
    let mut models = HashMap::new();
    models.insert("gpt".to_string(), make_model_unbounded("prov"));
    let mut cfg = make_root_cfg(HashMap::new(), models, HashMap::new());
    cfg.tool_defs = tools_with("fs-server");

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(errors.is_empty(), "no collisions: {errors:?}");
}

/// THE `tools:` SECTION'S SECRET REFERENCES ARE ENUMERATED, so `--validate` and boot resolve each one
/// (P3 DEL-MCP: the section is a door plane's, carried as written). Its owning plane's declaration
/// names where references live — busbar's own RFC 8693 subject token, and a stdio child's
/// environment values — and the section the registry lifted answers every reference at those paths,
/// with its full config path, and nothing that is not a reference.
#[test]
fn the_tools_section_enumerates_every_secret_reference_its_plane_declares() {
    linked::install();
    let text = "providers: {}\nmodels: {}\ntools:\n  \
        exchanged:\n    url: \"https://x.example/t\"\n    pin: { mechanism: unpinned }\n    \
        aud: \"https://x.example\"\n    token_exchange:\n      \
        token_url: \"https://as.example/token\"\n      \
        subject_token: { env: BUSBAR_TEST_SUBJECT_TOKEN }\n  \
        child:\n    transport: stdio\n    command: \"/usr/bin/true\"\n    \
        pin: { mechanism: unpinned }\n    \
        env:\n      API_KEY: { env: BUSBAR_TEST_CHILD_KEY }\n      MODE: \"plain\"\n";
    let deploy = config::deploy_from_yaml_str(text)
        .unwrap_or_else(|e| panic!("the section parses: {e}\n{text}"));
    let mut found: Vec<String> = deploy
        .tools
        .0
        .secret_refs()
        .into_iter()
        .map(|(at, _)| at)
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "tools.child.env.API_KEY",
            "tools.exchanged.token_exchange.subject_token",
        ],
        "every reference at the plane's declared paths, and the plain value beside one is not one"
    );
}

/// THE `agents:` SECTION'S SECRET REFERENCES ARE ENUMERATED, so `--validate` and boot resolve each
/// one (the section is a door plane's, carried as written). Its owning plane's declaration names
/// where references live — the leased outbound delegation credential, and busbar's own client
/// certificate and key for a mutual handshake — and the section the registry lifted answers every
/// reference at those paths, with its full config path, and nothing that is not a reference.
#[test]
fn the_agents_section_enumerates_every_secret_reference_its_plane_declares() {
    linked::install();
    let text = "providers: {}\nmodels: {}\nagents:\n  \
        leased:\n    url: \"https://a.example/rpc\"\n    pin: { mechanism: unpinned }\n    \
        upstream_credential:\n      secret: { env: BUSBAR_TEST_AGENT_LEASE }\n      \
        lease_ttl_ms: 60000\n  \
        mutual:\n    url: \"https://b.example/rpc\"\n    pin: { mechanism: unpinned }\n    \
        client_identity:\n      cert: { env: BUSBAR_TEST_AGENT_CERT }\n      \
        key: { env: BUSBAR_TEST_AGENT_KEY }\n  \
        plain:\n    url: \"https://c.example/rpc\"\n    pin: { mechanism: unpinned }\n";
    let deploy = config::deploy_from_yaml_str(text)
        .unwrap_or_else(|e| panic!("the section parses: {e}\n{text}"));
    let mut found: Vec<String> = deploy
        .agents
        .0
        .secret_refs()
        .into_iter()
        .map(|(at, _)| at)
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "agents.leased.upstream_credential.secret",
            "agents.mutual.client_identity.cert",
            "agents.mutual.client_identity.key",
        ],
        "every reference at the plane's declared paths, and a registration holding none adds none"
    );
}

/// THE BILLING SWITCH'S MONEY-SACRED ARM, at boot (#42, #77(5); /status row 124, the rigs'
/// `h2-unpriced-refuses` arm 2): a plane section whose OWN card (`<section>.rate_card`, #47) is
/// present — so that plane's billing is ON — and silent about one class the plane declares must
/// refuse, naming that class, on the path boot and `--validate` both take (`deploy_from_yaml_str` →
/// `resolve` → `config_validate::validate`). A card configuring every declared class, an explicit 0
/// included, boots; no card at all is billing OFF and boots. Every test-linked plane that declares
/// a priced class and is not the fallback is asked, addressed by its declaration; the classes are
/// the plane's own, less its fee units (a fee unit is no class a card prices).
#[test]
fn a_plane_card_silent_about_a_declared_class_refuses_at_boot() {
    linked::install();
    let planes: Vec<_> = linked::planes()
        .iter()
        .copied()
        .filter(|d| !d.fallback)
        .filter(|d| {
            d.billable_classes
                .iter()
                .any(|c| !d.fee_units.contains(&c.class))
        })
        .collect();
    assert!(
        planes.len() >= 2,
        "the rigs' two billed planes (the `tools:` and `agents:` sections) are test-linked: {:?}",
        planes.iter().map(|d| d.key).collect::<Vec<_>>()
    );
    for d in planes {
        let classes: Vec<&str> = (d.billable_classes.iter())
            .map(|c| c.class)
            .filter(|c| !d.fee_units.contains(c))
            .collect();
        let (unpriced, priced) = classes.split_last().expect("a priced class");
        let section = |card: Option<&[&str]>| {
            let card = card.map_or(String::new(), |classes| {
                let units: Vec<String> = classes.iter().map(|c| format!("{c}: 0")).collect();
                format!(
                    "  rate_card:\n    lane: {{ units: {{ {} }} }}\n",
                    units.join(", ")
                )
            });
            format!(
                "store: {{ module: memory }}\nproviders: {{}}\nmodels: {{}}\n{s}:\n  \
                 fees: {{ per_request: 1 }}\n{card}  \
                 probe: {{ url: \"https://x.example/t\", pin: {{ mechanism: unpinned }} }}\n",
                s = d.config_section,
            )
        };
        let validated = |text: String| {
            let deploy = config::deploy_from_yaml_str(&text)
                .unwrap_or_else(|e| panic!("{}: the document parses: {e}\n{text}", d.key));
            let cfg = config::resolve(&deploy, &HashMap::new())
                .unwrap_or_else(|e| panic!("{}: the document resolves: {e:?}\n{text}", d.key));
            busbar_kernel::config_validate::validate(&cfg)
        };

        let errs = validated(section(Some(priced)))
            .expect_err("billing ON with a declared class unpriced must refuse (#77(5))");
        let want = format!(
            "{}.rate_card does not configure billable unit(s) {unpriced} declared by this plane; \
             add them (0 to make them free)",
            d.config_section
        );
        assert!(
            errs.contains(&want),
            "{}: the refusal names the unpriced class: {errs:?}",
            d.key
        );

        // The other two arms ask the money rule only: whatever else the minimal document lacks,
        // nothing about its card refuses.
        let card_refusals = |r: Result<(), Vec<String>>| -> Vec<String> {
            r.err()
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.contains("rate_card"))
                .collect()
        };
        let every = card_refusals(validated(section(Some(classes.as_slice()))));
        assert!(
            every.is_empty(),
            "{}: a card configuring every declared class (explicit 0) boots: {every:?}",
            d.key
        );
        let off = card_refusals(validated(section(None)));
        assert!(
            off.is_empty(),
            "{}: no card is billing OFF (#42) and boots: {off:?}",
            d.key
        );
    }
}
