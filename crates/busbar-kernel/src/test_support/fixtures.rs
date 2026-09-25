//! The shared config-build fixtures and the two neutral app seams.
//!
//! Split out of `test_support/mod.rs` so that file stays under the layout ceiling. A child
//! module reading `use super::*`, so every fixture below still names `TestApp`, `LaneSpec` and
//! the rest exactly as it did when it lived one file up.

use super::*;

// ── SHARED CONFIG-BUILD FIXTURES (relocated from src/tests/tests.rs) ─────────────────────────────
// `pub` so BOTH the in-crate unit tests and busbar-core's OWN integration-test target
// (`tests/plane_integration.rs`, where the plane crates link as ONE busbar_kernel) can build a RootCfg
// and drive it through the real `build_app_from_config`.
/// A minimal `RootCfg` whose SOLE provider's `api_key` is the given secret reference — the smallest
/// config that exercises `config_validate::secret_refs` (and thus `validate_secret_refs`).
pub fn cfg_with_provider_api_key(api_key: crate::config::SecretRef) -> crate::config::RootCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());
    let provider = crate::config::ProviderCfg {
        // The registry-supplied residual-default dialect — the neutral test protocol — in place of the
        // hard-coded `"openai"` literal. Under every surface that drives this fixture the LLM protocols
        // are registered first (core's `cfg(test)` auto-publish, or each test's `install_test_seams`),
        // so this resolves to the same default dialect the literal named.
        protocol: crate::proto::residual_default_dialect()
            .expect("a residual-default protocol (the neutral test dialect) must be registered")
            .into(),
        base_url: "https://api.example.com".into(),
        api_key,
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        max_output_key: None,
        anthropic_adaptive_thinking: None,
        native_structured_output: None,
        model_capabilities: Vec::new(),
    };
    let mut providers = std::collections::HashMap::new();
    providers.insert("acme".to_string(), provider);
    crate::config::RootCfg {
        tool_defs: crate::plane::config::ToolsSection::default().0,
        // No endpoint plane configured.
        endpoint_resources: Default::default(),
        oauth_as: None,
        agent_defs: crate::plane::config::AgentsSection::default().0,
        tool_pools: Default::default(),
        agent_pools: Default::default(),
        plane_sections: Default::default(),
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models: std::collections::HashMap::new(),
        pools: std::collections::HashMap::new(),
        hooks: std::collections::HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: None,
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        limits: crate::config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

// ── THE NEUTRAL FALLBACK-PLANE FIXTURE ────────────────────────────────────────────────────────────
// `plane::config::split_section_for_plane` REFUSES (not panics — see that fn's doc) when it resolves
// `plane::fallback_key()` and finds no plane registered to own it: since the A6/HostCtx
// dev-dependency-cycle cleanup moved every test that asserts REAL llm/mcp/a2a behaviour out to
// `tests/*_cross_plane.rs` (the only place with ONE `busbar_kernel` in the graph — see that target's
// docs), this crate's OWN `#[cfg(test)]` unit tests can no longer reach a real plane's `PLANE_DECL` at
// all: calling `busbar_llm::testkit::install_test_seams()` from here would register the REAL `llm`
// PlaneDecl into busbar_llm's OWN dependency-copy of this crate's process statics, not this compiled
// unit's — completely inert. A unit test that merely needs "some plane exists" so `pools:`/config
// resolution has an owner (not one that asserts what that plane DOES) calls this instead.
//
// Registers ONE neutral, all-stub `PlaneDecl` — no real dialect, no real wire format, nothing a
// production match arm or an assertion about llm/mcp/a2a could key off — flagged `fallback: true` so
// `plane::fallback_key()` resolves to it exactly the way the shipped LLM plane's flag does in
// production. Every hook is `None`/no-op: this stands for "a plane is installed", never for what a
// plane does. Idempotent (`register_test_plane` dedupes by key) and NOT isolated — a test that also
// asserts against the registered SET (or needs a plane-free registry) wraps its own body in
// `crate::plane::registry::TestRegistryIsolation::empty()` around this call, the same as any other
// `register_test_plane` caller.
static NEUTRAL_FALLBACK_PLANE: crate::plane::registry::PlaneDecl =
    crate::plane::registry::PlaneDecl {
        key: "neutral-test-fallback",
        fallback: true,
        config_section: "pools",
        scope_kinds: &["pool"],
        subject_noun: "pool",
        admin_noun: "pool",
        audit_kind: "pool_request",
        wire_format_names: || &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        resolve_provider: None,
    };

/// SAY, IN ONE LINE, THAT THIS TEST NEEDS A PLANE TO EXIST — not what it does, only that config
/// resolution has somewhere to put a `pools:`/fallback section rather than refusing with "no plane is
/// registered to own this config section". Call at the top of a test that builds/parses a
/// `RootCfg`/`DeployCfg` (directly or via `resolve`) but asserts nothing about real llm/mcp/a2a
/// behaviour; a test that DOES assert real plane behaviour belongs in `tests/*_cross_plane.rs`
/// instead, where the real `busbar_llm`/`busbar_mcp`/`busbar_a2a` crates are reachable.
pub fn register_neutral_test_plane() {
    crate::plane::registry::register_test_plane(&NEUTRAL_FALLBACK_PLANE);
}

pub fn build_once(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<crate::state::App, String> {
    // Test-only direct call: there is no outer admin transaction / persist step here, so firing any
    // resolved governance-credential rotation immediately is correct
    // and keeps this helper's callers (which assert on rotation taking effect) unchanged.
    let (app, gov_rotate, limits) = crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
    )?;
    // Same reasoning for the limits: no persist step follows, so this build IS the live generation
    // and its limits stay installed — the behaviour every caller of this helper has always had.
    limits.keep();
    if let Some(rotate) = gov_rotate {
        rotate();
    }
    Ok(app)
}

/// A CLOSED single-module auth chain (the given module), for integration tests that must build an
/// mcp-server App (`mcp:` refuses an open data-plane chain). Built in-crate so the caller names no
/// `AuthChainEntry` field.
pub fn closed_auth_chain(module: &str) -> crate::config::AuthCfg {
    let mut auth = crate::config::AuthCfg::default_none();
    auth.chain = vec![crate::config::AuthChainEntry {
        name: module.to_string(),
        module: module.to_string(),
        max_admin_scope: None,
        token: None,
        settings: serde_json::Map::new(),
    }];
    auth
}

/// Drive a REAL oversized POST to `path` through the REAL layer stack and return the 413 body.
/// Asserts only the status and JSON-ness; the SHAPE is each caller's assertion.
pub async fn oversized_413_body(
    app: std::sync::Arc<crate::state::App>,
    path: &str,
) -> serde_json::Value {
    // A tiny body cap so an ordinary request trips `DefaultBodyLimit`.
    let (router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Cooperative shutdown rather than `JoinHandle::abort`: `axum::serve`'s own graceful-shutdown
    // future is raced INSIDE its accept loop, so telling it to stop is a signal the server notices at
    // its own next poll, never a forced mid-flight interruption.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            })
            .await
            .unwrap()
    });

    let oversized = "x".repeat(4096);
    let r = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "pad": oversized }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        413,
        "the body cap must reject the oversized POST to {path}"
    );
    let body = r.text().await.unwrap();
    let _ = stop_tx.send(());
    let _ = server.await;
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"))
}

// ── THE NEUTRAL TEST-APP SEAM (busbar_kernel::test_support::TestAppSeam) ──────────────────────────────
// Core implements the neutral fixture seam for its concrete `TestApp`, so the extracted plane
// test-kits (`busbar-mcp`/`busbar-a2a`) build and drive the test App through the trait — naming no
// `busbar_kernel::state::App`/`test_support::TestApp` backwards. Each method delegates to the inherent
// fixture logic above (or to the type-erased scratch map); the object-safe scratch primitives back the
// generic `TestAppSeamExt::plane_scratch::<T>` sugar the plane test-kits call.
impl busbar_kernel::test_support::TestAppSeam for TestApp {
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn std::any::Any>,
    ) -> &mut dyn std::any::Any {
        self.plane_scratch.entry(key).or_insert_with(init).as_mut()
    }

    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn std::any::Any>> {
        self.plane_scratch.remove(key)
    }

    fn register_plane_finalizer(
        &mut self,
        f: Box<dyn FnOnce(&mut dyn busbar_kernel::test_support::TestAppSeam)>,
    ) {
        self.plane_finalizers.push(f);
    }

    fn configured_public_url(&self) -> Option<&str> {
        TestApp::configured_public_url(self)
    }

    fn card_issuer(
        &self,
        _plane_key: &'static str,
    ) -> Option<busbar_kernel::plane::registry::CardIssuer> {
        TestApp::card_issuer(self)
    }

    fn install_plane_runtime(
        &mut self,
        key: &'static str,
        rt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) {
        TestApp::install_plane_runtime(self, key, rt);
    }

    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) {
        TestApp::mount_plane(self, key, path, wire);
    }

    fn admit_plane(&mut self, key: &'static str, admission: busbar_kernel::plane::PlaneAdmission) {
        TestApp::admit_plane(self, key, admission);
    }

    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    ) {
        TestApp::set_container_hooks(self, plane_key, containers, section);
    }

    fn set_plane_defs_any(
        &mut self,
        plane_key: &'static str,
        defs: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) {
        TestApp::set_plane_defs_any(self, plane_key, defs);
    }
}

// ── THE NEUTRAL BUILT-APP SEAM (busbar_kernel::test_support::BuiltAppSeam) ────────────────────────────
// The second half of the fixture doorway: what a plane's tests drive on the `Arc<App>` that came OUT
// of `TestApp::build()`. Each method is a thin delegate to the very fn the plane's tests used to name
// directly (`plane_host::engine_host`, `build_router`, `App::plane_slot_mut`,
// `metrics::refresh_scrape_gauges`), so a plane's money-path tests forward a request / mount the real
// router / mutate their runtime slot through the trait, generic over `A: BuiltAppSeam`, naming no
// `busbar_kernel::` item.
impl busbar_kernel::test_support::BuiltAppSeam for crate::state::App {
    fn engine_host_of(
        app: &std::sync::Arc<Self>,
    ) -> std::sync::Arc<dyn busbar_kernel::plane_host::EngineHost> {
        crate::plane_host::engine_host(app)
    }

    fn engine_host_value_of(
        app: std::sync::Arc<Self>,
    ) -> impl busbar_kernel::plane_host::EngineHost + 'static {
        crate::plane_host::engine_host_value(&app)
    }

    fn router_of(app: std::sync::Arc<Self>) -> axum::Router {
        crate::build_router(app)
    }

    fn plane_slot_mut(
        &mut self,
        key: &str,
    ) -> Option<&mut std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        crate::state::App::plane_slot_mut(self, key)
    }

    fn refresh_scrape_gauges(&self) {
        crate::metrics::refresh_scrape_gauges(self);
    }
}
