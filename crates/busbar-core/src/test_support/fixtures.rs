//! The shared config-build fixtures and the two neutral app seams.
//!
//! Split out of `test_support/mod.rs` so that file stays under the layout ceiling. A child
//! module reading `use super::*`, so every fixture below still names `TestApp`, `LaneSpec` and
//! the rest exactly as it did when it lived one file up.

use super::*;

// ── SHARED CONFIG-BUILD FIXTURES (relocated from src/tests/tests.rs) ─────────────────────────────
// `pub` so BOTH the in-crate unit tests and busbar-core's OWN integration-test target
// (`tests/plane_integration.rs`, where the plane crates link as ONE busbar_core) can build a RootCfg
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
        tariff: None,
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

pub fn build_once(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<crate::state::App, String> {
    // Test-only direct call: there is no outer admin transaction / persist step here, so firing any
    // resolved governance-credential rotation immediately is correct
    // and keeps this helper's callers (which assert on rotation taking effect) unchanged.
    let (app, gov_rotate) = crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
    )?;
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
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

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
    server.abort();
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"))
}

// ── THE NEUTRAL TEST-APP SEAM (busbar_substrate::testkit::TestAppSeam) ──────────────────────────────
// Core implements the neutral fixture seam for its concrete `TestApp`, so the extracted plane
// test-kits (`busbar-mcp`/`busbar-a2a`) build and drive the test App through the trait — naming no
// `busbar_core::state::App`/`test_support::TestApp` backwards. Each method delegates to the inherent
// fixture logic above (or to the type-erased scratch map); the object-safe scratch primitives back the
// generic `TestAppSeamExt::plane_scratch::<T>` sugar the plane test-kits call.
impl busbar_substrate::testkit::TestAppSeam for TestApp {
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
        f: Box<dyn FnOnce(&mut dyn busbar_substrate::testkit::TestAppSeam)>,
    ) {
        self.plane_finalizers.push(f);
    }

    fn configured_public_url(&self) -> Option<&str> {
        TestApp::configured_public_url(self)
    }

    fn card_issuer(
        &self,
        _plane_key: &'static str,
    ) -> Option<busbar_substrate::plane::registry::CardIssuer> {
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

    fn admit_plane(
        &mut self,
        key: &'static str,
        admission: busbar_substrate::plane::PlaneAdmission,
    ) {
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

// ── THE NEUTRAL BUILT-APP SEAM (busbar_substrate::testkit::BuiltAppSeam) ────────────────────────────
// The second half of the fixture doorway: what a plane's tests drive on the `Arc<App>` that came OUT
// of `TestApp::build()`. Each method is a thin delegate to the very fn the plane's tests used to name
// directly (`plane_host::engine_host`, `build_router`, `App::plane_slot_mut`,
// `metrics::refresh_scrape_gauges`), so a plane's money-path tests forward a request / mount the real
// router / mutate their runtime slot through the trait, generic over `A: BuiltAppSeam`, naming no
// `busbar_core::` item.
impl busbar_substrate::testkit::BuiltAppSeam for crate::state::App {
    fn engine_host_of(
        app: &std::sync::Arc<Self>,
    ) -> std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost> {
        crate::plane_host::engine_host(app)
    }

    fn engine_host_value_of(
        app: std::sync::Arc<Self>,
    ) -> impl busbar_substrate::plane_host::EngineHost + 'static {
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
