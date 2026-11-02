use super::*;

pub fn stand_in_store() -> crate::config::StoreCfg {
    crate::config::StoreCfg {
        module: crate::test_support::store_double::STORE.0.to_string(),
        settings: serde_json::Map::new(),
    }
}

pub fn cfg_with_provider_api_key(api_key: crate::config::SecretRef) -> crate::config::RootCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());
    let provider = crate::config::ProviderCfg {
        protocol: crate::ingress::protocols::residual_default_dialect()
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
        options: Default::default(),
    };
    let mut providers = std::collections::HashMap::new();
    providers.insert(
        "acme".to_string(),
        crate::config::ResolvedProvider::from(provider),
    );
    let mut cfg = empty_cfg();
    cfg.providers = providers;
    cfg
}

static NEUTRAL_FALLBACK_PLANE: crate::plane_driver::registry::PlaneDecl = NEUTRAL_FALLBACK;

pub const NEUTRAL_FALLBACK: crate::plane_driver::registry::PlaneDecl =
    crate::plane_driver::registry::PlaneDecl {
        declaration: crate::plane_driver::registry::PlaneDeclaration {
            key: "neutral-test-fallback",
            fallback: true,
            config_section: "pools",
            scope_kinds: &["pool"],
            subject_noun: "pool",
            admin_noun: "pool",
            audit_kind: "pool_request",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[],
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

pub fn register_neutral_test_plane() {
    crate::test_support::planes::register_test_plane(&NEUTRAL_FALLBACK_PLANE);
}

pub fn neutral_fallback_plane() -> &'static crate::plane_driver::registry::PlaneDecl {
    &NEUTRAL_FALLBACK_PLANE
}

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

pub async fn oversized_413_body(
    app: std::sync::Arc<crate::state::App>,
    path: &str,
) -> serde_json::Value {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    let (router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);

    let oversized = serde_json::json!({ "pad": "x".repeat(4096) }).to_string();
    let request = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(path)
        .header(axum::http::header::HOST, "127.0.0.1")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::CONTENT_LENGTH, oversized.len())
        .body(axum::body::Body::from(oversized))
        .expect("an oversized POST request");
    let r = router.oneshot(request).await.expect("the router answers");
    assert_eq!(
        r.status().as_u16(),
        413,
        "the body cap must reject the oversized POST to {path}"
    );
    let bytes = r
        .into_body()
        .collect()
        .await
        .expect("the 413 body is read")
        .to_bytes();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"))
}

impl crate::test_support::TestAppSeam for TestApp {
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
        f: Box<dyn FnOnce(&mut dyn crate::test_support::TestAppSeam)>,
    ) {
        self.plane_finalizers.push(f);
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
        admission: busbar_kernel::plane_driver::dispatch::PlaneAdmission,
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

impl crate::test_support::BuiltAppSeam for crate::state::App {
    fn engine_host_of(
        app: &std::sync::Arc<Self>,
    ) -> std::sync::Arc<dyn busbar_kernel::plane_driver::EngineHost> {
        crate::plane_driver::engine_host(app)
    }

    fn engine_host_value_of(
        app: std::sync::Arc<Self>,
    ) -> impl busbar_kernel::plane_driver::EngineHost + 'static {
        crate::plane_driver::engine_host_value(&app)
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
        crate::snapshot::refresh_scrape_gauges(self);
    }
}

pub fn empty_cfg() -> crate::config::RootCfg {
    crate::config::RootCfg {
        plane_defs: Default::default(),

        endpoint_resources: Default::default(),
        oauth_as: None,
        credentials: Default::default(),
        plane_pools: Default::default(),
        plane_sections: Default::default(),
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers: std::collections::HashMap::new(),
        models: std::collections::HashMap::new(),
        pools: std::collections::HashMap::new(),
        hooks: std::collections::HashMap::new(),
        admin_auth: crate::config::default_admin_auth_names(),
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: Some(stand_in_store()),
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        guard: Default::default(),
        limits: crate::config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}
