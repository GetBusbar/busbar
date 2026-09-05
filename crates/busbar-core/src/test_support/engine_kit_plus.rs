// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE'S IMPLEMENTATION of the widened engine test-kit seam
//! (`busbar_substrate::testkit::engine_kit_plus`), on the SAME fixture types the base kit is
//! implemented for ([`CoreEngineKit`], `TestApp`, `App`): every verb is a thin delegate to the fixture
//! builder, the built App's own tables (`planes`, `plane_breakers`, the data route table view) or the
//! process-wide service (`metrics::render`, the prometheus exporter, `tls::install_crypto_provider`,
//! the built-in secret resolver, the named-map chassis) a plane's tests used to name directly. A
//! plane's test tree binds [`CORE_ENGINE_KIT`](super::engine_kit::CORE_ENGINE_KIT) once as
//! `&'static dyn EngineTestKitPlus` and reaches both kits through it.

use super::engine_kit::CoreEngineKit;
use super::TestApp;
use busbar_api::SecretResolve;
use busbar_plugin::cold::http_endpoint::RouteAuth;
use busbar_substrate::plane::PlaneAdmission;
use busbar_substrate::testkit::engine_kit_plus::{
    AppBuilder, EngineAppPlus, EngineTestKitPlus, NamedMapSectionFacts, TestAppKitPlus,
};
use std::sync::Arc;

impl EngineTestKitPlus for CoreEngineKit {
    fn new_app_plus(&self) -> AppBuilder {
        AppBuilder::new(Box::new(TestApp::new()))
    }

    fn metrics_render(&self) -> String {
        crate::metrics::init();
        crate::metrics::render()
    }

    fn scrape_exposition(&self) -> (u16, String) {
        use crate::plugin_routes::PluginHttpDispatch;
        let resp = crate::export::prometheus::PrometheusExport.handle_http(
            &busbar_plugin_loader::HttpEndpointRequest {
                method: "GET".into(),
                path: "/metrics".into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            },
        );
        (
            resp.status,
            String::from_utf8(resp.body).expect("the exposition is UTF-8"),
        )
    }

    fn install_crypto_provider(&self) {
        crate::tls::install_crypto_provider();
    }

    fn builtin_secret_resolver(&self) -> Box<dyn SecretResolve> {
        Box::new(crate::config::secret::SecretResolver::builtins_only())
    }

    fn plane_request_family(&self) -> &'static str {
        crate::metrics::PLANE_REQUESTS_TOTAL
    }

    fn named_map_section_facts(&self, section: &'static str) -> Option<NamedMapSectionFacts> {
        use crate::config::named_map::NamedMapSection;
        let this = NamedMapSection::Plane(section);
        NamedMapSection::sections()
            .contains(&this)
            .then(|| NamedMapSectionFacts {
                key: this.key(),
                path_root: this.path_root().into_owned(),
                requires_module: this.requires_module(),
                has_trust_ceiling: this.has_trust_ceiling(),
            })
    }
}

impl TestAppKitPlus for TestApp {
    fn set_public_url(&mut self, url: &str) {
        *self = std::mem::take(self).public_url(url);
    }
    fn add_agent_pool(&mut self, name: &str, members: &[&str]) {
        *self = std::mem::take(self).agent_pool(name, members);
    }
    fn build_plus(self: Box<Self>) -> Arc<dyn EngineAppPlus> {
        TestApp::build(*self)
    }
}

impl EngineAppPlus for crate::state::App {
    fn mount_of(&self, key: &str) -> Option<String> {
        self.planes.mount_of(key).map(str::to_string)
    }
    fn admission_for(&self, path: &str) -> Option<PlaneAdmission> {
        self.planes.admission_for(path).cloned()
    }
    fn data_route_table(&self) -> Vec<(String, RouteAuth)> {
        crate::base_data_route_table_view(self)
    }
    fn breaker_force_open(&self, key: &str, lane: usize, until: u64) {
        self.plane_breakers.force_open(key, lane, until)
    }
}
