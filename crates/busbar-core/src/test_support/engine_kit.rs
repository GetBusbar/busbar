// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE'S IMPLEMENTATION of the neutral engine test-kit seam
//! (`busbar_substrate::testkit::engine_kit`): every verb is a thin delegate to the fixture or
//! process-wide service a plane's tests used to name directly (`TestApp`, `GovState`, `metrics::init`,
//! the call log, the audit ring, the admin contract table, the store-plugin fixture, `build_router`,
//! `plane_host::engine_host`, `AppHandle`). A plane's test tree binds [`CORE_ENGINE_KIT`] in one
//! function and reaches all of it through `busbar_substrate::testkit::engine_kit::EngineTestKit` —
//! the plane names this crate in exactly that one binding line and nowhere else.

use super::TestApp;
use busbar_api::{AuditRecord, MeteringRow, Store, VirtualKey};
use busbar_substrate::governance::signing::TokenSigner;
use busbar_substrate::governance::NewKeySpec;
use busbar_substrate::plane::calllog::CallRecorded;
use busbar_substrate::plane::store::PlaneStore;
use busbar_substrate::plane_host::{EngineHost, LiveHostFactory};
use busbar_substrate::store::BreakerState;
use busbar_substrate::testkit::engine_kit::{
    AdminScope, EngineApp, EngineHandle, EngineTestKit, GovKit, HookEnvHandle, HookNeed, TestAppKit,
};
use std::any::Any;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// The engine's kit, as the `&'static` a plane's binding function hands back.
pub static CORE_ENGINE_KIT: CoreEngineKit = CoreEngineKit;

/// The engine's test-kit provider. Stateless: every service it reaches is process-wide already.
pub struct CoreEngineKit;

fn need(level: HookNeed) -> busbar_plugin_sign::NeedLevel {
    match level {
        HookNeed::No => busbar_plugin_sign::NeedLevel::No,
        HookNeed::Ro => busbar_plugin_sign::NeedLevel::Ro,
        HookNeed::Rw => busbar_plugin_sign::NeedLevel::Rw,
    }
}

impl EngineTestKit for CoreEngineKit {
    fn metrics_init(&self) {
        crate::metrics::init();
    }

    fn new_app(&self) -> Box<dyn TestAppKit> {
        Box::new(TestApp::new())
    }

    fn governance(
        &self,
        store: Arc<dyn Store>,
        admin_token: Option<String>,
        signer: Option<TokenSigner>,
    ) -> Result<Arc<dyn GovKit>, String> {
        crate::governance::GovState::new_with_signer(store, admin_token, signer)
            .map(|g| Arc::new(g) as Arc<dyn GovKit>)
            .map_err(|e| e.to_string())
    }

    fn hook_env(
        &self,
        aliases: &[&str],
        prompt: HookNeed,
        user: HookNeed,
    ) -> Option<HookEnvHandle> {
        super::test_hook_env(
            aliases,
            busbar_plugin_sign::HookNeeds {
                prompt: need(prompt),
                user: need(user),
            },
        )
        .map(|env| Box::new(env) as HookEnvHandle)
    }

    fn call_next_seq(&self, principal: &str) -> u64 {
        crate::calllog::CALLS.next_seq(principal)
    }

    fn ensure_call_stream_registered(&self) {
        crate::calllog::ensure_global_call_stream_registered();
    }

    fn aim_call_sink(&self, store: Option<Arc<dyn PlaneStore>>) {
        crate::calllog::aim_global_call_sink(store);
    }

    fn verify_call_rows(&self, rows: &[CallRecorded]) -> Result<(), String> {
        crate::calllog::verify_call_rows(rows).map_err(|e| format!("{e:?}"))
    }

    fn audit_high_water_seq(&self) -> u64 {
        crate::admin::audit::AUDIT
            .export()
            .iter()
            .map(|e| e.seq)
            .max()
            .unwrap_or(0)
    }

    fn emit_admin_audit_now(&self, action: &str, resource: &str, outcome: &str, principal: &str) {
        crate::plane::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }

    fn audit_entries(&self) -> Vec<AuditRecord> {
        crate::plane::auditlog::AUDIT_LOG
            .list_filtered(0, crate::admin::audit::MAX_AUDIT_ENTRIES, None, None)
            .into_iter()
            .map(|e| AuditRecord {
                seq: e.seq,
                ts: e.ts,
                action: e.action,
                resource: e.resource,
                outcome: e.outcome,
                principal: e.principal,
                prev_hash: e.prev_hash,
                hash: e.hash,
            })
            .collect()
    }

    fn admin_required_scope(&self, method: &axum::http::Method, path: &str) -> AdminScope {
        match crate::admin::v1::contract::required_scope(method, path) {
            crate::admin::v1::contract::Scope::ReadOnly => AdminScope::ReadOnly,
            crate::admin::v1::contract::Scope::Full => AdminScope::Full,
        }
    }

    fn validate_named_def(
        &self,
        section: &'static str,
        name: &str,
        def: &serde_json::Value,
    ) -> Result<(), String> {
        crate::config::named_map::NamedMapSection::Plane(section).validate_def(name, def)
    }

    fn durable_store_cfg(&self, tag: &str) -> (PathBuf, String) {
        super::plugin_store::durable_cfg(tag)
    }

    fn open_store_plugin(&self, cfg: &str) -> Arc<dyn Store> {
        super::plugin_store::open_plugin(cfg)
    }
}

impl GovKit for crate::governance::GovState {
    fn create_key(&self, spec: NewKeySpec, now: u64) -> Result<(VirtualKey, String), String> {
        crate::governance::GovState::create_key(self, spec, now).map_err(|e| e.to_string())
    }
    fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), String> {
        crate::governance::GovState::mint_signed(self, spec, exp, now).map_err(|e| e.to_string())
    }
    fn delete_key(&self, id: &str) -> Result<(), String> {
        crate::governance::GovState::delete_key(self, id).map_err(|e| e.to_string())
    }
    fn revoke(&self, sub: &str, reason: &str) -> Result<(), String> {
        crate::governance::GovState::revoke(self, sub, reason).map_err(|e| e.to_string())
    }
    fn refresh(&self) -> Result<(), String> {
        crate::governance::GovState::refresh(self).map_err(|e| e.to_string())
    }
    fn gov_resolve(&self) -> &dyn busbar_substrate::trust::validate::GovResolve {
        self
    }
    fn store(&self) -> Arc<dyn Store> {
        crate::governance::GovState::store(self)
    }
    fn flush_metering(&self) -> usize {
        crate::governance::GovState::flush_metering(self)
    }
    fn metering_for(&self, bucket: u64) -> Result<Vec<MeteringRow>, String> {
        crate::governance::GovState::metering_for(self, bucket).map_err(|e| e.to_string())
    }
}

/// Take the engine's concrete registry back out of the neutral handle a plane held.
fn gov_state(gov: Arc<dyn GovKit>) -> Arc<crate::governance::GovState> {
    let any: Arc<dyn Any + Send + Sync> = gov;
    any.downcast::<crate::governance::GovState>()
        .expect("a GovKit the engine's own kit minted is a GovState")
}

impl TestAppKit for TestApp {
    fn set_governance(&mut self, gov: Arc<dyn GovKit>) {
        *self = std::mem::take(self).governance(gov_state(gov));
    }
    fn add_hook(&mut self, name: &str, def: serde_json::Value) {
        let cfg: crate::config::HookCfg = serde_json::from_value(def)
            .unwrap_or_else(|e| panic!("test `hooks.{name}` document must parse: {e}"));
        *self = std::mem::take(self).hook(name, cfg);
    }
    fn set_hook_env(&mut self, env: HookEnvHandle) {
        let env = env
            .downcast::<crate::hooks::HookEnv>()
            .expect("a hook env the engine's own kit loaded is a HookEnv");
        *self = std::mem::take(self).hook_env(*env);
    }
    fn set_groups_tree(&mut self, groups: BTreeMap<String, serde_json::Value>) {
        let groups: BTreeMap<String, crate::config::GroupCfg> = groups
            .into_iter()
            .map(|(name, def)| {
                let cfg = serde_json::from_value(def)
                    .unwrap_or_else(|e| panic!("test `groups.{name}` document must parse: {e}"));
                (name, cfg)
            })
            .collect();
        *self = std::mem::take(self).groups_tree(groups);
    }
    fn use_keys_chain(&mut self) {
        *self = std::mem::take(self).keys_chain();
    }
    fn use_idp_chain(&mut self) {
        *self = std::mem::take(self).idp_chain();
    }
    fn add_tool_pool(&mut self, name: &str, members: &[&str], repeatable: &[&str]) {
        *self = std::mem::take(self).tool_pool(name, members, repeatable);
    }
    fn add_lane(&mut self, model: &str, protocol: &'static str, base_url: &str) {
        *self = std::mem::take(self).lane(super::LaneSpec::new(model, protocol, base_url));
    }
    fn set_durable_store(&mut self, store: Arc<dyn Store>) {
        *self = std::mem::take(self).mcp_durable_store(store);
    }
    fn build(self: Box<Self>) -> Arc<dyn EngineApp> {
        TestApp::build(*self)
    }
}

impl EngineApp for crate::state::App {
    fn router(self: Arc<Self>) -> axum::Router {
        crate::build_router(self)
    }
    fn router_with_handle(self: Arc<Self>) -> (axum::Router, Arc<dyn EngineHandle>) {
        let (router, handle) = crate::build_router_with_limits(
            self,
            crate::limits::translate_body_max_bytes(),
            crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
            crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
        );
        (router, handle)
    }
    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost> {
        crate::plane_host::engine_host(&self)
    }
    fn handle(self: Arc<Self>) -> Arc<dyn EngineHandle> {
        Arc::new(crate::state::AppHandle::new(self))
    }
    fn breaker_state(&self, key: &str) -> BreakerState {
        self.plane_breakers.state(key)
    }
    fn breaker_state_at(&self, key: &str, lane: usize) -> BreakerState {
        self.plane_breakers.state_at(key, lane)
    }
    fn breaker_reset(&self, key: &str) {
        self.plane_breakers.reset(key);
    }
    fn data_route_paths(&self) -> Vec<String> {
        crate::base_data_route_table_view(self)
            .into_iter()
            .map(|(path, _auth)| path)
            .collect()
    }
    fn guard_url(
        &self,
        url: &str,
        allow_private: bool,
    ) -> Result<(), (busbar_plugin::hot::GuardClass, String)> {
        match crate::plane_host::guard_url_over(self, url, allow_private) {
            crate::plane_host::GuardOutcome::Allow => Ok(()),
            crate::plane_host::GuardOutcome::Deny { class, reason } => Err((class, reason)),
        }
    }
}

/// Take the engine's concrete snapshot back out of the neutral handle a plane held.
fn app_of(app: Arc<dyn EngineApp>) -> Arc<crate::state::App> {
    let any: Arc<dyn Any + Send + Sync> = app;
    any.downcast::<crate::state::App>()
        .expect("an EngineApp the engine's own kit built is an App")
}

impl EngineHandle for crate::state::AppHandle {
    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost> {
        crate::plane_host::engine_host_from_handle(&self)
    }
    fn live_host_factory(self: Arc<Self>) -> LiveHostFactory {
        crate::plane_host::live_host_factory(self)
    }
    fn load(&self) -> Arc<dyn EngineApp> {
        crate::state::AppHandle::load(self)
    }
    fn swap(&self, next: Arc<dyn EngineApp>) {
        crate::state::AppHandle::swap(self, app_of(next));
    }
}
