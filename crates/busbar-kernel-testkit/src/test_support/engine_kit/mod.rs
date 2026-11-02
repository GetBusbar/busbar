// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::TestAppSeam;
use crate::config::groups::GroupCfg;
use crate::config::sections::RateEntryCfg;
use crate::governance::signing::TokenSigner;
use crate::governance::{DerivedUsage, NewKeySpec};
use crate::plane_driver::dispatch::PlaneAdmission;
use crate::plane_driver::slots::PlaneSlots;
use crate::plane_driver::{EngineHost, LiveHostFactory};
use crate::trust::validate::GovResolve;
use busbar_contract::records::{AuditRecord, MeteringRow, RecordStore, VirtualKey};
use std::any::Any;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// One axis of a hook plugin's declared content need — the `no ⊂ ro ⊂ rw` ladder the engine
/// compares a manifest's intent against the operator's grant on. Neutral twin of the manifest
/// crate's `NeedLevel`, so a plane test states a fixture hook's intent without that crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookNeed {
    /// Declares no need for this content.
    No,
    /// Asks to read this content.
    Ro,
    /// Asks to read and rewrite (prompt axis only).
    Rw,
}

/// The admin API's scope bar for one route — the answer the engine's admin contract table gives for
/// `(method, path)`, so a plane asserts which of its admin verbs are mutations without naming the
/// engine's contract module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminScope {
    /// A read (or a stateless dry-run): admitted to a read-only admin token.
    ReadOnly,
    /// A mutation: needs a full admin token.
    Full,
}

pub type HookEnvHandle = Box<dyn Any + Send>;

pub trait CostKit: Any + Send + Sync {}

pub trait GovKit: Any + Send + Sync {
    fn create_key(&self, spec: NewKeySpec, now: u64) -> Result<(VirtualKey, String), String>;

    fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, busbar_contract::redacted::Secret<String>), String>;

    fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> Result<(VirtualKey, String, String, String), String>;

    fn admin_token_hash(&self) -> Option<String>;

    fn delete_key(&self, id: &str) -> Result<(), String>;

    fn revoke(&self, sub: &str, reason: &str) -> Result<(), String>;

    fn all_keys(&self) -> Result<Vec<VirtualKey>, String>;

    fn is_revoked(&self, sub: &str) -> bool;

    fn update_key(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
    ) -> Result<Option<VirtualKey>, String>;

    fn try_admit(
        &self,
        cost: &dyn CostKit,
        key: &VirtualKey,
        pool: &str,
        now: u64,
    ) -> Result<(), String>;

    fn refresh(&self) -> Result<(), String>;

    fn gov_resolve(&self) -> &dyn GovResolve;

    fn store(&self) -> Arc<dyn RecordStore>;

    fn flush_metering(&self) -> usize;

    fn metering_for(&self, bucket: u64) -> Result<Vec<MeteringRow>, String>;

    fn hydrate_budgets(&self, cost: &dyn CostKit, now: u64) -> Result<(), String>;

    fn flush_budgets(&self);

    fn usage_for(
        &self,
        cost: &dyn CostKit,
        id: &str,
        now: u64,
    ) -> Result<Option<DerivedUsage>, String>;

    fn derived_bucket_usage(
        &self,
        cost: &dyn CostKit,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> Result<DerivedUsage, String>;
}

pub trait EngineHandle: Any + Send + Sync {
    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost>;

    fn live_host_factory(self: Arc<Self>) -> LiveHostFactory;

    fn load(&self) -> Arc<dyn EngineApp>;

    fn swap(&self, next: Arc<dyn EngineApp>);
}

pub trait EngineApp: PlaneSlots + Any + Send + Sync {
    fn router(self: Arc<Self>) -> axum::Router;

    fn router_with_handle(self: Arc<Self>) -> (axum::Router, Arc<dyn EngineHandle>);

    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost>;

    fn handle(self: Arc<Self>) -> Arc<dyn EngineHandle>;

    fn data_route_paths(&self) -> Vec<String>;
}

pub trait TestAppKit: TestAppSeam {
    fn set_governance(&mut self, gov: Arc<dyn GovKit>);

    fn set_cost(&mut self, cost: Arc<dyn CostKit>);

    fn add_hook(&mut self, name: &str, def: serde_json::Value);

    fn set_hook_env(&mut self, env: HookEnvHandle);

    fn set_groups_tree(&mut self, groups: BTreeMap<String, serde_json::Value>);

    fn use_keys_chain(&mut self);

    fn use_idp_chain(&mut self);

    fn add_tool_pool(&mut self, name: &str, members: &[&str], repeatable: &[&str]);

    fn add_lane(&mut self, model: &str, protocol: &'static str, base_url: &str);

    fn set_durable_store(&mut self, store: Arc<dyn RecordStore>);

    fn build(self: Box<Self>) -> Arc<dyn EngineApp>;
}

pub trait TestAppKitExt: Sized {
    fn governance(self, gov: Arc<dyn GovKit>) -> Self;

    fn cost(self, cost: Arc<dyn CostKit>) -> Self;

    fn hook(self, name: &str, def: serde_json::Value) -> Self;

    fn hook_env(self, env: HookEnvHandle) -> Self;

    fn groups_tree(self, groups: BTreeMap<String, serde_json::Value>) -> Self;

    fn keys_chain(self) -> Self;

    fn idp_chain(self) -> Self;

    fn tool_pool(self, name: &str, members: &[&str], repeatable: &[&str]) -> Self;

    fn lane(self, model: &str, protocol: &'static str, base_url: &str) -> Self;

    fn durable_store(self, store: Arc<dyn RecordStore>) -> Self;
}

impl TestAppKitExt for Box<dyn TestAppKit> {
    fn governance(mut self, gov: Arc<dyn GovKit>) -> Self {
        self.set_governance(gov);
        self
    }
    fn cost(mut self, cost: Arc<dyn CostKit>) -> Self {
        self.set_cost(cost);
        self
    }
    fn hook(mut self, name: &str, def: serde_json::Value) -> Self {
        self.add_hook(name, def);
        self
    }
    fn hook_env(mut self, env: HookEnvHandle) -> Self {
        self.set_hook_env(env);
        self
    }
    fn groups_tree(mut self, groups: BTreeMap<String, serde_json::Value>) -> Self {
        self.set_groups_tree(groups);
        self
    }
    fn keys_chain(mut self) -> Self {
        self.use_keys_chain();
        self
    }
    fn idp_chain(mut self) -> Self {
        self.use_idp_chain();
        self
    }
    fn tool_pool(mut self, name: &str, members: &[&str], repeatable: &[&str]) -> Self {
        self.add_tool_pool(name, members, repeatable);
        self
    }
    fn lane(mut self, model: &str, protocol: &'static str, base_url: &str) -> Self {
        self.add_lane(model, protocol, base_url);
        self
    }
    fn durable_store(mut self, store: Arc<dyn RecordStore>) -> Self {
        self.set_durable_store(store);
        self
    }
}

impl TestAppSeam for Box<dyn TestAppKit> {
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn Any>,
    ) -> &mut dyn Any {
        (**self).plane_scratch_any(key, init)
    }
    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn Any>> {
        (**self).take_plane_scratch_any(key)
    }
    fn register_plane_finalizer(&mut self, f: Box<dyn FnOnce(&mut dyn TestAppSeam)>) {
        (**self).register_plane_finalizer(f)
    }
    fn install_plane_runtime(&mut self, key: &'static str, rt: Arc<dyn Any + Send + Sync>) {
        (**self).install_plane_runtime(key, rt)
    }
    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) {
        (**self).mount_plane(key, path, wire)
    }
    fn admit_plane(&mut self, key: &'static str, admission: PlaneAdmission) {
        (**self).admit_plane(key, admission)
    }
    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    ) {
        (**self).set_container_hooks(plane_key, containers, section)
    }
    fn set_plane_defs_any(&mut self, plane_key: &'static str, defs: Arc<dyn Any + Send + Sync>) {
        (**self).set_plane_defs_any(plane_key, defs)
    }
}

pub trait EngineTestKit: Send + Sync {
    fn metrics_init(&self);

    fn install_operator_auth_row(&self, door: crate::test_support::AuthDoor);

    fn new_app(&self) -> Box<dyn TestAppKit>;

    fn governance(
        &self,
        store: Arc<dyn RecordStore>,
        admin_token: Option<String>,
        signer: Option<TokenSigner>,
    ) -> Result<Arc<dyn GovKit>, String>;

    fn scratch_store(&self) -> Arc<dyn RecordStore>;

    fn cost_flat(&self, price_per_request_cents: i64) -> Arc<dyn CostKit>;

    fn cost_parts(
        &self,
        rate_card: Option<&BTreeMap<String, RateEntryCfg>>,
        price_per_request_cents: i64,
        groups: &BTreeMap<String, GroupCfg>,
    ) -> Arc<dyn CostKit>;

    fn hook_env(&self, aliases: &[&str], prompt: HookNeed, user: HookNeed) -> HookEnvHandle;

    fn audit_high_water_seq(&self) -> u64;

    fn emit_admin_audit_now(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    fn audit_entries(&self) -> Vec<AuditRecord>;

    fn admin_required_scope(&self, method: &axum::http::Method, path: &str) -> AdminScope;

    fn validate_named_def(
        &self,
        section: &'static str,
        name: &str,
        def: &serde_json::Value,
    ) -> Result<(), String>;

    fn durable_store_cfg(&self, tag: &str) -> (PathBuf, String);

    fn open_store_plugin(&self, cfg: &str) -> Arc<dyn RecordStore>;
}

mod core_impl;
pub use core_impl::{CoreEngineKit, CORE_ENGINE_KIT};

pub(crate) use core_impl::{cost_model, gov_state};
