// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE TEST-KIT — the object-safe seam a plane crate's test binary drives the WHOLE engine
//! fixture through: building the test App, minting governance keys, reading the process-wide call
//! log and admin audit ring, loading the store-plugin fixture, and reaching the built App's router,
//! host, swappable handle and breaker cells — WITHOUT naming one `busbar_core::` item.
//!
//! Why a third seam beside [`super::TestAppSeam`] / [`super::BuiltAppSeam`]: those two are the
//! doorways a plane's TEST-KIT (its fluent builder extension) drives while the App is being built and
//! the doorway a test generic over `A: BuiltAppSeam` drives on the App that came out. They still
//! leave the plane's tests CONSTRUCTING the fixture by its core name
//! (`busbar_core::test_support::TestApp::new()`) and reaching the engine's process-wide services
//! (`metrics::init`, the call log, the audit ring, the governance registry, the admin scope table)
//! by theirs. This kit closes that gap: every one of those is a method on a trait object the engine
//! PROVIDES and the plane only CONSUMES.
//!
//! There is deliberately NO process-wide static and NO `install_*` here. The plane's test tree binds
//! the engine's kit in exactly one function (`fn engine() -> &'static dyn EngineTestKit { &CORE_KIT }`),
//! which is the one line in that tree that names the engine crate; every test reaches the engine
//! through that function. A static would have made this an installable seam that production never
//! installs — precisely what the construction gate's uninstalled-seam rule exists to refuse.
//!
//! Every type on these signatures is neutral: the substrate's own `EngineHost` / `PlaneSlots` /
//! `LiveHostFactory` / `BreakerState` / `TokenSigner` / `NewKeySpec` / `CallRecorded`, the
//! `busbar_api` store contracts (`Store`, `VirtualKey`, `MeteringRow`, `AuditRecord`), axum's
//! `Router` / `Method`, `serde_json::Value` for config documents the engine parses itself, and an
//! opaque `Box<dyn Any>` for the one fixture (the hook plugin environment) that has no neutral shape.

use super::TestAppSeam;
use crate::governance::signing::TokenSigner;
use crate::governance::NewKeySpec;
use crate::plane::calllog::CallRecorded;
use crate::plane::registry::CardIssuer;
use crate::plane::store::PlaneStore;
use crate::plane::PlaneAdmission;
use crate::plane_host::{EngineHost, LiveHostFactory, PlaneSlots};
use crate::store::BreakerState;
use crate::trust::validate::GovResolve;
use busbar_api::{AuditRecord, MeteringRow, Store, VirtualKey};
use busbar_plugin::hot::GuardClass;
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

/// A loaded hook plugin ENVIRONMENT (the engine's registry of dlopen'ed `kind: hook` plugins), held
/// opaque: it has no neutral shape, a plane only hands it back to [`TestAppKit::set_hook_env`], and
/// the engine downcasts it on the other side.
pub type HookEnvHandle = Box<dyn Any + Send>;

/// THE GOVERNANCE REGISTRY a test mints keys against and reads metering back out of — the engine's
/// own (a real registry over a real `Store`), reached by verb. Object-safe so a plane holds it as
/// `Arc<dyn GovKit>` and hands it to [`TestAppKit::set_governance`]. `Any` so the engine can take
/// its concrete registry back out by upcast + downcast; a plane never downcasts through it.
pub trait GovKit: Any + Send + Sync {
    /// Mint an UNSIGNED key from `spec` at `now`: the persisted key and its plaintext secret.
    fn create_key(&self, spec: NewKeySpec, now: u64) -> Result<(VirtualKey, String), String>;
    /// Mint a SIGNED (bearer-token) key from `spec`, expiring at `exp`, minted at `now`.
    fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> Result<(VirtualKey, String), String>;
    /// Delete key `id` and drop it from every cache.
    fn delete_key(&self, id: &str) -> Result<(), String>;
    /// Revoke the principal with subject id `sub` (every credential it holds), for `reason`.
    fn revoke(&self, sub: &str, reason: &str) -> Result<(), String>;
    /// Re-read the registry from its store.
    fn refresh(&self) -> Result<(), String>;
    /// This registry as the neutral live-principal resolver a standing permission re-checks
    /// against — the same object, seen through the seam the trust layer names.
    fn gov_resolve(&self) -> &dyn GovResolve;
    /// The store this registry is over.
    fn store(&self) -> Arc<dyn Store>;
    /// Flush the pending metering rows to the store; the number flushed.
    fn flush_metering(&self) -> usize;
    /// The metering rows persisted for `bucket`.
    fn metering_for(&self, bucket: u64) -> Result<Vec<MeteringRow>, String>;
}

/// THE SWAPPABLE HANDLE over a built App — the engine's live snapshot holder the route adapter, the
/// stdio session and the subscription streams read through, so a test can swap a second App in
/// mid-session exactly as a config apply does. `Any` so it upcasts to the type-erased
/// `Arc<dyn Any + Send + Sync>` a neutral request context carries the live engine as.
pub trait EngineHandle: Any + Send + Sync {
    /// Mint the neutral host over the handle's CURRENT snapshot (retains the live handle, so the
    /// slot-read paths see a swap that lands after admission).
    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost>;
    /// A factory minting a fresh host over the handle per call — the shape a per-frame transport
    /// (stdio) takes.
    fn live_host_factory(self: Arc<Self>) -> LiveHostFactory;
    /// The current snapshot.
    fn load(&self) -> Arc<dyn EngineApp>;
    /// Replace the snapshot with `next`, running the engine's swap hooks (the plane's `on_swap`).
    fn swap(&self, next: Arc<dyn EngineApp>);
}

/// A BUILT test App, reached only by the verbs a plane's tests drive on it. A [`PlaneSlots`] (the
/// neutral slot-read seam the engine's snapshot already implements), so `runtime(&app)` and every
/// other slot read a plane's production code makes works on it unchanged. `Any` so the engine can
/// take its concrete snapshot back in [`EngineHandle::swap`]; a plane never downcasts through it.
///
/// The object-safe twin of [`super::BuiltAppSeam`] (which carries an `impl Trait` return and so
/// cannot be a trait object); the engine implements both for the same snapshot type.
pub trait EngineApp: PlaneSlots + Any + Send + Sync {
    /// The full HTTP router over this App — every route behind the real auth / governance guards,
    /// exactly as the composition root mounts it.
    fn router(self: Arc<Self>) -> axum::Router;
    /// The router PLUS the live handle it reads through, with the production default inbound
    /// limits (body cap, concurrency, server-timing) — for a test that swaps a second App onto a
    /// served deployment mid-stream.
    fn router_with_handle(self: Arc<Self>) -> (axum::Router, Arc<dyn EngineHandle>);
    /// Mint the neutral host over this pinned snapshot.
    fn engine_host(self: Arc<Self>) -> Arc<dyn EngineHost>;
    /// Wrap this snapshot in a fresh swappable handle.
    fn handle(self: Arc<Self>) -> Arc<dyn EngineHandle>;
    /// The breaker cell state under `key` (the plane's own `tool:<server>` spelling), lane 0.
    fn breaker_state(&self, key: &str) -> BreakerState;
    /// The breaker cell state under `key` at pool lane `lane`.
    fn breaker_state_at(&self, key: &str, lane: usize) -> BreakerState;
    /// Close the breaker cell under `key` (lane 0) by hand — the supervisor's reset.
    fn breaker_reset(&self, key: &str);
    /// The mounted data-plane route paths — which paths appear — so a plane asserts what an
    /// (un)configured deployment mounts.
    fn data_route_paths(&self) -> Vec<String>;
    /// The host-owned structural URL guard the `guard_url` host slot drives, over this App's
    /// policy: `Ok(())` admissible, else the neutral refusal class and the offending host/url.
    fn guard_url(&self, url: &str, allow_private: bool) -> Result<(), (GuardClass, String)>;
}

/// THE TEST-APP BUILDER, object-safe: every engine-side fixture verb a plane's tests drove on the
/// concrete fixture, as a `&mut self` setter (chaining sugar is on [`TestAppKitExt`]). A
/// [`TestAppSeam`], so a plane's own test-kit extension (its `.mcp(cfg)`-style builders over the
/// scratch/finalizer seam) applies to it unchanged.
pub trait TestAppKit: TestAppSeam {
    /// Attach a governance registry (keys, budgets, metering) to the built App.
    fn set_governance(&mut self, gov: Arc<dyn GovKit>);
    /// Register one `hooks:` entry from its config document, through the engine's own parser.
    fn add_hook(&mut self, name: &str, def: serde_json::Value);
    /// Attach a loaded hook plugin environment (from [`EngineTestKit::hook_env`]).
    fn set_hook_env(&mut self, env: HookEnvHandle);
    /// Seed the whole `groups:` tree at once from config documents (registry AND cost model, the
    /// production invariant), through the engine's own parser.
    fn set_groups_tree(&mut self, groups: BTreeMap<String, serde_json::Value>);
    /// The built-in virtual-key auth chain (`keys`) as the whole data-plane chain.
    fn use_keys_chain(&mut self);
    /// The test-only identity-provider stand-in as the whole data-plane chain.
    fn use_idp_chain(&mut self);
    /// Define a `tool_pools:` entry over registered server names.
    fn add_tool_pool(&mut self, name: &str, members: &[&str], repeatable: &[&str]);
    /// Add one upstream LANE (`model` served by `protocol` at `base_url`) to the fallback plane.
    fn add_lane(&mut self, model: &str, protocol: &'static str, base_url: &str);
    /// The durable store the plane's write-through sinks (spent ledger, demotion record) land in.
    fn set_durable_store(&mut self, store: Arc<dyn Store>);
    /// Build the App.
    fn build(self: Box<Self>) -> Arc<dyn EngineApp>;
}

/// CHAINING SUGAR over [`TestAppKit`] for the boxed builder, so a test keeps the fluent
/// `test_app().mcp(&cfg).governance(gov).build()` shape.
pub trait TestAppKitExt: Sized {
    /// Chaining twin of [`TestAppKit::set_governance`].
    fn governance(self, gov: Arc<dyn GovKit>) -> Self;
    /// Chaining twin of [`TestAppKit::add_hook`].
    fn hook(self, name: &str, def: serde_json::Value) -> Self;
    /// Chaining twin of [`TestAppKit::set_hook_env`].
    fn hook_env(self, env: HookEnvHandle) -> Self;
    /// Chaining twin of [`TestAppKit::set_groups_tree`].
    fn groups_tree(self, groups: BTreeMap<String, serde_json::Value>) -> Self;
    /// Chaining twin of [`TestAppKit::use_keys_chain`].
    fn keys_chain(self) -> Self;
    /// Chaining twin of [`TestAppKit::use_idp_chain`].
    fn idp_chain(self) -> Self;
    /// Chaining twin of [`TestAppKit::add_tool_pool`].
    fn tool_pool(self, name: &str, members: &[&str], repeatable: &[&str]) -> Self;
    /// Chaining twin of [`TestAppKit::add_lane`].
    fn lane(self, model: &str, protocol: &'static str, base_url: &str) -> Self;
    /// Chaining twin of [`TestAppKit::set_durable_store`].
    fn durable_store(self, store: Arc<dyn Store>) -> Self;
}

impl TestAppKitExt for Box<dyn TestAppKit> {
    fn governance(mut self, gov: Arc<dyn GovKit>) -> Self {
        self.set_governance(gov);
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
    fn durable_store(mut self, store: Arc<dyn Store>) -> Self {
        self.set_durable_store(store);
        self
    }
}

// The boxed builder IS a `TestAppSeam` (delegating), so a plane's test-kit extension — written over
// `A: TestAppSeam` — applies to `Box<dyn TestAppKit>` exactly as it does to the engine's concrete
// fixture inside the engine's own test binary.
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
    fn configured_public_url(&self) -> Option<&str> {
        (**self).configured_public_url()
    }
    fn card_issuer(&self, plane_key: &'static str) -> Option<CardIssuer> {
        (**self).card_issuer(plane_key)
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

/// THE ENGINE'S TEST-KIT PROVIDER: the process-wide services and fixture constructors a plane's tests
/// reach that are the engine's and nobody else's. The engine implements it once; a plane's test tree
/// binds that one implementation in one function and reaches everything else through it.
pub trait EngineTestKit: Send + Sync {
    /// Install the engine's metrics recorder with a test-length retention window (idempotent).
    fn metrics_init(&self);
    /// A fresh test-App builder.
    fn new_app(&self) -> Box<dyn TestAppKit>;
    /// A governance registry over `store`, with an optional operator admin token and an optional
    /// bearer-token signer (a signer makes `mint_signed` possible).
    fn governance(
        &self,
        store: Arc<dyn Store>,
        admin_token: Option<String>,
        signer: Option<TokenSigner>,
    ) -> Result<Arc<dyn GovKit>, String>;
    /// A hook plugin environment loading the hermetic test hook cdylib under `aliases`, declaring
    /// `prompt`/`user` intent. `None` when the cdylib is not built (the caller decides whether that
    /// is a skip or a failure).
    fn hook_env(&self, aliases: &[&str], prompt: HookNeed, user: HookNeed)
        -> Option<HookEnvHandle>;

    // ── the process-wide per-call log ──────────────────────────────────────────────────────────
    /// The next sequence number `principal`'s call chain will mint.
    fn call_next_seq(&self, principal: &str) -> u64;
    /// Register the process-wide `call` stream with no sink (the boot step a harness that does not
    /// boot through the plane's hydrate hook has to do itself so an emit mints a seq).
    fn ensure_call_stream_registered(&self);
    /// Aim the process-wide call sink at `store` (`None` detaches it).
    fn aim_call_sink(&self, store: Option<Arc<dyn PlaneStore>>);
    /// Verify one principal's persisted call chain against its own hashes.
    fn verify_call_rows(&self, rows: &[CallRecorded]) -> Result<(), String>;

    // ── the process-wide admin audit ring ─────────────────────────────────────────────────────
    /// The highest audit sequence number appended so far (0 when empty) — monotonic for the process
    /// lifetime, unlike the ring's length, which saturates.
    fn audit_high_water_seq(&self) -> u64;
    /// Append one admin audit row now, attributed to `principal` — the decoy a regression guard
    /// plants to prove a lookup is scoped.
    fn emit_admin_audit_now(&self, action: &str, resource: &str, outcome: &str, principal: &str);
    /// Every retained audit row, newest first.
    fn audit_entries(&self) -> Vec<AuditRecord>;

    // ── the admin API contract ────────────────────────────────────────────────────────────────
    /// The scope bar the admin contract table assigns `(method, path)`.
    fn admin_required_scope(&self, method: &axum::http::Method, path: &str) -> AdminScope;
    /// Run the admin write path's typed parse of one named-map definition under `section` (the
    /// plane's declared config-section key) — the same grammar the file path enforces.
    fn validate_named_def(
        &self,
        section: &'static str,
        name: &str,
        def: &serde_json::Value,
    ) -> Result<(), String>;

    // ── the store-plugin fixture (the real cdylib, over the real plugin C ABI) ────────────────
    /// A private durable file for one test and the plugin config selecting the fixture's on-disk
    /// mode.
    fn durable_store_cfg(&self, tag: &str) -> (PathBuf, String);
    /// Open the example store plugin over the ABI with `cfg` — a fresh dlopen per call (a restart).
    fn open_store_plugin(&self, cfg: &str) -> Arc<dyn Store>;
}
