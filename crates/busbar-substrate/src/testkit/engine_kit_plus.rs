// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE TEST-KIT, WIDENED — the verbs a plane's tests drive on the engine fixture beyond the
//! base [`super::engine_kit`] seam. The base kit builds the App, mints keys, reads the call log and
//! audit ring and reaches the built App's router, host and breaker cells; a plane whose tests assert
//! on WHAT WAS MOUNTED (the public URL it was built for, its mount path, the audience bound to that
//! mount, the auth bar on each data route), read the engine's metrics exposition, force a breaker
//! cell open, load a TLS crypto provider, or resolve a `file:` secret the way the engine does, needs
//! these as well.
//!
//! Same rule as the base kit: NO process-wide static and NO `install_*` here. The engine implements
//! these traits for the same fixture types it implements the base kit for, so a plane's test tree
//! binds ONE function (`fn engine() -> &'static dyn EngineTestKitPlus`) — the one line in that tree
//! that names the engine crate — and reaches every verb of both kits through it.
//!
//! Every type on these signatures is neutral: the substrate's own [`PlaneAdmission`], the plugin
//! ABI's [`RouteAuth`], the store contract's [`SecretResolve`], `serde_json::Value` for the
//! documents the engine parses itself.

use super::engine_kit::{EngineApp, EngineTestKit, GovKit, HookEnvHandle, TestAppKit};
use super::TestAppSeam;
use crate::plane::registry::CardIssuer;
use crate::plane::PlaneAdmission;
use busbar_api::SecretResolve;
use busbar_plugin::cold::http_endpoint::RouteAuth;
use std::any::Any;
use std::sync::Arc;

/// What the engine's named-map config chassis knows about one section — the facts a plane asserts
/// to prove its section is a first-class member of that chassis rather than a special case bolted
/// beside it (the router, the OpenAPI generator and the overlay applier all enumerate the chassis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedMapSectionFacts {
    /// The section's config key (`agents`, `tools`, …).
    pub key: &'static str,
    /// The admin API path root the chassis serves the section under.
    pub path_root: String,
    /// Whether an entry must name a plugin module (a plane's remote endpoint names none).
    pub requires_module: bool,
    /// Whether the section carries an admin trust ceiling (only identity providers do).
    pub has_trust_ceiling: bool,
}

/// A BUILT test App, widened: the mount table, the audience bindings, the route table with its auth
/// bar, and a forced-open breaker cell. Everything the base [`EngineApp`] offers is reachable on it
/// unchanged (it is a supertrait).
pub trait EngineAppPlus: EngineApp {
    /// The path plane `key` is mounted at (its first claimed path), or `None` when the plane claimed
    /// no path in this deployment.
    fn mount_of(&self, key: &str) -> Option<String>;
    /// The RFC 8707 admission facts (audience, metadata document) bound to the plane that owns
    /// `path`, or `None` when nothing audience-bound is mounted there.
    fn admission_for(&self, path: &str) -> Option<PlaneAdmission>;
    /// The DATA router's route table exactly as it was built — every `(path, auth bar)` pair — so a
    /// plane asserts which of its routes are open and which take the data-plane bar.
    fn data_route_table(&self) -> Vec<(String, RouteAuth)>;
    /// Force the breaker cell under `key` at pool lane `lane` OPEN until `until` (seconds since the
    /// epoch) — the operator's "take this member out" the pool batteries reproduce.
    fn breaker_force_open(&self, key: &str, lane: usize, until: u64);
}

/// THE TEST-APP BUILDER, widened: the deployment's public URL and its candidate pools of registered
/// endpoints (the engine's `agent_pools:` section), and a `build` that hands back the widened App.
/// A [`TestAppKit`] (supertrait), so every base builder verb applies unchanged. A plane drives it
/// through [`AppBuilder`], which owns the chaining shape.
pub trait TestAppKitPlus: TestAppKit {
    /// The `public_url:` the deployment is reachable at — what a plane derives its served endpoint,
    /// its metadata document and its audience from.
    fn set_public_url(&mut self, url: &str);
    /// Define one `agent_pools:` entry over registered endpoint names.
    fn add_agent_pool(&mut self, name: &str, members: &[&str]);
    /// Build the App, widened.
    fn build_plus(self: Box<Self>) -> Arc<dyn EngineAppPlus>;
}

/// THE ENGINE'S TEST-KIT PROVIDER, widened. The base [`EngineTestKit`] is a supertrait, so the one
/// `&'static dyn EngineTestKitPlus` a plane binds serves both.
pub trait EngineTestKitPlus: EngineTestKit {
    /// A fresh test-App builder, widened.
    fn new_app_plus(&self) -> AppBuilder;
    /// The engine's metrics registry rendered as Prometheus exposition text (installing the
    /// recorder first if no test has yet), for a plane to sum its own series out of — see
    /// [`metric_sum`].
    fn metrics_render(&self) -> String;
    /// The bytes an operator's scrape receives, from the built-in prometheus exporter's own dispatch
    /// (its status and body) — the exact function the mounted `/metrics` route runs.
    fn scrape_exposition(&self) -> (u16, String);
    /// Install the process TLS crypto provider the engine's own listeners use (idempotent), for a
    /// test that stands up a rustls server of its own.
    fn install_crypto_provider(&self);
    /// The engine's secret resolver with only the built-in `env:` / `file:` modules — the resolver a
    /// deployment with no `kind: secret` plugin loaded runs.
    fn builtin_secret_resolver(&self) -> Box<dyn SecretResolve>;
    /// The metric family the engine counts every plane's front-door requests under (label keys:
    /// `plane`, `ingress_protocol`, `pool`, `outcome`).
    fn plane_request_family(&self) -> &'static str;
    /// The named-map chassis facts for the plane section keyed `section`, or `None` when the chassis
    /// does not enumerate that section at all.
    fn named_map_section_facts(&self, section: &'static str) -> Option<NamedMapSectionFacts>;
}

/// Sum every sample of the metric `name` in `exposition` whose label set carries ALL of `labels` —
/// the read-back a plane's counter assertions are made with. A sample line is `name{k="v",…} value`
/// or `name value`; a `name` that is merely a prefix of another family (`foo` vs `foo_total`) is not
/// matched.
pub fn metric_sum(exposition: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
    let frags: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
    exposition
        .lines()
        .filter(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .filter(|l| frags.iter().all(|f| l.contains(f.as_str())))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<f64>().ok())
        .sum()
}

/// THE WIDENED BUILDER a plane's tests chain on: `engine().new_app_plus().public_url(..)
/// .keys_chain().governance(gov).build()`. A concrete type over the engine's boxed
/// [`TestAppKitPlus`] so its chaining verbs are inherent methods (nothing to import, nothing for the
/// base kit's own `build` to shadow) and `build` hands back the WIDENED App. A [`TestAppSeam`]
/// (delegating), so a plane's own test-kit extension — written over `A: TestAppSeam` — applies to it
/// exactly as it does to the engine's concrete fixture.
pub struct AppBuilder {
    inner: Box<dyn TestAppKitPlus>,
}

impl AppBuilder {
    /// Wrap the engine's boxed builder. Only the engine's kit constructs one.
    pub fn new(inner: Box<dyn TestAppKitPlus>) -> Self {
        AppBuilder { inner }
    }
    /// Chaining twin of [`TestAppKitPlus::set_public_url`].
    #[must_use]
    pub fn public_url(mut self, url: &str) -> Self {
        self.inner.set_public_url(url);
        self
    }
    /// Chaining twin of [`TestAppKitPlus::add_agent_pool`].
    #[must_use]
    pub fn agent_pool(mut self, name: &str, members: &[&str]) -> Self {
        self.inner.add_agent_pool(name, members);
        self
    }
    /// Chaining twin of [`TestAppKit::set_governance`].
    #[must_use]
    pub fn governance(mut self, gov: Arc<dyn GovKit>) -> Self {
        self.inner.set_governance(gov);
        self
    }
    /// Chaining twin of [`TestAppKit::add_hook`].
    #[must_use]
    pub fn hook(mut self, name: &str, def: serde_json::Value) -> Self {
        self.inner.add_hook(name, def);
        self
    }
    /// Chaining twin of [`TestAppKit::set_hook_env`].
    #[must_use]
    pub fn hook_env(mut self, env: HookEnvHandle) -> Self {
        self.inner.set_hook_env(env);
        self
    }
    /// Chaining twin of [`TestAppKit::use_keys_chain`].
    #[must_use]
    pub fn keys_chain(mut self) -> Self {
        self.inner.use_keys_chain();
        self
    }
    /// Build the App, widened.
    pub fn build(self) -> Arc<dyn EngineAppPlus> {
        self.inner.build_plus()
    }
}

impl TestAppSeam for AppBuilder {
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn Any>,
    ) -> &mut dyn Any {
        self.inner.plane_scratch_any(key, init)
    }
    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn Any>> {
        self.inner.take_plane_scratch_any(key)
    }
    fn register_plane_finalizer(&mut self, f: Box<dyn FnOnce(&mut dyn TestAppSeam)>) {
        self.inner.register_plane_finalizer(f)
    }
    fn configured_public_url(&self) -> Option<&str> {
        self.inner.configured_public_url()
    }
    fn card_issuer(&self, plane_key: &'static str) -> Option<CardIssuer> {
        self.inner.card_issuer(plane_key)
    }
    fn install_plane_runtime(&mut self, key: &'static str, rt: Arc<dyn Any + Send + Sync>) {
        self.inner.install_plane_runtime(key, rt)
    }
    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) {
        self.inner.mount_plane(key, path, wire)
    }
    fn admit_plane(&mut self, key: &'static str, admission: PlaneAdmission) {
        self.inner.admit_plane(key, admission)
    }
    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    ) {
        self.inner
            .set_container_hooks(plane_key, containers, section)
    }
    fn set_plane_defs_any(&mut self, plane_key: &'static str, defs: Arc<dyn Any + Send + Sync>) {
        self.inner.set_plane_defs_any(plane_key, defs)
    }
}
