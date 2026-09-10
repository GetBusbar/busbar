// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAT ADAPTER — the composition's binding of the hook policy engine's port
//! ([`busbar_core_policy::HookSeat`]) over the hybrid-ABI plugin registry.
//!
//! The engine states what it needs of a hook plugin in its own words — the manifest's declared
//! needs, and "open this reference as a policy" — and names no loader, no signer and no ranking
//! plugin. This module is where those words meet the plugin tooling: a `plugin:` reference is
//! resolved out of the validated [`PluginRegistry`], its signed manifest's `needs:` ladder is read
//! onto the engine's [`Need`] ladder, and an open goes through the loader's `DlopenPolicy` with the
//! engine's own [`Projectors`] bridged onto the loader's `HookProjectors`. The adapter is 1:1 with
//! the registry it wraps — one seat is one plugin set — which is what keeps the engine's
//! single-flight resolution cache honest: it keys on the SEAT's address and holds it weakly, so a
//! `plugins refresh` or a reload (a new registry, hence a new seat) can never be served the dead
//! one's transport.
//!
//! The built-in ranking strategies are a plugin too, and whether they are compiled in is THIS
//! crate's `hooks-ranking` feature: [`native_resolver`] hands the engine `native_policy` under it
//! and `|_| None` without it, so `route: cheapest` on a build without the plugin stays the boot-time
//! config error `config_validate` makes it.

use busbar_core_policy::{
    DeclaredNeeds, HookSeat, NativeResolver, Need, Projectors, RoutingPolicy,
};
use busbar_plugin_loader::PluginRegistry;
use std::sync::Arc;

/// The validated plugin registry, seated behind the engine's port.
pub struct RegistrySeat(pub Arc<PluginRegistry>);

fn need_of(level: busbar_plugin_sign::NeedLevel) -> Need {
    match level {
        busbar_plugin_sign::NeedLevel::No => Need::No,
        busbar_plugin_sign::NeedLevel::Ro => Need::Ro,
        busbar_plugin_sign::NeedLevel::Rw => Need::Rw,
    }
}

impl HookSeat for RegistrySeat {
    fn declared_needs(&self, plugin_ref: &str) -> Option<DeclaredNeeds> {
        let p = self.0.resolve(plugin_ref)?;
        Some(DeclaredNeeds {
            prompt: need_of(p.manifest.needs.prompt),
            user: need_of(p.manifest.needs.user),
        })
    }

    fn open(
        &self,
        plugin_ref: &str,
        settings_json: &str,
        name: &str,
        projectors: &Arc<Projectors>,
    ) -> Result<Arc<dyn RoutingPolicy>, String> {
        self.0
            .open_hook(plugin_ref, settings_json, name, bridge(projectors))
    }
}

/// The engine's projectors as the loader's: each loader closure calls the engine's. Built per open;
/// six boxed closures over one `Arc` clone, beside a `dlopen`.
fn bridge(p: &Arc<Projectors>) -> Arc<busbar_plugin_loader::hook::HookProjectors> {
    let (a, b, c, d, e, f) = (
        p.clone(),
        p.clone(),
        p.clone(),
        p.clone(),
        p.clone(),
        p.clone(),
    );
    Arc::new(busbar_plugin_loader::hook::HookProjectors {
        decide: Box::new(move |req, cands, ctx| (a.decide)(req, cands, ctx)),
        transform: Box::new(move |req| (b.transform)(req)),
        normalize: Box::new(move |v, cands| (c.normalize)(v, cands)),
        transform_outcome: Box::new(move |v| (d.transform_outcome)(v)),
        status: Box::new(move |v| (e.status)(v)),
        describe_schema: Box::new(move |v| (f.describe_schema)(v)),
    })
}

/// The built-in ranking resolver this build hands the engine.
pub fn native_resolver() -> NativeResolver {
    #[cfg(feature = "hooks-ranking")]
    {
        Arc::new(busbar_hooks_ranking::native_policy)
    }
    #[cfg(not(feature = "hooks-ranking"))]
    {
        Arc::new(|_: &str| None)
    }
}

/// The hook environment as this crate builds it: the engine's [`busbar_core_policy::HookEnv`],
/// bound over a [`RegistrySeat`], beside the registry it was bound over — which the admin surface
/// still reads manifests and schemas out of directly (`GET /plugins/{name}/schema`, the hook
/// contract report), no `dlopen`, no instance.
///
/// Derefs to the engine's environment, so every resolver and control-plane read takes it as-is.
#[derive(Clone)]
pub struct HookEnv {
    /// The registry the seat is bound over.
    pub registry: Arc<PluginRegistry>,
    engine: busbar_core_policy::HookEnv,
}

impl HookEnv {
    /// Seat `registry` behind the engine's port and bundle it with this build's ranking resolver
    /// and the secret resolver. Every boot/reload builds a fresh one.
    pub fn new(
        registry: Arc<PluginRegistry>,
        secret_resolver: Arc<crate::config::secret::SecretResolver>,
    ) -> Self {
        let seat: Arc<dyn HookSeat> = Arc::new(RegistrySeat(registry.clone()));
        Self::bound(registry, seat, secret_resolver)
    }

    /// [`HookEnv::new`] over a seat the caller already holds — the dlopen battery's ABA proof
    /// needs to choose the seat's allocation itself.
    pub(crate) fn bound(
        registry: Arc<PluginRegistry>,
        seat: Arc<dyn HookSeat>,
        secret_resolver: Arc<crate::config::secret::SecretResolver>,
    ) -> Self {
        HookEnv {
            registry,
            engine: busbar_core_policy::HookEnv::new(seat, native_resolver(), secret_resolver),
        }
    }
}

impl std::ops::Deref for HookEnv {
    type Target = busbar_core_policy::HookEnv;
    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}
