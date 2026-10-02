// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ROWS (WIRE-AUTH): [`AuthRows`] answers and opens the plugin registry's `kind: auth` rows
//! on the process's one dispatcher. The composition root implements the contract's `AuthAxis` over
//! it and installs that axis on the kernel (`install_auth_axis`, ARCHITECT ruling 2026-09-29: the
//! opener seam, impl in the root), so the kernel's identity chain opens auth instances naming
//! neither this crate nor the root.
//!
//! A row opens on the auth kind's MEMORY ABI (`abi::auth`, through [`AuthInstance`]) when it is a
//! linked door ([`crate::registry::LinkedEntry::Door`]) or a dropped-in library exporting
//! `busbar_plugin_door`.
//!
//! M6-COLD-DELETE: a row still on the COLD auth lane (a linked `BUSBAR_COLD_ENTRY`, or a dropped-in
//! library with no door) opens through [`ColdAuth`], the not-yet-ported plugins' adapter (ARCHITECT
//! ruling 2026-09-29, WIRE-AUTH Q3 option B: the cold path stays only until the oidc/github/ldap
//! ports land). It and `crate::auth` are deleted at M6.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::auth::FACT_CACHEABLE;
use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::auth::{AuthModule, AuthVerdict};
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};

use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{load_dropped_bytes, load_linked, Bind, Dispatcher, LinkedRow, Plugin};
use crate::registry::LoadablePlugin;
use crate::PluginRegistry;

/// The auth kind's word in a registry row's manifest (`kind: auth`).
const AUTH: &str = "auth";

/// The host's clamp on an auth Statement's `max_inflight`.
const MAX_INFLIGHT_CAP: u32 = 64;

/// How a row opens.
enum Door {
    /// On the memory ABI: the bound plugin and its envelope sink.
    Memory(Plugin<Auth>, AuthSink),
    /// M6-COLD-DELETE: on the cold lane.
    Cold,
}

/// The auth rows of `registry`, opening instances on `dispatcher`.
pub struct AuthRows {
    registry: &'static PluginRegistry,
    dispatcher: Arc<Dispatcher>,
}

impl std::fmt::Debug for AuthRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRows").finish_non_exhaustive()
    }
}

impl AuthRows {
    /// The axis over `registry`'s auth rows, on `dispatcher`.
    #[must_use]
    pub fn new(registry: &'static PluginRegistry, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            registry,
            dispatcher,
        }
    }

    /// The `kind: auth` row config names by `module`: the registry's name or manifest alias, else
    /// an alias the row's Statement states (its alias rewrites).
    fn row(&self, module: &str) -> Option<&'static LoadablePlugin> {
        self.registry
            .resolve(module)
            .filter(|p| p.manifest.kind == AUTH)
            .or_else(|| {
                let rows = self
                    .registry
                    .linked()
                    .iter()
                    .chain(self.registry.loadable());
                rows.filter(|p| p.manifest.kind == AUTH)
                    .find(|p| stated_aliases(p).iter().any(|a| a == module))
            })
    }

    /// Load `row`'s door for the instance `label`, bound to the dispatcher and admitted against
    /// the Statement the row states (a linked door's own rendering, a dropped plugin's signed one).
    fn load(&self, row: &LoadablePlugin, label: &str) -> Result<Door, String> {
        let name = &row.manifest.name;
        let refused = |e: String| format!("auth plugin '{name}': {e}");
        let sink = AuthSink::new(name);
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: sink.bind(),
            dispatcher: self.dispatcher.adopter(),
            conns: None,
        };
        let loaded = match row.door() {
            Some(door) => LinkedRow::of(door).and_then(|r| load_linked::<Auth>(&r, bind)),
            None if row.image_is_cold_linked() => return Ok(Door::Cold),
            None => match row.manifest.stated_rendering().map_err(refused)? {
                // M6-COLD-DELETE: a dropped-in cold auth plugin states no Statement.
                None => return Ok(Door::Cold),
                Some(stated) => load_dropped_bytes::<Auth>(&row.lib_bytes, name, &stated, bind),
            },
        };
        let plugin = loaded.map_err(|e| refused(e.to_string()))?;
        Ok(Door::Memory(plugin, sink))
    }

    /// The config keys of the auth rows this build LINKS, in registration order.
    #[must_use]
    pub fn linked_names(&self) -> Vec<String> {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .map(|p| p.manifest.alias.clone())
            .collect()
    }

    /// Whether a `kind: auth` row answers `module`.
    #[must_use]
    pub fn answers(&self, module: &str) -> bool {
        self.row(module).is_some()
    }

    /// Whether `module` names a row this build LINKS.
    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .any(|p| p.manifest.alias == module || stated_aliases(p).iter().any(|a| a == module))
    }

    /// OPEN one instance of `module` over `settings` under the host's instance `label`.
    ///
    /// # Errors
    /// Why it will not open, naming the module.
    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        let row = self
            .row(module)
            .ok_or_else(|| format!("no `kind: auth` plugin answers to '{module}'"))?;
        match self.load(row, label)? {
            Door::Memory(plugin, sink) => {
                let (settings, secrets) = crate::auth_door::split_secrets(&plugin, settings);
                let text = settings.to_string();
                let opened = AuthInstance::open(
                    plugin,
                    sink,
                    self.dispatcher.clone(),
                    label,
                    text.as_bytes(),
                    secrets,
                )
                .map_err(|e| format!("auth plugin '{module}': {e}"))?;
                Ok(Arc::new(opened))
            }
            Door::Cold => {
                // The cold lane took its settings as text: a JSON string's own text, else the
                // document.
                let text = match settings {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let module = self.registry.open_auth(module, &text)?;
                Ok(Arc::new(ColdAuth::new(module)))
            }
        }
    }
}

/// The aliases `row`'s Statement states (its [`REWRITE_ALIAS`] rewrites; the design's One
/// Statement): a linked door's own rendering, a dropped plugin's signed one. A cold row states none.
/// A rendering that does not read back names nothing here; the load refuses it.
fn stated_aliases(row: &LoadablePlugin) -> Vec<String> {
    let stated = match row.door() {
        Some(door) => LinkedRow::of(door).ok().map(|r| r.statement),
        None => row.manifest.stated_rendering().ok().flatten(),
    };
    stated
        .and_then(|s| read(&s).ok())
        .map(|r| crate::boot::rewrites(&r, REWRITE_ALIAS).collect())
        .unwrap_or_default()
}

/// M6-COLD-DELETE: a not-yet-ported auth plugin on the cold lane, as [`AuthCalls`]. Its
/// `authenticate` is made on the caller's thread, as the kernel's chain has always made it, and
/// answered on the spot; the loader lends it no blocking thread (one memory ABI: no
/// `spawn_blocking` in the loader).
pub struct ColdAuth {
    module: Arc<dyn AuthModule>,
    name: String,
    facts: u32,
}

impl std::fmt::Debug for ColdAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdAuth")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ColdAuth {
    /// The adapter over an opened cold module.
    #[must_use]
    pub fn new(module: Box<dyn AuthModule>) -> Self {
        let facts = if module.cacheable() {
            FACT_CACHEABLE
        } else {
            0
        };
        Self {
            name: module.name().to_string(),
            module: Arc::from(module),
            facts,
        }
    }
}

/// A cold verdict as the chain reads it.
fn cold_verdict(v: AuthVerdict) -> Verified {
    match v {
        AuthVerdict::Identify(p) => Verified::Identity(VerifiedIdentity {
            subject: p.id,
            name: p.name,
            groups: p.roles,
            ttl_secs: p.ttl_secs,
            ..VerifiedIdentity::default()
        }),
        AuthVerdict::Reject => Verified::Reject,
        AuthVerdict::Pass => Verified::Pass,
    }
}

/// One cold verify: its credential as the cold lane took it. The host's request carries none.
fn cold_credential(_request: &VerifyRequest) -> Option<String> {
    None
}

impl AuthCalls for ColdAuth {
    fn name(&self) -> &str {
        &self.name
    }

    fn facts(&self) -> u32 {
        self.facts
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        let credential = cold_credential(request);
        // The cold lane names no strips: its verdict with its default decision.
        Some(cold_verdict(self.module.authenticate(credential.as_deref())).into())
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(ColdVerifying(self.verify_now(&request)))
    }

    fn refresh(&self) -> Result<u64, String> {
        // A cold plugin's verdicts are cached by the kernel (its `cacheable`), which the admin flush
        // reaches directly: nothing is held here.
        Ok(0)
    }
}

/// A cold verify, answered on the spot.
struct ColdVerifying(Option<VerifyAnswer>);

impl Future for ColdVerifying {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<VerifyAnswer> {
        Poll::Ready(self.0.take().unwrap_or_else(|| Verified::Failed.into()))
    }
}

impl Verifying for ColdVerifying {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        let mut cx = Context::from_waker(Waker::noop());
        match Pin::new(self).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/auth_axis_tests.rs"]
mod tests;
