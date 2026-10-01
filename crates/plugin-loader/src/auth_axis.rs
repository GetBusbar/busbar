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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::auth::FACT_CACHEABLE;
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::auth::{AuthModule, AuthVerdict};
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyRequest, Verifying,
};

use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{
    load_dropped_bytes, load_linked, Bind, Dispatcher, LoadError, ManifestFacts, Plugin,
};
use crate::registry::LoadablePlugin;
use crate::PluginRegistry;

/// The auth kind's name in the registry.
const AUTH: &str = busbar_contract::abi::cold::kind::AUTH;

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

    fn row(&self, module: &str) -> Option<&'static LoadablePlugin> {
        self.registry
            .resolve(module)
            .filter(|p| p.manifest.kind == AUTH)
    }

    /// Load `row`'s door, bound to the dispatcher.
    fn load(&self, row: &LoadablePlugin) -> Result<Door, String> {
        let name = &row.manifest.name;
        let sink = AuthSink::new(name);
        let bind = Bind {
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: sink.bind(),
            dispatcher: self.dispatcher.adopter(),
        };
        let loaded = match row.door() {
            Some(door) => load_linked::<Auth>(door, bind),
            None if row.image_is_cold_linked() => return Ok(Door::Cold),
            None => {
                let facts = ManifestFacts {
                    mechanism_version: MECHANISM_VERSION,
                    kind: KindCode::Auth,
                    kind_abi: KindCode::Auth.abi_version(),
                };
                match load_dropped_bytes::<Auth>(&row.lib_bytes, name, &facts, bind) {
                    // M6-COLD-DELETE: a dropped-in cold auth plugin states the same number and no
                    // door.
                    Err(LoadError::NoDoor(_)) => return Ok(Door::Cold),
                    other => other,
                }
            }
        };
        let plugin = loaded.map_err(|e| format!("auth plugin '{name}': {e}"))?;
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
            .any(|p| p.manifest.kind == AUTH && p.manifest.alias == module)
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
        match self.load(row)? {
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

/// The most cold `verify`s in flight across the process: past it a verify is
/// [`Verified::Overloaded`], never queued behind a wedged plugin.
const COLD_MAX_INFLIGHT: u32 = 64;

/// Cold verifies in flight.
static COLD_INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// M6-COLD-DELETE: a not-yet-ported auth plugin on the cold lane, as [`AuthCalls`]. Its
/// `authenticate` is a blocking call over the cold ABI, so it is never made on the caller's thread
/// ([`AuthCalls::verify_now`] answers `None`) and a submitted one runs on the runtime's blocking pool.
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

    fn verify_now(&self, _request: &VerifyRequest) -> Option<Verified> {
        None
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        let module = self.module.clone();
        let credential = cold_credential(&request);
        drop(request);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // No runtime to lend a blocking thread: the call is made here, as the cold lane
            // always was.
            return Box::new(ColdVerifying::Ready(Some(cold_verdict(
                module.authenticate(credential.as_deref()),
            ))));
        };
        if COLD_INFLIGHT.fetch_add(1, Ordering::AcqRel) >= COLD_MAX_INFLIGHT {
            COLD_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
            return Box::new(ColdVerifying::Ready(Some(Verified::Overloaded)));
        }
        let handle = runtime.spawn_blocking(move || {
            let v = cold_verdict(module.authenticate(credential.as_deref()));
            COLD_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
            v
        });
        Box::new(ColdVerifying::Running(handle))
    }

    fn refresh(&self) -> Result<u64, String> {
        // A cold plugin's verdicts are cached by the kernel (its `cacheable`), which the admin flush
        // reaches directly: nothing is held here.
        Ok(0)
    }
}

/// A cold verify: answered, or running on the blocking pool.
enum ColdVerifying {
    Ready(Option<Verified>),
    Running(tokio::task::JoinHandle<Verified>),
}

impl Future for ColdVerifying {
    type Output = Verified;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Verified> {
        match &mut *self {
            Self::Ready(v) => Poll::Ready(v.take().unwrap_or(Verified::Failed)),
            // A panicking plugin (a join error) fails closed.
            Self::Running(h) => Pin::new(h).poll(cx).map(|r| r.unwrap_or(Verified::Failed)),
        }
    }
}

impl Verifying for ColdVerifying {
    fn settled(&mut self) -> Option<Verified> {
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
