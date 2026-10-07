// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INBOUND VERIFY UNDER A ROUTE'S AUTH SCHEME, AND THE REPLAY CLAIM EVERY INBOUND VERIFY MEETS.
//!
//! THE DESIGN §6 "Inbound verify": a verified identity may carry a replay key and a time to live,
//! and the verify caller claims the record (`auth-replay`, plugin/key, ttl) once; a key already
//! claimed is 401. [`claim_replay`] is that claim, the one the data-plane chain
//! ([`super::AuthMiddleware`]) and the public-route verify ([`verify_inbound`]) both make.
//!
//! Spec Part 3 "Inbound webhooks": a plane's public route may name the auth SCHEME its callers are
//! verified under; the kernel runs the inbound verify of the auth instances serving that scheme
//! over the request's head and its whole bounded body before the plane's `serve`. The plane names a
//! scheme, never an instance, and never sees the secret. Every denial answers alike (401): a
//! missing signature, a wrong one, a replay, and a scheme no instance serves are not told apart.

use std::sync::Arc;

use busbar_contract::auth_calls::{
    AuthCalls, Replay, Strip, Verified, VerifiedIdentity, VerifyRequest,
};
use busbar_contract::records::RecordStore;

/// The record kind a replay claim is made under.
pub const AUTH_REPLAY_KIND: &str = "auth-replay";

/// THE REPLAY CLAIM: `replay`'s key, under the verifying `plugin`, claimed once in `store` for its
/// time to live from `now` (whole seconds). `true` = this is the first sighting inside the window;
/// `false` = the key was already claimed, or the store could not answer (fail-closed). An empty key
/// claims nothing and admits.
#[must_use]
pub fn claim_replay(store: &dyn RecordStore, plugin: &str, replay: &Replay, now: u64) -> bool {
    if replay.key.is_empty() {
        return true;
    }
    let token = format!("{plugin}/{}", replay.key);
    let expires_at = now.saturating_add(replay.ttl_secs.max(1));
    matches!(
        store.redeem_plane_token(AUTH_REPLAY_KIND, &token, expires_at, now),
        Ok(true)
    )
}

/// What the public-route verify decided.
#[derive(Debug)]
pub enum InboundVerdict {
    /// An instance identified the caller, and its replay key (if any) was claimed for the first
    /// time. `strips` are the credential lines the verifiers named: the caller's head loses them
    /// before the plane is handed it.
    Identified {
        /// The identity.
        identity: Box<VerifiedIdentity>,
        /// The lines to strip.
        strips: Vec<Strip>,
    },
    /// Refused: no instance identified the caller, one rejected it, it failed to answer, or the
    /// identity's replay key was already claimed. Answered 401, every cause alike.
    Denied,
    /// An instance's `max_inflight` was full: the request was not queued. Answered 503.
    Overloaded,
}

/// THE PUBLIC-ROUTE VERIFY: `request` (at the `HeadBody` point) through each of `instances` in
/// order, the instances serving the route's scheme. The first identity admits once its replay key
/// is claimed in `store` (`None`: no store, so a replay-keyed identity is refused); a reject or a
/// failure stops, refused; a pass tries the next; none identifying is refused. `now` is the
/// request's one clock reading, whole seconds.
pub async fn verify_inbound(
    instances: &[Arc<dyn AuthCalls>],
    request: &VerifyRequest,
    store: Option<&dyn RecordStore>,
    now: u64,
) -> InboundVerdict {
    let mut strips = Vec::new();
    for calls in instances {
        let answer = Box::into_pin(calls.verify(request.clone())).await;
        strips.extend(answer.strips.iter().cloned());
        match answer.verified {
            Verified::Identity(identity) => {
                if let Some(replay) = identity.replay.as_deref() {
                    let claimed = store.is_some_and(|s| claim_replay(s, calls.name(), replay, now));
                    if !claimed {
                        return InboundVerdict::Denied;
                    }
                }
                return InboundVerdict::Identified {
                    identity: Box::new(identity),
                    strips,
                };
            }
            Verified::Pass => {}
            Verified::Overloaded => return InboundVerdict::Overloaded,
            Verified::Reject | Verified::Failed => return InboundVerdict::Denied,
        }
    }
    InboundVerdict::Denied
}

/// The scheme an auth plugin named `module` serves: its name with the auth kind's crate prefix
/// struck (THE DESIGN §6: the mechanism-named `busbar-auth-webhook-signature` serves the scheme
/// `webhook-signature`); a name without the prefix is its own scheme.
#[must_use]
pub fn scheme_of(module: &str) -> &str {
    module.strip_prefix("busbar-auth-").unwrap_or(module)
}

/// Whether some `identity-providers:` instance serves `scheme`: the configuration fact a public
/// route's scheme is refused without.
#[must_use]
pub fn configured(providers: &crate::config::IdentityProviders, scheme: &str) -> bool {
    providers.values().any(|p| scheme_of(&p.module) == scheme)
}

/// Opens one instance: `(module, host label, resolved settings)`.
type Opener =
    dyn Fn(&str, &str, &serde_json::Value) -> Result<Arc<dyn AuthCalls>, String> + Send + Sync;

/// THE INSTANCES SERVING EACH SCHEME, for one generation: the `identity-providers:` entries whose
/// module serves it, opened on the auth axis the first time a request names the scheme (an entry no
/// route names is never opened, as 1.5.5 opened no provider nothing referenced), each with its own
/// settings, its secret references resolved for that one crossing. Rebuilt with every App.
pub struct InboundSchemes {
    /// `(name, module, settings)` of every configured provider.
    providers: Vec<(String, String, serde_json::Map<String, serde_json::Value>)>,
    resolver: Option<Arc<dyn busbar_contract::secret::SecretResolve + Send + Sync>>,
    opener: Option<Box<Opener>>,
    opened: std::sync::Mutex<std::collections::HashMap<String, Vec<Arc<dyn AuthCalls>>>>,
}

impl std::fmt::Debug for InboundSchemes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundSchemes")
            .field("configured", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl InboundSchemes {
    /// None configured: every scheme is served by nothing.
    #[must_use]
    pub fn none() -> Self {
        Self {
            providers: Vec::new(),
            resolver: None,
            opener: None,
            opened: std::sync::Mutex::default(),
        }
    }

    /// `providers`, opened on `registry`'s auth axis with their settings resolved by `resolver`.
    #[must_use]
    pub fn new(
        providers: &crate::config::IdentityProviders,
        registry: Arc<busbar_plugin_loader::PluginRegistry>,
        resolver: Arc<dyn busbar_contract::secret::SecretResolve + Send + Sync>,
    ) -> Self {
        let axis = std::sync::OnceLock::new();
        let opener = move |module: &str, label: &str, settings: &serde_json::Value| {
            let axis: &Option<Arc<dyn busbar_contract::auth_calls::AuthAxis>> =
                axis.get_or_init(|| crate::preflight::auth_axis(registry.clone()));
            axis.as_ref()
                .ok_or_else(|| format!("no `kind: auth` plugin answers to '{module}'"))?
                .open(module, label, settings)
        };
        Self {
            providers: providers
                .iter()
                .map(|(name, p)| (name.clone(), p.module.clone(), p.settings.clone()))
                .collect(),
            resolver: Some(resolver),
            opener: Some(Box::new(opener)),
            opened: std::sync::Mutex::default(),
        }
    }

    /// Instances already opened, by scheme (a test's, or a composition that opened its own).
    #[must_use]
    pub fn opened(by_scheme: std::collections::HashMap<String, Vec<Arc<dyn AuthCalls>>>) -> Self {
        Self {
            opened: std::sync::Mutex::new(by_scheme),
            ..Self::none()
        }
    }

    /// The instances serving `scheme`, opened once. A provider that will not open is left out and
    /// logged (its requests then meet the instances that did open, or none: refused).
    pub fn instances(&self, scheme: &str) -> Vec<Arc<dyn AuthCalls>> {
        let mut opened = self
            .opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(found) = opened.get(scheme) {
            return found.clone();
        }
        let (Some(open), Some(resolver)) = (&self.opener, &self.resolver) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (name, module, settings) in &self.providers {
            if scheme_of(module) != scheme {
                continue;
            }
            let opened_one = crate::config::secret::resolve_settings(settings, resolver.as_ref())
                .map_err(|e| format!("identity-providers.{name} settings: {e}"))
                .and_then(|resolved| {
                    open(
                        module,
                        &format!("identity-providers.{name}"),
                        &serde_json::Value::Object(resolved),
                    )
                });
            match opened_one {
                Ok(calls) => found.push(calls),
                Err(e) => tracing::error!(
                    provider = %name,
                    scheme,
                    error = %e,
                    "an inbound verifier did not open; its scheme's requests are refused without it"
                ),
            }
        }
        opened.insert(scheme.to_string(), found.clone());
        found
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod tests;
