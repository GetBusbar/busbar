// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE AS A RUNNING THING: what the operator's `agents:` section lowers to, and the one
//! object whose EXISTENCE is the answer to "is this deployment an A2A plane?".
//!
//! ## Absent config means absent plane, not a disabled one
//!
//! [`A2aPlane::from_config`] returns `None` when no agent is configured. That is the whole gate:
//! a deployment with no `agents:` section holds no registry, spawns no job and mounts no route, so
//! "is the A2A plane running here?" is answered by the mounted surface rather than by a boolean an
//! operator has to trust. The alternative — always build the plane and check a flag on every path —
//! puts the answer in as many places as there are paths.
//!
//! ## INTENT is lowered once; ACCUMULATION lives here and only here
//!
//! [`super::config::AgentDefCfg`] is what the operator wrote and may edit. An
//! [`super::registry::AgentRegistration`] is that intent PLUS everything that has since been
//! observed: the last sighting, the cached card, the re-verification ledger, the breaker's window.
//! The split is the same one `AgentDefCfg`'s own doc draws, and this type is where the second half
//! actually lives — behind one `RwLock`, because a re-verification sweep mutates every registration
//! it looks at and a reader that saw half a sweep would be reading a registry that never existed.
//!
//! ## Nothing here comes into existence trusted
//!
//! Every registration is built by `AgentRegistration::registered`, which is the fail-closed floor:
//! `Pending`, no pin approved, no card cached, nothing delegable. A pin an operator DECLARED in
//! config is deliberately NOT lifted into an approval here — [`super::config::declared_pin`] can
//! read one, but an approval is a statement about a document that was actually SEEN, and turning a
//! config value into one at boot would approve a card nobody has fetched. The `connect` verb
//! captures the fingerprint and a human approves it; that ordering is the trust root, not a
//! formality.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use super::config::{AgentPinCfg, AgentsCfg, DEFAULT_RECOVERY_BACKOFF_MS};
use super::fetch::FetchPolicy;
use super::registry::AgentRegistration;

/// THE PLANE. Built once per config generation; `None` when this deployment fronts no agents.
pub(crate) struct A2aPlane {
    /// busbar's public base origin, carried so the card-serving path has ONE reading of it. `None`
    /// is a serving-time refusal ([`super::serve::ServeError::BadPublicUrl`]) rather than a boot
    /// failure: an operator may configure `agents:` for the DELEGATING direction alone, and
    /// refusing to boot would make the receiving side's requirement the whole plane's.
    public_url: Option<String>,
    /// The card-fetch policy every pass on this plane uses. One reading, so the sweep and an
    /// operator-driven `connect` cannot guard differently.
    fetch_policy: FetchPolicy,
    /// The operator's trust roots, by agent id. Held apart from the registrations because a pin is
    /// INTENT: it is re-read from config on every apply, and a registration's accumulated half is
    /// not.
    pins: BTreeMap<String, AgentPinCfg>,
    /// THE REGISTRY. One lock over the whole vector rather than one per entry: a sweep walks all of
    /// them, and a reader that saw a half-applied sweep would be reading a registry state that
    /// never existed at any instant.
    registrations: RwLock<Vec<AgentRegistration>>,
}

impl A2aPlane {
    /// LOWER `agents:` INTO A RUNNING REGISTRY, or answer that there is no plane here.
    ///
    /// Returns `None` when the section defines no agent. An `agents:` section carrying only the
    /// reserved section-level keys (`hooks:`, `upstream_credentials:`) is likewise no plane: those
    /// keys are defaults FOR agents, and defaults for an empty set are not a deployment that fronts
    /// anything.
    ///
    /// A per-agent cadence that does not parse is not reachable here: `validate_agent` already
    /// refused it at boot and at the admin write path, so [`super::config::policy_for`]'s error is
    /// a state config validation has already excluded. It is still handled rather than unwrapped —
    /// the registration keeps the constructor's default cadence and says so — because a panic in a
    /// config lowering is a panic on the operator's next apply.
    pub(crate) fn from_config(cfg: &AgentsCfg, public_url: Option<&str>) -> Option<Arc<Self>> {
        if cfg.agents.is_empty() {
            return None;
        }
        let mut pins = BTreeMap::new();
        let mut registrations = Vec::with_capacity(cfg.agents.len());
        for (name, def) in &cfg.agents {
            // THE FAIL-CLOSED FLOOR, and the only constructor. Everything below adds INTENT to it;
            // nothing below makes it trusted.
            let mut reg = AgentRegistration::registered(name, &def.url);
            if let Some(v) = def.protocol_version.as_deref() {
                reg.protocol_version = v.to_string();
            }
            match super::config::policy_for(def, DEFAULT_RECOVERY_BACKOFF_MS) {
                Ok(policy) => reg.reverify = policy,
                Err(e) => tracing::warn!(
                    agent = %name,
                    error = %e,
                    "the re-verification cadence did not parse; this registration keeps the release \
                     default. Config validation should have refused this before boot."
                ),
            }
            reg.egress_scopes = def.egress_scopes.clone();
            reg.outbound_cred = def.upstream_credential.clone();
            pins.insert(name.clone(), def.pin.clone());
            registrations.push(reg);
        }
        Some(Arc::new(Self {
            public_url: public_url.map(str::to_string),
            fetch_policy: FetchPolicy::default(),
            pins,
            registrations: RwLock::new(registrations),
        }))
    }

    /// busbar's public base origin, as the card-serving path reads it.
    pub(crate) fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    /// The one card-fetch policy this plane guards with.
    pub(crate) fn fetch_policy(&self) -> &FetchPolicy {
        &self.fetch_policy
    }

    /// The operator's trust root for one agent. `None` for an id this plane does not front, which
    /// is the only honest answer: there is no default pin, and inventing one would be inventing a
    /// trust root.
    pub(crate) fn pin_for(&self, agent_id: &str) -> Option<&AgentPinCfg> {
        self.pins.get(agent_id)
    }

    /// READ the registry. The closure form rather than a returned guard so the lock's scope is
    /// visible at every call site and a caller cannot hold it across an await point.
    pub(crate) fn with_registrations<R>(&self, f: impl FnOnce(&[AgentRegistration]) -> R) -> R {
        let guard = self.registrations.read().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }

    /// MUTATE the registry. Same closure discipline as the read side, for the same reason.
    ///
    /// Poisoning is recovered from rather than propagated: a panic in one sweep must not turn the
    /// registry into a permanently unreadable object, because a registry nobody can read is a plane
    /// that has silently stopped re-verifying anything.
    pub(crate) fn with_registrations_mut<R>(
        &self,
        f: impl FnOnce(&mut Vec<AgentRegistration>) -> R,
    ) -> R {
        let mut guard = self
            .registrations
            .write()
            .unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// How many agents this deployment fronts.
    pub(crate) fn len(&self) -> usize {
        self.with_registrations(<[AgentRegistration]>::len)
    }

    /// THIS PLANE'S ADMISSION FACTS, or `None` when it has no RECEIVING side to admit anyone to.
    ///
    /// `None` for exactly one reason: no usable `public_url`. That is the same asymmetry the field's
    /// own doc records — an operator may configure `agents:` for the DELEGATING direction alone, and
    /// a deployment that only delegates fronts nothing, so it has no resource for a token to be
    /// bound to and no metadata document to point a refused caller at. Answering `None` here is what
    /// makes `main` mount no receiving route in that case, rather than mounting one that could only
    /// ever refuse.
    ///
    /// Both strings come from [`super::serve`], which is also what builds the endpoint the served
    /// card advertises. A caller reads the audience to ask for off the card busbar served it, so the
    /// two must be one derivation — an independently configured audience is a confused-deputy gap
    /// that opens the first time somebody edits one of the two.
    pub(crate) fn admission(&self) -> Option<crate::plane::PlaneAdmission> {
        let public = self.public_url.as_deref()?;
        Some(crate::plane::PlaneAdmission {
            audience: super::serve::canonical_uri(public).ok()?,
            resource_metadata: super::serve::metadata_url(public).ok()?,
        })
    }
}

#[cfg(test)]
#[path = "tests/plane_tests.rs"]
mod plane_tests;
