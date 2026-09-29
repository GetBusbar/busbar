// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `agents:` SECTION, as the host reads it. The grammar itself (the entry and section types,
//! [`validate_agent`], the kernel-owned [`TRUST_KEYS`]) is the plane's and is defined in the plane
//! crate (`busbar_plane_a2a::a2a::config`), re-exported here so every caller path resolves the same
//! items. What stays here is what names the host: the section as the kernel's config trait object
//! ([`AgentsSection`]), the cadence as the kernel's reverify policy ([`policy_for`]), and a `pin:`
//! as the kernel's trust declaration ([`pin_declaration`]).

pub use super::plane_crate::config::*;

use super::creds::OutboundCredential;

/// THE `agents:` SECTION AS THE KERNEL'S CONFIG TRAIT OBJECT. A wrapper, because the section type is
/// the plane crate's and the trait is the kernel's. Its `as_any` hands out the inner [`AgentsCfg`],
/// so every reader that downcasts the section keeps reading the grammar's own type.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentsSection(pub AgentsCfg);

impl busbar_kernel::plane::config::PlaneCfg for AgentsSection {
    /// The A2A plane's secret references: each agent's LEASED outbound delegation credential
    /// (`agents.<name>.upstream_credential.secret`) and both halves of its outbound client identity
    /// (`agents.<name>.client_identity.cert` / `.key`). Moved here VERBATIM from the core
    /// `config_validate::secret_refs` walk so the exhaustive destructure that forces a
    /// secret/not-secret decision on every new field lives beside the fields it guards.
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)> {
        // EXHAUSTIVE, no `..`, at both levels: adding a field to `AgentsCfg`, `AgentDefCfg`,
        // `OutboundCredential` or `ClientIdentityCfg` fails to build with `E0027 pattern does not
        // mention field` until somebody decides, here, whether it carries a secret. That force used to
        // live in `config_validate::secret_refs`; it moved with the sweep.
        let mut refs: Vec<(String, &busbar_contract::secret_ref::SecretRef)> = Vec::new();
        let AgentsCfg {
            // The all-agents attach list and credential MODE carry no reference: a hook name is a bare
            // name into the top-level `hooks:` map, and the mode is a `Copy` selector.
            all_agent_hooks: _,
            all_agent_upstream_credentials: _,
            agents,
        } = &self.0;
        for (name, def) in agents {
            let AgentDefCfg {
                upstream_credential,
                client_identity,
                // An endpoint URL, an out-of-band VERIFICATION pin, two cadence strings, a pinned
                // protocol version, a private-address opt-in, a `Copy` credential-mode selector, egress
                // scope names and bare hook names. None of them is a credential, and `pin.key` is the one that most looks like
                // one: it is the public half of the operator's trust root, and an operator who cannot
                // publish it has the wrong value in the field.
                url: _,
                pin: _,
                reverify_ttl: _,
                recovery_backoff: _,
                protocol_version: _,
                allow_private: _,
                upstream_credentials: _,
                egress_scopes: _,
                hooks: _,
            } = def;
            if let Some(cred) = upstream_credential {
                let OutboundCredential {
                    secret,
                    // Where the resolved value is placed on the wire, and how long the lease lasts.
                    // Neither is material.
                    placement: _,
                    lease_ttl_ms: _,
                } = cred;
                refs.push((format!("agents.{name}.upstream_credential.secret"), secret));
            }
            // THE OUTBOUND CLIENT IDENTITY. Both halves are references and both are walked: an
            // unresolvable `cert:` fails the handshake exactly as an unresolvable `key:` does, and
            // `--validate` that checked only the secret half would report a config that cannot connect
            // as valid.
            if let Some(identity) = client_identity {
                let ClientIdentityCfg { cert, key } = identity;
                refs.push((format!("agents.{name}.client_identity.cert"), cert));
                refs.push((format!("agents.{name}.client_identity.key"), key));
            }
        }
        refs
    }

    fn contains_def(&self, name: &str) -> bool {
        self.0.agents.contains_key(name)
    }

    fn def_names(&self) -> Vec<&str> {
        self.0.agents.keys().map(|s| s.as_str()).collect()
    }

    fn entry_document(&self, name: &str) -> Option<serde_json::Value> {
        self.0
            .agents
            .get(name)
            .and_then(|cfg| serde_json::to_value(cfg).ok())
    }

    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        // THE SAME typed parse the file runs, through the SAME error wording. The value rules already
        // ran through the plane's `config_validate` seam at the write path's `parse_def`; this parse
        // is the fail-closed backstop and cannot fail on a definition that reached install.
        let cfg: AgentDefCfg = serde_json::from_value(def.clone())
            .map_err(|e| format!("invalid `agents.{name}` definition: {e}"))?;
        self.0.agents.insert(name.to_string(), cfg);
        Ok(())
    }

    fn container_gates(&self) -> busbar_kernel::plane::config::ContainerGateInputs {
        busbar_kernel::plane::config::ContainerGateInputs {
            section_hooks: self.0.all_agent_hooks.clone(),
            containers: self
                .0
                .agents
                .iter()
                .map(|(name, def)| (name.clone(), def.hooks.clone()))
                .collect(),
        }
    }

    fn validate_registry(&self) -> Result<(), String> {
        // The A2A plane has no cross-registration section rule (the MCP published-name uniqueness is
        // the one plane that does); every A2A registry rule is per-entry, run at parse.
        Ok(())
    }

    fn is_present(&self) -> bool {
        !self.0.agents.is_empty()
            || !self.0.all_agent_hooks.is_empty()
            || self.0.all_agent_upstream_credentials.is_some()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        &self.0
    }

    fn clone_box(&self) -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.0.clone())
    }
}

/// The effective re-verification cadence for one registration, as the pure-function policy
/// [`super::reverify`] consumes.
///
/// Config in, policy out, no clock and no I/O — so the cadence an operator wrote and the cadence
/// the decision uses are provably the same value rather than two parallel readings of it.
pub(crate) fn policy_for(
    def: &AgentDefCfg,
    default_backoff_ms: u64,
) -> Result<super::reverify::Policy, String> {
    let ttl = def.reverify_ttl.as_deref().unwrap_or(DEFAULT_REVERIFY_TTL);
    let ttl_ms = busbar_contract::duration::parse_duration_secs(ttl)?.saturating_mul(1_000);
    let recovery_backoff_ms = match def.recovery_backoff.as_deref() {
        None => default_backoff_ms,
        Some(v) => busbar_contract::duration::parse_duration_secs(v)?.saturating_mul(1_000),
    };
    Ok(super::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms,
    })
}

/// A `pin:` object as the kernel's plane-neutral trust reader takes it. A projection, not a
/// decision: every question asked of it is [`busbar_kernel::trust::declared`]'s, and this plane's
/// answers are its [`busbar_kernel::trust::declared::Declares`] impl in [`super::pin`].
///
/// No production caller: the `connect`/`approve` verbs lock the pin that was OBSERVED and verified,
/// never the declared one, so this stays a reader until a config-vs-observed diff wants it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn pin_declaration(
    pin: &AgentPinCfg,
) -> busbar_kernel::trust::declared::Declaration<'_, PinMechanism> {
    busbar_kernel::trust::declared::Declaration {
        mechanism: pin.mechanism,
        key: pin.key.as_deref(),
        fingerprint: pin.fingerprint.as_deref(),
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/config_tests.rs"]
mod config_tests;
