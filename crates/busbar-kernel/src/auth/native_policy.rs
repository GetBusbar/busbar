// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The existing data and operator authorization decisions at the native auth boundary.
//! Policy is complete before verification, and is checked before a replay claim is consumed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_plugin_abi::fail::refused::R_POLICY;
use busbar_ports::auth::{AuthIn, Identity};

use super::chain_run::IdentityPolicy;
use super::{AdminAuthChain, ChainVerdict, Principal};

enum Surface {
    Data,
    Operator {
        chain: Arc<AdminAuthChain>,
        principal: Box<str>,
        cap: Option<busbar_contract::authz::Scope>,
    },
}

/// One configured provider, runtime reservation and serving generation. The native identity's
/// groups feed the same binding table as the existing ingress; no claim grants authority itself.
pub struct BindingsPolicy {
    instance: u64,
    provider: Box<str>,
    epoch: u64,
    current_epoch: Arc<AtomicU64>,
    bindings: crate::config::RoleBindings,
    surface: Surface,
}

impl BindingsPolicy {
    /// Build from the unpublished, complete candidate's data policy. `provider` is its configured
    /// identity-provider name, never the plugin's canonical image name or an asserted claim.
    /// `epoch` is the publication owner's admitted generation, not a parallel policy counter.
    #[must_use]
    pub fn data(app: &crate::state::App, instance: u64, provider: &str, epoch: u64) -> Self {
        Self {
            instance,
            provider: provider.into(),
            epoch,
            current_epoch: Arc::clone(&app.config_generation),
            bindings: app.role_bindings.clone(),
            surface: Surface::Data,
        }
    }

    /// Operator authority and the provider ceiling are the generation's existing admitted values.
    /// The request's actual method/path determines the required rung and named verb on every call.
    #[must_use]
    pub fn operator(app: &crate::state::App, instance: u64, provider: &str, epoch: u64) -> Self {
        let mut policy = Self::data(app, instance, provider, epoch);
        policy.surface = Surface::Operator {
            chain: Arc::clone(&app.admin_modules),
            principal: crate::config::operator_principal_id().into(),
            cap: super::module_admin_scope_cap(app, provider),
        };
        policy
    }

    fn verdict(&self, identity: &Identity) -> ChainVerdict {
        ChainVerdict::Identified {
            module: self.provider.to_string(),
            principal: Principal {
                id: identity.subject().to_owned(),
                name: None,
                roles: identity.groups().map(str::to_owned).collect(),
                ttl_secs: identity.cache_s().map(u64::from),
            },
            resolved: None,
            signed_authority: None,
        }
    }
}

impl IdentityPolicy for BindingsPolicy {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn authorize(&self, instance: u64, identity: &Identity, req: &AuthIn<'_>) -> Result<(), u32> {
        if instance != self.instance
            || self.current_epoch.load(Ordering::Acquire) != self.epoch
            || identity.subject().is_empty()
            || identity
                .expires_at_s()
                .is_some_and(|until| req.now_s >= until)
        {
            return Err(R_POLICY);
        }
        let verdict = self.verdict(identity);
        let admitted = match &self.surface {
            Surface::Data => super::resolve_identity_from_bindings(&self.bindings, verdict).is_ok(),
            Surface::Operator {
                chain,
                principal,
                cap,
            } => {
                let door = super::admin_door_from_bindings(
                    &self.bindings,
                    &chain.operator,
                    principal,
                    verdict,
                    *cap,
                    crate::admin::seam::admin_verb_rung,
                );
                super::admin_door_admits(&door, req.method, req.path)
            }
        };
        admitted.then_some(()).ok_or(R_POLICY)
    }
}

#[cfg(test)]
#[path = "tests/native_policy_tests.rs"]
mod tests;
