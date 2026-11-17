// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Candidate assembly of the concrete kernel native auth chain.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

pub(crate) use busbar_kernel::auth::native_chain::{
    AuthInstance, AuthOwners, NativeChain, OpenedAuth,
};
use busbar_kernel::auth::native_policy::{BindingsPolicy, ChainPolicy};
use busbar_kernel::directory::Holds;
use busbar_kernel::plane_grants::KeyRefresh;
use busbar_kernel::state::App;

#[cfg(test)]
use busbar_kernel::{
    auth::chain_run::{ChainEnd, Request},
    auth::native_admin::PreparedAnswer,
    issued::IssuedCredentials,
    plane_driver::port_intents::Namespace,
    plane_grants::ReplayGuard,
};
#[cfg(test)]
use busbar_plugin_abi::host_side::caller::{Caller, InstanceLimits};
#[cfg(test)]
use busbar_ports::{
    auth::{AuthIn, AuthPort},
    CallCx,
};

/// One complete candidate's auth handles and per-instance refresh/hold owners.
pub(crate) struct AuthSet {
    instances: BTreeMap<Arc<str>, Arc<AuthInstance>>,
    pub(crate) owners: Arc<AuthOwners>,
}

impl AuthSet {
    pub(crate) fn new(
        opened: Vec<OpenedAuth>,
        holds: &Holds,
        owners: AuthOwners,
        refresh_interval: Duration,
    ) -> Result<Self, String> {
        let mut instances = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for opened in opened {
            let id = opened.who.instance;
            let name = Arc::clone(&opened.who.name);
            if id == 0 || !ids.insert(id) || instances.contains_key(&name) {
                return Err(format!(
                    "identity-providers.{name}: ambiguous auth reservation"
                ));
            }
            let held = holds.for_inbound(id).unwrap_or_default().into();
            instances.insert(
                name,
                Arc::new(AuthInstance {
                    opened,
                    keys: Arc::new(KeyRefresh::new(refresh_interval)),
                    holds: held,
                }),
            );
        }
        Ok(Self {
            instances,
            owners: Arc::new(owners),
        })
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Arc<AuthInstance>> {
        self.instances.get(name)
    }

    /// The configured operator chain under the candidate's frozen bindings and current generation.
    pub(crate) fn operator_chain(
        &self,
        app: &App,
        epoch: u64,
        names: &[&str],
    ) -> Result<NativeChain, String> {
        let mut instances = Vec::with_capacity(names.len());
        let mut policies = Vec::with_capacity(names.len());
        for name in names {
            let instance = self.get(name).ok_or_else(|| {
                format!("auth.admin_auth: '{name}' has no opened native auth instance")
            })?;
            if instance.opened.methods
                & (busbar_plugin_abi::auth::M_VERIFY | busbar_plugin_abi::auth::M_VERIFY_IO)
                == 0
            {
                return Err(format!("auth.admin_auth: '{name}' cannot verify"));
            }
            policies.push(BindingsPolicy::operator(
                app,
                instance.opened.who.instance,
                name,
                epoch,
            ));
            instances.push(Arc::clone(instance));
        }
        Ok(NativeChain::operator(
            instances,
            ChainPolicy::new(epoch, policies),
            Arc::clone(&self.owners),
        ))
    }
}

#[cfg(test)]
#[path = "tests/min3_auth.rs"]
mod tests;
