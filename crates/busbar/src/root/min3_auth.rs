// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete native auth consumers assembled from S8's admitted, opened instances.
//! No registry access, mutable application lookup, or service installation occurs here.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use busbar_kernel::auth::chain_run::{
    run_owned_chain, AuthServices, ChainEnd, ChainInstance, Request,
};
use busbar_kernel::auth::native_policy::{BindingsPolicy, ChainPolicy};
use busbar_kernel::auth::verdicts::VerdictCache;
use busbar_kernel::directory::{HoldSet, Holds};
use busbar_kernel::issued::IssuedCredentials;
use busbar_kernel::plane_driver::port_intents::Namespace;
use busbar_kernel::plane_grants::{KeyRefresh, ReplayGuard};
use busbar_kernel::state::App;
use busbar_plugin_abi::host_side::caller::{Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{AuthIn, AuthPort};
use busbar_ports::CallCx;

/// S8's actual instance and admitted describe, with the same reservation used by DIRECTORY.
pub(crate) struct OpenedAuth {
    pub(crate) who: Namespace,
    pub(crate) port: Arc<dyn AuthPort>,
    pub(crate) methods: u64,
    pub(crate) out_of_process: bool,
    pub(crate) limits: InstanceLimits,
}

/// Actual S7 owners. Issued grants come from operator policy, never plugin describes.
pub(crate) struct AuthOwners {
    pub(crate) issued: Arc<dyn IssuedCredentials>,
    pub(crate) replay: Arc<dyn ReplayGuard>,
    pub(crate) cache: Arc<dyn VerdictCache>,
}

pub(crate) struct AuthInstance {
    pub(crate) opened: OpenedAuth,
    pub(crate) keys: Arc<KeyRefresh>,
    pub(crate) holds: Box<[Arc<HoldSet>]>,
}

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
        Ok(NativeChain {
            instances,
            policy: ChainPolicy::new(epoch, policies),
            owners: Arc::clone(&self.owners),
        })
    }
}

/// A retained chain cannot acquire a newer application's authority while verifying a request.
pub(crate) struct NativeChain {
    instances: Vec<Arc<AuthInstance>>,
    policy: ChainPolicy,
    owners: Arc<AuthOwners>,
}

impl NativeChain {
    pub(crate) fn verify<'a>(
        &'a self,
        cx: CallCx,
        req: &AuthIn<'_>,
    ) -> impl std::future::Future<Output = ChainEnd> + Send + 'a {
        let request = Request::new(req);
        async move {
            let callers: Vec<_> = self
                .instances
                .iter()
                .map(|instance| {
                    let opened = &instance.opened;
                    Caller {
                        plugin: &opened.who.plugin,
                        kind: KindCode::Auth,
                        name: &opened.who.name,
                        instance: opened.who.instance,
                        slot: opened.who.slot,
                        chain: 0,
                        deadline: cx.deadline,
                        stack: cx.stack,
                        out_of_process: opened.out_of_process,
                        limits: opened.limits,
                    }
                })
                .collect();
            let chain: Vec<_> = self
                .instances
                .iter()
                .zip(&callers)
                .map(|(instance, caller)| ChainInstance {
                    id: instance.opened.who.instance,
                    port: instance.opened.port.as_ref(),
                    caller,
                    keys: &instance.keys,
                    holds: &instance.holds,
                })
                .collect();
            let services = AuthServices {
                issued: self.owners.issued.as_ref(),
                replay: self.owners.replay.as_ref(),
                policy: &self.policy,
            };
            run_owned_chain(&services, self.owners.cache.as_ref(), &chain, cx, request).await
        }
    }
}

#[cfg(test)]
#[path = "tests/min3_auth.rs"]
mod tests;
