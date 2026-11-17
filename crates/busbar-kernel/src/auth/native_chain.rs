// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Concrete preparation shared by native consumers. Only this module owns verified state.
//! Root supplies opened ports and frozen policy; no prepared identity is accepted as input.

use super::chain_run::{
    prepare_owned, run_owned_chain, AuthServices, ChainEnd, ChainInstance, IdentityPolicy, Request,
    Verdict,
};
use super::native_admin::{PreparedAnswer, PreparedIdentity};
use super::native_policy::ChainPolicy;
use super::verdicts::VerdictCache;
use crate::directory::HoldSet;
use crate::issued::IssuedCredentials;
use crate::plane_driver::port_intents::Namespace;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use busbar_plugin_abi::host_side::caller::{Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{AuthIn, AuthPort};
use busbar_ports::CallCx;
use std::sync::Arc;

/// S8's actual instance and admitted describe, with the same reservation used by DIRECTORY.
pub struct OpenedAuth {
    pub who: Namespace,
    pub port: Arc<dyn AuthPort>,
    pub methods: u64,
    pub out_of_process: bool,
    pub limits: InstanceLimits,
}

/// Actual S7 owners. Issued grants come from operator policy, never plugin describes.
pub struct AuthOwners {
    pub issued: Arc<dyn IssuedCredentials>,
    pub replay: Arc<dyn ReplayGuard>,
    pub cache: Arc<dyn VerdictCache>,
}

pub struct AuthInstance {
    pub opened: OpenedAuth,
    pub keys: Arc<KeyRefresh>,
    pub holds: Box<[Arc<HoldSet>]>,
}

/// A retained chain cannot acquire a newer application's authority while verifying a request.
pub struct NativeChain {
    instances: Vec<Arc<AuthInstance>>,
    policy: ChainPolicy,
    owners: Arc<AuthOwners>,
    data: bool,
}

impl NativeChain {
    /// Assemble the existing operator preparation from actual opened owners and frozen policy.
    pub fn operator(
        instances: Vec<Arc<AuthInstance>>,
        policy: ChainPolicy,
        owners: Arc<AuthOwners>,
    ) -> Self {
        Self {
            instances,
            policy,
            owners,
            data: false,
        }
    }

    /// Assemble one explicit DATA chain from the actual opened reservations. This is
    /// preparation ownership, never a final route/resource authorization decision.
    pub fn data(
        epoch: u64,
        instances: Vec<Arc<AuthInstance>>,
        owners: Arc<AuthOwners>,
    ) -> Result<Self, &'static str> {
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        if instances.is_empty() {
            return Err("native principal data requires an explicit auth chain");
        }
        for instance in &instances {
            let opened = &instance.opened;
            if opened.who.instance == 0
                || opened.who.name.as_ref() == crate::config::KEYS_MODULE
                || !ids.insert(opened.who.instance)
                || !names.insert(opened.who.name.as_ref())
                || opened.methods
                    & (busbar_plugin_abi::auth::M_VERIFY | busbar_plugin_abi::auth::M_VERIFY_IO)
                    == 0
            {
                return Err("native data chain has an unsupported or duplicate reservation");
            }
        }
        Ok(Self {
            instances,
            policy: ChainPolicy::new(epoch, Vec::new()),
            owners,
            data: true,
        })
    }

    pub fn is_data(&self) -> bool {
        self.data
    }

    pub fn epoch(&self) -> u64 {
        self.policy.epoch()
    }

    pub fn matches_names(&self, names: &[Box<str>]) -> bool {
        self.instances.len() == names.len()
            && self
                .instances
                .iter()
                .zip(names)
                .all(|(instance, name)| instance.opened.who.name.as_ref() == name.as_ref())
    }

    pub async fn prepare(
        self: &Arc<Self>,
        cx: CallCx,
        request: Request,
    ) -> Result<PreparedAnswer, busbar_ports::PortError> {
        for instance in &self.instances {
            let caller = caller(instance, cx);
            let services = AuthServices {
                issued: self.owners.issued.as_ref(),
                replay: self.owners.replay.as_ref(),
                policy: &self.policy,
            };
            let verdict = prepare_owned(
                &services,
                self.owners.cache.as_ref(),
                ChainInstance {
                    id: instance.opened.who.instance,
                    port: instance.opened.port.as_ref(),
                    caller: &caller,
                    keys: &instance.keys,
                    holds: &instance.holds,
                },
                cx,
                &request,
            )
            .await?;
            match verdict {
                Verdict::NotMine => continue,
                Verdict::Identity(identity) => {
                    let cutoff = match identity.replay() {
                        Some((_, ttl)) => {
                            let Some(until) =
                                request.view(|req| req.now_s.checked_add(ttl.clamp(1, 86_400)))
                            else {
                                return Ok(PreparedAnswer::Rejected);
                            };
                            Some(until)
                        }
                        None => None,
                    };
                    return Ok(PreparedAnswer::Identity(Arc::new(Prepared {
                        chain: Arc::clone(self),
                        instance: Arc::clone(instance),
                        request,
                        identity,
                        cx,
                        cutoff,
                    })));
                }
                Verdict::Held => return Ok(PreparedAnswer::Held),
                Verdict::Rejected { .. } | Verdict::PolicyRejected { .. } => {
                    return Ok(PreparedAnswer::Rejected)
                }
            }
        }
        Ok(PreparedAnswer::NotMine)
    }

    #[doc(hidden)]
    pub fn verify<'a>(
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

fn caller(instance: &AuthInstance, cx: CallCx) -> Caller<'_> {
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
}

struct Prepared {
    chain: Arc<NativeChain>,
    instance: Arc<AuthInstance>,
    request: Request,
    identity: busbar_ports::auth::Identity,
    cx: CallCx,
    cutoff: Option<u64>,
}

impl PreparedIdentity for Prepared {
    fn provider(&self) -> &str {
        &self.instance.opened.who.name
    }
    fn credential_headers(&self) -> &[Box<str>] {
        self.instance.opened.port.cred_headers()
    }
    fn identity(&self) -> &busbar_ports::auth::Identity {
        &self.identity
    }
    fn request(&self) -> &Request {
        &self.request
    }
    fn authorize(&self, now_s: u64) -> Result<(), u32> {
        use busbar_plugin_abi::fail::refused::R_POLICY;
        if self.cutoff.is_some_and(|until| now_s >= until)
            || crate::holds::held_by(Some(&self.instance.holds), self.identity.subject()).is_some()
        {
            return Err(R_POLICY);
        }
        self.request.view(|req| {
            let now = AuthIn { now_s, ..*req };
            self.chain
                .policy
                .authorize(self.instance.opened.who.instance, &self.identity, &now)
        })
    }
    fn claim(&self) -> busbar_plugin_abi::host_side::caller::BoxFut<'_, bool> {
        Box::pin(async move {
            match (self.identity.replay(), self.cutoff) {
                (Some((key, _)), Some(until)) => {
                    let who = caller(&self.instance, self.cx);
                    self.chain
                        .owners
                        .replay
                        .claim_until(&who, key, until)
                        .await
                        .unwrap_or(false)
                }
                (None, None) => true,
                _ => false,
            }
        })
    }
}
