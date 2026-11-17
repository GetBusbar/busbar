// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Concrete preparation shared by native consumers. Only this module owns verified state.
//! Root supplies opened ports and frozen policy; no prepared identity is accepted as input.

use super::chain_run::{
    prepare_snapshot as verify_snapshot, run_owned_chain, AuthServices, ChainEnd, ChainInstance,
    IdentityPolicy, Request, Verdict,
};
use super::native_admin::{PreparedAnswer, PreparedIdentity};
use super::native_policy::ChainPolicy;
use super::verdicts::VerdictCache;
use crate::directory::HoldSet;
use crate::inbound::request_snapshot::ChargedRequestSnapshot;
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

/// Concrete verification result. Arbitrary admin trait implementations cannot create
/// the private identity value carried here or enter DATA completion.
pub enum NativePreparedAnswer {
    Identity(Arc<PreparedNativeIdentity>),
    NotMine,
    Rejected,
    Held,
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

    /// Existing admin projection over the same concrete preparation loop.
    pub async fn prepare(
        self: &Arc<Self>,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
    ) -> Result<PreparedAnswer, busbar_ports::PortError> {
        Ok(match self.prepare_snapshot(cx, request).await? {
            NativePreparedAnswer::Identity(value) => PreparedAnswer::Identity(value),
            NativePreparedAnswer::NotMine => PreparedAnswer::NotMine,
            NativePreparedAnswer::Rejected => PreparedAnswer::Rejected,
            NativePreparedAnswer::Held => PreparedAnswer::Held,
        })
    }

    pub fn reads_header(&self, name: &str) -> bool {
        self.instances.iter().any(|instance| {
            instance
                .opened
                .port
                .cred_headers()
                .iter()
                .any(|header| header.eq_ignore_ascii_case(name))
        })
    }

    pub async fn prepare_snapshot(
        self: &Arc<Self>,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
    ) -> Result<NativePreparedAnswer, busbar_ports::PortError> {
        for instance in &self.instances {
            let caller = caller(instance, cx);
            let services = AuthServices {
                issued: self.owners.issued.as_ref(),
                replay: self.owners.replay.as_ref(),
                policy: &self.policy,
            };
            let verdict = verify_snapshot(
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
                            let Some(until) = request.now_s().checked_add(ttl.clamp(1, 86_400))
                            else {
                                return Ok(NativePreparedAnswer::Rejected);
                            };
                            Some(until)
                        }
                        None => None,
                    };
                    return Ok(NativePreparedAnswer::Identity(Arc::new(
                        PreparedNativeIdentity {
                            chain: Arc::clone(self),
                            instance: Arc::clone(instance),
                            request,
                            identity,
                            cx,
                            cutoff,
                        },
                    )));
                }
                Verdict::Held => return Ok(NativePreparedAnswer::Held),
                Verdict::Rejected { .. } | Verdict::PolicyRejected { .. } => {
                    return Ok(NativePreparedAnswer::Rejected)
                }
            }
        }
        Ok(NativePreparedAnswer::NotMine)
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

pub struct PreparedNativeIdentity {
    chain: Arc<NativeChain>,
    instance: Arc<AuthInstance>,
    request: Arc<ChargedRequestSnapshot>,
    identity: busbar_ports::auth::Identity,
    cx: CallCx,
    cutoff: Option<u64>,
}

impl PreparedIdentity for PreparedNativeIdentity {
    fn claim_classified(
        &self,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'_, super::native_admin::NativeReplayClaim>
    {
        Box::pin(PreparedNativeIdentity::claim_classified(self))
    }
    fn provider(&self) -> &str {
        &self.instance.opened.who.name
    }
    fn credential_headers(&self) -> &[Box<str>] {
        self.instance.opened.port.cred_headers()
    }
    fn identity(&self) -> &busbar_ports::auth::Identity {
        &self.identity
    }
    fn request(&self) -> &Arc<ChargedRequestSnapshot> {
        &self.request
    }
    fn authorize(&self, now_s: u64) -> Result<(), u32> {
        self.fresh(now_s)?;
        self.request
            .with_auth_input(|req| {
                let now = AuthIn { now_s, ..*req };
                self.chain
                    .policy
                    .authorize(self.instance.opened.who.instance, &self.identity, &now)
            })
            .map_err(|_| busbar_plugin_abi::fail::refused::R_POLICY)?
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

impl PreparedNativeIdentity {
    /// Invoked once by the consumed DATA preparation owner; never retries the claim.
    pub(crate) async fn claim_classified(&self) -> super::native_admin::NativeReplayClaim {
        use super::native_admin::NativeReplayClaim;
        match (self.identity.replay(), self.cutoff) {
            (Some((key, _)), Some(until)) => {
                let who = caller(&self.instance, self.cx);
                match self.chain.owners.replay.claim_until(&who, key, until).await {
                    Ok(true) => NativeReplayClaim::Claimed,
                    Ok(false) => NativeReplayClaim::Duplicate,
                    Err(error) => NativeReplayClaim::Unknown(error),
                }
            }
            (None, None) => NativeReplayClaim::Claimed,
            _ => NativeReplayClaim::Inconsistent,
        }
    }

    pub fn snapshot(&self) -> &Arc<ChargedRequestSnapshot> {
        &self.request
    }
    pub fn provider(&self) -> &str {
        &self.instance.opened.who.name
    }
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        &self.identity
    }
    pub(crate) fn belongs_to(&self, chain: &Arc<NativeChain>) -> bool {
        Arc::ptr_eq(&self.chain, chain)
    }
    /// Refreshes expiry/hold facts without resolving or discarding a governed key.
    pub(crate) fn fresh(&self, now_s: u64) -> Result<(), u32> {
        if self.identity.subject().is_empty()
            || self
                .identity
                .expires_at_s()
                .is_some_and(|until| now_s >= until)
            || self.cutoff.is_some_and(|until| now_s >= until)
            || std::time::Instant::now() >= self.cx.deadline
            || crate::holds::held_by(Some(&self.instance.holds), self.identity.subject()).is_some()
        {
            return Err(busbar_plugin_abi::fail::refused::R_POLICY);
        }
        Ok(())
    }
    pub(crate) fn claim(&self) -> busbar_plugin_abi::host_side::caller::BoxFut<'_, bool> {
        <Self as PreparedIdentity>::claim(self)
    }
}
