// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Concrete preparation shared by native consumers. Only this module owns verified state.
//! Root supplies opened ports and frozen policy; no prepared identity is accepted as input.

use super::chain_run::{
    prepare_snapshot as verify_snapshot, run_owned_chain, AuthServices, ChainEnd, ChainInstance,
    IdentityPolicy, Request, Verdict,
};
use super::native_admin::PreparedAnswer;
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
    /// The chain names the built-in member `anonymous`: a caller that presents no credential is
    /// identified as the principal `anonymous`. What that principal may use, and under which
    /// group it is limited, comes from `role_bindings.anonymous`, exactly as for any identity.
    anonymous: bool,
    /// The chain names the built-in member `keys`: core's own verifier of the tokens core signs
    /// (`auth::native_keys`). Only a data chain can; the operator chain never has it.
    keys: bool,
}

/// The built-in members a data chain names beside its opened instances.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuiltIn {
    /// [`ANONYMOUS`].
    pub anonymous: bool,
    /// [`KEYS`].
    pub keys: bool,
}

impl BuiltIn {
    /// The built-in members `names` (a chain as the operator wrote it) names.
    pub fn named<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut members = Self::default();
        for name in names {
            members.anonymous |= name == ANONYMOUS;
            members.keys |= name == KEYS;
        }
        members
    }

    /// Whether `name` is a built-in member's word: it names no opened instance.
    pub fn is(name: &str) -> bool {
        name == ANONYMOUS || name == KEYS
    }
}

/// The built-in chain member that verifies the tokens core itself signs: `auth.chain: [keys]`.
pub const KEYS: &str = crate::config::KEYS_MODULE;

/// The built-in chain member that admits a caller presenting no credential, and the principal it
/// identifies that caller as (1.5.5's audit attribution for its open relay). An operator writes
/// `auth: { chain: [anonymous] }` to run an open relay; nothing is one by omission.
pub const ANONYMOUS: &str = "anonymous";

/// The provider a request a core ticket admitted is attributed to (`auth::native_ticket`). It is
/// not a chain member: no operator names it, and it is never the anonymous principal.
pub const TICKET: &str = "ticket";

/// The load refusal of an explicitly empty chain. An empty list is what a templating slip
/// produces, and everywhere else an empty list means none: here it would mean everyone.
pub const EMPTY_CHAIN_REFUSED: &str =
    "auth.chain is empty: no verifier, so nobody could be admitted. To run an open relay, name it: \
     `chain: [anonymous]`, and grant it under `role_bindings.anonymous`";

/// The boot line when the chain admits `anonymous` and its binding places it in no group.
pub const ANONYMOUS_UNLIMITED: &str =
    "auth.chain admits `anonymous` and `role_bindings.anonymous` names no group: an open relay \
     with no rate, concurrency or budget limit";

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
            anonymous: false,
            // SECURITY: the admin listener's chain never judges a core-minted token.
            keys: false,
        }
    }

    /// Whether the chain names the built-in member `keys`: a core-signed token presented on its
    /// route is judged by core's own verifier, and by no instance.
    pub fn admits_keys(&self) -> bool {
        self.keys
    }

    /// Whether the chain names the built-in member `anonymous`: it can yield a subject its callers
    /// share, so a route that keeps state per caller is not mounted under it.
    pub fn admits_anonymous(&self) -> bool {
        self.anonymous
    }

    /// Whether the chain is `anonymous` alone: 1.5.5's open relay. No credential is read and no
    /// verifier runs; every caller is the principal `anonymous`.
    pub fn is_open(&self) -> bool {
        self.anonymous && self.instances.is_empty() && !self.keys
    }

    /// Assemble one explicit DATA chain from the actual opened reservations. This is
    /// preparation ownership, never a final route/resource authorization decision.
    ///
    /// A chain with no instance is refused ([`EMPTY_CHAIN_REFUSED`]): nobody could be admitted.
    pub fn data(
        epoch: u64,
        instances: Vec<Arc<AuthInstance>>,
        owners: Arc<AuthOwners>,
    ) -> Result<Self, &'static str> {
        Self::assemble(epoch, instances, owners, BuiltIn::default())
    }

    /// The DATA chain of an operator who named the built-in member `anonymous` among (or instead
    /// of) its verifiers: `instances` are the other members, in order, and may be none (the open
    /// relay).
    pub fn data_admitting_anonymous(
        epoch: u64,
        instances: Vec<Arc<AuthInstance>>,
        owners: Arc<AuthOwners>,
    ) -> Result<Self, &'static str> {
        Self::assemble(
            epoch,
            instances,
            owners,
            BuiltIn {
                anonymous: true,
                keys: false,
            },
        )
    }

    /// The DATA chain of an operator who named built-in members among (or instead of) its
    /// verifiers: `instances` are the opened members, in order, and may be none where a built-in
    /// member is named. `keys` judges a core-signed token whatever its place in the list (no
    /// instance is ever handed one); `anonymous` is always last.
    pub fn data_with(
        epoch: u64,
        instances: Vec<Arc<AuthInstance>>,
        owners: Arc<AuthOwners>,
        members: BuiltIn,
    ) -> Result<Self, &'static str> {
        Self::assemble(epoch, instances, owners, members)
    }

    fn assemble(
        epoch: u64,
        instances: Vec<Arc<AuthInstance>>,
        owners: Arc<AuthOwners>,
        members: BuiltIn,
    ) -> Result<Self, &'static str> {
        let BuiltIn { anonymous, keys } = members;
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        if instances.is_empty() && !anonymous && !keys {
            return Err(EMPTY_CHAIN_REFUSED);
        }
        for instance in &instances {
            let opened = &instance.opened;
            if opened.who.instance == 0
                || opened.who.name.as_ref() == crate::config::KEYS_MODULE
                // The word is the built-in member's: no instance may answer to it, or its
                // principals would earn the open relay's binding.
                || opened.who.name.as_ref() == ANONYMOUS
                || !ids.insert(opened.who.instance)
                || !names.insert(opened.who.name.as_ref())
                || opened.methods
                    & busbar_plugin_abi::auth::M_VERIFY
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
            anonymous,
            keys,
        })
    }

    /// The identity of a caller whose core-signed token the built-in member `keys` verified
    /// (`auth::native_keys::admit`): the key's id is the subject. It carries no replay key and
    /// belongs to no instance; its key is re-judged at the gate (`CoreKey::standing`).
    pub(crate) fn core_identity(
        self: &Arc<Self>,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
        core: super::native_keys::CoreKey,
    ) -> Arc<PreparedNativeIdentity> {
        Arc::new(PreparedNativeIdentity {
            chain: Arc::clone(self),
            instance: None,
            request,
            identity: busbar_ports::auth::Identity::of_subject(core.subject()),
            cx,
            cutoff: None,
            core: Some(core),
            origin: Origin::Keys,
        })
    }

    /// The identity of a request a core ticket admitted. Only the ticket verifier's value
    /// (`auth::native_ticket::TicketVerified`) can make one: its key is the issuer's governed key
    /// as it stands now, and it is never the anonymous principal.
    pub fn ticket_identity(
        self: &Arc<Self>,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
        verified: &super::native_ticket::TicketVerified,
    ) -> Arc<PreparedNativeIdentity> {
        Arc::new(PreparedNativeIdentity {
            chain: Arc::clone(self),
            instance: None,
            request,
            identity: verified.identity().clone(),
            cx,
            cutoff: None,
            core: None,
            origin: Origin::Ticket(Arc::clone(verified.key())),
        })
    }

    /// The principal a caller that presents no credential is identified as, where the chain
    /// admits `anonymous`.
    fn anonymous_identity(
        self: &Arc<Self>,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
    ) -> NativePreparedAnswer {
        NativePreparedAnswer::Identity(Arc::new(PreparedNativeIdentity {
            chain: Arc::clone(self),
            instance: None,
            request,
            identity: busbar_ports::auth::Identity::of_subject(ANONYMOUS),
            cx,
            cutoff: None,
            core: None,
            origin: Origin::Anonymous,
        }))
    }

    /// Whether the request's head carries a credential this chain would read: `authorization`,
    /// or a header one of its instances declares. A request that carries one and that no member
    /// accepts is not anonymous: it is not verified.
    fn presents_credential(&self, request: &ChargedRequestSnapshot) -> bool {
        request
            .with_auth_input(|input| {
                input.headers.iter().any(|field| {
                    let name = field.name.get();
                    name.eq_ignore_ascii_case("authorization") || self.reads_header(name)
                })
            })
            // A head that cannot be read is not the head of a caller presenting nothing.
            .unwrap_or(true)
    }

    pub fn is_data(&self) -> bool {
        self.data
    }

    pub fn epoch(&self) -> u64 {
        self.policy.epoch()
    }

    /// Whether this chain is the one `names` (a route's chain as configured) states: the same
    /// opened instances in the same order, and exactly the built-in members it names. A route
    /// that names `keys` is never bound to a chain without the member, nor the reverse.
    pub fn matches_names(&self, names: &[Box<str>]) -> bool {
        let members = BuiltIn::named(names.iter().map(|name| &**name));
        let mut opened = names.iter().filter(|name| !BuiltIn::is(name));
        members.anonymous == self.anonymous
            && members.keys == self.keys
            && self.instances.iter().all(|instance| {
                opened.next().map(|name| &**name) == Some(&*instance.opened.who.name)
            })
            && opened.next().is_none()
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

    /// Every D_CRED_HEADER its instances declare, in chain order (duplicates possible).
    pub fn carriers(&self) -> impl Iterator<Item = &str> {
        self.instances
            .iter()
            .flat_map(|instance| instance.opened.port.cred_headers().iter().map(|h| &**h))
    }

    /// Whether every member of the chain states the header its credential arrives in (a
    /// D_CRED_HEADER). Only then does a head carrying none of the chain's carriers prove that no
    /// member could verify it: a member that states no header may verify by something a head's
    /// fields do not show (a client certificate, the peer), and nothing is concluded for it.
    pub fn reads_only_declared_headers(&self) -> bool {
        !self.instances.is_empty()
            && self
                .instances
                .iter()
                .all(|instance| !instance.opened.port.cred_headers().is_empty())
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
        // `anonymous` alone: the open relay reads no credential and runs no verifier.
        if self.is_open() {
            return Ok(self.anonymous_identity(cx, request));
        }
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
                            instance: Some(Arc::clone(instance)),
                            request,
                            identity,
                            cx,
                            cutoff,
                            core: None,
                            origin: Origin::Instance,
                        },
                    )));
                }
                Verdict::Held => return Ok(NativePreparedAnswer::Held),
                Verdict::Rejected { .. } | Verdict::PolicyRejected { .. } => {
                    return Ok(NativePreparedAnswer::Rejected)
                }
            }
        }
        // Beside verifiers, `anonymous` is the last member: it admits only a caller every other
        // member passed over AND that presents no credential. A caller a member can verify by
        // something a head's fields do not show (a client certificate) is that member's, never
        // anonymous; a credential no member accepts stays unverified, never downgraded.
        if self.anonymous && !self.presents_credential(&request) {
            return Ok(self.anonymous_identity(cx, request));
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
            // One caller and one chain position per configured instance, on the stack for an ordinary chain.
            let mut callers: smallvec::SmallVec<[_; 4]> = smallvec::SmallVec::new();
            for instance in &self.instances {
                let opened = &instance.opened;
                callers.push(Caller {
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
                });
            }
            let mut chain: smallvec::SmallVec<[_; 4]> = smallvec::SmallVec::new();
            for (instance, caller) in self.instances.iter().zip(&callers) {
                chain.push(ChainInstance {
                    id: instance.opened.who.instance,
                    port: instance.opened.port.as_ref(),
                    caller,
                    keys: &instance.keys,
                    holds: &instance.holds,
                });
            }
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
    /// The instance that verified the credential; `None` for the anonymous principal of an
    /// explicitly empty data chain (nothing was verified).
    instance: Option<Arc<AuthInstance>>,
    request: Arc<ChargedRequestSnapshot>,
    identity: busbar_ports::auth::Identity,
    cx: CallCx,
    cutoff: Option<u64>,
    /// The core-signed token the built-in member `keys` verified; `None` for every other
    /// identity. Its key is the identity's key: no role binding is consulted for it.
    core: Option<super::native_keys::CoreKey>,
    /// How the identity was reached. Stated by its constructor, never inferred from which other
    /// field is empty: "no instance verified it" is not "anonymous" (a ticket or a core-signed
    /// token is verified by core itself).
    origin: Origin,
}

/// How a [`PreparedNativeIdentity`] was reached.
enum Origin {
    /// An instance of the chain verified the credential.
    Instance,
    /// The built-in member `anonymous`: the caller presented no credential.
    Anonymous,
    /// The built-in member `keys` verified a core-signed token.
    Keys,
    /// A core ticket admitted the request; the issuer's governed key as it stands now.
    Ticket(Arc<busbar_contract::records::VirtualKey>),
}

impl std::fmt::Debug for PreparedNativeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedIdentity").finish_non_exhaustive()
    }
}

impl PreparedNativeIdentity {
    pub fn credential_headers(&self) -> &[Box<str>] {
        self.instance
            .as_ref()
            .map_or(&[], |instance| instance.opened.port.cred_headers())
    }
    pub fn request(&self) -> &Arc<ChargedRequestSnapshot> {
        &self.request
    }
    pub fn authorize(&self, now_s: u64) -> Result<(), u32> {
        self.fresh(now_s)?;
        // The anonymous principal was verified by no instance; no instance policy applies to it.
        let Some(instance) = &self.instance else {
            return Ok(());
        };
        self.request
            .with_auth_input(|req| {
                let now = AuthIn { now_s, ..*req };
                self.chain
                    .policy
                    .authorize(instance.opened.who.instance, &self.identity, &now)
            })
            .map_err(|_| busbar_plugin_abi::fail::refused::R_POLICY)?
    }
    pub fn claim(&self) -> busbar_plugin_abi::host_side::caller::BoxFut<'_, bool> {
        Box::pin(async move {
            match (self.identity.replay(), self.cutoff, &self.instance) {
                (Some((key, _)), Some(until), Some(instance)) => {
                    let who = caller(instance, self.cx);
                    self.chain
                        .owners
                        .replay
                        .claim_until(&who, key, until)
                        .await
                        .unwrap_or(false)
                }
                (None, None, _) => true,
                _ => false,
            }
        })
    }
}

impl PreparedNativeIdentity {
    /// Invoked once by the consumed DATA preparation owner; never retries the claim.
    pub(crate) async fn claim_classified(&self) -> super::native_admin::NativeReplayClaim {
        use super::native_admin::NativeReplayClaim;
        match (self.identity.replay(), self.cutoff, &self.instance) {
            (Some((key, _)), Some(until), Some(instance)) => {
                let who = caller(instance, self.cx);
                match self.chain.owners.replay.claim_until(&who, key, until).await {
                    Ok(true) => NativeReplayClaim::Claimed,
                    Ok(false) => NativeReplayClaim::Duplicate,
                    Err(error) => NativeReplayClaim::Unknown(error),
                }
            }
            (None, None, _) => NativeReplayClaim::Claimed,
            _ => NativeReplayClaim::Inconsistent,
        }
    }

    pub fn snapshot(&self) -> &Arc<ChargedRequestSnapshot> {
        &self.request
    }
    pub fn provider(&self) -> &str {
        match (&self.instance, &self.origin) {
            (Some(instance), _) => &instance.opened.who.name,
            (None, Origin::Keys) => KEYS,
            (None, Origin::Ticket(_)) => TICKET,
            (None, Origin::Anonymous | Origin::Instance) => ANONYMOUS,
        }
    }
    /// The provider's name as a verdict holds it: the instance's own shared name, not a copy.
    pub(crate) fn provider_text(&self) -> busbar_contract::kept::Text {
        match (&self.instance, &self.origin) {
            (Some(instance), _) => {
                busbar_contract::kept::Text::from(Arc::clone(&instance.opened.who.name))
            }
            (None, Origin::Keys) => busbar_contract::kept::Text::fixed(KEYS),
            (None, Origin::Ticket(_)) => busbar_contract::kept::Text::fixed(TICKET),
            (None, Origin::Anonymous | Origin::Instance) => {
                busbar_contract::kept::Text::fixed(ANONYMOUS)
            }
        }
    }
    /// Whether this is the anonymous principal: the built-in member `anonymous` admitted a caller
    /// that presented no credential. Stated by the constructor, never inferred from an empty
    /// instance: a caller a ticket admitted or whose core-signed token `keys` verified is never
    /// anonymous and never earns `role_bindings.anonymous`.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.origin, Origin::Anonymous)
    }
    /// The issuer's governed key of a request a core ticket admitted, if this is one.
    pub(crate) fn ticket_key(&self) -> Option<&Arc<busbar_contract::records::VirtualKey>> {
        match &self.origin {
            Origin::Ticket(key) => Some(key),
            _ => None,
        }
    }
    /// The core-signed token the built-in member `keys` verified for this identity, if it is one.
    pub(crate) fn core_key(&self) -> Option<&super::native_keys::CoreKey> {
        self.core.as_ref()
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
            || self.instance.as_ref().is_some_and(|instance| {
                crate::holds::held_by(Some(&instance.holds), self.identity.subject()).is_some()
            })
        {
            return Err(busbar_plugin_abi::fail::refused::R_POLICY);
        }
        Ok(())
    }
}
