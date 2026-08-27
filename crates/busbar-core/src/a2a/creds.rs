// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OUTBOUND DELEGATION CREDENTIALS: held by busbar, scoped to one registration, injected at the
//! hop, and LEASED rather than stable-forever.
//!
//! ## The caller's credential never leaves busbar. That is the whole rule
//!
//! A fronted agent delegating to a registered agent is busbar making a call, as busbar. The
//! inbound caller's key authenticated them TO busbar and authorised them against busbar's scopes;
//! it means nothing to a third-party vendor and handing it over would give that vendor a working
//! busbar credential belonging to someone else. So there is no argument on any function in this
//! module through which an inbound credential could travel, and
//! [`super::config::validate_agent`] refuses `upstream_credentials: passthrough` on the `agents:`
//! plane outright, at parse, with a message that says why.
//!
//! Refusing the VALUE while keeping the WORD is deliberate: the reserved section keys are identical
//! across planes so an operator learns the vocabulary once, and a plane that cannot honor a value
//! says so loudly instead of accepting it and doing something else.
//!
//! ## Leased, and the lease is a field rather than an adjective
//!
//! The design called these credentials "time-limited" while the record held a stable handle with no
//! expiry anywhere on it, which made the claim prose. Here the lease is [`Lease::expires_at_ms`],
//! minted from [`OutboundCredential::lease_ttl_ms`] at each hop and checked before the credential
//! is used. A lease is not a revocation mechanism and does not pretend to be one; it bounds how
//! long a resolved secret is allowed to sit in memory being reused.
//!
//! ## THE SECOND RULE, and it is not the first one restated: the TRANSITIVE CONFUSED DEPUTY
//!
//! "The caller's key never leaves" is a statement about WHICH SECRET travels. It says nothing about
//! WHOSE AUTHORITY is spent. busbar is both directions at once, so an authenticated inbound call can
//! cause busbar to spend its OWN standing credential on a backend agent the caller was never
//! entitled to reach — and every byte of that hop is busbar's own, so rule one is satisfied while
//! the caller has just gained reach it does not hold. A client-only gateway cannot have this bug:
//! it has no inbound principal to be confused about. The sibling plane states the same thing and
//! closes it at its credential-selection site (`mcp/client/egress.rs`, rule 2). This is that gate
//! for the A2A plane.
//!
//! **The outbound credential is bound to the inbound principal's grant**, and the binding is a TYPE
//! rather than a call-ordering convention. [`authorise_egress`] is the only way to obtain an
//! [`EgressGrant`], the witness's field is private to core's gate module so NO module can build one
//! — this one included — and [`mint`] and [`mint_from`] both REQUIRE one. Forgetting the check is
//! therefore a COMPILE error at the call site rather than a review comment — which matters because
//! the caller that will forget is the one that does not exist yet.
//!
//! THE GATE ITSELF IS CORE'S ([`crate::egress_auth::gate`]). It was written twice — here and at
//! `mcp/client/egress.rs` — and one copy checked key liveness while the other did not. What is left
//! here is what is genuinely this plane's: the GRANT KIND ([`AgentGrant`]) and the refusal WORDING
//! ([`AgentEgressDenied`]).
//!
//! The agent id the lease is minted FOR is read off the grant rather than passed beside it. A
//! signature that took both would admit the one combination that defeats the whole gate: authorise
//! against `planner`, mint against `payments`.
//!
//! Fail-closed, and never a fallback: a caller with no grant gets [`AgentEgressDenied::NoAgentGrant`] and
//! NO credential. Falling back to the registration's own credential is precisely the deputy.
//!
//! ## The record holds a HANDLE, never the secret
//!
//! [`OutboundCredential`] carries a [`busbar_api::SecretRef`] — the module plus its settings —
//! and the secret is resolved at delegation time. It is never in the registration record, never in
//! the Agent Card, and never in a debug rendering: [`Lease`] has a hand-written `Debug` for exactly
//! the reason `VirtualKey` and `CredentialSecret` do.

// MOUNTED. `mint_from` and `Lease::header_for` are on the hot path: `ingress::invoke` mints a lease
// per relayed submission and the lease is the ONLY credential that goes on the hop. `mint` itself —
// the whole-registration form — still has no production caller, because the hot path holds a cloned
// handle rather than a registration (cloning one per request would copy a cached Agent Card per
// call); it stays as the place the "no parameter for a caller credential" property is asserted
// against a real registration.
#![cfg_attr(not(test), allow(dead_code))]

use busbar_api::VirtualKey;

use busbar_api::SecretRef;
use busbar_substrate::egress_auth::gate::{EgressRefusal, EgressSubject, Requirement};

/// WHICH OF THIS PLANE'S GRANTS a refusal is about. ONE variant, because this plane requires one
/// grant — and it is an enum rather than nothing so that a second A2A requirement would be a compile
/// error at the wording below rather than a silent reuse of the agent sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentGrant {
    /// `agent:<id>`: the caller may cause busbar to reach this backend agent.
    Agent,
}

/// THE SUBJECT OF AN A2A EGRESS: one backend agent, BORROWED.
///
/// It borrows the agent id rather than copying it so that the id the check was made against and the
/// id the lease is minted for are the same bytes, not two strings that agree today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AgentEgress<'a> {
    agent_id: &'a str,
}

/// WHAT THIS PLANE SUPPLIES TO THE CORE GATE: one grant, and the key-liveness rule.
impl EgressSubject for AgentEgress<'_> {
    type Grant = AgentGrant;

    /// TRUE, and it stays true: a key that may not authenticate may certainly not cause a credential
    /// to be minted, and a LEASE outliving the key that occasioned it is a hop nobody's grant covers.
    /// The sibling MCP plane sets this FALSE, which is the divergence the unification wrote down
    /// rather than introduced — see `mcp/client/egress.rs`.
    const REQUIRE_LIVE_KEY: bool = true;

    fn grants_required(&self) -> Vec<Requirement<AgentGrant>> {
        vec![Requirement {
            grant: AgentGrant::Agent,
            scope_kind: super::inbound::SCOPE_KIND_AGENT,
            value: self.agent_id.to_string(),
        }]
    }
}

/// WHY NO OUTBOUND CREDENTIAL MAY BE SELECTED FOR THIS CALLER.
///
/// Named rather than folded into [`LeaseError`], because these are refusals about the CALLER's
/// authority and the rest are refusals about the CONFIGURATION. An operator reading "the caller
/// holds no grant" acts differently from one reading "the secret did not resolve".
///
/// THE WORDING IS THIS PLANE'S and the DECISION is core's: these are core's
/// [`busbar_substrate::egress_auth::gate::EgressRefusal`] wearing A2A's sentences, produced by the total
/// conversion below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentEgressDenied {
    /// The inbound principal holds no `agent:<id>` grant for the target. FAIL CLOSED: busbar does
    /// not spend its own credential on behalf of a caller that is not itself authorised for the
    /// backend agent.
    NoAgentGrant { caller: String, agent_id: String },
    /// The key is disabled, tombstoned or expired. A key that may not authenticate may certainly not
    /// cause a credential to be minted, and a lease outliving the key that occasioned it is a hop
    /// nobody's grant covers.
    KeyNotLive { caller: String },
}

/// THE PLANE'S WORDING, TOTAL over core's refusal. Byte-identical to what this module printed when
/// it owned its own gate; `match` with no wildcard, so a refusal core grows later cannot arrive here
/// silently.
impl From<EgressRefusal<AgentGrant>> for AgentEgressDenied {
    fn from(refusal: EgressRefusal<AgentGrant>) -> Self {
        match refusal {
            EgressRefusal::KeyNotLive { caller } => AgentEgressDenied::KeyNotLive { caller },
            EgressRefusal::NoGrant {
                caller,
                grant: AgentGrant::Agent,
                value,
                ..
            } => AgentEgressDenied::NoAgentGrant {
                caller,
                agent_id: value,
            },
        }
    }
}

impl std::fmt::Display for AgentEgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentEgressDenied::NoAgentGrant { caller, agent_id } => write!(
                f,
                "key `{caller}` holds no `{}:{agent_id}` grant, so NO outbound credential is \
                 selected for it: busbar does not spend its own credential on behalf of a caller \
                 that is not itself authorised for the backend agent",
                super::inbound::SCOPE_KIND_AGENT
            ),
            AgentEgressDenied::KeyNotLive { caller } => write!(
                f,
                "key `{caller}` is not live, so no outbound credential is leased for it"
            ),
        }
    }
}

/// PROOF THAT THE INBOUND PRINCIPAL IS ITSELF AUTHORISED FOR THIS BACKEND AGENT.
///
/// Core's witness, carrying this plane's subject. The whole value of the type is that it cannot be
/// built anywhere but [`busbar_substrate::egress_auth::gate::authorise`] — its field is private to core's gate
/// module, so NO module in the crate (this one included) can construct one — and the mint functions
/// take one by reference. A future delegating call site that forgot the grant check does not compile.
pub(crate) type EgressGrant<'a> = busbar_substrate::egress_auth::gate::EgressGrant<AgentEgress<'a>>;

/// The agent this grant is for, read off core's witness. An EXTENSION TRAIT rather than an inherent
/// `impl` because [`EgressGrant`] became `busbar-substrate`'s type in Phase-B B1, and an inherent
/// `impl` may be written only in the crate that defines the type. Same access (`self.subject()`, the
/// witness's own accessor) and same `pub(crate)` reach; the mint still reads the id OFF the grant
/// rather than taking it as a second parameter.
pub(crate) trait EgressGrantExt {
    /// The agent this grant is for. Read by the mint rather than passed beside it; see the module
    /// note on why a second parameter would defeat the gate.
    fn agent_id(&self) -> &str;
}

impl EgressGrantExt for EgressGrant<'_> {
    fn agent_id(&self) -> &str {
        self.subject().agent_id
    }
}

/// THE EGRESS GATE FOR THIS PLANE: [`busbar_substrate::egress_auth::gate::authorise`] with A2A's grant kind and
/// A2A's wording, and nothing else.
///
/// The question it asks — may busbar spend a credential on this backend agent ON BEHALF OF THIS
/// CALLER? — is the SAME predicate [`super::inbound::authorize`] and [`super::registry`]'s catalogue ask, and
/// asking it again here is not redundancy: those two answer "what may this caller SEE and INVOKE",
/// and this one answers "what may busbar's own credentials be spent on", which is a different
/// question asked at a different moment by a function that may one day have a call site the other
/// two never reach.
pub(crate) fn authorise_egress<'a>(
    caller: &VirtualKey,
    agent_id: &'a str,
    now: u64,
) -> Result<EgressGrant<'a>, AgentEgressDenied> {
    busbar_substrate::egress_auth::gate::authorise(caller, AgentEgress { agent_id }, now)
        .map_err(AgentEgressDenied::from)
}

/// Where a leased credential is placed on the outbound request.
///
/// An enum rather than a free-form header name because "put this secret wherever the config says"
/// is how a credential ends up in a query string, and a query string is in every access log on the
/// path.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialPlacement {
    /// `Authorization: Bearer <secret>`.
    #[default]
    Bearer,
    /// A named header carrying the secret verbatim (`X-API-Key: <secret>`), which is what several
    /// A2A vendors' `APIKey` security scheme means in practice.
    Header(String),
}

impl CredentialPlacement {
    /// The header this placement writes.
    pub(crate) fn header_name(&self) -> &str {
        match self {
            CredentialPlacement::Bearer => "authorization",
            CredentialPlacement::Header(name) => name.as_str(),
        }
    }
}

/// The HANDLE plus its lease policy, as the registration holds it. Operator INTENT, so it is
/// overlay state — and the reason `config_validate::secret_refs` now walks the `agents:` arm.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutboundCredential {
    /// The reference resolved at delegation time. NOT the secret.
    pub(crate) secret: SecretRef,
    /// Where the resolved value is placed on the outbound request.
    #[serde(default)]
    pub(crate) placement: CredentialPlacement,
    /// How long a minted lease is usable, in milliseconds. Zero is refused at parse: a lease that
    /// has expired before it is used is a credential that can never be presented, and an operator
    /// who wrote `0` meant something they did not get.
    pub(crate) lease_ttl_ms: u64,
}

/// Why a lease could not be minted or used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LeaseError {
    /// The registration has no outbound credential configured, and the hop needs one.
    NotConfigured(String),
    /// The secret module could not resolve the handle.
    Unresolved { agent_id: String, err: String },
    /// A lease was presented for a DIFFERENT agent than the one it was minted for.
    WrongAgent {
        minted_for: String,
        used_for: String,
    },
    /// The lease has expired.
    Expired {
        agent_id: String,
        expired_at_ms: u64,
        now_ms: u64,
    },
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseError::NotConfigured(a) => write!(
                f,
                "agent `{a}` has no `upstream_credential:` and the delegation hop needs one; \
                 busbar delegates as itself and never forwards the caller's credential"
            ),
            LeaseError::Unresolved { agent_id, err } => {
                write!(f, "agent `{agent_id}`: outbound credential did not resolve: {err}")
            }
            LeaseError::WrongAgent {
                minted_for,
                used_for,
            } => write!(
                f,
                "a credential leased for agent `{minted_for}` was presented on a hop to `{used_for}`"
            ),
            LeaseError::Expired {
                agent_id,
                expired_at_ms,
                now_ms,
            } => write!(
                f,
                "the credential lease for agent `{agent_id}` expired at {expired_at_ms}ms and it \
                 is now {now_ms}ms"
            ),
        }
    }
}

/// A RESOLVED, SCOPED, EXPIRING credential for exactly one registration.
///
/// `agent_id` is on the lease rather than only in the caller's head: a resolved secret that carries
/// no record of what it was resolved FOR is one an unrelated code path can pick up and present
/// somewhere else, and [`Lease::header_for`] refuses that by comparison rather than by convention.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Lease {
    agent_id: String,
    placement: CredentialPlacement,
    secret: String,
    expires_at_ms: u64,
}

// MANUAL Debug that NEVER prints the secret, mirroring `VirtualKey::generation_hash` and
// `CredentialSecret::secret`. A derived one would put a live vendor credential into any log line
// that debug-formats a registration.
impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("agent_id", &self.agent_id)
            .field("placement", &self.placement)
            .field("secret", &"<redacted; present>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl Lease {
    pub(crate) fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub(crate) fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// THE ONE WAY THE SECRET LEAVES THIS TYPE: as a `(header, value)` pair for exactly the agent
    /// the lease was minted for, and only while the lease is live.
    ///
    /// Both checks are here rather than at the call site on purpose. A caller that has to remember
    /// to check the expiry is a caller that will forget once, and the once is the interesting one.
    pub(crate) fn header_for(
        &self,
        agent_id: &str,
        now_ms: u64,
    ) -> Result<(String, String), LeaseError> {
        if self.agent_id != agent_id {
            return Err(LeaseError::WrongAgent {
                minted_for: self.agent_id.clone(),
                used_for: agent_id.to_string(),
            });
        }
        if now_ms >= self.expires_at_ms {
            return Err(LeaseError::Expired {
                agent_id: self.agent_id.clone(),
                expired_at_ms: self.expires_at_ms,
                now_ms,
            });
        }
        let value = match &self.placement {
            CredentialPlacement::Bearer => format!("Bearer {}", self.secret),
            CredentialPlacement::Header(_) => self.secret.clone(),
        };
        Ok((self.placement.header_name().to_string(), value))
    }
}

/// MINT A LEASE for one hop, against a registration.
///
/// TWO security properties live in this signature and they are DIFFERENT claims:
///
/// - There is NO PARAMETER through which an inbound caller's CREDENTIAL could arrive. A future edit
///   that wanted to forward one would have to add an argument, which is a change a reviewer sees.
/// - There IS a parameter through which the inbound caller's GRANT must arrive, and it is a type
///   only [`authorise_egress`] can produce. Passing the check is not optional, and skipping it is
///   not a mistake this function can be made in.
///
/// The registration must be the one the grant was taken against; that is CHECKED rather than
/// assumed, because a caller holding a grant for one agent and a registration for another is
/// exactly the mix-up the gate exists to stop.
pub(crate) fn mint(
    grant: &EgressGrant<'_>,
    registration: &super::registry::AgentRegistration,
    resolver: &dyn busbar_api::SecretResolve,
    now_ms: u64,
) -> Result<Lease, LeaseError> {
    if registration.agent_id != grant.agent_id() {
        return Err(LeaseError::WrongAgent {
            minted_for: grant.agent_id().to_string(),
            used_for: registration.agent_id.clone(),
        });
    }
    let cred = registration
        .outbound_cred
        .as_ref()
        .ok_or_else(|| LeaseError::NotConfigured(registration.agent_id.clone()))?;
    mint_from(grant, cred, resolver, now_ms)
}

/// MINT A LEASE from the GRANT and the HANDLE alone.
///
/// The hot path holds a cloned handle rather than the whole registration (a registration carries a
/// cached Agent Card, and cloning one per request would copy a document per call), so this is the
/// entry point [`super::relay`] uses and [`mint`] delegates to.
///
/// THE AGENT ID IS READ OFF THE GRANT, not passed beside it. A signature taking both would admit
/// the one combination that defeats the gate entirely: authorise against the agent the caller
/// holds, mint against the one it does not.
pub(crate) fn mint_from(
    grant: &EgressGrant<'_>,
    cred: &OutboundCredential,
    resolver: &dyn busbar_api::SecretResolve,
    now_ms: u64,
) -> Result<Lease, LeaseError> {
    let agent_id = grant.agent_id();
    let secret = resolver
        .resolve_string(&cred.secret)
        .map_err(|err| LeaseError::Unresolved {
            agent_id: agent_id.to_string(),
            err,
        })?;
    Ok(Lease {
        agent_id: agent_id.to_string(),
        placement: cred.placement.clone(),
        secret,
        expires_at_ms: now_ms.saturating_add(cred.lease_ttl_ms),
    })
}

#[cfg(test)]
#[path = "tests/creds_tests.rs"]
mod creds_tests;
