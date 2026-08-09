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
//! ## The record holds a HANDLE, never the secret
//!
//! [`OutboundCredential`] carries a [`crate::config::SecretRef`] — the module plus its settings —
//! and the secret is resolved at delegation time. It is never in the registration record, never in
//! the Agent Card, and never in a debug rendering: [`Lease`] has a hand-written `Debug` for exactly
//! the reason `VirtualKey` and `CredentialSecret` do.

use crate::config::secret::SecretResolver;
use crate::config::SecretRef;

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

/// MINT A LEASE for one hop.
///
/// The signature is the security property: it takes the REGISTRATION and the clock, and there is no
/// parameter through which an inbound caller's credential could arrive. A future edit that wanted
/// to forward one would have to add an argument, which is a change a reviewer sees.
pub(crate) fn mint(
    registration: &super::registry::AgentRegistration,
    resolver: &SecretResolver,
    now_ms: u64,
) -> Result<Lease, LeaseError> {
    let cred = registration
        .outbound_cred
        .as_ref()
        .ok_or_else(|| LeaseError::NotConfigured(registration.agent_id.clone()))?;
    let secret = resolver
        .resolve_string(&cred.secret)
        .map_err(|err| LeaseError::Unresolved {
            agent_id: registration.agent_id.clone(),
            err,
        })?;
    Ok(Lease {
        agent_id: registration.agent_id.clone(),
        placement: cred.placement.clone(),
        secret,
        expires_at_ms: now_ms.saturating_add(cred.lease_ttl_ms),
    })
}

#[cfg(test)]
#[path = "tests/creds_tests.rs"]
mod creds_tests;
