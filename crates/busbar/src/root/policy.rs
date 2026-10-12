// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The values the units take from configuration rather than from a `Default`, and the one place
//! that is decided.
//!
//! ## Why a default is the wrong answer here
//!
//! Every value below has a perfectly sensible `Default` or a perfectly sensible empty case, and
//! none of them is safe to bind: a transport built from its own default ignores the operator's
//! limits, and an empty scope view authorizes everything.
//!
//! **The scope view.** Its natural empty case is a policy that says nothing about anything, and the
//! scope unit is explicit that a pair the policy is silent about has NO required scope, which is a
//! REFUSAL and not a pass. An operation nobody wrote a policy entry for has not been authorized. A
//! view that inverted that — answering "read-only is enough" for an unknown pair, or answering
//! `Some` where it meant "I do not know" — would authorize by omission, and every plane's operation
//! classes would open at once. So the type below cannot express the inversion: it holds declared
//! entries and answers `None` for everything else, and the only way to permit something is to have
//! said so.
//!
//! ## What is not here
//!
//! The hook-veto seat. The scope unit does not reach the hook machinery and says so; the
//! composition is the root's, and it is an ordering rather than a value: the scope check runs
//! first, and a veto after it wins regardless of what it returned. That ordering belongs to the
//! step, not to the policy it reads, so it is not a field of anything in this file.

use std::collections::BTreeMap;

use busbar_contract::transport::TransportSettings;
use busbar_contract::{ClaimKey, OpClassId};
use busbar_kernel::config::limits::LimitsResolved;
use busbar_kernel_scope::{PolicyView, Scope};

/// The settings every linked transport is built from, taken off the deployment's resolved limits
/// rather than from a `Default`.
///
/// Every field of `TransportSettings` is an operator knob that already has a home in `limits:` /
/// `advanced:`, and the legacy serving path builds its upstream client from exactly these six
/// values. The one that matters most is `request_body_max_bytes`: it is the SAME number the served
/// door's inbound body limit is built from, so a transport built from a `Default` would accept a
/// body the door refused (or refuse one the door accepted) on any deployment that set the knob.
/// `request_timeout_secs` is the same shape of hazard for a different knob: a deployment that
/// raised `limits.upstream_request_timeout_secs` for long generations must have the transport's own
/// `client.request()` wait raised with it, not silently re-capped at a transport-crate default.
/// Reading all six off one struct is what makes that impossible to get half-right.
///
/// A deployment that sets nothing gets the config layer's own resolved defaults — which for the
/// body cap is the same 32 MiB `TransportSettings::default()` carries, so an unset limit changes
/// nothing.
///
/// The two deprecated upstream env overrides are read here, as 1.5.5 read them at its client build:
/// `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` and `BUSBAR_UPSTREAM_HTTP1_ONLY`, when set, win over
/// `advanced.upstream_h2_prior_knowledge` / `advanced.upstream_http1_only` (anything but empty or
/// `0` reads as on). The transports these settings open (the http door's prior-knowledge and
/// http1-only keys) are the egress client now, so an existing pin keeps working across the upgrade.
/// The deprecation line itself is the kernel's app build's, in 1.5.5's words, once per boot.
#[must_use]
pub fn client_settings(limits: &LimitsResolved) -> TransportSettings {
    client_settings_under(limits, |name| std::env::var_os(name))
}

/// [`client_settings`] with the process environment read through `env`.
#[must_use]
pub(crate) fn client_settings_under(
    limits: &LimitsResolved,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> TransportSettings {
    use busbar_kernel::appbuild::{
        upstream_bool_env_override, ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE, ENV_UPSTREAM_HTTP1_ONLY,
    };
    TransportSettings {
        pool_max_idle_per_host: limits.pool_max_idle_per_host,
        pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
        upstream_http1_only: upstream_bool_env_override(
            env(ENV_UPSTREAM_HTTP1_ONLY),
            limits.upstream_http1_only,
        ),
        upstream_h2_prior_knowledge: upstream_bool_env_override(
            env(ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE),
            limits.upstream_h2_prior_knowledge,
        ),
        request_body_max_bytes: limits.request_body_max_bytes,
        // The deployment resolves one body limit; the transport holds it against both directions,
        // which is the same posture its own default takes.
        response_body_max_bytes: limits.request_body_max_bytes,
        request_timeout_secs: limits.upstream_request_timeout_secs,
    }
}

/// The scope unit's policy view, over what the deployment's policy actually declared.
///
/// It holds entries and nothing else. There is no default arm, no catch-all and no "unknown means
/// read-only": a pair with no entry answers `None`, and the scope unit reads `None` as a refusal.
/// The type is shaped so that the dangerous answer cannot be given by accident — you cannot
/// construct one that permits something it was not told about.
#[derive(Debug, Default, Clone)]
pub struct ScopePolicy {
    entries: BTreeMap<(&'static str, &'static str), Scope>,
}

impl ScopePolicy {
    /// A policy that permits nothing, because it has been told nothing.
    #[must_use]
    pub fn new() -> Self {
        ScopePolicy::default()
    }

    /// Declare the scope one claim's operation class requires.
    #[must_use]
    pub fn declaring(mut self, claim: ClaimKey, op: OpClassId, scope: Scope) -> Self {
        self.entries.insert((claim.as_str(), op.as_str()), scope);
        self
    }

    /// How many pairs the policy speaks about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the policy speaks about nothing, and therefore permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl PolicyView for ScopePolicy {
    fn required_scope(&self, claim: ClaimKey, op: OpClassId) -> Option<Scope> {
        // `None` here is a refusal, not a pass, and this is the whole of the implementation for
        // exactly that reason: there is nowhere for a fallback to be added by accident.
        self.entries.get(&(claim.as_str(), op.as_str())).copied()
    }
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
