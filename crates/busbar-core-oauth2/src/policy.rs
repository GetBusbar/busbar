// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! REGISTRATION IS NOT A PRIVILEGE ESCALATION PATH.
//!
//! This is the most dangerous surface on this plane, and the danger is not subtle: RFC 7591 lets an
//! unauthenticated caller create a client, and the client it creates is the thing that later asks
//! for a token. If what it may ask for is decided by what it wrote on its own registration, then
//! "register yourself" and "grant yourself" are the same act.
//!
//! The defence has two halves and BOTH are here rather than one being assumed:
//!
//! 1. **The ceiling is configuration, not request content.** `oauth_as.default_grant` is the whole
//!    of what a self-registered client may ever hold, and it defaults to EMPTY. `oauth-as` enforces
//!    it as a REFUSAL (`invalid_client_metadata`) rather than a narrowing, which is the stronger of
//!    the two behaviours: a client that asked for `admin` is told no, rather than quietly issued a
//!    lesser client it then believes is an `admin` one.
//! 2. **The policy is a choice somebody wrote.** `oauth-as` refuses every registration when no
//!    [`RegistrationPolicy`] is installed, so an open endpoint cannot be reached by setting a config
//!    field and moving on. [`OpenRegistration`] below is that choice, and it is deliberately the
//!    smallest possible one: it says who may register, and it says NOTHING about what they get,
//!    because the ceiling above is not the policy's to move.
//!
//! ## Registration is bounded, and what it creates does not outlive its use
//!
//! An unauthenticated registration WRITES a client, and `oauth-as` gives a client no expiry, so an
//! open endpoint is unbounded growth unless something bounds it. Two things do, and both are this
//! plane's:
//!
//! 1. **A throttle.** Registration is bounded by the node's registration budget
//!    (`plane::Registrations`), carried from one config generation to the next, so a reload hands
//!    no caller a fresh budget: at most 60 registrations ADMITTED a minute per process (the
//!    library's derivation is at its `rate_limit` module). A registration refused, or a body that
//!    does not parse, spends none of it, so one caller's refusals cannot close registration for
//!    everyone. `oauth-as`'s shipped `FixedWindowRateLimiter`, carried the same way, bounds the
//!    authorization endpoint and client authentication at the token endpoint.
//! 2. **Reclamation.** A self-registered client that has held nothing (no code, token, refresh
//!    token, pushed request, device grant or consent) for [`REGISTERED_CLIENT_IDLE`] is deleted by
//!    the sweep, in the deployment's store (`shared`) and in this process (`cimd::Records`) alike.
//!    A client the operator provisioned (`oauth_as.clients:`) and a metadata-document client are
//!    never stored, so neither is ever reclaimed. A reclaimed client that comes back is told
//!    `invalid_client` and registers again, which RFC 7591 clients do.
//!
//! ## The escalation the ceiling alone would NOT stop
//!
//! A registrant cannot widen its scope, but it could try to widen its GRANT TYPES — asking for
//! `client_credentials`, which mints a token with no user in the loop at all. `RegistrationConfig`'s
//! `allowed_grant_types` is therefore pinned to the two the authorization-code flow needs, and the
//! adversarial test asserts the refusal rather than the configuration.

use crate::config::AsIdentity;
use oauth_as::registration::{RegistrationAttempt, RegistrationDecision, RegistrationPolicy};

pub(crate) const REGISTERED_CLIENT_IDLE: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

pub(crate) struct OpenRegistration;

impl RegistrationPolicy for OpenRegistration {
    fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        if attempt
            .metadata
            .client_name
            .as_deref()
            .is_some_and(name_impersonates_the_deployment)
        {
            return RegistrationDecision::Deny;
        }
        RegistrationDecision::Allow
    }
}

pub(super) fn name_impersonates_the_deployment(name: &str) -> bool {
    name.to_ascii_lowercase().contains("busbar")
}

pub(crate) fn registration_config(
    identity: &AsIdentity,
) -> Box<oauth_as::registration::RegistrationConfig> {
    let mut config = oauth_as::registration::RegistrationConfig::new();

    config.registration_endpoint = Some(format!("{}/register", identity.issuer()));
    config.allowed_scopes = default_grant_scopes(identity);

    config.allowed_grant_types = vec![
        oauth_as::grant::GrantType::AuthorizationCode,
        oauth_as::grant::GrantType::RefreshToken,
    ];

    config.management_enabled = false;
    Box::new(config)
}

pub(crate) fn default_grant_scopes(identity: &AsIdentity) -> oauth_as::scope::ScopeSet {
    oauth_as::scope::ScopeSet::from_tokens(identity.default_grant())
        .expect("AsIdentity::from_cfg refuses a default_grant entry that is not a scope token")
}

#[cfg(test)]
#[path = "tests/policy_tests.rs"]
mod policy_tests;
