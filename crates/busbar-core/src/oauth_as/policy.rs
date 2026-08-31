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
//! 2. **The policy is a decision somebody wrote.** `oauth-as` refuses every registration when no
//!    [`RegistrationPolicy`] is installed, so an open endpoint cannot be reached by setting a config
//!    field and moving on. [`OpenRegistration`] below is that decision, and it is deliberately the
//!    smallest possible one: it says who may register, and it says NOTHING about what they get,
//!    because the ceiling above is not the policy's to move.
//!
//! ## The escalation the ceiling alone would NOT stop
//!
//! A registrant cannot widen its scope, but it could try to widen its GRANT TYPES — asking for
//! `client_credentials`, which mints a token with no user in the loop at all. `RegistrationConfig`'s
//! `allowed_grant_types` is therefore pinned to the two the authorization-code flow needs, and the
//! adversarial test asserts the refusal rather than the configuration.

use oauth_as::registration::{RegistrationAttempt, RegistrationDecision, RegistrationPolicy};

/// The policy for every deployment that configured `oauth_as:`: anyone may register, and
/// registering buys exactly the operator's `default_grant`. There is no toggle — the 1.6.0 ruling
/// is that all three registration mechanisms are ON whenever the plane is.
///
/// "Anyone may register" is the honest reading of what the operator asked for — the clients this
/// mechanism exists for (Codex, ChatGPT, Claude.ai) have no prior relationship with the deployment
/// and no initial access token to present, so a policy that demanded one would advertise a
/// registration endpoint no real client can use. What makes that safe is that registration confers
/// no authority: see the module header.
pub(crate) struct OpenRegistration;

impl RegistrationPolicy for OpenRegistration {
    fn authorize(&self, attempt: &RegistrationAttempt<'_>) -> RegistrationDecision {
        // ONE refusal, and it is not about authority. A registrant that names itself after this
        // deployment is phishing the consent screen: the screen shows `client_name`, and a user
        // asked to approve "busbar" cannot tell the gateway from a stranger who typed the word.
        // Refused here rather than escaped at render time, because an escape makes the string safe
        // to display and does nothing about it being a lie.
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

/// Does this `client_name` claim to be busbar itself?
///
/// Case-insensitive and substring-based, which is deliberately blunt: the cost of a false positive
/// is that a client picks a different name, and the cost of a false negative is a consent screen
/// that lies to a user about who is asking.
///
/// `pub(super)` because [`super::cimd`] applies the SAME refusal to a metadata document's
/// `client_name`: a client that arrives by the replacement mechanism must not be able to say the
/// word the deprecated one is refused for.
pub(super) fn name_impersonates_the_deployment(name: &str) -> bool {
    name.to_ascii_lowercase().contains("busbar")
}

/// The RFC 7591 configuration: the CEILING, built from the operator's `default_grant`.
///
/// UNCONDITIONAL. Registration mounts whenever the plane does — `oauth-as` derives its route table
/// from the metadata document, so the always-advertised `registration_endpoint` here and the
/// always-mounted `/register` in `routes::mount` are two views of the same ruling and must agree.
pub(crate) fn registration_config(
    identity: &super::config::AsIdentity,
) -> Box<oauth_as::registration::RegistrationConfig> {
    let mut config = oauth_as::registration::RegistrationConfig::new();
    // Derived from the issuer rather than from the path, because this member is an absolute URL
    // and the path is what the router matched. Two spellings of one endpoint is how an
    // advertised endpoint and a served one drift apart.
    config.registration_endpoint = Some(format!("{}/register", identity.issuer()));
    config.allowed_scopes = default_grant_scopes(identity);
    // THE GRANTS A SELF-REGISTERED CLIENT MAY USE. `client_credentials` is deliberately absent: it
    // mints a token with no resource owner in the loop, so a client that could register itself into
    // it would have converted "I exist" into "I am authorised", which is the escalation this whole
    // module is about. `device_code` is absent for the same reason RFC 8628 section 5.4 gives —
    // it is the grant a remote-phishing attacker starts on the victim's behalf.
    config.allowed_grant_types = vec![
        oauth_as::grant::GrantType::AuthorizationCode,
        oauth_as::grant::GrantType::RefreshToken,
    ];
    // RFC 7592 management is OFF. A registration that can be rewritten after it was approved is a
    // way to change what a user consented to without asking them again, and nothing in the MCP
    // client population uses it.
    config.management_enabled = false;
    Box::new(config)
}

/// The operator's `default_grant` as a `ScopeSet`.
///
/// Shared by the registration ceiling and by the CIMD path, so a client that arrives by the
/// deprecated mechanism and one that arrives by its replacement land on the SAME ceiling. Two
/// spellings of "what a self-registered client gets" is exactly the drift that would make the
/// adversarial test below true of one mechanism and false of the other.
pub(crate) fn default_grant_scopes(
    identity: &super::config::AsIdentity,
) -> oauth_as::scope::ScopeSet {
    // `expect` is sound and is not a shortcut: `AsIdentity::from_cfg` already refused every entry
    // that is not an RFC 6749 section 3.3 scope token, at BOOT, naming the offending value. An
    // `unwrap_or_default()` here would silently turn a grammar this crate rejects into an EMPTY
    // ceiling, which fails closed but hides the operator's mistake behind a working server.
    oauth_as::scope::ScopeSet::from_tokens(identity.default_grant())
        .expect("AsIdentity::from_cfg refuses a default_grant entry that is not a scope token")
}

#[cfg(test)]
#[path = "tests/policy_tests.rs"]
mod policy_tests;
