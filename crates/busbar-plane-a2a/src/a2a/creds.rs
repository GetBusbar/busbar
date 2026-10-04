// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND DELEGATION CREDENTIAL, as the `agents:` grammar spells it: a secret reference plus
//! its lease policy, held by busbar and scoped to one registration. Only the operator-intent types
//! live here; minting and presenting a lease is the host's.

use busbar_contract::secret_ref::SecretRef;

/// Where a leased credential is placed on the outbound request.
///
/// An enum rather than a free-form header name because "put this secret wherever the config says"
/// is how a credential ends up in a query string, and a query string is in every access log on the
/// path.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPlacement {
    /// `Authorization: Bearer <secret>`.
    #[default]
    #[serde(rename = "bearer")]
    AuthorizationHeader,
    /// A named header carrying the secret verbatim (`X-API-Key: <secret>`), which is what several
    /// A2A vendors' `APIKey` security scheme means in practice.
    Header(String),
}

impl CredentialPlacement {
    /// The header this placement writes.
    pub fn header_name(&self) -> &str {
        match self {
            CredentialPlacement::AuthorizationHeader => "authorization",
            CredentialPlacement::Header(name) => name.as_str(),
        }
    }
}

/// The HANDLE plus its lease policy, as the registration holds it. Operator INTENT, so it is
/// overlay state — and the reason `config_validate::secret_refs` now walks the `agents:` arm.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundCredential {
    /// The reference resolved at delegation time. NOT the secret.
    pub secret: SecretRef,
    /// Where the resolved value is placed on the outbound request.
    #[serde(default)]
    pub placement: CredentialPlacement,
    /// How long a minted lease is usable, in milliseconds. Zero is refused at parse: a lease that
    /// has expired before it is used is a credential that can never be presented, and an operator
    /// who wrote `0` meant something they did not get.
    pub lease_ttl_ms: u64,
}
