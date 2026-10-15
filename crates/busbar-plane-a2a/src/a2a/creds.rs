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
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize)]
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

/// THE TWO SPELLINGS the section grammar states (`busbar_contract::section`, `placement:`):
/// `bearer`, or an object naming the header, `{header: <name>}`. Read by hand rather than derived
/// because the section reaches this parse as a YAML value (`busbar_contract::section::split_section`),
/// and a YAML value reads a derived enum only from a tag (`!header <name>`), never from the object
/// the grammar documents; the tag spelling is read too.
impl<'de> serde::Deserialize<'de> for CredentialPlacement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Placement;
        impl<'de> serde::de::Visitor<'de> for Placement {
            type Value = CredentialPlacement;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("`bearer` or `{header: <name>}`")
            }
            fn visit_str<E: serde::de::Error>(self, word: &str) -> Result<Self::Value, E> {
                match word {
                    "bearer" => Ok(CredentialPlacement::AuthorizationHeader),
                    other => Err(E::unknown_variant(other, &["bearer", "header"])),
                }
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let Some(key) = map.next_key::<String>()? else {
                    return Err(A::Error::invalid_length(0, &self));
                };
                let placement = match key.as_str() {
                    "header" => CredentialPlacement::Header(map.next_value()?),
                    "bearer" => {
                        map.next_value::<serde::de::IgnoredAny>()?;
                        CredentialPlacement::AuthorizationHeader
                    }
                    other => return Err(A::Error::unknown_variant(other, &["bearer", "header"])),
                };
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(
                        "`placement:` names one placement, not several",
                    ));
                }
                Ok(placement)
            }
            fn visit_enum<A: serde::de::EnumAccess<'de>>(
                self,
                data: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::{Error as _, VariantAccess as _};
                let (word, variant) = data.variant::<String>()?;
                match word.as_str() {
                    "bearer" => variant
                        .unit_variant()
                        .map(|()| CredentialPlacement::AuthorizationHeader),
                    "header" => variant.newtype_variant().map(CredentialPlacement::Header),
                    other => Err(A::Error::unknown_variant(other, &["bearer", "header"])),
                }
            }
        }
        deserializer.deserialize_any(Placement)
    }
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
