// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Registered OAuth clients, mirrored from RFC 6749 section 2 with the OAuth 2.1 public /
//! confidential split.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::grant::GrantType;
use crate::scope::ScopeSet;

/// A client identifier (RFC 6749 section 2.2): opaque to this crate, unique per registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(String);

impl ClientId {
    /// Wrap an identifier.
    pub fn new(id: impl Into<String>) -> Self {
        ClientId(id.into())
    }

    /// The identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the client authenticates to the token endpoint (RFC 6749 section 2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientAuth {
    /// A public client (native app, browser app, device): no secret exists, so possession of the
    /// `client_id` proves nothing and the flows compensate (PKCE, device-code user interaction).
    Public,
    /// A confidential client holding a secret. The host decides how the secret at rest is
    /// protected; this crate only compares, in constant time.
    ConfidentialSecret {
        /// The shared secret the client presents.
        secret: String,
    },
}

impl ClientAuth {
    /// Verify a presented secret. Public clients accept `None` and reject any presented secret
    /// (presenting a secret for a secretless registration is a client mixup worth failing loud
    /// on). Confidential clients require the exact secret; comparison is constant time in the
    /// length of the registered secret.
    pub fn verify(&self, presented: Option<&str>) -> bool {
        match self {
            ClientAuth::Public => presented.is_none(),
            ClientAuth::ConfidentialSecret { secret } => match presented {
                Some(p) => constant_time_eq(secret.as_bytes(), p.as_bytes()),
                None => false,
            },
        }
    }
}

/// Constant-time byte comparison: the accumulator visits every byte of both inputs regardless of
/// where the first difference sits, so timing does not leak a prefix match. Length inequality is
/// folded into the accumulator rather than short-circuited.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc: u8 = (a.len() ^ b.len()) as u8 | ((a.len() ^ b.len()) >> 8) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        acc |= x ^ y;
    }
    acc == 0
}

/// A registered client: identity, authentication, and what it is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// The unique client identifier.
    pub client_id: ClientId,
    /// How the client authenticates.
    pub auth: ClientAuth,
    /// The grant types this registration may use; anything else is `unauthorized_client`.
    pub grant_types: Vec<GrantType>,
    /// Registered redirect URIs (authorization-code grant; exact-match per OAuth 2.1).
    pub redirect_uris: Vec<String>,
    /// The scopes this client may ever be granted; a request outside this set is `invalid_scope`.
    pub allowed_scopes: ScopeSet,
    /// The scopes granted when a request names none (RFC 6749 section 3.3 server default).
    pub default_scopes: ScopeSet,
    /// Human-readable name for consent and admin surfaces.
    pub name: Option<String>,
}

impl Client {
    /// Whether the registration permits `grant_type`.
    pub fn allows_grant(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_client_rejects_a_presented_secret() {
        let auth = ClientAuth::Public;
        assert!(auth.verify(None));
        assert!(!auth.verify(Some("anything")));
    }

    #[test]
    fn confidential_client_requires_the_exact_secret() {
        let auth = ClientAuth::ConfidentialSecret {
            secret: "s3cret".into(),
        };
        assert!(auth.verify(Some("s3cret")));
        assert!(!auth.verify(Some("s3creT")));
        assert!(!auth.verify(Some("s3cret-and-more")));
        assert!(!auth.verify(Some("")));
        assert!(!auth.verify(None));
    }

    #[test]
    fn constant_time_eq_agrees_with_eq() {
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"", b"", true),
            (b"a", b"", false),
            (b"", b"a", false),
            (b"abc", b"abc", true),
            (b"abc", b"abd", false),
            (b"abc", b"abcd", false),
        ];
        for (a, b, want) in cases {
            assert_eq!(constant_time_eq(a, b), *want, "{:?} vs {:?}", a, b);
        }
    }
}
