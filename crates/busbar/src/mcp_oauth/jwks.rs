// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWKS (JSON Web Key Set) model + verify-ready key material for the MCP resource server. Pure data
//! plus `ring` key material; no I/O — the operator hands busbar the key set out of band (see
//! [`super`] on why there is no `jwks_uri` fetch on this path).
//!
//! A JWKS is an authorization server's set of PUBLIC signing keys, each tagged by `kid`; a token's
//! header `kid` selects which one is allowed to have signed it.
//!
//! **On the duplication with `auth-oidc`.** The `auth-oidc` plugin carries a sibling of this model
//! and of [`super::jwt`], and the two are deliberate copies rather than a shared crate today: core
//! cannot call into a `dlopen`ed plugin on the request path, and the plugin ABI's
//! `AuthResponse { Identity }` has no slot for an audience or a client id
//! (`crates/plugin-abi/src/auth.rs`), so the resource server cannot delegate the one check it exists
//! to perform. When the two are unified the merge point is `crates/api`, which `auth-oidc` already
//! depends on. Recorded here so the next reader finds the reason rather than the smell.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use std::sync::OnceLock;

/// The base64url-decoded, verify-ready key material for one [`Jwk`], decoded ONCE (at first use,
/// then memoised on the owning key) so the per-request verify path never re-decodes `n`/`e` (RSA) or
/// `x`/`y` (EC). `Unusable` carries the precise error the decode raised, so a malformed key still
/// fails with an exact message at verify time and one odd key never poisons the parse of a whole set.
#[derive(Debug, Clone)]
pub(crate) enum KeyMaterial {
    /// RSA modulus + exponent, decoded from `n`/`e`.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// EC public point in uncompressed SEC1 form `0x04 || X || Y`, decoded from `x`/`y`.
    Ec { point: Vec<u8> },
    /// The material was absent or not base64url; the deferred error surfaces at verify time.
    Unusable(String),
}

impl KeyMaterial {
    /// Decode a key's material from its base64url fields, selected by `kty`. Never fails — a decode
    /// problem becomes [`KeyMaterial::Unusable`] so it surfaces at verify time with an exact message
    /// instead of vanishing at parse time.
    fn from_jwk(jwk: &Jwk) -> Self {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = match b64(jwk.n.as_deref(), "RSA modulus n") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                let e = match b64(jwk.e.as_deref(), "RSA exponent e") {
                    Ok(v) => v,
                    Err(err) => return Self::Unusable(err),
                };
                Self::Rsa { n, e }
            }
            "EC" => {
                let x = match b64(jwk.x.as_deref(), "EC coordinate x") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                let y = match b64(jwk.y.as_deref(), "EC coordinate y") {
                    Ok(v) => v,
                    Err(e) => return Self::Unusable(e),
                };
                // ring wants the uncompressed SEC1 point: 0x04 || X || Y.
                let mut point = Vec::with_capacity(1 + x.len() + y.len());
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Self::Ec { point }
            }
            other => Self::Unusable(format!("JWKS key has unsupported kty {other}")),
        }
    }
}

/// base64url-decode a required JWK field, naming the field on absence or bad format.
fn b64(field: Option<&str>, what: &str) -> Result<Vec<u8>, String> {
    let s = field.ok_or_else(|| format!("JWKS key missing {what}"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| format!("JWKS key {what} is not base64url"))
}

/// One JSON Web Key, the subset the supported algorithms need. Unknown members (`alg`, `x5c`, `x5t`,
/// …) are ignored: a real IdP's JWKS carries more than a verifier consumes, and rejecting on an
/// unknown member would make busbar fail on a perfectly ordinary Okta or Entra key set.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Jwk {
    /// Key type: `RSA` or `EC`. Selects which field group below is populated.
    pub(crate) kty: String,
    /// Key id, matched against a token header's `kid`. Optional in RFC 7517; a keyless key can only
    /// match a keyless header, so absence is treated as the empty id.
    #[serde(default)]
    pub(crate) kid: Option<String>,
    /// RSA modulus (base64url, unpadded). Present when `kty == "RSA"`.
    #[serde(default)]
    pub(crate) n: Option<String>,
    /// RSA public exponent (base64url). Present when `kty == "RSA"`.
    #[serde(default)]
    pub(crate) e: Option<String>,
    /// EC curve name (`P-256` for ES256). Present when `kty == "EC"`.
    #[serde(default)]
    pub(crate) crv: Option<String>,
    /// EC public-point X coordinate (base64url). Present when `kty == "EC"`.
    #[serde(default)]
    pub(crate) x: Option<String>,
    /// EC public-point Y coordinate (base64url). Present when `kty == "EC"`.
    #[serde(default)]
    pub(crate) y: Option<String>,
    /// Public key use (RFC 7517 §4.2): `"sig"` verifies signatures, `"enc"` does not. `use` is a
    /// Rust keyword, hence the rename. A key marked encryption-only must never verify a signature —
    /// enforced in [`super::jwt::verify_signature`].
    #[serde(rename = "use", default)]
    pub(crate) key_use: Option<String>,
    /// Memoised decoded material — decoded once on first verify, reused for every later request
    /// against this key. Not part of the wire form.
    #[serde(skip)]
    pub(crate) decoded: OnceLock<KeyMaterial>,
}

impl Jwk {
    /// The decoded, verify-ready material for this key — decoded once, then memoised.
    pub(crate) fn material(&self) -> &KeyMaterial {
        self.decoded.get_or_init(|| KeyMaterial::from_jwk(self))
    }
}

/// A parsed key set: one authorization server's current signing keys.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct JwkSet {
    /// The keys, from the document's top-level `keys` array.
    pub(crate) keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a JWKS document. An empty `keys` array is REFUSED here rather than at verify time: a
    /// key set that can verify nothing is a configuration mistake that would otherwise present as
    /// "every token is rejected", which is fail-closed but undiagnosable.
    pub(crate) fn parse(body: &str) -> Result<Self, String> {
        let set: Self =
            serde_json::from_str(body).map_err(|e| format!("invalid JWKS document: {e}"))?;
        if set.keys.is_empty() {
            return Err("JWKS document contains no keys".to_string());
        }
        Ok(set)
    }

    /// Every key whose `kid` matches. Selecting by `kid` rather than trying the whole set is what
    /// makes a key id meaningful; more than one key may share a `kid` when `kty` differs (RFC 7517
    /// §4.5, seen during an algorithm migration), so the caller must try every match rather than the
    /// first. A non-empty queried `kid` never falls through to a keyless key: that is only a match
    /// when the queried id is itself empty.
    pub(crate) fn find_all<'a>(&'a self, kid: &'a str) -> impl Iterator<Item = &'a Jwk> {
        self.keys
            .iter()
            .filter(move |k| k.kid.as_deref() == Some(kid) || (kid.is_empty() && k.kid.is_none()))
    }
}
