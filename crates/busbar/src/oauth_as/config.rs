// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `oauth_as:` BLOCK, and the boot-time refusals that make it either whole or absent.
//!
//! Every derivation happens here, once, so nothing downstream re-parses an issuer or re-decides a
//! path. A config that cannot produce an [`AsPlane`] does not boot: an authorization server that is
//! half-configured is worse than one that is absent, because it ANSWERS — and what it answers with
//! is tokens.

use serde::{Deserialize, Serialize};

use busbar_secret_ref::SecretRef;

/// `oauth_as:` — busbar as an OAuth 2.1 authorization server. ABSENT BY DEFAULT.
///
/// Absent means absent: no server object, no store, no signing key, no sweeper, no route. See the
/// module docs on [`super`] for what "costs nothing when off" is measured against.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OauthAsCfg {
    /// RFC 8414 `issuer`: the canonical absolute URL that names THIS authorization server, and the
    /// value every endpoint below is derived from.
    ///
    /// OPERATOR-CONFIGURED rather than derived from the request's `Host`, for the same reason
    /// `mcp.canonical_uri` is: an issuer a caller can choose by sending a header is not an identity.
    /// It is also what RFC 9207 puts in the `iss` of every authorization response, so a client
    /// comparing it byte-for-byte against what it discovered is doing the mix-up defence — which
    /// only works if this value never moves.
    pub(crate) issuer: String,

    /// The ES256 signing key, as a base64 PKCS#8 v1 DER document.
    ///
    /// ABSENT IS LEGAL AND IT IS THE DEVELOPMENT CASE: busbar generates an ephemeral key at boot and
    /// says so at `warn`. That is deliberate, because the alternative — refusing to boot without a
    /// key — makes trying this out a procurement exercise, and the failure it prevents is loud
    /// anyway: an ephemeral key means every token this deployment issued stops verifying the moment
    /// the process restarts. What must NOT happen is a DEFAULT key, which would be a published
    /// private key that signs valid tokens for every deployment that never set this field.
    #[serde(default)]
    pub(crate) signing_key: Option<SecretRef>,

    /// The `kid` published in the JWKS and carried in every token header. Advisory; it exists so an
    /// operator rotating keys can tell two of them apart in a log.
    #[serde(default)]
    pub(crate) key_id: Option<String>,

    /// RFC 7591 DYNAMIC CLIENT REGISTRATION. OFF BY DEFAULT.
    ///
    /// The `2026-07-28` MCP revision marks DCR *deprecated, retained for backwards compatibility*.
    /// It is here because the clients shipping today — Codex, ChatGPT, Claude.ai — speak it, and a
    /// gateway that cannot be registered with cannot be connected to. It is OFF by default because
    /// RFC 7591 section 5 is about an anonymous client-minting endpoint on the internet, and turning
    /// one on should be a line somebody wrote and a reviewer can find.
    #[serde(default)]
    pub(crate) dynamic_registration: bool,

    /// THE CEILING. What a client that registered itself — by either mechanism — is allowed to ask
    /// for, and it is the whole of what it gets.
    ///
    /// EMPTY BY DEFAULT, which means a self-registered client may request no scope at all and any
    /// `scope` member on its registration is refused `invalid_client_metadata`. An operator widens
    /// this deliberately; nothing widens it on their behalf, and no request widens it at runtime.
    #[serde(default)]
    pub(crate) default_grant: Vec<String>,

    /// Access token lifetime in seconds. Short on purpose (RFC 9728 §7 / the MCP revision's token
    /// theft note both ask for it); a client that wants continuity refreshes.
    #[serde(default)]
    pub(crate) access_token_ttl_secs: Option<u64>,
}

/// Why an `oauth_as:` block was refused at boot. Every arm names the field and what a correct value
/// looks like, because an operator reading "invalid oauth_as config" cannot act on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AsCfgError {
    /// `issuer` is empty.
    MissingIssuer,
    /// `issuer` is not an absolute `http(s)` URL.
    IssuerNotAbsolute(String),
    /// `issuer` carries a query or a fragment. RFC 8414 §2 makes the issuer a URL with no query and
    /// no fragment, and it is compared for exact equality, so normalising one away here would hand
    /// back a string that no longer equals what a client discovered.
    IssuerHasQueryOrFragment(String),
    /// `issuer` ends in `/`. A trailing slash makes `{issuer}/token` into `{issuer}//token`, which
    /// is a different path, and the RFC 9207 `iss` comparison is byte-for-byte.
    IssuerHasTrailingSlash(String),
    /// `default_grant` names a scope that is not a legal RFC 6749 §3.3 scope token.
    ScopeNotAToken(String),
}

impl std::fmt::Display for AsCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsCfgError::MissingIssuer => f.write_str(
                "oauth_as.issuer is required. It is this authorization server's identity: the value \
                 a client compares against the `iss` of every response it gets (RFC 9207), and the \
                 base every endpoint is derived from. Example: \
                 `issuer: https://gw.example.com`",
            ),
            AsCfgError::IssuerNotAbsolute(v) => write!(
                f,
                "oauth_as.issuer `{v}` is not an absolute http(s) URL. Example: \
                 `https://gw.example.com`"
            ),
            AsCfgError::IssuerHasQueryOrFragment(v) => write!(
                f,
                "oauth_as.issuer `{v}` carries a query or a fragment. RFC 8414 section 2 defines \
                 the issuer as a URL with neither, and it is compared byte-for-byte."
            ),
            AsCfgError::IssuerHasTrailingSlash(v) => write!(
                f,
                "oauth_as.issuer `{v}` ends in `/`. Every endpoint is derived as `{{issuer}}/name`, \
                 so a trailing slash produces `//name` — a different path from the one clients ask \
                 for. Write it without the slash."
            ),
            AsCfgError::ScopeNotAToken(v) => write!(
                f,
                "oauth_as.default_grant entry `{v}` is not a scope token. RFC 6749 section 3.3 \
                 allows printable ASCII except space, double quote and backslash."
            ),
        }
    }
}

/// The VALIDATED authorization server: every endpoint derived, every refusal already taken.
///
/// Holds no key and no server object — those are runtime state and live on [`super::plane::AsPlane`].
/// This is the config half, so it can be compared, logged and swapped without touching a secret.
/// The fields are `pub(crate)` for ONE reason, and it is not convenience: every value in this struct
/// is still read through the accessors below, but `config_validate::secret_refs` must be able to
/// DESTRUCTURE it exhaustively. That walker's whole design is that a newly added secret-bearing
/// field is a COMPILE error rather than an oversight, and a walk through an accessor cannot deliver
/// that — `identity.signing_key()` keeps compiling on the day somebody adds a second `SecretRef`
/// here, and the new secret is then one `--validate` reports as fine and the process fails on at
/// runtime. The destructure is the enforcement; the visibility is what the destructure costs.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AsIdentity {
    pub(crate) issuer: String,
    /// The path component of `issuer`, normalised, so a tenant-prefixed issuer
    /// (`https://host/tenant`) mounts its endpoints under that prefix rather than at the root.
    pub(crate) issuer_path: String,
    pub(crate) metadata_path: String,
    pub(crate) authorize_path: String,
    pub(crate) token_path: String,
    pub(crate) register_path: Option<String>,
    pub(crate) jwks_path: String,
    pub(crate) consent_path: String,
    pub(crate) default_grant: Vec<String>,
    pub(crate) dynamic_registration: bool,
    pub(crate) access_token_ttl: std::time::Duration,
    pub(crate) key_id: String,
    /// The operator's `signing_key:` reference, carried VERBATIM and unresolved.
    ///
    /// It lives on the validated identity rather than being consumed at `resolve` time because
    /// `config_validate::secret_refs` walks `RootCfg` and must be able to SEE it: a secret the
    /// walker cannot reach is a secret nothing checks, and that walker's whole design is that
    /// omission is a compile error rather than an oversight.
    pub(crate) signing_key: Option<SecretRef>,
}

/// RFC 8414 §3.1: the well-known segment goes BEFORE the issuer's path, not after it. This is the
/// one detail of the document that is easy to get backwards, and getting it backwards means every
/// conforming client's discovery 404s. (RFC 9728 inserts the path the OTHER way round, which is why
/// `mcp::PROTECTED_RESOURCE_WELL_KNOWN` and this constant are used differently a few lines apart.)
const AS_WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";

/// The default access token lifetime: ten minutes. Short because the MCP revision's token-theft note
/// asks for short-lived access tokens, and a client that wants continuity has a refresh token.
const DEFAULT_ACCESS_TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(600);

impl AsIdentity {
    /// Validate and derive. Every refusal is at BOOT rather than at first request: an operator finds
    /// out from a process that will not start, not from an agent that cannot log in.
    pub(crate) fn from_cfg(cfg: &OauthAsCfg) -> Result<Self, AsCfgError> {
        let issuer = cfg.issuer.trim();
        if issuer.is_empty() {
            return Err(AsCfgError::MissingIssuer);
        }
        if issuer.contains('?') || issuer.contains('#') {
            return Err(AsCfgError::IssuerHasQueryOrFragment(issuer.to_string()));
        }
        let (_origin, path) = split_absolute(issuer)
            .ok_or_else(|| AsCfgError::IssuerNotAbsolute(issuer.to_string()))?;
        if issuer.ends_with('/') {
            return Err(AsCfgError::IssuerHasTrailingSlash(issuer.to_string()));
        }
        for scope in &cfg.default_grant {
            if !is_scope_token(scope) {
                return Err(AsCfgError::ScopeNotAToken(scope.clone()));
            }
        }

        let issuer_path = path.trim_end_matches('/').to_string();
        let under = |name: &str| format!("{issuer_path}/{name}");

        Ok(Self {
            issuer: issuer.to_string(),
            // The well-known path is `/.well-known/oauth-authorization-server` at the ROOT, with the
            // issuer's own path appended after it (RFC 8414 §3.1).
            metadata_path: format!("{AS_WELL_KNOWN}{issuer_path}"),
            authorize_path: under("authorize"),
            token_path: under("token"),
            register_path: cfg.dynamic_registration.then(|| under("register")),
            jwks_path: under("jwks"),
            consent_path: under("consent"),
            issuer_path,
            default_grant: cfg.default_grant.clone(),
            dynamic_registration: cfg.dynamic_registration,
            access_token_ttl: cfg
                .access_token_ttl_secs
                .map_or(DEFAULT_ACCESS_TOKEN_TTL, std::time::Duration::from_secs),
            key_id: cfg.key_id.clone().unwrap_or_else(|| "busbar-as-1".into()),
            signing_key: cfg.signing_key.clone(),
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }
    pub(crate) fn metadata_path(&self) -> &str {
        &self.metadata_path
    }
    pub(crate) fn authorize_path(&self) -> &str {
        &self.authorize_path
    }
    pub(crate) fn token_path(&self) -> &str {
        &self.token_path
    }
    pub(crate) fn register_path(&self) -> Option<&str> {
        self.register_path.as_deref()
    }
    pub(crate) fn jwks_path(&self) -> &str {
        &self.jwks_path
    }
    pub(crate) fn consent_path(&self) -> &str {
        &self.consent_path
    }
    /// The absolute URL of the consent screen, which is what the authorize endpoint redirects a
    /// browser to. Absolute because the user agent is following it from wherever it started.
    pub(crate) fn consent_url(&self) -> String {
        format!("{}{}", self.origin(), self.consent_path)
    }
    pub(crate) fn jwks_uri(&self) -> String {
        format!("{}{}", self.origin(), self.jwks_path)
    }
    /// The issuer's `scheme://authority`, with its path removed.
    fn origin(&self) -> &str {
        &self.issuer[..self.issuer.len() - self.issuer_path.len()]
    }
    pub(crate) fn default_grant(&self) -> &[String] {
        &self.default_grant
    }
    pub(crate) fn dynamic_registration(&self) -> bool {
        self.dynamic_registration
    }
    pub(crate) fn access_token_ttl(&self) -> std::time::Duration {
        self.access_token_ttl
    }
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    pub(crate) fn signing_key(&self) -> Option<&SecretRef> {
        self.signing_key.as_ref()
    }
}

/// Split an absolute `http(s)` URL into `(origin, path)`, or `None` when it is not one.
///
/// Hand-written for the same reason `mcp::split_absolute` is: what is needed is a STRICT recogniser
/// for one shape, and a permissive general-purpose parser is the wrong tool for a value whose whole
/// job is to be compared for exact equality. A lenient parse that normalised `HTTPS://Host:443/as`
/// would hand back a string that no longer equals the `iss` a client recorded.
fn split_absolute(uri: &str) -> Option<(&str, &str)> {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;
    let authority_len = rest.find('/').unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let split = uri.len() - rest.len() + authority_len;
    Some((&uri[..split], &uri[split..]))
}

/// RFC 6749 §3.3 `scope-token`: one or more of `%x21 / %x23-5B / %x5D-7E` — printable ASCII except
/// space, double quote and backslash.
fn is_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
