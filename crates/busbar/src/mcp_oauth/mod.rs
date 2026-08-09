// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar as an OAuth **RESOURCE SERVER** for its own MCP endpoint.
//!
//! # The line this module does not cross
//!
//! busbar is the resource server and NOTHING ELSE here. It issues no token, runs no `/authorize`,
//! no `/token`, no code exchange, and authenticates no human. The authorization server is the
//! operator's existing IdP (Okta, Entra, Auth0), and a busbar-hosted authorization server is
//! separate, deferred, plugin-shaped work. If a future change in this module starts minting a
//! credential, it is in the wrong module.
//!
//! # The flow
//!
//! ```text
//! POST https://busbar.acme.com/mcp                     (no credential)
//!   -> 401 Unauthorized
//!      WWW-Authenticate: Bearer resource_metadata="https://busbar.acme.com/.well-known/oauth-protected-resource/mcp"
//!
//! GET  https://busbar.acme.com/.well-known/oauth-protected-resource/mcp
//!   -> { "resource": "...", "authorization_servers": ["https://acme.okta.com/oauth2/default"], ... }
//! ```
//!
//! The agent then leaves MCP entirely, does ordinary OAuth against that authorization server over
//! plain HTTPS, and comes back with an access token. Everything busbar does at that point is in
//! [`ResourceServer::admit`].
//!
//! # The one check this whole surface exists for
//!
//! **The token's audience must be busbar itself.** A token minted for some other service — a token
//! the operator's IdP quite legitimately issued to the same agent for a different API — MUST be
//! refused (RFC 8707 resource indicators, and the MCP authorization specification's confused-deputy
//! requirement). Without it busbar is a confused deputy: it would accept a credential intended for elsewhere and act on it
//! with busbar's own upstream authority, and every other gate in the system would still report
//! green, because every other gate is asking a different question. The audience comparison therefore
//! lives in [`ResourceServer::admit`] beside the signature check, not in a handler, so a route added
//! later cannot forget it.
//!
//! # Relationship to the P1 plane boundary
//!
//! `governance::signing`'s `aud` claim is the mirror of this check for busbar-MINTED tokens: it
//! keeps a token bound to the MCP plane off the data plane. This module is the other half — it keeps
//! a token bound to some OTHER resource off the MCP plane. Both are needed and neither implies the
//! other.
//!
//! # Why the key set is operator-supplied rather than fetched from a `jwks_uri`
//!
//! The keys arrive out of band, in config. That is the same posture busbar takes for every other
//! upstream trust root — operator-pinned, never trust-on-first-use, never "fetch and hope" — and it
//! buys three things a runtime fetch does not: no SSRF surface reachable from an
//! unauthenticated request path, no IdP outage turning into a busbar outage, and hermetic tests that
//! cannot pass by silently skipping a network call. A `jwks_uri` refresh is a real follow-up for
//! operators who rotate often; it is additive (a second source for the same [`jwks::JwkSet`]) and is
//! deliberately not on the critical path of the audience check.

use std::sync::Arc;

pub(crate) mod http;
pub(crate) mod jwks;
pub(crate) mod jwt;

#[cfg(test)]
#[path = "tests/admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "tests/http_tests.rs"]
mod http_tests;
#[cfg(test)]
#[path = "tests/jwks_tests.rs"]
mod jwks_tests;
#[cfg(test)]
#[path = "tests/jwt_tests.rs"]
mod jwt_tests;
#[cfg(test)]
#[path = "tests/metadata_tests.rs"]
mod metadata_tests;
#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod support;

/// busbar's MCP ingress mount. FIXED, not operator-chosen: the RFC 9728 metadata document's path is
/// derived from the resource's path (`/.well-known/oauth-protected-resource` + `/mcp`), and a
/// derived path that is also a `&'static str` route pattern is what lets the metadata route be
/// mounted by exact match rather than by a prefix exception, which is the rule every route bypass in
/// this codebase follows. `canonical_uri` is validated to carry exactly this path, so the document busbar serves and
/// the document a client derives are the same URL by construction.
pub(crate) const MCP_MOUNT_PATH: &str = "/mcp";

/// The RFC 9728 protected-resource metadata document for [`MCP_MOUNT_PATH`]. Path-scoped form: the
/// resource's path is inserted after the well-known prefix, which is what the 2025-06-18+ MCP
/// authorization spec has clients construct.
pub(crate) const PROTECTED_RESOURCE_METADATA_PATH: &str =
    "/.well-known/oauth-protected-resource/mcp";

/// The root form of the same document. Served as an ALIAS because a client that never saw the
/// `WWW-Authenticate` challenge (a hand-configured one, or an older one) probes here, and answering
/// 404 there turns a working deployment into an interop bug report. It is the identical document —
/// there is only one protected resource — so the alias widens no surface.
pub(crate) const PROTECTED_RESOURCE_METADATA_ROOT_PATH: &str =
    "/.well-known/oauth-protected-resource";

/// Clock-skew allowance, seconds, applied to `exp` and `nbf`. Real IdPs and real gateways disagree
/// about the time by a second or two and a zero-tolerance check turns that into intermittent 401s.
/// 60 seconds is the conventional allowance; it is small enough that an expired token is expired
/// long before a human notices, and it is a CONSTANT rather than a config key so an operator cannot
/// quietly widen it to an hour.
const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// One authorization server busbar will accept tokens from: its issuer identifier and its signing
/// keys. Both are operator-declared; nothing here is discovered at runtime.
#[derive(Debug)]
pub(crate) struct TrustedAuthorizationServer {
    /// The `iss` value tokens from this server must carry, compared byte-for-byte. This is also what
    /// the metadata document advertises, so a client is told exactly the issuer busbar will accept.
    issuer: String,
    /// This server's signing keys.
    keys: jwks::JwkSet,
}

/// The resource server: everything busbar needs to answer "may this token act on the MCP plane, and
/// as whom". Built once at boot from config, immutable thereafter, cheap to share.
#[derive(Debug)]
pub(crate) struct ResourceServer {
    /// busbar's own canonical resource identifier — the RFC 8707 `resource` value AND the audience
    /// every accepted token must carry. Operator-configured per deployment, never derived from a
    /// request header (a request-derived audience is an attacker-derived audience).
    canonical_uri: String,
    /// The absolute URL of the metadata document, named verbatim in the `WWW-Authenticate`
    /// challenge. Derived from `canonical_uri`'s origin, so the challenge and the document agree.
    /// Retained after the challenge is built so a test can assert that agreement against the route
    /// constant instead of against a second copy of the string.
    #[cfg_attr(not(test), allow(dead_code))]
    metadata_url: String,
    /// The precomputed challenge header value. Built once because it is constant for the lifetime of
    /// the config generation and it is emitted on an unauthenticated path, which is exactly the path
    /// an attacker can drive hardest.
    challenge: String,
    /// The precomputed metadata document body. Same reasoning, plus: one body means the two mounted
    /// paths cannot serve two different documents.
    metadata: String,
    /// The authorization servers whose tokens are acceptable, in operator order.
    servers: Vec<TrustedAuthorizationServer>,
}

/// Why a token was refused. Kept as a typed enum because these distinctions matter in a log and in a
/// test — and kept OFF the wire for the same reason `auth::unauthorized_response` keeps its message
/// independent of the cause: telling a caller which check failed turns the 401 into an oracle that
/// walks an attacker to a working token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No `Authorization: Bearer` credential at all. The ordinary first request of the flow, and the
    /// one the challenge exists to answer.
    NoCredential,
    /// Not a compact JWS, or its segments do not decode. Carries the parser's message for the log.
    Malformed(String),
    /// The header names an algorithm outside the accepted set — including `none`.
    UnsupportedAlgorithm(String),
    /// The `iss` claim names no configured authorization server.
    UntrustedIssuer,
    /// The issuer is configured but publishes no key matching the token's `kid`.
    UnknownKey,
    /// A key was found and did not sign these bytes.
    BadSignature,
    /// `exp` is in the past (or absent), beyond the skew allowance.
    Expired,
    /// `nbf` is in the future beyond the skew allowance.
    NotYetValid,
    /// The token carries no `aud` at all. **Refused**: an audience-less bearer token is usable at
    /// every resource that will take it, which is the confused-deputy condition itself.
    AudienceMissing,
    /// The token's audience names some other resource. **The check this module exists for.**
    AudienceMismatch,
    /// No `sub`: there is no principal to attribute the call to.
    SubjectMissing,
    /// No `client_id`/`azp`/`appid`: there is no agent to attribute the call to. RFC 9068 §2.2 makes
    /// `client_id` REQUIRED in a JWT access token, and per-agent attribution is a thing busbar
    /// promises its operators, so an unattributable token is refused rather than admitted as
    /// "unknown".
    ClientMissing,
}

impl Refusal {
    /// A short, stable tag for structured logs and metrics. Never rendered to the caller.
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            Refusal::NoCredential => "no_credential",
            Refusal::Malformed(_) => "malformed",
            Refusal::UnsupportedAlgorithm(_) => "unsupported_alg",
            Refusal::UntrustedIssuer => "untrusted_issuer",
            Refusal::UnknownKey => "unknown_key",
            Refusal::BadSignature => "bad_signature",
            Refusal::Expired => "expired",
            Refusal::NotYetValid => "not_yet_valid",
            Refusal::AudienceMissing => "audience_missing",
            Refusal::AudienceMismatch => "audience_mismatch",
            Refusal::SubjectMissing => "subject_missing",
            Refusal::ClientMissing => "client_missing",
        }
    }
}

/// A caller admitted onto the MCP plane: WHO (the human or service the IdP authenticated) and WHICH
/// AGENT (the OAuth client acting for them). Both, because "user X" and "user X through agent Y" are
/// different facts and the second is the one an operator wants in an audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpCaller {
    /// The token's `sub` — the stable subject handle the IdP asserts. Becomes the principal id, so
    /// it keys `auth.role_bindings:` exactly as any other identified principal does.
    pub(crate) subject: String,
    /// The OAuth client id of the agent presenting the token, from `client_id`, then `azp`, then
    /// `appid`. See [`Refusal::ClientMissing`] for why one is required.
    pub(crate) client_id: String,
    /// The issuer that vouched for this token, retained so an audit row can say WHICH IdP and so a
    /// two-IdP deployment does not collapse two subject namespaces into one.
    pub(crate) issuer: String,
    /// A display name if the token carries one (`name`, else `preferred_username`).
    pub(crate) name: Option<String>,
    /// Roles the token asserts (`roles`, else the space-delimited `scope`). Mapped to POLICY through
    /// `auth.role_bindings:` like every other module's roles — never trusted as policy itself.
    pub(crate) roles: Vec<String>,
    /// The token's `exp`, retained so a session cannot outlive the credential that opened it.
    pub(crate) expires_at: u64,
}

impl McpCaller {
    /// The identity handed to the existing governance path. IDENTITY ONLY — allowed pools, group and
    /// scopes are resolved by busbar from config, never asserted by the token, exactly as for a
    /// plugin-identified principal.
    pub(crate) fn principal(&self) -> busbar_api::Principal {
        busbar_api::Principal {
            id: self.subject.clone(),
            name: self.name.clone(),
            roles: self.roles.clone(),
            ttl_secs: None,
        }
    }
}

/// The claims busbar reads. Deliberately NOT `deny_unknown_fields`: a real access token from a real
/// IdP carries a dozen claims busbar has no opinion about, and refusing them would refuse every
/// production token.
#[derive(Debug, serde::Deserialize)]
struct AccessTokenClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<Audience>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    #[serde(default)]
    scope: Option<String>,
}

/// `aud` is a string OR an array of strings (RFC 7519 §4.1.3). Both spellings are in production use;
/// Okta emits the scalar, Entra emits either.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    /// Whether this audience names `expected`. Byte equality, no canonicalisation: an audience is an
    /// opaque identifier, and "helpfully" equating `https://x/mcp` with `https://x/mcp/` or
    /// case-folding a host is how an audience check acquires a bypass. The operator configures one
    /// string and the IdP is configured with the same string.
    fn names(&self, expected: &str) -> bool {
        match self {
            Audience::One(a) => a == expected,
            Audience::Many(list) => list.iter().any(|a| a == expected),
        }
    }
}

impl ResourceServer {
    /// Build from operator config. Every failure here is a BOOT failure with a named cause: a
    /// resource server that came up with an unusable key set would answer 401 to every legitimate
    /// caller, which looks exactly like an attack and is exactly not one.
    ///
    /// `servers` is `(issuer, jwks-document)` pairs in operator order.
    pub(crate) fn build(
        canonical_uri: &str,
        servers: Vec<(String, String)>,
    ) -> Result<Self, String> {
        let origin = validate_canonical_uri(canonical_uri)?;
        if servers.is_empty() {
            return Err(
                "mcp.authorization_servers must name at least one authorization server: an MCP \
                 endpoint with no issuer to point callers at can never be authenticated"
                    .to_string(),
            );
        }
        let mut trusted = Vec::with_capacity(servers.len());
        for (issuer, document) in servers {
            validate_issuer(&issuer)?;
            if trusted
                .iter()
                .any(|s: &TrustedAuthorizationServer| s.issuer == issuer)
            {
                return Err(format!(
                    "mcp.authorization_servers lists issuer {issuer} twice; an issuer selects the \
                     key set for a token, so a duplicate makes that selection ambiguous"
                ));
            }
            let keys = jwks::JwkSet::parse(&document)
                .map_err(|e| format!("mcp.authorization_servers[{issuer}].jwks: {e}"))?;
            trusted.push(TrustedAuthorizationServer { issuer, keys });
        }
        let metadata_url = format!("{origin}{PROTECTED_RESOURCE_METADATA_PATH}");
        // The document is deliberately SMALL: the resource identifier the client already knows, the
        // issuers it must go to, and how to present the token. No tool names, no pool names, no
        // scope inventory, no operator contact — this is served to an entirely unauthenticated
        // caller, so anything in it is public, and the useful contents of an MCP deployment are not.
        let metadata = serde_json::json!({
            "resource": canonical_uri,
            "authorization_servers": trusted.iter().map(|s| &s.issuer).collect::<Vec<_>>(),
            "bearer_methods_supported": ["header"],
        })
        .to_string();
        Ok(Self {
            canonical_uri: canonical_uri.to_string(),
            challenge: format!("Bearer resource_metadata=\"{metadata_url}\""),
            metadata_url,
            metadata,
            servers: trusted,
        })
    }

    /// The `WWW-Authenticate` value for an unauthenticated MCP request. This is the entire
    /// discovery mechanism: it names the metadata document and nothing about why the request failed.
    pub(crate) fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The RFC 9728 document body.
    pub(crate) fn metadata(&self) -> &str {
        &self.metadata
    }

    /// The absolute URL the challenge names. Exposed so a test can assert the challenge and the
    /// mounted route agree rather than assuming it; production reads the precomputed challenge, not
    /// this, which is why it is test-only.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// busbar's canonical resource identifier — the required audience. Read by the test that
    /// asserts the ADVERTISED resource and the ENFORCED audience are the same string; production
    /// compares against the field directly inside `admit`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn canonical_uri(&self) -> &str {
        &self.canonical_uri
    }

    /// Whether `path` is on the MCP plane. The mount and everything beneath it: MCP's streamable
    /// HTTP transport is one endpoint, but a subtree is what keeps a future `/mcp/<anything>` inside
    /// the same admission bar instead of outside it by default. A PREFIX is correct here precisely
    /// because the whole subtree belongs to one plane — the opposite of the `/auth/token` case,
    /// where a prefix would have handed a bypass to unrelated siblings.
    pub(crate) fn owns_path(&self, path: &str) -> bool {
        path == MCP_MOUNT_PATH || path.starts_with(&format!("{MCP_MOUNT_PATH}/"))
    }

    /// Validate a presented bearer token and resolve it to a caller.
    ///
    /// Order is deliberate and each step is fail-closed:
    /// 1. parse — a token that is not a compact JWS is refused before any claim is read;
    /// 2. algorithm — the accepted set, so `none` and `HS*` die by name;
    /// 3. issuer — selects the key set (a claim read before verification, which is unavoidable: a
    ///    verifier must choose a key, and choosing wrong simply means nothing verifies);
    /// 4. signature — nothing below this line is trusted above it;
    /// 5. expiry;
    /// 6. **audience** — the confused-deputy defence;
    /// 7. principal — subject and client, both required.
    pub(crate) fn admit(&self, token: &str, now: u64) -> Result<McpCaller, Refusal> {
        if token.is_empty() {
            return Err(Refusal::NoCredential);
        }
        let parts = jwt::split(token).map_err(Refusal::Malformed)?;
        if !jwt::supported_alg(&parts.header.alg) {
            return Err(Refusal::UnsupportedAlgorithm(parts.header.alg.clone()));
        }
        let claims: AccessTokenClaims = serde_json::from_slice(&parts.payload)
            .map_err(|e| Refusal::Malformed(format!("malformed JWT claims: {e}")))?;
        let issuer = claims.iss.as_deref().unwrap_or_default();
        let server = self
            .servers
            .iter()
            .find(|s| s.issuer == issuer)
            .ok_or(Refusal::UntrustedIssuer)?;

        let kid = parts.header.kid.clone().unwrap_or_default();
        let mut saw_key = false;
        let mut verified = false;
        for key in server.keys.find_all(&kid) {
            saw_key = true;
            if jwt::verify_signature(&parts, key).is_ok() {
                verified = true;
                break;
            }
        }
        if !saw_key {
            return Err(Refusal::UnknownKey);
        }
        if !verified {
            return Err(Refusal::BadSignature);
        }

        let exp = claims.exp.ok_or(Refusal::Expired)?;
        if now > exp.saturating_add(CLOCK_SKEW_LEEWAY_SECS) {
            return Err(Refusal::Expired);
        }
        if let Some(nbf) = claims.nbf {
            if now.saturating_add(CLOCK_SKEW_LEEWAY_SECS) < nbf {
                return Err(Refusal::NotYetValid);
            }
        }

        // THE CHECK THIS MODULE EXISTS FOR (RFC 8707 resource indicators, and the MCP
        // authorization specification's confused-deputy requirement). It sits here, in the resource
        // server, above the signature branch and below nothing: a token that is authentic,
        // unexpired and issued by a trusted IdP is STILL not a token for busbar unless it says so.
        // Refusing it is the difference between a gateway and a confused deputy, and the difference
        // is invisible to every other gate in the system.
        match claims.aud {
            None => return Err(Refusal::AudienceMissing),
            Some(ref aud) if !aud.names(&self.canonical_uri) => {
                return Err(Refusal::AudienceMismatch)
            }
            Some(_) => {}
        }

        let subject = claims.sub.filter(|s| !s.is_empty());
        let subject = subject.ok_or(Refusal::SubjectMissing)?;
        let client_id = claims
            .client_id
            .or(claims.azp)
            .or(claims.appid)
            .filter(|c| !c.is_empty())
            .ok_or(Refusal::ClientMissing)?;
        let roles = claims.roles.unwrap_or_else(|| {
            claims
                .scope
                .map(|s| {
                    s.split(' ')
                        .filter(|t| !t.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        });
        Ok(McpCaller {
            subject,
            client_id,
            issuer: server.issuer.clone(),
            name: claims.name.or(claims.preferred_username),
            roles,
            expires_at: exp,
        })
    }
}

/// Validate `mcp.canonical_uri` and return its ORIGIN (scheme + authority), which is what the
/// metadata URL is built from.
///
/// The rules mirror the ones `public_url:` already enforces, plus one specific to this key: the path
/// must be exactly [`MCP_MOUNT_PATH`]. That is what makes the metadata document's path a compile-time
/// constant, which is what lets it be mounted by exact match instead of a prefix exception — and it
/// means the URL a client derives from the resource identifier is the URL busbar actually serves,
/// rather than two derivations that agree until someone changes one.
fn validate_canonical_uri(uri: &str) -> Result<String, String> {
    let rest = if let Some(r) = uri.strip_prefix("https://") {
        r
    } else if let Some(r) = uri.strip_prefix("http://") {
        // Plain http is accepted for loopback only, so a developer can run the whole flow locally
        // without a certificate, and nobody can quietly ship a production MCP endpoint that carries
        // bearer tokens in clear text.
        if !(r.starts_with("127.0.0.1") || r.starts_with("localhost") || r.starts_with("[::1]")) {
            return Err(format!(
                "mcp.canonical_uri {uri} is plain http and not loopback: an MCP endpoint carries \
                 bearer tokens, so http is accepted only for 127.0.0.1/localhost/[::1]"
            ));
        }
        r
    } else {
        return Err(format!(
            "mcp.canonical_uri {uri} must be an absolute http(s) URL"
        ));
    };
    if uri.contains('?') || uri.contains('#') {
        return Err(format!(
            "mcp.canonical_uri {uri} must carry no query and no fragment: it is an identifier \
             compared byte-for-byte against a token's audience, not a link"
        ));
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("mcp.canonical_uri {uri} has no host"));
    }
    if path != MCP_MOUNT_PATH {
        return Err(format!(
            "mcp.canonical_uri {uri} must end in {MCP_MOUNT_PATH} (busbar's MCP mount): the \
             protected-resource metadata path is derived from it, so a different path would \
             advertise a document busbar does not serve"
        ));
    }
    let scheme = if uri.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    Ok(format!("{scheme}://{authority}"))
}

/// Validate one advertised issuer identifier. RFC 8414 §2 requires an https URL with no query and no
/// fragment; busbar additionally refuses an empty one rather than advertising a blank string in a
/// public document.
fn validate_issuer(issuer: &str) -> Result<(), String> {
    if issuer.is_empty() {
        return Err("mcp.authorization_servers[].issuer must not be empty".to_string());
    }
    let loopback_http = issuer.starts_with("http://127.0.0.1")
        || issuer.starts_with("http://localhost")
        || issuer.starts_with("http://[::1]");
    if !issuer.starts_with("https://") && !loopback_http {
        return Err(format!(
            "mcp.authorization_servers issuer {issuer} must be an https URL (RFC 8414 §2); plain \
             http is accepted only for loopback development"
        ));
    }
    if issuer.contains('?') || issuer.contains('#') {
        return Err(format!(
            "mcp.authorization_servers issuer {issuer} must carry no query and no fragment \
             (RFC 8414 §2)"
        ));
    }
    Ok(())
}

/// Request-extension carrier for an admitted MCP caller. Inserted by the auth middleware on the MCP
/// plane and read downstream for attribution. Present ONLY on an admitted MCP request, so its mere
/// presence is the proof that admission ran.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedMcpCaller(pub(crate) Arc<McpCaller>);
