// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S FRONT DOOR: busbar as an OAuth 2.1 RESOURCE SERVER, and the HTTP-level MUSTs of
//! MCP revision `2026-07-28`.
//!
//! ## What busbar is here
//!
//! busbar is the MCP SERVER. An AI agent connects to it exactly as it connects to a model provider:
//! with no credential first, which earns a `401` carrying a `WWW-Authenticate` challenge that names
//! this resource's RFC 9728 metadata document; it follows that to the operator's authorization
//! server, does ordinary OAuth over plain HTTPS, and comes back with a token. busbar then checks
//! that the token's audience is ITSELF — and from there it is machinery that already exists:
//! identity, budget, policy, rate limits, audit.
//!
//! busbar is NOT the authorization server. The tokens are minted by the operator's existing IdP
//! (Okta, Entra, Auth0), and nothing in this module issues one. That split is deliberate: an
//! authorization server is a plugin surface, and it is deferred.
//!
//! ## Why the audience check is the load-bearing one
//!
//! It is the CONFUSED-DEPUTY defence, and it is the difference between a gateway and an open relay.
//! Without it, a token an agent legitimately obtained for some OTHER resource — a token that IdP
//! happily issued, for a service that has nothing to do with busbar — is spendable here, against
//! busbar's pools, budget and upstream credentials. RFC 8707 exists precisely so a resource server
//! can say "this was not minted for me". busbar therefore compares the token's `aud` for EQUALITY
//! against one operator-configured canonical URI, and refuses anything else, including a token that
//! carries no audience at all.
//!
//! The check lives in the VERIFIER, reached through the plane's mount
//! (`crate::plane::PlaneAdmission`), not in a handler — so a route added to this plane tomorrow
//! inherits it and cannot forget it.
//!
//! ## The revision this targets, and what that means
//!
//! MCP `2026-07-28`, the streamable-HTTP stateless RC (SEP-2243/SEP-2575). It is a breaking
//! redesign, not an increment, and the parts of it that are pure HTTP are enforced here:
//!
//! - There is no `initialize` handshake and there are no protocol sessions. Every request is
//!   self-describing, carrying its protocol version and the client's capabilities in `_meta`. So
//!   there is no `Mcp-Session-Id` to mint, honour, or invalidate. A stateful protocol would need
//!   to TOMBSTONE the sessions pinned to a server the operator has de-approved; with no handshake
//!   and no sessions there is nothing to tombstone, so that defence collapses into a per-request
//!   generation check, which is simpler and cannot go stale.
//! - The GET stream endpoint is gone, and with it resumability. GET and DELETE answer `405`.
//! - `Mcp-Method` mirrors the body's `method` on every request, and `Mcp-Name` mirrors the target
//!   name on `tools/call`, `resources/read` and `prompts/get`. Both are REQUIRED for compliance, and
//!   a header that disagrees with the body is `400` with JSON-RPC code `-32020` — because a proxy
//!   routing on the header while the server executes the body is a request-smuggling primitive.
//! - `MCP-Protocol-Version` must equal the body `_meta` protocol version, same `-32020` on mismatch.
//! - An unknown method is `404` with JSON-RPC `-32601`, NOT a `200` carrying an error object.
//! - `Origin` validation is a MUST, `403` on an invalid one — the DNS-rebinding defence for a
//!   gateway that may be reachable from a browser context.
//!
//! ## The rooms behind the door
//!
//! The JSON-RPC method surface — the CATALOGUE (`tools/list`, `prompts/list`, `resources/list`,
//! `server/discover`) and DISPATCH (`tools/call`, `prompts/get`, `resources/read`) — lives in
//! [`method`], computed over the versioned snapshot in [`catalogue`], scoped by the caller's key
//! grants, sanitised by [`sanitize`] and bounded by [`inputreq`]. A method absent from that table
//! still takes the `404` / `-32601` arm, which was never a placeholder: it is the correct answer for
//! an unimplemented method and it stayed correct unchanged when the table gained entries.
//!
//! The registry those answers are computed from is the `tools:` config block ([`config`]), which is
//! the MCP plane in the same sense `pools:` is the LLM plane.
//!
//! ## What is deliberately NOT here
//!
//! The CLIENT direction — busbar calling OUT. Nothing in this module opens a connection to an
//! upstream MCP server, so a `tools/call` runs every governance check and then fails at the round
//! trip with a busbar-attributed error. That is stated in [`method::dispatch_upstream`] rather than
//! papered over with a stub result, because a fake result makes every check above it pass for the
//! wrong reason.

pub(crate) mod admin_view;
pub(crate) mod catalogue;
/// The CLIENT direction: busbar calling OUT to external MCP tool servers. The other half of
/// the same governance boundary this module's front door opens — same revision, same trust
/// lifecycle, same scope kinds, opposite initiator.
pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod ingress;
pub(crate) mod inputreq;
pub(crate) mod method;
pub(crate) mod resource;
pub(crate) mod sanitize;
pub(crate) mod upstream;

use serde::{Deserialize, Serialize};

/// The top-level `mcp:` config block. Its mere PRESENCE mounts the MCP plane; its absence means the
/// deployment carries no MCP surface at all — no ingress, no metadata document, nothing added to the
/// route table. A gateway that is not an MCP server should not answer as one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpCfg {
    /// The RFC 8707 resource indicator for this deployment: the canonical, absolute URI that names
    /// busbar's MCP endpoint, and therefore the exact `aud` value every inbound token must carry.
    ///
    /// It is OPERATOR-CONFIGURED rather than derived from the request's `Host`, and that is the
    /// whole point: deriving it from the request would let a caller choose its own audience by
    /// sending a `Host` header, which turns the confused-deputy defence into a formality. It is also
    /// what closes the multi-tenant gap — one deployment, one canonical audience, stated once.
    ///
    /// The MOUNT PATH is derived from this rather than configured separately, so the path a client
    /// posts to and the identifier its token is bound to cannot drift apart.
    pub(crate) canonical_uri: String,
    /// RFC 9728 `authorization_servers`: the issuer identifiers of the authorization servers that
    /// may mint tokens for this resource — in practice, the operator's IdP. At least one is
    /// REQUIRED, because this list is the entire content of the answer a credential-less client came
    /// for; an empty one advertises a resource nobody can obtain a token for.
    #[serde(default)]
    pub(crate) authorization_servers: Vec<String>,
    /// RFC 9728 `scopes_supported`: the scope values this resource understands. Advisory metadata —
    /// authorization is decided by the caller's grant, never by what this list says.
    #[serde(default)]
    pub(crate) scopes_supported: Vec<String>,
    /// Browser origins accepted on the MCP ingress, for the `2026-07-28` `Origin` MUST.
    ///
    /// EMPTY IS THE DEFAULT AND IT MEANS "no browser origin is accepted", which is the safe posture
    /// for a server whose clients are agents rather than pages: a request carrying NO `Origin` (every
    /// non-browser client) is unaffected, and a request carrying one is refused unless the operator
    /// listed it. The threat is DNS rebinding — a page on an attacker's origin resolving a name to
    /// busbar's loopback address and driving the tool plane with the user's ambient credentials.
    #[serde(default)]
    pub(crate) allowed_origins: Vec<String>,
}

/// The VALIDATED MCP resource: `McpCfg` after every derivation and refusal has already happened, so
/// nothing downstream re-parses a URI or re-decides a path.
///
/// Built once at boot. A config that cannot produce one does not boot — an MCP plane that is
/// half-configured is worse than one that is absent, because it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McpResource {
    /// The canonical URI verbatim, as configured. THE audience.
    canonical_uri: String,
    /// The path component of `canonical_uri`, normalised to a leading and no trailing slash. The
    /// ingress mount.
    mount_path: String,
    /// The RFC 9728 §3.1 metadata path: `/.well-known/oauth-protected-resource` with the resource's
    /// path INSERTED AFTER it, not before. This is the one detail of RFC 9728 that is easy to get
    /// backwards, and getting it backwards means every compliant client's discovery 404s.
    metadata_path: String,
    /// The absolute form of `metadata_path`, which is what goes in the challenge — a client that has
    /// no credential also has no reason to trust its own reconstruction of our origin.
    metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    allowed_origins: Vec<String>,
}

/// Why an `mcp:` block was refused at boot. Every arm names the field and what a correct value looks
/// like: a boot refusal that does not say what to type is a boot refusal the operator works around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum McpCfgError {
    /// `canonical_uri` was empty or absent.
    MissingCanonicalUri,
    /// `canonical_uri` was not an absolute `http`/`https` URI.
    CanonicalUriNotAbsolute(String),
    /// `canonical_uri` carried a query or a fragment. RFC 8707 §2 forbids a fragment outright, and a
    /// query would make the identifier depend on parameter ordering — two spellings of one resource
    /// is one spelling too many when the value is compared for equality.
    CanonicalUriHasQueryOrFragment(String),
    /// `canonical_uri` had no path, or only `/`. The resource must be distinguishable from the
    /// deployment's root: mounting the MCP plane at `/` would put it in front of the LLM residual
    /// and claim every path in the process.
    CanonicalUriHasNoPath(String),
    /// `authorization_servers` was empty.
    NoAuthorizationServers,
    /// An `authorization_servers` entry was not an absolute `http`/`https` URI.
    AuthorizationServerNotAbsolute(String),
}

impl std::fmt::Display for McpCfgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpCfgError::MissingCanonicalUri => write!(
                f,
                "mcp.canonical_uri is required: it is the audience every inbound token must carry \
                 (RFC 8707) and the path the endpoint mounts at. Example: \
                 `canonical_uri: https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriNotAbsolute(v) => write!(
                f,
                "mcp.canonical_uri `{v}` is not an absolute http(s) URI. It is compared for exact \
                 equality against a token's `aud`, so it must be the same absolute string the \
                 authorization server was asked to mint for. Example: \
                 `https://gateway.example.com/mcp`"
            ),
            McpCfgError::CanonicalUriHasQueryOrFragment(v) => write!(
                f,
                "mcp.canonical_uri `{v}` carries a query or fragment. RFC 8707 resource indicators \
                 carry neither: drop everything from the first `?` or `#`."
            ),
            McpCfgError::CanonicalUriHasNoPath(v) => write!(
                f,
                "mcp.canonical_uri `{v}` has no path. The MCP endpoint needs its own path so it \
                 does not claim the whole deployment. Example: `https://gateway.example.com/mcp`"
            ),
            McpCfgError::NoAuthorizationServers => write!(
                f,
                "mcp.authorization_servers must list at least one issuer. It is the entire content \
                 of the answer a client with no credential comes here for; with none, the `401` it \
                 gets names nowhere to go. Example: \
                 `authorization_servers: [https://login.example.com]`"
            ),
            McpCfgError::AuthorizationServerNotAbsolute(v) => write!(
                f,
                "mcp.authorization_servers entry `{v}` is not an absolute http(s) URI. An issuer \
                 identifier is an absolute URL. Example: `https://login.example.com`"
            ),
        }
    }
}

/// The RFC 9728 §3.1 well-known prefix. The resource's own path is appended AFTER this, per the
/// "path insertion" rule the RFC defines for a resource that is not at an origin root.
const PROTECTED_RESOURCE_WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

impl McpResource {
    /// Validate and derive. Every refusal is fail-closed at BOOT rather than at first request: an
    /// operator finds out from a process that will not start, not from an agent that cannot connect.
    pub(crate) fn from_cfg(cfg: &McpCfg) -> Result<Self, McpCfgError> {
        let uri = cfg.canonical_uri.trim();
        if uri.is_empty() {
            return Err(McpCfgError::MissingCanonicalUri);
        }
        let (origin, path) = split_absolute(uri)
            .ok_or_else(|| McpCfgError::CanonicalUriNotAbsolute(uri.to_string()))?;
        if path.contains('?') || path.contains('#') || origin.contains('#') {
            return Err(McpCfgError::CanonicalUriHasQueryOrFragment(uri.to_string()));
        }
        let mount_path = normalise_path(path);
        if mount_path.is_empty() {
            return Err(McpCfgError::CanonicalUriHasNoPath(uri.to_string()));
        }
        if cfg.authorization_servers.is_empty() {
            return Err(McpCfgError::NoAuthorizationServers);
        }
        for issuer in &cfg.authorization_servers {
            if split_absolute(issuer.trim()).is_none() {
                return Err(McpCfgError::AuthorizationServerNotAbsolute(issuer.clone()));
            }
        }
        let metadata_path = format!("{PROTECTED_RESOURCE_WELL_KNOWN}{mount_path}");
        Ok(Self {
            metadata_url: format!("{origin}{metadata_path}"),
            canonical_uri: uri.to_string(),
            mount_path,
            metadata_path,
            authorization_servers: cfg
                .authorization_servers
                .iter()
                .map(|s| s.trim().to_string())
                .collect(),
            scopes_supported: cfg.scopes_supported.clone(),
            allowed_origins: cfg.allowed_origins.clone(),
        })
    }

    /// THE audience. Compared for equality by the verifier; never parsed again.
    pub(crate) fn canonical_uri(&self) -> &str {
        &self.canonical_uri
    }

    /// The ingress mount path (`/mcp` for `https://host/mcp`).
    pub(crate) fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// The RFC 9728 metadata path this deployment serves the document at.
    pub(crate) fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// The absolute metadata URL, for the `resource_metadata` challenge parameter.
    pub(crate) fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    pub(crate) fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    pub(crate) fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// Whether an inbound `Origin` header is acceptable.
    ///
    /// A request with NO `Origin` is not this function's business — non-browser clients send none,
    /// and refusing them would refuse every agent. This answers only "is THIS origin allowed", and
    /// the empty allowlist answers `false` for every origin, which is the documented default.
    /// Comparison is exact: an `Origin` is a serialized origin (scheme, host, port), and matching it
    /// as a prefix is how `https://good.example` starts admitting `https://good.example.evil.test`.
    pub(crate) fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|a| a == origin)
    }

    /// The plane admission facts this resource contributes to the dispatch table: the audience a
    /// token must carry here, and where a refused caller is told to go.
    pub(crate) fn admission(&self) -> crate::plane::PlaneAdmission {
        crate::plane::PlaneAdmission {
            audience: self.canonical_uri().to_string(),
            resource_metadata: self.metadata_url().to_string(),
        }
    }
}

/// Split an absolute `http(s)` URI into `(origin, path)`, or `None` when it is not one.
///
/// Hand-written rather than pulled from a URL crate on purpose: what is needed is a STRICT
/// recogniser for one shape, and a permissive general-purpose parser is the wrong tool for a value
/// whose whole job is to be compared for exact equality. A lenient parse that accepts and normalises
/// `HTTPS://Host:443/mcp` would hand back a string that no longer equals the `aud` the IdP minted.
/// So: recognise, do not normalise.
fn split_absolute(uri: &str) -> Option<(&str, &str)> {
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))?;
    // The authority must be non-empty, must not itself contain a scheme separator, and must not be
    // the whole string's remainder only because the string ended at the scheme.
    let authority_len = rest.find('/').unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let scheme_len = uri.len() - rest.len();
    let split = scheme_len + authority_len;
    Some((&uri[..split], &uri[split..]))
}

/// `/mcp/` -> `/mcp`, `` -> ``, `/` -> ``. The same normalisation
/// [`crate::plane::PlaneDispatch::mount`] applies, so the derived mount and the dispatch mount are
/// the same string by construction rather than by two functions agreeing.
fn normalise_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
