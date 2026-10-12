// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `mcp:` ENDPOINT BLOCK: its grammar ([`McpCfg`]), its boot refusals ([`McpCfgError`]) and the
//! validated resource ([`McpResource`]) derived from it. Pure data and string rules, MOVED here from
//! the retired host crate with the `tools:` grammar beside it ([`crate::config`]), so the endpoint's
//! judging survives that crate's deletion unchanged: the same fields, the same refusals, the same
//! words. The composition root registers the block on the plane axis and lowers it through
//! [`McpResource::from_cfg`] at boot.

use serde::{Deserialize, Serialize};

/// The top-level `mcp:` config block. Its mere PRESENCE mounts the MCP plane; its absence means the
/// deployment carries no MCP surface at all — no ingress, no metadata document, nothing added to the
/// route table. A gateway that is not an MCP server should not answer as one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpCfg {
    /// The RFC 8707 resource indicator for this deployment: the canonical, absolute URI that names
    /// busbar's MCP endpoint, and therefore the exact `aud` value every inbound token must carry.
    ///
    /// It is OPERATOR-CONFIGURED rather than derived from the request's `Host`, and that is the
    /// whole point: deriving it from the request would let a caller choose its own audience by
    /// sending a `Host` header, which turns the confused-deputy defence into a formality. It is also
    /// what closes the multi-tenant gap — one deployment, one canonical audience, stated once.
    ///
    /// Its PATH must be the one path the claim table names: the mount is fixed, not configured, and
    /// a URI naming any other path is refused at boot (CG-17). The scheme, host and port are the
    /// operator's; the path is not.
    pub canonical_uri: String,
    /// RFC 9728 `authorization_servers`: the issuer identifiers of the authorization servers that
    /// may mint tokens for this resource — in practice, the operator's IdP. At least one is
    /// REQUIRED, because this list is the entire content of the answer a credential-less client came
    /// for; an empty one advertises a resource nobody can obtain a token for.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// RFC 9728 `scopes_supported`: the scope values this resource understands. Advisory metadata —
    /// authorization is decided by the caller's grant, never by what this list says.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Browser origins accepted on the MCP ingress, for the `2026-07-28` `Origin` MUST.
    ///
    /// EMPTY IS THE DEFAULT AND IT MEANS "no browser origin is accepted", which is the safe posture
    /// for a server whose clients are agents rather than pages: a request carrying NO `Origin` (every
    /// non-browser client) is unaffected, and a request carrying one is refused unless the operator
    /// listed it. The threat is DNS rebinding — a page on an attacker's origin resolving a name to
    /// busbar's loopback address and driving the tool plane with the user's ambient credentials.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// The VALIDATED MCP resource: `McpCfg` after every derivation and refusal has already happened, so
/// nothing downstream re-parses a URI or re-decides a path.
///
/// Built once at boot. A config that cannot produce one does not boot — an MCP plane that is
/// half-configured is worse than one that is absent, because it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpResource {
    /// The canonical URI verbatim, as configured. THE audience.
    canonical_uri: String,
    /// The path component of `canonical_uri`, normalised to a leading and no trailing slash. The
    /// ingress mount.
    mount_path: String,
    /// The RFC 9728 section 3.1 metadata path: `/.well-known/oauth-protected-resource` with the resource's
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
pub enum McpCfgError {
    /// `canonical_uri` was empty or absent.
    MissingCanonicalUri,
    /// `canonical_uri` was not an absolute `http`/`https` URI.
    CanonicalUriNotAbsolute(String),
    /// `canonical_uri` carried a query or a fragment. RFC 8707 section 2 forbids a fragment outright, and a
    /// query would make the identifier depend on parameter ordering — two spellings of one resource
    /// is one spelling too many when the value is compared for equality.
    CanonicalUriHasQueryOrFragment(String),
    /// `canonical_uri` had no path, or only `/`. The resource must be distinguishable from the
    /// deployment's root: mounting the MCP plane at `/` would put it in front of the LLM residual
    /// and claim every path in the process.
    CanonicalUriHasNoPath(String),
    /// `canonical_uri` named a path other than the one the claim table names. Inbound paths are
    /// compile-time claims in the Statement; a configured address naming another path would
    /// advertise, and bind every token's audience to, a path nothing is served at. The mount is
    /// fixed rather than configurable (CG-17). Carries the URI as configured and the path it named,
    /// normalised.
    CanonicalUriPathNotClaimed {
        /// The URI as configured.
        uri: String,
        /// The path it named, normalised to a leading and no trailing slash.
        path: String,
    },
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
            McpCfgError::CanonicalUriPathNotClaimed { uri, path } => write!(
                f,
                "mcp.canonical_uri `{uri}` names the path `{path}`, but the MCP endpoint is served \
                 only at `{DEFAULT_MOUNT}`; the path is fixed, not configurable. Keep the scheme, \
                 host and port and end the URI in `{DEFAULT_MOUNT}`. Example: \
                 `https://gateway.example.com{DEFAULT_MOUNT}`"
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

/// The RFC 9728 section 3.1 well-known prefix. The resource's own path is appended AFTER this, per the
/// "path insertion" rule the RFC defines for a resource that is not at an origin root.
///
/// The join itself is on the CODEC side, so the plane — which declares an OPEN claim on the composed
/// discovery path and may not name this crate — reads the same composer rather than a second one.
/// The well-known prefix went with it; there is one place the two are put together now.
///
/// `DEFAULT_MOUNT` is THE ONE PATH this endpoint is served at: the compile-time claim, read from the
/// claim table rather than written a second time here, so the path validation accepts and the path
/// claimed cannot disagree.
use crate::{codec::protected_resource_metadata_path, tool_claims::DEFAULT_MOUNT};

impl McpResource {
    /// Validate and derive. Every refusal is fail-closed at BOOT rather than at first request: an
    /// operator finds out from a process that will not start, not from an agent that cannot connect.
    pub fn from_cfg(cfg: &McpCfg) -> Result<Self, McpCfgError> {
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
        // The mount is not operator-configurable: one path is claimed and nothing else, so an
        // address naming any other path is a boot refusal here rather than a deployment that
        // advertises a path it does not serve (CG-17).
        if mount_path != DEFAULT_MOUNT {
            return Err(McpCfgError::CanonicalUriPathNotClaimed {
                uri: uri.to_string(),
                path: mount_path,
            });
        }
        if cfg.authorization_servers.is_empty() {
            return Err(McpCfgError::NoAuthorizationServers);
        }
        for issuer in &cfg.authorization_servers {
            if split_absolute(issuer.trim()).is_none() {
                return Err(McpCfgError::AuthorizationServerNotAbsolute(issuer.clone()));
            }
        }
        let metadata_path = protected_resource_metadata_path(&mount_path);
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
    pub fn canonical_uri(&self) -> &str {
        &self.canonical_uri
    }

    /// The ingress mount path (`/mcp` for `https://host/mcp`).
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }

    /// The RFC 9728 metadata path this deployment serves the document at.
    pub fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// The absolute metadata URL, for the `resource_metadata` challenge parameter.
    pub fn metadata_url(&self) -> &str {
        &self.metadata_url
    }

    /// The issuers allowed to mint tokens for this resource, trimmed.
    pub fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    /// The advisory scope values this resource lists.
    pub fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// THE OPERATOR'S BROWSER-ORIGIN ALLOWLIST, as data. The plane keeps the data; the verdict on
    /// an `Origin` is not made here. The empty allowlist admits no browser origin, which is the
    /// documented default.
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
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
/// core's plane dispatch applies to its mount path, so the derived mount and the dispatch mount are
/// the same string by construction rather than by two functions agreeing.
fn normalise_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("/{trimmed}")
}

// THE ENGINE BINDING for the plane's test binary: the one module that names the engine crate. Every
// App-needing test below reaches the engine through it (the neutral `testkit::engine_kit` seam).
// Gated on `test-support` alone (never bare `cfg(test)`, where no engine is in the closure): that is
// also the feature a dependent crate's test binary compiles the plane batteries in under
// (`admin_view::adminverbs_tests`), so those reach it too; in that feature-only build its helpers

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
