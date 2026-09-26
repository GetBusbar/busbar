// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE EGRESS-AUTH SEAM moved DOWN into `busbar-substrate` (the LLM plane named
//! `busbar_kernel::egress_auth` as its last backwards reach); this module re-exports it (glob) so
//! every historical `busbar_kernel::egress_auth::…` name — `resolve`, `prebuild_auth`,
//! `CredentialProvider`, `MetadataSsrfPolicy`, and the `jwt_bearer` /
//! `oauth_client_credentials` mint modules — resolves unchanged, and hosts the two egress-auth
//! tests that must stay core-side (below).
//!
//! Mirrors the sibling `gate` submodule, which relocated the same way in Phase-B B1: the real
//! content lives in `busbar_kernel::egress_auth`, and the local `pub mod gate;` below keeps
//! core's own gate shim (which hosts the gate tests that name `crate::audit_ring`). The glob's
//! `gate` is shadowed by that explicit declaration.

// Core's gate re-export shim (hosts the core-only `gate_tests`, which name `crate::audit_ring` /
// `crate::audit`). Explicitly declared so it shadows the glob's `gate`.
pub mod gate;

// THE PREBUILT-AUTH DIFFERENTIAL PROOF stays core-side: `resolve` reads the LLM dialect
// `ProtocolDecl`s, and only core's `proto::decl_for` wrapper seeds a built-in decl under
// `#[cfg(test)]` — a bare `cargo test -p busbar-substrate` registers none, so `resolve("bedrock")`
// would there wrongly report lane-constant. It names only the re-exported `crate::egress_auth`
// surface plus `crate::proto` / `crate::config`, all still valid here.
#[cfg(test)]
#[path = "tests/prebuilt_auth_tests.rs"]
mod prebuilt_auth_tests;

// The crate-wide license-header meta-test scans this crate's whole `src` (via `CARGO_MANIFEST_DIR`),
// so it stays with busbar-core; it is not egress-auth-specific.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use crate::proto::SigningContext;
use crate::teller::Kernel;
use axum::http::{HeaderName, HeaderValue};
use busbar_contract::protocol::{CredentialHeader::Raw, EgressScheme};
use busbar_kernel_identity::egress_auth::{present, presentation};
use std::sync::Arc;

pub(crate) mod bearer_token;
/// THE EGRESS GATE: whether an outbound credential may be leased AT ALL, for a given inbound
/// principal. The sibling of everything else in this module — the rest answers "which headers does
/// busbar present", this answers "may busbar spend its own authority here on this caller's behalf" —
/// and it is core because it was written once per plane and the copies had already diverged.
pub mod jwt_bearer;
pub mod oauth_client_credentials;

/// HTTP client used by the self-minting OAuth credentials (`jwt-bearer`, `oauth-client-credentials`)
/// to POST to a token endpoint — the ENGINE, on the cold open-web posture. Hardened like the
/// data-path upstream client:
///   * redirects are STRUCTURAL non-follows now (hyper follows nothing) — the credential (a signed
///     assertion, or `client_secret`) rides in the POST BODY, so no cross-host header-stripping
///     could protect it; a 307/308 from a compromised or typo'd token endpoint would re-POST the
///     plaintext secret to the redirect target (169.254.169.254 / localhost / RFC1918), and the
///     boot-time SSRF check only vets the configured URL string, never a runtime redirect target.
///   * bounded connect (the engine's 10s connect deadline, spanning TLS) + the overall
///     [`MINT_DEADLINE`] applied per request at both mint sites — a stalled token endpoint must not
///     hang the mint/refresh future forever (the refresh loop only retries on `Err`, so a hang
///     would silently freeze the lane's token and serve an empty bearer → upstream 401).
///
/// The `Result` signature stands (both callers thread it) even though the engine's webpki build
/// has no failing arm on this posture — the seam stays where a future posture could fail loudly.
pub(crate) fn minter_client() -> Result<crate::egress::engine::EngineClient, String> {
    Ok(crate::proxy::build_egress_client(
        &crate::egress::engine::EngineSpec::pooled_webpki(usize::MAX, 90, false, false),
    ))
}

/// The whole-mint deadline — send plus capped body read under ONE absolute instant, the
/// client-level 30s total the retired reqwest builder carried.
pub(crate) const MINT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

// The OAuth token response's `expires_in` reading (its default and its tolerant parse) is egress-auth
// semantics with no engine in it, so it lives with the egress-auth unit (#83a O1 placement).
pub(crate) use busbar_kernel_identity::egress_auth::{default_expires_in, deserialize_expires_in};

/// Read a token-endpoint HTTP response body under the engine's established capped-read primitive
/// (`proxy::read_capped`) rather than `resp.text()`, which buffers an UNBOUNDED body — a hijacked or
/// misbehaving token endpoint returning a multi-GB response would otherwise be read entirely into
/// memory. A real OAuth token response is well under 1 KiB, so the cap has zero effect on legitimate
/// traffic. Shared by `jwt_bearer::Signer::mint` and `oauth_client_credentials::ClientCreds::mint` so
/// the capped-read-and-decode logic lives in exactly one place instead of being duplicated byte-for-byte
/// across the two mechanisms.
///
/// Distinguishes WHY the read did not complete, mirroring how `proxy::engine`'s own `ReadEnd` call
/// sites (`walk.rs`, `engine/mod.rs`) already report `Truncated` vs `TransportError` separately rather
/// than folding them into one ambiguous message: an operator debugging a real connection drop needs a
/// different signal than one debugging an oversized-response misconfiguration.
pub(crate) async fn read_capped_token_response(
    resp: http::Response<hyper::body::Incoming>,
    deadline: tokio::time::Instant,
) -> Result<String, String> {
    use http_body_util::BodyExt;
    let cap = crate::proxy::max_upstream_buffered_bytes();
    let read = crate::proxy::read_capped(resp.into_body().into_data_stream(), cap);
    // The mint's ONE deadline keeps ticking through the body — the span reqwest's client-level
    // total covered.
    let Ok((raw, read_end)) = tokio::time::timeout_at(deadline, read).await else {
        return Err(
            "token endpoint response was not read before the mint deadline; refusing to parse a \
             partial token response"
                .to_string(),
        );
    };
    match read_end {
        crate::proxy::ReadEnd::Complete => Ok(String::from_utf8_lossy(&raw).into_owned()),
        crate::proxy::ReadEnd::Truncated => Err(format!(
            "token endpoint response exceeded the {cap}-byte cap; refusing to parse a truncated token response"
        )),
        crate::proxy::ReadEnd::TransportError => Err(
            "token endpoint connection failed mid-response; refusing to parse a partial token response"
                .to_string(),
        ),
    }
}

/// The operator's metadata-SSRF posture, threaded into a token-endpoint check so the boot/reload
/// validation matches `config_validate`'s validate-time check EXACTLY (validate == apply). Its three
/// fields are the SAME arguments `config_validate::ssrf_blocked_host` is called with: the union of the
/// provider's and global `allow_metadata_hosts` carve-outs, the nuclear `allow_all_metadata`, and the
/// operator's extra `blocked_metadata_hosts`. Without threading these, a token endpoint an operator
/// deliberately allow-listed passes `--validate` but dies at boot — the reverse of the safety guarantee.
pub struct MetadataSsrfPolicy<'a> {
    pub allow_overrides: &'a [String],
    pub allow_all: bool,
    pub blocked_hosts: &'a [String],
}

/// Produces the outbound auth headers for a single upstream request.
///
/// `key` is the per-request credential the caller resolved — the lane's configured key for
/// [`crate::auth::UpstreamCreds::Own`], or the forwarded caller token for `Passthrough`. A
/// self-minting credential (e.g. a future OAuth token provider) ignores `key`. `ctx` carries the
/// host / canonical-uri / body / timestamp a signer needs, plus the `Own | Passthrough` mode.
pub trait CredentialProvider: Send + Sync {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)>;

    /// Whether this credential can currently produce a usable auth header. Static credentials
    /// (api-key, bearer, sigv4, anthropic-native) are always ready. A self-minting credential (OAuth
    /// jwt-bearer / client-credentials) is NOT ready during the boot/reload window before its first
    /// mint completes — `headers_for` returns no header then, so an active health probe would send an
    /// unauthenticated request and a guaranteed 401 could HardDown-park a healthy lane. The prober
    /// consults this to skip a not-yet-minted lane until its token is live. Default: always ready.
    fn is_ready(&self) -> bool {
        true
    }

    /// Whether `headers_for` is LANE-CONSTANT: a pure function of the resolved credential string
    /// and the `Own`/`Passthrough` mode, reading nothing else from the [`SigningContext`]. `true`
    /// lets the boot path prebuild this lane's exact auth header set once and hand the request
    /// path a clone (see `Lane::prebuilt_auth`). Default `false` — fail closed: a credential that
    /// mints (OAuth) or signs the request bytes (SigV4) must never be frozen at boot, so only the
    /// static schemes below (and dialects declaring `egress_auth_lane_constant`) opt in.
    fn is_lane_constant(&self) -> bool {
        false
    }

    /// Whether this credential builds its header FROM the `key` it is handed. True for every static
    /// scheme (bearer, api-key header, anthropic-native, SigV4); false for a self-minting
    /// credential (OAuth jwt-bearer / client-credentials), which ignores `key` entirely and presents
    /// its own minted token.
    ///
    /// Callers use this to decide that an EMPTY key means "there is no credential to present, so
    /// send no auth header" — see `prebuild_auth` and the engine's `lane_auth_headers`. Asking the
    /// credential, rather than inspecting the lane, is what keeps a keyless provider
    /// (`api_key: none`) and a tokenless passthrough caller from suppressing a minted OAuth token,
    /// which never came from `key` in the first place. Default: true.
    fn uses_key(&self) -> bool {
        true
    }
}

/// Resolve a lane's egress credential at boot from its protocol name and auth style.
/// `auth: api-key` overrides the protocol's native scheme.
pub fn resolve(
    protocol_name: &str,
    auth: Option<crate::config::ProviderAuth>,
) -> Arc<dyn CredentialProvider> {
    if matches!(auth, Some(crate::config::ProviderAuth::ApiKey)) {
        return Arc::new(DeclaredScheme(
            EgressScheme::header("api-key"),
            Kernel::new(),
        ));
    }
    if matches!(
        auth,
        Some(crate::config::ProviderAuth::JwtBearer)
            | Some(crate::config::ProviderAuth::OAuthClientCredentials)
    ) {
        // The OAuth styles mint their token asynchronously at boot (see `jwt_bearer::build` /
        // `oauth_client_credentials::build`), so the boot path special-cases them and never routes
        // them through this sync resolver. Reaching here means that wiring was bypassed — fail closed
        // with a credential that emits no auth header (upstream 401) rather than sending raw secret
        // material as a bearer.
        return Arc::new(NoCredential);
    }
    // A protocol that DECLARED its native credential scheme (an extracted dialect: Anthropic's
    // api-key-vs-Bearer disambiguation was the first) supplies the builder through its
    // `ProtocolDecl`; the arms below are the shared schemes of the dialects still in-tree, and
    // each leaves this match when its dialect is extracted.
    if let Some(decl) = crate::proto::decl_for(protocol_name) {
        if let Some(scheme) = decl.egress_scheme {
            return Arc::new(DeclaredScheme(scheme, Kernel::new()));
        }
        if let Some(headers_for) = decl.egress_auth_headers {
            return Arc::new(DeclaredCredential {
                headers_for,
                // The decl says whether its builder reads only (key, mode) — see
                // `ProtocolDecl::egress_auth_lane_constant`. A signer (bedrock SigV4) declares
                // `false` and is never prebuilt.
                lane_constant: decl.egress_auth_lane_constant,
            });
        }
    }
    // Every protocol a real deployment registers declares its own native egress scheme on its
    // `ProtocolDecl` (`egress_auth_headers`), resolved and returned BEFORE this point. No dialect
    // literal remains in this neutral resolver. Config validation refuses an unknown protocol name
    // before a lane ever reaches here, so this is a defensive, fail-closed fallback that emits no
    // auth header (upstream 401) — not a live scheme for any protocol this build actually serves.
    Arc::new(NoCredential)
}

/// Fail-closed credential: emits no auth header. Used only as a defensive fallback if an
/// async-constructed credential (e.g. `jwt-bearer`) reaches the sync resolver — the upstream then
/// rejects with 401 rather than receiving a wrong or raw-secret header.
struct NoCredential;
impl CredentialProvider for NoCredential {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
    fn is_lane_constant(&self) -> bool {
        true // constantly nothing
    }
}

/// A DECLARED egress scheme (`ProtocolDecl::egress_scheme`, or the operator's `auth: api-key`
/// override, which is the static `api-key` header scheme): presented by the egress-auth unit under a
/// `Grant<Sign>` the lane's teller mints for each presentation, so the credential is written onto
/// the request here and never passes through a plane. A static scheme is lane-constant; a signer is not.
/// A credential the unit could not present (a byte that is not a legal header value) sends no auth
/// header — the upstream answers 401 — and is reported here, with the key never logged.
struct DeclaredScheme(EgressScheme, crate::teller::Kernel);
impl CredentialProvider for DeclaredScheme {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        let presented = present(&self.1.sign_token(), &self.0, key, ctx);
        if let (true, Some(Raw { header, .. })) = (
            presented.is_empty(),
            presentation(&self.0, key, ctx.upstream_creds),
        ) {
            crate::diag_warn!(
                crate::diagnostics::EGRESS_APIKEY_INVALID_BYTES,
                header,
                "egress credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
        }
        let typed = |(k, v): (String, String)| Some((k.parse().ok()?, v.parse().ok()?));
        presented.into_iter().filter_map(typed).collect()
    }
    fn is_lane_constant(&self) -> bool {
        matches!(self.0, EgressScheme::Static { .. })
    }
}

/// A credential scheme a PROTOCOL DECLARED (`ProtocolDecl::egress_auth_headers`) — the extracted
/// dialects' path into this layer. The builder is declared data; this wrapper is only the vtable
/// shape `resolve` hands back for every scheme.
struct DeclaredCredential {
    headers_for: fn(&str, &SigningContext) -> Vec<(HeaderName, HeaderValue)>,
    lane_constant: bool,
}
impl CredentialProvider for DeclaredCredential {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        (self.headers_for)(key, ctx)
    }
    fn is_lane_constant(&self) -> bool {
        self.lane_constant
    }
}

// The license-header meta-test (scans the whole crate `src`) and the prebuilt-auth differential
// proof STAY in busbar-core after the module relocated DOWN here: the prebuilt proof reads the
// LLM dialect `ProtocolDecl`s that only core's `#[cfg(test)]` decl seeding registers, and the
// license scan is a crate-wide meta-test core keeps for its own `src`. Both host under core's
// `egress_auth` re-export shim (mirroring how the `gate` submodule keeps its core-only gate tests).

// `read_capped_token_response` meta-test lives in tests/ per the repo layout rule (no inline test
// bodies in a mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/helper_tests.rs"]
mod helper_tests;

/// Prebuild a lane's `Own`-mode egress auth headers at boot, or `None` when the credential is not
/// lane-constant. THE SAME CALL the request path makes — `headers_for` with an `Own`-mode context —
/// so the map a request clones is byte-identical to what it would have built live; the context's
/// request-varying fields are inert by definition of [`CredentialProvider::is_lane_constant`]
/// (a `false` there is exactly "this credential reads them", and such a credential never gets here).
pub fn prebuild_auth(
    credential: &Arc<dyn CredentialProvider>,
    api_key: &str,
    signing_host: &str,
) -> Option<http::header::HeaderMap> {
    if !credential.is_lane_constant() {
        return None;
    }
    // NO CREDENTIAL ⇒ NO AUTH HEADER. An empty key means there is nothing to present: the provider
    // declared `api_key: none` (a keyless local upstream — ollama, vLLM). Freezing
    // `Authorization: Bearer ` with no token would be strictly worse than freezing nothing — a
    // keyless upstream may reject a malformed empty credential, and an empty auth header is a proxy
    // tell no native client emits. The same rule is applied per-request in `lane_auth_headers`.
    if api_key.is_empty() && credential.uses_key() {
        return Some(http::header::HeaderMap::new());
    }
    let ctx = SigningContext {
        host: signing_host,
        canonical_uri: "",
        body: &[],
        timestamp_epoch: 0,
        upstream_creds: busbar_contract::config::UpstreamCreds::Own,
    };
    Some(crate::proto::convert_headers(
        credential.headers_for(api_key, &ctx),
    ))
}
