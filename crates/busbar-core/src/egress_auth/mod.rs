//! Egress credential seam — how Busbar presents ITS OWN identity to an upstream provider.
//!
//! This is the OUTBOUND counterpart to the ingress [`crate::auth`] chain ("who is calling us"). A
//! [`CredentialProvider`] turns a lane's configured credential material into the exact auth headers
//! an outbound request carries. It is [`resolve`]d once per lane at boot from the lane's protocol +
//! configured auth style, and lives on [`crate::state::Lane`], so the request path dispatches
//! (`lane.credential.headers_for(...)`) instead of branching.
//!
//! "Protocol is post-auth": auth answers *who am I to this upstream* (headers / signature); the
//! protocol answers *how do I shape this payload*. They compose through [`SigningContext`] — a signer
//! (SigV4) consumes the protocol's already-written body + path — but auth no longer lives on the
//! `ProtocolWriter`. The per-scheme logic lives in `pub(crate)` free functions co-located with each
//! protocol's constants (`proto::bearer_auth_headers`, `proto::anthropic::anthropic_auth_headers`,
//! and, for an EXTRACTED dialect, a builder the dialect DECLARES on
//! `ProtocolDecl::egress_auth_headers` — `busbar-llm`'s Bedrock module hands in its SigV4 signer
//! that way, and this module wraps it in `DeclaredCredential` without ever naming the dialect).
//! This module owns the *dispatch*. Those same free functions
//! are what the byte-pinning auth tests call, so a credential and its test can never diverge.

use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use std::sync::Arc;

pub(crate) mod bearer_token;
/// THE EGRESS GATE: whether an outbound credential may be leased AT ALL, for a given inbound
/// principal. The sibling of everything else in this module — the rest answers "which headers does
/// busbar present", this answers "may busbar spend its own authority here on this caller's behalf" —
/// and it is core because it was written once per plane and the copies had already diverged.
pub mod gate;
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
pub(crate) fn minter_client() -> Result<crate::proxy::EgressClient, String> {
    Ok(crate::proxy::build_egress_client(
        &crate::proxy::EgressClientSpec::llm_lane(usize::MAX, 90, false, false),
    ))
}

/// The whole-mint deadline — send plus capped body read under ONE absolute instant, the
/// client-level 30s total the retired reqwest builder carried.
pub(crate) const MINT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Default token TTL when a token endpoint omits `expires_in` (RFC 6749 §5.1 makes it RECOMMENDED, not
/// required): a conservative 1 h so the token still refreshes on schedule.
pub(crate) fn default_expires_in() -> u64 {
    3600
}

/// Deserialize an OAuth `expires_in` TOLERANTLY. RFC 6749 specifies a number of seconds, but real IdPs
/// vary — ADFS and Azure AD v1 emit it as a JSON STRING (`"3600"`), and some omit it (handled by
/// `#[serde(default = "default_expires_in")]` on the field). A strict `u64` field breaks token minting
/// for those providers, silently downing the lane. Accept an integer, a JSON float/decimal
/// (`3600.0` / `"3600.5"`, truncated toward zero — a fractional second on a token TTL is noise), or a
/// numeric string. A negative or non-finite value is rejected.
pub(crate) fn deserialize_expires_in<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        // Order matters for `untagged`: an integer matches `Num` first; `Float` only catches a
        // non-integer JSON number; `Str` catches a quoted value.
        Num(u64),
        Float(f64),
        Str(String),
    }
    fn float_to_secs<E: serde::de::Error>(f: f64) -> Result<u64, E> {
        if f.is_finite() && f >= 0.0 {
            Ok(f as u64)
        } else {
            Err(E::custom(format!(
                "expires_in must be a non-negative number, got {f}"
            )))
        }
    }
    match NumOrStr::deserialize(d)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Float(f) => float_to_secs(f),
        NumOrStr::Str(s) => {
            let t = s.trim();
            if let Ok(n) = t.parse::<u64>() {
                Ok(n)
            } else if let Ok(f) = t.parse::<f64>() {
                float_to_secs(f)
            } else {
                Err(serde::de::Error::custom(format!(
                    "expires_in {s:?} is not a number"
                )))
            }
        }
    }
}

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
}

/// Resolve a lane's egress credential at boot from its protocol name and auth style.
/// `auth: api-key` overrides the protocol's native scheme.
pub fn resolve(
    protocol_name: &str,
    auth: Option<crate::config::ProviderAuth>,
) -> Arc<dyn CredentialProvider> {
    if matches!(auth, Some(crate::config::ProviderAuth::ApiKey)) {
        return Arc::new(ApiKeyHeader { header: "api-key" });
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
    // Every protocol this build serves declares its native egress scheme on its `ProtocolDecl`
    // (`egress_auth_headers`), resolved and returned BEFORE this point — anthropic and openai chat
    // (bearer), gemini (`x-goog-api-key`), cohere / responses (bearer), bedrock (SigV4). No dialect
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

/// Static custom header carrying the raw key (`api-key` or `x-goog-api-key`). An un-encodable key
/// yields no header (upstream 401s). Free function so auth tests exercise the exact same code.
/// Delegates to the neutral `busbar_substrate::proto::api_key_auth_headers` so the config-`api-key`
/// override path here and the Gemini dialect's `x-goog-api-key` scheme share ONE implementation.
pub fn api_key_headers(header: &'static str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    busbar_substrate::proto::api_key_auth_headers(header, key)
}

struct ApiKeyHeader {
    header: &'static str,
}
impl CredentialProvider for ApiKeyHeader {
    fn headers_for(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        api_key_headers(self.header, key)
    }
    fn is_lane_constant(&self) -> bool {
        true // pure function of the key
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

// License-header meta-test lives in tests/ per the repo layout rule (no inline test bodies in a
// mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;

// The prebuilt-auth differential proof (prebuilt == live for lane-constant schemes; signers
// refuse to prebuild). Lives in tests/ per the repo layout rule.
#[cfg(test)]
#[path = "tests/prebuilt_auth_tests.rs"]
mod prebuilt_auth_tests;

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
    let ctx = SigningContext {
        host: signing_host,
        canonical_uri: "",
        body: &[],
        timestamp_epoch: 0,
        upstream_creds: busbar_api::UpstreamCreds::Own,
    };
    Some(crate::proto::convert_headers(
        credential.headers_for(api_key, &ctx),
    ))
}
