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
//! `proto::bedrock::sigv4_sign_headers`); this module owns the *dispatch*. Those same free functions
//! are what the byte-pinning auth tests call, so a credential and its test can never diverge.

use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use std::sync::Arc;

pub(crate) mod bearer_token;
/// THE EGRESS GATE: whether an outbound credential may be leased AT ALL, for a given inbound
/// principal. The sibling of everything else in this module — the rest answers "which headers does
/// busbar present", this answers "may busbar spend its own authority here on this caller's behalf" —
/// and it is core because it was written once per plane and the copies had already diverged.
pub(crate) mod gate;
pub(crate) mod jwt_bearer;
pub(crate) mod oauth_client_credentials;

/// HTTP client used by the self-minting OAuth credentials (`jwt-bearer`, `oauth-client-credentials`)
/// to POST to a token endpoint. Hardened like the data-path upstream client (see `main.rs`):
///   * `redirect: none` — the credential (a signed assertion, or `client_secret`) rides in the POST
///     BODY, so reqwest's cross-host Authorization-stripping does not protect it; a 307/308 from a
///     compromised or typo'd token endpoint would re-POST the plaintext secret to the redirect target
///     (169.254.169.254 / localhost / RFC1918). The boot-time SSRF check only vets the configured URL
///     string, never a runtime redirect target, so following redirects reopens that exfil vector.
///   * bounded connect + overall timeouts — a stalled token endpoint must not hang the mint/refresh
///     future forever (the refresh loop only retries on `Err`, so a hang would silently freeze the
///     lane's token and serve an empty bearer → upstream 401).
pub(crate) fn minter_client() -> Result<reqwest::Client, String> {
    // `build` errors only when TLS init fails (native-tls unavailable/broken). Return the error so a
    // degraded-TLS environment disables just the OAuth egress lane with a diagnostic at boot/apply,
    // rather than `expect`-panicking the whole process (which the callers already handle: both
    // `build()` sites return `Result<_, String>`).
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("build OAuth token-minter HTTP client: {e}"))
}

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
pub(crate) async fn read_capped_token_response(resp: reqwest::Response) -> Result<String, String> {
    let cap = crate::proxy::max_upstream_buffered_bytes();
    let (raw, read_end) = crate::proxy::read_capped(resp, cap).await;
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
pub(crate) struct MetadataSsrfPolicy<'a> {
    pub(crate) allow_overrides: &'a [String],
    pub(crate) allow_all: bool,
    pub(crate) blocked_hosts: &'a [String],
}

/// Produces the outbound auth headers for a single upstream request.
///
/// `key` is the per-request credential the caller resolved — the lane's configured key for
/// [`crate::auth::UpstreamCreds::Own`], or the forwarded caller token for `Passthrough`. A
/// self-minting credential (e.g. a future OAuth token provider) ignores `key`. `ctx` carries the
/// host / canonical-uri / body / timestamp a signer needs, plus the `Own | Passthrough` mode.
pub(crate) trait CredentialProvider: Send + Sync {
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
}

/// Resolve a lane's egress credential at boot from its protocol name and auth style.
/// `auth: api-key` overrides the protocol's native scheme.
pub(crate) fn resolve(
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
    match protocol_name {
        "gemini" => Arc::new(ApiKeyHeader {
            header: "x-goog-api-key",
        }),
        "anthropic" => Arc::new(AnthropicNative),
        "bedrock" => Arc::new(SigV4),
        // openai / cohere / responses and any other bearer-native protocol.
        "cohere" => Arc::new(StaticBearer { proto: "cohere" }),
        "responses" => Arc::new(StaticBearer { proto: "responses" }),
        _ => Arc::new(StaticBearer { proto: "openai" }),
    }
}

/// Fail-closed credential: emits no auth header. Used only as a defensive fallback if an
/// async-constructed credential (e.g. `jwt-bearer`) reaches the sync resolver — the upstream then
/// rejects with 401 rather than receiving a wrong or raw-secret header.
struct NoCredential;
impl CredentialProvider for NoCredential {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
}

/// `Authorization: Bearer <key>` — openai / cohere / responses. Drops the header on a control-char key.
struct StaticBearer {
    proto: &'static str,
}
impl CredentialProvider for StaticBearer {
    fn headers_for(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::bearer_auth_headers(self.proto, key)
    }
}

/// Static custom header carrying the raw key (`api-key` or `x-goog-api-key`). An un-encodable key
/// yields no header (upstream 401s). Free function so auth tests exercise the exact same code.
pub(crate) fn api_key_headers(header: &'static str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    match HeaderValue::from_str(key) {
        Ok(v) => vec![(HeaderName::from_static(header), v)],
        Err(_) => {
            tracing::warn!(
                header,
                "egress credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
            Vec::new()
        }
    }
}

struct ApiKeyHeader {
    header: &'static str,
}
impl CredentialProvider for ApiKeyHeader {
    fn headers_for(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        api_key_headers(self.header, key)
    }
}

/// Anthropic's api-key (`sk-ant-api…` → `x-api-key`) vs Bearer (`sk-ant-oat…` → `Authorization`)
/// disambiguation, resolved against the `Own | Passthrough` mode for an ambiguous credential.
struct AnthropicNative;
impl CredentialProvider for AnthropicNative {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::anthropic::anthropic_auth_headers(key, Some(ctx.upstream_creds))
    }
}

/// AWS SigV4 over the request (body + canonical path from `ctx`) — Bedrock.
struct SigV4;
impl CredentialProvider for SigV4 {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::bedrock::sigv4_sign_headers(key, ctx)
    }
}

// License-header meta-test lives in tests/ per the repo layout rule (no inline test bodies in a
// mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;

// `read_capped_token_response` meta-test lives in tests/ per the repo layout rule (no inline test
// bodies in a mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/helper_tests.rs"]
mod helper_tests;
