// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE EGRESS-AUTH SEAM moved DOWN into `busbar-substrate` (the LLM plane named
//! `busbar_kernel::egress_auth` as its last backwards reach); this module re-exports it (glob) so
//! every historical `busbar_kernel::egress_auth::…` name — `CredentialProvider`,
//! `MetadataSsrfPolicy`, `bearer_auth_headers`, and the `jwt_bearer` /
//! `oauth_client_credentials` mint modules — resolves unchanged, and hosts the two egress-auth
//! tests that must stay core-side (below). The egress grant gate is authorization and lives in
//! `busbar_kernel_scope::egress`.

// The crate-wide license-header meta-test scans this crate's whole `src` (via `CARGO_MANIFEST_DIR`),
// so it stays with busbar-core; it is not egress-auth-specific.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use axum::http::{HeaderName, HeaderValue};
use busbar_contract::protocol::SigningContext;

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

// The OAuth token response (its `Redacted` access token and its tolerant `expires_in`) is egress-auth
// semantics with no engine in it, so it lives with the egress-auth unit (#83a O1 placement), as does
// the read-only serde helper a secret field of a decoded document names to land in `Redacted`.
pub(crate) use busbar_kernel_identity::egress_auth::{deserialize_redacted, TokenResponse};

/// The `map_err` for a `serde_json` decode whose INPUT may carry a secret — a service-account key, a
/// token response, a secret's settings. `serde_json::Error`'s own `Display` is withheld: a data
/// error quotes the offending value (`invalid type: string "<the value>"`), which here can be the
/// secret itself, and these messages reach `--validate` output, read-scope admin callers and logs.
/// What survives is `what` failed, the CLASS of failure and WHERE — enough to repair the document,
/// nothing of what it holds (secret-hygiene #53, Check 3: redact at the format site). The one
/// decoder text kept verbatim is a MISSING FIELD: serde spells it from the type's own schema
/// (``missing field `private_key` ``), never from the input, and it is the commonest repair.
pub(crate) fn json_err(what: &'static str) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        if e.is_data() && e.to_string().starts_with("missing field `") {
            return format!("{what}: {e}");
        }
        let class = match e.classify() {
            serde_json::error::Category::Io => "the input could not be read",
            serde_json::error::Category::Syntax => "it is not well-formed JSON",
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
            serde_json::error::Category::Eof => "it ends before the JSON does",
        };
        let (line, column) = (e.line(), e.column());
        format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
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

// The license-header meta-test scans the whole crate `src`; it is a crate-wide meta-test core keeps
// for its own `src`, hosted here.

// `read_capped_token_response` meta-test lives in tests/ per the repo layout rule (no inline test
// bodies in a mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/helper_tests.rs"]
mod helper_tests;

/// THE SHARED `Authorization: Bearer <key>` BUILDER, typed: the identity crate's builder, with a
/// credential carrying bytes no header may hold OMITTED (the upstream then answers 401) and that
/// omission logged under `label` (the caller's own name for what it presents to), the key never
/// logged. Protocol-neutral: a bearer token is a credential carrier, not a dialect.
pub fn bearer_auth_headers(label: &str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    let built = busbar_kernel_identity::egress_auth::bearer_auth_headers(key);
    if built.is_empty() {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::PROTO_AUTH_INVALID_HEADER_BYTES,
            protocol = label,
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401"
        );
    }
    let typed = |(k, v): (String, String)| Some((k.parse().ok()?, v.parse().ok()?));
    built.into_iter().filter_map(typed).collect()
}
