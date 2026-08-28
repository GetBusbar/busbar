// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED LLM-EGRESS HTTP CLIENT (wave 7) — hyper_util's legacy pool client over a
//! rustls/webpki connector, replacing reqwest on the forward path. What this buys per request:
//! the send consumes the lane's boot-precomputed `http::Uri` directly (reqwest re-parsed its
//! `Url` to a `Uri` through the full WHATWG parser at EVERY send), the request is hand-assembled
//! from the prebuilt header map (no `RequestBuilder` machinery, no redirect-policy hook, no
//! wrapper allocations), and the response is consumed as bare `http` parts + `Incoming` body.
//!
//! PARITY LEDGER — every facility the reqwest builder provided, re-provided or made structural
//! (see `appbuild.rs`'s old builder comments, preserved there):
//!   * pooling: `pool_max_idle_per_host` / `pool_idle_timeout` / Tokio pool timer — same knobs,
//!     same per-shard division; warm-pool reuse on config apply keyed by the same
//!     `UpstreamClientSettings` snapshot.
//!   * TLS trust: rustls + compiled-in webpki (Mozilla) roots — byte-identical trust story to
//!     reqwest's `rustls-tls` feature. ALPN offers `h2,http/1.1` by default; `http1_only` pins
//!     h1 (and wins over h2c, preserving the old apply-order); `h2_prior_knowledge` forces
//!     cleartext h2c.
//!   * timeouts: connect 10s on the connector; h2 keep-alive interval/timeout + adaptive window
//!     on the client. The old CLIENT-LEVEL total timeout is re-provided at the call sites — the
//!     engine bounds a non-streaming request (send + capped body read) with one deadline, and the
//!     streaming ceiling lives in the stream body itself — because a pool client cannot know
//!     which requests stream.
//!   * TCP: keepalive 60s + nodelay, same values, same rationale (delayed-ACK tail spike).
//!   * redirects: hyper never follows redirects — the SSRF guard reqwest needed a policy for is
//!     now structural.
//!   * proxy env: reqwest honored `HTTPS_PROXY`/`ALL_PROXY` implicitly (undocumented). The
//!     interim stance is FAIL-LOUD at boot when one is set (see `install_proxy_tunnel_if_configured`)
//!     — silently bypassing a corporate proxy would be the dangerous direction; a CONNECT tunnel
//!     lands behind that seam if a deployment needs it. OWNER RULING PENDING. Direct deployments
//!     (every known one) are untouched.
//!   * decompression: none before (no gzip/brotli features), none now.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;

/// The connector stack: TCP (+ optional boot-detected CONNECT tunnel) + rustls.
pub(crate) type EgressConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

/// The pooled egress client. `Full<Bytes>`: every LLM egress body is one owned buffer.
pub(crate) type EgressClient = hyper_util::client::legacy::Client<EgressConnector, Full<Bytes>>;

/// The error type `EgressClient::request` yields — named so the engine's transport-error
/// classification arms read as prose.
pub(crate) type EgressError = hyper_util::client::legacy::Error;

/// Inputs the builder needs — the same subset `UpstreamClientSettings` snapshots (plus the
/// per-shard idle division the caller already computes).
pub(crate) struct EgressClientSpec {
    pub(crate) idle_per_host: usize,
    pub(crate) pool_idle_timeout_secs: u64,
    pub(crate) http1_only: bool,
    pub(crate) h2_prior_knowledge: bool,
}

/// Build ONE egress client shard per the parity ledger above.
pub(crate) fn build_egress_client(spec: &EgressClientSpec) -> EgressClient {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    // The mock/bench upstreams are plain http; TLS wraps only https targets (below).
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(Some(Duration::from_secs(60)));
    http.set_nodelay(true);

    // rustls client config over the compiled-in webpki roots — the same trust anchors reqwest's
    // rustls-tls used. ALPN is set by the connector builder below (`enable_http1` pins h1;
    // `enable_all_versions` offers h2 then h1), which asserts the config arrives ALPN-empty.
    let tls = rustls_client_config();
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls);
    let https: EgressConnector = if spec.http1_only {
        builder.https_or_http().enable_http1().wrap_connector(http)
    } else {
        builder
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http)
    };

    let mut client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
    client
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .pool_max_idle_per_host(spec.idle_per_host)
        .pool_idle_timeout(Duration::from_secs(spec.pool_idle_timeout_secs))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_adaptive_window(true);
    // Cleartext h2c opt-in (bench / in-mesh): FORCE h2 without ALPN; h1-only wins over it,
    // preserving the old builder's apply-order.
    if spec.h2_prior_knowledge && !spec.http1_only {
        client.http2_only(true);
    }
    client.build(https)
}

/// The rustls client config: webpki roots, ALPN left to the connector builder.
fn rustls_client_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Assemble one egress request from the boot-precomputed parts: the lane's `http::Uri` and the
/// caller-built header map, body as one owned buffer. No builder, no validation re-runs — every
/// component was validated when it was made.
pub(crate) fn egress_request(
    uri: http::Uri,
    headers: http::HeaderMap,
    body: Bytes,
) -> http::Request<Full<Bytes>> {
    let mut req = http::Request::new(Full::new(body));
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = uri;
    *req.headers_mut() = headers;
    req
}

/// Collect a response body to `Bytes` with a hard cap — the generic replacement for the
/// reqwest-typed capped read. Returns `None` when the body exceeds `cap` (the caller's
/// oversized-response arm) and propagates transport errors.
pub(crate) async fn collect_capped(
    body: hyper::body::Incoming,
    cap: usize,
) -> Result<Option<Bytes>, hyper::Error> {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            if buf.len() + data.len() > cap {
                return Ok(None);
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(Some(buf.into()))
}

/// Boot-time proxy-env parity: reqwest honored `HTTPS_PROXY`/`https_proxy`/`ALL_PROXY`
/// implicitly, so their PRESENCE must keep working. Detection happens once here; the returned
/// value is `None` in every deployment that does not set them, and the direct connector above is
/// used untouched.
#[allow(dead_code)] // read by the tunnel wiring landing with the send-site cutover
pub(crate) fn proxy_env() -> Option<String> {
    for key in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "tests/egress_client_tests.rs"]
mod egress_client_tests;

pub(crate) use tunnel::install_proxy_tunnel_if_configured;

/// Minimal owned CONNECT tunnel for the proxy-env parity case. Constructed ONLY when a proxy env
/// var is present at boot; the direct path never touches it.
mod tunnel {
    /// Wire the tunnel when a proxy env is configured. For 1.6.0 the LLM egress path refuses to
    /// START under a proxy env rather than silently bypassing it (fail-loud beats silent
    /// behavior change in EITHER direction); the tunnel implementation lands behind this seam
    /// the moment a deployment needs it. reqwest-era behavior: env honored implicitly and
    /// undocumented; no known deployment sets it (the bench and every documented deploy run
    /// direct). Boot refusal with a clear message is the honest interim.
    pub(crate) fn install_proxy_tunnel_if_configured() -> Result<(), String> {
        match super::proxy_env() {
            None => Ok(()),
            Some(v) => Err(format!(
                "an egress proxy environment variable is set ({v:?}): 1.6.0's owned egress \
                 client does not yet tunnel through HTTP proxies. Unset HTTPS_PROXY/ALL_PROXY \
                 for the busbar process, or hold this deployment on 1.5.x until proxy tunneling \
                 lands."
            )),
        }
    }
}
