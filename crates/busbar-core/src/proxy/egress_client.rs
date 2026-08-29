// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED LLM-EGRESS HTTP CLIENT — hyper_util's legacy pool client over a
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
//!   * proxy env: reqwest honored `HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` implicitly (undocumented).
//!     Re-provided as an owned CONNECT tunnel (owner-ruled): when a proxy env var is present at
//!     boot, every egress connect goes TCP-to-proxy + `CONNECT host:port` + (for https targets)
//!     TLS over the tunnel — the same layering reqwest used, with `NO_PROXY` suffix matching and
//!     `Proxy-Authorization: Basic` from the proxy URL's userinfo. One documented deviation:
//!     plain-http targets are ALSO tunneled via CONNECT (reqwest forwarded them absolute-form);
//!     CONNECT-for-everything is what curl -p does and keeps request bytes identical either way.
//!     Deployments with no proxy env — every known one — take the direct arm, a `None` check per
//!     CONNECT (not per request; the pool reuses tunneled sockets like any other).
//!   * decompression: none before (no gzip/brotli features), none now.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;

/// The connector stack: TCP (+ boot-detected CONNECT tunnel when a proxy env is set) + rustls.
pub(crate) type EgressConnector = hyper_rustls::HttpsConnector<tunnel::TunnelConnector>;

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
    // The tunnel wrapper sits BETWEEN TCP and TLS: with no proxy env (every known deployment) it
    // delegates to the plain connector untouched; with one, it CONNECTs through the proxy and TLS
    // then handshakes over the tunnel with the real target's SNI — reqwest's exact layering.
    let http = tunnel::TunnelConnector::new(http, tunnel::installed_proxy());

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

/// The rustls client config: webpki roots, ALPN left to the connector builder. The crypto
/// provider is named EXPLICITLY (`ring` — the provider reqwest's `rustls-tls` used, so the
/// cipher-suite story is unchanged): the bare `builder()` auto-detects the process provider and
/// PANICS AT FIRST USE when more than one provider crate is in the binary's graph — which is
/// exactly the composed busbar binary, and a boot-time panic CI caught. Explicit therefore, never
/// ambient.
fn rustls_client_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring provider supports the default TLS protocol versions")
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

/// Boot-time proxy-env parity: reqwest honored `HTTPS_PROXY`/`https_proxy`/`ALL_PROXY`
/// implicitly, so their PRESENCE must keep working. Detection happens once here (scheme-specific
/// beats `ALL_PROXY`, reqwest's precedence); the returned value is `None` in every deployment
/// that does not set them, and the direct connector above is used untouched.
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

/// The owned CONNECT tunnel for the proxy-env parity case (owner-ruled: full tunnel, not the
/// boot-refusal interim). Constructed ONLY when a proxy env var is present at boot; the direct
/// path pays one `None` check per CONNECT and nothing per request.
mod tunnel {
    use std::sync::{Arc, OnceLock};

    /// The boot-resolved proxy: where to TCP-connect, what to put in `Proxy-Authorization`, and
    /// which target hosts bypass it (`NO_PROXY`). Parsed ONCE at boot by
    /// [`install_proxy_tunnel_if_configured`]; every client shard shares it by refcount.
    #[cfg_attr(test, derive(Debug))] // tests unwrap_err() around it; production never prints it
    pub(crate) struct ProxySpec {
        /// Proxy endpoint as the plain `host:port` CONNECT dial string.
        host: String,
        port: u16,
        /// `Proxy-Authorization: Basic <b64(user:pass)>` prebuilt from the proxy URL's userinfo.
        auth: Option<String>,
        /// Parsed `NO_PROXY` entries (lowercased, leading dots stripped). `*` becomes a match-all
        /// entry that disables tunneling entirely — the conventional semantics.
        no_proxy: Vec<String>,
    }

    impl ProxySpec {
        /// `NO_PROXY` semantics: an entry matches the target host exactly or as a domain suffix
        /// (`example.com` matches `api.example.com`), the conventional curl/reqwest behavior.
        fn bypasses(&self, target_host: &str) -> bool {
            let host = target_host.to_ascii_lowercase();
            self.no_proxy.iter().any(|e| {
                e == "*"
                    || host == *e
                    || (host.len() > e.len()
                        && host.ends_with(e.as_str())
                        && host.as_bytes()[host.len() - e.len() - 1] == b'.')
            })
        }
    }

    /// Parse a proxy env value (`http://[user:pass@]host[:port]`; a bare `host:port` is accepted
    /// too). `https://` proxies are refused loudly: TLS-to-proxy is a different transport this
    /// tunnel does not speak, and silently downgrading it to TCP would be a lie.
    pub(super) fn parse_proxy(v: &str) -> Result<ProxySpec, String> {
        let url = if v.contains("://") {
            v.to_string()
        } else {
            format!("http://{v}")
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|e| format!("proxy env value {v:?} is not a valid URL: {e}"))?;
        if parsed.scheme() != "http" {
            return Err(format!(
                "proxy env value {v:?} uses scheme {:?}: only plain http:// CONNECT proxies are \
                 supported (an https:// proxy would need TLS-to-proxy, which this tunnel does not \
                 speak)",
                parsed.scheme()
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("proxy env value {v:?} has no host"))?
            .to_string();
        let port = parsed.port().unwrap_or(80);
        let auth = (!parsed.username().is_empty()).then(|| {
            use base64::Engine;
            let creds = format!(
                "{}:{}",
                parsed.username(),
                parsed.password().unwrap_or_default()
            );
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(creds)
            )
        });
        Ok(ProxySpec {
            host,
            port,
            auth,
            no_proxy: no_proxy_env(),
        })
    }

    /// `NO_PROXY`/`no_proxy`: comma-separated hosts/suffixes; empty entries and leading dots
    /// dropped, everything lowercased once here so the per-connect match never re-normalizes.
    fn no_proxy_env() -> Vec<String> {
        for key in ["NO_PROXY", "no_proxy"] {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() {
                    return v
                        .split(',')
                        .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
                        .filter(|e| !e.is_empty())
                        .collect();
                }
            }
        }
        Vec::new()
    }

    /// The boot-installed proxy, `None` in every deployment without a proxy env. `OnceLock` so
    /// config applies rebuild clients against the SAME boot decision — proxy env is process
    /// environment, immutable for the process lifetime, exactly reqwest's read-once behavior.
    static INSTALLED: OnceLock<Option<Arc<ProxySpec>>> = OnceLock::new();

    /// Resolve the proxy env at boot: absent → direct (the common arm), present-and-valid →
    /// install the tunnel spec for every client build, present-and-garbage → refuse to start
    /// (fail-loud beats silently egressing direct past a configured proxy).
    pub(crate) fn install_proxy_tunnel_if_configured() -> Result<(), String> {
        let spec = match super::proxy_env() {
            None => None,
            Some(v) => Some(Arc::new(parse_proxy(&v)?)),
        };
        let _ = INSTALLED.set(spec);
        Ok(())
    }

    /// What the client builder wires in: the boot decision, or `None` for a build that runs
    /// before/without `install_proxy_tunnel_if_configured` (tests, tools) — direct, like reqwest
    /// built without proxy env.
    pub(crate) fn installed_proxy() -> Option<Arc<ProxySpec>> {
        INSTALLED.get().cloned().flatten()
    }

    /// The connector hyper-rustls wraps: plain TCP in the direct arm, TCP-to-proxy + CONNECT in
    /// the tunneled arm. Sits BELOW TLS, so an https target's TLS handshake (with the target's
    /// SNI, against the target's cert) runs over the established tunnel — the proxy sees only
    /// `CONNECT host:port`, never a decrypted byte.
    #[derive(Clone)]
    pub(crate) struct TunnelConnector {
        inner: hyper_util::client::legacy::connect::HttpConnector,
        proxy: Option<Arc<ProxySpec>>,
    }

    impl TunnelConnector {
        pub(crate) fn new(
            inner: hyper_util::client::legacy::connect::HttpConnector,
            proxy: Option<Arc<ProxySpec>>,
        ) -> Self {
            Self { inner, proxy }
        }
    }

    /// Hard ceiling on the proxy's CONNECT response head; a real response is one status line +
    /// a few headers. Anything larger is a misbehaving proxy and fails the connect.
    const CONNECT_HEAD_CAP: usize = 8 * 1024;
    /// Wall-clock bound on the CONNECT handshake — the same 10s the TCP connect itself carries,
    /// so a black-holing proxy fails over on the engine's normal transport-error arm.
    const CONNECT_HANDSHAKE_SECS: u64 = 10;

    type BoxError = Box<dyn std::error::Error + Send + Sync>;
    type ConnectFuture = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<hyper_util::rt::TokioIo<tokio::net::TcpStream>, BoxError>,
                > + Send,
        >,
    >;

    impl tower::Service<http::Uri> for TunnelConnector {
        type Response = hyper_util::rt::TokioIo<tokio::net::TcpStream>;
        type Error = BoxError;
        type Future = ConnectFuture;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            tower::Service::poll_ready(&mut self.inner, cx).map_err(Into::into)
        }

        fn call(&mut self, dst: http::Uri) -> Self::Future {
            // Direct arm: no proxy installed, or the target host is NO_PROXY-listed.
            let target_host = dst.host().unwrap_or_default().to_string();
            let proxy = match &self.proxy {
                Some(p) if !p.bypasses(&target_host) => p.clone(),
                _ => {
                    let fut = tower::Service::call(&mut self.inner, dst);
                    return Box::pin(async move { fut.await.map_err(Into::into) });
                }
            };
            // Tunneled arm: dial the PROXY with the same connector (its connect timeout,
            // keepalive and nodelay apply to the proxy socket), then CONNECT to the real target.
            let target_port = dst.port_u16().unwrap_or_else(|| {
                if dst.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            });
            let proxy_uri: http::Uri = match format!("http://{}:{}", proxy.host, proxy.port).parse()
            {
                Ok(u) => u,
                Err(e) => return Box::pin(async move { Err(Box::new(e) as BoxError) }),
            };
            let dial = tower::Service::call(&mut self.inner, proxy_uri);
            Box::pin(async move {
                let io = dial.await.map_err(Into::<BoxError>::into)?;
                let mut stream = io.into_inner();
                let handshake = connect_handshake(&mut stream, &target_host, target_port, &proxy);
                tokio::time::timeout(
                    std::time::Duration::from_secs(CONNECT_HANDSHAKE_SECS),
                    handshake,
                )
                .await
                .map_err(|_| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "proxy CONNECT handshake timed out",
                    )) as BoxError
                })??;
                Ok(hyper_util::rt::TokioIo::new(stream))
            })
        }
    }

    /// Write `CONNECT host:port HTTP/1.1` (+ Host, + Proxy-Authorization when configured), read
    /// the response head, and accept only a 2xx — the entire RFC 9110 §9.3.6 exchange. On return
    /// the stream IS the target connection.
    async fn connect_handshake(
        stream: &mut tokio::net::TcpStream,
        host: &str,
        port: u16,
        proxy: &ProxySpec,
    ) -> Result<(), BoxError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(auth) = &proxy.auth {
            req.push_str("Proxy-Authorization: ");
            req.push_str(auth);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;

        // Read to the end of the response head. A byte-at-a-time scan would syscall per byte;
        // a buffered over-read would swallow target bytes — but a compliant proxy sends NOTHING
        // after its 2xx head until we speak, so reading in small chunks and stopping at the
        // first complete head is both correct and cheap (one or two reads in practice).
        let mut head: Vec<u8> = Vec::with_capacity(256);
        loop {
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err("proxy closed the connection during CONNECT".into());
            }
            head.extend_from_slice(&buf[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if head.len() > CONNECT_HEAD_CAP {
                return Err("proxy CONNECT response head exceeded 8KiB".into());
            }
        }
        // Status line: `HTTP/1.x NNN ...` — accept any 2xx (RFC 9110: 2xx means the tunnel is
        // established; some proxies say 200 Connection established, some plain 200 OK).
        let line = head.split(|&b| b == b'\r').next().unwrap_or_default();
        let status_2xx = line
            .split(|&b| b == b' ')
            .nth(1)
            .is_some_and(|code| code.first() == Some(&b'2') && code.len() == 3);
        if !status_2xx {
            return Err(format!(
                "proxy refused CONNECT {host}:{port}: {}",
                String::from_utf8_lossy(line)
            )
            .into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_spec(
        host: &str,
        port: u16,
        auth: Option<String>,
        no_proxy: &[&str],
    ) -> Arc<ProxySpec> {
        Arc::new(ProxySpec {
            host: host.to_string(),
            port,
            auth,
            no_proxy: no_proxy.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[cfg(test)]
    pub(super) use parse_proxy as parse_proxy_for_tests;

    #[cfg(test)]
    pub(super) fn bypasses_for_tests(spec: &Arc<ProxySpec>, host: &str) -> bool {
        spec.bypasses(host)
    }
}
