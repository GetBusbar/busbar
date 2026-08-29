// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS ENGINE — hyper_util's legacy pool client over a rustls/webpki connector: the ONE
//! owned outbound HTTP stack (owner-ruled), relocated here from `busbar-core::proxy::egress_client`
//! so every plane (LLM/model, MCP, A2A) builds its clients from one neutral home. Core re-exports
//! every name from its old `crate::proxy::` paths, so the LLM lanes are byte-for-byte the client
//! this file was when it lived there.
//!
//! Born as the LLM forward-path client, replacing reqwest there. What it buys per request:
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
//!   * proxy env: reqwest honored `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` implicitly
//!     (undocumented; hyper-util's env matcher under the hood). Re-provided SCHEME-SCOPED as an
//!     owned CONNECT tunnel (owner-ruled): https:// targets use `HTTPS_PROXY`, http:// targets
//!     use `HTTP_PROXY`, each falling back to `ALL_PROXY`, uppercase read before lowercase —
//!     reqwest's exact precedence. When the target's scheme has a proxy and the host is not
//!     `NO_PROXY`-excluded, the connect goes TCP-to-proxy + `CONNECT host:port` + (for https
//!     targets) TLS over the tunnel — the same layering reqwest used — with
//!     `Proxy-Authorization: Basic` from the proxy URL's userinfo. `NO_PROXY` matches
//!     hosts/domain-suffixes AND IP literals AND CIDR blocks, reqwest's full rule set. One
//!     documented deviation: plain-http targets are ALSO tunneled via CONNECT (reqwest forwarded
//!     them absolute-form); CONNECT-for-everything is what curl -p does and keeps request bytes
//!     identical either way. Deployments with no proxy env — every known one — take the direct
//!     arm, a `None` check per CONNECT (not per request; the pool reuses tunneled sockets like
//!     any other).
//!   * decompression: none before (no gzip/brotli features), none now.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;

// THE ENGINE'S LAYERS, each its own file: the resolver (where the pin lives), the peer-identity
// observation, and the whole-connect deadline. The CONNECT tunnel stays in this file's `tunnel`
// module, where it moved from core verbatim.
pub mod deadline;
pub mod observe;
pub mod resolve;

pub use deadline::ConnectDeadline;
pub use observe::{peer_spki, ObservedIo, PeerSpki, SpkiObserve};
pub use resolve::{EgressResolver, ResolveNames};

/// The connector stack, bottom-up: TCP through the pin-aware resolver (+ boot-detected CONNECT
/// tunnel when a proxy env is set) + rustls, the whole connect under one wall-clock deadline,
/// with the peer identity observed on the way out. ONE concrete type for every posture — the
/// per-posture differences are VALUES inside the layers, never per-request branches.
pub type EngineConnector =
    SpkiObserve<ConnectDeadline<hyper_rustls::HttpsConnector<tunnel::TunnelConnector>>>;

/// The pooled egress client. `Full<Bytes>`: every engine egress body is one owned buffer.
pub type EngineClient = hyper_util::client::legacy::Client<EngineConnector, Full<Bytes>>;

/// The error type `EngineClient::request` yields — named so a consumer's transport-error
/// classification arms read as prose.
pub type EngineError = hyper_util::client::legacy::Error;

/// The engine's posture, one value per client build. Composed ONLY through the blessed
/// constructors ([`EngineSpec::llm_lane`] today; the pinned-plane posture joins it as the
/// migration proceeds), so no call site ever assembles a posture by hand and "no new knobs" stays
/// structural rather than reviewed.
pub struct EngineSpec {
    pub idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub http1_only: bool,
    pub h2_prior_knowledge: bool,
    /// Destination pinning. `None` = the LLM lanes (their destination is operator config,
    /// guarded at apply). `Some` makes DNS structural: the resolver becomes the pin itself
    /// ([`EgressResolver::Pinned`]) and `dns` below is never consulted.
    pub pin: Option<PinnedDest>,
    /// DNS when unpinned.
    pub dns: Dns,
    /// Peer-certificate observation for SPKI pinning ([`observe`]). Off on the LLM lanes (no
    /// walk, no hash per connect); on for every pinned posture.
    pub observe_spki: bool,
}

/// The pin: exactly one hostname answered with exactly one already-judged address. The judged
/// PORT stays on the URI (the resolver answers port 0 and `HttpConnector` takes the port from
/// the destination) — reqwest's documented `.resolve()` behaviour.
pub struct PinnedDest {
    pub host: Arc<str>,
    pub addr: IpAddr,
}

/// DNS posture when no pin is installed.
pub enum Dns {
    /// `getaddrinfo` — reqwest's default and `HttpConnector`'s default.
    System,
    /// Caller-supplied (tests: the counting resolver that proves "zero engine lookups").
    Custom(Arc<dyn ResolveNames>),
}

impl EngineSpec {
    /// TODAY'S LLM-LANE POSTURE, exactly: webpki trust, system DNS, no pin, no observation, no
    /// client identity, boot-env proxy tunnel, h2 keep-alive 30s/10s + adaptive window, TCP
    /// keepalive 60s — the values the parity ledger above documents, parameterized only by the
    /// four inputs `UpstreamClientSettings` snapshots (plus the per-shard idle division the
    /// caller already computes).
    pub fn llm_lane(
        idle_per_host: usize,
        pool_idle_timeout_secs: u64,
        http1_only: bool,
        h2_prior_knowledge: bool,
    ) -> Self {
        EngineSpec {
            idle_per_host,
            pool_idle_timeout_secs,
            http1_only,
            h2_prior_knowledge,
            pin: None,
            dns: Dns::System,
            observe_spki: false,
        }
    }
}

// ── ESTABLISHMENT TOPOLOGY, published once by the composition root ──────────────────────────────
// The connect gate (tunnel module below) sizes each shard's establishment share as a constant
// GLOBAL budget divided by the number of client shards the process runs — one gate per built
// client, one client per data worker on the LLM lanes. That worker count is a core/binary
// topology fact and substrate cannot name core (the dependency points the other way), so the
// fact is PUBLISHED down: core's `set_data_workers` forwards the same number here in the same
// boot act, one composition-root call with two subscribers. Unpublished honestly means ONE
// runtime (tools, tests, embedded uses) — the exact rule core's own `data_workers_or_one`
// applied — because a consumer sizing a PACING budget must never guess N cores where one
// runtime exists.

/// The published establishment-shard count. Set once, before anything builds; immutable.
static ESTABLISHMENT_SHARDS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Publish the shard count. First call wins; later calls are ignored (boot runs once).
pub fn set_establishment_shards(n: usize) {
    let _ = ESTABLISHMENT_SHARDS.set(n.max(1));
}

/// The published count, 1 when the composition root has not published one.
fn establishment_shards_or_one() -> usize {
    ESTABLISHMENT_SHARDS.get().copied().unwrap_or(1)
}

/// Build ONE engine client per the spec's posture. Fallible by SIGNATURE for the postures the
/// migration adds (a private extra root or client identity that does not parse must fail the
/// build loudly); the LLM-lane posture has no failing arm, which is what lets core's infallible
/// `build_egress_client` shim stand over this without a panic path in practice.
pub fn build_client(spec: &EngineSpec) -> Result<EngineClient, String> {
    // THE RESOLVER IS THE PIN (see `resolve`): a pinned spec installs the one-name table and the
    // `dns` posture is structurally unreachable — not "unused", absent from the connector.
    let resolver = match (&spec.pin, &spec.dns) {
        (Some(pin), _) => EgressResolver::Pinned {
            host: Arc::clone(&pin.host),
            addr: pin.addr,
        },
        (None, Dns::System) => EgressResolver::system(),
        (None, Dns::Custom(names)) => EgressResolver::Custom(Arc::clone(names)),
    };
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    // The mock/bench upstreams are plain http; TLS wraps only https targets (below).
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(Some(Duration::from_secs(60)));
    http.set_nodelay(true);

    // rustls client config over the compiled-in webpki roots — the same trust anchors reqwest's
    // rustls-tls used. ALPN is set by the connector builder below (`enable_http1` pins h1;
    // `enable_all_versions` offers h2 then h1), which asserts the config arrives ALPN-empty.
    // The tunnel wrapper sits BETWEEN TCP and TLS: with no proxy env (every known deployment) it
    // delegates to the plain connector untouched; with one, it CONNECTs through the proxy the
    // target's SCHEME selects and TLS then handshakes over the tunnel with the real target's SNI
    // — reqwest's exact layering and scoping.
    let http = tunnel::TunnelConnector::new(http, tunnel::installed_proxy());

    let tls = rustls_client_config();
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls);
    let https = if spec.http1_only {
        builder.https_or_http().enable_http1().wrap_connector(http)
    } else {
        builder
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http)
    };
    // One wall-clock bound over the WHOLE connect — TCP + tunnel + TLS handshake (see
    // `deadline`; reqwest's connect_timeout parity on the pinned postures, a strict tightening
    // of the latent black-hole-TLS gap on the LLM lanes). Then the peer-identity observation,
    // a per-connect branch that is pass-through when `observe_spki` is off.
    let https: EngineConnector = SpkiObserve::new(
        ConnectDeadline::new(https, super::EGRESS_CONNECT_TIMEOUT),
        spec.observe_spki,
    );

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
    Ok(client.build(https))
}

/// The rustls client config: webpki roots, ALPN left to the connector builder. The crypto
/// provider is named EXPLICITLY (`ring` — the provider reqwest's `rustls-tls` used, so the
/// cipher-suite story is unchanged): the bare `builder()` auto-detects the process provider and
/// PANICS AT FIRST USE when more than one provider crate is in the binary's graph — which is
/// exactly the composed busbar binary, and a boot-time panic CI caught. Explicit therefore, never
/// ambient.
fn rustls_client_config() -> rustls::ClientConfig {
    // ONE root store and ONE crypto provider, shared by refcount across every client shard
    // (`ClientConfig` holds both behind `Arc`s, and both builder seams take `Into<Arc<_>>`).
    // This builder runs ONCE PER DATA WORKER (one client shard each, `appbuild`'s `make_one`),
    // and `TLS_SERVER_ROOTS.to_vec()` materializes the ~150-anchor trust store on the heap —
    // N private copies of identical, immutable data was pure idle RSS scaling with core count.
    // Same anchors, same provider, same cipher-suite story; only the duplication is gone.
    static ROOTS: std::sync::OnceLock<std::sync::Arc<rustls::RootCertStore>> =
        std::sync::OnceLock::new();
    static PROVIDER: std::sync::OnceLock<std::sync::Arc<rustls::crypto::CryptoProvider>> =
        std::sync::OnceLock::new();
    let roots = ROOTS
        .get_or_init(|| {
            std::sync::Arc::new(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        })
        .clone();
    let provider = PROVIDER
        .get_or_init(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .clone();
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Assemble one egress request from the boot-precomputed parts: the lane's `http::Uri` and the
/// caller-built header map, body as one owned buffer. No builder, no validation re-runs — every
/// component was validated when it was made.
pub fn egress_request(
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

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod engine_tests;

/// The pin-as-resolver contract: one-name table, doctrine-text byte-parity with the reqwest
/// resolver, and the client-level zero-lookup proof through the real `build_client` wiring.
#[cfg(test)]
#[path = "tests/resolver_tests.rs"]
mod resolver_tests;

/// The R1 extras-propagation spike (pooled reuse carries `PeerSpki` on every response), SNI
/// preservation under the pin with its wrong-name refusing twin, the R2 URI-port-wins proof, and
/// the whole-connect deadline against a black-holing TLS peer.
#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod observe_tests;

pub use tunnel::install_proxy_tunnel_if_configured;

/// The owned CONNECT tunnel for the proxy-env parity case (owner-ruled: full tunnel, not the
/// boot-refusal interim). Constructed ONLY when a proxy env var is present at boot; the direct
/// path pays one `None` check per CONNECT and nothing per request.
mod tunnel {
    use std::net::IpAddr;
    use std::sync::{Arc, OnceLock};

    /// One boot-resolved proxy endpoint: where to TCP-connect and what to put in
    /// `Proxy-Authorization`. Parsed ONCE at boot; shared by refcount from the per-scheme slots
    /// of [`ProxyConfig`].
    #[cfg_attr(test, derive(Debug))] // tests unwrap_err() around it; production never prints it
    pub struct ProxySpec {
        /// Proxy endpoint as the plain `host:port` CONNECT dial string.
        host: String,
        port: u16,
        /// `Proxy-Authorization: Basic <b64(user:pass)>` prebuilt from the proxy URL's userinfo.
        auth: Option<String>,
    }

    /// The boot-resolved proxy DECISION, reqwest-scoped: https:// targets use the `https` slot
    /// (`HTTPS_PROXY`, `ALL_PROXY` fallback), everything else uses the `http` slot (`HTTP_PROXY`,
    /// `ALL_PROXY` fallback), and `NO_PROXY` excludes hosts from both. This mirrors hyper-util's
    /// `client::proxy::matcher::Builder::build` (`http: http.or(all)`, `https: https.or(all)`)
    /// and `Matcher::intercept` (NO_PROXY first, then the slot picked by `dst.scheme_str()`) —
    /// the machinery reqwest 0.12 delegates its implicit env behavior to.
    #[cfg_attr(test, derive(Debug))]
    pub struct ProxyConfig {
        https: Option<Arc<ProxySpec>>,
        http: Option<Arc<ProxySpec>>,
        no_proxy: NoProxy,
    }

    impl ProxyConfig {
        /// The per-CONNECT decision: `None` → direct (NO_PROXY-excluded, or no proxy configured
        /// for the target's scheme), `Some` → tunnel through that proxy.
        fn select(&self, dst_is_https: bool, target_host: &str) -> Option<Arc<ProxySpec>> {
            if self.no_proxy.matches(target_host) {
                return None;
            }
            if dst_is_https {
                self.https.clone()
            } else {
                self.http.clone()
            }
        }
    }

    /// Parsed `NO_PROXY` entries, reqwest's full rule set (hyper-util `matcher::NoProxy`, which
    /// documents itself as curl's rules): `*` matches everything; an IP literal matches exactly;
    /// a CIDR block (`10.0.0.0/8`, `fd00::/8`) matches by containment; anything else is a domain
    /// matched exactly or as a `.`-boundary suffix. Like reqwest, an IP-literal target host is
    /// checked ONLY against the IP/CIDR entries and a domain host ONLY against the domain
    /// entries.
    #[cfg_attr(test, derive(Debug))]
    struct NoProxy {
        entries: Vec<NoProxyEntry>,
    }

    #[cfg_attr(test, derive(Debug))]
    enum NoProxyEntry {
        MatchAll,
        /// Lowercased, leading dot stripped (`.google.com` ≡ `google.com`, per curl/reqwest).
        Domain(String),
        Ip(IpAddr),
        /// Network address + prefix length, validated ≤32 (v4) / ≤128 (v6) at parse.
        Cidr(IpAddr, u8),
    }

    impl NoProxy {
        /// Comma-separated entries, whitespace trimmed, empties dropped. Entry classification
        /// mirrors reqwest: try CIDR, then IP literal, then fall back to domain — a malformed
        /// CIDR (`10.0.0.0/40`) therefore degrades to a domain entry that never matches, exactly
        /// as `ipnet` parse failure does under reqwest, rather than aborting boot.
        fn parse(raw: &str) -> Self {
            let mut entries = Vec::new();
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if part == "*" {
                    entries.push(NoProxyEntry::MatchAll);
                    continue;
                }
                if let Some((addr, len)) = part.split_once('/') {
                    if let (Ok(addr), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u8>()) {
                        let max = if addr.is_ipv4() { 32 } else { 128 };
                        if len <= max {
                            entries.push(NoProxyEntry::Cidr(addr, len));
                            continue;
                        }
                    }
                } else if let Ok(addr) = part.parse::<IpAddr>() {
                    entries.push(NoProxyEntry::Ip(addr));
                    continue;
                }
                entries.push(NoProxyEntry::Domain(
                    part.trim_start_matches('.').to_ascii_lowercase(),
                ));
            }
            NoProxy { entries }
        }

        fn matches(&self, target_host: &str) -> bool {
            // `http::Uri::host()` may carry an IPv6 literal in brackets; strip them before the
            // IpAddr parse, as hyper-util's NoProxy::contains does.
            let bare = target_host.trim_start_matches('[').trim_end_matches(']');
            let ip: Option<IpAddr> = bare.parse().ok();
            let host = target_host.to_ascii_lowercase();
            self.entries.iter().any(|entry| match entry {
                NoProxyEntry::MatchAll => true,
                NoProxyEntry::Ip(a) => ip == Some(*a),
                NoProxyEntry::Cidr(net, len) => ip.is_some_and(|h| cidr_contains(net, *len, &h)),
                NoProxyEntry::Domain(d) => {
                    ip.is_none()
                        && (host == *d
                            || (host.len() > d.len()
                                && host.ends_with(d.as_str())
                                && host.as_bytes()[host.len() - d.len() - 1] == b'.'))
                }
            })
        }
    }

    /// CIDR containment by prefix-length bit compare over octets — the ~10 lines that make an
    /// `ipnet` dependency unnecessary. Families never cross: a v4 block does not match a v6
    /// address and vice versa, INCLUDING v6-mapped forms (`10.0.0.0/8` does NOT match
    /// `::ffff:10.0.0.1` — it is a v6 address), matching `ipnet`/reqwest, which do not
    /// special-case mapped addresses either.
    fn cidr_contains(net: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
        match (net, addr) {
            (IpAddr::V4(n), IpAddr::V4(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
            (IpAddr::V6(n), IpAddr::V6(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
            _ => false,
        }
    }

    /// The first `prefix` bits of `net` and `addr` are equal. `prefix` is pre-validated against
    /// the address width; `/0` matches everything (whole bytes to compare: none, remainder: 0).
    fn octets_prefix_eq(net: &[u8], addr: &[u8], prefix: u8) -> bool {
        let whole = usize::from(prefix / 8);
        let rem = prefix % 8;
        if net[..whole] != addr[..whole] {
            return false;
        }
        if rem == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        (net[whole] & mask) == (addr[whole] & mask)
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
        Ok(ProxySpec { host, port, auth })
    }

    /// The raw proxy env, read once — a plain value bag so precedence resolution
    /// ([`resolve_config`]) is a pure function tests exercise WITHOUT mutating process env
    /// (parallel tests race on env mutation).
    #[derive(Default)]
    pub(super) struct ProxyEnvValues {
        pub(super) https: Option<String>,
        pub(super) http: Option<String>,
        pub(super) all: Option<String>,
        pub(super) no: Option<String>,
    }

    impl ProxyEnvValues {
        /// Uppercase read before lowercase, empty values treated as unset — hyper-util
        /// `matcher::Builder::from_env`'s `get_first_env(&["HTTPS_PROXY", "https_proxy"])`
        /// ordering (empty parses to nothing there; skipping it here is the same outcome).
        pub(super) fn from_process_env() -> Self {
            fn first(keys: [&str; 2]) -> Option<String> {
                keys.iter()
                    .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            }
            ProxyEnvValues {
                https: first(["HTTPS_PROXY", "https_proxy"]),
                // Read unconditionally — hyper-util's matcher additionally skips uppercase
                // `HTTP_PROXY` under CGI (`REQUEST_METHOD` set; the httpoxy guard). busbar is a
                // server binary, never a CGI child, so the guard's precondition cannot hold and
                // the unconditional read is behavior-identical where this process runs.
                http: first(["HTTP_PROXY", "http_proxy"]),
                all: first(["ALL_PROXY", "all_proxy"]),
                no: first(["NO_PROXY", "no_proxy"]),
            }
        }
    }

    /// Resolve the value bag into the per-scheme slots, reqwest's precedence: scheme-specific
    /// var first, `ALL_PROXY` as the fallback for BOTH slots (hyper-util `Builder::build`:
    /// `http: http.or(all)`, `https: https.or(all)`). No proxy var at all → `None`, the direct
    /// arm. Any PRESENT value that does not parse is a hard error — reqwest silently ignored
    /// garbage and fell through, but silently egressing direct past a configured proxy is the
    /// dangerous direction, so busbar refuses to boot instead (documented deviation).
    pub(super) fn resolve_config(env: &ProxyEnvValues) -> Result<Option<Arc<ProxyConfig>>, String> {
        let all = env
            .all
            .as_deref()
            .map(parse_proxy)
            .transpose()?
            .map(Arc::new);
        let scheme_slot = |v: &Option<String>| -> Result<Option<Arc<ProxySpec>>, String> {
            Ok(match v.as_deref() {
                Some(v) => Some(Arc::new(parse_proxy(v)?)),
                None => all.clone(),
            })
        };
        let https = scheme_slot(&env.https)?;
        let http = scheme_slot(&env.http)?;
        if https.is_none() && http.is_none() {
            return Ok(None);
        }
        Ok(Some(Arc::new(ProxyConfig {
            https,
            http,
            no_proxy: NoProxy::parse(env.no.as_deref().unwrap_or("")),
        })))
    }

    /// The boot-installed proxy decision, `None` in every deployment without a proxy env.
    /// `OnceLock` so config applies rebuild clients against the SAME boot decision — proxy env
    /// is process environment, immutable for the process lifetime, exactly reqwest's read-once
    /// behavior.
    static INSTALLED: OnceLock<Option<Arc<ProxyConfig>>> = OnceLock::new();

    /// Resolve the proxy env at boot: absent → direct (the common arm), present-and-valid →
    /// install the scheme-scoped config for every client build, present-and-garbage → refuse to
    /// start (fail-loud beats silently egressing direct past a configured proxy).
    pub fn install_proxy_tunnel_if_configured() -> Result<(), String> {
        let config = resolve_config(&ProxyEnvValues::from_process_env())?;
        let _ = INSTALLED.set(config);
        Ok(())
    }

    /// What the client builder wires in: the boot decision, or `None` for a build that runs
    /// before/without `install_proxy_tunnel_if_configured` (tests, tools) — direct, like reqwest
    /// built without proxy env.
    pub fn installed_proxy() -> Option<Arc<ProxyConfig>> {
        INSTALLED.get().cloned().flatten()
    }

    /// The connector hyper-rustls wraps: plain TCP in the direct arm, TCP-to-proxy + CONNECT in
    /// the tunneled arm. Sits BELOW TLS, so an https target's TLS handshake (with the target's
    /// SNI, against the target's cert) runs over the established tunnel — the proxy sees only
    /// `CONNECT host:port`, never a decrypted byte.
    #[derive(Clone)]
    pub struct TunnelConnector {
        inner: hyper_util::client::legacy::connect::HttpConnector<super::EgressResolver>,
        config: Option<Arc<ProxyConfig>>,
        /// Per-shard connect pacing — see [`ConnectGate`]. Shared by clones of this connector
        /// (hyper clones the service per connect), NOT across shards: each worker paces its own
        /// establishment so no cross-worker lock ever appears on the connect path.
        gate: Arc<ConnectGate>,
    }

    impl TunnelConnector {
        pub fn new(
            inner: hyper_util::client::legacy::connect::HttpConnector<super::EgressResolver>,
            config: Option<Arc<ProxyConfig>>,
        ) -> Self {
            Self {
                inner,
                config,
                gate: Arc::new(ConnectGate::new()),
            }
        }
    }

    /// THE CONNECT GATE (overload-cliff fix, part 1) — bounds concurrent connection
    /// ESTABLISHMENT per destination authority, per client shard. The bench rig proved the
    /// mechanism it closes: under a concurrency step the pool's checkout race opens ~1.3–1.6
    /// upstream connections per client connection with no coalescing, ~10k simultaneous SYNs
    /// overrun the provider's accept queue (a typical listen backlog is 128), the 1s SYN
    /// retransmit pushes first-wave latency past client deadlines, aborts destroy in-flight
    /// connections, and the reconnect wave re-synchronizes — a self-sustaining storm that
    /// collapsed throughput 4x at 10k+ concurrent clients while the CPUs sat half idle. The
    /// gate makes establishment PACED AND FAIR (FIFO semaphore per authority): 16 in-flight
    /// connects per shard × the worker count keeps the global burst under a backlog-128
    /// provider's accept capacity, waves cannot synchronize, and steady state converges.
    /// Established, pooled connections never touch this — it prices only the storm. The
    /// permit ends when the SOCKET exists (post-dial, post-CONNECT on the tunneled arm); TLS
    /// handshakes ride ABOVE this layer un-permitted — the accept queue (where the measured
    /// collapse lived) is protected, provider-side handshake CPU is rate-shaped but not
    /// concurrency-capped.
    ///
    /// The GLOBAL establishment budget per authority — a constant, not a knob — sized to half
    /// the smallest commodity accept backlog (128) so a whole-process burst fits a
    /// backlog-128 provider with headroom. Each shard's share is this divided by the worker
    /// count (floor 1), computed once per gate slot: 4 workers → 16/shard (the bench-proven
    /// shape), 64 workers → 1/shard (64 global), 128 workers → 1/shard (128 global — the one
    /// arithmetic overrun, at the topology cap, bounded to exactly the backlog rather than
    /// 16x it). The re-audit caught the first cut of this constant (a flat 16/shard) silently
    /// scaling its guarantee with N — this form keeps the burst bound worker-count-invariant,
    /// the campaign's own "1-core box behaves like a 16-core box" bar. Permit wait time is
    /// not unbounded — every send runs under the attempt's one deadline envelope, so a
    /// connect starved past the budget classifies as the transport timeout it is and fails
    /// over.
    const CONNECTS_PER_AUTHORITY_GLOBAL: usize = 64;

    /// This shard's share of the global budget. Reads the composition root's published
    /// establishment-shard count (1 when unset — tools/tests), never a per-request read:
    /// computed once per gate slot at first CONNECT to an authority.
    pub(super) fn connects_per_shard() -> usize {
        (CONNECTS_PER_AUTHORITY_GLOBAL / super::establishment_shards_or_one()).max(1)
    }

    /// Per-shard registry of per-authority connect semaphores. Keys are the DIALED authority
    /// (the target for direct connects, the proxy for tunneled ones — the storm lands on
    /// whichever socket is actually dialed). Growth is bounded by the number of distinct
    /// configured authorities; entries are never evicted because that set is config-sized.
    pub(crate) struct ConnectGate {
        slots: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    }

    impl ConnectGate {
        fn new() -> Self {
            Self {
                slots: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// The semaphore for one authority — one lock hop per CONNECT (never per request).
        fn slot(&self, authority: &str) -> Arc<tokio::sync::Semaphore> {
            let mut slots = self.slots.lock().expect("connect-gate lock");
            slots
                .entry(authority.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(connects_per_shard())))
                .clone()
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
            // Scheme-scoped selection (reqwest's `Matcher::intercept`): https targets use the
            // https slot, everything else the http slot; NO_PROXY excludes from both. Direct
            // arm: no config installed, no proxy for this scheme, or the host is excluded.
            let target_host = dst.host().unwrap_or_default().to_string();
            let dst_is_https = dst.scheme_str() == Some("https");
            let proxy = match self
                .config
                .as_ref()
                .and_then(|c| c.select(dst_is_https, &target_host))
            {
                Some(p) => p,
                None => {
                    // Direct arm: gate on the target authority, then dial. The permit spans
                    // establishment only — it drops the moment the socket exists.
                    let authority = format!(
                        "{}:{}",
                        target_host,
                        dst.port_u16()
                            .unwrap_or(if dst_is_https { 443 } else { 80 })
                    );
                    let gate = self.gate.slot(&authority);
                    let fut = tower::Service::call(&mut self.inner, dst);
                    return Box::pin(async move {
                        let _permit = gate
                            .acquire_owned()
                            .await
                            .expect("connect-gate semaphore is never closed");
                        fut.await.map_err(Into::into)
                    });
                }
            };
            // Tunneled arm: dial the PROXY with the same connector (its connect timeout,
            // keepalive and nodelay apply to the proxy socket), then CONNECT to the real target.
            let target_port = dst
                .port_u16()
                .unwrap_or(if dst_is_https { 443 } else { 80 });
            let proxy_uri: http::Uri = match format!("http://{}:{}", proxy.host, proxy.port).parse()
            {
                Ok(u) => u,
                Err(e) => return Box::pin(async move { Err(Box::new(e) as BoxError) }),
            };
            // Tunneled arm: the storm lands on the PROXY socket, so gate on the proxy
            // authority; the permit spans dial + CONNECT handshake (both are establishment).
            let gate = self.gate.slot(&format!("{}:{}", proxy.host, proxy.port));
            let dial = tower::Service::call(&mut self.inner, proxy_uri);
            Box::pin(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .expect("connect-gate semaphore is never closed");
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

    /// A full config whose BOTH slots point at one scripted proxy — what the end-to-end test
    /// wires directly so parallel tests never race an env var or the OnceLock.
    #[cfg(test)]
    pub(super) fn test_config(
        host: &str,
        port: u16,
        auth: Option<String>,
        no_proxy: &str,
    ) -> Arc<ProxyConfig> {
        let spec = Arc::new(ProxySpec {
            host: host.to_string(),
            port,
            auth,
        });
        Arc::new(ProxyConfig {
            https: Some(spec.clone()),
            http: Some(spec),
            no_proxy: NoProxy::parse(no_proxy),
        })
    }

    #[cfg(test)]
    pub(super) use parse_proxy as parse_proxy_for_tests;

    #[cfg(test)]
    pub(super) use connects_per_shard as connects_per_shard_for_tests;

    #[cfg(test)]
    impl ConnectGate {
        pub(super) fn new_for_tests() -> Self {
            Self::new()
        }
        pub(super) fn slot_for_tests(&self, authority: &str) -> Arc<tokio::sync::Semaphore> {
            self.slot(authority)
        }
    }
    #[cfg(test)]
    pub(super) use resolve_config as resolve_config_for_tests;
    #[cfg(test)]
    pub(super) use ProxyEnvValues as ProxyEnvValuesForTests;

    /// The per-CONNECT decision as tests see it: the selected proxy's `host:port`, or `None` for
    /// the direct arm.
    #[cfg(test)]
    pub(super) fn select_for_tests(
        config: &Arc<ProxyConfig>,
        dst_is_https: bool,
        target_host: &str,
    ) -> Option<String> {
        config
            .select(dst_is_https, target_host)
            .map(|p| format!("{}:{}", p.host, p.port))
    }

    #[cfg(test)]
    pub(super) fn no_proxy_matches_for_tests(entries: &str, target_host: &str) -> bool {
        NoProxy::parse(entries).matches(target_host)
    }
}
