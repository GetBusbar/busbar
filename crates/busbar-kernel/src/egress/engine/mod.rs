// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS ENGINE — the OWNED connection pool with dial coalescing (`pool.rs`/`client.rs`)
//! over the connector's TLS wrap: the ONE owned outbound HTTP stack (owner-ruled), relocated
//! here from `busbar-core::proxy::egress_client` so every plane builds its clients from one
//! neutral home; every caller names it at `crate::egress::engine`. The pool was
//! `hyper_util::client::legacy::Client` until the owned-pool step: hyper (the protocol library)
//! and the whole connector stack stay; only the legacy client's pool — whose checkout raced a
//! fresh dial per request and dropped the losers post-SYN — went, replaced by the coalescing
//! invariant in `pool.rs`.
//!
//! Replaces reqwest as the client every plane's egress builds through. What it buys per request:
//! the send consumes a caller's boot-precomputed `http::Uri` directly (reqwest re-parsed its
//! `Url` to a `Uri` through the full WHATWG parser at EVERY send), the request is hand-assembled
//! from the prebuilt header map (no `RequestBuilder` machinery, no redirect-policy hook, no
//! wrapper allocations), and the response is consumed as bare `http` parts + `Incoming` body.
//!
//! PARITY LEDGER — every facility the reqwest builder provided, re-provided or made structural
//! (see `appbuild.rs`'s old builder comments, preserved there):
//!   * pooling: `pool_max_idle_per_host` / `pool_idle_timeout` / Tokio pool timer — same knobs,
//!     same per-shard division; warm-pool reuse on config apply keyed by the plane's own
//!     `ClientSettingsInput` snapshot (the core `UpstreamClientSettings` it replaced is deleted).
//!   * TLS trust: rustls + compiled-in webpki (Mozilla) roots, run by the connector's TLS wrap
//!     (`crate::secure`) — byte-identical trust story to reqwest's `rustls-tls` feature. ALPN offers `h2,http/1.1` by default; `http1_only` pins
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
//!   * proxy env: re-provided as an owned CONNECT tunnel. The environment itself is read in ONE
//!     place, the connector (`busbar_core_connector::proxy`, status row 130 E5a), into the
//!     shared choice the composition root installs here ([`install_proxy`]); this engine reads
//!     no environment. When the choice names a proxy for the target, the connect goes to the
//!     proxy + `CONNECT host:port` + (for a secured target) TLS over the tunnel, with the
//!     choice's `Proxy-Authorization`. Deployments with no proxy — every known one — take the
//!     direct arm, a `None` check per CONNECT (not per request; the pool reuses tunneled sockets
//!     like any other).
//!   * decompression: none before (no gzip/brotli features), none now.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;

// THE ENGINE'S LAYERS, each its own file: the resolver (where the pin lives), the peer-identity
// observation, the whole-connect deadline — and, since the pool became OWNED, the client surface
// (`client`: request preparation, send/retry, return path) over the checkout/dial machinery
// (`pool`: the sharded authority map, the coalescing invariant, the on-demand reaper). The
// CONNECT tunnel stays in this file's `tunnel` module, where it moved from core verbatim.
mod client;
pub mod deadline;
pub mod https;
pub mod observe;
mod pool;
pub mod resolve;
pub mod tls;

#[cfg(any(test, feature = "test-support"))]
pub use crate::egress::fixtures::with_scoped_dial;
pub use deadline::ConnectDeadline;
pub use observe::{peer_key_pin, KeyPinObserve, ObservedIo, PeerKeyPin};
pub use resolve::{EgressResolver, ResolveNames};
pub use tls::{ClientIdentity, Trust};

/// The connector stack, bottom-up: TCP through the pin-aware resolver (+ boot-detected CONNECT
/// tunnel when a proxy env is set) + the connector's TLS wrap ([`https`]), the whole connect under
/// one wall-clock deadline,
/// with the peer identity observed on the way out. ONE concrete type for every posture — the
/// per-posture differences are VALUES inside the layers, never per-request branches.
pub type EngineConnector =
    KeyPinObserve<ConnectDeadline<https::HttpsConnector<tunnel::TunnelConnector>>>;

/// The pooled egress client — the OWNED pool with dial coalescing (`client.rs`/`pool.rs`),
/// behind the same `request()` surface the `hyper_util::client::legacy::Client` alias had.
/// `Full<Bytes>`: every engine egress body is one owned buffer.
pub use client::{ConnReturned, EngineClient};

/// The error type `EngineClient::request` yields — named so a consumer's transport-error
/// classification arms read as prose. Owned (`pool::EngineError`): carries its cause chain as
/// error OBJECTS (`source()` intact end-to-end) so core's timeout downcast walk and substrate's
/// `is_connect()` split both keep working byte-identically.
pub use pool::EngineError;

/// The engine's posture, one value per client build. Composed ONLY through the blessed
/// constructors ([`EngineSpec::pooled_webpki`] today; the pinned-plane posture joins it as the
/// migration proceeds), so no call site ever assembles a posture by hand and "no new knobs" stays
/// structural rather than reviewed.
pub struct EngineSpec {
    pub idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub http1_only: bool,
    pub h2_prior_knowledge: bool,
    /// Destination pinning. `None` = the pooled posture (destinations are operator config, judged
    /// at every dial by the destination guard, `judge`). `Some` makes DNS structural: the resolver
    /// becomes the pin itself ([`EgressResolver::Pinned`]) and `dns` and `judge` below are never
    /// consulted.
    pub pin: Option<PinnedDest>,
    /// DNS when unpinned.
    pub dns: Dns,
    /// The destination guard every address `dns` answers with is judged by when unpinned: `None`
    /// = the guard behind the egress-trust capability a test binary handed in, read at each dial
    /// (none in a shipped build: every answer refused, fail closed).
    pub judge: Option<Arc<dyn crate::host_services::DestJudge>>,
    /// Peer-certificate observation for SPKI pinning ([`observe`]). Off on the pooled posture (no
    /// walk, no hash per connect); on for every pinned posture.
    pub observe_key_pin: bool,
    /// Trust source ([`tls::Trust`]): the compiled-in webpki roots, optionally joined by
    /// operator-registered extras.
    pub trust: Trust,
    /// Busbar's own end of the handshake, when a peer asks for one.
    pub identity: Option<ClientIdentity>,
    /// CONNECT-tunnel posture. [`ProxyPosture::Direct`] on every pinned posture: a CONNECT proxy
    /// performs the target connect ITSELF, so a proxied pinned hop cannot connect to the judged
    /// address — the pin doctrine and proxy delegation are mutually exclusive, and the reqwest
    /// stack's silent proxy-env bypass of the pin was a latent guard bypass, not behaviour to
    /// preserve (the design's second sanctioned deviation; no known deployment sets a proxy env).
    pub proxy: ProxyPosture,
    /// h2 keep-alive interval/timeout + adaptive window: `Some` on the pooled posture, `None` on
    /// the pinned postures (reqwest set none — parity).
    pub h2_keepalive: Option<H2KeepAlive>,
    /// The TLS wrap the https arm is secured by: `None` (every blessed posture) = the wrap of the
    /// egress-trust capability a test binary handed in (`crate::secure::layer`; none in a shipped
    /// build). A test hands its own TLS double here, as it hands its own names to `dns` and its own
    /// guard to `judge`.
    pub tls: Option<Arc<dyn crate::secure::SecureLayer>>,
    /// TCP keepalive: pooled `Some(60s)`; pinned `None` (reqwest default — parity). nodelay is
    /// unconditional (both stacks set it).
    pub tcp_keepalive: Option<Duration>,
}

/// CONNECT-tunnel posture (see [`EngineSpec::proxy`]).
pub enum ProxyPosture {
    /// Honor the proxy choice installed at boot ([`install_proxy`], the connector's parse of the
    /// proxy environment) — the pooled posture's reqwest-parity behavior.
    BootEnv,
    /// Never tunnel: the tunnel arm is structurally absent (`TunnelConnector::new(http, None)`).
    Direct,
}

/// The h2 keep-alive setting the pooled posture carries (reqwest's pinned clients set none).
#[derive(Clone, Copy)]
pub struct H2KeepAlive {
    pub interval: Duration,
    pub timeout: Duration,
    pub adaptive_window: bool,
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
    /// THE POOLED-WEBPKI EGRESS POSTURE (system trust + judged system DNS + boot-env tunnel + pooled reuse): webpki trust, system DNS judged by the destination guard, no pin, no observation, no
    /// client identity, boot-env proxy tunnel, h2 keep-alive 30s/10s + adaptive window, TCP
    /// keepalive 60s — the values the parity ledger above documents, parameterized only by the
    /// four inputs the plane's `ClientSettingsInput` snapshots (plus the per-shard idle division the
    /// caller already computes).
    pub fn pooled_webpki(
        idle_per_host: usize,
        pool_idle_timeout_secs: u64,
        http1_only: bool,
        h2_prior_knowledge: bool,
    ) -> Self {
        let (judge, names) = resolve::pooled_dial();
        EngineSpec {
            idle_per_host,
            pool_idle_timeout_secs,
            http1_only,
            h2_prior_knowledge,
            pin: None,
            dns: names.map_or(Dns::System, Dns::Custom),
            judge,
            observe_key_pin: false,
            trust: Trust::Webpki,
            identity: None,
            proxy: ProxyPosture::BootEnv,
            h2_keepalive: Some(H2KeepAlive {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(10),
                adaptive_window: true,
            }),
            tls: None,
            tcp_keepalive: Some(Duration::from_secs(60)),
        }
    }

    /// THE PINNED-PLANE POSTURE, reqwest-parity value for value with the retiring
    /// `build_pinned_client`: extras join the webpki store, the pin is the resolver, the peer
    /// identity is observed, the tunnel arm is structurally absent (see [`EngineSpec::proxy`]),
    /// ALPN offers h2+h1 (reqwest with its `http2` feature — parity), no h2 keep-alive, no TCP
    /// keepalive, the pool holds idle connections for [`super::EGRESS_POOL_IDLE_TIMEOUT`] under
    /// hyper's default per-host cap. Redirects were never followed by either stack; hyper makes
    /// that structural.
    pub fn pinned(
        host: Arc<str>,
        addr: IpAddr,
        identity: Option<ClientIdentity>,
        extra_roots: Vec<Vec<u8>>,
    ) -> Self {
        EngineSpec {
            idle_per_host: usize::MAX,
            pool_idle_timeout_secs: super::EGRESS_POOL_IDLE_TIMEOUT.as_secs(),
            http1_only: false,
            h2_prior_knowledge: false,
            pin: Some(PinnedDest { host, addr }),
            dns: Dns::System,
            judge: None,
            observe_key_pin: true,
            trust: Trust::WebpkiPlus(extra_roots),
            identity,
            proxy: ProxyPosture::Direct,
            h2_keepalive: None,
            tls: None,
            tcp_keepalive: None,
        }
    }
}

// ── ESTABLISHMENT TOPOLOGY, published once by the composition root ──────────────────────────────
// The connect gate (tunnel module below) sizes each shard's establishment share as a constant
// GLOBAL budget divided by the number of client shards the process runs — one gate per built
// client, one client per data worker under the pooled posture. That worker count is a core/binary
// topology fact and substrate cannot name core (the dependency points the other way), so the
// fact is PUBLISHED down: core's `set_data_workers` forwards the same number here in the same
// boot act, one composition-root call with two subscribers. Unpublished honestly means ONE
// runtime (tools, tests, embedded uses): `establishment_shards_or_one` answers 1 until a count
// is published, and the one fallback deriver is core's `UpstreamClients::shard_count`
// (`busbar-core/src/state.rs`), whose unpublished arm computes the machine-derived shard count
// and publishes it here itself — because a consumer sizing a PACING budget must never guess N
// cores where one runtime exists.

/// The published establishment-shard count. Set once, before anything builds; immutable.
static ESTABLISHMENT_SHARDS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Publish the shard count. First call wins; later calls are ignored (boot runs once).
pub fn set_establishment_shards(n: usize) {
    let _ = ESTABLISHMENT_SHARDS.set(n.max(1));
}

/// The published count, 1 when the composition root has not published one. `pub` (was private)
/// for exactly one reader class: the cross-crate equality pin that asserts core's
/// `shard_count()` fallback publishes the same value this returns — one derivation function,
/// no cross-crate duplicate of the formula.
pub fn establishment_shards_or_one() -> usize {
    ESTABLISHMENT_SHARDS.get().copied().unwrap_or(1)
}

/// The per-client dial bound, THE single source both the owned pool's coalescing
/// invariant and the ConnectGate's permit count read (bound == permits is what composes the two
/// into one mechanism). Worker-sharded clients (the pooled posture) take the per-shard share of the
/// global establishment budget; a pinned single-client posture (`EngineSpec::pinned`) IS its
/// authority's whole budget — one client, not N shards, so the divide-by-N would leave N−1
/// shares permanently unused. The 64-per-authority-process-wide envelope holds in both cases.
pub(crate) fn dial_bound_for(pin: Option<&PinnedDest>) -> usize {
    match pin {
        // The presence of a pin is read here as a TOPOLOGY fact (a pinned spec builds ONE
        // client per destination, so that client is its authority's whole establishment
        // budget) — never as a trust decision; may-this-serve stays with
        // `crate::trust::Approval::serves`.
        Some(_) => tunnel::CONNECTS_PER_AUTHORITY_GLOBAL,
        None => tunnel::connects_per_shard(),
    }
}

/// The ALPN offers of 1.5.5's client: `http/1.1` alone under `http1_only`, else `h2` then `http/1.1`.
const OFFER_H1: &[&[u8]] = &[b"http/1.1"];
const OFFER_H2_H1: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Build ONE engine client per the spec's posture. Fallible by SIGNATURE for the postures the
/// migration adds (a private extra root or client identity that does not parse must fail the
/// build loudly); the pooled posture has no failing arm, which is what lets core's infallible
/// `build_egress_client` shim stand over this without a panic path in practice.
pub fn build_client(spec: &EngineSpec) -> Result<EngineClient, String> {
    // THE RESOLVER IS THE PIN (see `resolve`): a pinned spec installs the one-name table and the
    // `dns` posture is structurally unreachable — not "unused", absent from the connector. An
    // unpinned spec judges every answer through the destination guard before the connector sees it.
    let (resolver, posture) = match (&spec.pin, &spec.dns) {
        (Some(pin), _) => (
            EgressResolver::Pinned {
                host: Arc::clone(&pin.host),
                addr: pin.addr,
            },
            tunnel::DialPosture::Pinned { addr: pin.addr },
        ),
        (None, dns) => {
            let names = match dns {
                Dns::System => EgressResolver::system(),
                Dns::Custom(names) => EgressResolver::Custom(Arc::clone(names)),
            };
            (
                EgressResolver::Judged {
                    names: Box::new(names.clone()),
                    judge: spec.judge.clone(),
                },
                tunnel::DialPosture::Judged {
                    judge: spec.judge.clone(),
                    names,
                },
            )
        }
    };
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    // The mock/bench upstreams are plain http; TLS wraps only https targets (below).
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(spec.tcp_keepalive);
    http.set_nodelay(true);

    // The tunnel wrapper sits BETWEEN TCP and TLS: with no proxy env (every known deployment) it
    // delegates to the plain connector untouched; with one, it CONNECTs through the proxy the
    // target's SCHEME selects and TLS then handshakes over the tunnel with the real target's SNI
    // — reqwest's exact layering and scoping.
    let proxy = match spec.proxy {
        ProxyPosture::BootEnv => tunnel::installed_proxy(),
        // The pinned postures never tunnel: a CONNECT proxy would perform the target connect
        // itself, bypassing the judged address — the tunnel arm is structurally absent.
        ProxyPosture::Direct => None,
    };
    // The per-client bound, resolved ONCE and handed to BOTH consumers: the gate's permits and
    // the pool's coalescing bound — one number, one derivation, no drift.
    let dial_bound = dial_bound_for(spec.pin.as_ref());
    let http = tunnel::TunnelConnector::new(http, proxy, dial_bound, posture);

    // The client TLS over the compiled-in webpki roots — the same trust anchors reqwest's
    // rustls-tls used — built by the connector's TLS wrap. 1.5.5's hello (reqwest) offered
    // `http/1.1` under http1-only, `h2, http/1.1` otherwise, so the offer is stated here.
    let offer = if spec.http1_only {
        OFFER_H1
    } else {
        OFFER_H2_H1
    };
    let https = https::HttpsConnector::new(http, client_tls(spec, offer)?);
    // One wall-clock bound over the WHOLE connect — TCP + tunnel + TLS handshake (see
    // `deadline`; reqwest's connect_timeout parity on the pinned postures, a strict tightening
    // of the latent black-hole-TLS gap on the pooled posture). Then the peer-identity observation,
    // a per-connect branch that is pass-through when `observe_key_pin` is off.
    let https: EngineConnector = KeyPinObserve::new(
        ConnectDeadline::new(https, super::EGRESS_CONNECT_TIMEOUT),
        spec.observe_key_pin,
    );

    // The OWNED pool over the connector stack: the same knobs the legacy builder took, resolved
    // into the pool's config. h2 keep-alive is the pooled posture's setting (pinned postures set NONE
    // — reqwest parity); the cleartext h2c opt-in forces h2 without ALPN and h1-only wins over
    // it, preserving the old builder's apply-order (the pool reads the pair the same way).
    Ok(EngineClient::assemble(
        https,
        client::PoolConfig {
            idle_cap_per_host: spec.idle_per_host,
            idle_timeout: Duration::from_secs(spec.pool_idle_timeout_secs),
            http1_only: spec.http1_only,
            h2_prior_knowledge: spec.h2_prior_knowledge,
            h2_keepalive: spec.h2_keepalive,
            dial_bound,
        },
    ))
}

/// The client TLS for a spec's trust and identity, with the ALPN offer `alpn`, built by the
/// connector's TLS wrap (`crate::secure`). `None` in a process that installed no wrap: its
/// https dials then fail after the TCP connect, naming the missing install. An extra root the store
/// refuses, or an identity the stack refuses, fails the build loudly.
pub(crate) fn client_tls(
    spec: &EngineSpec,
    alpn: &[&[u8]],
) -> Result<Option<Arc<dyn crate::secure::ClientTls>>, String> {
    let Some(layer) = spec.tls.clone().or_else(crate::secure::layer) else {
        return Ok(None);
    };
    let extra_roots = match &spec.trust {
        Trust::Webpki => None,
        Trust::WebpkiPlus(extras) => Some(extras.as_slice()),
    };
    layer
        .client(&crate::secure::ClientTlsSpec {
            extra_roots,
            identity: spec.identity.as_ref().map(|id| (id.chain(), id.key())),
            alpn,
        })
        .map(Some)
}

/// Assemble one egress request from precomputed parts: method, `http::Uri`, caller-built header
/// map, body as one owned buffer. No builder machinery, no validation re-runs — every component
/// was validated when it was made. The method-parameterized generalization of [`egress_request`]
/// for the plane hops (a card fetch is a GET, a relay a POST, a plugin hop whatever it named).
///
/// ONE reqwest-parity transformation runs here, because these callers take OPERATOR-SPELLED URLs:
/// URL userinfo (`https://user:pass@host/…`) is stripped from the URI and moved to an
/// `Authorization: Basic` header (reqwest has done exactly this since 0.11.10). Left in place,
/// the userinfo never reaches the wire (hyper's request line is origin-form and `Host` derives
/// from the host alone) but it WOULD sit in hyper's per-authority pool key — which hyper traces
/// at debug level, turning an operator's embedded credential into a log leak. An explicitly-set
/// `Authorization` header wins over the URL's.
///
/// No default header is added here: a plane hop goes out with exactly the caller's fields. The
/// four hops that were reqwest requests in 1.5.5 take [`client_request`] instead.
pub fn request(
    method: http::Method,
    uri: http::Uri,
    mut headers: http::HeaderMap,
    body: Bytes,
) -> http::Request<Full<Bytes>> {
    let uri = strip_userinfo_into_basic_auth(uri, &mut headers);
    let mut req = http::Request::new(Full::new(body));
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    *req.headers_mut() = headers;
    req
}

/// [`request`] plus reqwest's client default: `accept: */*` after the caller's fields when the
/// caller names no Accept. Only the four hops that were reqwest requests in 1.5.5 use it: the
/// jwt-bearer and client-credentials token mints, the login token exchange and the plugin fetch.
pub fn client_request(
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: Bytes,
) -> http::Request<Full<Bytes>> {
    // After the userinfo move, as reqwest merged its defaults: `authorization` precedes `accept`.
    let mut req = request(method, uri, headers, body);
    let entry = req.headers_mut().entry(http::header::ACCEPT);
    entry.or_insert(http::HeaderValue::from_static("*/*"));
    req
}

/// The reqwest-parity userinfo move (see [`request`]). A URI without userinfo — every hot-path
/// URI — passes through untouched; a rebuild that fails (an authority that stops parsing without
/// its userinfo cannot really happen: removing bytes cannot invalidate a parsed authority) keeps
/// the original URI rather than inventing a refusal at request-assembly time.
fn strip_userinfo_into_basic_auth(uri: http::Uri, headers: &mut http::HeaderMap) -> http::Uri {
    let Some(authority) = uri.authority() else {
        return uri;
    };
    let Some((userinfo, host_port)) = authority.as_str().rsplit_once('@') else {
        return uri;
    };
    let Ok(bare) = host_port.parse::<http::uri::Authority>() else {
        return uri;
    };
    if !headers.contains_key(http::header::AUTHORIZATION) {
        use base64::Engine as _;
        let creds = if userinfo.contains(':') {
            userinfo.to_string()
        } else {
            // A lone username is an empty password — RFC 7617's shape, reqwest's behaviour.
            format!("{userinfo}:")
        };
        let value = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        );
        if let Ok(value) = http::HeaderValue::from_str(&value) {
            let mut value = value;
            value.set_sensitive(true);
            headers.insert(http::header::AUTHORIZATION, value);
        }
    }
    let mut parts = uri.into_parts();
    parts.authority = Some(bare);
    http::Uri::from_parts(parts).expect("removing userinfo keeps the URI well-formed")
}

/// A PROVIDER BASE URL'S USERINFO, AS 1.5.5 PRESENTED IT (row 74, F25): the `Authorization: Basic`
/// value its `user[:pass]@` spells, held core-side and presented at the egress hop alone.
///
/// TRANSITIONAL: deleted with the legacy lane plane (row 155 C). It serves the legacy in-process lane plane alone; the door path, the one that ships,
/// holds no userinfo bytes in any kernel type: the composition root reads them into a basic
/// credential of the auth kind (`root::userinfo`) and the kernel carries only the binding's handle.
///
/// 1.5.5 built every provider request with reqwest over `{base_url}{path}`, its credential after
/// (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1669-1670`, `proxy/engine/walk.rs:583-584`,
/// `health.rs:313-314`). reqwest 0.12.28's `RequestBuilder::new`
/// (`src/async_impl/request.rs:169-182`) took the URL's userinfo out (`extract_authority`,
/// `:581-605`: percent-decoded, nothing when the user is empty and there is
/// no password) and added it FIRST as `authorization: Basic base64(user:pass)`, sensitive
/// (`src/util.rs:4-25`); the lane's own credential then went in through `.headers(auth)`, whose
/// `replace_headers` (`src/util.rs:50-77`) REPLACED that field when the credential named
/// `authorization` and left it in place otherwise. So: the Basic field rides, first, exactly when
/// the request's own credential names no `authorization`.
///
/// `Debug` prints a marker and the header is sensitive. The legacy lane plane that carries one
/// never reads it: it hands it back to the kernel's hop as an opaque request extension
/// ([`present_url_userinfo`]).
#[derive(Clone)]
pub struct UrlUserinfo(http::HeaderValue);

impl UrlUserinfo {
    /// The Basic value `url`'s authority spells, or `None` when it spells no user and no password.
    /// The authority ends at the first `/`, `?`, `#` or `\`, and the userinfo is everything before
    /// its LAST `@`; the user is what precedes the first `:`, the pass what follows it (an empty
    /// pass is none). Both are percent-decoded as reqwest decoded them: a user that does not decode
    /// to UTF-8 presents nothing, a pass that does not is no pass (`extract_authority`'s two arms).
    #[must_use]
    pub fn of(url: &str) -> Option<Self> {
        use base64::Engine as _;
        use zeroize::Zeroize as _;
        let (_, rest) = url.split_once("://")?;
        let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
        let (spelled, _) = rest[..end].rsplit_once('@')?;
        let (user, pass) = match spelled.split_once(':') {
            Some((user, pass)) => (user, Some(pass).filter(|p| !p.is_empty())),
            None => (spelled, None),
        };
        let mut plain = percent_decoded(user)?;
        // A pass that does not decode is no pass, as reqwest's `password` arm read it.
        let mut pass = pass.and_then(percent_decoded);
        if plain.is_empty() && pass.is_none() {
            return None;
        }
        plain.push(':');
        if let Some(pass) = pass.as_mut() {
            plain.push_str(pass);
            pass.zeroize();
        }
        let mut encoded = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());
        plain.zeroize();
        let value = http::HeaderValue::from_maybe_shared(Bytes::from(format!("Basic {encoded}")));
        encoded.zeroize();
        let mut value = value.ok()?;
        value.set_sensitive(true);
        Some(Self(value))
    }

    /// The field value, for the kernel's own hops.
    pub(crate) fn value(&self) -> &http::HeaderValue {
        &self.0
    }
}

impl std::fmt::Debug for UrlUserinfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UrlUserinfo(<redacted>)")
    }
}

/// `%XX` sequences decoded to bytes, the result read as UTF-8 (`None` when it is not). A `%` that
/// opens no two-digit hex escape is kept as written, as the percent-decoder reqwest used kept it.
fn percent_decoded(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&h), Some(&l)) if hex(h).is_some() && hex(l).is_some() => {
                let (h, l) = (hex(h).unwrap_or(0), hex(l).unwrap_or(0));
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// TRANSITIONAL: deleted with the legacy lane plane (row 155 C).
///
/// THE HOP THAT PRESENTS A BASE URL'S USERINFO: a request carrying a [`UrlUserinfo`] extension
/// goes out with `authorization: Basic …` as its FIRST field when, and only when, it names no
/// `authorization` of its own — 1.5.5's order and condition (see [`UrlUserinfo`]). The extension is
/// taken off either way, so nothing past this hop holds it. A request without one is untouched.
pub(crate) fn present_url_userinfo(req: &mut http::Request<Full<Bytes>>) {
    let Some(userinfo) = req.extensions_mut().remove::<UrlUserinfo>() else {
        return;
    };
    if req.headers().contains_key(http::header::AUTHORIZATION) {
        return;
    }
    let rest = std::mem::take(req.headers_mut());
    let mut fields = http::HeaderMap::with_capacity(rest.len() + 1);
    fields.insert(http::header::AUTHORIZATION, userinfo.0);
    fields.extend(rest);
    *req.headers_mut() = fields;
}

/// Assemble one egress request from boot-precomputed parts, POST (the one method this
/// fixed-destination forward path speaks). Deliberately NOT [`request`]: the caller's `http::Uri`
/// was validated at boot (no userinfo can survive config validation), so this path keeps zero
/// per-request branches — byte-for-byte the assembly it has always been.
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

/// One hop's transport failure, classified — the neutral vocabulary a seam consumer maps onto its
/// own taxonomy (the plane split is connect-class vs everything-that-reached-the-wire; a deadline
/// is the latter, exactly as the reqwest per-request timeout classified: `is_connect()` false).
#[derive(Debug)]
pub enum HopError {
    /// The connection could not be established (TCP, tunnel, TLS, resolver refusal) — hyper's
    /// `is_connect` class, which `reqwest::Error::is_connect` wrapped.
    Connect(String),
    /// The hop reached the wire and failed after — reset, protocol error, peer refusal past the
    /// handshake (the TLS 1.3 identityless-mTLS shape the differential harness pinned).
    Io(String),
    /// The caller's deadline elapsed before the head arrived.
    Deadline,
}

/// The one wording a deadline failure carries — shared by [`send_bounded`] and a body pump that
/// enforces the same deadline over its chunk reads (reqwest's per-request timeout spanned the
/// whole exchange INCLUDING the body, and the engine keeps that discipline).
pub const HOP_DEADLINE_CAUSE: &str = "governed egress hop exceeded its deadline";

impl HopError {
    /// The connect-class test, mirroring `reqwest::Error::is_connect` for the seam's fail-over
    /// classification.
    pub fn is_connect(&self) -> bool {
        matches!(self, HopError::Connect(_))
    }

    /// The flattened cause chain (already URL-free: hyper errors never carry the URL — that was
    /// only ever reqwest's addition, so there is nothing to strip).
    pub fn into_cause(self) -> String {
        match self {
            HopError::Connect(cause) | HopError::Io(cause) => cause,
            HopError::Deadline => HOP_DEADLINE_CAUSE.to_string(),
        }
    }
}

/// Send one request under an absolute deadline, classifying the failure ([`HopError`]). The
/// deadline handle stays the CALLER'S: reqwest's per-request `.timeout()` bounded the whole
/// exchange including the body read, so a caller that streams keeps enforcing the same instant
/// over its chunk loop — this bounds only the exchange up to the response head.
pub async fn send_bounded(
    client: &EngineClient,
    req: http::Request<Full<Bytes>>,
    deadline: tokio::time::Instant,
) -> Result<http::Response<hyper::body::Incoming>, HopError> {
    match tokio::time::timeout_at(deadline, client.request(req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => {
            let cause = super::with_cause(&e);
            if e.is_connect() {
                Err(HopError::Connect(cause))
            } else {
                Err(HopError::Io(cause))
            }
        }
        Err(_elapsed) => Err(HopError::Deadline),
    }
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod engine_tests;

/// The owned-pool pinning battery (h1/coalescing/error rows): the byte-level wire
/// differential against the legacy client, the dial-coalescing invariant under bursts/cancels,
/// FIFO fairness, park-at-cap, idle-FIN, the take_message retry boundary with its over-retry
/// falsifier, the DOA checkout retry, and the error-chain classification contract.
#[cfg(test)]
#[path = "tests/pool_tests.rs"]
mod pool_tests;

/// The owned-pool h2 rows: singleflight + the `:authority` differential, the last-checkout idle
/// clock, the generation-guarded clear, and the KnownProto transition rule (ALPN-switch fixture).
#[cfg(test)]
#[path = "tests/pool_h2_tests.rs"]
mod pool_h2_tests;

/// The pin-as-resolver contract: one-name table, doctrine-text byte-parity with the reqwest
/// resolver, and the client-level zero-lookup proof through the real `build_client` wiring.
#[cfg(test)]
#[path = "tests/resolver_tests.rs"]
mod resolver_tests;

/// The dial judge on the pooled posture: rebinding and mixed answers refused before any socket,
/// loopback admitted and pooled, a published table read by the next dial, the refusal's connect
/// class, and the name kept for SNI and `Host`.
#[cfg(test)]
#[path = "tests/dial_judge_tests.rs"]
mod dial_judge_tests;

/// The tunnelled target judged before CONNECT (K3 #5): a private literal or a privately-answering
/// name is never tunnelled to, a name that does not resolve here still is.
#[cfg(test)]
#[path = "tests/tunnel_judge_tests.rs"]
mod tunnel_judge_tests;

/// The R1 extras-propagation spike (pooled reuse carries `PeerKeyPin` on every response), SNI
/// preservation under the pin with its wrong-name refusing twin, the R2 URI-port-wins proof, and
/// the whole-connect deadline against a black-holing TLS peer.
#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod observe_tests;

/// The TLS postures: the R4 `ClientIdentity::from_pem` / `reqwest::Identity::from_pem` verdict
/// parity corpus, the mTLS handshake through the real pinned posture, the private-CA
/// extra-root arm, and the loud garbage-root build refusal.
#[cfg(test)]
#[path = "tests/tls_tests.rs"]
mod tls_tests;

pub use tunnel::install_proxy;

/// The owned CONNECT tunnel for the proxy-env parity case (owner-ruled: full tunnel, not the
/// boot-refusal interim). Constructed ONLY when a proxy env var is present at boot; the direct
/// path pays one `None` check per CONNECT and nothing per request.
mod tunnel {
    use std::net::IpAddr;
    use std::sync::{Arc, OnceLock};

    /// THE PROXY CHOICE IS NOT READ HERE (status row 130 E5a; ARCHITECT ruling 2026-10-12): the
    /// proxy environment is parsed in ONE place, the connector (`busbar_core_connector::proxy`), into
    /// the shared [`ProxyChoice`]; the composition root hands this engine that value at boot
    /// ([`install_proxy`]), and the engine reads no environment of its own.
    use busbar_contract::proxy_route::{ProxyChoice, ProxyHop};

    /// The boot-installed proxy choice, `None` in every deployment without a proxy environment.
    /// `OnceLock` so config applies rebuild clients against the SAME boot choice — the process
    /// environment, immutable for the process lifetime, exactly reqwest's read-once behavior.
    static INSTALLED: OnceLock<Option<Arc<ProxyChoice>>> = OnceLock::new();

    /// Install the process's proxy choice — the connector's, handed over by the composition root
    /// at boot, before any client is built. First install wins.
    pub fn install_proxy(choice: Option<Arc<ProxyChoice>>) {
        let _ = INSTALLED.set(choice);
    }

    /// What the client builder wires in: the boot choice, or `None` for a build that runs
    /// before/without [`install_proxy`] (tests, tools) — direct, like reqwest built without proxy
    /// env.
    pub fn installed_proxy() -> Option<Arc<ProxyChoice>> {
        INSTALLED.get().cloned().flatten()
    }

    /// The connector the https arm (`https`) wraps: plain TCP in the direct arm, TCP-to-proxy + CONNECT in
    /// the tunneled arm. Sits BELOW TLS, so an https target's TLS handshake (with the target's
    /// SNI, against the target's cert) runs over the established tunnel — the proxy sees only
    /// `CONNECT host:port`, never a decrypted byte.
    #[derive(Clone)]
    pub struct TunnelConnector {
        inner: hyper_util::client::legacy::connect::HttpConnector<super::EgressResolver>,
        config: Option<Arc<ProxyChoice>>,
        /// Per-shard connect pacing — see [`ConnectGate`]. Shared by clones of this connector
        /// (hyper clones the service per connect), NOT across shards: each worker paces its own
        /// establishment so no cross-worker lock ever appears on the connect path.
        gate: Arc<ConnectGate>,
        /// How every target this connector dials is judged before a socket opens.
        posture: DialPosture,
    }

    /// HOW A TARGET IS JUDGED BEFORE THE DIAL (THE DESIGN §5 DESTINATION GUARD: one check for every
    /// outbound connection, a literal included). `HttpConnector` hands an IP-literal host straight
    /// to the socket without asking its resolver, so the resolver's judgement alone never sees a
    /// literal; this is the judgement that does, and it runs on both arms, direct and tunnelled.
    #[derive(Clone)]
    pub enum DialPosture {
        /// The pinned posture: the resolver answers only the pin, so a literal target must BE the
        /// pinned address; any other literal is refused.
        Pinned { addr: IpAddr },
        /// The pooled posture: the guard's name arm judges every target (a literal as its own
        /// answer; a metadata, blocked or `localhost` name), then the resolver judges a name's
        /// answer. A tunnelled target is resolved here through `names` as well: an answer is judged
        /// whole and a refused one is never tunnelled to; a name that does not resolve here goes to
        /// the proxy after the name arm (reach behind the proxy is the proxy's boundary).
        Judged {
            judge: Option<Arc<dyn crate::host_services::DestJudge>>,
            names: super::EgressResolver,
        },
    }

    impl DialPosture {
        /// The judgement every dial opens with, before any socket.
        fn admit(&self, target_host: &str) -> Result<(), BoxError> {
            match self {
                DialPosture::Pinned { addr } => {
                    let bare = target_host.trim_start_matches('[').trim_end_matches(']');
                    match bare.parse::<IpAddr>() {
                        Ok(ip) if ip != *addr => Err(format!(
                            "a pinned governed egress connects only to the address its guard judged \
                             ({addr}); the egress client asked to dial the literal `{target_host}`, \
                             which no guard judged"
                        )
                        .into()),
                        _ => Ok(()),
                    }
                }
                DialPosture::Judged { judge, .. } => {
                    super::resolve::judged_name(judge.as_ref(), target_host)
                }
            }
        }

        /// A tunnelled target's own resolution, judged: `Err` when it resolved here to an answer
        /// the guard refuses; `Ok` when the answer is admitted or the name does not resolve here
        /// (the proxy resolves it). A literal was judged by [`Self::admit`] already.
        async fn admit_tunnelled(&self, target_host: &str) -> Result<(), BoxError> {
            let DialPosture::Judged { judge, names } = self else {
                return Ok(());
            };
            let bare = target_host.trim_start_matches('[').trim_end_matches(']');
            if bare.parse::<IpAddr>().is_ok() {
                return Ok(());
            }
            let Ok(name) = bare.parse::<hyper_util::client::legacy::connect::dns::Name>() else {
                return Ok(());
            };
            let mut names = names.clone();
            if std::future::poll_fn(|cx| tower::Service::poll_ready(&mut names, cx))
                .await
                .is_err()
            {
                return Ok(());
            }
            match tower::Service::call(&mut names, name).await {
                Ok(addrs) => {
                    let addrs: Vec<std::net::SocketAddr> = addrs.collect();
                    if addrs.is_empty() {
                        return Ok(());
                    }
                    super::resolve::judged_answer(judge.as_ref(), target_host, addrs)
                }
                Err(_) => Ok(()),
            }
        }
    }

    impl TunnelConnector {
        pub fn new(
            inner: hyper_util::client::legacy::connect::HttpConnector<super::EgressResolver>,
            config: Option<Arc<ProxyChoice>>,
            dial_bound: usize,
            posture: DialPosture,
        ) -> Self {
            Self {
                inner,
                config,
                gate: Arc::new(ConnectGate::new(dial_bound)),
                posture,
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
    pub(super) const CONNECTS_PER_AUTHORITY_GLOBAL: usize = 64;

    /// This shard's share of the global budget. Reads the composition root's published
    /// establishment-shard count (1 when unset — tools/tests), never a per-request read:
    /// resolved once per client build (`dial_bound_for`) into the gate's permit count AND the
    /// owned pool's coalescing bound — the same number, so bound == permits by construction.
    pub(super) fn connects_per_shard() -> usize {
        (CONNECTS_PER_AUTHORITY_GLOBAL / super::establishment_shards_or_one()).max(1)
    }

    /// Per-shard registry of per-authority connect semaphores. Keys are the DIALED authority
    /// (the target for direct connects, the proxy for tunneled ones — the storm lands on
    /// whichever socket is actually dialed). Growth is bounded by the number of distinct
    /// configured authorities; entries are never evicted because that set is config-sized.
    pub(crate) struct ConnectGate {
        /// The per-authority permit count — the per-client bound this gate was built with
        /// (per-shard share for sharded clients, the undivided global for pinned postures).
        bound: usize,
        slots: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
    }

    impl ConnectGate {
        fn new(bound: usize) -> Self {
            Self {
                bound,
                slots: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        /// The semaphore for one authority — one lock hop per CONNECT (never per request).
        fn slot(&self, authority: &str) -> Arc<tokio::sync::Semaphore> {
            let mut slots = self.slots.lock().expect("connect-gate lock");
            slots
                .entry(authority.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(self.bound)))
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
            // THE GUARD FIRST, on both arms: no socket opens to a target it refuses.
            if let Err(refused) = self.posture.admit(&target_host) {
                return Box::pin(async move { Err(refused) });
            }
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
            let proxy_uri: http::Uri =
                match format!("http://{}:{}", proxy.host(), proxy.port()).parse() {
                    Ok(u) => u,
                    Err(e) => return Box::pin(async move { Err(Box::new(e) as BoxError) }),
                };
            // Tunneled arm: the storm lands on the PROXY socket, so gate on the proxy
            // authority; the permit spans dial + CONNECT handshake (both are establishment).
            let gate = self
                .gate
                .slot(&format!("{}:{}", proxy.host(), proxy.port()));
            let dial = tower::Service::call(&mut self.inner, proxy_uri);
            let posture = self.posture.clone();
            Box::pin(async move {
                // The proxy connects to the target itself, so the target's answer is judged HERE,
                // before the proxy is dialled or asked anything.
                posture.admit_tunnelled(&target_host).await?;
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
        proxy: &ProxyHop,
    ) -> Result<(), BoxError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(auth) = proxy.proxy_authorization() {
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

    /// A whole choice whose BOTH slots point at one scripted proxy — what the end-to-end test
    /// wires directly so parallel tests never race an env var or the OnceLock.
    #[cfg(test)]
    pub(super) fn test_config(
        host: &str,
        port: u16,
        auth: Option<String>,
        no_proxy: &str,
    ) -> Arc<ProxyChoice> {
        let hop = Arc::new(ProxyHop::new(host.to_string(), port, auth));
        Arc::new(ProxyChoice::new(Some(hop.clone()), Some(hop), no_proxy))
    }

    #[cfg(test)]
    pub(super) use connects_per_shard as connects_per_shard_for_tests;

    /// The pooled posture a hand-assembled test connector dials by: the refusing guard double with
    /// the loopback every fixture binds allowlisted, as an operator lists a loopback upstream.
    #[cfg(test)]
    pub(super) fn loopback_listed_for_tests() -> DialPosture {
        DialPosture::Judged {
            judge: Some(crate::egress::fixtures::private_refusing(&["127.0.0.1"])),
            names: super::EgressResolver::system(),
        }
    }

    #[cfg(test)]
    impl ConnectGate {
        pub(super) fn new_for_tests() -> Self {
            Self::new(connects_per_shard())
        }
        pub(super) fn slot_for_tests(&self, authority: &str) -> Arc<tokio::sync::Semaphore> {
            self.slot(authority)
        }
    }
}
