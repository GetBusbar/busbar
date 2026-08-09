// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION RESOLVER AND TRANSPORT BEHIND THE AGENT CARD FETCH.
//!
//! [`super::fetch`] removes the time-of-check/time-of-use gap by resolving a name EXACTLY ONCE per
//! hop, judging every address the answer contained, and handing the surviving address to a
//! transport. That is only true if the transport actually USES it.
//!
//! ## The one way this file can be wrong, and it looks right
//!
//! An HTTP client handed a URL performs its OWN name resolution when it connects. A transport that
//! takes the pinned address as an argument and then ignores it — passing the URL to the client and
//! letting the client resolve the host — reinstates the second lookup, which is the whole of DNS
//! rebinding. It compiles, it reads correctly, and against a fixture resolver that is never
//! consulted it passes every test the guard has, because no fixture ever reaches a socket. So the
//! transport here does two separate things about it:
//!
//! 1. **It pins.** The client is built with a host→address override for the one host it is about
//!    to contact, so the connection goes to the address the guard already judged.
//! 2. **It makes the second lookup IMPOSSIBLE, not merely unused.** The client's own resolver is
//!    replaced with one that refuses every name it is ever asked. If a future change drops the pin,
//!    the fetch FAILS LOUDLY instead of quietly resolving the name a second time. A guard whose
//!    failure mode is silent is a guard that will one day be removed by accident.
//!
//! ## Pinning the address must not weaken TLS
//!
//! The pin changes WHERE THE SOCKET GOES and nothing else. The request still carries the original
//! hostname, so the TLS handshake still sends that hostname as SNI and the certificate is still
//! verified against that hostname by the ordinary chain-and-name check. Turning off certificate
//! validation to make an address-pinned connection "work" would trade the rebinding hazard for a
//! strictly worse one — any machine on the path could then serve the card — so it is not available
//! here and there is no knob for it.
//!
//! ## Blocking, on a thread of its own
//!
//! The fetch seam is synchronous, and the client is async. Each call runs its future to completion
//! on a DEDICATED thread with its own current-thread runtime, which is safe whether the caller sits
//! on a runtime worker or on a plain thread — a nested `block_on` on a runtime thread would panic.
//! The same shape the plugin downloader uses, for the same reason. A card fetch happens on a
//! re-verification tick, not on the request hot path, so a thread and a client per hop is a cost
//! that is not worth engineering away.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::fetch::{FetchPolicy, HttpResponse, Resolver, Transport};

/// How long one hop may take, end to end. An agent card is a small JSON document from a host an
/// operator named; a hop that has not completed in this long is not going to.
pub(crate) const CARD_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Run one future to completion on a DEDICATED thread with its own current-thread runtime.
///
/// Not `Handle::current().block_on(..)` and not `block_in_place`: both make assumptions about the
/// caller (that there IS a runtime, that it is multi-threaded) that a synchronous seam cannot make.
/// A thread of its own has no such precondition and cannot panic on the caller's behalf.
fn on_a_dedicated_runtime<T, F>(what: &str, body: F) -> Result<T, String>
where
    F: FnOnce(&tokio::runtime::Runtime) -> Result<T, String> + Send,
    T: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("{what}: could not start a runtime: {e}"))?;
            body(&rt)
        })
        .join()
        .map_err(|_| format!("{what}: the worker thread panicked"))?
    })
}

/// THE REAL RESOLVER: the system resolver, reached through tokio.
///
/// Returns EVERY address the name answered with, de-duplicated but otherwise untouched and
/// unsorted. Filtering or re-ordering here would quietly decide which address the guard gets to
/// judge, and the guard's rule is that it judges all of them.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TokioResolver;

impl Resolver for TokioResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        // Port zero: this seam answers about ADDRESSES. The port belongs to the URL and is applied
        // by the transport, so asking the resolver about one would be asking a second question.
        let target = format!("{host}:0");
        on_a_dedicated_runtime("agent card name lookup", move |rt| {
            rt.block_on(async move {
                let answered = tokio::net::lookup_host(target)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut out: Vec<IpAddr> = Vec::new();
                for sa in answered {
                    let ip = sa.ip();
                    // A name answering the same address under both a v4 and a v6 query is ONE
                    // fact, not two. De-duplication is not filtering: nothing that was answered is
                    // dropped, so the guard still sees every distinct address.
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
                Ok(out)
            })
        })
    }
}

/// The client's own resolver, in production: one that refuses.
///
/// The pin below means the client never needs to resolve anything. This makes the difference
/// between "never needs to" and "cannot" observable: if the pin is ever dropped, the fetch fails
/// with this message rather than succeeding against whatever the name means the second time.
struct NoSecondLookup;

impl reqwest::dns::Resolve for NoSecondLookup {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_string();
        Box::pin(std::future::ready(Err(Box::<
            dyn std::error::Error + Send + Sync,
        >::from(format!(
            "the agent card fetch resolves a name exactly once, before the guard judges the \
             answer, and connects to the address that survived; the HTTP client asked to resolve \
             `{name}` a second time, which is the lookup an attacker needs and must not exist"
        )))))
    }
}

/// A client error WITH ITS CAUSE CHAIN.
///
/// `reqwest::Error`'s own `Display` is the request that failed and nothing about why — "error
/// sending request for url (…)" is the whole message, and the certificate refusal, the connection
/// reset and the timeout all render identically. The reason lives in the `source()` chain, so it is
/// flattened here. An operator reading a refused card fetch is entitled to the reason, and so is
/// [`super::fetch::FetchRefusal::Transport`], which carries this string verbatim.
fn with_cause(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut cause = err.source();
    while let Some(c) = cause {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cause = c.source();
    }
    out
}

/// Hands a shared resolver to the client, which wants a concrete type.
struct DelegatingDns(Arc<dyn reqwest::dns::Resolve>);

impl reqwest::dns::Resolve for DelegatingDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.resolve(name)
    }
}

/// THE REAL TRANSPORT: one `reqwest` GET per hop, to the PINNED ADDRESS.
pub(crate) struct ReqwestTransport {
    /// The resolver the CLIENT is given. Production installs [`NoSecondLookup`]; the tests install
    /// a counting one, which is the only way to assert that the client did not perform a lookup.
    dns: Arc<dyn reqwest::dns::Resolve>,
    /// Body ceiling, mirrored from the policy so the read stops at the cap rather than buffering an
    /// upstream-chosen number of bytes and measuring afterwards.
    max_body_bytes: usize,
    timeout: Duration,
    /// Additional trust anchors. EMPTY in production — the platform's roots are the roots. Present
    /// so a test can stand up a real TLS server and assert what the handshake did, which is the
    /// only way the SNI and certificate-verification claims above are checkable at all.
    extra_roots: Vec<reqwest::Certificate>,
}

impl ReqwestTransport {
    pub(crate) fn new(policy: &FetchPolicy) -> Self {
        Self::with_client_resolver(policy, Arc::new(NoSecondLookup))
    }

    pub(crate) fn with_client_resolver(
        policy: &FetchPolicy,
        dns: Arc<dyn reqwest::dns::Resolve>,
    ) -> Self {
        Self {
            dns,
            max_body_bytes: policy.max_body_bytes,
            timeout: CARD_FETCH_TIMEOUT,
            extra_roots: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn trusting_root(mut self, pem: &[u8]) -> Self {
        self.extra_roots
            .push(reqwest::Certificate::from_pem(pem).expect("a PEM certificate"));
        self
    }
}

impl Transport for ReqwestTransport {
    fn get(&self, url: &reqwest::Url, addr: IpAddr) -> Result<HttpResponse, String> {
        let Some(raw_host) = url.host_str() else {
            return Err(format!("`{url}` has no host to connect to"));
        };
        // `host_str` brackets an IPv6 literal; the client keys its host override on the unbracketed
        // form, so the two spellings are normalized to one here rather than silently missing.
        let host = raw_host.strip_prefix('[').unwrap_or(raw_host);
        let host = host.strip_suffix(']').unwrap_or(host).to_string();
        let Some(port) = url.port_or_known_default() else {
            return Err(format!("`{url}` has no port and its scheme implies none"));
        };
        let pinned = SocketAddr::new(addr, port);

        let dns = Arc::new(DelegatingDns(Arc::clone(&self.dns)));
        let roots = self.extra_roots.clone();
        let timeout = self.timeout;
        let cap = self.max_body_bytes.saturating_add(1);
        let url = url.clone();

        on_a_dedicated_runtime("agent card fetch", move |rt| {
            rt.block_on(async move {
                let mut builder = reqwest::Client::builder()
                    // A 3xx is a fresh, fully untrusted URL that the GUARD must see. A client that
                    // followed it would perform the next hop with no guard at all.
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(timeout)
                    .dns_resolver(dns)
                    // THE PIN. A host→address override for the one host this request is about, so
                    // the socket goes to the address the guard already judged. It overrides the
                    // client's resolver rather than replacing it, which is why the refusing
                    // resolver above is still reachable if this line is ever lost.
                    //
                    // The REQUEST is unchanged: it still carries `host`, so the `Host` header, the
                    // TLS SNI and the certificate's name check are all still about the hostname.
                    // Rewriting the URL to the address would have connected to the same socket and
                    // silently changed all three.
                    .resolve(&host, pinned);
                for root in roots {
                    builder = builder.add_root_certificate(root);
                }
                let client = builder.build().map_err(|e| {
                    format!("could not build the card-fetch client: {}", with_cause(&e))
                })?;

                let resp = client
                    .get(url.clone())
                    .send()
                    .await
                    .map_err(|e| with_cause(&e))?;
                let status = resp.status().as_u16();
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);

                // Read to the cap PLUS ONE. Stopping exactly at the cap would make an
                // exactly-at-the-limit body indistinguishable from an oversized one; one byte over
                // is what lets the fetch driver's own ceiling check make that call.
                let (bytes, end) = crate::proxy::read_capped(resp, cap).await;
                match end {
                    crate::proxy::ReadEnd::TransportError => {
                        Err(format!("`{url}`: the connection failed mid-body"))
                    }
                    // Complete or Truncated both hand the bytes back: an over-cap body arrives one
                    // byte past the ceiling and the driver refuses it there, so the size decision
                    // stays in the one module that owns the policy.
                    _ => Ok(HttpResponse {
                        status,
                        location,
                        body: bytes.to_vec(),
                    }),
                }
            })
        })
    }
}

/// THE PRODUCTION CARD-FETCH PLANE: the real resolver, the real transport and the operator's
/// policy, held together so a caller cannot pick up one without the others.
///
/// A caller holding a resolver and a transport from different places could pair a real transport
/// with a fixture resolver, which is the one combination that would look tested and connect
/// wherever the client felt like.
pub(crate) struct LiveCardFetch {
    resolver: TokioResolver,
    transport: ReqwestTransport,
    policy: FetchPolicy,
}

impl LiveCardFetch {
    pub(crate) fn new(policy: FetchPolicy) -> Self {
        Self {
            resolver: TokioResolver,
            transport: ReqwestTransport::new(&policy),
            policy,
        }
    }

    pub(crate) fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }

    pub(crate) fn transport(&self) -> &dyn Transport {
        &self.transport
    }

    pub(crate) fn policy(&self) -> &FetchPolicy {
        &self.policy
    }

    /// The verb layer's two seams, over the real network.
    pub(crate) fn probe<'a>(
        &'a self,
        registration: &'a super::registry::AgentRegistration,
        pin_cfg: &'a super::config::AgentPinCfg,
    ) -> super::verify::RegistrationProbe<'a> {
        super::verify::RegistrationProbe {
            registration,
            pin_cfg,
            resolver: self.resolver(),
            transport: self.transport(),
            policy: self.policy(),
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod transport_tests;
