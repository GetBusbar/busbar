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
//! ## Reading the peer certificate does not mean trusting one
//!
//! An unsigned agent card has no JWS root, and the only authenticity root left for it is the
//! certificate the endpoint proved it held the key for. So this transport records the leaf
//! certificate's SubjectPublicKeyInfo pin ([`super::spki::spki_pin`]) on every TLS hop.
//!
//! **The certificate is read AFTER the ordinary verification, off a handshake that already
//! succeeded.** `reqwest`'s `tls_info` hands back the leaf of a connection the chain-and-name check
//! already accepted; a handshake that failed produces no response and therefore no pin. There is
//! consequently no path in this file that turns "we saw a certificate" into "we accepted a
//! certificate", and the knob that would switch verification off appears nowhere in this crate — a
//! pin obtained that way would be strictly worse than no pin, because it would read to an operator
//! as a network-layer root while accepting any certificate on the path.
//!
//! ## Blocking, on a thread of its own
//!
//! The fetch seam is synchronous, and the client is async. Each call runs its future to completion
//! on a DEDICATED thread with its own current-thread runtime, which is safe whether the caller sits
//! on a runtime worker or on a plain thread — a nested `block_on` on a runtime thread would panic.
//! The same shape the plugin downloader uses, for the same reason.
//!
//! A card fetch happens on a re-verification tick, so a thread per hop was a cost not worth
//! engineering away. THE RELAY CHANGED THAT: [`super::relay`] is a second caller and it IS the
//! request hot path. The blocking is handled at the call site — `ingress::invoke` enters this seam
//! through `spawn_blocking`, so no axum worker is held for a backend agent's think time. The CLIENT
//! is no longer per hop: this transport now holds a [`crate::egress::PinnedClientPool`] keyed by the
//! judged `(host, pinned address)`, so a repeated hop to an already-judged target reuses the
//! connection. That reuse is safe precisely because the key is the PINNED address and the pooled
//! client still refuses a second lookup — reuse only ever reaches the address the guard already
//! judged, so the cache cannot launder an unvalidated destination.

// PARTLY UNMOUNTED. The live card fetch is driven by the re-verification job and the relay POST by
// the receiving ingress. The pieces a caller-supplied root or an injected client would use are
// reached only by tests today.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::egress::seam::{self, HopSpec};

use super::fetch::{FetchPolicy, HttpResponse, Resolver, Transport};
use super::relay::{ChunkFlow, RelayTransport, StreamHead};
use super::verify::CardTransports;

/// How long one hop may take, end to end. An agent card is a small JSON document from a host an
/// operator named; a hop that has not completed in this long is not going to.
pub(crate) const CARD_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How long ONE RELAYED TASK SUBMISSION may take, end to end.
///
/// Six times the card ceiling, because the two hops are not the same shape: a card is a small
/// static document, and a relayed `message/send` is the backend agent actually doing the work the
/// caller asked for. A ceiling tuned for a document read would turn every slow-but-healthy agent
/// into a `502`. It is still a ceiling rather than none: an unbounded relay is a way to pin a
/// blocking thread per request for as long as an upstream feels like holding it.
pub(crate) const RELAY_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a STREAMING relay may hold its thread. Longer than the unary ceiling and still finite,
/// for the same reason: a stream is legitimately long-lived, and an unbounded one is a way to pin a
/// thread per request forever. `reqwest`'s `timeout` covers the whole request INCLUDING the body,
/// which is what makes this the right knob rather than a read timeout.
pub(crate) const RELAY_STREAM_TIMEOUT: Duration = Duration::from_secs(600);

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

// THE PEER'S TRANSPORT-LAYER IDENTITY is now observed HOST-SIDE, on the egress seam.
//
// The hop no longer runs behind a `reqwest::Response` this plane holds — the host owns the socket and
// the verified handshake, and hands back the `sha256/…` pin on the seam's `seam::Buffered`, decoded
// from the SAME bytes `crate::plane_host::spki::pin` produces (which `super::spki::spki_pin`
// re-exports), so the pin string is byte-identical to the one this file used to compute. `None` on a
// plaintext hop and `None` where the certificate cannot be read, unchanged: `super::verify` refuses
// a transport-pinned registration whose fetch produced no observed pin, because "we could not look"
// and "it matched" are the two answers a pin exists to keep apart.

/// THE CLIENT CERTIFICATES THIS DEPLOYMENT PRESENTS, by agent id.
///
/// Resolved ONCE, at boot, by [`resolve_client_identities`] — not per hop and not per sweep. Two
/// reasons, and the second is the one that matters: a private key re-read from `env` or a file on
/// every tick is a private key crossing the resolver seam on every tick, and a key that fails to
/// resolve at 03:00 would silently stop a registration being re-verified rather than stopping the
/// operator at boot.
pub(crate) type ClientIdentities = BTreeMap<String, reqwest::Identity>;

/// RESOLVE EVERY `agents.<name>.client_identity` INTO A USABLE CLIENT CERTIFICATE. FAIL-CLOSED.
///
/// The PEM bytes come through [`crate::tls::read_pem`] — the same function busbar's own inbound
/// listener loads its cert and key with — so there is exactly one place in the tree that turns a
/// [`crate::config::SecretRef`] into TLS PEM, and it is the one that already knows not to log what it
/// read. The cert and the key are concatenated because that is the single buffer
/// `reqwest::Identity::from_pem` takes; the pairing is checked there, by the TLS stack, rather than
/// by a second parser here.
///
/// An error is returned rather than logged and skipped. A registration whose client certificate did
/// not load is a registration that can never be contacted, and a deployment that boots into that
/// state reads to an operator as working.
pub(crate) fn resolve_client_identities(
    cfg: &super::config::AgentsCfg,
    resolver: &crate::config::secret::SecretResolver,
) -> Result<ClientIdentities, String> {
    let mut out = ClientIdentities::new();
    for (name, def) in &cfg.agents {
        let Some(identity) = def.client_identity.as_ref() else {
            continue;
        };
        let mut pem = crate::tls::read_pem(resolver, &identity.cert, "client cert")
            .map_err(|e| format!("`agents.{name}.client_identity.cert`: {e}"))?;
        // A PEM section must start at the beginning of a line. A chain that ends without a trailing
        // newline would otherwise glue its `-----END-----` to the key's `-----BEGIN-----`, and the
        // resulting parse error would name the key rather than the missing byte.
        if !pem.ends_with(b"\n") {
            pem.push(b'\n');
        }
        pem.extend_from_slice(
            &crate::tls::read_pem(resolver, &identity.key, "client key")
                .map_err(|e| format!("`agents.{name}.client_identity.key`: {e}"))?,
        );
        // NEVER echoes the buffer: the error is the TLS stack's own, and the buffer holds a private
        // key.
        let id = reqwest::Identity::from_pem(&pem).map_err(|e| {
            format!(
                "`agents.{name}.client_identity`: the certificate ({}) and key ({}) are not a \
                 usable client identity: {e}",
                identity.cert.describe(),
                identity.key.describe()
            )
        })?;
        out.insert(name.clone(), id);
    }
    Ok(out)
}

/// THE REAL TRANSPORT: a pinned `reqwest` hop to the PINNED ADDRESS, over the unified core egress
/// backend ([`crate::egress`]) — pooled by the pinned address, so a repeated hop to an
/// already-judged target reuses the connection, and the client still refuses a second lookup.
pub(crate) struct ReqwestTransport {
    /// The resolver a plane-supplied client would have been given. VESTIGIAL under the seam (Design A):
    /// the hop now runs host-side, where the host installs its own [`crate::egress::RefuseSecondLookup`]
    /// and — because every hop carries the already-judged pinned address — performs NO lookup at all. It
    /// is kept only so the test constructor that asserts "the client did not perform a second lookup"
    /// still stands one up; the assertion holds precisely because nothing consults it.
    #[allow(dead_code)]
    dns: Arc<dyn reqwest::dns::Resolve>,
    /// Body ceiling, mirrored from the policy so the read stops at the cap rather than buffering an
    /// upstream-chosen number of bytes and measuring afterwards.
    max_body_bytes: usize,
    timeout: Duration,
    /// Additional trust anchors, accumulated by [`Self::trusting_root`] (test-only) so the full set can
    /// be re-registered as one host-side [`crate::plane_host::trust_anchor`] ref. EMPTY in production —
    /// the platform's roots are the roots.
    extra_roots: Vec<reqwest::Certificate>,
    /// THE OPAQUE host-side trust-anchor ref (`0` = platform roots only). Registered ONCE, when the
    /// transport is built, and carried on every per-hop [`EgressDesc`](busbar_plugin::hot::EgressDesc);
    /// the host resolves it to the parsed roots — the certificate bytes never cross the seam.
    trust_anchor_ref: u64,
    /// THE OPAQUE host-side client-identity ref (`0` = present none), for the ONE agent this transport
    /// was built for. Registered ONCE, at boot, from the identity [`Self::presenting`] was handed, and
    /// carried on every per-hop desc; the host resolves it and offers the certificate when the peer's
    /// `CertificateRequest` asks. `0` where the operator named none — the honest mTLS outcome, the peer
    /// closes the handshake itself rather than busbar forging an identity. The private key never crosses
    /// the seam. There is no fallback identity and no plane-wide one.
    client_identity_ref: u64,
}

impl ReqwestTransport {
    pub(crate) fn new(policy: &FetchPolicy) -> Self {
        Self::with_client_resolver(
            policy,
            Arc::new(busbar_substrate::egress::RefuseSecondLookup),
        )
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
            trust_anchor_ref: 0,
            client_identity_ref: 0,
        }
    }

    /// THE OUTBOUND MUTUAL-TLS LEG: present `identity` on every hop this transport makes.
    ///
    /// Consuming, and per TRANSPORT rather than per client, because the whole point of the change
    /// that introduced it is that one transport can no longer stand for the whole plane: an identity
    /// that could be attached after the fact is an identity that could be attached to the transport
    /// a different agent is being fetched with. The parsed key is handed to the host registry ONCE
    /// here (at boot), not per hop — this transport keeps only the opaque ref.
    pub(crate) fn presenting(mut self, identity: reqwest::Identity) -> Self {
        self.client_identity_ref = crate::plane_host::identity::register(identity);
        self
    }

    #[cfg(test)]
    pub(crate) fn trusting_root(mut self, pem: &[u8]) -> Self {
        self.extra_roots
            .push(reqwest::Certificate::from_pem(pem).expect("a PEM certificate"));
        // Re-register the FULL accumulated set (a fresh ref each time), so the desc's one ref resolves
        // to every root this transport was told to trust — the host owns the parsed certificates.
        self.trust_anchor_ref = crate::plane_host::trust_anchor::register(self.extra_roots.clone());
        self
    }
}

/// ONE PINNED HOP, shared by the card fetch and the relay.
///
/// The two callers differ in method, headers, body and ceiling and in NOTHING ELSE, so they share
/// one execution path. That is not tidiness: the pin, the refusing resolver, the no-redirect policy
/// and the capped read are the security properties of this file, and a second copy of them is a
/// second place for one of them to go missing. When the relay was first written as its own
/// `reqwest` call it silently had none of them, and every test that did not reach a socket stayed
/// green.
struct Hop<'a> {
    url: &'a reqwest::Url,
    /// The address the guard judged. The socket goes HERE; see the pin below.
    addr: IpAddr,
    headers: &'a [(String, String)],
    body: Option<Vec<u8>>,
}

impl ReqwestTransport {
    /// The neutral [`HopSpec`] for one hop, carrying the plane's ALREADY-JUDGED pinned address as
    /// `resolved_addr` (Design A: the host connects there and resolves nothing, so this plane's "no
    /// second lookup" guarantee holds) and this transport's opaque identity/trust-anchor refs.
    fn hop_spec<'a>(
        &'a self,
        url: &'a str,
        addr: IpAddr,
        headers: &'a [(String, String)],
        body: &'a [u8],
        timeout: Duration,
    ) -> HopSpec<'a> {
        HopSpec {
            verb: "",
            url,
            headers,
            body,
            // The a2a fetch guard runs PLANE-SIDE (`guard_hop`) and has already judged this hop; the
            // host re-judges nothing when a pinned address is supplied, so these stances are moot here.
            allow_private: true,
            allow_plaintext: true,
            client_identity_ref: self.client_identity_ref,
            trust_anchor_ref: self.trust_anchor_ref,
            timeout,
            resolved_addr: Some(addr),
        }
    }

    fn execute(
        &self,
        _what: &'static str,
        method: reqwest::Method,
        hop: Hop<'_>,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let Hop {
            url,
            addr,
            headers,
            body,
        } = hop;
        let cap = self.max_body_bytes.saturating_add(1);
        let body = body.unwrap_or_default();
        let mut spec = self.hop_spec(url.as_str(), addr, headers, &body, timeout);
        spec.verb = method.as_str();

        // THE HOP, over the HOSTLESS egress seam. The host owns the socket, the pinned client (its own
        // refusing resolver), the verified handshake and the capped read; it hands back the status, the
        // `Location`, the peer SPKI pin (decoded from the same bytes `super::spki::spki_pin` produces)
        // and whether busbar's own client identity was carried into the handshake. The deadline rides
        // the desc (`timeout_ms`), the identity/trust anchors ride their opaque refs.
        let buffered =
            seam::with_hostless(|scope| seam::buffered(scope, &spec, cap)).map_err(|f| f.cause)?;

        match buffered.end {
            // A mid-body transport failure is reported with the SAME fixed line the plane's own read
            // produced — built HERE from the url the plane still holds (the seam kept the cause and the
            // url separate).
            busbar_substrate::proxy::ReadEnd::TransportError => {
                Err(format!("`{url}`: the connection failed mid-body"))
            }
            // Complete or Truncated both hand the bytes back: an over-cap body arrives one byte past
            // the ceiling and the driver refuses it there, so the size decision stays in the one
            // module that owns the policy.
            _ => Ok(HttpResponse {
                status: buffered.status,
                location: buffered.location,
                body: buffered.body,
                peer_spki: buffered.peer_spki,
                client_identity_offered: buffered.client_identity_offered,
            }),
        }
    }
}

impl Transport for ReqwestTransport {
    fn get(&self, url: &reqwest::Url, addr: IpAddr) -> Result<HttpResponse, String> {
        self.execute(
            "agent card fetch",
            reqwest::Method::GET,
            Hop {
                url,
                addr,
                headers: &[],
                body: None,
            },
            self.timeout,
        )
    }
}

/// THE RELAY POST, THROUGH THE SAME PINNED HOP.
///
/// The only differences from the card fetch are the method, the headers, the body and a longer
/// ceiling. Everything that makes the hop safe is [`ReqwestTransport::execute`]'s, so it cannot be
/// true of one caller and false of the other.
impl RelayTransport for ReqwestTransport {
    fn send(
        &self,
        http_method: &str,
        url: &reqwest::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        // PARSED, NOT MATCHED. The verb comes off the framing that composed the request, and
        // `reqwest::Method` is the type that already knows which tokens are methods — a table here
        // would be a second, shorter answer to a question the http crate has answered once.
        let method = reqwest::Method::from_bytes(http_method.as_bytes())
            .map_err(|_| format!("`{http_method}` is not an HTTP method"))?;
        // A BODY-LESS REQUEST SENDS NO BODY. A zero-length body on a `GET` is not the same request
        // as no body at all: it puts `content-length: 0` on a request the specification defines
        // without one, which some peers refuse outright.
        let body = (!body.is_empty()).then(|| body.to_vec());
        self.execute(
            "a2a task relay",
            method,
            Hop {
                url,
                addr,
                headers,
                body,
            },
            RELAY_TIMEOUT,
        )
    }

    /// THE STREAMING RELAY, THROUGH THE SAME PINNED CLIENT.
    ///
    /// The head is read and returned before a single byte of body is delivered, because a relay
    /// that has already written to its caller cannot then answer a 502. A non-2xx never reaches the
    /// chunk loop at all: its body is read to the cap and handed back whole so the driver can
    /// report the status with the backend's own words in the log.
    fn post_stream(
        &self,
        url: &reqwest::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
        on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String> {
        let cap = self.max_body_bytes.saturating_add(1);
        let mut spec = self.hop_spec(url.as_str(), addr, headers, body, RELAY_STREAM_TIMEOUT);
        spec.verb = "POST";

        // ONE hostless scope spans the head AND the pump, so the streaming egress stays open between
        // `stream_head` and `pump` (the arena closer fires only when the closure returns). The head's
        // buffer-or-stream decision, the SSE content-type test and the non-stream cap read are all the
        // seam's — the same rules this file used to own, now on the one host code path.
        seam::with_hostless(|scope| {
            match seam::stream_head(scope, &spec, cap).map_err(|f| f.cause)? {
                // A non-2xx or non-`text/event-stream` reply is not a stream: its head carries the body
                // read whole to the cap, handed back for the driver to report with the backend's words.
                seam::StreamOutcome::Buffered(head) => Ok(head),
                // A live event-stream: pump the body to the sink, then return the head. A mid-body
                // failure carries the FLATTENED cause the host stashed (`with_cause(&e)`), so the relay
                // reports the SAME operator line its own path did.
                seam::StreamOutcome::Streaming { head, id } => {
                    match seam::pump(scope, id, on_chunk) {
                        seam::PumpEnd::Done => Ok(head),
                        seam::PumpEnd::Failed(f) => Err(f.cause),
                    }
                }
            }
        })
    }
}

impl super::relay::RelaySeam for LiveCardFetch {
    fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        &self.transport
    }
}

/// THE PRODUCTION CARD-FETCH PLANE: the real resolver, the real transport and the operator's
/// policy, held together so a caller cannot pick up one without the others.
///
/// A caller holding a resolver and a transport from different places could pair a real transport
/// with a fixture resolver, which is the one combination that would look tested and connect
/// wherever the client felt like.
/// ## ONE TRANSPORT PER AGENT, not one per plane
///
/// This object used to hold a single [`ReqwestTransport`] and hand the same one to every
/// registration the sweep walked. That was the structural reason `pin.mechanism: mtls` could not be
/// made to work: a client identity is per REGISTRATION — it is the certificate this operator agreed
/// to present to THAT vendor — and there was nowhere to put one that did not immediately become the
/// identity presented to everybody. So the identities are built into transports HERE, once per
/// config generation, and [`CardTransports::for_agent`] hands the sweep the one that belongs to the
/// registration it is looking at.
pub(crate) struct LiveCardFetch {
    resolver: TokioResolver,
    /// The transport for a registration that names NO client identity, and the one the relay seam
    /// and the probe still use. It presents no certificate, which against an mTLS peer means the
    /// hop is refused — loudly, by the peer — rather than made with somebody else's identity.
    transport: ReqwestTransport,
    /// The transports that DO carry an identity, by agent id. Built once, from the identities
    /// resolved at boot; a registration absent from here gets `transport` above.
    per_agent: BTreeMap<String, ReqwestTransport>,
    policy: FetchPolicy,
}

impl LiveCardFetch {
    pub(crate) fn new(policy: FetchPolicy) -> Self {
        Self::presenting(policy, &ClientIdentities::new())
    }

    /// The production bundle for a plane whose registrations name client certificates.
    ///
    /// Takes the identities by reference and clones per agent, because a `reqwest::Identity` is a
    /// parsed key that several transports may need over a process lifetime and the caller resolved
    /// them once.
    pub(crate) fn presenting(policy: FetchPolicy, identities: &ClientIdentities) -> Self {
        let per_agent = identities
            .iter()
            .map(|(agent_id, identity)| {
                (
                    agent_id.clone(),
                    ReqwestTransport::new(&policy).presenting(identity.clone()),
                )
            })
            .collect();
        Self {
            resolver: TokioResolver,
            transport: ReqwestTransport::new(&policy),
            per_agent,
            policy,
        }
    }

    /// EVERY transport in this bundle, with one extra trust anchor. Test-only.
    ///
    /// It exists for one assertion that cannot be made any other way: that the per-agent transports
    /// carry DIFFERENT client identities. Proving that needs two real mTLS peers, and a real peer
    /// needs a server certificate the client will accept — so the root has to reach the transports
    /// THIS BUNDLE built, not a hand-made one beside them. Applying it uniformly is what leaves the
    /// identity as the only thing that varies between the hops under test.
    #[cfg(test)]
    pub(crate) fn trusting_root(self, pem: &[u8]) -> Self {
        let Self {
            resolver,
            transport,
            per_agent,
            policy,
        } = self;
        Self {
            resolver,
            transport: transport.trusting_root(pem),
            per_agent: per_agent
                .into_iter()
                .map(|(id, t)| (id, t.trusting_root(pem)))
                .collect(),
            policy,
        }
    }

    pub(crate) fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }

    pub(crate) fn transport(&self) -> &dyn Transport {
        &self.transport
    }

    /// The CARD-FETCH policy this bundle guards its own hops with.
    ///
    /// INHERENT, and deliberately NOT on [`super::relay::RelaySeam`] any more — see that trait for
    /// why a seam is no longer askable for a policy at all. The card-fetch and re-verification
    /// paths hold a concrete `LiveCardFetch` and legitimately need the policy they were built with;
    /// the push-delivery path holds a `dyn RelaySeam` and must not be able to reach one.
    pub(crate) fn policy(&self) -> &FetchPolicy {
        &self.policy
    }

    /// The verb layer's two seams, over the real network.
    ///
    /// THE TRANSPORT IS THE REGISTRATION'S OWN, asked for by agent id exactly as the sweep asks —
    /// a probe built on the identity-free transport would fetch an mTLS vendor's card over a hop
    /// carrying no certificate, and an operator running `connect` would be told the mutual half did
    /// not happen for a registration whose timer verifies it every tick.
    pub(crate) fn probe<'a>(
        &'a self,
        registration: &'a super::registry::AgentRegistration,
        pin_cfg: &'a super::config::AgentPinCfg,
    ) -> super::verify::RegistrationProbe<'a> {
        super::verify::RegistrationProbe {
            registration,
            pin_cfg,
            resolver: self.resolver(),
            transport: self.for_agent(&registration.agent_id),
            policy: self.policy(),
        }
    }
}

/// THE SWEEP'S SEAM, ANSWERED PER REGISTRATION.
///
/// The registration's own transport where it has one, and the identity-free one otherwise. Never a
/// substitute: an agent whose certificate did not resolve never reaches here at all, because
/// [`resolve_client_identities`] refuses at boot.
impl CardTransports for LiveCardFetch {
    fn for_agent(&self, agent_id: &str) -> &dyn Transport {
        self.per_agent
            .get(agent_id)
            .map_or(&self.transport as &dyn Transport, |t| t as &dyn Transport)
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod transport_tests;

// A SECOND TEST MODULE, and it is a sibling of the first rather than a section inside it because it
// asks a different question of the same machinery: `transport_tests` proves the pin does not weaken
// the connection, and this one proves what the connection PROVES. It reuses that file's TLS harness
// deliberately — a second server fixture would be a second thing that could stop matching
// production.
#[cfg(test)]
#[path = "tests/transport_pin_tests.rs"]
mod transport_pin_tests;

// A THIRD TEST MODULE, and a sibling for the same reason the second one is: it asks what the
// connection PROVES ABOUT BUSBAR rather than about the peer. It reuses the first file's TLS harness
// and CA generator deliberately — a second server fixture would be a second thing that could stop
// matching production.
#[cfg(test)]
#[path = "tests/transport_mtls_tests.rs"]
mod transport_mtls_tests;
