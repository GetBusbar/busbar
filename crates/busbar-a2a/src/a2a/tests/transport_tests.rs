// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TESTS THAT ONLY THE REAL CLIENT CAN FAIL.
//!
//! `tests/fetch_tests.rs` proves the GUARD: one lookup per hop, every address judged, a mixed
//! answer refused. It proves all of that against a fixture transport, and a fixture transport
//! cannot re-resolve a hostname because it never opens a socket. So a transport that accepted the
//! pinned address and then let the HTTP client resolve the hostname itself would pass every test in
//! that file while reinstating exactly the second lookup the guard exists to remove.
//!
//! Every test here therefore uses the PRODUCTION transport against a REAL socket. The rebinding
//! case is expressed the way the attack is: one name, two servers, and a name lookup that answers
//! the honest one first and the hostile one afterwards. The correct transport asks once and
//! connects to the address that was judged. The naive one asks twice and gets the second answer,
//! and this file was written against the naive one first to prove it says so.
//!
//! ## Why these stop at the transport seam instead of driving `fetch_card`
//!
//! A test server binds to loopback, and loopback is INTERNAL — the guard refuses it, correctly and
//! with no override, so no end-to-end `fetch_card` can reach a socket a test is allowed to create.
//! Adding a "test addresses are fine" escape hatch to the guard would be a hole in production to
//! make a test pass. So each test performs the same two steps the driver does — one lookup through
//! the resolver, then the transport with the address that lookup produced — and asserts on what the
//! real client did with them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{CertificateParams, CertifiedKey, IsCa, Issuer, KeyPair};

use super::*;
use crate::a2a::fetch::{FetchPolicy, Resolver, Transport};

pub(crate) const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The hostname every test uses. It is in the RFC 6761 `.test` TLD, so a machine running these
/// tests cannot resolve it by accident and a lookup that "succeeded" can only have come from the
/// resolver the test installed.
pub(crate) const HOST: &str = "a2a.vendor.test";

// ══ THE RESOLVER THAT COUNTS ═════════════════════════════════════════════════════════════════════

/// ONE resolver playing BOTH roles: the fetch path's [`Resolver`], and the resolver the real HTTP
/// client is forced to use. One counter spans the two, so "how many times was this name looked up
/// during the fetch" is a single number rather than two that have to be added up by hand.
///
/// The two roles deliberately give DIFFERENT answers. The guard-side answer is the honest server;
/// the client-side answer is the hostile one. That is a rebinding upstream, and it means the body
/// that comes back names which lookup the socket was opened from.
struct CountingResolver {
    lookups: Arc<AtomicUsize>,
    /// What the fetch path is told: the address the guard would judge and pin.
    judged: IpAddr,
    /// What the CLIENT is told, if it ever asks. A different server, so an answer from here is
    /// visible in the response body rather than inferred.
    rebound: SocketAddr,
}

impl CountingResolver {
    fn new(judged: IpAddr, rebound: SocketAddr) -> Self {
        Self {
            lookups: Arc::new(AtomicUsize::new(0)),
            judged,
            rebound,
        }
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Resolver for CountingResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(vec![self.judged])
    }
}

/// The client-side half. Shares the counter, and answers the HOSTILE address.
struct ClientSideResolver {
    lookups: Arc<AtomicUsize>,
    rebound: SocketAddr,
}

impl reqwest::dns::Resolve for ClientSideResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(self.rebound));
        Box::pin(std::future::ready(Ok(addrs)))
    }
}

impl CountingResolver {
    fn client_side(&self) -> Arc<ClientSideResolver> {
        Arc::new(ClientSideResolver {
            lookups: Arc::clone(&self.lookups),
            rebound: self.rebound,
        })
    }
}

// ══ REAL SERVERS ═════════════════════════════════════════════════════════════════════════════════

/// Read one HTTP request off `stream`, up to and including the blank line that ends the headers.
/// Returns the request line, or `None` if the peer went away first.
pub(crate) fn read_request<R: BufRead>(stream: &mut R) -> Option<String> {
    let mut first = String::new();
    if stream.read_line(&mut first).ok()? == 0 {
        return None;
    }
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).ok()? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    Some(first.trim_end().to_string())
}

pub(crate) fn http_response(
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
    body: &str,
) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    out.push_str("Content-Type: application/json\r\n");
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n");
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

/// A plaintext HTTP server on an ephemeral loopback port that answers every request identically.
/// Returns its address and the list of request lines it served, so a test can assert that a server
/// was NOT contacted as well as that one was.
fn spawn_http(status: u16, extra: Vec<(String, String)>, body: String) -> (SocketAddr, Requests) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let seen: Requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(&stream);
            let Some(line) = read_request(&mut reader) else {
                continue;
            };
            recorder.lock().expect("record").push(line);
            let pairs: Vec<(&str, &str)> = extra
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let mut w = &stream;
            let _ = w.write_all(&http_response(status, "OK", &pairs, &body));
            let _ = w.flush();
        }
    });
    (addr, seen)
}

type Requests = Arc<Mutex<Vec<String>>>;

/// What one TLS connection told us about itself. Recorded even when the handshake FAILS, because a
/// client that rejects the certificate has already sent its `ClientHello` — which is where the
/// server name lives, and is precisely what these tests need to read.
pub(crate) type ObservedSni = Arc<Mutex<Vec<Option<String>>>>;

/// A real rustls server on an ephemeral loopback port. Records the SNI of every connection and, if
/// the handshake completes, answers `body`.
pub(crate) fn spawn_tls(cert_pem: &str, key_pem: &str, body: String) -> (SocketAddr, ObservedSni) {
    busbar_core::tls::install_crypto_provider();
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = {
        use rustls_pki_types::pem::PemObject;
        rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("server cert PEM")
    };
    let key = {
        use rustls_pki_types::pem::PemObject;
        rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("server key PEM")
    };
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config"),
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let sni: ObservedSni = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&sni);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            // Drive the handshake. It may FAIL (an untrusted certificate is rejected by the peer);
            // the `ClientHello` has already been read either way, which is what is being observed.
            let handshake = conn.complete_io(&mut stream);
            recorder
                .lock()
                .expect("record")
                .push(conn.server_name().map(str::to_string));
            if handshake.is_err() {
                continue;
            }
            let mut tls = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf);
            let _ = tls.write_all(&http_response(200, "OK", &[], &body));
            let _ = tls.flush();
            conn.send_close_notify();
            let _ = conn.complete_io(&mut stream);
        }
    });
    (addr, sni)
}

/// A CA plus a leaf certificate signed by it for `sans`. Returns (ca_pem, leaf_pem, leaf_key_pem).
pub(crate) fn ca_and_leaf(sans: Vec<String>) -> (String, String, String) {
    let ca_kp = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).expect("self-signed ca");

    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().expect("leaf key");
    let leaf_params = CertificateParams::new(sans).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_kp, &issuer)
        .expect("signed leaf");

    (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
}

pub(crate) fn url(scheme: &str, port: u16, path: &str) -> reqwest::Url {
    reqwest::Url::parse(&format!("{scheme}://{HOST}:{port}{path}")).expect("a URL")
}

/// The two steps the fetch driver performs for one hop, run against the REAL pieces: exactly one
/// lookup, then the transport with the address that lookup produced.
fn one_hop(
    resolver: &dyn Resolver,
    transport: &dyn Transport,
    url: &reqwest::Url,
) -> Result<crate::a2a::fetch::HttpResponse, String> {
    let addrs = resolver.resolve(HOST)?;
    let addr = *addrs.first().ok_or("no addresses")?;
    transport.get(url, addr)
}

// ══ THE REBINDING GUARD, AGAINST THE REAL CLIENT ═════════════════════════════════════════════════

/// THE TEST THIS FILE EXISTS FOR.
///
/// The fixture-resolver twin of this assertion lives in `fetch_tests.rs` and is satisfied by a
/// transport that never opens a socket. This one is not: the client is real, it is given a resolver
/// that would happily answer, and the assertion is that it never asks.
#[test]
fn a_host_that_resolves_differently_on_the_second_lookup_never_gets_a_second_lookup() {
    let (honest, honest_seen) = spawn_http(
        200,
        Vec::new(),
        r#"{"protocolVersion":"0.3.0","name":"planner"}"#.to_string(),
    );
    let (hostile, hostile_seen) = spawn_http(
        200,
        Vec::new(),
        r#"{"protocolVersion":"0.3.0","name":"REBOUND"}"#.to_string(),
    );

    // Honest on the lookup the guard makes; hostile on any lookup the client makes.
    let resolver = CountingResolver::new(honest.ip(), hostile);
    let policy = FetchPolicy::default();
    let transport =
        ReqwestTransport::with_client_resolver(&policy, resolver.client_side() as Arc<_>);

    let resp = one_hop(
        &resolver,
        &transport,
        &url("http", honest.port(), "/.well-known/agent-card.json"),
    )
    .expect("the pinned hop must complete");

    assert_eq!(
        resolver.lookups(),
        1,
        "the name must be looked up EXACTLY ONCE for the whole hop; a second lookup is the \
         rebinding attack, and the client performing one of its own counts"
    );
    assert_eq!(resp.status, 200);
    let body = String::from_utf8(resp.body).expect("utf-8 body");
    assert!(
        body.contains("planner"),
        "the socket must have gone to the JUDGED address; body was {body}"
    );
    assert!(
        !body.contains("REBOUND"),
        "the socket reached the address the SECOND lookup answered: {body}"
    );
    assert_eq!(
        honest_seen.lock().expect("seen").len(),
        1,
        "the judged address must have been contacted exactly once"
    );
    assert!(
        hostile_seen.lock().expect("seen").is_empty(),
        "the rebound address must never be contacted at all, got {:?}",
        hostile_seen.lock().expect("seen")
    );
}

/// The production constructor makes the second lookup IMPOSSIBLE rather than merely unused: the
/// client's own resolver refuses every name. The hop still completes, because it never needs one.
#[test]
fn the_production_transport_gives_its_client_a_resolver_that_refuses_every_name() {
    let (honest, _seen) = spawn_http(200, Vec::new(), r#"{"name":"planner"}"#.to_string());
    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);

    // `a2a.vendor.test` resolves nowhere on any machine, and the client's resolver refuses
    // regardless. Only the pin can produce a connection here.
    let resp = transport
        .get(
            &url("http", honest.port(), "/.well-known/agent-card.json"),
            LOOPBACK,
        )
        .expect("the pin, and only the pin, must carry this hop");
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body)
        .expect("utf-8")
        .contains("planner"));
}

/// And the refusal is REACHABLE, not decoration: a client asked to resolve gets an error naming the
/// invariant. Proven by asking the production resolver directly, because the pin means the fetch
/// path never reaches it — an unreachable guard that has never been executed is not a guard.
#[test]
fn the_clients_refusing_resolver_names_the_invariant_when_it_is_reached() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let refuser = busbar_substrate::egress::RefuseSecondLookup;
    let err = rt.block_on(async {
        reqwest::dns::Resolve::resolve(&refuser, HOST.parse().expect("a name"))
            .await
            .err()
            .map(|e| e.to_string())
    });
    let err = err.expect("the client's resolver must refuse");
    assert!(
        err.contains("exactly once") && err.contains(HOST),
        "the refusal must name the invariant and the name it was asked about, got: {err}"
    );
}

// ══ PINNING THE ADDRESS DOES NOT WEAKEN TLS ══════════════════════════════════════════════════════

/// SNI carries the HOSTNAME, never the pinned address.
///
/// The socket goes to 127.0.0.1 and the server still sees `a2a.vendor.test` in the `ClientHello`.
/// An implementation that pinned by rewriting the URL to the address — the other obvious way to
/// make the connection go where you want — would send the address here and break every upstream
/// that serves more than one name from one socket, silently.
#[test]
fn the_tls_handshake_sends_the_hostname_as_sni_not_the_pinned_address() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("self-signed");
    let (addr, sni) = spawn_tls(&cert.pem(), &signing_key.serialize_pem(), String::new());

    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);
    // The certificate is self-signed and NOT trusted, so this fetch fails — after the ClientHello.
    let _ = transport.get(&url("https", addr.port(), "/card"), LOOPBACK);

    // The handshake runs on the server's own thread; give it a moment to record.
    let observed = wait_for_sni(&sni);
    assert_eq!(
        observed,
        vec![Some(HOST.to_string())],
        "the handshake must present the URL's hostname as SNI even though the socket was pinned to \
         {LOOPBACK}"
    );
}

/// Certificate verification is STILL ON. The pin decides where the socket goes and nothing else; a
/// certificate no root vouches for is refused exactly as it would be without a pin.
#[test]
fn an_untrusted_certificate_is_still_refused_over_a_pinned_connection() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("self-signed");
    let (addr, _sni) = spawn_tls(
        &cert.pem(),
        &signing_key.serialize_pem(),
        r#"{"name":"planner"}"#.to_string(),
    );

    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);
    let err = transport
        .get(&url("https", addr.port(), "/card"), LOOPBACK)
        .expect_err("an untrusted certificate must not produce a card");
    assert!(
        err.contains("invalid peer certificate") && err.contains("UnknownIssuer"),
        "the refusal must be the certificate chain check, named: {err}"
    );
}

/// And the verification is against the HOSTNAME, not the address.
///
/// Both halves run against the SAME trusted CA and the SAME loopback socket, so the only thing that
/// differs is the name on the certificate. The certificates carry no address in their SANs at all,
/// so the accepted one can only have been accepted by name.
#[test]
fn a_trusted_certificate_is_accepted_for_the_hostname_and_refused_for_another_name() {
    let (ca_pem, leaf_pem, leaf_key) = ca_and_leaf(vec![HOST.to_string()]);
    let (right, _sni) = spawn_tls(&leaf_pem, &leaf_key, r#"{"name":"planner"}"#.to_string());

    let policy = FetchPolicy::default();
    let resp = ReqwestTransport::new(&policy)
        .trusting_root(ca_pem.as_bytes())
        .get(&url("https", right.port(), "/card"), LOOPBACK)
        .expect("a certificate for the URL's hostname, from a trusted CA, must be accepted");
    assert_eq!(resp.status, 200);
    assert!(String::from_utf8(resp.body)
        .expect("utf-8")
        .contains("planner"));

    // Same CA, same trust, same socket — a certificate for somebody else's name.
    let (other_ca, other_leaf, other_key) = ca_and_leaf(vec!["attacker.test".to_string()]);
    let (wrong, _sni2) = spawn_tls(&other_leaf, &other_key, r#"{"name":"planner"}"#.to_string());
    let err = ReqwestTransport::new(&policy)
        .trusting_root(other_ca.as_bytes())
        .get(&url("https", wrong.port(), "/card"), LOOPBACK)
        .expect_err("a certificate for a different name must be refused");
    assert!(
        err.contains("invalid peer certificate")
            && err.contains(&format!("certificate not valid for name \"{HOST}\""))
            && err.contains("attacker.test"),
        "the CA is trusted and the socket is the same; the only thing left to refuse on is the \
         NAME, and the refusal must say so: {err}"
    );
}

/// The server thread records SNI after its own handshake attempt returns; poll briefly rather than
/// sleeping a fixed amount, so the test is neither flaky nor slow.
fn wait_for_sni(sni: &ObservedSni) -> Vec<Option<String>> {
    for _ in 0..200 {
        let seen = sni.lock().expect("sni").clone();
        if !seen.is_empty() {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Vec::new()
}

// ══ THE REST OF THE TRANSPORT CONTRACT ═══════════════════════════════════════════════════════════

/// A 3xx is HANDED BACK, never followed. Following it would perform the next hop with no guard.
#[test]
fn a_redirect_is_returned_for_the_driver_to_re_guard_rather_than_followed() {
    let (elsewhere, elsewhere_seen) =
        spawn_http(200, Vec::new(), r#"{"name":"ELSEWHERE"}"#.to_string());
    let (redirector, _seen) = spawn_http(
        302,
        vec![(
            "Location".to_string(),
            format!("http://{HOST}:{}/moved", elsewhere.port()),
        )],
        String::new(),
    );

    let policy = FetchPolicy::default();
    let resp = ReqwestTransport::new(&policy)
        .get(&url("http", redirector.port(), "/card"), LOOPBACK)
        .expect("a 3xx is a response, not a failure");

    assert_eq!(resp.status, 302);
    assert_eq!(
        resp.location.as_deref(),
        Some(format!("http://{HOST}:{}/moved", elsewhere.port()).as_str()),
        "the Location must be handed back verbatim for the guard to re-judge"
    );
    assert!(
        elsewhere_seen.lock().expect("seen").is_empty(),
        "the transport must not have followed the redirect itself"
    );
}

/// An over-cap body arrives ONE BYTE past the ceiling, which is what lets the fetch driver's own
/// size check refuse it. Reading to exactly the cap would make an at-the-limit body and an
/// unbounded one indistinguishable.
#[test]
fn an_oversized_body_is_cut_one_byte_past_the_ceiling_so_the_driver_can_refuse_it() {
    let policy = FetchPolicy {
        max_body_bytes: 64,
        ..FetchPolicy::default()
    };
    let (addr, _seen) = spawn_http(200, Vec::new(), "x".repeat(4096));

    let resp = ReqwestTransport::new(&policy)
        .get(&url("http", addr.port(), "/card"), LOOPBACK)
        .expect("an oversized body is still a response");
    assert_eq!(
        resp.body.len(),
        65,
        "the read must stop at the ceiling plus one, so `body.len() > max_body_bytes` is true and \
         the driver refuses it"
    );
    assert!(resp.body.len() > policy.max_body_bytes);
}

/// A non-2xx status is reported as itself. The transport classifies nothing; the driver owns that.
#[test]
fn a_non_success_status_is_handed_back_rather_than_turned_into_a_transport_error() {
    let (addr, _seen) = spawn_http(404, Vec::new(), "not here".to_string());
    let policy = FetchPolicy::default();
    let resp = ReqwestTransport::new(&policy)
        .get(&url("http", addr.port(), "/card"), LOOPBACK)
        .expect("a 404 is a response, not a transport failure");
    assert_eq!(resp.status, 404);
}

// ══ THE REAL RESOLVER ════════════════════════════════════════════════════════════════════════════

/// The real resolver answers over tokio's DNS, from a plain synchronous caller and with no ambient
/// runtime — which is the situation the re-verification job is in.
#[test]
fn the_real_resolver_answers_loopback_from_a_thread_with_no_runtime() {
    let addrs = TokioResolver
        .resolve("localhost")
        .expect("localhost must resolve on any machine that can run these tests");
    assert!(
        !addrs.is_empty(),
        "an empty answer is a different fact from a failure and must not be produced here"
    );
    assert!(
        addrs.iter().all(|a| a.is_loopback()),
        "localhost must answer loopback and nothing else, got {addrs:?}"
    );
    // De-duplicated: a name answering the same address twice is one fact.
    let mut unique = addrs.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        addrs.len(),
        "the answer must be duplicate-free"
    );
}

/// A name that does not resolve is an `Err`, never an empty `Ok`. The guard treats the two
/// differently on purpose: a failure must not read as "nothing internal here".
#[test]
fn a_name_that_does_not_resolve_is_an_error_and_not_an_empty_answer() {
    let err = TokioResolver
        .resolve(HOST)
        .expect_err("a .test name must not resolve");
    assert!(!err.is_empty(), "the failure must carry its reason");
}

/// The resolver runs on a thread of its own, so it works from INSIDE a runtime too — where a naive
/// `block_on` would panic. The re-verification job may be driven from either place.
#[test]
fn the_real_resolver_works_from_inside_a_runtime_as_well() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let addrs = rt.block_on(async { TokioResolver.resolve("localhost") });
    assert!(addrs
        .expect("localhost resolves")
        .iter()
        .all(IpAddr::is_loopback));
}

/// And so does the transport.
#[test]
fn the_real_transport_works_from_inside_a_runtime_as_well() {
    let (addr, _seen) = spawn_http(200, Vec::new(), r#"{"name":"planner"}"#.to_string());
    let policy = FetchPolicy::default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let resp = rt.block_on(async {
        ReqwestTransport::new(&policy).get(&url("http", addr.port(), "/card"), LOOPBACK)
    });
    assert_eq!(resp.expect("the hop must complete").status, 200);
}

// ══ THE PRODUCTION PLANE ═════════════════════════════════════════════════════════════════════════

/// The production bundle hands out the REAL resolver and the REAL transport, so a caller cannot
/// pair one of them with a fixture and end up with a fetch that looks tested and connects wherever
/// the client felt like.
#[test]
fn the_production_bundle_hands_out_the_real_pieces_and_the_operators_policy() {
    let policy = FetchPolicy {
        max_redirects: 1,
        max_body_bytes: 1234,
        allow_plaintext: true,
        allow_private: true,
    };
    let live = LiveCardFetch::new(policy.clone());
    assert_eq!(
        live.policy(),
        &policy,
        "the operator's policy is carried through unchanged"
    );

    // The transport is the real one: it opens a socket to the pinned address.
    let (addr, seen) = spawn_http(200, Vec::new(), r#"{"name":"planner"}"#.to_string());
    let resp = live
        .transport()
        .get(&url("http", addr.port(), "/card"), LOOPBACK)
        .expect("the bundled transport must be the real one");
    assert_eq!(resp.status, 200);
    assert_eq!(seen.lock().expect("seen").len(), 1);

    // The resolver is the real one: it answers about a real name.
    assert!(live
        .resolver()
        .resolve("localhost")
        .expect("the bundled resolver must be the real one")
        .iter()
        .all(IpAddr::is_loopback));
}

/// THE DRIVER IS WIRED TO THE REAL PIECES, and the GUARD is still in front of them.
///
/// A production plane that reached a socket without passing `resolve_and_pin` would be a transport
/// with no guard, which is worse than no transport. So the re-verification pass is driven with the
/// production resolver and transport against a backend on loopback — a real, reachable server — and
/// the pass must be REFUSED for the reason the guard gives, with the server never contacted.
#[test]
fn the_reverification_pass_runs_on_the_real_pieces_and_the_guard_still_refuses_loopback() {
    let (addr, seen) = spawn_http(200, Vec::new(), r#"{"name":"planner"}"#.to_string());
    // Plaintext opted in, so the refusal below can only be the ADDRESS check and not the scheme
    // check standing in front of it.
    let live = LiveCardFetch::new(FetchPolicy {
        allow_plaintext: true,
        ..FetchPolicy::default()
    });

    let mut registration = crate::a2a::registry::AgentRegistration::registered(
        "planner",
        format!("http://127.0.0.1:{}", addr.port()),
    );
    let pin_cfg = crate::a2a::config::AgentPinCfg {
        mechanism: crate::a2a::config::PinMechanism::JwsIssuerKey,
        key: Some("k".to_string()),
        fingerprint: None,
    };

    let pass = crate::a2a::verify::reverify_once(
        &mut registration,
        &pin_cfg,
        live.resolver(),
        live.transport(),
        live.policy(),
        1_000,
        true,
    );

    let refusal = pass
        .refusal
        .expect("a loopback backend must be refused, not fetched");
    let text = refusal.to_string();
    assert!(
        text.contains("127.0.0.1") && text.contains("internal address"),
        "the refusal must name the address the guard rejected, got: {text}"
    );
    assert!(
        seen.lock().expect("seen").is_empty(),
        "the guard must refuse BEFORE the transport opens a socket; the server saw {:?}",
        seen.lock().expect("seen")
    );
}

/// The verb layer's probe, over the production plane. Same shape, same guard: a name that does not
/// resolve is a resolution failure carried up from the REAL resolver, not a fixture's script.
#[test]
fn the_production_probe_carries_a_real_resolution_failure_up_to_the_verb_layer() {
    use crate::a2a::verbs::CardSource;

    let live = LiveCardFetch::new(FetchPolicy::default());
    let registration =
        crate::a2a::registry::AgentRegistration::registered("planner", format!("https://{HOST}"));
    let pin_cfg = crate::a2a::config::AgentPinCfg {
        mechanism: crate::a2a::config::PinMechanism::JwsIssuerKey,
        key: Some("k".to_string()),
        fingerprint: None,
    };

    let err = live
        .probe(&registration, &pin_cfg)
        .fetch_card("planner")
        .expect_err("a .test name cannot resolve, so no card can be fetched");
    assert!(
        err.contains(HOST) && err.contains("did not resolve"),
        "the probe must report the real resolver's failure, naming the host: {err}"
    );
}
