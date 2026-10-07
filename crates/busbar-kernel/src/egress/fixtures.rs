// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIXTURE SERVERS for the egress differential harness — real sockets.
//!
//! The one-egress-stack ruling is proven by DIFFERENTIAL testing: the same hop driven through the
//! owned engine and through the reqwest reference implementation must produce the same observable
//! outcome (status, body, observed peer identity, error class). These fixtures are the ground the
//! comparison stands on: a plaintext server that RECORDS what each connection carried (for the
//! redirect canary and the status/body rows), the throw-away CA material a TLS fixture serves, and
//! resolver doubles that let a test assert "the client performed no lookup of its own" as a count
//! rather than an intention. The recording TLS and mTLS servers are the connector's
//! (`busbar_core_connector::test_support::spawn_tls`): TLS stays in the connector, and their
//! responses are this module's [`CannedResponse`], rendered.
//!
//! Everything here is test machinery: the module compiles under `cfg(test)` for this crate's own
//! suite and under the `test-support` feature for the crates whose test binaries link this one
//! (busbar-core's differential harness). Nothing in a shipped build reaches it.
//!
//! The servers speak HTTP/1.1, so the recorded request/connection counts stay meaningful whichever
//! client drives them (an h2 client multiplexes and would fold two requests into one stream count). Each accept loop runs on a plain OS thread — no runtime coupling with
//! the client under test — and each connection is served on its own thread so a pooled client
//! holding one connection open never blocks the next one.
//!
//! The gate below restates, on the file itself, the `#[cfg(any(test, feature = "test-support"))]`
//! that `egress/mod.rs` already puts on `pub mod fixtures;` — it changes nothing the compiler builds.
//! It is written here so a per-file reader (`cargo xtask loc`, which classifies a file by its own
//! attributes and path, never by the `mod` item that declares it) counts this test machinery as the
//! `test` bucket it is rather than billing 391 lines of fixture servers to the kernel's production
//! LOC ceiling (`loc-ceilings:kernel`).
#![cfg(any(test, feature = "test-support"))]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// One scripted HTTP/1.1 response, served identically to every request the fixture answers.
#[derive(Clone, Debug)]
pub struct CannedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl CannedResponse {
    /// A plain 200 with the given body.
    pub fn ok(body: &str) -> Self {
        CannedResponse {
            status: 200,
            headers: Vec::new(),
            body: body.to_string(),
        }
    }

    /// A redirect answering `location` — the canary body for the "never followed" assertions.
    pub fn redirect(status: u16, location: &str) -> Self {
        CannedResponse {
            status,
            headers: vec![("location".to_string(), location.to_string())],
            body: String::new(),
        }
    }

    /// The response's bytes, as a fixture writes them (what the connector's TLS fixture serves).
    pub fn render(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} X\r\n", self.status);
        for (k, v) in &self.headers {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        out.push_str(&format!("content-length: {}\r\n", self.body.len()));
        out.push_str("connection: keep-alive\r\n\r\n");
        out.push_str(&self.body);
        out.into_bytes()
    }
}

/// What one connection to a fixture told the server about itself. Every field is an observation a
/// differential test compares across the two stacks.
#[derive(Clone, Debug, Default)]
pub struct ConnRecord {
    /// The server name from the ClientHello — recorded even when the handshake FAILS, because a
    /// client that rejects the certificate has already sent its SNI, and "the SNI stayed on the
    /// hostname under an address pin" is exactly what needs reading off a refused handshake too.
    pub sni: Option<String>,
    /// The leaf certificate the client presented, DER — `None` when none was presented.
    pub client_cert: Option<Vec<u8>>,
    /// Whether the TLS handshake completed. `false` marks a connection the client refused
    /// (wrong-name certificate, missing identity against an mTLS peer).
    pub handshake_ok: bool,
    /// The protocol the handshake agreed (ALPN); `None` for a hello with no ALPN extension.
    pub alpn: Option<Vec<u8>>,
    /// How many HTTP requests rode this one connection — the pooled-reuse observation.
    pub requests: usize,
    /// Every request HEAD this TLS connection carried, verbatim to the blank line — what a
    /// test reads the `Host` header off.
    pub heads: Vec<String>,
}

type SharedRecords = Arc<Mutex<Vec<Arc<Mutex<ConnRecord>>>>>;

/// A live plaintext fixture: request lines and connection records for the redirect canary and the
/// status/body parity rows.
pub struct HttpFixture {
    pub addr: SocketAddr,
    records: SharedRecords,
    request_lines: Arc<Mutex<Vec<String>>>,
    request_heads: Arc<Mutex<Vec<String>>>,
}

impl HttpFixture {
    pub fn records(&self) -> Vec<ConnRecord> {
        snapshot(&self.records)
    }

    /// Every request line the fixture served, across all connections.
    pub fn request_lines(&self) -> Vec<String> {
        self.request_lines.lock().expect("request lines").clone()
    }

    /// Every full request HEAD (request line + headers, verbatim bytes to the blank line) the
    /// fixture served — what the owned-pool wire differential byte-compares between the legacy
    /// client and the owned client (request-target form, Host presence and formatting).
    pub fn request_heads(&self) -> Vec<String> {
        self.request_heads.lock().expect("request heads").clone()
    }
}

fn snapshot(records: &SharedRecords) -> Vec<ConnRecord> {
    records
        .lock()
        .expect("records")
        .iter()
        .map(|r| r.lock().expect("record").clone())
        .collect()
}

/// Spawn the plaintext recording server.
pub fn spawn_http(response: CannedResponse, max_requests_per_connection: usize) -> HttpFixture {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records: SharedRecords = Arc::new(Mutex::new(Vec::new()));
    let request_lines = Arc::new(Mutex::new(Vec::new()));
    let request_heads = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&records);
    let lines = Arc::clone(&request_lines);
    let heads = Arc::clone(&request_heads);
    let response = response.render();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let record = Arc::new(Mutex::new(ConnRecord {
                handshake_ok: true, // plaintext: there is no handshake to fail
                ..ConnRecord::default()
            }));
            recorder.lock().expect("records").push(Arc::clone(&record));
            let lines = Arc::clone(&lines);
            let heads = Arc::clone(&heads);
            let response = response.clone();
            std::thread::spawn(move || {
                for _ in 0..max_requests_per_connection {
                    let Some(head) = read_one_request(&mut stream) else {
                        break;
                    };
                    lines
                        .lock()
                        .expect("lines")
                        .push(head.lines().next().unwrap_or_default().to_string());
                    heads.lock().expect("heads").push(head);
                    record.lock().expect("record").requests += 1;
                    if stream
                        .write_all(&response)
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    HttpFixture {
        addr,
        records,
        request_lines,
        request_heads,
    }
}

/// Spawn a plaintext server that answers each request with a response HEAD advertising
/// `content-length: claimed_len` but then CLOSES the connection WITHOUT sending the body. The
/// premature EOF a client's body read hits (fewer than `claimed_len` bytes before the socket
/// closes) is surfaced by hyper as a TRANSPORT error, DISTINCT from a clean short body or a
/// size-cap truncation. This is the mid-body connection drop the self-minting OAuth credentials
/// must classify as a transport failure — the substrate, real-socket twin of busbar-core's old
/// `MockResponse::SseTransportError { ok_events: vec![] }`.
///
/// `claimed_len` MUST be > 0 so the client expects body bytes that never arrive; the head is
/// written and flushed (then a brief pause) before the socket drops, so the response head parses —
/// the request's `send_bounded` returns Ok — and only the subsequent body read fails.
pub fn spawn_http_premature_close(claimed_len: usize) -> HttpFixture {
    assert!(
        claimed_len > 0,
        "claimed_len must be > 0 to force a premature-EOF body read"
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records: SharedRecords = Arc::new(Mutex::new(Vec::new()));
    let request_lines = Arc::new(Mutex::new(Vec::new()));
    let request_heads = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&records);
    let lines = Arc::clone(&request_lines);
    let heads = Arc::clone(&request_heads);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let record = Arc::new(Mutex::new(ConnRecord {
                handshake_ok: true, // plaintext: there is no handshake to fail
                ..ConnRecord::default()
            }));
            recorder.lock().expect("records").push(Arc::clone(&record));
            let lines = Arc::clone(&lines);
            let heads = Arc::clone(&heads);
            std::thread::spawn(move || {
                let Some(head) = read_one_request(&mut stream) else {
                    return;
                };
                lines
                    .lock()
                    .expect("lines")
                    .push(head.lines().next().unwrap_or_default().to_string());
                heads.lock().expect("heads").push(head);
                record.lock().expect("record").requests += 1;
                // Advertise a body that never comes, flush the head, pause so it lands as a
                // complete response head before the FIN, then DROP the socket with the body still
                // owed — the client's body read hits EOF short of `claimed_len` → transport error.
                let response = format!(
                    "HTTP/1.1 200 X\r\ncontent-length: {claimed_len}\r\nconnection: close\r\n\r\n"
                );
                let _ = stream
                    .write_all(response.as_bytes())
                    .and_then(|()| stream.flush());
                std::thread::sleep(std::time::Duration::from_millis(20));
                // `stream` drops here → connection closes mid-body.
            });
        }
    });
    HttpFixture {
        addr,
        records,
        request_lines,
        request_heads,
    }
}

/// Read one HTTP/1.1 request off the stream: the head to its blank line, then exactly
/// `content-length` body bytes so the next read starts at the next request. Returns the full
/// request HEAD text, or `None` on a closed/broken connection.
fn read_one_request<S: Read>(stream: &mut S) -> Option<String> {
    let mut head: Vec<u8> = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    let split_at = loop {
        if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
    };
    let (head_bytes, over_read) = head.split_at(split_at);
    let head_text = String::from_utf8_lossy(head_bytes);
    let content_length: usize = head_text
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(over_read.len());
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let n = stream.read(&mut buf[..want]).ok()?;
        if n == 0 {
            return None;
        }
        remaining -= n;
    }
    Some(head_text.into_owned())
}

/// A throw-away CA plus a leaf it signed for `sans` — the private-CA / known-leaf server material.
pub struct CaLeaf {
    pub ca_pem: String,
    pub leaf_pem: String,
    pub leaf_key_pem: String,
    /// The leaf DER, for computing the expected SPKI pin outside the stack under test.
    pub leaf_der: Vec<u8>,
    /// The leaf's private key, PKCS#8 DER — an identity built from its parts.
    pub leaf_key_der: Vec<u8>,
}

/// Mint a CA and a leaf certificate for the given subject alternative names.
pub fn ca_and_leaf(sans: &[&str]) -> CaLeaf {
    let ca_kp = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).expect("self-signed ca");
    let ca_pem = ca_cert.pem();

    let issuer = rcgen::Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_params =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("leaf params");
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).expect("leaf");
    CaLeaf {
        ca_pem,
        leaf_der: leaf_cert.der().as_ref().to_vec(),
        leaf_pem: leaf_cert.pem(),
        leaf_key_pem: leaf_kp.serialize_pem(),
        leaf_key_der: leaf_kp.serialize_der(),
    }
}

/// A resolver double for the reqwest reference stack that answers a SCRIPTED sequence of
/// addresses and counts how often it was consulted. The rebinding shape — first answer honest,
/// every later answer hostile — is the attack the resolve-then-pin doctrine exists to close, and
/// the count is how "the pinned client never asked" becomes an assertion.
pub struct RebindingResolver {
    first: SocketAddr,
    then: SocketAddr,
    calls: AtomicUsize,
}

impl RebindingResolver {
    pub fn new(first: SocketAddr, then: SocketAddr) -> Self {
        RebindingResolver {
            first,
            then,
            calls: AtomicUsize::new(0),
        }
    }

    /// A pure counting double: every answer is the same honest address.
    pub fn counting(addr: SocketAddr) -> Self {
        Self::new(addr, addr)
    }

    /// How many times any client asked this resolver anything.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The next scripted answer, counted: the honest address first, the hostile one after.
    fn answer(&self) -> SocketAddr {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first
        } else {
            self.then
        }
    }
}

impl reqwest::dns::Resolve for RebindingResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = self.answer();
        Box::pin(std::future::ready(Ok(
            Box::new(std::iter::once(addr)) as Box<dyn Iterator<Item = SocketAddr> + Send>
        )))
    }
}

/// The same scripted answers for the engine's resolver seam, so one double drives both stacks.
impl crate::egress::engine::ResolveNames for RebindingResolver {
    fn resolve(
        &self,
        _name: &str,
    ) -> futures::future::BoxFuture<
        'static,
        Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        Box::pin(std::future::ready(Ok(vec![self.answer()])))
    }
}

/// The loopback IP as the address family every fixture binds.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A test's scoped dial posture: its destination judge and its names.
type ScopedDial = (
    Arc<dyn crate::host_services::DestJudge>,
    Arc<dyn crate::egress::engine::ResolveNames>,
);

thread_local! {
    static SCOPED_DIAL: std::cell::RefCell<Option<ScopedDial>> =
        const { std::cell::RefCell::new(None) };
}

/// TEST SEAM: every pooled client built by `build` on this thread judges by `judge` and resolves
/// through `names`.
pub fn with_scoped_dial<R>(
    judge: Arc<dyn crate::host_services::DestJudge>,
    names: Arc<dyn crate::egress::engine::ResolveNames>,
    build: impl FnOnce() -> R,
) -> R {
    let prior = SCOPED_DIAL.with(|s| s.replace(Some((judge, names))));
    let built = build();
    SCOPED_DIAL.with(|s| *s.borrow_mut() = prior);
    built
}

/// A TEST DOUBLE of a refusing destination guard (the guard itself is the connector's, which the
/// kernel cannot name): an answer holding a private, loopback or cloud-metadata address is refused
/// unless its host or that address is in the allowlist, whatever the class. What a test proves with
/// it is the engine's side: every answer is asked of the guard, and a refusal is a connect failure.
pub struct PrivateRefusing(pub Vec<String>);

impl crate::host_services::DestJudge for PrivateRefusing {
    fn judge_name(&self, _dest: &str, _class: u32, _refuse_private: bool) -> Result<(), u64> {
        Ok(())
    }
    /// A literal is its own answer: judged as [`Self::judge_answer`] judges one; a name passes to
    /// the resolution and its answer's judgement.
    fn judge_host(&self, host: &str, class: u32) -> Result<(), crate::host_services::DestRefusal> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        match busbar_contract::net::host_ip(bare) {
            Some(ip) => self.judge_answer(host, &[ip], class),
            None => Ok(()),
        }
    }
    fn judge(
        &self,
        _dest: &str,
        _class: u32,
        _refuse_private: bool,
        _done: Box<dyn FnOnce(crate::host_services::Admitted) + Send>,
    ) -> Option<crate::host_services::Admitted> {
        Some(Err(busbar_contract::abi::host::service::DEST_NO_HOST.into()))
    }
    fn judge_answer(
        &self,
        host: &str,
        addrs: &[IpAddr],
        _class: u32,
    ) -> Result<(), crate::host_services::DestRefusal> {
        use busbar_contract::abi::host::service::{DEST_INTERNAL, DEST_METADATA};
        use busbar_contract::net::{ip_is_cloud_metadata, ip_is_internal};
        let allowed = |a: &IpAddr| self.0.iter().any(|e| *e == host || *e == a.to_string());
        for a in addrs.iter().filter(|a| !allowed(a)) {
            let verdict = if ip_is_cloud_metadata(a) {
                DEST_METADATA
            } else if ip_is_internal(a) {
                DEST_INTERNAL
            } else {
                continue;
            };
            return Err(crate::host_services::DestRefusal {
                verdict,
                reason: format!("host `{host}` resolves to the refused address {a}"),
            });
        }
        Ok(())
    }
}

/// [`PrivateRefusing`] over `allow`.
pub fn private_refusing(allow: &[&str]) -> Arc<dyn crate::host_services::DestJudge> {
    Arc::new(PrivateRefusing(
        allow.iter().map(|s| (*s).to_owned()).collect(),
    ))
}

/// The posture [`with_scoped_dial`] set on this thread, if any: what a pooled client built here
/// resolves through and judges by.
pub(crate) fn scoped_dial() -> Option<ScopedDial> {
    SCOPED_DIAL.with(|s| s.borrow().clone())
}

// ── THE TLS TEST DOUBLE ──────────────────────────────────────────────────────────────────────────

/// A TEST DOUBLE of the connector's TLS wrap (the wrap itself is the connector's, which the kernel
/// cannot name — the same posture as [`PrivateRefusing`] for the guard). No cryptography: one hello
/// line each way over the TCP stream, then the stream as it is. What a test proves with it is the
/// engine's side of the seam: the server name and the ALPN offer it hands the wrap, the extra roots
/// and the identity it asks for, the facts it reads back (the agreed protocol, the peer's leaf), and
/// how a refused handshake surfaces. Real TLS — the ClientHello on the wire, certificate verification,
/// a mutual handshake — is proven where TLS lives: the connector's own tests, its
/// `tls/engine_tests.rs` among them, which drive this engine over the connector's wrap.
#[derive(Clone, Default)]
pub struct TlsDouble {
    hellos: Arc<Mutex<Vec<DoubleHello>>>,
}

/// What one client hello through the [`TlsDouble`] carried, as the engine built it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DoubleHello {
    /// The server name the engine handed the wrap (SNI, and the name a certificate is checked
    /// against).
    pub server_name: String,
    /// The ALPN offer, in order.
    pub offer: Vec<Vec<u8>>,
    /// How many extra trust roots joined the webpki roots; `None` = the webpki roots alone.
    pub extra_roots: Option<usize>,
    /// The leaf of the identity the client was built to present.
    pub identity_leaf: Option<Vec<u8>>,
}

impl TlsDouble {
    /// The double as the layer a test hands an engine client (`EngineSpec::tls`).
    #[must_use]
    pub fn layer(&self) -> Arc<dyn crate::secure::SecureLayer> {
        Arc::new(self.clone())
    }

    /// Every hello the double's clients sent, in order.
    pub fn hellos(&self) -> Vec<DoubleHello> {
        self.hellos.lock().expect("hellos").clone()
    }
}

impl crate::secure::SecureLayer for TlsDouble {
    /// A plain PEM walk (certificates and one private key, the last key winning), enough for a test
    /// identity; the connector's walk, and its verdict parity with `reqwest::Identity::from_pem`, is
    /// proven over the real wrap (the connector's `tls/engine_tests.rs`).
    fn identity_from_pem(
        &self,
        pem: &[u8],
    ) -> Result<(Vec<Vec<u8>>, crate::secure::KeyDer), String> {
        use base64::Engine as _;
        let text = String::from_utf8_lossy(pem);
        let mut chain = Vec::new();
        let mut key = None;
        let mut rest = text.as_ref();
        while let Some(at) = rest.find("-----BEGIN ") {
            let after = &rest[at + "-----BEGIN ".len()..];
            let label_end = after.find("-----").ok_or("an unterminated PEM header")?;
            let label = &after[..label_end];
            let body_start = label_end + "-----".len();
            let end_marker = format!("-----END {label}-----");
            let body_end = after.find(&end_marker).ok_or("a PEM section with no end")?;
            let body: String = after[body_start..body_end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|e| format!("a PEM section does not decode: {e}"))?;
            match label {
                "CERTIFICATE" => chain.push(der),
                "PRIVATE KEY" => key = Some(crate::secure::KeyDer::Pkcs8(der)),
                "RSA PRIVATE KEY" => key = Some(crate::secure::KeyDer::Pkcs1(der)),
                "EC PRIVATE KEY" => key = Some(crate::secure::KeyDer::Sec1(der)),
                other => {
                    return Err(format!(
                        "a PEM section with no place in an identity: {other}"
                    ))
                }
            }
            rest = &after[body_end + end_marker.len()..];
        }
        if chain.is_empty() {
            return Err("client identity PEM holds no certificate".to_string());
        }
        let key = key.ok_or("client identity PEM holds no private key")?;
        Ok((chain, key))
    }

    fn client(
        &self,
        spec: &crate::secure::ClientTlsSpec<'_>,
    ) -> Result<Arc<dyn crate::secure::ClientTls>, String> {
        Ok(Arc::new(DoubleClient {
            offer: spec.alpn.iter().map(|p| p.to_vec()).collect(),
            extra_roots: spec.extra_roots.map(<[Vec<u8>]>::len),
            identity_leaf: spec.identity.and_then(|(chain, _)| chain.first().cloned()),
            hellos: Arc::clone(&self.hellos),
        }))
    }

    fn duplex_client(&self) -> Result<Arc<dyn crate::secure::ClientTls>, String> {
        self.client(&crate::secure::ClientTlsSpec {
            extra_roots: None,
            identity: None,
            alpn: &[],
        })
    }
}

struct DoubleClient {
    offer: Vec<Vec<u8>>,
    extra_roots: Option<usize>,
    identity_leaf: Option<Vec<u8>>,
    hellos: Arc<Mutex<Vec<DoubleHello>>>,
}

fn hex_or_dash(bytes: Option<&[u8]>) -> String {
    bytes.map_or_else(|| "-".to_string(), hex::encode)
}

fn from_hex_or_dash(word: &str) -> Option<Vec<u8>> {
    (word != "-").then(|| hex::decode(word).expect("a hello field is hex"))
}

impl crate::secure::ClientTls for DoubleClient {
    fn handshake(
        &self,
        server_name: &str,
    ) -> Result<crate::secure::Handshake, Box<dyn std::error::Error + Send + Sync>> {
        if server_name.is_empty() || server_name.contains(char::is_whitespace) {
            return Err(format!("the TLS double refuses the server name {server_name:?}").into());
        }
        let hello = DoubleHello {
            server_name: server_name.to_string(),
            offer: self.offer.clone(),
            extra_roots: self.extra_roots,
            identity_leaf: self.identity_leaf.clone(),
        };
        let hellos = Arc::clone(&self.hellos);
        Ok(Box::new(move |tcp: tokio::net::TcpStream| {
            Box::pin(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut tcp = tcp;
                let offer = if hello.offer.is_empty() {
                    "-".to_string()
                } else {
                    hello
                        .offer
                        .iter()
                        .map(|p| String::from_utf8_lossy(p).into_owned())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let roots = hello
                    .extra_roots
                    .map_or_else(|| "-".to_string(), |n| n.to_string());
                let line = format!(
                    "HELLO {} {offer} {} {roots}\n",
                    hello.server_name,
                    hex_or_dash(hello.identity_leaf.as_deref())
                );
                hellos.lock().expect("hellos").push(hello);
                tcp.write_all(line.as_bytes()).await?;
                let mut reply = Vec::new();
                let mut byte = [0_u8; 1];
                while tcp.read(&mut byte).await? == 1 && byte[0] != b'\n' {
                    reply.push(byte[0]);
                }
                let reply = String::from_utf8_lossy(&reply).into_owned();
                let mut words = reply.split(' ');
                match words.next() {
                    Some("OK") => {
                        let alpn = from_hex_or_dash(words.next().unwrap_or("-"));
                        let leaf = from_hex_or_dash(words.next().unwrap_or("-"));
                        let secured: Box<dyn crate::secure::SecuredIo> =
                            Box::new(DoubleSecured { tcp, alpn, leaf });
                        Ok(secured)
                    }
                    Some("REFUSE") => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        reply["REFUSE ".len().min(reply.len())..].to_string(),
                    )),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the TLS double's peer closed before its hello",
                    )),
                }
            }) as crate::secure::HandshakeFut
        }))
    }
}

struct DoubleSecured {
    tcp: tokio::net::TcpStream,
    alpn: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
}

impl crate::secure::SecuredIo for DoubleSecured {
    fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }
    fn peer_leaf(&self) -> Option<&[u8]> {
        self.leaf.as_deref()
    }
    fn tcp(&self) -> &tokio::net::TcpStream {
        &self.tcp
    }
}

impl tokio::io::AsyncRead for DoubleSecured {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DoubleSecured {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

/// The far end of the [`TlsDouble`]: the leaf it presents, the protocols it agrees (its own order of
/// preference, the first the client offered), whether it demands a client identity, and a handshake
/// it refuses outright with a cause of its choosing.
#[derive(Clone, Default)]
pub struct DoublePeer {
    /// The leaf presented, DER.
    pub leaf: Option<Vec<u8>>,
    /// The protocols agreed by ALPN, in preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Refuse a client that presents no identity.
    pub require_identity: bool,
    /// The client leaves (DER) this end accepts as an identity; empty = any. A presented identity
    /// that is none of them is refused as an invalid certificate, as a mutual-TLS peer refuses a
    /// client certificate chaining to a CA it does not trust.
    pub accept_only: Vec<Vec<u8>>,
    /// Refuse every handshake with this cause.
    pub refuse: Option<String>,
}

/// What the far end read off one client hello.
#[derive(Clone, Debug, Default)]
pub struct PeerHello {
    /// The server name the client sent.
    pub server_name: Option<String>,
    /// The protocol agreed.
    pub alpn: Option<Vec<u8>>,
    /// The identity leaf the client presented.
    pub client_leaf: Option<Vec<u8>>,
    /// How many extra trust roots the client joined to the webpki roots; `None` = none.
    pub extra_roots: Option<usize>,
    /// Whether the handshake completed.
    pub ok: bool,
}

impl DoublePeer {
    fn answer(&self, hello: &str) -> (PeerHello, String) {
        let mut words = hello.split(' ');
        let mut seen = PeerHello::default();
        if words.next() != Some("HELLO") {
            return (seen, "REFUSE not a hello".to_string());
        }
        seen.server_name = words.next().map(str::to_string);
        let offer: Vec<Vec<u8>> = match words.next() {
            None | Some("-") => Vec::new(),
            Some(csv) => csv.split(',').map(|p| p.as_bytes().to_vec()).collect(),
        };
        seen.client_leaf = from_hex_or_dash(words.next().unwrap_or("-"));
        seen.extra_roots = words.next().and_then(|n| n.parse().ok());
        if let Some(cause) = &self.refuse {
            return (seen, format!("REFUSE {cause}"));
        }
        if self.require_identity && seen.client_leaf.is_none() {
            return (
                seen,
                "REFUSE peer sent no certificates (the TLS double demands one)".to_string(),
            );
        }
        if let Some(leaf) = &seen.client_leaf {
            if !self.accept_only.is_empty() && !self.accept_only.contains(leaf) {
                return (
                    seen,
                    "REFUSE invalid peer certificate (the TLS double accepts other identities)"
                        .to_string(),
                );
            }
        }
        seen.alpn = self.alpn.iter().find(|p| offer.contains(p)).cloned();
        seen.ok = true;
        let reply = format!(
            "OK {} {}",
            hex_or_dash(seen.alpn.as_deref()),
            hex_or_dash(self.leaf.as_deref())
        );
        (seen, reply)
    }

    /// Answer one hello on a blocking std stream.
    pub fn accept(&self, stream: &mut std::net::TcpStream) -> PeerHello {
        let mut hello = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).is_ok_and(|n| n == 1) && byte[0] != b'\n' {
            hello.push(byte[0]);
        }
        let (seen, reply) = self.answer(&String::from_utf8_lossy(&hello));
        let _ = stream.write_all(format!("{reply}\n").as_bytes());
        let _ = stream.flush();
        seen
    }

    /// Answer one hello on a tokio stream.
    pub async fn accept_tokio(&self, stream: &mut tokio::net::TcpStream) -> PeerHello {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut hello = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).await.is_ok_and(|n| n == 1) && byte[0] != b'\n' {
            hello.push(byte[0]);
        }
        let (seen, reply) = self.answer(&String::from_utf8_lossy(&hello));
        let _ = stream.write_all(format!("{reply}\n").as_bytes()).await;
        seen
    }
}

/// A live recording server behind the [`TlsDouble`]'s far end: what each connection's hello carried
/// and the HTTP/1.1 requests it served, readable while connections are still open.
pub struct DoubleFixture {
    pub addr: SocketAddr,
    records: SharedRecords,
}

impl DoubleFixture {
    /// Snapshot of every connection's record, in accept order.
    pub fn records(&self) -> Vec<ConnRecord> {
        snapshot(&self.records)
    }

    /// Snapshot once `pred` holds, polling with a bound (a refused handshake's record can land just
    /// after the client hears the refusal). Panics at the bound.
    pub fn records_when(&self, pred: impl Fn(&[ConnRecord]) -> bool) -> Vec<ConnRecord> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let records = self.records();
            if pred(&records) {
                return records;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fixture records never settled: {records:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Spawn the recording server behind `peer`: the double's hello, then `response` to each of up to
/// `max_requests_per_connection` HTTP/1.1 requests per connection. The record's `sni`, `alpn`,
/// `client_cert` and `handshake_ok` are what the hello carried and how it ended.
pub fn spawn_double(
    peer: DoublePeer,
    response: CannedResponse,
    max_requests_per_connection: usize,
) -> DoubleFixture {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records: SharedRecords = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&records);
    let response = response.render();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let record = Arc::new(Mutex::new(ConnRecord::default()));
            recorder.lock().expect("records").push(Arc::clone(&record));
            let peer = peer.clone();
            let response = response.clone();
            std::thread::spawn(move || {
                let seen = peer.accept(&mut stream);
                {
                    let mut rec = record.lock().expect("record");
                    rec.sni = seen.server_name;
                    rec.alpn = seen.alpn;
                    rec.client_cert = seen.client_leaf;
                    rec.handshake_ok = seen.ok;
                }
                if !seen.ok {
                    return;
                }
                for _ in 0..max_requests_per_connection {
                    let Some(head) = read_one_request(&mut stream) else {
                        break;
                    };
                    {
                        let mut rec = record.lock().expect("record");
                        rec.requests += 1;
                        rec.heads.push(head);
                    }
                    if stream
                        .write_all(&response)
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    DoubleFixture { addr, records }
}

// ── the TLS wrap of a test binary no composition root boots ────────────────────────────────────

/// The egress-trust capability a test binary with no composition root installs to carry a TLS wrap:
/// the pass-through primitives (so every other answer is the one no capability gives), and `layer`.
pub struct TlsEgressTrust(pub Arc<dyn crate::secure::SecureLayer>);

impl crate::plane_host::egress_trust::EgressTrustHost for TlsEgressTrust {
    fn secure_layer(&self) -> Option<Arc<dyn crate::secure::SecureLayer>> {
        Some(Arc::clone(&self.0))
    }
}

/// TEST SEAM: carry `layer` as the wrap every client in this test binary is built over, in the
/// egress-trust capability the composition root installs at boot in a shipped process (first
/// install wins).
pub fn install_test_tls(layer: Arc<dyn crate::secure::SecureLayer>) {
    crate::plane_host::egress_trust::install_egress_trust_host(Arc::new(TlsEgressTrust(layer)));
}
