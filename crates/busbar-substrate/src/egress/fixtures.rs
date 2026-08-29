// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIXTURE SERVERS for the egress differential harness — real sockets, real rustls handshakes.
//!
//! The one-egress-stack ruling is proven by DIFFERENTIAL testing: the same hop driven through the
//! owned engine and through the reqwest reference implementation must produce the same observable
//! outcome (status, body, observed peer identity, error class). These fixtures are the ground the
//! comparison stands on: a TLS server that RECORDS what each connection told it (the SNI in the
//! ClientHello, the client certificate if one was presented, how many requests rode the
//! connection), an mTLS-requiring variant, a plaintext server for the redirect canary, and
//! resolver doubles that let a test assert "the client performed no lookup of its own" as a count
//! rather than an intention.
//!
//! Everything here is test machinery: the module compiles under `cfg(test)` for this crate's own
//! suite and under the `test-support` feature for the crates whose test binaries link this one
//! (busbar-core's differential harness). Nothing in a shipped build reaches it.
//!
//! The servers speak HTTP/1.1 and pin it via ALPN, so the recorded request/connection counts stay
//! meaningful whichever client drives them (an h2 client multiplexes and would fold two requests
//! into one stream count). Each accept loop runs on a plain OS thread — no runtime coupling with
//! the client under test — and each connection is served on its own thread so a pooled client
//! holding one connection open never blocks the next one.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

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

    fn render(&self) -> Vec<u8> {
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
    /// How many HTTP requests rode this one connection — the pooled-reuse observation.
    pub requests: usize,
}

type SharedRecords = Arc<Mutex<Vec<Arc<Mutex<ConnRecord>>>>>;

/// Whether (and against which root) the fixture demands a client certificate.
pub enum ClientAuth {
    None,
    /// The handshake REQUIRES a client certificate chaining to this root; a client presenting
    /// nothing is refused by the server, which is the behaviour an mTLS upstream shows busbar.
    Required {
        ca_pem: String,
    },
}

/// What a TLS fixture serves and demands.
pub struct TlsServerSpec {
    /// The server's certificate chain, PEM (leaf first).
    pub cert_chain_pem: String,
    /// The server's private key, PEM.
    pub key_pem: String,
    pub client_auth: ClientAuth,
    pub response: CannedResponse,
    /// How many requests one connection may carry before the fixture closes it.
    pub max_requests_per_connection: usize,
}

/// A live fixture server: its dial address plus the per-connection records, readable while
/// connections are still open (a pooled client keeps its connection alive between requests, and
/// the reuse assertion must read the count mid-life).
pub struct TlsFixture {
    pub addr: SocketAddr,
    records: SharedRecords,
}

impl TlsFixture {
    /// Snapshot of every connection's record, in accept order.
    pub fn records(&self) -> Vec<ConnRecord> {
        snapshot(&self.records)
    }

    /// Snapshot once `pred` holds, polling with a bound. A client learns about a REFUSED
    /// handshake the moment it sends its alert — often before the server thread has finished
    /// writing what it observed — so a test that asserts on a refusal's record waits for the
    /// record to settle rather than racing the fixture thread. Panics at the bound: a record
    /// that never settles is a fixture defect, not a pass.
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

/// A live plaintext fixture: request lines and connection records for the redirect canary and the
/// status/body parity rows.
pub struct HttpFixture {
    pub addr: SocketAddr,
    records: SharedRecords,
    request_lines: Arc<Mutex<Vec<String>>>,
}

impl HttpFixture {
    pub fn records(&self) -> Vec<ConnRecord> {
        snapshot(&self.records)
    }

    /// Every request line the fixture served, across all connections.
    pub fn request_lines(&self) -> Vec<String> {
        self.request_lines.lock().expect("request lines").clone()
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

/// Spawn the recording TLS server. The accept loop lives on an OS thread for the lifetime of the
/// process's test run; ephemeral loopback ports keep parallel fixtures independent.
pub fn spawn_tls(spec: TlsServerSpec) -> TlsFixture {
    let config = Arc::new(server_config(&spec));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records: SharedRecords = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&records);
    let response = spec.response.render();
    let max_requests = spec.max_requests_per_connection;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let record = Arc::new(Mutex::new(ConnRecord::default()));
            recorder.lock().expect("records").push(Arc::clone(&record));
            let config = Arc::clone(&config);
            let response = response.clone();
            std::thread::spawn(move || {
                serve_tls_conn(stream, config, record, &response, max_requests);
            });
        }
    });
    TlsFixture { addr, records }
}

fn serve_tls_conn(
    mut stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    record: Arc<Mutex<ConnRecord>>,
    response: &[u8],
    max_requests: usize,
) {
    let Ok(mut conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    // Drive the handshake. It may FAIL (a client refusing the certificate, or the server refusing
    // a client that presented no identity); the ClientHello has been read either way, so the SNI
    // is recorded on both arms.
    let handshake = conn.complete_io(&mut stream);
    {
        let mut rec = record.lock().expect("record");
        rec.sni = conn.server_name().map(str::to_string);
        rec.handshake_ok = handshake.is_ok();
        rec.client_cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|leaf| leaf.as_ref().to_vec());
    }
    if handshake.is_err() {
        return;
    }
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
    for _ in 0..max_requests {
        if read_one_request(&mut tls).is_none() {
            break;
        }
        record.lock().expect("record").requests += 1;
        if tls.write_all(response).and_then(|()| tls.flush()).is_err() {
            break;
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut stream);
}

/// Spawn the plaintext recording server.
pub fn spawn_http(response: CannedResponse, max_requests_per_connection: usize) -> HttpFixture {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records: SharedRecords = Arc::new(Mutex::new(Vec::new()));
    let request_lines = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&records);
    let lines = Arc::clone(&request_lines);
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
            let response = response.clone();
            std::thread::spawn(move || {
                for _ in 0..max_requests_per_connection {
                    let Some(line) = read_one_request(&mut stream) else {
                        break;
                    };
                    lines.lock().expect("lines").push(line);
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
    }
}

/// Read one HTTP/1.1 request off the stream: the head to its blank line, then exactly
/// `content-length` body bytes so the next read starts at the next request. Returns the request
/// line, or `None` on a closed/broken connection.
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
    Some(head_text.lines().next().unwrap_or_default().to_string())
}

/// The fixture server's rustls config: ring provider named explicitly (the composed test binary
/// carries more than one provider crate, and the bare builder panics on ambiguity), HTTP/1.1
/// pinned via ALPN.
fn server_config(spec: &TlsServerSpec) -> rustls::ServerConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = certs_from_pem(&spec.cert_chain_pem);
    let key = PrivateKeyDer::from_pem_slice(spec.key_pem.as_bytes()).expect("server key PEM");
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions");
    let builder = match &spec.client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Required { ca_pem } => {
            let mut roots = rustls::RootCertStore::empty();
            for der in certs_from_pem(ca_pem) {
                roots.add(der).expect("client CA root");
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .expect("client verifier");
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .expect("server certificate");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Parse every certificate in a PEM bundle to DER.
pub fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM")
}

/// A throw-away CA plus a leaf it signed for `sans` — the private-CA / known-leaf server material.
pub struct CaLeaf {
    pub ca_pem: String,
    pub leaf_pem: String,
    pub leaf_key_pem: String,
    /// The leaf DER, for computing the expected SPKI pin outside the stack under test.
    pub leaf_der: Vec<u8>,
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
}

impl reqwest::dns::Resolve for RebindingResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let addr = if n == 0 { self.first } else { self.then };
        Box::pin(std::future::ready(Ok(
            Box::new(std::iter::once(addr)) as Box<dyn Iterator<Item = SocketAddr> + Send>
        )))
    }
}

/// The loopback IP as the address family every fixture binds.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
