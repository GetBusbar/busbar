// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S TLS TEST KIT: the TLS far ends and the recording TLS fixture server, for the
//! tests that need a real handshake.
//! TLS stays in the connector (THE DESIGN; 1.6.0-TODO P2), so no other crate names a TLS library —
//! not even in a test — and only the composition root names the connector, so these serve the
//! root's tests (`tests/engine_tls.rs`, `root::tests::connector_h2`) and, pending the ruling the lane
//! file W3B records (Q-W3B-1), `busbar-a2a`'s real-handshake transport battery. Every type here is kernel-free (bytes, std
//! and tokio streams, the contract's `ConnectionSecurity`), so a crate whose test build links a
//! different build of the kernel than this crate does can use it all the same.
//!
//! Test machinery only: compiled under `cfg(test)` for this crate's own suite and under the
//! `test-support` feature for the dependent test binaries. Nothing in a shipped build reaches it.
//! The gate below restates, on the file itself, the gate `lib.rs` puts on `pub mod test_support;`,
//! so a per-file reader (`cargo xtask loc`) counts this file as the test machinery it is.
#![cfg(any(test, feature = "test-support"))]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::transport::wire::ConnectionSecurity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Every certificate in a PEM bundle, DER.
///
/// # Panics
/// A section that does not parse.
#[must_use]
pub fn certs_from_pem(pem: &str) -> Vec<Vec<u8>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.expect("certificate PEM").to_vec())
        .collect()
}

// ── the far end ──────────────────────────────────────────────────────────────────────────────────

/// A test far end's TLS: its certificate and key, the client CA it demands a certificate chaining
/// to (mutual TLS) when it names one, and the protocols it agrees by ALPN.
#[derive(Clone)]
pub struct ServerTls(Arc<rustls::ServerConfig>);

impl ServerTls {
    /// From DER: the chain (leaf first), the private key (PKCS#8, PKCS#1 or SEC1), the client CA
    /// certificates (none = no client certificate asked for), the ALPN protocols agreed.
    ///
    /// # Errors
    /// The material is not a usable server identity.
    pub fn new(
        chain: &[Vec<u8>],
        key: &[u8],
        client_ca: Option<&[Vec<u8>]>,
        alpn: &[&[u8]],
    ) -> Result<Self, String> {
        let key = PrivateKeyDer::try_from(key.to_vec()).map_err(|e| format!("server key: {e}"))?;
        Self::build(chain, key, client_ca, alpn)
    }

    /// [`ServerTls::new`] from PEM.
    ///
    /// # Errors
    /// The material does not parse or is not a usable server identity.
    pub fn from_pem(
        chain_pem: &str,
        key_pem: &str,
        client_ca_pem: Option<&str>,
        alpn: &[&[u8]],
    ) -> Result<Self, String> {
        let chain = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
            .map(|c| c.map(|c| c.to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("server chain: {e}"))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| format!("server key: {e}"))?;
        let client_ca = match client_ca_pem {
            Some(pem) => Some(
                CertificateDer::pem_slice_iter(pem.as_bytes())
                    .map(|c| c.map(|c| c.to_vec()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("client CA: {e}"))?,
            ),
            None => None,
        };
        Self::build(&chain, key, client_ca.as_deref(), alpn)
    }

    fn build(
        chain: &[Vec<u8>],
        key: PrivateKeyDer<'static>,
        client_ca: Option<&[Vec<u8>]>,
        alpn: &[&[u8]],
    ) -> Result<Self, String> {
        // Ring installed as the process's backend first, so the builders below read it.
        let _ = crate::tls::installed_crypto();
        let builder = rustls::ServerConfig::builder();
        let builder = match client_ca {
            None => builder.with_no_client_auth(),
            Some(cas) => {
                let mut roots = rustls::RootCertStore::empty();
                for ca in cas {
                    roots
                        .add(CertificateDer::from(ca.clone()))
                        .map_err(|e| format!("client CA: {e}"))?;
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|e| format!("client verifier: {e}"))?;
                builder.with_client_cert_verifier(verifier)
            }
        };
        let mut config = builder
            .with_single_cert(
                chain.iter().cloned().map(CertificateDer::from).collect(),
                key,
            )
            .map_err(|e| format!("server certificate: {e}"))?;
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Self(Arc::new(config)))
    }

    /// The protocols this far end agrees by ALPN, in order.
    #[must_use]
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        self.0.alpn_protocols.clone()
    }

    /// The connector's own TLS wrap ([`crate::tls::Tls`]) over this far end's config — what a
    /// listener a test serves is handed.
    #[must_use]
    pub fn security(&self) -> Arc<dyn ConnectionSecurity> {
        Arc::new(crate::tls::Tls::new(Arc::clone(&self.0)))
    }

    /// Run the server handshake on a blocking std stream. The handshake may FAIL (a client refusing
    /// the certificate, or this end refusing a client that presented no identity); the ClientHello
    /// has been read either way, so what it carried is on the session on both arms.
    ///
    /// # Errors
    /// The session could not be created at all.
    pub fn accept_std(&self, mut tcp: TcpStream) -> io::Result<StdServerSession> {
        let mut conn =
            rustls::ServerConnection::new(Arc::clone(&self.0)).map_err(io::Error::other)?;
        let refused = match conn.complete_io(&mut tcp) {
            Ok(_) => None,
            // This end's OWN reason for refusing, as the TLS stack words it.
            Err(e) => Some(
                conn.process_new_packets()
                    .err()
                    .map_or_else(|| e.to_string(), |te| te.to_string()),
            ),
        };
        Ok(StdServerSession { conn, tcp, refused })
    }

    /// Run the server handshake on a tokio stream, reading the ClientHello's ALPN offer first.
    /// `Err` when no ClientHello was read; otherwise the offer, and the handshake's outcome.
    ///
    /// # Errors
    /// No ClientHello arrived.
    pub async fn accept(
        &self,
        tcp: tokio::net::TcpStream,
    ) -> io::Result<(Vec<Vec<u8>>, io::Result<TokioServerSession>)> {
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await?;
        let offered: Vec<Vec<u8>> = start
            .client_hello()
            .alpn()
            .map(|names| names.map(<[u8]>::to_vec).collect())
            .unwrap_or_default();
        let session = start
            .into_stream(Arc::clone(&self.0))
            .await
            .map(TokioServerSession);
        Ok((offered, session))
    }
}

/// One accepted connection on a blocking std stream.
pub struct StdServerSession {
    conn: rustls::ServerConnection,
    tcp: TcpStream,
    refused: Option<String>,
}

impl StdServerSession {
    /// Whether the handshake completed.
    #[must_use]
    pub fn handshake_ok(&self) -> bool {
        self.refused.is_none()
    }

    /// Why this end refused the handshake, as the TLS stack words it.
    #[must_use]
    pub fn refusal(&self) -> Option<&str> {
        self.refused.as_deref()
    }

    /// The server name the ClientHello carried.
    #[must_use]
    pub fn sni(&self) -> Option<String> {
        self.conn.server_name().map(str::to_string)
    }

    /// The protocol ALPN agreed.
    #[must_use]
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.conn.alpn_protocol().map(<[u8]>::to_vec)
    }

    /// The certificates the client presented, leaf first (empty when none).
    #[must_use]
    pub fn peer_certs(&self) -> Vec<Vec<u8>> {
        self.conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
            .unwrap_or_default()
    }

    /// Send `close_notify` and flush it out.
    pub fn close(&mut self) {
        self.conn.send_close_notify();
        let _ = self.conn.complete_io(&mut self.tcp);
    }
}

impl Read for StdServerSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).read(buf)
    }
}

impl Write for StdServerSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.tcp).flush()
    }
}

/// One accepted connection on a tokio stream.
pub struct TokioServerSession(tokio_rustls::server::TlsStream<tokio::net::TcpStream>);

impl TokioServerSession {
    /// The protocol ALPN agreed.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.get_ref().1.alpn_protocol()
    }
}

impl AsyncRead for TokioServerSession {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TokioServerSession {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

// ── the recording TLS fixture server ─────────────────────────────────────────────────────────────

/// What one connection to a TLS fixture told the server about itself. Every field is an observation
/// a differential test compares across the two stacks.
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

/// Every connection's record, in accept order, shared with the accept thread.
#[derive(Clone, Default)]
struct Records(Arc<Mutex<Vec<Arc<Mutex<ConnRecord>>>>>);

/// Whether (and against which root) the fixture demands a client certificate.
pub enum ClientAuth {
    /// No client certificate is asked for.
    None,
    /// The handshake REQUIRES a client certificate chaining to this root; a client presenting
    /// nothing is refused by the server, which is the behaviour an mTLS upstream shows busbar.
    Required {
        /// The root, PEM.
        ca_pem: String,
    },
}

/// What a TLS fixture serves and demands.
pub struct TlsServerSpec {
    /// The server's certificate chain, PEM (leaf first).
    pub cert_chain_pem: String,
    /// The server's private key, PEM.
    pub key_pem: String,
    /// Whether a client certificate is demanded.
    pub client_auth: ClientAuth,
    /// The response every request is answered with, as written to the wire.
    pub response: Vec<u8>,
    /// How many requests one connection may carry before the fixture closes it.
    pub max_requests_per_connection: usize,
}

/// A live TLS fixture server: its dial address plus the per-connection records, readable while
/// connections are still open (a pooled client keeps its connection alive between requests, and the
/// reuse assertion must read the count mid-life).
pub struct TlsFixture {
    /// Where to dial it.
    pub addr: SocketAddr,
    records: Records,
}

impl TlsFixture {
    /// Snapshot of every connection's record, in accept order.
    ///
    /// # Panics
    /// A fixture thread panicked holding the records.
    #[must_use]
    pub fn records(&self) -> Vec<ConnRecord> {
        self.records
            .0
            .lock()
            .expect("records")
            .iter()
            .map(|r| r.lock().expect("record").clone())
            .collect()
    }

    /// Snapshot once `pred` holds, polling with a bound. A client learns about a REFUSED handshake
    /// the moment it sends its alert — often before the server thread has finished writing what it
    /// observed — so a test that asserts on a refusal's record waits for the record to settle rather
    /// than racing the fixture thread.
    ///
    /// # Panics
    /// At the bound: a record that never settles is a fixture defect, not a pass.
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

/// Spawn the recording TLS server: HTTP/1.1, pinned via ALPN, so the recorded request and
/// connection counts stay meaningful whichever client drives it. The accept loop lives on an OS
/// thread for the lifetime of the process's test run, each connection on its own thread (a pooled
/// client holding one connection open never blocks the next); ephemeral loopback ports keep
/// parallel fixtures independent.
///
/// # Panics
/// The spec's material does not make a server, or no loopback port binds.
#[must_use]
pub fn spawn_tls(spec: TlsServerSpec) -> TlsFixture {
    let client_ca = match &spec.client_auth {
        ClientAuth::None => None,
        ClientAuth::Required { ca_pem } => Some(ca_pem.as_str()),
    };
    let server = ServerTls::from_pem(
        &spec.cert_chain_pem,
        &spec.key_pem,
        client_ca,
        &[b"http/1.1"],
    )
    .expect("the fixture's server material");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let records = Records::default();
    let recorder = records.clone();
    let response = spec.response;
    let max_requests = spec.max_requests_per_connection;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let record = Arc::new(Mutex::new(ConnRecord::default()));
            recorder
                .0
                .lock()
                .expect("records")
                .push(Arc::clone(&record));
            let server = server.clone();
            let response = response.clone();
            std::thread::spawn(move || {
                serve_tls_conn(&server, stream, &record, &response, max_requests);
            });
        }
    });
    TlsFixture { addr, records }
}

fn serve_tls_conn(
    server: &ServerTls,
    stream: TcpStream,
    record: &Mutex<ConnRecord>,
    response: &[u8],
    max_requests: usize,
) {
    let Ok(mut tls) = server.accept_std(stream) else {
        return;
    };
    {
        let mut rec = record.lock().expect("record");
        rec.sni = tls.sni();
        rec.handshake_ok = tls.handshake_ok();
        rec.alpn = tls.alpn();
        rec.client_cert = tls.peer_certs().into_iter().next();
    }
    if !tls.handshake_ok() {
        return;
    }
    for _ in 0..max_requests {
        let Some(head) = read_one_request(&mut tls) else {
            break;
        };
        {
            let mut rec = record.lock().expect("record");
            rec.requests += 1;
            rec.heads.push(head);
        }
        if tls.write_all(response).and_then(|()| tls.flush()).is_err() {
            break;
        }
    }
    tls.close();
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
