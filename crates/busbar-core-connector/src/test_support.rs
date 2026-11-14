// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S TLS TEST KIT: the TLS far ends, for the

#![cfg(any(test, feature = "test-support"))]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[path = "test_support_adoption.rs"]
mod adoption;
pub use adoption::observe_adoption;

/// A real held datagram upstream for composition-root tests. Its exchange, writer, reader and
pub(crate) struct DatagramSession(crate::dialled::Dialled);

impl DatagramSession {
    /// Hold a begun association until its exchange settles it and attaches its actual leg.
    #[must_use]
    pub fn new(
        framing: crate::datagram::DatagramFraming,
        port: crate::udp::ReadyPort,
        pairing: Arc<crate::datagram::Pairing>,
    ) -> Self {
        Self(crate::dialled::Dialled::new(framing, port, pairing, None))
    }

    /// Feed an actual exchange piece through the held upstream's admission path.
    pub fn exchanged(
        &self,
        piece: busbar_contract::conn::Piece,
        bytes: &[u8],
    ) -> Result<Option<busbar_contract::conn::Piece>, busbar_contract::conn::ConnError> {
        self.0.exchanged(piece, bytes)
    }

    /// Consume the next upstream channel piece, retaining partial-read storage in the real leg.
    pub fn read(
        &self,
        waker: &std::task::Waker,
        bytes: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.0.read(waker, bytes)
    }

    /// Offer application input to the actual bounded upstream writer.
    pub fn write(
        &self,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        self.0.write(bytes, end, text)
    }

    /// Register the actual upstream reader's interest.
    #[must_use]
    pub fn ready(&self, waker: &std::task::Waker) -> bool {
        self.0.ready(waker)
    }

    /// Close both legs through the real session's close path.
    pub fn close(&self) {
        self.0.close();
    }
}

impl Drop for DatagramSession {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// The default association's actual conservative pre-crossing reservation, including lease
#[must_use]
pub fn datagram_output_reservation_bytes() -> usize {
    let copied = crate::framer::Buffers::default()
        .retention_bound()
        .expect("default copied-output layout fits usize");
    let routed = crate::datagram::ROUTES_CAP * crate::framer::WIRE_CAP * 3;
    crate::publication::Memory::reservation_size(copied + routed)
        .expect("default reservation layout fits usize")
}

/// A private test CA and a `localhost` leaf it signed: the CA's certificate as PEM (what a suite's
/// test trust anchors are), the leaf's certificate and its private key, DER (what a far end serves
/// with [`ServerTls::new`]).
#[derive(Debug, Clone)]
pub struct TestCa {
    /// The CA certificate, PEM.
    pub ca_pem: String,
    /// The `localhost` leaf certificate, DER.
    pub leaf_der: Vec<u8>,
    /// The leaf's private key, PKCS#8 DER.
    pub key_der: Vec<u8>,
}

/// A fresh [`TestCa`].
#[must_use]
pub fn private_ca() -> TestCa {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().expect("a CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).expect("the CA certificate");
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let kp = KeyPair::generate().expect("a leaf key");
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("leaf params")
        .signed_by(&kp, &issuer)
        .expect("the leaf certificate");
    TestCa {
        ca_pem: ca.pem(),
        leaf_der: leaf.der().to_vec(),
        key_der: kp.serialize_der(),
    }
}

/// Every certificate in a PEM bundle, DER.
#[must_use]
pub fn certs_from_pem(pem: &str) -> Vec<Vec<u8>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.expect("certificate PEM").to_vec())
        .collect()
}

/// A test far end's TLS: its certificate and key, the client CA it demands a certificate chaining
/// to (mutual TLS) when it names one, and the protocols it agrees by ALPN.
#[derive(Clone)]
pub struct ServerTls(Arc<rustls::ServerConfig>);

impl ServerTls {
    /// From DER: the chain (leaf first), the private key (PKCS#8, PKCS#1 or SEC1), the client CA
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

    /// Run the server handshake on a blocking std stream. The handshake may FAIL (a client refusing
    pub fn accept_std(&self, mut tcp: TcpStream) -> io::Result<StdServerSession> {
        let mut conn =
            rustls::ServerConnection::new(Arc::clone(&self.0)).map_err(io::Error::other)?;
        let refused = match conn.complete_io(&mut tcp) {
            Ok(_) => None,

            Err(e) => Some(
                conn.process_new_packets()
                    .err()
                    .map_or_else(|| e.to_string(), |te| te.to_string()),
            ),
        };
        Ok(StdServerSession { conn, tcp, refused })
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
