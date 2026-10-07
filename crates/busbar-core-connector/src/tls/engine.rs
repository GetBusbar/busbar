// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TLS, served from here. The kernel names no TLS library (THE DESIGN: TLS stays in
//! the connector; 1.6.0-TODO P2 "drop rustls from the kernel"): its outbound engine's https arm, its
//! duplex dial's `wss` arm and its client-identity PEM parse ask `busbar_kernel::secure`, and
//! [`Layer`] answers that seam — the composition root hands it to the kernel inside the egress-trust
//! capability it installs once, at boot (`GuardedEgressTrust`).
//!
//! Everything here is the code that used to sit on the kernel side of that seam, moved verbatim:
//! the client config the kernel's engine built (`rustls_client_config`: the shared webpki store, the
//! explicitly-named ring backend, the safe default versions, the ALPN offer the engine states), the
//! handshake `hyper-rustls` ran for it (`TlsConnector::connect` over the dialled TCP stream, the
//! name checked before the dial), the `wss` client config the duplex dial built, and the identity
//! PEM walk (`ClientIdentity::from_pem`, `reqwest::Identity::from_pem` verdict parity).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_kernel::secure::{self as seam, ClientTlsSpec, KeyDer};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// TEST SEAM: install this module as the TLS wrap every client of THIS crate's test binary's kernel
/// is built over, where no composition root installs the egress-trust capability. Idempotent.
#[cfg(test)]
pub fn install() {
    busbar_kernel::secure::install_test_tls(Arc::new(Layer));
}

/// The PEM section a client identity's private key was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// `PRIVATE KEY` (PKCS#8).
    Pkcs8,
    /// `RSA PRIVATE KEY` (PKCS#1).
    Pkcs1,
    /// `EC PRIVATE KEY` (SEC1).
    Sec1,
}

/// A client identity read from PEM: the chain (leaf first) and the private key, by the section it
/// was read from.
pub struct PemIdentity {
    /// The certificate chain, leaf first, each one DER.
    pub chain: Vec<Vec<u8>>,
    /// The section the key was read from.
    pub kind: KeyKind,
    /// The private key, DER.
    pub key: Vec<u8>,
}

/// A client identity a client is built to present.
#[derive(Clone, Copy)]
pub struct IdentityRef<'a> {
    /// The certificate chain, leaf first, each one DER.
    pub chain: &'a [Vec<u8>],
    /// The section the key was read from.
    pub kind: KeyKind,
    /// The private key, DER.
    pub key: &'a [u8],
}

/// The connector's TLS wrap, as the kernel reaches it.
#[derive(Debug, Default, Clone, Copy)]
pub struct Layer;

impl Layer {
    /// One PEM buffer holding the certificate chain and the private key, any order —
    /// `reqwest::Identity::from_pem` verdict parity: the same `rustls-pki-types` PEM walk, the same
    /// accepted section kinds (certificates plus a PKCS#8 / PKCS#1 / SEC1 private key), the same
    /// rejections (an unparseable buffer, a section kind that has no place in an identity, no
    /// certificate, no key) and the same tolerance: a buffer carrying MORE than one private key loads
    /// with the LAST one. The error names what was missing or refused.
    ///
    /// # Errors
    ///
    /// The buffer is not a usable identity; the text says why.
    pub fn identity_from_pem(pem: &[u8]) -> Result<PemIdentity, String> {
        use rustls_pki_types::pem::{self, SectionKind};
        let mut cursor = std::io::Cursor::new(pem);
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let mut keys: Vec<(KeyKind, Vec<u8>)> = Vec::new();
        while let Some((kind, data)) = pem::from_buf(&mut cursor)
            .map_err(|e| format!("client identity PEM does not parse: {e:?}"))?
        {
            match kind {
                SectionKind::Certificate => chain.push(data),
                SectionKind::PrivateKey => keys.push((KeyKind::Pkcs8, data)),
                SectionKind::RsaPrivateKey => keys.push((KeyKind::Pkcs1, data)),
                SectionKind::EcPrivateKey => keys.push((KeyKind::Sec1, data)),
                other => {
                    return Err(format!(
                        "client identity PEM carries a section that has no place in an \
                         identity ({other:?}): expected certificates and a private key \
                         (PKCS#8, PKCS#1 or SEC1)"
                    ))
                }
            }
        }
        if chain.is_empty() {
            return Err("client identity PEM holds no certificate".to_string());
        }
        let Some((kind, key)) = keys.pop() else {
            return Err(
                "client identity PEM holds no private key (PKCS#8, PKCS#1 or SEC1)".to_string(),
            );
        };
        Ok(PemIdentity { chain, kind, key })
    }

    /// The client TLS config for one posture: webpki roots (plus `extra_roots`), the ALPN offer
    /// `alpn`, and the client identity when one is given. The crypto backend is named EXPLICITLY
    /// (`ring` — the backend reqwest's `rustls-tls` used, so the cipher-suite story is unchanged):
    /// the bare `builder()` auto-detects the process backend and PANICS AT FIRST USE when more than
    /// one backend crate is in the binary's graph — which is exactly the composed busbar binary.
    /// Explicit therefore, never ambient.
    ///
    /// # Errors
    ///
    /// An extra root the store refuses, or an identity the stack refuses; never skipped silently.
    pub fn client(
        extra_roots: Option<&[Vec<u8>]>,
        identity: Option<IdentityRef<'_>>,
        alpn: &[&[u8]],
    ) -> Result<Client, String> {
        // ONE base root store and ONE crypto backend, shared by refcount across every client shard
        // (`ClientConfig` holds both behind `Arc`s, and both builder seams take `Into<Arc<_>>`).
        // The pooled-posture builder runs ONCE PER DATA WORKER (one client shard each), and
        // `TLS_SERVER_ROOTS.to_vec()` materializes the ~150-anchor trust store on the heap — N
        // private copies of identical, immutable data was pure idle RSS scaling with core count.
        // A posture with extras builds its OWN store (the extras join the defaults, exactly
        // reqwest's `add_root_certificate` semantics) — a per-client-build cost on the cold pinned
        // path, never per request.
        static ROOTS: std::sync::OnceLock<Arc<rustls::RootCertStore>> = std::sync::OnceLock::new();
        static RING: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> =
            std::sync::OnceLock::new();
        let roots = match extra_roots {
            None => ROOTS
                .get_or_init(|| {
                    Arc::new(rustls::RootCertStore {
                        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                    })
                })
                .clone(),
            Some(extras) => {
                let mut store = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                for der in extras {
                    store.add(CertificateDer::from(der.clone())).map_err(|e| {
                        format!("an extra trust root was refused by the root store: {e}")
                    })?;
                }
                Arc::new(store)
            }
        };
        let ring = RING.get_or_init(|| Arc::new(super::ring())).clone();
        let builder = rustls::ClientConfig::builder_with_provider(ring)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions")
            .with_root_certificates(roots);
        let mut config = match identity {
            None => builder.with_no_client_auth(),
            // BUSBAR'S OWN END OF A MUTUAL HANDSHAKE. Offering a certificate ASKS FOR NOTHING and
            // WEAKENS NOTHING: it is presented only when the peer's `CertificateRequest` asks, and
            // the peer's certificate is still verified by the ordinary chain-and-name check.
            Some(identity) => builder
                .with_client_auth_cert(
                    identity
                        .chain
                        .iter()
                        .cloned()
                        .map(CertificateDer::from)
                        .collect(),
                    private_key(identity.kind, identity.key),
                )
                .map_err(|e| format!("the client identity was refused by rustls: {e}"))?,
        };
        config.alpn_protocols = alpn.iter().map(|id| id.to_vec()).collect();
        Ok(Client(tokio_rustls::TlsConnector::from(Arc::new(config))))
    }
}

/// The typed key rustls takes, from the section it was read from. A copy per CLIENT BUILD, never per
/// request; the kernel's identity keeps (and wipes) the one it parsed.
fn private_key(kind: KeyKind, der: &[u8]) -> PrivateKeyDer<'static> {
    match kind {
        KeyKind::Pkcs8 => PrivateKeyDer::Pkcs8(der.to_vec().into()),
        KeyKind::Pkcs1 => PrivateKeyDer::Pkcs1(der.to_vec().into()),
        KeyKind::Sec1 => PrivateKeyDer::Sec1(der.to_vec().into()),
    }
}

/// A built TLS client: one config, shared by every handshake it runs.
#[derive(Clone)]
pub struct Client(tokio_rustls::TlsConnector);

impl Client {
    /// The handshake for `server_name` — checked now, before any socket opens, as hyper-rustls
    /// checked it before its dial.
    ///
    /// # Errors
    ///
    /// `server_name` is not a usable server name (the TLS stack's own error).
    pub fn handshake(&self, server_name: &str) -> Result<Pending, BoxError> {
        let name = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| Box::new(e) as BoxError)?;
        Ok(Pending {
            connector: self.0.clone(),
            name,
        })
    }
}

/// One handshake, waiting for its TCP stream.
pub struct Pending {
    connector: tokio_rustls::TlsConnector,
    name: rustls_pki_types::ServerName<'static>,
}

impl Pending {
    /// Run the client handshake over `tcp`.
    ///
    /// # Errors
    ///
    /// The handshake failed; the error is the TLS stack's, unwrapped.
    pub async fn run(self, tcp: TcpStream) -> io::Result<Secured> {
        self.connector
            .connect(self.name, tcp)
            .await
            .map(Secured::over)
    }
}

/// A secured client stream, and the SPKI pin of the leaf its verified handshake produced.
pub struct Secured(tokio_rustls::client::TlsStream<TcpStream>, Option<String>);

impl Secured {
    /// The secured stream over `tls`, its peer pin computed ONCE, now: a leaf the DER walk refuses
    /// (or no leaf) leaves the pin absent, never a pass.
    fn over(tls: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        let pin = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|leaf| super::spki::pin(leaf.as_ref()).ok());
        Self(tls, pin)
    }

    /// The `sha256/<base64>` SPKI pin of the peer's leaf ([`super::spki::pin`]), or `None`.
    #[must_use]
    pub fn peer_spki(&self) -> Option<&str> {
        self.1.as_deref()
    }

    /// The protocol ALPN agreed.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.get_ref().1.alpn_protocol()
    }

    /// The peer's leaf certificate, DER.
    #[must_use]
    pub fn peer_leaf(&self) -> Option<&[u8]> {
        self.0
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(AsRef::as_ref)
    }

    /// The TCP stream under the session.
    #[must_use]
    pub fn tcp(&self) -> &TcpStream {
        self.0.get_ref().0
    }
}

impl AsyncRead for Secured {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Secured {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

// ── the bindings to the kernel's seam (the library build's traits) ──────────────────────────────

impl seam::SecureLayer for Layer {
    fn identity_from_pem(&self, pem: &[u8]) -> Result<(Vec<Vec<u8>>, KeyDer), String> {
        let PemIdentity { chain, kind, key } = Layer::identity_from_pem(pem)?;
        Ok((
            chain,
            match kind {
                KeyKind::Pkcs8 => KeyDer::Pkcs8(key),
                KeyKind::Pkcs1 => KeyDer::Pkcs1(key),
                KeyKind::Sec1 => KeyDer::Sec1(key),
            },
        ))
    }

    fn client(&self, spec: &ClientTlsSpec<'_>) -> Result<Arc<dyn seam::ClientTls>, String> {
        let identity = spec.identity.map(|(chain, key)| IdentityRef {
            chain,
            kind: match key {
                KeyDer::Pkcs8(_) => KeyKind::Pkcs8,
                KeyDer::Pkcs1(_) => KeyKind::Pkcs1,
                KeyDer::Sec1(_) => KeyKind::Sec1,
            },
            key: key.secret_der(),
        });
        Ok(Arc::new(Layer::client(
            spec.extra_roots,
            identity,
            spec.alpn,
        )?))
    }

    fn duplex_client(&self) -> Result<Arc<dyn seam::ClientTls>, String> {
        // Built once and shared by every `wss` dial, as the dial's config always was.
        static DUPLEX: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
        if let Some(client) = DUPLEX.get() {
            return Ok(Arc::new(client.clone()));
        }
        let client = Layer::client(None, None, &[])?;
        Ok(Arc::new(DUPLEX.get_or_init(|| client).clone()))
    }
}

impl seam::ClientTls for Client {
    fn handshake(&self, server_name: &str) -> Result<seam::Handshake, BoxError> {
        let pending = Client::handshake(self, server_name)?;
        Ok(Box::new(move |tcp: TcpStream| {
            Box::pin(async move {
                let secured: Box<dyn seam::SecuredIo> = Box::new(pending.run(tcp).await?);
                Ok(secured)
            }) as seam::HandshakeFut
        }))
    }
}

impl seam::SecuredIo for Secured {
    fn alpn(&self) -> Option<&[u8]> {
        Secured::alpn(self)
    }
    fn peer_spki(&self) -> Option<&str> {
        Secured::peer_spki(self)
    }
    fn tcp(&self) -> &TcpStream {
        Secured::tcp(self)
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
