// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR'S TLS WRAP, AS THE KERNEL REACHES IT. TLS stays in the connector (BUSBAR-1.6.0.md
//! THE DESIGN, the connections section: "the connector composes carrier → [secure layer] →
//! framer; the secure layer is ONE core-owned slot"; 1.6.0-TODO P2: "TLS lives only in the
//! connector (drop rustls from the kernel …)"). This crate names no TLS library: the egress
//! engine's https arm, the duplex dial's `wss` arm and the client-identity PEM parse each ask this
//! seam, and `busbar-core-connector` (which depends on this crate, never the other way) answers it.
//!
//! The answer arrives through the egress-trust capability the composition root already installs
//! once, at boot, before anything dials ([`crate::plane_host::egress_trust::EgressTrustHost::secure_layer`]):
//! the outbound trust a dial is secured with is that capability's business, so no second
//! process-wide seam is opened for it.
//!
//! What crosses is the posture a client is built for (trust anchors, a client identity, the ALPN
//! offer — plain DER and bytes) and, per dial, a connected TCP stream going in and a secured stream
//! coming out. The secured stream answers the two facts the engine reads off a handshake: the
//! protocol ALPN agreed and the peer's leaf certificate. No key type, no config type and no
//! certificate type of the TLS library is named on this side.
//!
//! A process whose capability carries no wrap (a tool, another crate's test binary) builds its
//! clients all the same; only an https or `wss` dial fails, after the TCP connect, naming the
//! missing wrap.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A client identity's private key, DER, by the PEM section it was read from.
pub enum KeyDer {
    /// `PRIVATE KEY` (PKCS#8).
    Pkcs8(Vec<u8>),
    /// `RSA PRIVATE KEY` (PKCS#1).
    Pkcs1(Vec<u8>),
    /// `EC PRIVATE KEY` (SEC1).
    Sec1(Vec<u8>),
}

impl KeyDer {
    /// The key's DER bytes.
    pub fn secret_der(&self) -> &[u8] {
        match self {
            KeyDer::Pkcs8(der) | KeyDer::Pkcs1(der) | KeyDer::Sec1(der) => der,
        }
    }

    /// Overwrite the key's bytes in place (`Zeroize for Vec<u8>`: the elements, then the length to
    /// zero, then the spare capacity).
    pub(crate) fn zeroize(&mut self) {
        use zeroize::Zeroize as _;
        match self {
            KeyDer::Pkcs8(der) | KeyDer::Pkcs1(der) | KeyDer::Sec1(der) => der.zeroize(),
        }
    }
}

/// The posture one TLS client is built for.
pub struct ClientTlsSpec<'a> {
    /// Extra trust anchors (DER) JOINING the compiled-in webpki roots; `None` = the webpki roots
    /// alone (one store shared by every client built so).
    pub extra_roots: Option<&'a [Vec<u8>]>,
    /// Busbar's own end of a mutual handshake: the chain (leaf first) and its key.
    pub identity: Option<(&'a [Vec<u8>], &'a KeyDer)>,
    /// The ALPN offer, in order; empty = no ALPN extension.
    pub alpn: &'a [&'a [u8]],
}

/// A secured (handshaken) stream, with the two facts the engine reads off its handshake.
pub trait SecuredIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {
    /// The protocol ALPN agreed; `None` when none was.
    fn alpn(&self) -> Option<&[u8]>;
    /// The peer's leaf certificate, DER, from the verified handshake.
    fn peer_leaf(&self) -> Option<&[u8]>;
    /// The TCP stream under the session (what a connection reports itself connected over).
    fn tcp(&self) -> &TcpStream;
}

/// The future one handshake runs as.
pub type HandshakeFut = Pin<Box<dyn Future<Output = std::io::Result<Box<dyn SecuredIo>>> + Send>>;

/// One handshake for one server name, run over the TCP stream it is handed once connected.
pub type Handshake = Box<dyn FnOnce(TcpStream) -> HandshakeFut + Send>;

/// A built TLS client.
pub trait ClientTls: Send + Sync {
    /// The handshake for `server_name` (the SNI offered and the name the peer's certificate is
    /// verified against). The name is checked HERE, before any socket opens; an unusable name is
    /// this call's error.
    fn handshake(&self, server_name: &str) -> Result<Handshake, BoxError>;
}

/// The connector's TLS wrap.
pub trait SecureLayer: Send + Sync {
    /// One PEM buffer holding a certificate chain and a private key, any order, read with
    /// `reqwest::Identity::from_pem` verdict parity (`ClientIdentity::from_pem`).
    fn identity_from_pem(&self, pem: &[u8]) -> Result<(Vec<Vec<u8>>, KeyDer), String>;
    /// A client for `spec`. An extra root the store refuses, or an identity the stack refuses, is
    /// this call's error.
    fn client(&self, spec: &ClientTlsSpec<'_>) -> Result<Arc<dyn ClientTls>, String>;
    /// The ONE client every duplex `wss` dial shares (webpki roots, no identity, no ALPN offer):
    /// built once and shared, as the dial's config always was, so the dials share its session
    /// store as they always did.
    fn duplex_client(&self) -> Result<Arc<dyn ClientTls>, String>;
}

/// The connector's wrap: the root-installed egress-trust capability's. A test hands an engine
/// client a TLS double of its own (`EngineSpec::tls`), or, in a test binary no composition root
/// boots, installs a capability carrying one ([`install_test_tls`]).
pub fn layer() -> Option<Arc<dyn SecureLayer>> {
    crate::plane_host::egress_trust::egress_trust_host().and_then(|host| host.secure_layer())
}

/// TEST SEAM: carry `layer` in the egress-trust capability of a test binary no composition root
/// boots (`egress::fixtures::install_test_tls`; first install wins).
#[cfg(any(test, feature = "test-support"))]
pub use crate::egress::fixtures::install_test_tls;

/// What an https or `wss` dial fails with in a process whose egress-trust capability carries no
/// TLS wrap.
pub const NO_LAYER: &str =
    "no TLS layer is installed (the composition root installs busbar-core-connector's)";
