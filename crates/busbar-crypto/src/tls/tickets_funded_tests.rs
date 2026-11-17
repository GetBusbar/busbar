// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicU8, AtomicUsize};

struct TestClock;
impl Clock for TestClock {
    fn now_ns(&self) -> u64 {
        1
    }
}

#[derive(Debug)]
struct Controlled {
    inner: Arc<dyn ProducesTickets>,
    mode: AtomicU8,
    calls: AtomicUsize,
}
impl ProducesTickets for Controlled {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }
    fn supports_bounded_output(&self) -> bool {
        self.inner.supports_bounded_output()
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        panic!("bounded connection called the legacy ticket producer")
    }
    fn encrypt_bounded(
        &self,
        plain: &[u8],
        storage: &rustls::TicketStorage<'_>,
    ) -> Result<Option<rustls::TicketBuffer>, rustls::OutputStorageError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.mode.load(Ordering::Relaxed) {
            0 => Ok(None),
            1 => Err(rustls::OutputStorageError::Limit),
            _ => self.inner.encrypt_bounded(plain, storage),
        }
    }
    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        self.inner.decrypt(ticket)
    }
}

fn configs(
    version: &'static rustls::SupportedProtocolVersion,
    ticketer: Arc<dyn ProducesTickets>,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let crate::testing::rcgen::CertifiedKey { cert, signing_key } =
        crate::testing::rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(super::super::provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
    let mut server = rustls::ServerConfig::builder_with_provider(super::super::provider())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    client.cert_compressors.clear();
    server.cert_compressors.clear();
    client.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    server.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    server.ticketer = ticketer;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let plan = super::super::write_progress::output_plan().unwrap();
    super::super::write_progress::configure_client(&mut client, plan).unwrap();
    super::super::write_progress::configure_server(&mut server, plan).unwrap();
    (Arc::new(client), Arc::new(server))
}

fn connect(
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
) -> Result<rustls::HandshakeKind, rustls::Error> {
    let mut client = rustls::ClientConnection::new(client, "localhost".try_into().unwrap())?;
    let mut server = rustls::ServerConnection::new(server)?;
    for _ in 0..100 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        if !wire.is_empty() {
            server.read_tls(&mut wire.as_slice()).unwrap();
            server.process_new_packets()?;
        }
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        if !wire.is_empty() {
            client.read_tls(&mut wire.as_slice()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            let kind = client.handshake_kind().unwrap();
            assert_eq!(server.handshake_kind(), Some(kind));
            return Ok(kind);
        }
    }
    panic!("ticket handshake did not finish");
}

#[test]
fn bounded_sealed_tickets_preserve_key_failure_recovery_and_actual_resumption() {
    for &version in b::TLS_VERSIONS {
        let inner = Arc::new(Controlled {
            inner: b::ticketer().unwrap(),
            mode: AtomicU8::new(0),
            calls: AtomicUsize::new(0),
        });
        let sealed = Arc::new(Sealed::new(inner.clone(), "funded-test", TestClock));
        let (client, server) = configs(version, sealed.clone());
        assert_eq!(
            connect(client.clone(), server.clone()).unwrap(),
            rustls::HandshakeKind::Full
        );
        assert!(sealed.failing.load(Ordering::Relaxed));
        inner.mode.store(2, Ordering::Relaxed);
        assert_eq!(
            connect(client.clone(), server.clone()).unwrap(),
            rustls::HandshakeKind::Full
        );
        assert!(!sealed.failing.load(Ordering::Relaxed));
        assert_eq!(
            connect(client, server).unwrap(),
            rustls::HandshakeKind::Resumed
        );
        assert!(inner.calls.load(Ordering::Relaxed) >= 3);
    }
}

#[test]
fn bounded_storage_failure_is_terminal_without_a_key_outage_warning() {
    for &version in b::TLS_VERSIONS {
        let inner = Arc::new(Controlled {
            inner: b::ticketer().unwrap(),
            mode: AtomicU8::new(1),
            calls: AtomicUsize::new(0),
        });
        let sealed = Arc::new(Sealed::new(inner.clone(), "funded-test", TestClock));
        let (client, server) = configs(version, sealed.clone());
        assert!(matches!(
            connect(client, server),
            Err(rustls::Error::OutputStorage(
                rustls::OutputStorageError::Limit
            ))
        ));
        assert!(!sealed.failing.load(Ordering::Relaxed));
        assert!(inner.calls.load(Ordering::Relaxed) > 0);
    }
}
