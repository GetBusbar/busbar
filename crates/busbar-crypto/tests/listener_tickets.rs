// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R56 `shared-ticketer` and R57 `raw-ticketer` (TRANSPORT-TLS T1): session tickets
//! come from the facade only as a `ListenerTickets`, one per listener config, never as a raw
//! `ProducesTickets`. A ticket one listener sealed resumes on that listener and on no other.

use std::sync::Arc;

use busbar_contract::crypto::tls::{self, ListenerTickets};
use rustls::{ClientConnection, HandshakeKind, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

const CA: &[u8] = include_bytes!("../fixtures/ca.der");
const LEAF: &[u8] = include_bytes!("../fixtures/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("../fixtures/leaf.key.der");

/// One listener's config: its own `ListenerTickets`, installed the only way the facade allows.
fn listener(label: &str) -> Arc<ServerConfig> {
    let tickets = ListenerTickets::new(label).expect("the backend issues session tickets");
    tls::server_config(move |b| {
        let chain = vec![
            CertificateDer::from(LEAF.to_vec()),
            CertificateDer::from(CA.to_vec()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(LEAF_KEY.to_vec()));
        let mut c = b.with_no_client_auth().with_single_cert(chain, key)?;
        tickets.install(&mut c);
        Ok(c)
    })
    .expect("server config")
}

fn client() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(CA.to_vec())).unwrap();
    let verifier = tls::server_verifier(Arc::new(roots)).unwrap();
    tls::client_config(|b| Ok(b.with_webpki_verifier(verifier).with_no_client_auth())).unwrap()
}

/// Shuttle records both ways until neither side has anything left to write (so the client has
/// read the server's post-handshake NewSessionTicket messages), and say how the client connected.
fn connect(client: &Arc<rustls::ClientConfig>, server: &Arc<ServerConfig>) -> HandshakeKind {
    let name = ServerName::try_from("localhost").unwrap();
    let mut c = ClientConnection::new(client.clone(), name).unwrap();
    let mut s = ServerConnection::new(server.clone()).unwrap();
    for _ in 0..20 {
        let mut moved = false;
        if c.wants_write() {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
            moved = true;
        }
        if s.wants_write() {
            let mut buf = Vec::new();
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets().unwrap();
            moved = true;
        }
        if !moved && !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
    }
    assert!(!c.is_handshaking() && !s.is_handshaking());
    c.handshake_kind().expect("handshake finished")
}

#[test]
fn a_ticket_resumes_on_the_listener_that_sealed_it() {
    let data = listener("data");
    let client = client();
    assert_eq!(connect(&client, &data), HandshakeKind::Full);
    assert_eq!(connect(&client, &data), HandshakeKind::Resumed);
}

#[test]
fn a_ticket_never_crosses_listeners() {
    let data = listener("data");
    let admin = listener("admin");
    let client = client();
    assert_eq!(connect(&client, &data), HandshakeKind::Full);
    // The admin listener has its own key domain: the data listener's ticket opens nothing there.
    assert_eq!(connect(&client, &admin), HandshakeKind::Full);
}
