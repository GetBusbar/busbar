// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REGISTRATION'S PEER-KEY PIN AND CLIENT IDENTITY, END TO END THROUGH THE HOST (the transport pin,
//! ARCHITECT 2026-10-03: "the connector enforces pins itself"): a registration written as an
//! operator writes it, read by the host's one reader of its anchors ([`super::registration_anchors`])
//! under the trust keys and the `trust_from` path a REAL linked plane door states, sealed on the
//! in-tree connector over this build's linked wires, and dialled over real TLS to a far end on
//! loopback.
//!
//! * A far end whose certificate's key is not the one a `cert_spki` pin names is refused after its
//!   handshake and before a request byte is written; the matching pin is reached.
//! * An `mtls` registration's `client_identity` (`{cert, key}`, secret references the host
//!   resolves) is presented in the handshake, and a far end that requires a client certificate
//!   accepts it. With no identity sealed, the host does not refuse the dial: the far end refuses the
//!   handshake (the plane's own section reading is what refuses `mtls` without `client_identity:`).
//!
//! The plane door is found by what its Statement states (a pin mechanism that pins the far end's key
//! and a member-target need whose `trust_from` names a member path), never by name.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::conn::{
    ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::transport::trust::{key_pin, Anchors, EgressTrust};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::registry::Transports;
use busbar_core_connector::{process, Connector, DEFAULT_CLASS};
use busbar_kernel::config::Destinations;
use rcgen::PublicKeyData as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::root::loader::dispatch::kinds::plane::{Plane, ServedFacts};

const OWNER: InstanceId = InstanceId(7);

/// What the far end saw on one connection: `None`, its handshake failed; else whether the dialler
/// presented a client certificate, and every request byte it read before the dialler's head ended
/// or the dialler left.
type Saw = Option<(bool, Vec<u8>)>;

/// The linked plane door whose Statement seals a peer-key pin and a client identity per
/// registration, bound on a probe: what it states, and the member-target need whose `trust_from`
/// names the registration's client identity.
fn sealing_plane() -> (ServedFacts, NeedId) {
    use crate::root::loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    let probe = Dispatcher::new(DispatchConfig::default());
    crate::LINKED
        .plane_doors
        .iter()
        .find_map(|door| {
            let row = LinkedRow::of(*door).ok()?;
            let served = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("registration-pin-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: probe.adopter(),
                    conns: ConnTable::Probe,
                },
            )
            .ok()?
            .served();
            let pins_key = served
                .trust_keys
                .iter()
                .any(|k| k.mechanisms.iter().any(|m| m.peer_key));
            let need = served
                .need_targets
                .iter()
                .zip(&served.need_trust)
                .position(|(target, trust)| {
                    busbar_contract::section::member_target(target).is_some()
                        && busbar_contract::section::member_target(trust).is_some()
                })?;
            let need = NeedId(u32::try_from(need).ok()?);
            pins_key.then_some((served, need))
        })
        .expect("a linked plane door seals a peer-key pin and a client identity per registration")
}

/// The registration key a pin is written under, and the mechanism tokens that pin the far end's
/// key, as `served` declares them.
fn pin_key(served: &ServedFacts) -> (&'static str, Vec<&'static str>) {
    let decl = served
        .trust_keys
        .iter()
        .find(|k| k.mechanisms.iter().any(|m| m.peer_key))
        .expect("a pin key");
    let peer = decl
        .mechanisms
        .iter()
        .filter(|m| m.peer_key)
        .map(|m| m.token)
        .collect();
    (decl.key, peer)
}

/// A test root and one leaf it issued: the leaf's PEM chain, its key's PEM, and its key's pin
/// taken off the key pair itself (never off the certificate the connector walks).
struct Issued {
    der: Vec<u8>,
    pem: String,
    key_der: Vec<u8>,
    key_pem: String,
    pin: String,
}

/// A private CA: its DER, and the leaves it issues.
struct Pki {
    ca_der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("a CA key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("the CA");
        Self {
            ca_der: ca.der().to_vec(),
            issuer: rcgen::Issuer::new(ca_params, ca_key),
        }
    }

    fn leaf(&self, name: &str) -> Issued {
        let kp = rcgen::KeyPair::generate().expect("a leaf key");
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .expect("leaf params")
            .signed_by(&kp, &self.issuer)
            .expect("the leaf");
        Issued {
            der: cert.der().to_vec(),
            pem: cert.pem(),
            key_der: kp.serialize_der(),
            key_pem: kp.serialize_pem(),
            pin: key_pin(&kp.subject_public_key_info()),
        }
    }
}

/// A TLS far end on loopback serving `leaf` (requiring a client certificate under `pki`'s root when
/// `mutual`), agreeing `http/1.1`, answering `200 ok` to a whole request head: its port, and what
/// it saw on each connection, reported once that connection is done.
async fn far_end(pki: &Pki, leaf: &Issued, mutual: bool) -> (u16, UnboundedReceiver<Saw>) {
    busbar_core_connector::tls::install_crypto_provider();
    let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
    let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key_der.clone()).expect("a key");
    let builder = rustls::ServerConfig::builder();
    let mut config = if mutual {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(pki.ca_der.clone()))
            .expect("the root");
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("a client verifier");
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    }
    .with_single_cert(chain, key)
    .expect("a server config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let (tx, rx) = unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(s).await else {
                    let _ = tx.send(None);
                    return;
                };
                let presented = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|c| !c.is_empty());
                let mut got = Vec::new();
                let mut buf = [0_u8; 4096];
                let ended = |got: &[u8]| got.windows(4).any(|w| w == b"\r\n\r\n");
                while !ended(&got) {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                if ended(&got) {
                    let answer =
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                    let _ = tls.write_all(answer).await;
                    let _ = tls.shutdown().await;
                }
                let _ = tx.send(Some((presented, got)));
            });
        }
    });
    (port, rx)
}

/// The in-tree connector over this build's linked wires, judging with a guard that admits
/// loopback, trusting `pki`'s root, with `need` declared on the transport `served` states for it.
fn connector(pki: &Pki, served: &ServedFacts, need: NeedId) -> Connector {
    let dest = crate::root::connector::guard_for(&Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    })
    .expect("the guard");
    let view = Transports::new(
        crate::root::connector::entries(
            crate::LINKED_TRANSPORT_DOORS,
            &TransportSettings::default(),
        )
        .expect("the linked doors open"),
    )
    .expect("the view");
    let tls = busbar_core_connector::tls::client::build_client_config(&EgressTrust {
        extra_anchors: vec![pki.ca_der.clone()],
        ..EgressTrust::default()
    })
    .expect("the trust");
    let c = Connector::serving(
        view,
        process::judge(dest, &[]),
        Some(Arc::new(tls)),
        Arc::new(|_, _| {}),
    );
    let transport = served.need_transports[need.0 as usize];
    c.declare_need(OWNER, need, transport, DEFAULT_CLASS)
        .expect("a linked wire serves the need");
    c
}

/// A PEM file of this test's own holding `value`: its path.
fn pem_on_disk(name: &str, value: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-registration-pin-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    path
}

/// A registration as an operator writes it: its target at `url`, its pin `{mechanism, key}`, and,
/// when given, its client identity `{cert: {file}, key: {file}}` under the key `served`'s
/// `trust_from` names for `need`.
fn registration(
    served: &ServedFacts,
    need: NeedId,
    url: &str,
    (mechanism, key): (&str, &str),
    identity: Option<(&Path, &Path)>,
) -> serde_yaml::Value {
    use serde_yaml::{Mapping, Value};
    let at = need.0 as usize;
    let target =
        busbar_contract::section::member_target(served.need_targets[at]).expect("a target");
    let trust =
        busbar_contract::section::member_target(served.need_trust[at]).expect("a trust path");
    // A file secret reference, built by the contract's own constructor and written as it
    // serializes (`{module, settings}`, a spelling the reference's reader accepts).
    let file = |p: &Path| -> Value {
        serde_yaml::to_value(busbar_contract::secret_ref::SecretRef::file(
            p.display().to_string(),
        ))
        .expect("a secret reference")
    };
    let mut pin = Mapping::new();
    pin.insert("mechanism".into(), mechanism.into());
    pin.insert("key".into(), key.into());
    let mut r = Mapping::new();
    r.insert(target.into(), url.into());
    r.insert(pin_key(served).0.into(), Value::Mapping(pin));
    if let Some((cert, private)) = identity {
        let mut id = Mapping::new();
        id.insert("cert".into(), file(cert));
        id.insert("key".into(), file(private));
        r.insert(trust.into(), Value::Mapping(id));
    }
    Value::Mapping(r)
}

/// Read `entry`'s anchors off `registration` through the host's one reader, and seal them on `c`
/// for `need` at `origin`, as the composition seals a registration member's.
fn seal(
    c: &Connector,
    served: &ServedFacts,
    need: NeedId,
    entry: &str,
    origin: &str,
    registration: &serde_yaml::Value,
) -> Anchors {
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let anchors = super::registration_anchors(entry, registration, need, served, &secrets)
        .expect("the registration's anchors read");
    c.anchor(OWNER, need, entry, origin, &anchors)
        .expect("the anchors seal");
    anchors
}

/// One GET over `need` to `url` naming registration `entry`, read to its end: the connection (when
/// it opened) and the status and body, or the refusal.
async fn exchange(
    c: &Connector,
    need: NeedId,
    url: &str,
    entry: &str,
) -> (Option<ConnId>, Result<(Option<u32>, Vec<u8>), ConnError>) {
    let desc = OpenDesc {
        target: url,
        method: b"GET",
        head_target: b"/agent",
        timeout_ms: 5_000,
        member: entry,
        ..OpenDesc::default()
    };
    let conn = match c.open(OWNER, need, &desc) {
        Ok(conn) => conn,
        Err(e) => return (None, Err(e)),
    };
    let (mut status, mut body) = (None, Vec::new());
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let piece = tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
        )
        .await
        .expect("the connector answers the exchange");
        match piece {
            Err(e) => return (Some(conn), Err(e)),
            Ok(p) => match p.kind {
                PieceKind::Completion => return (Some(conn), Ok((status, body))),
                PieceKind::Fields if status.is_none() => status = p.status_code,
                PieceKind::Body => body.extend_from_slice(&buf[..p.len]),
                _ => {}
            },
        }
    }
}

/// What the far end saw on the connection it finished next.
async fn saw(rx: &mut UnboundedReceiver<Saw>) -> Saw {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the far end reports the connection")
        .expect("the far end runs")
}

/// RED-AND-GREEN, THE PEER-KEY PIN THROUGH THE HOST: a registration pinning the key the far end
/// serves is reached, and the connection's facts carry that key; another registration of the same
/// section at the same far end, pinning a key the far end does not serve (a valid chain under the
/// trusted root, the right name), is refused after the handshake and before any request byte
/// reaches the far end, its facts still naming the key the far end served.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_registrations_peer_key_pin_refuses_a_far_end_serving_another_key_and_reaches_its_own() {
    let (served, need) = sealing_plane();
    let (_, peer) = pin_key(&served);
    assert!(
        peer.contains(&"cert_spki") && peer.contains(&"mtls"),
        "the plane's `cert_spki` and `mtls` pin the far end's key: {peer:?}"
    );
    let pki = Pki::new();
    let leaf = pki.leaf("127.0.0.1");
    let never_served = pki.leaf("127.0.0.1");
    let (port, mut rx) = far_end(&pki, &leaf, false).await;
    let origin = format!("https://127.0.0.1:{port}");
    let url = format!("{origin}/agent");
    let c = connector(&pki, &served, need);

    let matching = registration(&served, need, &url, ("cert_spki", &leaf.pin), None);
    let anchors = seal(&c, &served, need, "pinned", &origin, &matching);
    assert_eq!(anchors.key_pin.as_deref(), Some(leaf.pin.as_str()));
    let (conn, got) = exchange(&c, need, &url, "pinned").await;
    let conn = conn.expect("the matching pin opens");
    assert_eq!(
        got,
        Ok((Some(200), b"ok".to_vec())),
        "the matching pin is reached"
    );
    let facts = c.facts(OWNER, conn).expect("the facts");
    assert_eq!(facts.peer_key_pin.as_deref(), Some(leaf.pin.as_str()));
    assert!(!facts.client_identity, "no identity is sealed");
    c.close(OWNER, conn).expect("closed");
    let (presented, bytes) = saw(&mut rx).await.expect("the handshake completed");
    assert!(!presented);
    assert!(bytes.starts_with(b"GET /agent "), "{bytes:?}");

    let mismatched = registration(&served, need, &url, ("cert_spki", &never_served.pin), None);
    seal(&c, &served, need, "mispinned", &origin, &mismatched);
    let (conn, got) = exchange(&c, need, &url, "mispinned").await;
    assert_eq!(
        got,
        Err(ConnError::Refused),
        "a far end serving another key is refused"
    );
    let conn = conn.expect("the open was refused at its handshake, not before");
    let facts = c.facts(OWNER, conn).expect("the facts after the refusal");
    assert_eq!(
        facts.peer_key_pin.as_deref(),
        Some(leaf.pin.as_str()),
        "the refusal was the pin's: the far end served its own key"
    );
    c.close(OWNER, conn).expect("closed");
    assert!(
        saw(&mut rx).await.is_none_or(|(_, bytes)| bytes.is_empty()),
        "no request byte reached the far end"
    );
}

/// RED-AND-GREEN, `mtls` THROUGH THE HOST: a registration whose `client_identity` names its
/// certificate and key as secret references is resolved by the host, sealed, and presented in the
/// handshake; a far end requiring a client certificate accepts it and is reached. A registration of
/// the same section pinning the same key with NO identity is not refused by the host (its anchors
/// carry the pin alone): the far end refuses the handshake, and nothing it serves is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_mtls_registration_presents_its_client_identity_and_one_with_none_is_refused_by_the_far_end(
) {
    let (served, need) = sealing_plane();
    let pki = Pki::new();
    let leaf = pki.leaf("127.0.0.1");
    let client = pki.leaf("busbar.client");
    let (port, mut rx) = far_end(&pki, &leaf, true).await;
    let origin = format!("https://127.0.0.1:{port}");
    let url = format!("{origin}/agent");
    let c = connector(&pki, &served, need);
    let cert = pem_on_disk("client-cert", &client.pem);
    let key = pem_on_disk("client-key", &client.key_pem);

    let mutual = registration(
        &served,
        need,
        &url,
        ("mtls", &leaf.pin),
        Some((cert.as_path(), key.as_path())),
    );
    let anchors = seal(&c, &served, need, "mutual", &origin, &mutual);
    assert_eq!(
        anchors
            .client_identity
            .as_ref()
            .map(|i| i.cert_chain.clone()),
        Some(vec![client.der.clone()]),
        "the host resolved the identity's certificate reference"
    );
    let (conn, got) = exchange(&c, need, &url, "mutual").await;
    let conn = conn.expect("the open");
    assert_eq!(
        got,
        Ok((Some(200), b"ok".to_vec())),
        "the mutual far end accepts it"
    );
    let facts = c.facts(OWNER, conn).expect("the facts");
    assert!(facts.client_identity, "the identity was presented");
    assert_eq!(facts.peer_key_pin.as_deref(), Some(leaf.pin.as_str()));
    c.close(OWNER, conn).expect("closed");
    let (presented, bytes) = saw(&mut rx).await.expect("the handshake completed");
    assert!(presented, "the far end saw busbar's client certificate");
    assert!(bytes.starts_with(b"GET /agent "), "{bytes:?}");

    let bare = registration(&served, need, &url, ("cert_spki", &leaf.pin), None);
    let anchors = seal(&c, &served, need, "bare", &origin, &bare);
    assert!(
        anchors.client_identity.is_none() && anchors.key_pin.is_some(),
        "the host seals the pin alone and does not refuse the registration"
    );
    let (conn, got) = exchange(&c, need, &url, "bare").await;
    assert!(got.is_err(), "no identity: the exchange fails ({got:?})");
    if let Some(conn) = conn {
        c.close(OWNER, conn).expect("closed");
    }
    assert_eq!(
        saw(&mut rx).await,
        None,
        "the far end refused the handshake: no client certificate was presented"
    );
    let _ = std::fs::remove_file(&cert);
    let _ = std::fs::remove_file(&key);
}
