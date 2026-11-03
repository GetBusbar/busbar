// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

type Saw = Option<(bool, Vec<u8>)>;

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

struct Issued {
    der: Vec<u8>,
    pem: String,
    key_der: Vec<u8>,
    key_pem: String,
    pin: String,
}

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

fn pem_on_disk(name: &str, value: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-registration-pin-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    path
}

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

fn seal(
    c: &Connector,
    served: &ServedFacts,
    need: NeedId,
    entry: &str,
    origin: &str,
    registration: &serde_yaml::Value,
) -> Anchors {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let anchors = super::registration_anchors(entry, registration, need, served, &secrets)
        .expect("the registration's anchors read");
    c.anchor(OWNER, need, entry, origin, &anchors)
        .expect("the anchors seal");
    anchors
}

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

async fn saw(rx: &mut UnboundedReceiver<Saw>) -> Saw {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the far end reports the connection")
        .expect("the far end runs")
}

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

#[test]
fn structured_member_tls_validates_certificates_and_does_not_accept_nested_identity() {
    let pki = Pki::new();
    let leaf = pki.leaf("member.example");
    let registration = serde_yaml::to_value(serde_json::json!({
        "tls": { "ca_cert_pem": leaf.pem }
    }))
    .expect("registration");
    assert_eq!(
        super::registration_ca_anchors("member", &registration).unwrap(),
        vec![leaf.der]
    );
    for tls in [
        serde_json::json!({"ca_cert_pem": ""}),
        serde_json::json!({"ca_cert_pem": "not certificate material"}),
        serde_json::json!({"ca_cert_pem": leaf.key_pem}),
        serde_json::json!({"ca_cert_pem": 123}),
        serde_json::json!({"client_identity": {"cert": "hidden", "key": "hidden"}}),
        serde_json::json!("not a bundle"),
    ] {
        let registration = serde_yaml::to_value(serde_json::json!({"tls": tls})).unwrap();
        let error = super::registration_ca_anchors("member", &registration)
            .expect_err("invalid TLS rejected");
        assert!(error.contains("member"));
        assert!(!error.contains("PRIVATE KEY"));
        assert!(!error.contains("hidden"));
    }
    for registration in [serde_json::json!({}), serde_json::json!({"tls": {}})] {
        let registration = serde_yaml::to_value(registration).unwrap();
        assert!(super::registration_ca_anchors("member", &registration)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn legacy_identity_selector_does_not_parse_member_tls_bundle() {
    let served = ServedFacts {
        section: "tools",
        need_trust: vec!["settings.*.client_identity"],
        ..Default::default()
    };
    let registration = serde_yaml::from_str("tls: {ca_cert_pem: malformed}").unwrap();
    let anchors = super::registration_anchors(
        "member",
        &registration,
        NeedId(0),
        &served,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap();
    assert!(anchors.extra_anchors.is_empty());
    assert!(anchors.client_identity.is_none());
}

#[test]
fn structured_tls_preserves_sibling_identity_requirements() {
    let registration = serde_yaml::from_str("tls: {}\nclient_identity: {key: secret-key}").unwrap();
    for selector in ["settings.*.tls", "settings.*.client_identity"] {
        let served = ServedFacts {
            section: "tools",
            need_trust: vec![selector],
            ..Default::default()
        };
        let error = super::registration_anchors(
            "member",
            &registration,
            NeedId(0),
            &served,
            &busbar_kernel::config::secret::SecretResolver::builtins_only(),
        )
        .expect_err("identity certificate remains required");
        assert_eq!(
            error,
            "member 'member': `client_identity.cert:` is required"
        );
        assert!(!error.contains("secret-key"));
    }
}

#[test]
fn member_tls_rules_reject_candidate_before_apply_and_ignore_unselected_sections() {
    use busbar_kernel::appbuild::RootRules as _;
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nmodels: {}\nproviders: {}\n",
    )
    .unwrap();
    let mut cfg =
        busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new()).unwrap();
    let invalid: serde_yaml::Value =
        serde_yaml::from_str("member: {tls: {ca_cert_pem: invalid}}").unwrap();
    cfg.endpoint_resources
        .insert("unrelated", Arc::new(("unrelated", invalid.clone())));
    let rules = super::Rules::default();
    rules.hold_member_tls_sections(&["tools"]);
    assert!(
        rules.check(&cfg).is_ok(),
        "unselected TLS-shaped data is not reinterpreted"
    );
    cfg.endpoint_resources
        .insert("tools", Arc::new(("tools", invalid)));
    let error = rules
        .check(&cfg)
        .expect_err("candidate must fail before apply callbacks");
    assert!(error.contains("tls.ca_cert_pem"));
    let selected = ServedFacts {
        section: "tools",
        need_trust: vec!["settings.*.tls"],
        ..Default::default()
    };
    let legacy = ServedFacts {
        section: "tools",
        need_trust: vec!["settings.*.client_identity"],
        ..Default::default()
    };
    let candidate = cfg.endpoint_resources["tools"]
        .downcast_ref::<(&'static str, serde_yaml::Value)>()
        .unwrap();
    assert!(super::member_tls_refusal(&selected, &candidate.1).is_err());
    assert!(super::member_tls_refusal(&legacy, &candidate.1).is_ok());
}
