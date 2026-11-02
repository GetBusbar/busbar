// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A NEED'S `trust_from`(`BUSBAR-1.6.0.md` section 5, the host

use std::sync::Arc;

use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, Knobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);

/// A private CA and a `localhost` leaf it signed: (ca_pem, leaf_der, key_der).
fn private_ca() -> (String, Vec<u8>, Vec<u8>) {
    let ca = crate::test_support::private_ca();
    (ca.ca_pem, ca.leaf_der, ca.key_der)
}

/// A TLS far end on loopback presenting `leaf`: every connection whose handshake completes has its
async fn tls_far_end(leaf: Vec<u8>, key: Vec<u8>) -> String {
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = acceptor.accept(s).await {
                    let mut buf = [0_u8; 5];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(&buf).await;
                        let _ = s.flush().await;
                    }
                }
            });
        }
    });
    far
}

/// The process's connector shape: a door whose targets ask for connection security, every literal
fn secure_connector() -> Connector {
    crate::tls::install_crypto_provider();
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(TestDoor::new(
                "sec",
                &["sec"],
                &[],
                Knobs {
                    secure_name: Some("localhost"),
                    ..Knobs::default()
                },
            )),
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let tls = crate::tls::client::build_client_config(&Default::default()).expect("the config");
    Connector::serving(
        view,
        crate::tests::loopback_literals(),
        Some(Arc::new(tls)),
        Arc::new(|_, _| {}),
    )
}

/// An outbound need over the secure door, the plugin naming its target, its trust from `trust_from`.
fn trusting_need(trust_from: &str) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: crate::DEFAULT_CLASS,
        transport: "sec".to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: trust_from.to_owned(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

/// Open the need to `far`, send `hello`, and answer what the far end sent back, or the refusal.
async fn exchange(c: &Connector, far: &str) -> Result<Vec<u8>, ConnError> {
    let id = c.open(
        OWNER,
        NeedId(0),
        &OpenDesc {
            target: far,
            body: busbar_contract::conn::Bytes::from_static(b"hello"),
            ..OpenDesc::default()
        },
    )?;
    let mut buf = [0_u8; 64];
    let piece = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)),
    )
    .await
    .expect("the open settles");
    let _ = c.close(OWNER, id);
    piece.map(|p| buf[..p.len].to_vec())
}

/// RED: a far end whose certificate chains to a private CA is refused over the public roots alone,
#[test]
fn a_private_ca_upstream_is_refused_without_trust_from_and_served_with_it() {
    let (ca_pem, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = tls_far_end(leaf, key).await;
        let c = secure_connector();
        let plain = trusting_need("");
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &plain, None, None),
            Ok(())
        );
        assert_eq!(
            exchange(&c, &far).await,
            Err(ConnError::Refused),
            "the public roots alone refuse a private CA's certificate"
        );
        let trusting = trusting_need("settings.ca");
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &trusting, None, Some(&ca_pem)),
            Ok(())
        );
        assert_eq!(exchange(&c, &far).await.as_deref(), Ok(&b"hello"[..]));
    });
}

/// RED: a `trust_from` that resolved to nothing, or to a PEM that holds no parsable certificate,
#[test]
fn a_trust_from_that_does_not_parse_refuses_the_need() {
    let (ca_pem, _, _) = private_ca();
    let c = secure_connector();
    let need = trusting_need("settings.ca");
    let torn = &ca_pem[..ca_pem.len() / 2];
    let garbled = ca_pem.replacen("MII", "M*I", 1);
    for bad in [
        Some("not a certificate"),
        Some(torn),
        Some(garbled.as_str()),
    ] {
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, bad),
            Err(ConnError::Refused),
            "{bad:?}"
        );
        assert_eq!(
            DeclaredConns::declared(&c, OWNER, NeedId(0)),
            Some(Err(ConnError::Refused))
        );
        assert!(c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "127.0.0.1:1",
                    ..OpenDesc::default()
                },
            )
            .is_err());
    }
    assert_eq!(
        DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, Some(&ca_pem)),
        Ok(())
    );
}

/// RED: re-declaring the need (a refresh) with another CA moves its trust: the far end the old CA
#[test]
fn a_refresh_with_a_changed_ca_re_declares_the_trust() {
    let (ca_pem, leaf, key) = private_ca();
    let (other_pem, _, _) = private_ca();
    worker().block_on(async move {
        let far = tls_far_end(leaf, key).await;
        let c = secure_connector();
        let need = trusting_need("settings.ca");
        let declare =
            |pem: &str| DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, Some(pem));
        assert_eq!(declare(&ca_pem), Ok(()));
        assert_eq!(exchange(&c, &far).await.as_deref(), Ok(&b"hello"[..]));
        assert_eq!(declare(&other_pem), Ok(()));
        assert_eq!(
            exchange(&c, &far).await,
            Err(ConnError::Refused),
            "the old CA is no longer trusted"
        );
        assert_eq!(declare(&ca_pem), Ok(()));
        assert_eq!(exchange(&c, &far).await.as_deref(), Ok(&b"hello"[..]));
    });
}

/// THE OWNED NAMESPACE (`owned.<section>.<key>`): an anchor named in a plane's other owned sections
#[test]
fn an_absent_owned_trust_anchor_declares_the_need_over_the_public_roots_alone() {
    let (_, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = tls_far_end(leaf, key).await;
        let c = secure_connector();
        let need = trusting_need("owned.agent_push.ca");
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None),
            Ok(()),
            "an owned anchor the operator did not write refuses nothing"
        );
        assert_eq!(DeclaredConns::declared(&c, OWNER, NeedId(0)), Some(Ok(())));
        assert_eq!(
            exchange(&c, &far).await,
            Err(ConnError::Refused),
            "the public roots alone refuse a private CA's certificate"
        );
    });
}

/// RED: an owned anchor the operator wrote is the operator CA added on top of the public roots, as
#[test]
fn an_owned_trust_anchor_serves_its_ca_and_refuses_another() {
    let (ca_pem, leaf, key) = private_ca();
    let (other_pem, _, _) = private_ca();
    worker().block_on(async move {
        let far = tls_far_end(leaf, key).await;
        let c = secure_connector();
        let need = trusting_need("owned.agent_push.ca");
        let declare =
            |pem: &str| DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, Some(pem));
        assert_eq!(declare(&ca_pem), Ok(()));
        assert_eq!(exchange(&c, &far).await.as_deref(), Ok(&b"hello"[..]));
        assert_eq!(declare(&other_pem), Ok(()));
        assert_eq!(
            exchange(&c, &far).await,
            Err(ConnError::Refused),
            "a far end under a CA the operator did not write is refused"
        );
    });
}

/// RED: an owned anchor the operator wrote that is no trust anchor refuses the need, exactly as a
#[test]
fn a_written_owned_trust_anchor_that_does_not_parse_refuses_the_need() {
    let (ca_pem, _, _) = private_ca();
    let c = secure_connector();
    let need = trusting_need("owned.agent_push.ca");
    let torn = &ca_pem[..ca_pem.len() / 2];
    for bad in ["not a certificate", torn] {
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, Some(bad)),
            Err(ConnError::Refused),
            "{bad:?}"
        );
        assert_eq!(
            DeclaredConns::declared(&c, OWNER, NeedId(0)),
            Some(Err(ConnError::Refused))
        );
    }
}

/// A `settings.` trust anchor that resolved to nothing is OPTIONAL, as an owned one is: an auth
#[test]
fn an_absent_settings_trust_anchor_declares_the_need_over_the_public_roots_alone() {
    let (_, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = tls_far_end(leaf, key).await;
        let c = secure_connector();
        let need = trusting_need("settings.ca_cert_pem");
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None),
            Ok(()),
            "a settings anchor the operator did not configure refuses nothing"
        );
        assert_eq!(DeclaredConns::declared(&c, OWNER, NeedId(0)), Some(Ok(())));
        assert_eq!(
            exchange(&c, &far).await,
            Err(ConnError::Refused),
            "the public roots alone refuse a private CA's certificate"
        );
    });
}
