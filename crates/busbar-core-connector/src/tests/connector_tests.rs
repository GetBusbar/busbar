// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const OWNER: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

/// A far end on loopback: the bound listener, and the address a need dials to reach it.
async fn far_end() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (l, addr)
}

/// A declared need is answered with the shell's refusal, never a silent success; an undeclared one
/// is refused as undeclared.
#[test]
fn a_declared_need_is_refused_until_a_transport_is_composed() {
    let c = Connector::new();
    c.declare(OWNER, NeedId(0));
    let desc = OpenDesc {
        target: "127.0.0.1:1",
        ..OpenDesc::default()
    };
    assert_eq!(c.open(OWNER, NeedId(0), &desc), Err(NO_TRANSPORT_YET));
    assert_eq!(
        c.open(OWNER, NeedId(1), &desc),
        Err(ConnError::UndeclaredNeed)
    );
    assert_eq!(
        c.open(OTHER, NeedId(0), &desc),
        Err(ConnError::UndeclaredNeed)
    );
}

/// No id is live in the shell, so every id-taking operation answers closed, never a fault.
#[test]
fn an_id_the_shell_never_opened_is_closed() {
    let c = Connector::new();
    let mut buf = [0_u8; 4];
    assert_eq!(
        c.write(OWNER, ConnId(1), b"x", true),
        Err(ConnError::Closed)
    );
    assert_eq!(
        c.read(OWNER, ConnId(1), 0, &mut buf),
        Err(ConnError::Closed)
    );
    assert_eq!(c.wait(OWNER, &[ConnId(1)], 0), Err(ConnError::Closed));
    assert_eq!(c.facts(OWNER, ConnId(1)), Err(ConnError::Closed));
    assert_eq!(c.close(OWNER, ConnId(1)), Err(ConnError::Closed));
}

/// A declared need whose target is a cloud metadata host is refused before any dial.
#[test]
fn a_metadata_target_is_refused_before_any_dial() {
    let c = Connector::new();
    c.declare(OWNER, NeedId(0));
    let desc = OpenDesc {
        target: "169.254.169.254:80",
        ..OpenDesc::default()
    };
    assert_eq!(c.open(OWNER, NeedId(0), &desc), Err(ConnError::Refused));
    assert!(endpoint::check(desc.target).is_err());
}

// ── the table over a composed connection ──

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

fn serving(wakes: Arc<AtomicU64>) -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .unwrap();
    Connector::serving(
        view,
        Arc::new(crate::LiteralsOnly),
        None,
        Arc::new(move |_| {
            wakes.fetch_add(1, Ordering::SeqCst);
        }),
    )
}

/// A declared need over a served transport opens a real connection: the opening body goes out,
/// a read with nothing ready is Pending with the ticket registered, the far end's bytes wake the
/// ticket, and the next read answers them.
#[test]
fn a_need_over_a_served_transport_reaches_a_real_far_end() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            let _ = tx.send(buf.to_vec());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            s.write_all(b"answer").await.unwrap();
        });
        let wakes = Arc::new(AtomicU64::new(0));
        let c = serving(wakes.clone());
        c.declare_over(OWNER, NeedId(0), "bytes");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        assert_eq!(c.read(OWNER, id, 7, &mut buf), Err(ConnError::Pending));
        // Nothing drives the connection but the caller's own reads: read until the far end has the
        // opening body (it answers only after a pause, so no answer is taken here).
        let mut rx = rx;
        let first = loop {
            assert_eq!(c.read(OWNER, id, 7, &mut buf), Err(ConnError::Pending));
            match rx.try_recv() {
                Ok(v) => break v,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        assert_eq!(first, b"first");
        let piece = loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                other => break other.unwrap(),
            }
        };
        assert_eq!(&buf[..piece.len], b"answer");
        assert!(wakes.load(Ordering::SeqCst) >= 1, "the ticket was woken");
        assert_eq!(c.read(OTHER, id, 7, &mut buf), Err(ConnError::NotOwner));
        assert_eq!(c.facts(OWNER, id).unwrap().claim.as_deref(), Some("bytes"));
        c.close(OWNER, id).unwrap();
        assert_eq!(c.read(OWNER, id, 7, &mut buf), Err(ConnError::Closed));
    });
}

/// RED: a metadata target is refused through the table even when a transport serves the need.
#[test]
fn a_metadata_target_is_refused_even_over_a_served_transport() {
    worker().block_on(async {
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes");
        for target in [
            "169.254.169.254:80",
            "[fd00:ec2::254]:80",
            "100.100.100.200:80",
        ] {
            let desc = OpenDesc {
                target,
                ..OpenDesc::default()
            };
            assert_eq!(
                c.open(OWNER, NeedId(0), &desc),
                Err(ConnError::Refused),
                "{target}"
            );
        }
    });
}

/// The egress class a restricted need is declared in: its judge refuses internal addresses.
const RESTRICTED: u32 = 7;

/// RED: each need's dial is judged under the need's OWN egress class. A judge that refuses internal
/// addresses in a restricted class refuses a loopback target for the need declared in that class,
/// while the same target opens for a need in the default class on the same connector.
#[test]
fn a_need_in_a_restricted_class_is_refused_a_target_that_class_forbids() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let view = Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap();
        let judge = |dest: &str, class: u32, _: crate::Judged| {
            let addr = crate::socket::address_of(dest)
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE);
            Some(match (class, addr) {
                (RESTRICTED, Ok(a)) if a.ip().is_loopback() => {
                    Err(busbar_contract::abi::host::service::DEST_UNRESOLVABLE)
                }
                (_, got) => got,
            })
        };
        let c = Connector::serving(view, Arc::new(judge), None, Arc::new(|_| {}));
        c.declare_over(OWNER, NeedId(0), "bytes");
        c.declare_need(OWNER, NeedId(1), "bytes", RESTRICTED);
        let desc = OpenDesc {
            target: &far,
            ..OpenDesc::default()
        };
        assert_eq!(
            c.open(OWNER, NeedId(1), &desc),
            Err(ConnError::Refused),
            "the restricted need is judged under its own class"
        );
        let id = c
            .open(OWNER, NeedId(0), &desc)
            .expect("the default-class need opens the same target");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: writes made while a dial's judgement is pending are held under the same cap: a write past
/// it is taken short, and the next is answered Pending, never buffered without bound.
#[test]
fn writes_held_for_a_pending_judgement_are_capped() {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .unwrap();
    // A judge that never answers: every dial stays in flight.
    let judge = |_: &str, _: u32, done: crate::Judged| {
        std::mem::forget(done);
        None
    };
    let c = Connector::serving(view, Arc::new(judge), None, Arc::new(|_| {}));
    c.declare_over(OWNER, NeedId(0), "bytes");
    let desc = OpenDesc {
        target: "upstream.test:80",
        ..OpenDesc::default()
    };
    let id = c
        .open(OWNER, NeedId(0), &desc)
        .expect("opens, judgement pending");
    let big = vec![1_u8; crate::compose::WRITE_BUFFER_BYTES + 10];
    assert_eq!(
        c.write(OWNER, id, &big, true),
        Ok(crate::compose::WRITE_BUFFER_BYTES),
        "taken short, up to the cap"
    );
    assert_eq!(
        c.write(OWNER, id, b"more", false),
        Err(ConnError::Pending),
        "no room: Pending"
    );
    assert_eq!(
        c.write(OWNER, id, b"", true),
        Ok(0),
        "an empty write still passes"
    );
}

/// A need dials a hostname through the kernel's one judge, over the plugin's own table. Its one
/// `unsafe` is the host's own lowered table (`HostConns::new`), test-only as `support` is.
#[allow(unsafe_code)]
#[path = "name_dial_tests.rs"]
mod name_dial;

// ── EGRESS: the declared target; metadata and link-local are refused on every need ──

/// A connector serving the byte-exact door, admitting literals (loopback and private included).
fn literal_connector() -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .unwrap();
    Connector::serving(view, Arc::new(crate::LiteralsOnly), None, Arc::new(|_| {}))
}

/// RED: a need whose config names its target (`target_from`) dials that target and no other: an
/// open to another host, or to another port on the same host, is refused before any dial, while
/// the declared target itself opens.
#[test]
fn a_config_targeted_need_dialing_elsewhere_is_refused() {
    worker().block_on(async {
        let (_listening, declared) = far_end().await;
        let c = literal_connector();
        c.declare_need_to(OWNER, NeedId(0), "bytes", crate::DEFAULT_CLASS, &declared);
        let open = |target: &str| {
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            )
        };
        assert_eq!(
            open("127.0.0.2:443"),
            Err(ConnError::Refused),
            "another host"
        );
        assert_eq!(open("127.0.0.1:1"), Err(ConnError::Refused), "another port");
        let id = open(&declared).expect("the declared target opens");
        c.close(OWNER, id).unwrap();
    });
}

/// An outbound need over the test transport whose target comes from `target_from`.
fn config_targeted_need(target_from: &str) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: crate::DEFAULT_CLASS,
        transport: "bytes".to_owned(),
        auth: String::new(),
        target_from: target_from.to_owned(),
        trust_from: String::new(),
        details: busbar_contract::abi::mechanism::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// RED: a need the loader's conns fill declares with the target its `target_from` resolved to is
/// pinned to it (ARCHITECT ruling 2026-09-30 on the conns fill, option A): an open to another host
/// is refused before any dial, while the resolved target opens. Declaring it again with another
/// target (a refresh) moves the pin.
#[test]
fn a_fill_declared_need_is_pinned_to_its_resolved_target() {
    worker().block_on(async {
        let (_listening, resolved) = far_end().await;
        let c = literal_connector();
        let need = config_targeted_need("settings.upstream");
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&resolved)),
            Ok(())
        );
        let open = |target: &str| {
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            )
        };
        assert_eq!(
            open("127.0.0.2:443"),
            Err(ConnError::Refused),
            "another host"
        );
        let id = open(&resolved).expect("the resolved target opens");
        c.close(OWNER, id).unwrap();
        let (_moved_listening, moved) = far_end().await;
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&moved)),
            Ok(())
        );
        assert_eq!(open(&resolved), Err(ConnError::Refused), "the old pin");
        let id = open(&moved).expect("the re-declared target opens");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a need whose `target_from` resolved to nothing is refused, its answer kept, and nothing
/// opens on it, even after an earlier declaration pinned it.
#[test]
fn a_fill_declared_need_whose_target_resolved_to_nothing_is_refused() {
    worker().block_on(async {
        let (_listening, resolved) = far_end().await;
        let c = literal_connector();
        let need = config_targeted_need("settings.upstream");
        let _ = DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&resolved));
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None),
            Err(ConnError::Refused)
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
                    target: &resolved,
                    ..OpenDesc::default()
                },
            )
            .is_err());
    });
}

/// A need whose target the plugin names (no `target_from`) is judged by its egress class only: any
/// host the class admits opens.
#[test]
fn a_plugin_named_need_to_a_class_legal_host_is_allowed() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let c = literal_connector();
        c.declare_over(OWNER, NeedId(0), "bytes");
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &far,
                    ..OpenDesc::default()
                },
            )
            .expect("a plugin-named target the class admits opens");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a plugin-named need to a cloud metadata or link-local address is refused, whatever its
/// class admits.
#[test]
fn a_plugin_named_need_to_the_metadata_address_is_refused() {
    worker().block_on(async {
        let c = literal_connector();
        c.declare_over(OWNER, NeedId(0), "bytes");
        for target in ["169.254.169.254:80", "169.254.1.1:80", "[fe80::1]:80"] {
            assert_eq!(
                c.open(
                    OWNER,
                    NeedId(0),
                    &OpenDesc {
                        target,
                        ..OpenDesc::default()
                    },
                ),
                Err(ConnError::Refused),
                "{target}"
            );
        }
    });
}

/// A HOST-SIDE READER awaits a connection through `poll_read`: nothing ready is `Pending` with the
/// reader's own waker registered, the far end's bytes wake THAT waker (the task finishes without
/// being re-polled by anything else), and no plugin ticket is ever woken.
#[test]
fn a_host_side_reader_is_woken_through_its_own_waker() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            s.write_all(b"answer").await.unwrap();
        });
        let wakes = Arc::new(AtomicU64::new(0));
        let c = serving(wakes.clone());
        c.declare_over(OWNER, NeedId(0), "bytes");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let piece = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)),
        )
        .await
        .expect("the reader's waker was woken")
        .unwrap();
        assert_eq!(&buf[..piece.len], b"answer");
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            0,
            "no plugin ticket was woken"
        );
        let polled =
            std::future::poll_fn(|cx| std::task::Poll::Ready(c.poll_read(OTHER, id, cx, &mut buf)))
                .await;
        assert_eq!(polled, std::task::Poll::Ready(Err(ConnError::NotOwner)));
    });
}

// ── EGRESS: the scheme each egress class allows (PB-100) ──

use busbar_contract::abi::host::conn::connector::{
    EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};

/// A connector serving a plaintext door (`plain`) and a door whose targets ask for connection
/// security (`sec`), admitting every literal, with a client config for the secure one.
fn scheme_connector() -> Connector {
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(TestDoor::identity("plain")),
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(TestDoor::new(
                "sec",
                &["sec"],
                &[],
                crate::support::Knobs {
                    secure_name: Some("localhost"),
                    ..crate::support::Knobs::default()
                },
            )),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let tls = crate::tls::client::build_client_config(&Default::default()).expect("the config");
    Connector::serving(
        view,
        Arc::new(crate::LiteralsOnly),
        Some(Arc::new(tls)),
        Arc::new(|_| {}),
    )
}

fn open_in(c: &Connector, need: u32, target: &str) -> Result<ConnId, ConnError> {
    c.open(
        OWNER,
        NeedId(need),
        &OpenDesc {
            target,
            ..OpenDesc::default()
        },
    )
}

/// RED: open-web dials over connection security only: a plaintext target, public or not, is
/// refused before any judgement; the same class over a secure target opens.
#[test]
fn http_to_a_public_host_under_open_web_is_refused() {
    worker().block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_OPEN_WEB);
        c.declare_need(OWNER, NeedId(1), "sec", EGRESS_OPEN_WEB);
        assert_eq!(open_in(&c, 0, "93.184.216.34:80"), Err(ConnError::Refused));
        assert_eq!(open_in(&c, 0, &far), Err(ConnError::Refused));
        let id = open_in(&c, 1, &far).expect("open-web over a secure target opens");
        c.close(OWNER, id).unwrap();
    });
}

/// Operator-infrastructure takes the operator's configured plaintext private target (1.5.5's
/// private-network http api_base case).
#[test]
fn the_operator_infrastructure_http_private_target_is_allowed() {
    worker().block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_OPERATOR_INFRASTRUCTURE);
        let id = open_in(&c, 0, &far).expect("plaintext to the private target opens");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: loopback-allowed dials plaintext to loopback only: a plaintext private (non-loopback)
/// address is refused; plaintext loopback opens.
#[test]
fn loopback_allowed_refuses_plaintext_off_loopback() {
    worker().block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_LOOPBACK_ALLOWED);
        assert_eq!(open_in(&c, 0, "10.1.2.3:80"), Err(ConnError::Refused));
        let id = open_in(&c, 0, &far).expect("plaintext loopback opens");
        c.close(OWNER, id).unwrap();
    });
}
