// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const OWNER: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

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
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
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
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
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
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let declared = l.local_addr().unwrap().to_string();
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

/// A need whose target the plugin names (no `target_from`) is judged by its egress class only: any
/// host the class admits opens.
#[test]
fn a_plugin_named_need_to_a_class_legal_host_is_allowed() {
    worker().block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
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
