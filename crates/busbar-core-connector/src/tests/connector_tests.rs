// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const OWNER: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

/// The literal judge over a guard that allowlists the loopback far ends these tests dial, and the
/// private address the scheme-rule test names (the destination guard refuses both by default), so
/// what those tests assert stays the connector's own rule.
fn loopback_literals() -> std::sync::Arc<dyn crate::DialJudge> {
    let allow = ["127.0.0.1", "::1", "10.1.2.3"].map(str::to_owned).to_vec();
    std::sync::Arc::new(crate::LiteralsOnly(
        crate::guard::Guard::from_config(&busbar_kernel::config::Destinations {
            block_private_addresses: true,
            allow,
            ..busbar_kernel::config::Destinations::default()
        })
        .expect("the loopback allowlist"),
    ))
}

/// A far end on loopback: the bound listener, and the address a need dials to reach it.
async fn far_end() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (l, addr)
}

/// A need declared without a transport (an inbound need) dials nothing: its open is refused; an
/// undeclared one is refused as undeclared.
#[test]
fn a_need_declared_without_a_transport_dials_nothing() {
    let c = Connector::new();
    c.declare(OWNER, NeedId(0));
    let desc = OpenDesc {
        target: "127.0.0.1:1",
        ..OpenDesc::default()
    };
    assert_eq!(c.open(OWNER, NeedId(0), &desc), Err(ConnError::Refused));
    assert_eq!(
        c.open(OWNER, NeedId(1), &desc),
        Err(ConnError::UndeclaredNeed)
    );
    assert_eq!(
        c.open(OTHER, NeedId(0), &desc),
        Err(ConnError::UndeclaredNeed)
    );
}

/// RED (spec Part 2 #50, THE SCHEME MATCH AT DECLARE): a need over a scheme no loaded transport
/// serves is refused when it is declared, by the inherent declare and the table's alike, and is
/// left undeclared, so no open ever meets an unserved scheme; re-declaring a served need over an
/// unserved scheme drops its record. The same need over the served scheme opens.
#[test]
fn a_need_over_an_unserved_scheme_is_refused_at_declare_and_a_served_one_opens() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let c = literal_connector();
        assert!(c.serves_scheme("bytes"));
        assert!(!c.serves_scheme("nowhere"));
        assert_eq!(
            c.declare_over(OWNER, NeedId(0), "nowhere"),
            Err(ConnError::Refused)
        );
        let mut unserved = config_targeted_need("");
        unserved.transport = "nowhere".to_owned();
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(1), &unserved, None),
            Err(ConnError::Refused)
        );
        assert_eq!(c.declared(OWNER, NeedId(1)), Some(Err(ConnError::Refused)));
        let desc = OpenDesc {
            target: &far,
            ..OpenDesc::default()
        };
        assert_eq!(
            c.open(OWNER, NeedId(0), &desc),
            Err(ConnError::UndeclaredNeed)
        );
        assert_eq!(
            c.open(OWNER, NeedId(1), &desc),
            Err(ConnError::UndeclaredNeed)
        );

        // The served scheme opens.
        DeclaredConns::declare(&c, OWNER, NeedId(2), &config_targeted_need(""), None)
            .expect("a served scheme declares");
        let id = c
            .open(OWNER, NeedId(2), &desc)
            .expect("a need over a served scheme opens");
        c.close(OWNER, id).unwrap();

        // A served need re-declared over an unserved scheme loses its record.
        assert_eq!(
            c.declare_over(OWNER, NeedId(2), "nowhere"),
            Err(ConnError::Refused)
        );
        assert_eq!(c.open(OWNER, NeedId(2), &desc), Err(ConnError::Refused));
    });
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
        loopback_literals(),
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        c.declare_need(OWNER, NeedId(1), "bytes", RESTRICTED)
            .expect("a served scheme declares");
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
    c.declare_over(OWNER, NeedId(0), "bytes")
        .expect("a served scheme declares");
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

/// A connector serving the byte-exact door, admitting literals (its loopback far ends allowlisted).
fn literal_connector() -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .unwrap();
    Connector::serving(view, loopback_literals(), None, Arc::new(|_| {}))
}

/// RED: a need whose config names its target (`target_from`) dials that target and no other: an
/// open to another host, or to another port on the same host, is refused before any dial, while
/// the declared target itself opens.
#[test]
fn a_config_targeted_need_dialing_elsewhere_is_refused() {
    worker().block_on(async {
        let (_listening, declared) = far_end().await;
        let c = literal_connector();
        c.declare_need_to(OWNER, NeedId(0), "bytes", crate::DEFAULT_CLASS, &declared)
            .expect("a served scheme declares");
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
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
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
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

// ── EGRESS: the scheme each egress class allows ──

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
        loopback_literals(),
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
        let (_listening, far) = far_end().await;
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_OPEN_WEB)
            .expect("a served scheme declares");
        c.declare_need(OWNER, NeedId(1), "sec", EGRESS_OPEN_WEB)
            .expect("a served scheme declares");
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
        let (_listening, far) = far_end().await;
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_OPERATOR_INFRASTRUCTURE)
            .expect("a served scheme declares");
        let id = open_in(&c, 0, &far).expect("plaintext to the private target opens");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: loopback-allowed dials plaintext to loopback only: a plaintext private (non-loopback)
/// address is refused; plaintext loopback opens.
#[test]
fn loopback_allowed_refuses_plaintext_off_loopback() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let c = scheme_connector();
        c.declare_need(OWNER, NeedId(0), "plain", EGRESS_LOOPBACK_ALLOWED)
            .expect("a served scheme declares");
        assert_eq!(open_in(&c, 0, "10.1.2.3:80"), Err(ConnError::Refused));
        let id = open_in(&c, 0, &far).expect("plaintext loopback opens");
        c.close(OWNER, id).unwrap();
    });
}

/// An inbound need listens through the table: the listener is bound for the need's owner, an
/// accepted connection is held for that owner (read and answered on the piece's stream through the
/// table), another instance can neither accept on the need nor read the connection, and a need
/// listens once.
#[test]
fn an_inbound_need_listens_and_its_connections_are_its_owners() {
    worker().block_on(async {
        let wakes = Arc::new(AtomicU64::new(0));
        let c = serving(wakes.clone());
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        c.declare_over(OWNER, NeedId(1), "bytes")
            .expect("a served scheme declares");
        c.declare_over(OTHER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let limits = crate::listen::AcceptLimits::default();
        let addr = c
            .listen(OWNER, NeedId(0), "127.0.0.1:0", None, limits)
            .expect("listens");
        let second = c
            .listen(OWNER, NeedId(1), "127.0.0.1:0", None, limits)
            .expect("a second need gets its own listener");
        assert_ne!(addr, second);
        assert_eq!(
            c.listen(OWNER, NeedId(0), "127.0.0.1:0", None, limits),
            Err(ConnError::Refused),
            "a need listens once"
        );
        assert_eq!(
            c.listen(OWNER, NeedId(7), "127.0.0.1:0", None, limits),
            Err(ConnError::UndeclaredNeed)
        );
        assert_eq!(
            c.accept(OTHER, NeedId(0), 3).map(|_| ()),
            Err(ConnError::Refused)
        );
        assert_eq!(
            c.accept(OWNER, NeedId(0), 3).map(|_| ()),
            Err(ConnError::Pending)
        );
        let client = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"knock").await.unwrap();
            let mut got = [0_u8; 5];
            s.read_exact(&mut got).await.unwrap();
            got
        });
        let id = loop {
            match c.accept(OWNER, NeedId(0), 3) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                other => break other.expect("accepted").0,
            }
        };
        let mut buf = [0_u8; 64];
        assert_eq!(c.read(OTHER, id, 3, &mut buf), Err(ConnError::NotOwner));
        let mut got = Vec::new();
        let mut stream = 0;
        while got.len() < 5 {
            match c.read(OWNER, id, 3, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                Ok(p) => {
                    stream = p.stream.0;
                    got.extend_from_slice(&buf[..p.len]);
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert_eq!(got, b"knock");
        assert_eq!(
            c.emit(OTHER, id, stream, b"x", false),
            Err(ConnError::NotOwner)
        );
        c.emit(OWNER, id, stream, b"welcome"[..5].as_ref(), false)
            .unwrap();
        // Nothing drives the connection but the owner's own calls.
        let answered = loop {
            let _ = c.wait(OWNER, &[id], 3);
            if client.is_finished() {
                break client.await.unwrap();
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(&answered, b"welco");
        assert!(
            wakes.load(Ordering::SeqCst) >= 1,
            "the accept woke the ticket"
        );
        c.close(OWNER, id).unwrap();
    });
}

/// RED (ARCHITECT ruling 2026-10-02, WIRE-EXPORT userinfo): a need declared with a target that
/// carries a userinfo — a URL's `user:pass@` or a bare `user@host:port` — is REFUSED, fail closed:
/// the answer is kept for the need's admission, and nothing opens on it. The same target without
/// the userinfo is declared.
#[test]
fn a_declared_target_carrying_a_userinfo_is_refused() {
    worker().block_on(async {
        let (_listening, resolved) = far_end().await;
        let c = literal_connector();
        let need = config_targeted_need("settings.url");
        for credentialed in [
            format!("http://user:secret@{resolved}/v1/traces"),
            format!("user@{resolved}"),
        ] {
            assert_eq!(
                DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&credentialed)),
                Err(ConnError::Refused),
                "{credentialed}"
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
        }
        assert_eq!(
            DeclaredConns::declare(
                &c,
                OWNER,
                NeedId(0),
                &need,
                Some(&format!("http://{resolved}/v1/traces"))
            ),
            Ok(())
        );
    });
}
