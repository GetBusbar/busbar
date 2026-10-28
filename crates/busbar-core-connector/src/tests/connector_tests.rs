// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const OWNER: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

/// The literal judge over a guard that allowlists the loopback far ends these tests dial, and the
/// private address the scheme-rule test names (the destination guard refuses both by default), so
/// what those tests assert stays the connector's own rule.
pub(crate) fn loopback_literals() -> std::sync::Arc<dyn crate::DialJudge> {
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
            DeclaredConns::declare(&c, OWNER, NeedId(1), &unserved, None, None),
            Err(ConnError::Refused)
        );
        assert_eq!(c.declared(OWNER, NeedId(1)), Some(Err(ConnError::Refused)));
        // An inbound need over an unserved scheme is refused alike (ARCHITECT ruling 2026-10-02).
        let mut inbound = unserved.clone();
        inbound.direction = busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(3), &inbound, None, None),
            Err(ConnError::Refused)
        );
        inbound.transport = "bytes".to_owned();
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(3), &inbound, None, None),
            Ok(())
        );
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
        DeclaredConns::declare(&c, OWNER, NeedId(2), &config_targeted_need(""), None, None)
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
        c.write(OWNER, ConnId(1), b"x", true, false),
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
        Arc::new(move |_, _| {
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

/// RED (#74): the connector's wake names the caller the read registered its ticket for, never
/// only the ticket: the host blames the instance that supplied a ticket it never minted, whichever
/// thread the wake fires on. Every wake of a read parked by `OWNER` on ticket 7 is `(OWNER, 7)`.
#[test]
fn a_parked_reads_wake_names_the_caller_it_parked_for() {
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
        let woke: Arc<std::sync::Mutex<Vec<(InstanceId, u64)>>> = Arc::default();
        let seen = woke.clone();
        let view = Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap();
        let c = Connector::serving(
            view,
            loopback_literals(),
            None,
            Arc::new(move |owner, t| seen.lock().unwrap().push((owner, t))),
        );
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let piece = loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                other => break other.unwrap(),
            }
        };
        assert_eq!(&buf[..piece.len], b"answer");
        let woke = woke.lock().unwrap().clone();
        assert!(!woke.is_empty(), "the ticket was woken");
        assert!(
            woke.iter().all(|w| *w == (OWNER, 7)),
            "a wake named another caller or ticket: {woke:?}"
        );
    });
}

/// RED (C19-TAIL U5 write): a write through the table stated as text reaches the framer as a text
/// emit (`EMIT_TEXT`), held through the dial like any early write.
#[test]
fn a_text_write_through_the_table_reaches_the_framer_as_text() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 2];
            s.read_exact(&mut buf).await.unwrap();
            let _ = tx.send(buf.to_vec());
        });
        let door = Arc::new(
            TestDoor::identity("bytes").with_role(busbar_contract::abi::transport::ROLE_FRAMER),
        );
        let view = Transports::new(vec![
            Entry {
                door: door.clone(),
                alpn: Vec::new(),
            },
            Entry {
                door: Arc::new(TestDoor::identity("carrier")),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let c = Connector::serving(view, loopback_literals(), None, Arc::new(|_, _: Ticket| {}));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        assert_eq!(c.write(OWNER, id, b"{}", true, true), Ok(2));
        let mut buf = [0_u8; 8];
        let got = loop {
            let _ = c.read(OWNER, id, 7, &mut buf);
            match rx.try_recv() {
                Ok(v) => break v,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        assert_eq!(got, b"{}");
        assert_eq!(door.count("emit text"), 1, "the write crossed as text");
        assert_eq!(door.count("emit"), 0, "and never as binary");
    });
}

/// The table's head piece from a framer whose head field block states `declared` as its declared
/// body length (or states none), read through the connection table from a far end that answers a
/// one-field head.
fn head_through_the_table(declared: Option<u64>) -> Piece {
    worker().block_on(async {
        let (l, far) = far_end().await;
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"k: v\r\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(s);
        });
        let door = Arc::new(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            crate::support::Knobs {
                fields: true,
                declared_len: declared,
                ..crate::support::Knobs::default()
            },
        ));
        let view = Transports::new(vec![
            Entry {
                door,
                alpn: Vec::new(),
            },
            Entry {
                door: Arc::new(TestDoor::identity("carrier")),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let c = Connector::serving(view, loopback_literals(), None, Arc::new(|_, _: Ticket| {}));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let started = std::time::Instant::now();
        let piece = loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(5),
                        "the head never arrived"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                other => break other.expect("the head reads"),
            }
        };
        assert_eq!(
            piece.kind,
            PieceKind::Fields,
            "the framer's field block is the head"
        );
        assert_eq!(&buf[..piece.len], b"k: v\r\n");
        c.close(OWNER, id).unwrap();
        piece
    })
}

/// RED (1.5.5 parity, the pre-body download cap): the declared body length a framer states on its
/// head's field block reaches the table's head piece untouched, never as a field; a framer that
/// states none yields none.
#[test]
fn a_framers_declared_body_length_reaches_the_tables_head_piece() {
    assert_eq!(
        head_through_the_table(Some(1 << 40)).declared_len,
        Some(1 << 40)
    );
    assert_eq!(head_through_the_table(None).declared_len, None);
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
        let c = Connector::serving(view, Arc::new(judge), None, Arc::new(|_, _| {}));
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
    let c = Connector::serving(view, Arc::new(judge), None, Arc::new(|_, _| {}));
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
        c.write(OWNER, id, &big, true, false),
        Ok(crate::compose::WRITE_BUFFER_BYTES),
        "taken short, up to the cap"
    );
    assert_eq!(
        c.write(OWNER, id, b"more", false, false),
        Err(ConnError::Pending),
        "no room: Pending"
    );
    assert_eq!(
        c.write(OWNER, id, b"", true, false),
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
    Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {}))
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
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&resolved), None),
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
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&moved), None),
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
        let _ = DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&resolved), None);
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None),
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

/// RED (Q128 arch u22 HIGH 2; THE DESIGN §5 egress table, `provider`: "allow-list +
/// `allow_metadata_hosts`", and the DESTINATION GUARD, checked in ONE place): a provider need whose
/// 1.5.5 carve-out (`allow_metadata_hosts: ["169.254.169.254"]`, as 1.5.5 documented it for IMDS)
/// names a metadata address is DIALLED there: the guard admits it and the connector dials the
/// address the judgement pinned (here the loopback far end standing in for the metadata service).
/// The same open from a need in another class, and to a metadata address no carve-out names, is
/// refused by the same guard. RED on the endpoint check that refused every metadata host ahead of
/// the guard, so its carve-outs reached no dial.
#[test]
fn a_provider_carve_out_reaches_its_metadata_address_on_the_dial() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let stand_in: std::net::SocketAddr = far.parse().unwrap();
        let guard = crate::guard::Guard::from_config(&busbar_kernel::config::Destinations {
            block_private_addresses: true,
            legacy_allow: vec!["169.254.169.254".to_owned()],
            ..busbar_kernel::config::Destinations::default()
        })
        .expect("the carve-out");
        let judge = move |dest: &str, class: u32, _: crate::Judged| {
            let at = crate::socket::address_of(dest)?;
            Some(
                guard
                    .judge_answer(&at.ip().to_string(), &[at.ip()], class)
                    .map(|()| stand_in)
                    .map_err(|r| r.verdict),
            )
        };
        let view = Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap();
        let c = Connector::serving(view, Arc::new(judge), None, Arc::new(|_, _| {}));
        c.declare_need(
            OWNER,
            NeedId(0),
            "bytes",
            busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER,
        )
        .expect("a provider need declares");
        c.declare_need(OWNER, NeedId(1), "bytes", crate::DEFAULT_CLASS)
            .expect("a default-class need declares");
        let id = open_in(&c, 0, "169.254.169.254:80")
            .expect("the provider's carve-out reaches its metadata address");
        c.close(OWNER, id).unwrap();
        assert_eq!(
            open_in(&c, 1, "169.254.169.254:80"),
            Err(ConnError::Refused),
            "no carve-out speaks for another class"
        );
        assert_eq!(
            open_in(&c, 0, "100.100.100.200:80"),
            Err(ConnError::Refused),
            "a carve-out admits only what it names"
        );
    });
}

/// RED (ARCHITECT rule 15.3: ports `execute_hop_does_not_follow_redirect`, deleted with the
/// core-run login hop): THE CONNECTOR NEVER FOLLOWS AN ANSWER. A far end answering a `302` whose
/// `Location` names another listener hands that answer to the need's owner through the table, byte
/// for byte, and the connector dials nothing the answer names: the listener it points at never sees
/// a connection, so nothing the request carried (a token exchange's client secret) is re-sent there.
#[test]
fn an_answer_naming_another_place_is_handed_up_and_never_dialled() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let answer = format!(
            "HTTP/1.1 302 Found\r\nlocation: http://{}/steal\r\ncontent-length: 0\r\n\r\n",
            elsewhere.local_addr().unwrap()
        );
        let sent = answer.clone().into_bytes();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&sent).await.unwrap();
        });
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"token",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut got = Vec::new();
        let mut buf = [0_u8; 256];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < answer.len() {
            assert!(std::time::Instant::now() < deadline, "the answer arrives");
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                Ok(piece) => got.extend_from_slice(&buf[..piece.len]),
                Err(e) => panic!("the exchange failed: {e:?}"),
            }
        }
        assert_eq!(got, answer.as_bytes(), "the redirect is the answer");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let dialled =
            tokio::time::timeout(std::time::Duration::from_millis(50), elsewhere.accept()).await;
        assert!(dialled.is_err(), "the location was never dialled");
        c.close(OWNER, id).unwrap();
    });
}

/// RED (ARCHITECT parity ruling A5; ports `sanitize_hop_header_rejects_crlf_and_hop_control` and
/// `execute_hop_refuses_a_crlf_injected_header`, v1.5.5 `crates/busbar/src/auth/token.rs:805`
/// `FORBIDDEN_HOP_HEADERS`, `:893-907` `sanitize_hop_header`, `crates/busbar/src/auth/tests/
/// token_tests.rs:750-762`): a plugin's exchange whose head carries a NUL (or a CR or LF) in its
/// target, its request target, its method, a field name or a field value, or a field stating the
/// message's own framing (`Content-Length`, `Transfer-Encoding`, any case), is REFUSED whole before
/// anything is dialled: the far end never sees a connection, so no byte of it (a token exchange's
/// client secret) leaves. A clean head with an `Authorization` field opens. RED on the connector
/// that handed every head to the framer.
#[test]
fn a_head_carrying_nul_or_its_own_framing_is_refused_before_any_dial() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let nul_target = format!("{far}\0");
        let clean: &[(&str, &[u8])] = &[("authorization", b"Bearer abc.def".as_slice())];
        let refused: &[(&str, OpenDesc<'_>)] = &[
            (
                "NUL in the target",
                OpenDesc {
                    target: &nul_target,
                    ..OpenDesc::default()
                },
            ),
            (
                "NUL in the request target",
                OpenDesc {
                    target: &far,
                    head_target: b"/v1/\0traces",
                    ..OpenDesc::default()
                },
            ),
            (
                "NUL in the method",
                OpenDesc {
                    target: &far,
                    method: b"PO\0ST",
                    ..OpenDesc::default()
                },
            ),
            (
                "NUL in a field value",
                OpenDesc {
                    target: &far,
                    fields: &[("x-nul", b"a\0b".as_slice())],
                    ..OpenDesc::default()
                },
            ),
            (
                "NUL in a field name",
                OpenDesc {
                    target: &far,
                    fields: &[("x-\0nul", b"v".as_slice())],
                    ..OpenDesc::default()
                },
            ),
            (
                "CRLF in a field value",
                OpenDesc {
                    target: &far,
                    fields: &[("x-evil", b"a\r\nInjected: 1".as_slice())],
                    ..OpenDesc::default()
                },
            ),
            (
                "LF in a field name",
                OpenDesc {
                    target: &far,
                    fields: &[("Bad\nName", b"v".as_slice())],
                    ..OpenDesc::default()
                },
            ),
            (
                "CRLF in the request target",
                OpenDesc {
                    target: &far,
                    head_target: b"/v1\r\nX: y",
                    ..OpenDesc::default()
                },
            ),
            (
                "the plugin's own content-length",
                OpenDesc {
                    target: &far,
                    fields: &[
                        ("authorization", b"Bearer abc.def".as_slice()),
                        ("content-length", b"5".as_slice()),
                    ],
                    body: b"token",
                    ..OpenDesc::default()
                },
            ),
            (
                "the plugin's own Content-Length",
                OpenDesc {
                    target: &far,
                    fields: &[("Content-Length", b"0".as_slice())],
                    ..OpenDesc::default()
                },
            ),
            (
                "the plugin's own transfer-encoding",
                OpenDesc {
                    target: &far,
                    fields: &[("Transfer-Encoding", b"chunked".as_slice())],
                    body: b"token",
                    ..OpenDesc::default()
                },
            ),
            (
                "the plugin's own TRANSFER-ENCODING",
                OpenDesc {
                    target: &far,
                    fields: &[("TRANSFER-ENCODING", b"identity".as_slice())],
                    ..OpenDesc::default()
                },
            ),
        ];
        for (why, desc) in refused {
            assert_eq!(
                c.open(OWNER, NeedId(0), desc),
                Err(ConnError::Refused),
                "{why}"
            );
        }
        let dialled = tokio::time::timeout(std::time::Duration::from_millis(100), l.accept()).await;
        assert!(dialled.is_err(), "a refused head dials nothing");
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &far,
                    fields: clean,
                    method: b"POST",
                    head_target: b"/v1/traces",
                    body: b"token",
                    ..OpenDesc::default()
                },
            )
            .expect("a clean head opens");
        c.close(OWNER, id).unwrap();
    });
}

/// RED (ARCHITECT ruling on #780, Part 1 Law 0 and Part 2 #3; ports the `Host` arm of
/// `sanitize_hop_header_rejects_crlf_and_hop_control`, v1.5.5 `crates/busbar/src/auth/token.rs:805`
/// `FORBIDDEN_HOP_HEADERS`, `crates/busbar/src/auth/tests/token_tests.rs:750-762`): where the host
/// writes an instance's authority ([`DeclaredConns::hold_authority`], held by the loader for every
/// auth-kind instance), an open whose head carries a `host` field of its own (any case) is REFUSED
/// before anything is dialled, as 1.5.5 refused it on an auth module's token exchange: the far end
/// sees no connection. The same instance's clean head opens. GREEN ARM: an instance the host holds
/// no authority for (a plane's upstream, which may sign its `host`, SigV4) opens with the `host`
/// field it wrote. RED on the head check that refused only the framing fields.
#[test]
fn an_auth_instances_own_host_field_is_refused_before_any_dial() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.hold_authority(OWNER);
        for owner in [OWNER, OTHER] {
            c.declare_over(owner, NeedId(0), "bytes")
                .expect("a served scheme declares");
        }
        for host in ["host", "Host", "HOST", " host"] {
            let fields: &[(&str, &[u8])] = &[
                ("content-type", b"application/x-www-form-urlencoded".as_slice()),
                (host, b"idp.example.com".as_slice()),
            ];
            assert_eq!(
                c.open(
                    OWNER,
                    NeedId(0),
                    &OpenDesc {
                        target: &far,
                        fields,
                        method: b"POST",
                        head_target: b"/token",
                        body: b"grant_type=authorization_code",
                        ..OpenDesc::default()
                    },
                ),
                Err(ConnError::Refused),
                "the auth instance's own {host:?} field"
            );
        }
        let dialled = tokio::time::timeout(std::time::Duration::from_millis(100), l.accept()).await;
        assert!(dialled.is_err(), "a refused head dials nothing");
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &far,
                    fields: &[("content-type", b"application/x-www-form-urlencoded".as_slice())],
                    method: b"POST",
                    head_target: b"/token",
                    body: b"grant_type=authorization_code",
                    ..OpenDesc::default()
                },
            )
            .expect("the auth instance's clean head opens");
        c.close(OWNER, id).unwrap();
        // GREEN ARM: a plane's upstream keeps the `host` field it wrote (and signed).
        let id = c
            .open(
                OTHER,
                NeedId(0),
                &OpenDesc {
                    target: &far,
                    fields: &[
                        ("host", b"upstream.example.com".as_slice()),
                        ("authorization", b"AWS4-HMAC-SHA256 Credential=AKID/20261012/us-east-1/svc/aws4_request, SignedHeaders=host;x-amz-date, Signature=00".as_slice()),
                    ],
                    method: b"POST",
                    head_target: b"/v1/op",
                    body: b"{}",
                    ..OpenDesc::default()
                },
            )
            .expect("a plane's signed host field opens");
        c.close(OTHER, id).unwrap();
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

/// A far end that takes the opening and then holds the connection open, answering nothing, until
/// `release` fires (or `answer` is written first, after `after`, then held again).
fn stalled_far_end(
    l: tokio::net::TcpListener,
    answer: Option<(
        std::time::Duration,
        &'static [u8],
        std::time::Duration,
        &'static [u8],
    )>,
) {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = [0_u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        if let Some((after, first, then, second)) = answer {
            tokio::time::sleep(after).await;
            s.write_all(first).await.unwrap();
            tokio::time::sleep(then).await;
            s.write_all(second).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(s);
    });
}

/// RED (ARCHITECT timeout ruling, step 2; BUSBAR-1.6.0.md:4890): `timeout_ms` bounds the WHOLE
/// request until its answer, not only the dial. A far end that connects, takes the request and
/// never answers is a timeout once the bound passes: a host-side reader is woken with it, within
/// the bound and not at the far end's leisure.
#[test]
fn a_request_bound_times_out_a_far_end_that_never_answers() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        stalled_far_end(l, None);
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            timeout_ms: 300,
            ..OpenDesc::default()
        };
        let started = std::time::Instant::now();
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)),
        )
        .await
        .expect("the bound woke the reader before the far end ever answered");
        assert_eq!(read, Err(ConnError::Timeout));
        let took = started.elapsed();
        assert!(
            took >= std::time::Duration::from_millis(300)
                && took < std::time::Duration::from_secs(2),
            "timed out at the bound, not before it and not long after: {took:?}"
        );
        assert_eq!(
            c.read(OWNER, id, 7, &mut buf),
            Err(ConnError::Timeout),
            "a read after the bound stays a timeout"
        );
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a plugin reader (a ticket, as WRITE_REQUEST's exchange reads) waiting on a request past
/// its bound has its ticket woken, and its next read is the timeout.
#[test]
fn a_request_bound_wakes_a_plugin_ticket_with_the_timeout() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        stalled_far_end(l, None);
        let wakes = Arc::new(AtomicU64::new(0));
        let c = serving(wakes.clone());
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            timeout_ms: 200,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let started = std::time::Instant::now();
        let read = loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(5),
                        "never timed out"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                other => break other,
            }
        };
        assert_eq!(read, Err(ConnError::Timeout));
        assert!(
            wakes.load(Ordering::SeqCst) >= 1,
            "the ticket was woken by the bound"
        );
        assert_eq!(
            c.wait(OWNER, &[id], 7),
            Ok(0),
            "a request past its bound is ready to read"
        );
    });
}

/// The bound ends where the answer begins: an answer whose first piece arrived inside the bound is
/// read to its end even when its later pieces arrive after it.
#[test]
fn a_request_bound_is_spent_once_the_answer_begins() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        let ms = std::time::Duration::from_millis;
        stalled_far_end(l, Some((ms(20), b"head", ms(400), b"tail")));
        let c = serving(Arc::new(AtomicU64::new(0)));
        c.declare_over(OWNER, NeedId(0), "bytes")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"first",
            timeout_ms: 200,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut got = Vec::new();
        while got.len() < 8 {
            let mut buf = [0_u8; 64];
            let piece = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)),
            )
            .await
            .expect("the answer arrives")
            .expect("an answer begun inside the bound is not cut by it");
            got.extend_from_slice(&buf[..piece.len]);
        }
        assert_eq!(got, b"headtail");
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
        Arc::new(|_, _| {}),
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

/// RED (SEAM-4f, ARCHITECT ruling on mint endpoints: https or loopback plaintext, as 1.5.5
/// validated `token_url`/`token_uri`): a mint endpoint's need, its target the binding's own setting,
/// in the `loopback-allowed` class, dials a plaintext loopback endpoint and refuses a plaintext
/// private one; the `open-web` class it was declared in refused the loopback endpoint outright.
/// Each refusal is the need's ADMISSION at declare (the target is pinned, so its static facts are
/// judged there, G1(a)), and every open on the refused need is refused with it.
#[test]
fn a_configured_mint_endpoint_takes_loopback_plaintext_and_nothing_else_in_plaintext() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let c = scheme_connector();
        let need = |class| ReadNeed {
            egress_class: class,
            transport: "plain".to_owned(),
            ..config_targeted_need("settings.token_url")
        };
        let declare = |id, class, target: &str| {
            DeclaredConns::declare(&c, OWNER, NeedId(id), &need(class), Some(target), None)
        };
        assert_eq!(declare(0, EGRESS_LOOPBACK_ALLOWED, &far), Ok(()));
        let id = open_in(&c, 0, &far).expect("a loopback plaintext mint endpoint opens");
        c.close(OWNER, id).unwrap();
        assert_eq!(
            declare(1, EGRESS_LOOPBACK_ALLOWED, "10.1.2.3:80"),
            Err(ConnError::Refused),
            "plaintext off loopback, refused at its admission"
        );
        assert_eq!(
            open_in(&c, 1, "10.1.2.3:80"),
            Err(ConnError::Refused),
            "plaintext off loopback"
        );
        assert_eq!(
            declare(2, EGRESS_OPEN_WEB, &far),
            Err(ConnError::Refused),
            "open-web refuses every plaintext endpoint, at its admission"
        );
        assert_eq!(
            open_in(&c, 2, &far),
            Err(ConnError::Refused),
            "open-web refuses every plaintext endpoint"
        );
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
            c.emit(OTHER, id, stream, b"x", false, false),
            Err(ConnError::NotOwner)
        );
        c.emit(OWNER, id, stream, b"welcome"[..5].as_ref(), false, false)
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

/// RED (ARCHITECT ruling 2026-10-02, WIRE-EXPORT userinfo; kept by the row 159 settings-URL
/// userinfo ruling (a)): the refusal of a userinfo in a need's target STAYS for every target the need's own
/// settings did not give it — a need with no `target_from`, a member path, a path outside its
/// settings. Such a target carrying a userinfo — a URL's `user:pass@` or a bare `user@host:port` —
/// is REFUSED, fail closed: the answer is kept for the need's admission, and nothing opens on it.
/// So is a settings-derived target whose userinfo cannot be read out of it. The same target
/// without the userinfo is declared.
#[test]
fn a_target_not_from_its_own_settings_carrying_a_userinfo_is_still_refused() {
    worker().block_on(async {
        let (_listening, resolved) = far_end().await;
        let c = literal_connector();
        let refused = |need: &ReadNeed, credentialed: &str| {
            assert_eq!(
                DeclaredConns::declare(&c, OWNER, NeedId(0), need, Some(credentialed), None),
                Err(ConnError::Refused),
                "{:?} {credentialed}",
                need.target_from
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
        };
        for target_from in [
            "",
            "settings.*.url",
            "request.url",
            "settings.",
            "settings..url",
        ] {
            let need = config_targeted_need(target_from);
            for credentialed in [
                format!("http://user:secret@{resolved}/v1/traces"),
                format!("user@{resolved}"),
            ] {
                refused(&need, &credentialed);
            }
        }
        refused(
            &config_targeted_need("settings.url"),
            &format!("http:\\\\user:secret@{resolved}/v1/traces"),
        );
        assert_eq!(
            DeclaredConns::declare(
                &c,
                OWNER,
                NeedId(0),
                &config_targeted_need("settings.url"),
                Some(&format!("http://{resolved}/v1/traces")),
                None
            ),
            Ok(())
        );
    });
}

/// RED (ARCHITECT ruling, row 159 settings-URL userinfo finding (a)(b)): USERINFO IS NOT PART OF A
/// SETTINGS-DERIVED TARGET. A need whose `target_from` reads the plugin's own settings, declared
/// with a target carrying a userinfo — a URL's `user:pass@`, a bare `user:pass@host:port` or
/// `user@host:port` — is declared, pinned to that target WITHOUT the userinfo, and opens there.
/// The userinfo is dropped: no record the connector keeps holds it, no event logged while the need
/// is declared, admitted, opened or refused carries it, and no error text says it.
#[test]
fn a_settings_derived_target_is_declared_without_its_userinfo() {
    const USER: &str = "the-user";
    const SECRET: &str = "s3cret-pw";
    let cap = crate::warn_capture::WarnCapture::capturing_debug();
    let mut said: Vec<String> = Vec::new();
    tracing::subscriber::with_default(cap.clone(), || {
        worker().block_on(async {
            let (_listening, resolved) = far_end().await;
            let c = literal_connector();
            let need = config_targeted_need("settings.url");
            let pinned = |need_id: NeedId| {
                c.over
                    .lock()
                    .unwrap()
                    .get(&(OWNER, need_id))
                    .and_then(|d| d.declared_target.clone())
            };
            for (credentialed, cleared) in [
                (
                    format!("http://{USER}:{SECRET}@{resolved}/v1/traces"),
                    format!("http://{resolved}/v1/traces"),
                ),
                (format!("{USER}:{SECRET}@{resolved}"), resolved.clone()),
                (format!("{USER}@{resolved}"), resolved.clone()),
            ] {
                assert_eq!(
                    DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some(&credentialed), None),
                    Ok(()),
                    "{credentialed}"
                );
                assert_eq!(DeclaredConns::declared(&c, OWNER, NeedId(0)), Some(Ok(())));
                assert_eq!(pinned(NeedId(0)).as_deref(), Some(cleared.as_str()));
                said.push(format!("{:?}", pinned(NeedId(0))));
                said.push(format!("{:?}", c.declared_spec(OWNER, NeedId(0))));
            }
            // The cleared target is the one the need dials: an open naming none opens there.
            let id = c
                .open(OWNER, NeedId(0), &OpenDesc::default())
                .expect("the cleared target opens");
            c.close(OWNER, id).unwrap();
            // A settings-derived target refused on other grounds (a cloud metadata host) says
            // nothing of its userinfo either, and leaves no record of it.
            let metadata = format!("{USER}:{SECRET}@169.254.169.254:80");
            let e = DeclaredConns::declare(&c, OWNER, NeedId(1), &need, Some(&metadata), None)
                .expect_err("a metadata host is refused");
            said.push(format!("{e:?} {}", e.text()));
            assert_eq!(pinned(NeedId(1)), None);
            let e = c
                .open(OWNER, NeedId(1), &OpenDesc::default())
                .expect_err("nothing opens on a refused need");
            said.push(format!("{e:?} {}", e.text()));
        });
    });
    said.extend(cap.messages());
    for line in &said {
        assert!(
            !line.contains(SECRET) && !line.contains(USER),
            "the dropped userinfo was repeated: {line}"
        );
    }
}

// ── a need whose target is a PROGRAM ───────────────────────────────────────────────────────────

/// An outbound program need over the test transport, in `class`, with `auth`.
fn program_need(class: u32, auth: &str) -> ReadNeed {
    ReadNeed {
        egress_class: class,
        auth: auth.to_owned(),
        ..config_targeted_need("settings.server")
    }
}

fn program(command: &str, args: &[&str], env: &[(&str, &str)]) -> busbar_contract::conn::Program {
    busbar_contract::conn::Program {
        command: command.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        env_refs: Vec::new(),
    }
}

/// Read until `want` bytes arrived (or the connection ended), driving it by the caller's reads.
async fn read_all(c: &Connector, id: ConnId, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0_u8; 256];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while got.len() < want && std::time::Instant::now() < deadline {
        match c.read(OWNER, id, 7, &mut buf) {
            Ok(piece) => {
                got.extend_from_slice(&buf[..piece.len]);
                if piece.kind == PieceKind::Completion {
                    break;
                }
            }
            Err(ConnError::Pending) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Err(e) => panic!("the read failed: {e:?}"),
        }
    }
    got
}

/// Whether process `pid` is gone (or a zombie: it ended and waits to be reaped).
fn gone(pid: &str) -> bool {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("ps runs");
    let stat = String::from_utf8_lossy(&out.stdout);
    stat.trim().is_empty() || stat.trim().starts_with('Z')
}

/// RED (ARCHITECT round 4 (e)): a need whose `target_from` resolved to a PROGRAM is carried in the
/// operator-infrastructure class: every open spawns it (no shell, only its stated environment),
/// its stdin and stdout are the connection, and the connector kills it on close.
#[test]
fn a_program_need_spawns_its_program_and_kills_it_on_close() {
    use busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    worker().block_on(async {
        let c = literal_connector();
        let need = program_need(EGRESS_OPERATOR_INFRASTRUCTURE, "");
        // The program states its process id, then echoes what it is sent.
        let echo = program("/bin/sh", &["-c", "echo $$; exec /bin/cat"], &[]);
        assert_eq!(
            DeclaredConns::declare_program(&c, OWNER, NeedId(0), &need, &echo),
            Ok(())
        );
        assert_eq!(DeclaredConns::declared(&c, OWNER, NeedId(0)), Some(Ok(())));
        let id = c
            .open(OWNER, NeedId(0), &OpenDesc::default())
            .expect("the program opens");
        let first = read_all(&c, id, 1).await;
        let line = String::from_utf8(first).unwrap();
        let pid = line.lines().next().expect("the pid line").trim().to_owned();
        assert!(pid.parse::<u32>().is_ok(), "{line:?}");
        assert_eq!(c.write(OWNER, id, b"hello\n", true, false), Ok(6));
        let echoed = read_all(&c, id, 6).await;
        assert_eq!(echoed, b"hello\n");
        assert!(!gone(&pid), "the program runs while the connection is open");
        c.close(OWNER, id).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !gone(&pid) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone(&pid), "the connector killed the program on close");
    });
}

/// The program's environment is ONLY what its settings state: nothing of the host's leaks in.
#[test]
fn a_program_inherits_no_environment_but_its_own() {
    use busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    worker().block_on(async {
        let c = literal_connector();
        let need = program_need(EGRESS_OPERATOR_INFRASTRUCTURE, "");
        let env = program("/usr/bin/env", &[], &[("DECLARED", "yes")]);
        DeclaredConns::declare_program(&c, OWNER, NeedId(0), &need, &env).unwrap();
        let id = c.open(OWNER, NeedId(0), &OpenDesc::default()).unwrap();
        let out = read_all(&c, id, usize::MAX).await;
        assert_eq!(String::from_utf8(out).unwrap(), "DECLARED=yes\n");
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a program need is refused outside the operator-infrastructure class, with an auth style,
/// over an unserved scheme, or for a command that is not an absolute path — and an open on it that
/// names a target of its own is refused: it spawns its program and nothing else.
#[test]
fn a_program_need_is_refused_unless_the_operator_declared_it_as_written() {
    use busbar_contract::abi::host::conn::connector::{
        EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    worker().block_on(async {
        let c = literal_connector();
        let cat = program("/bin/cat", &[], &[]);
        let refused = |need: &ReadNeed, p: &busbar_contract::conn::Program| {
            assert_eq!(
                DeclaredConns::declare_program(&c, OWNER, NeedId(0), need, p),
                Err(ConnError::Refused)
            );
            assert!(
                c.open(OWNER, NeedId(0), &OpenDesc::default()).is_err(),
                "nothing opens on a refused need"
            );
        };
        refused(&program_need(EGRESS_OPEN_WEB, ""), &cat);
        refused(&program_need(crate::DEFAULT_CLASS, ""), &cat);
        refused(
            &program_need(EGRESS_OPERATOR_INFRASTRUCTURE, "bearer"),
            &cat,
        );
        refused(
            &ReadNeed {
                transport: "nowhere".into(),
                ..program_need(EGRESS_OPERATOR_INFRASTRUCTURE, "")
            },
            &cat,
        );
        refused(
            &program_need(EGRESS_OPERATOR_INFRASTRUCTURE, ""),
            &program("cat", &[], &[]),
        );
        let need = program_need(EGRESS_OPERATOR_INFRASTRUCTURE, "");
        DeclaredConns::declare_program(&c, OWNER, NeedId(0), &need, &cat).unwrap();
        assert_eq!(
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "127.0.0.1:1",
                    ..OpenDesc::default()
                }
            ),
            Err(ConnError::Refused),
            "a program need dials no target of the open's"
        );
    });
}

/// RED (ARCHITECT, the stream-end ruling): a dialled exchange's EMPTY answers, binary and text,
/// reach the caller as body pieces; the exchange completes only on the framer's `PIECE_END`, never
/// on an empty piece.
#[test]
fn a_dialled_exchange_relays_empty_messages_and_completes_only_on_the_end_flag() {
    worker().block_on(async {
        let (l, far) = far_end().await;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 3];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"btxe").await.unwrap();
            let mut hold = [0_u8; 1];
            let _ = s.read(&mut hold).await;
        });
        let view = Transports::new(vec![
            Entry {
                door: Arc::new(TestDoor::new(
                    "messages",
                    &["messages"],
                    &[],
                    crate::support::Knobs {
                        messages: Some(crate::compose::EXCHANGE_STREAM),
                        ..crate::support::Knobs::default()
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
        let c = Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {}));
        c.declare_over(OWNER, NeedId(0), "messages")
            .expect("a served scheme declares");
        let desc = OpenDesc {
            target: &far,
            body: b"ask",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match c.read(OWNER, id, 7, &mut buf) {
                Ok(p) => {
                    seen.push((p.kind, buf[..p.len].to_vec()));
                    if p.kind == PieceKind::Completion {
                        break;
                    }
                }
                Err(ConnError::Pending) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(e) => panic!("the read failed: {e:?}"),
            }
        }
        assert_eq!(
            seen,
            [
                (PieceKind::Body, Vec::new()),
                (PieceKind::Body, Vec::new()),
                (PieceKind::Body, b"x".to_vec()),
                (PieceKind::Completion, Vec::new()),
            ],
            "two empty messages and one byte, then the exchange's end"
        );
        c.close(OWNER, id).unwrap();
    });
}

/// THE TRANSPORT PIN (the transport pin, ARCHITECT 2026-10-03): a destination's sealed trust
/// anchors are enforced by the connector itself on every connection to it, against a real TLS far
/// end on loopback whose certificate chains to a test root the connector trusts.
mod transport_pin {
    use std::sync::{Arc, Mutex};

    use busbar_contract::transport::trust::{key_pin, Anchors, ClientIdentity, EgressTrust};
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair, PublicKeyData as _};

    use super::*;
    use crate::registry::{Entry, Transports};
    use crate::support::{worker, TestDoor};

    /// A test root and the leaves it issues.
    struct Pki {
        ca_der: Vec<u8>,
        /// The root as PEM: what a need's `trust_from` resolves to.
        ca_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    /// One issued leaf: its DER, its key's PKCS#8 DER, and its key's pin, taken off the key pair
    /// itself (never off the certificate the connector walks).
    struct Leaf {
        der: Vec<u8>,
        key: Vec<u8>,
        pin: String,
    }

    impl Pki {
        /// A fresh root under a subject no other root of this process carries: two roots sharing
        /// a subject would make one a name-match candidate for the other's leaves, and a leaf
        /// under an unrelated root would then be refused on its signature, not as an unknown
        /// issuer.
        fn new() -> Self {
            static ROOTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = ROOTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let kp = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::new()).unwrap();
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                format!("connector test root {n}"),
            );
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = params.self_signed(&kp).unwrap();
            Self {
                ca_der: ca.der().to_vec(),
                ca_pem: ca.pem(),
                issuer: Issuer::new(params, kp),
            }
        }

        fn leaf(&self, name: &str) -> Leaf {
            let kp = KeyPair::generate().unwrap();
            let cert = CertificateParams::new(vec![name.to_string()])
                .unwrap()
                .signed_by(&kp, &self.issuer)
                .unwrap();
            Leaf {
                der: cert.der().to_vec(),
                key: kp.serialize_der(),
                pin: key_pin(&kp.subject_public_key_info()),
            }
        }
    }

    /// What the far end saw on one connection: the bytes it read, and whether the dialler
    /// presented a client certificate.
    type Seen = Arc<Mutex<Option<(Vec<u8>, bool)>>>;

    /// A TLS far end on loopback serving `leaf` (asking for a client certificate under `pki`'s
    /// root when `mutual`), answering `answer` once it read five bytes: its address, and what it
    /// saw.
    async fn tls_far_end(pki: &Pki, leaf: &Leaf, mutual: bool) -> (String, Seen) {
        crate::tls::install_crypto_provider();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
        let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key.clone()).unwrap();
        let builder = rustls::ServerConfig::builder();
        let config = if mutual {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls_pki_types::CertificateDer::from(pki.ca_der.clone()))
                .unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        }
        .with_single_cert(chain, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (l, far) = far_end().await;
        let seen: Seen = Arc::default();
        let saw = Arc::clone(&seen);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, saw) = (acceptor.clone(), Arc::clone(&saw));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let presented = tls.get_ref().1.peer_certificates().is_some();
                    let mut buf = [0_u8; 5];
                    let got = tls.read_exact(&mut buf).await.map(|_| buf.to_vec());
                    *saw.lock().unwrap() = Some((got.unwrap_or_default(), presented));
                    let _ = tls.write_all(b"answer").await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (far, seen)
    }

    /// A connector serving a door whose targets ask for connection security under the name
    /// `localhost` (`sec`) and a plaintext one (`plain`), trusting `pki`'s root, with `need` 0
    /// declared over `sec` and need 1 over `plain`.
    fn trusting(pki: &Pki) -> Connector {
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
        let tls = crate::tls::client::build_client_config(&EgressTrust {
            extra_anchors: vec![pki.ca_der.clone()],
            ..EgressTrust::default()
        })
        .unwrap();
        let c = Connector::serving(
            view,
            loopback_literals(),
            Some(Arc::new(tls)),
            Arc::new(|_, _| {}),
        );
        c.declare_over(OWNER, NeedId(0), "sec").unwrap();
        c.declare_over(OWNER, NeedId(1), "plain").unwrap();
        c
    }

    /// Open need 0 at `far` with a five-byte opening body and read to its first answer: the
    /// connection, and the read's answer.
    async fn exchange(c: &Connector, far: &str) -> (ConnId, Result<Vec<u8>, ConnError>) {
        let desc = OpenDesc {
            target: far,
            body: b"first",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(p) => return (id, Ok(buf[..p.len].to_vec())),
                Err(e) => return (id, Err(e)),
            }
        }
    }

    /// A far end serving the pinned key is reached, and the connection's facts carry the key it
    /// observed; no client identity was presented (none is sealed).
    #[test]
    fn a_far_end_serving_the_pinned_key_is_reached_and_its_key_is_the_facts() {
        worker().block_on(async {
            let pki = Pki::new();
            let leaf = pki.leaf("localhost");
            let (far, seen) = tls_far_end(&pki, &leaf, false).await;
            let c = trusting(&pki);
            let anchors = Anchors {
                key_pin: Some(format!(" {} ", leaf.pin)),
                client_identity: None,
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                .expect("sealed");
            let (id, got) = exchange(&c, &far).await;
            assert_eq!(got.as_deref(), Ok(&b"answer"[..]));
            let facts = c.facts(OWNER, id).expect("facts");
            assert_eq!(facts.peer_key_pin.as_deref(), Some(leaf.pin.as_str()));
            assert!(!facts.client_identity);
            assert_eq!(
                seen.lock().unwrap().clone(),
                Some((b"first".to_vec(), false))
            );
        });
    }

    /// RED: a far end serving ANOTHER key (a valid chain, the right name) is refused after its
    /// handshake and before a request byte is written; the facts still name the key it served.
    #[test]
    fn a_far_end_serving_another_key_is_refused_before_any_request_byte() {
        worker().block_on(async {
            let pki = Pki::new();
            let pinned = pki.leaf("localhost");
            let served = pki.leaf("localhost");
            let (far, seen) = tls_far_end(&pki, &served, false).await;
            let c = trusting(&pki);
            let anchors = Anchors {
                key_pin: Some(pinned.pin.clone()),
                client_identity: None,
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                .expect("sealed");
            let (id, got) = exchange(&c, &far).await;
            assert_eq!(got, Err(ConnError::Refused));
            let facts = c.facts(OWNER, id).expect("facts after the refusal");
            assert_eq!(facts.peer_key_pin.as_deref(), Some(served.pin.as_str()));
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert!(
                seen.lock()
                    .unwrap()
                    .as_ref()
                    .is_none_or(|(bytes, _)| bytes.is_empty()),
                "no request byte reached the far end"
            );
            c.close(OWNER, id).expect("closed");
            // Unsealed, the same far end is reached again: the refusal was the anchors'.
            c.anchor(OWNER, NeedId(0), "", &far, &Anchors::default())
                .expect("unsealed");
            let (_, got) = exchange(&c, &far).await;
            assert_eq!(got.as_deref(), Ok(&b"answer"[..]));
        });
    }

    /// A far end that asks for a client certificate is presented the sealed identity, and the
    /// facts say so; without one sealed, the same far end refuses the handshake.
    #[test]
    fn a_sealed_client_identity_is_presented_to_a_mutual_far_end() {
        worker().block_on(async {
            let pki = Pki::new();
            let server = pki.leaf("localhost");
            let client = pki.leaf("busbar.client");
            let (far, seen) = tls_far_end(&pki, &server, true).await;
            let c = trusting(&pki);
            let (_, got) = exchange(&c, &far).await;
            assert!(got.is_err(), "no identity: the mutual far end refuses");
            let anchors = Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![client.der.clone()],
                    private_key: client.key.clone().into(),
                }),
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                .expect("sealed");
            let (id, got) = exchange(&c, &far).await;
            assert_eq!(got.as_deref(), Ok(&b"answer"[..]));
            let facts = c.facts(OWNER, id).expect("facts");
            assert!(facts.client_identity, "the identity was presented");
            assert_eq!(facts.peer_key_pin.as_deref(), Some(server.pin.as_str()));
            assert_eq!(
                seen.lock().unwrap().clone(),
                Some((b"first".to_vec(), true))
            );
        });
    }

    /// Open need 0 at `far` naming registration `member` and read to its first answer.
    async fn exchange_as(c: &Connector, far: &str, member: &str) -> Result<Vec<u8>, ConnError> {
        let desc = OpenDesc {
            target: far,
            body: b"first",
            member,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(p) => return Ok(buf[..p.len].to_vec()),
                Err(e) => return Err(e),
            }
        }
    }

    /// RED: two REGISTRATIONS at one authority hold their own anchors. The first seals a client
    /// identity, the second (sealed after it, at the same `host:port`) seals none: an open naming
    /// the first still presents ITS identity to the mutual far end, and an open naming the second
    /// presents nothing, never the first's. Keyed by the authority alone, the second seal dropped
    /// the first's and the first registration's own open was refused.
    #[test]
    fn two_registrations_at_one_authority_each_present_their_own_identity() {
        worker().block_on(async {
            let pki = Pki::new();
            let server = pki.leaf("localhost");
            let client = pki.leaf("busbar.client");
            let (far, _seen) = tls_far_end(&pki, &server, true).await;
            let c = trusting(&pki);
            let own = Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![client.der.clone()],
                    private_key: client.key.clone().into(),
                }),
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "planner", &far, &own)
                .expect("sealed");
            c.anchor(OWNER, NeedId(0), "bare", &far, &Anchors::default())
                .expect("sealed");
            assert_eq!(
                exchange_as(&c, &far, "planner").await.as_deref(),
                Ok(&b"answer"[..]),
                "the registration presents its own identity"
            );
            assert!(
                exchange_as(&c, &far, "bare").await.is_err(),
                "a registration holding no identity presents none, never another's"
            );
        });
    }

    /// RED: a pinned destination reached without connection security has no key to hold, and is
    /// refused before any dial; an identity that does not parse refuses the seal.
    #[test]
    fn a_pinned_destination_over_plaintext_is_refused_and_a_bad_identity_refuses_the_seal() {
        worker().block_on(async {
            let pki = Pki::new();
            let leaf = pki.leaf("localhost");
            let (_listening, far) = far_end().await;
            let c = trusting(&pki);
            let anchors = Anchors {
                key_pin: Some(leaf.pin.clone()),
                client_identity: None,
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(1), "", &far, &anchors)
                .expect("sealed");
            assert_eq!(open_in(&c, 1, &far), Err(ConnError::Refused));
            let bad = Anchors {
                key_pin: None,
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![leaf.der.clone()],
                    private_key: b"not a key".to_vec().into(),
                }),
                private_reach: false,
            };
            assert_eq!(
                c.anchor(OWNER, NeedId(0), "", &far, &bad),
                Err(ConnError::Refused)
            );
            // A need the owner never declared seals nothing.
            assert_eq!(
                c.anchor(OTHER, NeedId(0), "", &far, &anchors),
                Err(ConnError::Refused)
            );
        });
    }

    /// A TLS far end on loopback serving `leaf`, answering every five bytes it reads with one
    /// one-byte message and the exchange's end (`xe`, the scripted entry's) and keeping each
    /// connection open: its address.
    async fn keeping_tls_far_end(leaf: &Leaf) -> String {
        crate::tls::install_crypto_provider();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
        let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key.clone()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (l, far) = far_end().await;
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((s, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let mut buf = [0_u8; 5];
                    while tls.read_exact(&mut buf).await.is_ok() {
                        if tls.write_all(b"xe").await.is_err() || tls.flush().await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        far
    }

    /// [`trusting`]'s connector, its secure entry answering the scripted messages, keeping every
    /// line an exchange finished on: need 0 is declared over it.
    fn pooled_trusting(pki: &Pki) -> Connector {
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
                        messages: Some(crate::compose::EXCHANGE_STREAM),
                        ..crate::support::Knobs::default()
                    },
                )),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let tls = crate::tls::client::build_client_config(&EgressTrust {
            extra_anchors: vec![pki.ca_der.clone()],
            ..EgressTrust::default()
        })
        .unwrap();
        let c = Connector::serving(
            view,
            loopback_literals(),
            Some(Arc::new(tls)),
            Arc::new(|_, _| {}),
        )
        .pooling(crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: std::time::Duration::from_secs(60),
        });
        c.declare_over(OWNER, NeedId(0), "sec").unwrap();
        c
    }

    /// RED (THE DESIGN §8, the connector holds every destination's trust; the transport pin): a
    /// line secured under one seal of a destination's anchors is never lent to an open held to
    /// another. Sealed again with a key the far end does not serve, the next open dials afresh and
    /// is refused at its handshake; keyed without the anchors, it rode the line verified under the
    /// old seal and the new pin was never checked.
    #[test]
    fn a_pooled_line_is_never_lent_once_its_destination_is_sealed_again() {
        worker().block_on(async {
            let pki = Pki::new();
            let served = pki.leaf("localhost");
            let other = pki.leaf("localhost");
            let far = keeping_tls_far_end(&served).await;
            let c = pooled_trusting(&pki);
            let pinned = |pin: &str| Anchors {
                key_pin: Some(pin.to_owned()),
                client_identity: None,
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "", &far, &pinned(&served.pin))
                .expect("sealed");
            assert_eq!(
                pooled_exchange(&c, (OWNER, 0), &far, b"first", true).await,
                (b"x".to_vec(), true, None),
                "held to the key it serves, the exchange finishes whole and its line is kept"
            );
            c.anchor(OWNER, NeedId(0), "", &far, &pinned(&other.pin))
                .expect("sealed again");
            let (got, _, failed) = pooled_exchange(&c, (OWNER, 0), &far, b"first", false).await;
            assert_eq!(
                (got, failed),
                (Vec::new(), Some(ConnError::Refused)),
                "the open is held to the new pin, never lent the line the old seal verified"
            );
        });
    }

    /// [`keeping_tls_far_end`], counting the connections it accepted: its address and the count.
    async fn counting_tls_far_end(leaf: &Leaf) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        crate::tls::install_crypto_provider();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
        let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key.clone()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (l, far) = far_end().await;
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((s, _)) = l.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let mut buf = [0_u8; 5];
                    while tls.read_exact(&mut buf).await.is_ok() {
                        if tls.write_all(b"xe").await.is_err() || tls.flush().await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (far, accepted)
    }

    /// A connector whose own trust is the public roots alone, its secure entry (riding the plain
    /// address carrier, as [`pooled_trusting`]'s does) answering the scripted messages, keeping
    /// every line an exchange finished on: a far end under a private root is reached only through
    /// a need whose `trust_from` names that root.
    fn pooled_public_roots() -> Connector {
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
                        messages: Some(crate::compose::EXCHANGE_STREAM),
                        ..crate::support::Knobs::default()
                    },
                )),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let tls = crate::tls::client::build_client_config(&EgressTrust::default()).unwrap();
        Connector::serving(
            view,
            loopback_literals(),
            Some(Arc::new(tls)),
            Arc::new(|_, _| {}),
        )
        .pooling(crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: std::time::Duration::from_secs(60),
        })
    }

    /// Declare `OWNER`'s need 0 over the secure entry, its `trust_from` resolved to `pem`.
    fn declare_operator_ca(c: &Connector, pem: &str) -> Result<(), ConnError> {
        let need = ReadNeed {
            direction: DIRECTION_OUTBOUND,
            egress_class: crate::DEFAULT_CLASS,
            transport: "sec".to_owned(),
            auth: String::new(),
            target_from: String::new(),
            trust_from: "settings.ca".to_owned(),
            details: busbar_contract::abi::mechanism::rendering::ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            timeout_ms: 0,
        };
        DeclaredConns::declare(c, OWNER, NeedId(0), &need, None, Some(pem))
    }

    /// RED (THE DESIGN §5, the host connector: a need's `trust_from` is "an extra trusted root
    /// added on top of the public roots"; §8, the connector holds each need's trust): a line
    /// verified under a need's operator CA is never lent once the need is declared again with
    /// another CA. The next open dials afresh and its handshake is refused, as the far end's root is
    /// no longer trusted; keyed without the need's client config, it rode the line the old CA
    /// verified and the new trust was never checked.
    #[test]
    fn a_pooled_line_is_never_lent_once_its_need_trusts_another_operator_ca() {
        worker().block_on(async {
            let pki = Pki::new();
            let other = Pki::new();
            let (far, accepted) = counting_tls_far_end(&pki.leaf("localhost")).await;
            let c = pooled_public_roots();
            declare_operator_ca(&c, &pki.ca_pem).expect("declared under its CA");
            assert_eq!(
                pooled_exchange(&c, (OWNER, 0), &far, b"first", true).await,
                (b"x".to_vec(), true, None),
                "under the CA that signed the far end, the exchange finishes whole and its line is kept"
            );
            declare_operator_ca(&c, &other.ca_pem).expect("declared again under another CA");
            let (got, _, failed) = pooled_exchange(&c, (OWNER, 0), &far, b"again", false).await;
            assert_eq!(
                (got, failed),
                (Vec::new(), Some(ConnError::Refused)),
                "the open is held to the need's new CA, never lent the line the old CA verified"
            );
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                2,
                "the open under the new CA dialled afresh"
            );
        });
    }

    /// GREEN twin: a need declared once under its operator CA keeps pooling: its next open rides
    /// the line its first exchange finished on, and the far end accepts one connection only. (The
    /// scripted framer answers on its one stream, so an exchange over a lent line is read to its
    /// first byte, as `a_pooled_line_is_never_lent_to_another_need_or_instance`'s is.)
    #[test]
    fn a_need_under_its_operator_ca_rides_its_own_pooled_line() {
        worker().block_on(async {
            let pki = Pki::new();
            let (far, accepted) = counting_tls_far_end(&pki.leaf("localhost")).await;
            let c = pooled_public_roots();
            declare_operator_ca(&c, &pki.ca_pem).expect("declared under its CA");
            assert_eq!(
                pooled_exchange(&c, (OWNER, 0), &far, b"first", true).await,
                (b"x".to_vec(), true, None),
                "under the need's CA, the exchange finishes whole and its line is kept"
            );
            let (got, _, failed) = pooled_exchange(&c, (OWNER, 0), &far, b"again", false).await;
            assert_eq!(
                (got, failed),
                (b"x".to_vec(), None),
                "the need's next open is answered under its CA"
            );
            assert_eq!(
                accepted.load(Ordering::SeqCst),
                1,
                "the need's next open rode its kept line"
            );
        });
    }

    /// Every per-instance record `c` still holds for `owner`, by name.
    fn records_of(c: &Connector, owner: InstanceId) -> Vec<&'static str> {
        let mut held = Vec::new();
        if c.over.lock().unwrap().keys().any(|(o, _)| *o == owner) {
            held.push("needs");
        }
        if c.declared.lock().unwrap().keys().any(|(o, _)| *o == owner) {
            held.push("declarations");
        }
        if c.slab.check_need(owner, NeedId(0)).is_ok() {
            held.push("table needs");
        }
        if c.anchored
            .lock()
            .unwrap()
            .keys()
            .any(|(o, _, _)| *o == owner)
        {
            held.push("sealed destinations");
        }
        if c.member_anchored
            .lock()
            .unwrap()
            .keys()
            .any(|(o, _, _)| *o == owner)
        {
            held.push("sealed registrations");
        }
        if c.registered
            .lock()
            .unwrap()
            .keys()
            .any(|(o, _, _)| *o == owner)
        {
            held.push("registrations at a destination");
        }
        if c.reaching
            .lock()
            .unwrap()
            .keys()
            .any(|(o, _, _)| *o == owner)
        {
            held.push("private reaches");
        }
        if c.auths
            .lock()
            .unwrap()
            .keys()
            .any(|(o, _, _, _)| *o == owner)
        {
            held.push("auth bindings");
        }
        if c.authority_held.lock().unwrap().contains(&owner) {
            held.push("held authority");
        }
        if c.listeners.lock().unwrap().keys().any(|(o, _)| *o == owner) {
            held.push("listeners");
        }
        held
    }

    /// RED (audit row 159, connector HIGH 5: "every per-instance record grows with each reload"):
    /// a reload replaces an instance with one under a new id and the gone one is forgotten. Over
    /// every replace cycle nothing a gone instance declared, sealed, bound or held stays on the
    /// connector. GREEN twins: the instance that replaced it, and a neighbour never replaced, keep
    /// every record and still exchange; a forgotten id declared again works.
    #[test]
    fn a_forgotten_instance_leaves_no_record_however_many_reloads() {
        worker().block_on(async {
            let pki = Pki::new();
            let served = pki.leaf("localhost");
            let far = keeping_tls_far_end(&served).await;
            let c = pooled_trusting(&pki);
            let pinned = Anchors {
                key_pin: Some(served.pin.clone()),
                client_identity: None,
                private_reach: false,
            };
            // Declared as the loader declares a plugin's need (`DeclaredConns::declare`), which
            // records the declaration as well as the need.
            let need = ReadNeed {
                transport: "sec".to_owned(),
                ..super::config_targeted_need("")
            };
            let hold = |owner: InstanceId| {
                DeclaredConns::declare(&c, owner, NeedId(0), &need, None, None).expect("declared");
                c.hold_authority(owner);
                c.anchor(owner, NeedId(0), "", &far, &pinned)
                    .expect("the destination sealed");
                c.anchor(owner, NeedId(0), "planner", &far, &pinned)
                    .expect("the registration sealed");
                c.seal_reach(owner, NeedId(0), "planner", &far, true)
                    .expect("the reach sealed");
                c.bind_auth(
                    owner,
                    NeedId(0),
                    "planner",
                    "https://vendor.example",
                    bound_as(1),
                );
            };
            let every = vec![
                "needs",
                "declarations",
                "table needs",
                "sealed destinations",
                "sealed registrations",
                "registrations at a destination",
                "private reaches",
                "auth bindings",
                "held authority",
            ];
            let whole = (b"x".to_vec(), true, None);
            hold(OWNER);
            let mut live = InstanceId(10);
            hold(live);
            assert_eq!(
                records_of(&c, live),
                every,
                "a live instance holds its records"
            );
            assert_eq!(
                pooled_exchange(&c, (live, 0), &far, b"first", true).await,
                whole
            );
            let mut gone = Vec::new();
            for cycle in 11..15 {
                let next = InstanceId(cycle);
                hold(next);
                c.forget(live);
                gone.push(live);
                live = next;
                for g in &gone {
                    assert_eq!(
                        records_of(&c, *g),
                        Vec::<&str>::new(),
                        "a forgotten instance holds no record (reload {cycle})"
                    );
                }
                assert_eq!(
                    records_of(&c, live),
                    every,
                    "the instance that replaced it holds its own"
                );
                assert_eq!(
                    pooled_exchange(&c, (live, 0), &far, b"first", true).await,
                    whole,
                    "the instance that replaced it exchanges"
                );
            }
            assert_eq!(
                records_of(&c, OWNER),
                every,
                "a neighbour's records are untouched"
            );
            assert_eq!(
                pooled_exchange(&c, (OWNER, 0), &far, b"first", true).await,
                whole,
                "a neighbour still exchanges"
            );
            hold(gone[0]);
            assert_eq!(
                pooled_exchange(&c, (gone[0], 0), &far, b"first", true).await,
                whole,
                "a forgotten id declared again exchanges"
            );
        });
    }

    /// RED (`PollConns::anchor`: "an open naming it, to its own target's authority, is held to its
    /// anchors alone (none, where they are empty)"): a registration holding NO anchors, sealed
    /// BEFORE another registration at the same authority that holds a client identity, still
    /// presents nothing. Read through to the destination's seal, its open presented the other
    /// registration's identity.
    #[test]
    fn a_registration_holding_no_anchors_never_borrows_one_sealed_after_it() {
        worker().block_on(async {
            let pki = Pki::new();
            let server = pki.leaf("localhost");
            let client = pki.leaf("busbar.client");
            let (far, _seen) = tls_far_end(&pki, &server, true).await;
            let c = trusting(&pki);
            c.anchor(OWNER, NeedId(0), "bare", &far, &Anchors::default())
                .expect("sealed");
            let own = Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![client.der.clone()],
                    private_key: client.key.clone().into(),
                }),
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "planner", &far, &own)
                .expect("sealed");
            assert_eq!(
                exchange_as(&c, &far, "planner").await.as_deref(),
                Ok(&b"answer"[..]),
                "the registration presents its own identity"
            );
            assert!(
                exchange_as(&c, &far, "bare").await.is_err(),
                "a registration holding no identity presents none, never one sealed after it"
            );
        });
    }

    /// RED (`PollConns::anchor`; "a pin nobody enforces is refused, never dropped"): an open naming
    /// no registration is held to the destination's anchors. Where every registration sealed at
    /// its authority agrees, that is theirs; where they disagree there is no one answer, and the
    /// open is refused. Kept as whichever registration was sealed last, a registration holding
    /// nothing erased another's pin and identity for every such open.
    #[test]
    fn an_open_naming_no_registration_is_refused_where_the_registrations_at_its_authority_disagree()
    {
        worker().block_on(async {
            let pki = Pki::new();
            let server = pki.leaf("localhost");
            let client = pki.leaf("busbar.client");
            let (far, _seen) = tls_far_end(&pki, &server, true).await;
            let c = trusting(&pki);
            let own = Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![client.der.clone()],
                    private_key: client.key.clone().into(),
                }),
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "planner", &far, &own)
                .expect("sealed");
            let (_, got) = exchange(&c, &far).await;
            assert_eq!(
                got.as_deref(),
                Ok(&b"answer"[..]),
                "control: one registration at the authority is the destination's anchors"
            );
            c.anchor(OWNER, NeedId(0), "bare", &far, &Anchors::default())
                .expect("sealed");
            let open = c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &far,
                    body: b"first",
                    ..OpenDesc::default()
                },
            );
            assert_eq!(
                open.err(),
                Some(ConnError::Refused),
                "two registrations disagree: an open naming neither is refused"
            );
        });
    }

    /// What a splicing proxy saw, one entry per tunnel in the order they were asked: the CONNECT
    /// head, and every byte it relayed from the dialler to the far end after answering it.
    type ProxySeen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// A CONNECT proxy on loopback, as a corporate egress proxy is: it reads the CONNECT head,
    /// answers `200`, dials the authority it was asked for and splices the two sockets, recording
    /// the head and every byte the dialler sent through the tunnel.
    async fn splicing_proxy() -> (u16, ProxySeen) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: ProxySeen = Arc::default();
        let saw = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let saw = Arc::clone(&saw);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if sock.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let authority = head
                        .strip_prefix("CONNECT ")
                        .and_then(|rest| rest.split(' ').next())
                        .unwrap_or_default()
                        .to_owned();
                    let slot = {
                        let mut saw = saw.lock().unwrap();
                        saw.push((head, Vec::new()));
                        saw.len() - 1
                    };
                    let Ok(upstream) = tokio::net::TcpStream::connect(authority).await else {
                        return;
                    };
                    sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let (mut down_r, mut down_w) = sock.into_split();
                    let (mut up_r, mut up_w) = upstream.into_split();
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut up_r, &mut down_w).await;
                    });
                    let mut buf = [0_u8; 4096];
                    loop {
                        let n = down_r.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        // Recorded before it is relayed, so the far end's answer never outruns
                        // the record of what reached it.
                        saw.lock().unwrap()[slot].1.extend_from_slice(&buf[..n]);
                        if up_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    /// [`trusting`], dialling every framed connection through the proxy at `port`.
    fn trusting_through(pki: &Pki, port: u16) -> Connector {
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
        let tls = crate::tls::client::build_client_config(&EgressTrust {
            extra_anchors: vec![pki.ca_der.clone()],
            ..EgressTrust::default()
        })
        .unwrap();
        let c = Connector::serving(
            view,
            loopback_literals(),
            Some(Arc::new(tls)),
            Arc::new(|_, _| {}),
        )
        .proxying(Some(crate::proxy::test_config("127.0.0.1", port, None, "")));
        c.declare_over(OWNER, NeedId(0), "sec").unwrap();
        c
    }

    /// THE KERNEL ENGINE'S PROXIED mTLS HOP, THROUGH THE CONNECTOR (u30; status row 130: the
    /// CONNECT proxy and busbar's client identity are the connector's alone once the kernel engine
    /// is deleted). A secured dial under a proxy asks the proxy for a tunnel to the far end's own
    /// authority before anything else, then runs the handshake over the tunnel: the far end's key
    /// is the one observed, busbar's sealed identity is presented to a far end that asks for one,
    /// and the proxy relays only ciphertext (the request bytes never cross it in the clear).
    ///
    /// RED: with no identity sealed, the same proxied dial reaches the mutual far end and is
    /// refused by it, so the identity the green arm presents is the sealed one, carried through
    /// the tunnel.
    #[test]
    fn a_proxied_dial_tunnels_first_then_presents_the_sealed_identity_over_tls() {
        worker().block_on(async {
            let pki = Pki::new();
            let server = pki.leaf("localhost");
            let client = pki.leaf("busbar.client");
            let (far, seen) = tls_far_end(&pki, &server, true).await;
            let (port, proxied) = splicing_proxy().await;
            let c = trusting_through(&pki, port);

            let (_, got) = exchange(&c, &far).await;
            assert!(got.is_err(), "no identity: the mutual far end refuses");
            assert_eq!(
                proxied
                    .lock()
                    .unwrap()
                    .first()
                    .map(|(head, _)| head.clone()),
                Some(format!("CONNECT {far} HTTP/1.1\r\nHost: {far}\r\n\r\n")),
                "the unsealed dial went through the proxy too"
            );

            let anchors = Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(ClientIdentity {
                    cert_chain: vec![client.der.clone()],
                    private_key: client.key.clone().into(),
                }),
                private_reach: false,
            };
            c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                .expect("sealed");
            let (id, got) = exchange(&c, &far).await;
            assert_eq!(got.as_deref(), Ok(&b"answer"[..]));
            let facts = c.facts(OWNER, id).expect("facts");
            assert!(facts.client_identity, "the identity was presented");
            assert_eq!(facts.peer_key_pin.as_deref(), Some(server.pin.as_str()));
            assert_eq!(
                seen.lock().unwrap().clone(),
                Some((b"first".to_vec(), true))
            );
            let tunnels = proxied.lock().unwrap().clone();
            assert_eq!(tunnels.len(), 2, "one tunnel per dial: {tunnels:?}");
            let (head, relayed) = tunnels[1].clone();
            assert_eq!(
                head,
                format!("CONNECT {far} HTTP/1.1\r\nHost: {far}\r\n\r\n"),
                "the proxy was asked for the far end's own authority, and nothing came before it"
            );
            assert!(
                relayed.first() == Some(&0x16),
                "the first byte through the tunnel is a TLS handshake record"
            );
            assert!(
                !relayed.windows(5).any(|w| w == b"first"),
                "the proxy never saw a decrypted request byte"
            );
        });
    }

    /// A TLS far end on loopback serving `leaf`, answering `answer` once it read five bytes: its
    /// address, and, per connection once it is done, every byte it read (empty: the dialler left, or
    /// failed its handshake, before writing any).
    async fn reporting_tls_far_end(
        leaf: &Leaf,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        crate::tls::install_crypto_provider();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
        let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key.clone()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (l, far) = far_end().await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        let _ = tx.send(Vec::new());
                        return;
                    };
                    let mut got = Vec::new();
                    let mut buf = [0_u8; 64];
                    while got.len() < 5 {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    if got.len() >= 5 {
                        let _ = tls.write_all(b"answer").await;
                        let _ = tls.shutdown().await;
                    }
                    let _ = tx.send(got);
                });
            }
        });
        (far, rx)
    }

    /// Open need 0 at `far` with a five-byte opening body and read to its first answer, waking on
    /// the connection's own readiness: the connection, and the read's answer.
    async fn exchange_awaited(c: &Connector, far: &str) -> (ConnId, Result<Vec<u8>, ConnError>) {
        let desc = OpenDesc {
            target: far,
            body: b"first",
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)),
        )
        .await
        .expect("the connector answers");
        (id, read.map(|p| buf[..p.len].to_vec()))
    }

    /// What the far end read on the connection it finished next.
    async fn far_read(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the far end reports the connection")
            .expect("the far end runs")
    }

    /// RED (the operator docs: a pin is written `sha256/<base64>`): a pin written in
    /// the DOCUMENTED spelling is the served key's and reaches it, and so does its plain base64
    /// alias; a pin of another key is refused in either spelling, after the handshake and before
    /// any request byte reaches the far end. Compared as written, the documented spelling never
    /// matched the observed key (plain base64), so every documented pin refused its own far end.
    /// The facts report the observed key in the canonical spelling either way.
    #[test]
    fn a_pin_in_either_spelling_reaches_its_key_and_refuses_another_before_any_request_byte() {
        worker().block_on(async {
            let pki = Pki::new();
            let served = pki.leaf("localhost");
            let other = pki.leaf("localhost");
            let (far, mut rx) = reporting_tls_far_end(&served).await;
            let c = trusting(&pki);
            let plain = |pin: &str| {
                pin.strip_prefix(busbar_contract::transport::trust::KEY_PIN_TAG)
                    .expect("the canonical spelling is tagged")
                    .to_owned()
            };
            assert!(served.pin.starts_with("sha256/"), "{}", served.pin);
            for written in [served.pin.clone(), plain(&served.pin)] {
                let anchors = Anchors {
                    key_pin: Some(written.clone()),
                    client_identity: None,
                    private_reach: false,
                };
                c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                    .expect("sealed");
                let (id, got) = exchange_awaited(&c, &far).await;
                assert_eq!(got.as_deref(), Ok(&b"answer"[..]), "{written}");
                let facts = c.facts(OWNER, id).expect("facts");
                assert_eq!(
                    facts.peer_key_pin.as_deref(),
                    Some(served.pin.as_str()),
                    "the facts report the observed key canonically, whatever the pin's spelling"
                );
                c.close(OWNER, id).expect("closed");
                assert_eq!(far_read(&mut rx).await, b"first", "{written}");
            }
            for written in [other.pin.clone(), plain(&other.pin)] {
                let anchors = Anchors {
                    key_pin: Some(written.clone()),
                    client_identity: None,
                    private_reach: false,
                };
                c.anchor(OWNER, NeedId(0), "", &far, &anchors)
                    .expect("sealed");
                let (id, got) = exchange_awaited(&c, &far).await;
                assert_eq!(got, Err(ConnError::Refused), "{written}");
                let facts = c.facts(OWNER, id).expect("facts after the refusal");
                assert_eq!(
                    facts.peer_key_pin.as_deref(),
                    Some(served.pin.as_str()),
                    "the refusal names the key served, canonically"
                );
                c.close(OWNER, id).expect("closed");
                assert!(
                    far_read(&mut rx).await.is_empty(),
                    "no request byte reached the far end ({written})"
                );
            }
        });
    }

    /// A pin that names no SHA-256 digest (a stand-in such as `sha256/BASE=`, another tag, a digest
    /// of another length) refuses the seal: it is never held as a string no key can match.
    #[test]
    fn a_pin_that_names_no_digest_refuses_the_seal() {
        worker().block_on(async {
            let pki = Pki::new();
            let leaf = pki.leaf("localhost");
            let (_listening, far) = far_end().await;
            let c = trusting(&pki);
            for bad in ["sha256/BASE=", "sha1/AAAA", "not a pin", "sha256/"] {
                let anchors = Anchors {
                    key_pin: Some(bad.to_owned()),
                    client_identity: None,
                    private_reach: false,
                };
                assert_eq!(
                    c.anchor(OWNER, NeedId(0), "", &far, &anchors),
                    Err(ConnError::Refused),
                    "{bad}"
                );
            }
            let good = Anchors {
                key_pin: Some(leaf.pin.clone()),
                client_identity: None,
                private_reach: false,
            };
            assert_eq!(c.anchor(OWNER, NeedId(0), "", &far, &good), Ok(()));
        });
    }

    // ── THE SECURE LAYER'S TWINS, each over a real loopback handshake: the rows the deleted
    // `tls/engine_tests.rs` held, proven against the connector's own outbound security ─────────

    /// What one connection told a [`naming_far_end`]: the server name its ClientHello offered, and
    /// whether the handshake completed.
    type Named = tokio::sync::mpsc::UnboundedReceiver<(Option<String>, bool)>;

    /// How many connections a [`naming_far_end`] accepted.
    type Accepted = Arc<std::sync::atomic::AtomicUsize>;

    /// A TLS far end on loopback serving `leaf`, answering `answer` once it read five bytes. Per
    /// connection it reports the name the ClientHello offered, read off the hello BEFORE the
    /// handshake runs (so a handshake the dialler refuses reports its name too), and whether the
    /// handshake completed; and it counts every connection it accepts. Its address, the reports,
    /// the count.
    async fn naming_far_end(leaf: &Leaf) -> (String, Named, Accepted) {
        crate::tls::install_crypto_provider();
        let chain = vec![rustls_pki_types::CertificateDer::from(leaf.der.clone())];
        let key = rustls_pki_types::PrivateKeyDer::try_from(leaf.key.clone()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let config = Arc::new(config);
        let (l, far) = far_end().await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let accepted = Accepted::default();
        let counted = Arc::clone(&accepted);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((s, _)) = l.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (config, tx) = (Arc::clone(&config), tx.clone());
                tokio::spawn(async move {
                    let hello = rustls::server::Acceptor::default();
                    let Ok(start) = tokio_rustls::LazyConfigAcceptor::new(hello, s).await else {
                        let _ = tx.send((None, false));
                        return;
                    };
                    let name = start.client_hello().server_name().map(str::to_owned);
                    match start.into_stream(config).await {
                        Err(_) => {
                            let _ = tx.send((name, false));
                        }
                        Ok(mut tls) => {
                            let _ = tx.send((name, true));
                            let mut buf = [0_u8; 5];
                            if tls.read_exact(&mut buf).await.is_ok() {
                                let _ = tls.write_all(b"answer").await;
                                let _ = tls.shutdown().await;
                            }
                        }
                    }
                });
            }
        });
        (far, rx, accepted)
    }

    /// The next report off a [`naming_far_end`], bounded so a far end that never reports fails the
    /// test rather than hanging it.
    async fn next_report(named: &mut Named) -> (Option<String>, bool) {
        tokio::time::timeout(std::time::Duration::from_secs(10), named.recv())
            .await
            .expect("the far end reports the connection")
            .expect("the far end is still listening")
    }

    /// A connector serving one door whose targets ask for connection security under `name`,
    /// trusting `anchor` on top of the public roots and judging every dial through `judge`, with
    /// need 0 declared over it. Its wake raises the returned [`tokio::sync::Notify`], so a reader
    /// waits on the connector's own wake and never on a clock.
    fn naming(
        name: &'static str,
        anchor: &[u8],
        judge: Arc<dyn crate::DialJudge>,
    ) -> (Connector, Arc<tokio::sync::Notify>) {
        // The framer rides the address carrier, so one is loaded beside it.
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
                        secure_name: Some(name),
                        ..crate::support::Knobs::default()
                    },
                )),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let tls = crate::tls::client::build_client_config(&EgressTrust {
            extra_anchors: vec![anchor.to_vec()],
            ..EgressTrust::default()
        })
        .unwrap();
        let woken = Arc::new(tokio::sync::Notify::new());
        let wake = Arc::clone(&woken);
        let c = Connector::serving(
            view,
            judge,
            Some(Arc::new(tls)),
            Arc::new(move |_, _| wake.notify_one()),
        );
        c.declare_over(OWNER, NeedId(0), "sec").unwrap();
        (c, woken)
    }

    /// Open need 0 at `target` within `judged` (empty: no set stated) with a five-byte opening
    /// body, and read to its first answer, waiting on the connector's wake between reads: the
    /// connection, and the read's answer.
    async fn exchange_woken(
        c: &Connector,
        woken: &tokio::sync::Notify,
        target: &str,
        judged: &[std::net::IpAddr],
    ) -> (ConnId, Result<Vec<u8>, ConnError>) {
        let desc = OpenDesc {
            target,
            body: b"first",
            within: judged,
            ..OpenDesc::default()
        };
        let id = c.open(OWNER, NeedId(0), &desc).expect("opens");
        let mut buf = [0_u8; 64];
        let read = async {
            loop {
                match c.read(OWNER, id, 7, &mut buf) {
                    Err(ConnError::Pending) => woken.notified().await,
                    Ok(p) => return Ok(buf[..p.len].to_vec()),
                    Err(e) => return Err(e),
                }
            }
        };
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), read)
            .await
            .expect("the connector wakes its reader with an answer");
        (id, got)
    }

    /// THE REAL WRAP OFFERS THE CONFIGURED NAME AND HOLDS THE CERTIFICATE TO IT (the twin the
    /// deleted `tls/engine_tests.rs::sni_stays_on_the_hostname_and_a_wrong_name_cert_is_refused`
    /// held). The socket goes to the pinned loopback address while the name the target asks
    /// security under is `pinned.test`: the far end serving a leaf for `pinned.test` reads that
    /// name off the ClientHello, completes the handshake and answers, and the connection's facts
    /// carry the name offered. RED TWIN: a far end at a pinned loopback address serving a leaf for
    /// `other.test`, under a root the dialler trusts, still reads `pinned.test` off the hello and
    /// is REFUSED at the handshake, the name check its cause: the certificate is held to the
    /// configured name, never to the address the socket went to.
    #[test]
    fn the_real_wrap_offers_the_configured_name_and_refuses_a_certificate_for_another() {
        use busbar_contract::abi::host::conn::connector::CAUSE_SECURITY;
        worker().block_on(async {
            let pki = Pki::new();
            let (c, woken) = naming("pinned.test", &pki.ca_der, loopback_literals());

            let (far, mut named, _) = naming_far_end(&pki.leaf("pinned.test")).await;
            let (id, got) = exchange_woken(&c, &woken, &far, &[]).await;
            assert_eq!(
                got.as_deref(),
                Ok(&b"answer"[..]),
                "the rightly-named far end answers"
            );
            assert_eq!(
                next_report(&mut named).await,
                (Some("pinned.test".to_owned()), true),
                "the hello carried the configured name and the handshake completed"
            );
            let facts = c.facts(OWNER, id).expect("facts");
            assert_eq!(facts.sni.as_deref(), Some("pinned.test"));
            assert_eq!(
                c.cause(OWNER, id),
                None,
                "an answered connection has no cause"
            );

            let (far, mut named, _) = naming_far_end(&pki.leaf("other.test")).await;
            let (id, got) = exchange_woken(&c, &woken, &far, &[]).await;
            assert_eq!(
                got,
                Err(ConnError::Refused),
                "a certificate for another name is refused"
            );
            let cause = c.cause(OWNER, id).expect("a cause");
            assert_eq!(cause.stage, CAUSE_SECURITY);
            assert!(
                cause.text.contains("certificate not valid for name")
                    && cause.text.contains("pinned.test"),
                "the name check's own refusal: {}",
                cause.text
            );
            // The far end's handshake ends when the dialler leaves the refused connection.
            c.close(OWNER, id).expect("closed");
            assert_eq!(
                next_report(&mut named).await,
                (Some("pinned.test".to_owned()), false),
                "the hello carried the configured name even though the handshake was refused"
            );
        });
    }

    /// A resolver answering `.0` with `.1`, at once, off the caller's thread.
    struct Answers(&'static str, std::net::IpAddr);

    impl crate::guard::Resolve for Answers {
        fn resolve(&self, host: &str, done: crate::guard::Resolved) {
            let answer = if host == self.0 {
                Ok(vec![self.1])
            } else {
                Err("NXDOMAIN".to_owned())
            };
            std::thread::spawn(move || done(answer));
        }
    }

    /// A JUDGED SECURE DIAL GOES ONLY WHERE THE GUARD JUDGED, AND KEEPS THE NAME (the twin the
    /// deleted `tls/engine_tests.rs::a_judged_tls_dial_keeps_the_name_for_sni_and_host` held). A
    /// need dials `judged.test` through the deployment's one guard, the name answering the loopback
    /// far end's address. RED TWIN first: stated `within` an address set the guard judged that does
    /// not hold that answer, the dial is REFUSED. Then the same dial within the set holding the
    /// answer lands there: the ClientHello offers the name, the leaf minted for `judged.test` alone
    /// verifies against it, and the far end answers. The far end's count, read once the landed
    /// dial's handshake is reported, is one: the refused dial never reached it (accepts are taken
    /// in arrival order, so a connection the refused dial made would have been counted first).
    #[test]
    fn a_judged_secure_dial_lands_only_where_the_guard_judged_and_keeps_the_name() {
        worker().block_on(async {
            let pki = Pki::new();
            let (far, mut named, accepted) = naming_far_end(&pki.leaf("judged.test")).await;
            let port = far.rsplit_once(':').expect("host:port").1;
            let target = format!("judged.test:{port}");
            let destinations = busbar_kernel::config::Destinations {
                block_private_addresses: true,
                allow: vec!["127.0.0.0/8".to_owned()],
                ..busbar_kernel::config::Destinations::default()
            };
            let guard = crate::guard::Guard::from_config(&destinations).unwrap();
            let resolver = Arc::new(Answers("judged.test", [127, 0, 0, 1].into()));
            let dest = crate::process::GuardJudge::new(guard, resolver);
            let judge = crate::process::judge(Arc::new(dest), &[]);
            let (c, woken) = naming("judged.test", &pki.ca_der, judge);

            let elsewhere: [std::net::IpAddr; 1] = [[127, 0, 0, 2].into()];
            let (_, got) = exchange_woken(&c, &woken, &target, &elsewhere).await;
            assert_eq!(
                got,
                Err(ConnError::Refused),
                "the name answered an address the guard never judged"
            );

            let judged: [std::net::IpAddr; 1] = [[127, 0, 0, 1].into()];
            let (id, got) = exchange_woken(&c, &woken, &target, &judged).await;
            assert_eq!(
                got.as_deref(),
                Ok(&b"answer"[..]),
                "the dial landed where the guard judged"
            );
            assert_eq!(
                next_report(&mut named).await,
                (Some("judged.test".to_owned()), true),
                "the hello offered the name and the certificate verified against it"
            );
            assert_eq!(
                accepted.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the refused dial reached no far end"
            );
            let facts = c.facts(OWNER, id).expect("facts");
            assert_eq!(facts.sni.as_deref(), Some("judged.test"));
        });
    }

    /// A TRUST REFUSAL NAMES THE SECURITY STACK'S OWN CAUSE, AND THE TRUSTED TWIN IS REACHED (the
    /// twin the deleted `tls/engine_tests.rs::a_tls_trust_refusal_renders_the_real_cause` held). A
    /// far end whose leaf an unrelated root signed is REFUSED at connection security, and the
    /// connection's cause is the stack's own words for an unknown issuer, never a vague closed
    /// channel. GREEN TWIN: the same far end, dialled by a connector trusting the root that signed
    /// its leaf, answers, and the answered connection has no cause.
    #[test]
    fn a_trust_refusal_names_its_cause_and_the_trusted_twin_is_reached() {
        use busbar_contract::abi::host::conn::connector::CAUSE_SECURITY;
        worker().block_on(async {
            let served = Pki::new();
            let unrelated = Pki::new();
            let (far, _named, _) = naming_far_end(&served.leaf("refused.test")).await;

            let (c, woken) = naming("refused.test", &unrelated.ca_der, loopback_literals());
            let (id, got) = exchange_woken(&c, &woken, &far, &[]).await;
            assert_eq!(got, Err(ConnError::Refused), "refused on trust");
            let cause = c.cause(OWNER, id).expect("a cause");
            let issuer = rustls::CertificateError::UnknownIssuer;
            let unknown = rustls::Error::InvalidCertificate(issuer);
            assert_eq!(cause.stage, CAUSE_SECURITY);
            assert_eq!(cause.text, unknown.to_string(), "the stack's own refusal");
            assert!(
                cause.text.contains("invalid peer certificate"),
                "the stack's own words: {}",
                cause.text
            );
            assert!(
                !cause.text.to_ascii_lowercase().contains("channel closed"),
                "never a vague channel-closed: {}",
                cause.text
            );

            let (c, woken) = naming("refused.test", &served.ca_der, loopback_literals());
            let (id, got) = exchange_woken(&c, &woken, &far, &[]).await;
            assert_eq!(
                got.as_deref(),
                Ok(&b"answer"[..]),
                "the trusted twin is reached"
            );
            assert_eq!(
                c.cause(OWNER, id),
                None,
                "an answered connection has no cause"
            );
        });
    }
}

/// RED (SEAM-4f/4k, a registration's private reach, `abi::plane::TRUST_PRIVATE_REACH`, sealed per
/// REGISTRATION): under a strict guard (private refused, nothing allowlisted) a provider-class
/// need's open that names a registration holding a reach dials that registration's private
/// destination, as an allowlist entry naming it would; a second registration at the SAME
/// authority without one, an open naming no registration, and another need are all still refused
/// (the class is unchanged); a reach never admits a cloud-metadata address; and a seal without it
/// takes it back.
#[test]
fn a_registrations_private_reach_admits_its_own_opens_and_nothing_else() {
    worker().block_on(async {
        let (_listening, far) = far_end().await;
        let view = Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap();
        let strict = Arc::new(crate::LiteralsOnly(crate::guard::Guard::default()));
        let c = Connector::serving(view, strict, None, Arc::new(|_, _| {}));
        for need in [0, 1] {
            c.declare_need(
                OWNER,
                NeedId(need),
                "bytes",
                busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER,
            )
            .expect("a served scheme declares");
        }
        let open_as = |need: u32, target: &str, member: &str| {
            c.open(
                OWNER,
                NeedId(need),
                &OpenDesc {
                    target,
                    member,
                    ..OpenDesc::default()
                },
            )
        };
        assert_eq!(
            open_as(0, &far, "inside"),
            Err(ConnError::Refused),
            "no reach yet"
        );
        c.seal_reach(OWNER, NeedId(0), "inside", &far, true)
            .expect("sealed");
        c.seal_reach(OWNER, NeedId(0), "outside", &far, false)
            .expect("nothing to seal");
        let id = open_as(0, &far, "inside").expect("the registration's own open reaches");
        c.close(OWNER, id).unwrap();
        assert_eq!(
            open_as(0, &far, "outside"),
            Err(ConnError::Refused),
            "another registration at the same authority holds no reach"
        );
        assert_eq!(
            open_as(0, &far, ""),
            Err(ConnError::Refused),
            "an open naming no registration holds none"
        );
        assert_eq!(
            open_as(1, &far, "inside"),
            Err(ConnError::Refused),
            "the reach is the need's alone"
        );
        let metadata = "169.254.169.254:80";
        c.seal_reach(OWNER, NeedId(0), "inside", metadata, true)
            .expect("sealed");
        assert_eq!(
            open_as(0, metadata, "inside"),
            Err(ConnError::Refused),
            "a reach never admits cloud metadata"
        );
        c.seal_reach(OWNER, NeedId(0), "inside", &far, true)
            .expect("sealed");
        c.seal_reach(OWNER, NeedId(0), "inside", &far, false)
            .expect("dropped");
        assert_eq!(
            open_as(0, &far, "inside"),
            Err(ConnError::Refused),
            "a seal without the reach takes it back"
        );
        assert!(
            Connector::new()
                .seal_reach(OWNER, NeedId(0), "inside", &far, true)
                .is_err(),
            "an undeclared need holds no reach"
        );
    });
}

// ── THE ADMISSION OF A PINNED TARGET: the verdict `need_admit` reports is the one every dial meets ──

/// A connector serving `plain` (an entry that locates a target in plaintext) and `sec` (one that
/// locates it over connection security), admitting literals as [`literal_connector`] does.
fn plain_and_secure_connector() -> Connector {
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
    Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {}))
}

/// A config-targeted outbound need over `transport` in `class`.
fn pinned_need(transport: &str, class: u32) -> ReadNeed {
    let mut need = config_targeted_need("settings.url");
    need.transport = transport.to_owned();
    need.egress_class = class;
    need
}

/// RED (1.5.5: a request-log webhook target that is not `https://` was refused when the sink was
/// configured): an open-web need pinned to a plaintext target is REFUSED at declare, so the host's
/// admission (`need_admit`) answers what every dial of it already met, and the need opens nothing.
/// It holds for a literal and for a name alike: the scheme rule needs no resolution.
#[test]
fn an_open_web_need_pinned_to_a_plaintext_target_is_refused_at_declare() {
    let c = plain_and_secure_connector();
    let need = pinned_need("plain", EGRESS_OPEN_WEB);
    for (id, target) in [(0, "127.0.0.1:4318"), (1, "localhost:4318")] {
        assert_eq!(
            DeclaredConns::declare(&c, OWNER, NeedId(id), &need, Some(target), None),
            Err(ConnError::Refused),
            "{target}"
        );
        assert_eq!(
            DeclaredConns::declared(&c, OWNER, NeedId(id)),
            Some(Err(ConnError::Refused)),
            "{target}: the admission the plugin reads"
        );
        assert!(c
            .open(
                OWNER,
                NeedId(id),
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            )
            .is_err());
    }
}

/// GREEN: the admission judges only what the dial would. An open-web need pinned to a secure target
/// on an allowlisted literal is admitted, as is a name (no resolution happens at declare; its
/// addresses stay the dial's), and a default-class need pinned to a plaintext loopback literal
/// (operator infrastructure, the class a configured target is judged in) is admitted too.
#[test]
fn a_pinned_target_every_dial_would_admit_is_admitted_at_declare() {
    let c = plain_and_secure_connector();
    let secure = pinned_need("sec", EGRESS_OPEN_WEB);
    assert_eq!(
        DeclaredConns::declare(&c, OWNER, NeedId(0), &secure, Some("10.1.2.3:443"), None),
        Ok(())
    );
    assert_eq!(
        DeclaredConns::declare(
            &c,
            OWNER,
            NeedId(1),
            &secure,
            Some("collector.example:443"),
            None
        ),
        Ok(())
    );
    let plain = pinned_need("plain", crate::DEFAULT_CLASS);
    assert_eq!(
        DeclaredConns::declare(&c, OWNER, NeedId(2), &plain, Some("127.0.0.1:4318"), None),
        Ok(())
    );
    assert_eq!(DeclaredConns::declared(&c, OWNER, NeedId(2)), Some(Ok(())));
}

/// RED (THE DESIGN §5: `open-web` is "public https only"; v1.5.5 refused a private open-web target
/// and disabled the instance, `crates/busbar/src/observability.rs:214-240`): an open-web need whose
/// config pins it to a private literal the allowlist does not name is REFUSED at declare, over a
/// secure connection too. Its configured target does not make it operator infrastructure (the
/// class rule itself is `guard_tests::a_configured_open_web_target_keeps_its_class_and_is_refused_a_private_address`).
#[test]
fn an_open_web_need_pinned_to_a_private_literal_is_refused_at_declare() {
    let c = plain_and_secure_connector();
    let need = pinned_need("sec", EGRESS_OPEN_WEB);
    assert_eq!(
        DeclaredConns::declare(&c, OWNER, NeedId(0), &need, Some("10.0.0.5:443"), None),
        Err(ConnError::Refused)
    );
    assert_eq!(
        DeclaredConns::declared(&c, OWNER, NeedId(0)),
        Some(Err(ConnError::Refused))
    );
}

/// RED: a pinned literal the guard refuses (a cloud metadata address, which no class and no
/// configured target lifts) is refused at declare, over connection security too.
#[test]
fn a_pinned_metadata_literal_is_refused_at_declare() {
    let c = plain_and_secure_connector();
    let need = pinned_need("sec", EGRESS_OPEN_WEB);
    assert_eq!(
        DeclaredConns::declare(
            &c,
            OWNER,
            NeedId(0),
            &need,
            Some("169.254.169.254:443"),
            None
        ),
        Err(ConnError::Refused)
    );
    assert_eq!(
        DeclaredConns::declared(&c, OWNER, NeedId(0)),
        Some(Err(ConnError::Refused))
    );
}

/// An outbound auth that is only ever bound: it opens nothing and answers no fields.
struct OnlyBound;

impl busbar_contract::auth_calls::OutboundAuth for OnlyBound {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Err("only bound".to_string())
    }
    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        Some(busbar_contract::auth_calls::Fields::Refused)
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        unreachable!("no cell here asks a bound auth for fields")
    }
}

/// A binding under `handle`, nothing else to it.
fn bound_as(handle: u64) -> busbar_contract::conn::ConnAuth {
    busbar_contract::conn::ConnAuth {
        auth: Arc::new(OnlyBound),
        handle,
        style_flags: 0,
        points: busbar_contract::abi::auth::AuthPoints(0),
        passthrough: false,
        lender: None,
        per_request: None,
    }
}

/// EACH MEMBER'S BINDING IS ITS OWN, even at an origin it shares (predev `creds.rs`
/// `Lease::header_for`: a lease minted for one agent is refused on a hop to another; R5: an agent
/// with no credential is dialled with none): two members at one origin each answer their own
/// binding, a member that bound none answers none (never its neighbour's), a request naming no
/// member answers none, and a member's binding reaches no other origin. RED: the table held one
/// binding per origin, the last member bound there answering for every request to it.
#[test]
fn members_sharing_an_origin_each_answer_their_own_binding_and_never_a_neighbours() {
    let c = Connector::default();
    let (owner, need) = (InstanceId(3), NeedId(1));
    let origin = "https://vendor.example";
    c.bind_auth(owner, need, "planner", origin, bound_as(1));
    c.bind_auth(owner, need, "summarizer", origin, bound_as(2));
    let handle =
        |member: &str, target: &str| c.auth_of(owner, need, member, target).map(|b| b.handle);
    assert_eq!(handle("planner", "https://vendor.example/planner"), Some(1));
    assert_eq!(
        handle("summarizer", "https://vendor.example/summarizer"),
        Some(2)
    );
    assert_eq!(
        handle("scout", "https://vendor.example/scout"),
        None,
        "a member with none"
    );
    assert_eq!(
        handle("", "https://vendor.example/planner"),
        None,
        "a request naming none"
    );
    assert_eq!(
        handle("planner", "https://elsewhere.example/planner"),
        None,
        "another origin"
    );
    assert_eq!(
        c.auth_of(owner, NeedId(2), "planner", origin)
            .map(|b| b.handle),
        None,
        "another need"
    );
}

/// A REQUEST NAMING NO MEMBER GETS NO BINDING, even where EXACTLY ONE member is bound at its origin
/// (the coordinator's answer: no origin fallback; R5: a request that is no member's is dialled
/// with no credential): the connector keys a binding by (instance, need, member, target origin),
/// so the one member's own request answers its binding and a memberless request to the same origin
/// answers none, its request carrying no `authorization`. RED: an origin fallback (answer the
/// binding when a single member holds one at the origin) lends that member's credential to a
/// request that is not its own.
#[test]
fn a_request_naming_no_member_gets_no_binding_even_from_the_one_member_at_its_origin() {
    let c = Connector::default();
    let (owner, need) = (InstanceId(3), NeedId(1));
    c.bind_auth(owner, need, "solo", "https://solo.example", bound_as(7));
    let handle =
        |member: &str, target: &str| c.auth_of(owner, need, member, target).map(|b| b.handle);
    assert_eq!(
        handle("solo", "https://solo.example/solo"),
        Some(7),
        "the member's own request carries its binding"
    );
    assert_eq!(
        handle("", "https://solo.example/solo"),
        None,
        "a request naming no member carries no binding, though one member alone is bound there"
    );
    assert_eq!(
        handle("", "https://solo.example"),
        None,
        "nor at the bare origin"
    );
}

/// THE POOL IS KEYED BY WHO DIALLED AND WHAT THE DIAL TRUSTED (THE DESIGN §5, §8: the connector is
/// the only holder of trust roots and mTLS identity; a `ConnId` belongs to the instance that opened
/// it). A far end on loopback that answers every three bytes it reads with one one-byte message and
/// the exchange's end (`xe`, the `messages` entry's script) and keeps each connection open: its
/// address, how many connections it accepted, and how many of them the dialler has closed.
async fn keeping_far_end() -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let (l, far) = far_end().await;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ended = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (count, gone) = (Arc::clone(&accepted), Arc::clone(&ended));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let gone = Arc::clone(&gone);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0_u8; 3];
                while s.read_exact(&mut buf).await.is_ok() {
                    if s.write_all(b"xe").await.is_err() {
                        break;
                    }
                }
                gone.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (far, accepted, ended)
}

/// A connector serving the scripted `messages` framer over a `carrier`, keeping finished lines idle
/// for `idle`.
fn pooled_messages(idle: std::time::Duration) -> Connector {
    let view = Transports::new(vec![
        Entry {
            door: Arc::new(TestDoor::new(
                "messages",
                &["messages"],
                &[],
                crate::support::Knobs {
                    messages: Some(crate::compose::EXCHANGE_STREAM),
                    ..crate::support::Knobs::default()
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
    Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {})).pooling(
        crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: idle,
        },
    )
}

/// What one pooled exchange read: its bytes, whether it completed (its line goes back to the pool
/// once closed), and the error that ended it, if one did.
type Exchanged = (Vec<u8>, bool, Option<ConnError>);

/// Open `owner`'s `need` at `far` with `body`, read its answer (to the exchange's end where
/// `to_end`, else its first byte), and close it.
async fn pooled_exchange(
    c: &Connector,
    (owner, need): (InstanceId, u32),
    far: &str,
    body: &[u8],
    to_end: bool,
) -> Exchanged {
    let id = c
        .open(
            owner,
            NeedId(need),
            &OpenDesc {
                target: far,
                body,
                ..OpenDesc::default()
            },
        )
        .expect("opens");
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    let mut whole = false;
    let mut failed = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match c.read(owner, id, 7, &mut buf) {
            Ok(p) if p.kind == PieceKind::Completion => {
                whole = true;
                break;
            }
            Ok(p) => {
                got.extend_from_slice(&buf[..p.len]);
                if !to_end && !got.is_empty() {
                    break;
                }
            }
            Err(ConnError::Pending) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let _ = c.close(owner, id);
    (got, whole, failed)
}

/// RED (THE DESIGN §5 "a `ConnId` belongs to the plugin instance that opened it"; §8 the connector
/// holds each need's trust): a line an exchange finished on is lent again only to an open of the
/// SAME instance's SAME need. Another need of the instance, and another instance, each dial their
/// own; the need's own next open rides the kept line. Keyed by the destination alone, the second
/// need's open rode the first need's line (secured, where it was, under the first need's trust).
#[test]
fn a_pooled_line_is_never_lent_to_another_need_or_instance() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(std::time::Duration::from_secs(60));
        for (owner, need) in [(OWNER, 0), (OWNER, 1), (OTHER, 0)] {
            c.declare_over(owner, NeedId(need), "messages")
                .expect("a served scheme declares");
        }
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", true).await,
            (b"x".to_vec(), true, None),
            "the first exchange finishes whole, and its line is kept"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        let other_need = pooled_exchange(&c, (OWNER, 1), &far, b"ask", true).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "another need of the same instance dials its own line"
        );
        assert_eq!(other_need, (b"x".to_vec(), true, None));
        let other_instance = pooled_exchange(&c, (OTHER, 0), &far, b"ask", true).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "another instance dials its own line"
        );
        assert_eq!(other_instance, (b"x".to_vec(), true, None));
        let again = pooled_exchange(&c, (OWNER, 0), &far, b"ask", false).await;
        assert_eq!(
            again.0,
            b"x".to_vec(),
            "the need's own next open is answered"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "control: the need's own next open rides its kept line"
        );
    });
}

/// RED (audit row 159, connector HIGH 5: "every per-instance record grows with each reload"): a
/// forgotten instance's lines and listener go with it. The idle line its exchange finished on is
/// closed at once, never left on the pool for the idle reaper, and its listener leaves the table.
/// GREEN twin: a neighbour's kept line stays open and is lent to its next open.
#[test]
fn a_forgotten_instances_pooled_line_and_listener_go_and_a_neighbours_line_is_kept() {
    worker().block_on(async {
        let (far, accepted, ended) = keeping_far_end().await;
        let c = pooled_messages(std::time::Duration::from_secs(60));
        for owner in [OWNER, OTHER] {
            c.declare_over(owner, NeedId(0), "messages")
                .expect("a served scheme declares");
        }
        c.listen(
            OTHER,
            NeedId(0),
            "127.0.0.1:0",
            None,
            crate::listen::AcceptLimits::default(),
        )
        .expect("listens");
        let whole = (b"x".to_vec(), true, None);
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", true).await,
            whole
        );
        assert_eq!(
            pooled_exchange(&c, (OTHER, 0), &far, b"ask", true).await,
            whole
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "each kept its own line");
        c.forget(OTHER);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ended.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "the forgotten instance's idle line is closed at once"
        );
        assert!(
            !c.listeners.lock().unwrap().keys().any(|(o, _)| *o == OTHER),
            "the forgotten instance's listener leaves the table"
        );
        let again = pooled_exchange(&c, (OWNER, 0), &far, b"ask", false).await;
        assert_eq!(
            again.0,
            b"x".to_vec(),
            "the neighbour's next open is answered"
        );
        assert_eq!(
            (
                accepted.load(Ordering::SeqCst),
                ended.load(Ordering::SeqCst)
            ),
            (2, 1),
            "the neighbour's next open rides its kept line, still open"
        );
    });
}

/// RED (`limits.pool_idle_timeout_secs`, the pool's own contract: "an idle connection reaped once
/// it has sat" that long): an idle line whose time ran out is closed when the pool is next used,
/// whatever place that use opens to. Expired lines were reaped only when an open or a release
/// touched their own place again, so a place dialled once kept its socket open for the life of
/// the process.
#[test]
fn an_idle_pooled_line_is_closed_once_its_idle_time_passes_whatever_is_opened_next() {
    worker().block_on(async {
        let (first_far, _, first_closed) = keeping_far_end().await;
        let (second_far, _, _) = keeping_far_end().await;
        let c = pooled_messages(std::time::Duration::from_millis(50));
        c.declare_over(OWNER, NeedId(0), "messages")
            .expect("a served scheme declares");
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &first_far, b"ask", true).await,
            (b"x".to_vec(), true, None),
            "the first place's exchange finishes whole, and its line is kept idle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &second_far, b"ask", true).await,
            (b"x".to_vec(), true, None),
            "an open to another place"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while first_closed.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            first_closed.load(Ordering::SeqCst),
            1,
            "the first place's line, idle past its time, is closed"
        );
    });
}
