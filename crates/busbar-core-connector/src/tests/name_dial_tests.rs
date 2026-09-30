// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A NEED DIALS A HOSTNAME THROUGH THE KERNEL'S ONE JUDGE, END TO END (`BUSBAR-1.6.0.md` THE
//! DESIGN, connections; R-K; CONNECTOR-19 ruling (b)). A plugin's view of the connection table
//! (`HostConns`, over the host's lowered slots) opens a need whose target is a NAME; the connector
//! judges the authority through the kernel's `dest.judge` (`KernelServices::judge_dial`), the name
//! resolves off the caller's thread, and the connector dials exactly the pinned address. The open
//! answers at once with the dial in flight; the resolution wakes the reader's ticket; a refusal the
//! name decides answers the open, and an answered address the rules refuse answers the read —
//! 1.5.5's refusal timing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::{host_slots, ConnHost, HostConns};
use busbar_contract::conn::{ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc};
use busbar_kernel::host_services::{DestRules, KernelServices, Resolve, Resolved};
use busbar_kernel::net_guard::{Denylist, GuardPolicy};

use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};
use crate::Connector;

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);

/// A resolver answering from a fixed table, off the caller's thread, after a pause — so the open
/// is always in flight when the first read finds it.
struct Table(Vec<(&'static str, IpAddr)>);

impl Resolve for Table {
    fn resolve(&self, host: &str, done: Resolved) {
        let answer: Vec<IpAddr> = self
            .0
            .iter()
            .filter(|(n, _)| *n == host)
            .map(|(_, a)| *a)
            .collect();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            done(if answer.is_empty() {
                Err("NXDOMAIN".into())
            } else {
                Ok(answer)
            });
        });
    }
}

/// The connector serving a byte-exact door, its dials judged by the kernel's one judge over
/// `resolver` (the host default class admitting internal addresses, as a loopback far end needs).
fn connector(resolver: Arc<dyn Resolve>, wakes: Arc<AtomicU64>) -> Arc<Connector> {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .expect("the view");
    let rules = DestRules {
        policy: GuardPolicy {
            allow_private: true,
            ..GuardPolicy::default()
        },
        denylist: Arc::new(Denylist::new(&[], &[], false)),
    };
    // The root's join: the kernel's one judge, as the connector's dial judge.
    let kernel = KernelServices::new(HashMap::from([(0, rules)]), resolver);
    let judge =
        move |dest: &str, class: u32, done: crate::Judged| kernel.judge_dial(dest, class, done);
    let c = Arc::new(Connector::serving(
        view,
        Arc::new(judge),
        None,
        Arc::new(move |_| {
            wakes.fetch_add(1, Ordering::SeqCst);
        }),
    ));
    c.declare_over(OWNER, NEED, "bytes");
    c
}

/// Read one piece, driving the connection by reads alone.
async fn read(t: &HostConns, id: ConnId) -> Result<Vec<u8>, ConnError> {
    let mut buf = [0_u8; 64];
    for _ in 0..2000 {
        match t.read(id, 7, &mut buf) {
            Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(1)).await,
            Err(e) => return Err(e),
            Ok(p) => return Ok(buf[..p.len].to_vec()),
        }
    }
    panic!("no answer in two seconds");
}

/// An echo far end on `ip`, answering one connection.
async fn echo(ip: IpAddr) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = [0_u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
    });
    port
}

fn host(c: &Arc<Connector>) -> ConnHost {
    ConnHost::new(Arc::clone(c) as Arc<dyn Conns>, OWNER)
}

/// The plugin's view of `host`'s table. `host` must not move while the view is used: the view's
/// context points at it.
fn table(host: &ConnHost) -> HostConns {
    // SAFETY: the host's own slots over the context it minted; `host` outlives every call and
    // stays in place.
    unsafe { HostConns::new(host_slots(), host.ctx()) }
}

/// THE PROOF: a hostname target opens at once, the read before the resolution answers is Pending,
/// the resolution wakes the ticket, and the bytes round-trip over the address the judge pinned.
#[test]
fn a_need_dials_a_hostname_through_the_kernel_judge() {
    worker().block_on(async {
        let port = echo([127, 0, 0, 1].into()).await;
        let wakes = Arc::new(AtomicU64::new(0));
        let c = connector(
            Arc::new(Table(vec![("upstream.test", [127, 0, 0, 1].into())])),
            Arc::clone(&wakes),
        );
        let host = host(&c);
        let t = table(&host);
        let target = format!("upstream.test:{port}");
        let id = t
            .open(
                NEED,
                &OpenDesc {
                    target: &target,
                    ..OpenDesc::default()
                },
            )
            .expect("a name opens, its dial in flight");
        let mut buf = [0_u8; 8];
        assert_eq!(t.read(id, 7, &mut buf), Err(ConnError::Pending));
        assert_eq!(
            t.write(id, b"ping", false),
            Ok(4),
            "a write waits for the dial"
        );
        assert_eq!(read(&t, id).await.expect("the echo"), b"ping");
        assert!(
            wakes.load(Ordering::SeqCst) >= 1,
            "the resolution woke the ticket"
        );
        t.close(id).unwrap();
    });
}

/// The system resolver, through the same path: `localhost` resolves, is judged, and is dialled at
/// the address it answered first.
#[test]
fn a_need_dials_localhost_through_the_system_resolver() {
    use std::net::ToSocketAddrs;
    let first = ("localhost", 0)
        .to_socket_addrs()
        .expect("localhost resolves")
        .next()
        .expect("to an address")
        .ip();
    worker().block_on(async {
        let port = echo(first).await;
        let c = connector(
            Arc::new(busbar_kernel::host_services::SystemResolver),
            Arc::default(),
        );
        let host = host(&c);
        let t = table(&host);
        let target = format!("localhost:{port}");
        let id = t
            .open(
                NEED,
                &OpenDesc {
                    target: &target,
                    ..OpenDesc::default()
                },
            )
            .expect("opens");
        assert_eq!(t.write(id, b"pong", false), Ok(4));
        assert_eq!(read(&t, id).await.expect("the echo"), b"pong");
    });
}

/// RED: a refusal the name decides answers the open itself, before any resolution; a name whose
/// answer is a cloud metadata address (a rebinding) or that does not resolve opens with its dial in
/// flight and is refused on the read that finds the judgement — nothing is ever dialled.
#[test]
fn a_name_the_judge_refuses_is_never_dialled() {
    worker().block_on(async {
        let c = connector(
            Arc::new(Table(vec![("rebind.test", [169, 254, 169, 254].into())])),
            Arc::default(),
        );
        let host = host(&c);
        let t = table(&host);
        let open = |target: &str| {
            t.open(
                NEED,
                &OpenDesc {
                    target,
                    ..OpenDesc::default()
                },
            )
        };
        assert_eq!(
            open("metadata.google.internal:80"),
            Err(ConnError::Refused),
            "decided by the name, at once"
        );
        for target in ["rebind.test:80", "nowhere.test:80"] {
            let id = open(target).expect("a name opens, its judgement pending");
            assert_eq!(read(&t, id).await, Err(ConnError::Refused), "{target}");
            assert_eq!(
                read(&t, id).await,
                Err(ConnError::Refused),
                "{target}: the refusal stays"
            );
        }
    });
}
