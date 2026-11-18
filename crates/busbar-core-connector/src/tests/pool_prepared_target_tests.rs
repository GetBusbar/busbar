// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W1 §8: the prepared commit's own target on a lent line when the target is the
//! need's declared one, and a cold prepared line dropped at once. Counted at the far end.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::framer::{Call, Crossed, DoorFacts};
use crate::registry::{Entry, Transports};
use crate::support::{worker, Knobs, TestDoor};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);
const TICKET: Ticket = 7;

/// The scripted `messages` framer: the far end's `x` is a one-byte message, `e` ends the
/// exchange, each on the latest emitted exchange.
fn messages_knobs() -> Knobs {
    Knobs {
        messages: Some(crate::compose::EXCHANGE_STREAM),
        messages_follow_emit: true,
        ..Knobs::default()
    }
}

/// A connector serving `door` for `messages` over a loaded carrier, keeping finished lines idle.
fn pooled(door: Arc<dyn FramerDoor>) -> Connector {
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
    let c = Connector::serving(
        view,
        crate::tests::loopback_literals(),
        None,
        Arc::new(|_, _| {}),
    )
    .pooling(crate::pool::PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    });
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
    c
}

fn desc(target: &str) -> OpenDesc<'_> {
    OpenDesc {
        target,
        body: Bytes::from_static(b"ask"),
        ..OpenDesc::default()
    }
}

/// `conn`'s facts, once its line has landed.
async fn facts(c: &Connector, conn: ConnId) -> ConnFacts {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match c.facts(OWNER, conn) {
                Ok(facts) => break facts,
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                other => panic!("unexpected facts: {other:?}"),
            }
        }
    })
    .await
    .expect("the prepared line lands")
}

/// `conn`'s whole answer: its bytes, whether it ended whole, and the error that ended it.
async fn answer(c: &Connector, conn: ConnId) -> (Vec<u8>, bool, Option<ConnError>) {
    let mut buf = [0_u8; 64];
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match c.read(OWNER, conn, TICKET, &mut buf) {
            Ok(p) if p.kind == PieceKind::Completion => {
                return (got, p.stream != StreamId(0), None);
            }
            Ok(p) => got.extend_from_slice(&buf[..p.len]),
            Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
            Err(e) => return (got, false, Some(e)),
        }
    }
    panic!("the answer did not end in time: {got:?}");
}

/// One prepared exchange: prepare, facts, commit, its whole answer, close.
async fn prepared_exchange(c: &Connector, target: &str) -> Vec<u8> {
    let desc = desc(target);
    let conn = c.prepare_request(OWNER, NEED, &desc, 1000).unwrap();
    facts(c, conn).await;
    c.commit_request(OWNER, conn, &desc, false).unwrap();
    let (got, whole, failed) = answer(c, conn).await;
    assert_eq!((whole, failed), (true, None), "the answer ends whole");
    c.close(OWNER, conn).unwrap();
    got
}

/// A `messages` framer that renders each opening's fields, and whose Locate states a head line
/// naming the target's path: `x-path: /v1/traces` or `x-path: /v1/metrics`.
struct PathDoor {
    framing: TestDoor,
    traces: TestDoor,
    metrics: TestDoor,
}

impl PathDoor {
    fn new() -> Self {
        let located = |line: &'static [u8]| {
            TestDoor::new(
                "messages",
                &["messages"],
                &[],
                Knobs {
                    locate_authority: true,
                    head_lines: Some(line),
                    ..messages_knobs()
                },
            )
        };
        Self {
            framing: TestDoor::new(
                "messages",
                &["messages"],
                &[],
                Knobs {
                    render_fields: true,
                    ..messages_knobs()
                },
            ),
            traces: located(b"x-path: /v1/traces\r\n"),
            metrics: located(b"x-path: /v1/metrics\r\n"),
        }
    }
}

impl FramerDoor for PathDoor {
    fn io_owner(&self) -> Option<u64> {
        self.framing.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.framing.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        let metrics = match &call {
            Call::Locate(i, _) => {
                Some(crate::support::lent(i.target.ptr, i.target.len).ends_with(b"/v1/metrics"))
            }
            _ => None,
        };
        match metrics {
            Some(true) => self.metrics.cross(call),
            Some(false) => self.traces.cross(call),
            None => self.framing.cross(call),
        }
    }
}

/// A far end that answers each request `xe` and records its head: the bytes up to its blank line
/// (a request is its rendered fields, a blank line, and the 3-byte body).
async fn head_recording_far_end() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(Mutex::new(Vec::new()));
    let (count, seen) = (Arc::clone(&accepted), Arc::clone(&heads));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut pending = Vec::new();
                let mut buf = [0_u8; 256];
                loop {
                    while let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        if pending.len() < at + 4 + 3 {
                            break;
                        }
                        let head = String::from_utf8_lossy(&pending[..at]).into_owned();
                        seen.lock().unwrap().push(head);
                        pending.drain(..at + 4 + 3);
                        if s.write_all(b"xe").await.is_err() {
                            return;
                        }
                    }
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                    }
                }
            });
        }
    });
    (far, accepted, heads)
}

/// The declared-target variant of `prepared_commit_uses_its_own_target_on_a_lent_line`: the
/// need is declared for `/v1/metrics`; after a `/v1/traces` exchange on its key, a prepare with
/// an empty target (the declared one) is lent that line. RED against a commit that re-plans from
/// the line's target: its head carries `/v1/traces`.
#[test]
fn prepared_commit_uses_its_declared_target_on_a_lent_line() {
    worker().block_on(async {
        let (far, accepted, heads) = head_recording_far_end().await;
        let c = pooled(Arc::new(PathDoor::new()));
        let traces = format!("http://{far}/v1/traces");
        let metrics = format!("http://{far}/v1/metrics");
        c.declare_need_to(OWNER, NEED, "messages", crate::DEFAULT_CLASS, &metrics)
            .unwrap();
        assert_eq!(prepared_exchange(&c, &traces).await, b"x");
        assert_eq!(prepared_exchange(&c, "").await, b"x");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the declared-target prepare was lent the line"
        );
        let heads = heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 2, "{heads:?}");
        assert!(heads[0].contains("x-path: /v1/traces"), "{heads:?}");
        assert!(
            heads[1].contains("x-path: /v1/metrics") && !heads[1].contains("/v1/traces"),
            "the second head carries its declared target's defaults: {heads:?}"
        );
    });
}

/// A far end that counts its accepts, answers each 3-byte request `xe`, and counts the
/// connections whose client end closed (read 0 or failed).
async fn closing_far_end() -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (count, ends) = (Arc::clone(&accepted), Arc::clone(&closed));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let ends = Arc::clone(&ends);
            tokio::spawn(async move {
                let mut buf = [0_u8; 3];
                while s.read_exact(&mut buf).await.is_ok() {
                    if s.write_all(b"xe").await.is_err() {
                        break;
                    }
                }
                ends.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (far, accepted, closed)
}

/// A cold prepared line dropped at once (no `landed`, no `facts()`) is not kept: the next
/// prepared exchange rides a line of its own (accepts=2), and the first line is closed, not left
/// in the pool. Green before and after: it pins W1.5's narrowed claim.
#[test]
fn abandoned_before_facts_cold_closes() {
    worker().block_on(async {
        let (far, accepted, closed) = closing_far_end().await;
        let c = pooled(Arc::new(TestDoor::new(
            "messages",
            &["messages"],
            &[],
            messages_knobs(),
        )));
        c.declare_over(OWNER, NEED, "messages").unwrap();
        let conn = c.prepare_request(OWNER, NEED, &desc(&far), 1000).unwrap();
        // The connector never drives it; only the far end's accept is awaited, so the first
        // line is known to exist before it is dropped.
        tokio::time::timeout(Duration::from_secs(5), async {
            while accepted.load(Ordering::SeqCst) < 1 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the cold prepare's connect reaches the far end");
        c.close(OWNER, conn).unwrap();
        assert_eq!(prepared_exchange(&c, &far).await, b"x");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the cold line was not lent to the next prepare"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while closed.load(Ordering::SeqCst) < 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the dropped cold line is closed, not kept in the pool");
        assert_eq!(
            closed.load(Ordering::SeqCst),
            1,
            "only the dropped cold line closed; the second is idle in the pool"
        );
    });
}
