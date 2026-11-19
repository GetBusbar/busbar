// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W4: a declared target's place is a declaration fact. The head's deadline-bearing
//! locate stays per request; the open's plan, its authority pin and a prepared commit's re-plan
//! reuse the place the first open located through the same door, under the same settings.
//! Counted at the far end: every Locate crossing the test door answers.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::framer::{Call, Crossed, DoorFacts};
use crate::registry::{Entry, Transports};
use crate::support::{worker, Knobs, TestDoor};
use busbar_contract::abi::mechanism::call::Outcome;

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);

/// A framer over the `bytes` scheme that states one head line of its own.
fn framer() -> TestDoor {
    TestDoor::new(
        "bytes",
        &["bytes"],
        &[],
        Knobs {
            head_lines: Some(b"x-place: 1\r\n"),
            ..Knobs::default()
        },
    )
}

/// The connector serving `door` for `bytes`, over a loaded address carrier.
fn connector(door: Arc<dyn FramerDoor>) -> Connector {
    let view = Transports::new(vec![
        Entry {
            door,
            alpn: Arc::default(),
        },
        Entry {
            door: Arc::new(TestDoor::identity("carrier")),
            alpn: Arc::default(),
        },
    ])
    .unwrap();
    let c = Connector::serving(
        view,
        crate::tests::loopback_literals(),
        None,
        Arc::new(|_, _| {}),
    );
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
    c
}

fn desc(target: &str) -> OpenDesc<'_> {
    OpenDesc {
        target,
        body: Bytes::from_static(b"x"),
        method: b"POST",
        head_target: b"/",
        ..OpenDesc::default()
    }
}

/// One plane-style request: the head's defaults, then the open. Answers the open and how many
/// Locate crossings the pair made.
fn request(c: &Connector, door: &TestDoor, target: &str) -> (Result<ConnId, ConnError>, usize) {
    let before = door.count("locate");
    c.head_defaults(OWNER, NEED, target, 1000)
        .expect("the head's defaults");
    let opened = c.open(OWNER, NEED, &desc(target));
    (opened, door.count("locate") - before)
}

/// Drive `id` until `door` began a framing `begins` times in all (an open dials when driven).
async fn begun(c: &Connector, door: &TestDoor, id: ConnId, begins: usize) {
    let mut buf = [0_u8; 16];
    tokio::time::timeout(Duration::from_secs(5), async {
        while door.count("begin") < begins {
            let _ = c.read(OWNER, id, 7, &mut buf);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the open reaches its far end and begins its framing");
}

/// RED: a declared-target request located its target three times (the head, the open's plan,
/// the authority pin). Once the first open has located the place, a request locates once: the
/// head's deadline-bearing defaults.
#[test]
fn declared_target_request_locates_once() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(framer());
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &at)
            .unwrap();
        let (warm, _) = request(&c, &door, "");
        c.close(OWNER, warm.expect("the warm-up open")).unwrap();
        for _ in 0..3 {
            let (opened, locates) = request(&c, &door, "");
            assert_eq!(locates, 1, "one locate per declared-target request");
            c.close(OWNER, opened.expect("the open")).unwrap();
        }
    });
}

/// A declare makes no Locate crossing, before and after: the place fills lazily, on an open.
#[test]
fn declare_alone_locates_nothing() {
    let door = Arc::new(framer());
    let c = connector(door.clone());
    c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, "127.0.0.1:9")
        .unwrap();
    assert_eq!(door.count("locate"), 0);
}

/// A target the plugin names per open keeps its two locates (the head, the plan), before and
/// after: only a declared target's place is kept.
#[test]
fn undeclared_target_locates_twice() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(framer());
        let c = connector(door.clone());
        c.declare_over(OWNER, NEED, "bytes").unwrap();
        for _ in 0..3 {
            let (opened, locates) = request(&c, &door, &at);
            assert_eq!(locates, 2, "the head and the plan, every request");
            c.close(OWNER, opened.expect("the open")).unwrap();
        }
    });
}

/// RED: a prepared commit on a declared target re-planned with a fresh locate. With the place
/// kept, the commit adds none.
#[test]
fn prepared_commit_on_declared_target_adds_no_locate() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(framer());
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &at)
            .unwrap();
        let (warm, _) = request(&c, &door, "");
        c.close(OWNER, warm.expect("the warm-up open")).unwrap();
        let desc = desc("");
        let conn = c.prepare_request(OWNER, NEED, &desc, 1000).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match c.facts(OWNER, conn) {
                    Ok(_) => break,
                    Err(ConnError::Pending) => tokio::task::yield_now().await,
                    other => panic!("unexpected facts: {other:?}"),
                }
            }
        })
        .await
        .expect("the prepared line lands");
        let before = door.count("locate");
        c.commit_request(OWNER, conn, &desc, false).unwrap();
        assert_eq!(
            door.count("locate") - before,
            0,
            "the commit re-plans from the kept place"
        );
        c.close(OWNER, conn).unwrap();
    });
}

/// A framer whose Locate fails while `fail` is set, otherwise the inner door's.
struct Flaky {
    inner: TestDoor,
    fail: AtomicBool,
}

impl FramerDoor for Flaky {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        if matches!(call, Call::Locate(..)) && self.fail.load(Ordering::SeqCst) {
            self.inner.crossings.lock().unwrap().push("locate");
            return Crossed {
                outcome: Outcome::Failed,
                error: Some(b"not yet".to_vec()),
            };
        }
        self.inner.cross(call)
    }
}

/// A first open whose locate fails fails as today and stores nothing; the next open locates
/// again and fills the place, and the one after reuses it.
#[test]
fn failed_first_locate_stores_nothing() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(Flaky {
            inner: framer(),
            fail: AtomicBool::new(true),
        });
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &at)
            .unwrap();
        let counted = || door.inner.count("locate");
        let before = counted();
        assert!(c.open(OWNER, NEED, &desc("")).is_err(), "it fails as today");
        assert_eq!(counted() - before, 1, "the failing open asked once");

        door.fail.store(false, Ordering::SeqCst);
        let before = counted();
        let filled = c
            .open(OWNER, NEED, &desc(""))
            .expect("the door answers now");
        assert!(
            counted() - before >= 1,
            "nothing was stored: it locates again"
        );
        c.close(OWNER, filled).unwrap();

        let before = counted();
        let reused = c.open(OWNER, NEED, &desc("")).expect("the open");
        assert_eq!(
            counted() - before,
            0,
            "the place was filled by the last open"
        );
        c.close(OWNER, reused).unwrap();
    });
}

/// The head a declared-target open hands its framer is the same whether its place was located
/// for it or kept from an earlier open: the same defaults, completed the same way.
#[test]
fn head_defaults_unchanged() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(framer());
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &at)
            .unwrap();
        let first = c.open(OWNER, NEED, &desc("")).unwrap();
        begun(&c, &door, first, 1).await;
        let second = c.open(OWNER, NEED, &desc("")).unwrap();
        begun(&c, &door, second, 2).await;
        let begun = door.begun_fields.lock().unwrap().clone();
        assert_eq!(begun.len(), 2);
        assert!(
            begun[0]
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case(b"x-place") && v == b"1"),
            "the located default is in the head: {begun:?}"
        );
        assert_eq!(begun[0], begun[1], "byte-identical heads");
        c.close(OWNER, first).unwrap();
        c.close(OWNER, second).unwrap();
        drop(listener);
    });
}

/// A framer whose settings the test refreshes, as `Live::refresh` does a loaded transport's:
/// Locate answers through `before` until `refreshed`, then through `after` (another authority),
/// and its settings epoch is the test's. With `bump_in_locate` set, the next Locate itself moves
/// the epoch, as a refresh returning during the call does.
struct Refreshing {
    before: TestDoor,
    after: TestDoor,
    refreshed: AtomicBool,
    epoch: AtomicU64,
    bump_in_locate: AtomicBool,
    locates: AtomicUsize,
}

impl Refreshing {
    fn new(after: &'static str) -> Self {
        Self {
            before: framer(),
            after: TestDoor::new(
                "bytes",
                &["bytes"],
                &[],
                Knobs {
                    authority: Some(after),
                    head_lines: Some(b"x-place: 1\r\n"),
                    ..Knobs::default()
                },
            ),
            refreshed: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            bump_in_locate: AtomicBool::new(false),
            locates: AtomicUsize::new(0),
        }
    }

    fn locates(&self) -> usize {
        self.locates.load(Ordering::SeqCst)
    }
}

impl FramerDoor for Refreshing {
    fn io_owner(&self) -> Option<u64> {
        self.before.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.before.facts()
    }
    fn settings_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        if matches!(call, Call::Locate(..)) {
            self.locates.fetch_add(1, Ordering::SeqCst);
            if self.bump_in_locate.swap(false, Ordering::SeqCst) {
                self.epoch.fetch_add(1, Ordering::SeqCst);
            }
            if self.refreshed.load(Ordering::SeqCst) {
                return self.after.cross(call);
            }
        }
        self.before.cross(call)
    }
}

/// Drive `id` until `listener` accepted a connection.
async fn reached(c: &Connector, id: ConnId, listener: &tokio::net::TcpListener) {
    let mut buf = [0_u8; 16];
    tokio::time::timeout(Duration::from_secs(5), async {
        let accept = listener.accept();
        tokio::pin!(accept);
        loop {
            tokio::select! {
                accepted = &mut accept => {
                    accepted.unwrap();
                    break;
                }
                () = tokio::task::yield_now() => {
                    let _ = c.read(OWNER, id, 7, &mut buf);
                }
            }
        }
    })
    .await
    .expect("the open reaches the far end its place names");
}

/// A settings refresh moves the door's epoch, so the kept place is stale: the next open locates
/// again under the new settings and dials what they name; the one after reuses the new place.
#[test]
fn refresh_changes_place_relocates() {
    worker().block_on(async {
        let before = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let after = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let before_at = before.local_addr().unwrap().to_string();
        let after_at: &'static str = Box::leak(after.local_addr().unwrap().to_string().into());
        let door = Arc::new(Refreshing::new(after_at));
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &before_at)
            .unwrap();
        let first = c.open(OWNER, NEED, &desc("")).unwrap();
        reached(&c, first, &before).await;
        let counted = door.locates();
        let kept = c.open(OWNER, NEED, &desc("")).unwrap();
        assert_eq!(door.locates() - counted, 0, "the place is kept");
        reached(&c, kept, &before).await;

        door.refreshed.store(true, Ordering::SeqCst);
        door.epoch.fetch_add(1, Ordering::SeqCst);
        let counted = door.locates();
        let moved = c.open(OWNER, NEED, &desc("")).unwrap();
        assert_eq!(
            door.locates() - counted,
            1,
            "a stale place is located again"
        );
        reached(&c, moved, &after).await;
        let counted = door.locates();
        let next = c.open(OWNER, NEED, &desc("")).unwrap();
        assert_eq!(door.locates() - counted, 0, "the refreshed place is kept");
        reached(&c, next, &after).await;
        for id in [first, kept, moved, next] {
            c.close(OWNER, id).unwrap();
        }
    });
}

/// A refresh that returns while a place is being located stores nothing from that answer: the
/// open goes on with it, and the next site locates again.
#[test]
fn refresh_during_fill_stores_nothing() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let door = Arc::new(Refreshing::new("127.0.0.1:9"));
        let c = connector(door.clone());
        c.declare_need_to(OWNER, NEED, "bytes", crate::DEFAULT_CLASS, &at)
            .unwrap();
        door.bump_in_locate.store(true, Ordering::SeqCst);
        let first = c
            .open(OWNER, NEED, &desc(""))
            .expect("the open uses its own answer");
        assert_eq!(
            door.locates(),
            2,
            "the plan's answer was not kept, so the authority pin located again"
        );
        reached(&c, first, &listener).await;
        let counted = door.locates();
        let next = c.open(OWNER, NEED, &desc("")).unwrap();
        assert_eq!(door.locates() - counted, 0, "the pin's answer was kept");
        c.close(OWNER, first).unwrap();
        c.close(OWNER, next).unwrap();
    });
}
