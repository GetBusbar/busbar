// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::time::Duration;

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};

/// Complete a real framed exchange but leave its ConnId open, before close takes it from the slab.
async fn completed(c: &Connector, far: &str) -> ConnId {
    let id = c
        .open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: far,
                body: busbar_contract::conn::Bytes::copy_from_slice(b"ask"),
                ..OpenDesc::default()
            },
        )
        .expect("opens");
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0; 64];
        loop {
            let piece = futures::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf))
                .await
                .expect("reads");
            if piece.kind == PieceKind::Completion {
                break;
            }
            bytes.extend_from_slice(&buf[..piece.len]);
        }
    })
    .await
    .expect("the exchange finishes");
    assert_eq!(bytes, b"x");
    id
}

async fn closed(ended: &std::sync::atomic::AtomicUsize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while ended.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the forgotten connection closes without another use of the pool");
}

#[test]
fn recovered_pooling_can_enable_reuse_after_bootstrap_disabled_it() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60)).pooling(crate::pool::PoolPosture::NONE);
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let bootstrap = completed(&c, &far).await;
        c.close(OWNER, bootstrap).unwrap();
        c.pools.reconfigure(crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: Duration::from_secs(60),
        });
        for _ in 0..2 {
            let id = completed(&c, &far).await;
            c.close(OWNER, id).unwrap();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "only the effective requests share a line"
        );
    });
}

#[test]
fn recovered_pooling_retires_idle_cache_without_closing_an_active_anchor() {
    worker().block_on(async {
        let (far, accepted, ended) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let idle = completed(&c, &far).await;

        let active = completed(&c, &far).await;
        c.close(OWNER, idle).unwrap();
        let (_, held) = c.slab.get(OWNER, active).unwrap();
        let line = Arc::clone(&held.line.lock().unwrap().as_ref().unwrap().0);
        c.pools.reconfigure(crate::pool::PoolPosture::NONE);
        assert!(
            line.reusable(),
            "the bootstrap anchor still owns its active connection"
        );
        closed(&ended).await;
        c.close(OWNER, active).unwrap();
        assert!(
            !line.reusable(),
            "its last close does not return it to the retired cache"
        );
        for _ in 0..2 {
            let id = completed(&c, &far).await;
            c.close(OWNER, id).unwrap();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "the effective posture disables reuse"
        );
    });
}

#[test]
fn recovered_idle_timeout_applies_to_newly_completed_exchanges() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        c.pools.reconfigure(crate::pool::PoolPosture {
            max_idle_per_host: 8,
            idle_timeout: Duration::ZERO,
        });
        for _ in 0..2 {
            let id = completed(&c, &far).await;
            c.close(OWNER, id).unwrap();
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "zero effective idle time keeps no idle line"
        );
    });
}

#[test]
fn recovered_idle_budget_limits_the_number_of_reusable_lines() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60)).pooling(crate::pool::PoolPosture {
            max_idle_per_host: 128,
            idle_timeout: Duration::from_secs(60),
        });
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        c.pools.reconfigure(crate::pool::PoolPosture {
            max_idle_per_host: 1,
            idle_timeout: Duration::from_secs(60),
        });
        let mut simultaneous = Vec::new();
        for _ in 0..3 {
            simultaneous.push(completed(&c, &far).await);
        }
        for id in simultaneous {
            c.close(OWNER, id).unwrap();
        }
        let first = completed(&c, &far).await;
        let second = completed(&c, &far).await;
        c.close(OWNER, first).unwrap();
        c.close(OWNER, second).unwrap();
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            4,
            "only one of the three effective lines was retained"
        );
    });
}

#[test]
fn a_close_that_took_its_conn_before_forget_closes_the_retired_line() {
    worker().block_on(async {
        let (far, _, ended) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let id = completed(&c, &far).await;

        let held = c.slab.remove(OWNER, id).unwrap();
        let (shard, key) = held.pooled.as_ref().unwrap();
        let (line, stream) = held.line.lock().unwrap().take().unwrap();
        assert!(line.reusable());
        assert!(held.whole.load(Ordering::Acquire));
        c.forget(OWNER);
        c.let_go(&held, &line, stream, true);

        assert!(!line.reusable(), "the last holder closes a retired line");
        assert!(c.pools.lend(*shard, key).is_none(), "retirement is final");
        closed(&ended).await;
    });
}

#[test]
fn an_unregistered_release_preserves_its_holder_without_retaining_the_key() {
    worker().block_on(async {
        let (far, _, ended) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let id = completed(&c, &far).await;
        let held = c.slab.remove(OWNER, id).unwrap();
        let (shard, original) = held.pooled.as_ref().unwrap();
        let (line, stream) = held.line.lock().unwrap().take().unwrap();
        c.forget(OWNER);

        let trust = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let weak = Arc::downgrade(&trust);
        let mut key = original.clone();
        key.trust = Some(crate::pool::Same(trust));
        c.pools.release(*shard, &key, &line);
        assert!(
            line.reusable(),
            "the remaining holder still owns a live line"
        );
        drop(key);
        let retained = weak.upgrade().is_some();
        c.let_go(&held, &line, stream, true);
        assert!(
            !retained,
            "a release with a live holder retains no absent key"
        );
        assert!(
            !line.reusable(),
            "its last release closes the uncached line"
        );
        closed(&ended).await;
    });
}

#[test]
fn a_registered_complete_line_still_serves_the_next_exchange() {
    worker().block_on(async {
        let (far, accepted, _) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let id = completed(&c, &far).await;
        c.close(OWNER, id).unwrap();
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", false).await.0,
            b"x"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "the line was reused");
    });
}

#[test]
fn an_uncached_line_closes_without_displacing_a_registered_line_for_the_same_key() {
    worker().block_on(async {
        let (far, accepted, ended) = keeping_far_end().await;
        let c = pooled_messages(Duration::from_secs(60));
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let first = completed(&c, &far).await;
        let second = completed(&c, &far).await;
        let held = c.slab.remove(OWNER, first).unwrap();
        let (shard, key) = held.pooled.as_ref().unwrap();
        let (line, stream) = held.line.lock().unwrap().take().unwrap();
        c.pools.drop_line(*shard, key, &line);
        assert!(
            line.reusable(),
            "an unregistered line stays with its holder"
        );
        c.close(OWNER, second).unwrap();
        c.let_go(&held, &line, stream, true);
        assert!(!line.reusable(), "release closes the unregistered line");
        closed(&ended).await;
        assert_eq!(
            pooled_exchange(&c, (OWNER, 0), &far, b"ask", false).await.0,
            b"x"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the other line was reused"
        );
    });
}

struct PausedRead {
    inner: TestDoor,
    gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

struct ReentrantShut {
    inner: TestDoor,
    connector: Mutex<std::sync::Weak<Connector>>,
    calls: AtomicUsize,
}

impl FramerDoor for ReentrantShut {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if matches!(&call, Carry::Shut(..)) {
            let connector = self.connector.lock().unwrap().upgrade();
            if let Some(connector) = connector {
                connector.pools.reconfigure(crate::pool::PoolPosture::NONE);
                self.calls.fetch_add(1, Ordering::SeqCst);
            }
        }
        self.inner.carry(side, resume, call)
    }
}

#[test]
fn retiring_the_bootstrap_pool_closes_connections_outside_every_pool_lock() {
    let rt = worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (far, _, _) = keeping_far_end().await;
        let carrier = Arc::new(ReentrantShut {
            inner: TestDoor::identity("carrier"),
            connector: Mutex::new(std::sync::Weak::new()),
            calls: AtomicUsize::new(0),
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
                door: carrier.clone(),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let c = Arc::new(
            Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {}))
                .pooling(crate::pool::PoolPosture::default()),
        );
        *carrier.connector.lock().unwrap() = Arc::downgrade(&c);
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let id = completed(&c, &far).await;
        c.close(OWNER, id).unwrap();
        let retiring = Arc::clone(&c);
        let (done, observed) = mpsc::channel();
        let retired = std::thread::spawn(move || {
            let _runtime = handle.enter();
            retiring.pools.reconfigure(crate::pool::PoolPosture::NONE);
            done.send(()).unwrap();
        });
        observed
            .recv_timeout(Duration::from_secs(5))
            .expect("a close callback can re-enter pool publication");
        retired.join().unwrap();
        assert_eq!(carrier.calls.load(Ordering::SeqCst), 1);
    });
}

impl FramerDoor for PausedRead {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if matches!(&call, Carry::Read(..)) {
            let gate = self.gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
        }
        self.inner.carry(side, resume, call)
    }
}

#[test]
fn forget_removes_an_idle_line_while_its_unlocked_freshness_read_is_in_flight() {
    idle_probe_loses_retired_membership(|c| c.forget(OWNER));
}

#[test]
fn bootstrap_recovery_removes_an_idle_line_while_its_freshness_read_is_in_flight() {
    idle_probe_loses_retired_membership(|c| {
        c.pools.reconfigure(crate::pool::PoolPosture::default())
    });
}

fn idle_probe_loses_retired_membership(retire: impl FnOnce(&Connector)) {
    let rt = worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (far, _, ended) = keeping_far_end().await;
        let carrier = Arc::new(PausedRead {
            inner: TestDoor::identity("carrier"),
            gate: Mutex::new(None),
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
                door: carrier.clone(),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let c = Arc::new(
            Connector::serving(view, loopback_literals(), None, Arc::new(|_, _| {})).pooling(
                crate::pool::PoolPosture {
                    max_idle_per_host: 8,
                    idle_timeout: Duration::from_secs(60),
                },
            ),
        );
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let id = completed(&c, &far).await;
        let (_, held) = c.slab.get(OWNER, id).unwrap();
        let (shard, key) = held.pooled.clone().unwrap();
        c.close(OWNER, id).unwrap();
        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel();
        *carrier.gate.lock().unwrap() = Some((entered_tx, held_back));
        let lending = Arc::clone(&c);
        let probe_key = key.clone();
        let probe = std::thread::spawn(move || {
            let _rt = handle.enter();
            lending.pools.lend(shard, &probe_key)
        });
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the idle freshness read reaches the carrier");
        retire(&c);
        release.send(()).unwrap();
        let lent = probe.join().unwrap();
        let was_lent = lent.is_some();

        if let Some(line) = lent {
            line.leave(crate::compose::EXCHANGE_STREAM, false);
            c.pools.drop_line(shard, &key, &line);
        }
        assert!(
            !was_lent,
            "a freshness probe cannot restore a retired entry"
        );
        assert!(c.pools.lend(shard, &key).is_none());
        closed(&ended).await;
    });
}
