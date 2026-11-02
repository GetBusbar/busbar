// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use std::time::{Duration, Instant};

struct Counted(
    TestDoor,
    std::sync::atomic::AtomicUsize,
    Mutex<Option<Box<dyn FnOnce() + Send>>>,
);

impl FramerDoor for Counted {
    fn facts(&self) -> &DoorFacts {
        self.0.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.0.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.0.side()
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if matches!(&call, Carry::Dial(..)) {
            self.1.fetch_add(1, Ordering::SeqCst);
            let crossing = self.2.lock().unwrap().take();
            if let Some(crossing) = crossing {
                crossing();
            }
        }
        self.0.carry(side, resume, call)
    }
}

fn pending(timeout_ms: u64) -> (Connector, Arc<Counted>, Arc<Mutex<Option<crate::Judged>>>) {
    let carrier = Arc::new(Counted(
        TestDoor::identity("bytes"),
        Default::default(),
        Mutex::new(None),
    ));
    let pending = Arc::new(Mutex::new(None));
    let answering = pending.clone();
    let c = Connector::serving(
        Transports::new(vec![Entry {
            door: carrier.clone(),
            alpn: Vec::new(),
        }])
        .unwrap(),
        Arc::new(move |_: &str, _: u32, done: crate::Judged| {
            *answering.lock().unwrap() = Some(done);
            None
        }),
        None,
        Arc::new(|_, _| {}),
    );
    let mut need = config_targeted_need("");
    need.timeout_ms = timeout_ms;
    DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None).unwrap();
    (c, carrier, pending)
}

#[test]
fn declared_dial_inheritance_and_explicit_request_bounds_stay_independent() {
    for (declared, dial, request, expected) in [
        (700, 0, 0, 700),
        (700, 123, 900, 123),
        (
            0,
            0,
            0,
            crate::compose::DEFAULT_OPEN_TIMEOUT.as_millis() as u64,
        ),
    ] {
        let (c, _, _) = pending(declared);
        let before = Instant::now();
        let id = c
            .open_request(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "pending.test:443",
                    timeout_ms: request,
                    ..Default::default()
                },
                false,
                dial,
            )
            .unwrap();
        let after = Instant::now();
        let held = c.slab.get(OWNER, id).unwrap().1;
        let at = held.dial_due.lock().unwrap().as_ref().unwrap().at;
        assert!(at >= before + Duration::from_millis(expected));
        assert!(at <= after + Duration::from_millis(expected));
        let request_at = held.due.lock().unwrap().as_ref().map(|due| due.at);
        if request == 0 {
            assert!(request_at.is_none());
        } else {
            assert!(request_at.unwrap() >= before + Duration::from_millis(request));
        }
        assert_eq!(c.landed(OWNER, id, 70), Err(ConnError::Pending));
        assert_eq!(c.landed(OWNER, id, 70), Err(ConnError::Pending));
        assert_eq!(
            held.dial_due.lock().unwrap().as_ref().unwrap().at,
            at,
            "Pending keeps the original dial clock"
        );
        c.close(OWNER, id).unwrap();
    }
}

#[test]
fn a_declared_dial_timeout_covers_the_pended_judgement_without_replay() {
    let (c, carrier, pending) = pending(700);
    let id = c
        .open_request(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "pending.test:443",
                ..Default::default()
            },
            false,
            0,
        )
        .unwrap();
    assert_eq!(c.write(OWNER, id, b"accepted", true, true), Ok(8));
    let held = c.slab.get(OWNER, id).unwrap().1;
    held.dial_due.lock().unwrap().as_mut().unwrap().at = Instant::now();
    pending.lock().unwrap().take().unwrap()(Ok("127.0.0.1:9".parse().unwrap()));
    for _ in 0..3 {
        assert_eq!(c.landed(OWNER, id, 71), Err(ConnError::Timeout));
        assert_eq!(c.wait(OWNER, &[id], 71), Ok(0));
        assert_eq!(c.read(OWNER, id, 71, &mut [0; 8]), Err(ConnError::Timeout));
    }
    assert_eq!(
        carrier.1.load(Ordering::SeqCst),
        0,
        "an expired dial never crosses into the carrier"
    );
    c.close(OWNER, id).unwrap();
    assert_eq!(c.read(OWNER, id, 71, &mut [0; 8]), Err(ConnError::Closed));
}

#[test]
fn re_declaration_changes_only_the_next_opens_inherited_bound() {
    let (c, _, _) = pending(700);
    let first = c
        .open_request(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "first.test:443",
                ..Default::default()
            },
            false,
            0,
        )
        .unwrap();
    let first_due = c
        .slab
        .get(OWNER, first)
        .unwrap()
        .1
        .dial_due
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .at;
    let mut need = config_targeted_need("");
    need.timeout_ms = 1200;
    DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None).unwrap();
    let before = Instant::now();
    let second = c
        .open_request(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "second.test:443",
                ..Default::default()
            },
            false,
            0,
        )
        .unwrap();
    let held = c.slab.get(OWNER, second).unwrap().1;
    assert!(
        held.dial_due.lock().unwrap().as_ref().unwrap().at >= before + Duration::from_millis(1200)
    );
    assert_eq!(
        c.slab
            .get(OWNER, first)
            .unwrap()
            .1
            .dial_due
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .at,
        first_due
    );
    c.close(OWNER, first).unwrap();
    c.close(OWNER, second).unwrap();
}

#[test]
fn a_legacy_explicit_open_bound_overrides_the_declared_dial_default() {
    let (c, _, _) = pending(700);
    let before = Instant::now();
    let id = c
        .open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "pending.test:443",
                timeout_ms: 123,
                ..Default::default()
            },
        )
        .unwrap();
    let held = c.slab.get(OWNER, id).unwrap().1;
    assert!(
        held.dial_due.lock().unwrap().as_ref().unwrap().at < before + Duration::from_millis(700)
    );
    assert!(held.due.lock().unwrap().as_ref().unwrap().at >= before + Duration::from_millis(123));
    c.close(OWNER, id).unwrap();
}

#[test]
fn a_pending_dial_deadline_wakes_the_actual_connector_reader() {
    worker().block_on(async {
        let (c, carrier, _) = pending(30);
        let id = c
            .open_request(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "pending.test:443",
                    ..Default::default()
                },
                false,
                0,
            )
            .unwrap();
        let mut bytes = [0; 8];
        let got = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut bytes)),
        )
        .await
        .unwrap();
        assert_eq!(got, Err(ConnError::Timeout));
        assert_eq!(carrier.1.load(Ordering::SeqCst), 0);
        c.close(OWNER, id).unwrap();
    });
}

#[test]
fn landing_spends_only_the_dial_bound_and_the_first_reply_spends_the_request_bound() {
    use tokio::io::AsyncWriteExt as _;
    worker().block_on(async {
        let (listener, target) = far_end().await;
        let waking = Arc::new(futures::task::AtomicWaker::new());
        let signal = waking.clone();
        let c = Connector::serving(
            Transports::new(vec![Entry {
                door: Arc::new(TestDoor::identity("bytes")),
                alpn: Vec::new(),
            }])
            .unwrap(),
            loopback_literals(),
            None,
            Arc::new(move |_, _| signal.wake()),
        );
        let mut need = config_targeted_need("");
        need.timeout_ms = 60_000;
        DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None).unwrap();
        let id = c
            .open_request(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &target,
                    timeout_ms: 90_000,
                    ..Default::default()
                },
                false,
                60_000,
            )
            .unwrap();
        let held = c.slab.get(OWNER, id).unwrap().1;
        let mut bytes = [0; 8];
        tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| {
                assert_eq!(
                    c.poll_read(OWNER, id, cx, &mut bytes),
                    Poll::Pending,
                    "the far end has sent no reply"
                );
                if held.dial_due.lock().unwrap().is_none() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();
        assert!(held.dial_due.lock().unwrap().is_none());
        assert!(held.due.lock().unwrap().is_some());
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.write_all(b"ok").await.unwrap();
        let piece = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut bytes)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..piece.len], b"ok");
        assert!(held.due.lock().unwrap().is_none());
        c.close(OWNER, id).unwrap();
    });
}

#[test]
fn a_pended_dns_dial_carries_its_expired_original_bound_into_the_tls_stage() {
    crate::tls::install_crypto_provider();
    let ca = crate::test_support::private_ca();
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: crate::test_support::certs_from_pem(&ca.ca_pem),
        ..Default::default()
    };
    let tls = Arc::new(crate::tls::client::build_client_config(&trust).unwrap());
    worker().block_on(async {
        let (_listener, address) = far_end().await;
        let carrier = Arc::new(Counted(
            TestDoor::identity("bytes"),
            Default::default(),
            Mutex::new(None),
        ));
        let answer = Arc::new(Mutex::new(None));
        let pending = answer.clone();
        let framing = Arc::new(TestDoor::new(
            "frames",
            &["frames"],
            &["bytes"],
            crate::support::Knobs {
                secure_name: Some("localhost"),
                ..Default::default()
            },
        ));
        let c = Connector::serving(
            Transports::new(vec![
                Entry {
                    door: framing.clone(),
                    alpn: Vec::new(),
                },
                Entry {
                    door: carrier.clone(),
                    alpn: Vec::new(),
                },
            ])
            .unwrap(),
            Arc::new(move |_: &str, _: u32, done: crate::Judged| {
                *pending.lock().unwrap() = Some(done);
                None
            }),
            Some(tls),
            Arc::new(|_, _| {}),
        );
        let mut need = config_targeted_need("");
        need.transport = "frames".to_owned();
        need.timeout_ms = 60_000;
        DeclaredConns::declare(&c, OWNER, NeedId(0), &need, None, None).unwrap();
        let id = c
            .open_request(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "tls.test:443",
                    timeout_ms: 90_000,
                    ..Default::default()
                },
                false,
                0,
            )
            .unwrap();
        assert_eq!(c.landed(OWNER, id, 73), Err(ConnError::Pending));
        assert_eq!(carrier.1.load(Ordering::SeqCst), 0);
        let held = c.slab.get(OWNER, id).unwrap().1;
        let expiring = held.clone();
        *carrier.2.lock().unwrap() = Some(Box::new(move || {
            // The original budget expires while resolution's admitted dial crosses. The TLS
            // engine has already been constructed with valid trust, but must get no fresh clock.
            expiring.dial_due.lock().unwrap().as_mut().unwrap().at = Instant::now();
        }));
        answer.lock().unwrap().take().unwrap()(Ok(address.parse().unwrap()));
        assert_eq!(c.read(OWNER, id, 73, &mut [0; 8]), Err(ConnError::Timeout));
        assert_eq!(
            carrier.1.load(Ordering::SeqCst),
            1,
            "valid TLS reached the actual admitted carrier"
        );
        assert_eq!(
            framing.count("begin"),
            0,
            "no request framing starts past the original dial bound"
        );
        assert!(
            held.due.lock().unwrap().is_some(),
            "the independent request bound was not spent by landing"
        );
        c.close(OWNER, id).unwrap();
    });
}
