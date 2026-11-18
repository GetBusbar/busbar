// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W5: one declaration is held once, shared by every open as an `Arc`, never
//! deep-cloned per open (its anchors' DER, its client identity's private key).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

const OWNER: InstanceId = InstanceId(1);

/// Whether `T` implements `Clone`, answered at run time by method resolution: the `Clone` impl
/// on the probe itself is found before the fallback on its reference.
struct Probe<T>(std::marker::PhantomData<T>);
trait CloneKind {
    fn is_clone(&self) -> bool {
        true
    }
}
impl<T: Clone> CloneKind for Probe<T> {}
trait PlainKind {
    fn is_clone(&self) -> bool {
        false
    }
}
impl<T> PlainKind for &Probe<T> {}

/// RED: `DeclaredNeed` derived `Clone` and every open cloned it whole. A declaration is shared, so
/// the type must not be `Clone` at all: a reintroduced per-open copy is caught here.
#[test]
fn declared_need_is_not_clone() {
    let cloneable = &Probe::<String>(std::marker::PhantomData);
    let plain = &Probe::<std::sync::Mutex<()>>(std::marker::PhantomData);
    assert!(
        cloneable.is_clone() && !plain.is_clone(),
        "control: the probe tells a Clone type from one that is not"
    );
    let probe = &Probe::<DeclaredNeed>(std::marker::PhantomData);
    assert!(
        !probe.is_clone(),
        "DeclaredNeed is shared as an Arc, never cloned"
    );
}

fn connector() -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Arc::default(),
    }])
    .unwrap();
    Connector::serving(
        view,
        crate::tests::loopback_literals(),
        None,
        Arc::new(|_, _| {}),
    )
}

/// Drive `id` until `listener` accepted its connection (an open dials when it is driven).
async fn reached(c: &Connector, id: ConnId, listener: tokio::net::TcpListener) {
    let accepted = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    let mut buf = [0_u8; 16];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !accepted.is_finished() {
            let _ = c.read(OWNER, id, 7, &mut buf);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the open reaches its declared target");
    accepted.await.unwrap().unwrap();
}

/// A re-declare during an open does not change that open's snapshot, and the next open uses the
/// new declaration. Green before and after W5: it guards the snapshot semantics.
#[test]
fn redeclare_during_open_keeps_snapshot() {
    worker().block_on(async {
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_at = first.local_addr().unwrap().to_string();
        let second_at = second.local_addr().unwrap().to_string();
        let c = connector();
        c.declare_need_to(OWNER, NeedId(0), "bytes", crate::DEFAULT_CLASS, &first_at)
            .expect("a served scheme declares");
        let open = || {
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "",
                    body: Bytes::from_static(b"x"),
                    ..OpenDesc::default()
                },
            )
            .expect("the declared target opens")
        };
        let id = open();
        reached(&c, id, first).await;

        let snapshot = c.over.lock().unwrap().get(&(OWNER, NeedId(0))).cloned();
        c.declare_need_to(OWNER, NeedId(0), "bytes", crate::DEFAULT_CLASS, &second_at)
            .expect("a served scheme re-declares");
        assert_eq!(
            snapshot.as_ref().and_then(|d| d.declared_target.as_deref()),
            Some(first_at.as_str()),
            "a snapshot taken before the re-declare keeps the old declaration"
        );
        assert_eq!(
            c.over
                .lock()
                .unwrap()
                .get(&(OWNER, NeedId(0)))
                .and_then(|d| d.declared_target.clone())
                .as_deref(),
            Some(second_at.as_str()),
            "the re-declare replaces the record"
        );
        drop(snapshot);

        let next = open();
        reached(&c, next, second).await;
        c.close(OWNER, id).unwrap();
        c.close(OWNER, next).unwrap();
    });
}
