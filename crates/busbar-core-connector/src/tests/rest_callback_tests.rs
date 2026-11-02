// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::callback_waker::Probe;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

#[test]
fn a_public_read_of_busy_rest_clones_and_retires_its_waiter_after_unlocking() {
    worker().block_on(async {
        let owner = InstanceId(1);
        let need = NeedId(1);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = Connector::serving(
            Transports::new(vec![Entry {
                door: Arc::new(TestDoor::identity("bytes")),
                alpn: Vec::new(),
            }])
            .unwrap(),
            crate::tests::loopback_literals(),
            None,
            Arc::new(|_, _| {}),
        );
        c.declare_over(owner, need, "bytes").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let id = c
            .open(
                owner,
                need,
                &OpenDesc {
                    target: &target,
                    ..Default::default()
                },
            )
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let held = c.slab.get(owner, id).unwrap().1;
        let (line, stream) = held.line().unwrap();
        futures::future::poll_fn(|cx| line.poll_landed(stream, cx))
            .await
            .unwrap();
        held.landed();

        let (reading, _) = Reading::begin(&held.rest, Waker::noop()).unwrap();
        let weak = Arc::downgrade(&held);
        let probe = Probe::new(move || {
            weak.upgrade()
                .is_some_and(|held| held.rest.try_lock().is_err())
        });
        let waker = probe.waker();
        assert!(c
            .poll_read(owner, id, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        assert!(c
            .poll_read(owner, id, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        drop(reading);
        assert!(probe.clones.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            probe.wakes.load(Ordering::SeqCst),
            1,
            "duplicate polls retain one waiter"
        );
        assert!(probe.drops.load(Ordering::SeqCst) > 0);
        probe.assert_unlocked();
        c.close(owner, id).unwrap();
    });
}
