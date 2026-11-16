// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ZEROIZE (ABI-MIN3-INTERFACE §14): After a chain that wrote a secret, a FETCH header and a WRITE, the pooled
//! buffers read back all zero.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-H1: the fixture image (W1-A3's) resolves one SECRET through the driver, so its pooled buffers held the
//! secret value (the NEED_RES), the NEED records and the answer. The pool's invariant is that every block it
//! holds is all zero; the arm draws more blocks than the chain used and reads each one whole.

use core::future::Future;
use core::pin::{pin, Pin};
use core::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host::{CallStack, Caller, Driver, First, InstanceLimits, Pool, PooledOut};
use busbar_plugin_abi::records::tag;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_test::FakeNeeds;

use crate::bridge_fixture as fx;

fn caller() -> Caller<'static> {
    Caller {
        plugin: "bridge-fixture",
        kind: KindCode::Secret,
        name: "fixture",
        instance: 1,
        slot: 1,
        chain: 0,
        deadline: Instant::now() + Duration::from_secs(60),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

fn first<'i>(started: fx::Started<'i, fx::Secret>) -> First<'i, fx::Secret> {
    started.into()
}

#[test]
fn chain_buffers_read_back_zero() {
    const SECRET: &[u8] = b"pg-password-7f3a9c";
    let instance = fx::instance();
    let mut needs = FakeNeeds::new();
    needs.secret("/store/password", SECRET);
    {
        let mut drv = Driver::new(&needs, caller());
        let req = Pool::global().acquire(1 << 20);
        let mut fut = pin!(drv.run(0, 1 << 20, req, |_, lease| first(fx::start(
            &instance, b"secret", lease
        ))));
        let Poll::Ready(Ok(done)) = poll_once(fut.as_mut()) else {
            panic!("the secret chain did not finish");
        };
        let answer = done.answer.answer();
        let text = answer
            .records()
            .map(|rec| rec.expect("framed"))
            .find(|rec| rec.tag == tag::TEXT)
            .map(|rec| rec.body.to_vec());
        assert_eq!(
            text.as_deref(),
            Some(SECRET),
            "the secret came back through NEED_RES"
        );
    }
    assert_eq!(
        needs.released(),
        1,
        "the chain made a NEED: released exactly once"
    );
    let drawn: Vec<PooledOut> = (0..64).map(|_| Pool::global().acquire(1 << 20)).collect();
    for buf in &drawn {
        assert!(buf.bytes().is_empty());
        assert!(
            buf.whole().iter().all(|&b| b == 0),
            "a pooled block held a byte after its release"
        );
        assert!(
            !buf.whole().windows(SECRET.len()).any(|w| w == SECRET),
            "the secret is in a pooled block"
        );
    }
}
