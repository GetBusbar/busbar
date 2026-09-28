// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` on the worker's reactor: refused off a worker (no reactor thread to fall back on),
//! not-ready then ready on a real socket, a cleared readiness waits for a fresh edge, and a
//! deregistered descriptor comes back whole.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::task::{Context, Poll};

use super::*;
use crate::support::worker;

fn pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    a.set_nonblocking(true).unwrap();
    (a, b)
}

/// RED: off a worker there is no reactor, and none is started to hide behind.
#[test]
fn register_off_a_worker_is_refused() {
    let (a, _b) = pair();
    let e = register(a).expect_err("no worker, no registration");
    assert_eq!(e.to_string(), NOT_ON_A_WORKER);
}

#[test]
fn a_read_is_not_ready_until_the_far_end_writes() {
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut buf = [0_u8; 8];
        assert!(reg
            .poll_io(Direction::Read, &mut cx, |mut s| s.read(&mut buf))
            .is_pending());
        b.write_all(b"ready").unwrap();
        let n = futures::future::poll_fn(|cx| {
            reg.poll_io(Direction::Read, cx, |mut s| s.read(&mut buf))
        })
        .await
        .unwrap();
        assert_eq!(&buf[..n], b"ready");
        // Drained: the next attempt answers WouldBlock, clears the readiness and waits again.
        assert!(matches!(
            reg.poll_io(Direction::Read, &mut cx, |mut s| s.read(&mut buf)),
            Poll::Pending
        ));
        let mut back = reg.deregister();
        let _ = back.set_nonblocking(false);
        b.write_all(b"x").unwrap();
        let mut one = [0_u8; 1];
        back.read_exact(&mut one).unwrap();
        assert_eq!(&one, b"x", "the descriptor comes back whole");
    });
}
