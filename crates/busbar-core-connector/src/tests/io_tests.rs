// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` on the worker's reactor: refused off a worker (no reactor thread to fall back on),

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

        assert!(matches!(
            reg.poll_io(Direction::Read, &mut cx, |mut s| s.read(&mut buf)),
            Poll::Pending
        ));
        let mut back = reg.deregister().unwrap();
        let _ = back.set_nonblocking(false);
        b.write_all(b"x").unwrap();
        let mut one = [0_u8; 1];
        back.read_exact(&mut one).unwrap();
        assert_eq!(&one, b"x", "the descriptor comes back whole");
    });
}

// ---- T8 (TRANSPORT-TLS §2.1): a short transfer clears readiness on edge-triggered selectors ----

use std::cell::Cell;
use std::time::Duration;

/// The T8 hang bound: a wake that never comes fails the test instead of hanging the job.
const HANG: Duration = Duration::from_secs(5);

/// Reads into `buf` through [`Registered::poll_io_sized`], counting every attempt of the op.
fn sized_read(
    reg: &Registered<TcpStream>,
    ops: &Cell<usize>,
    buf: &mut [u8],
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<usize>> {
    let want = buf.len();
    reg.poll_io_sized(Direction::Read, want, cx, |mut s| {
        ops.set(ops.get() + 1);
        s.read(buf)
    })
}

/// RED on dev: a 600 B response took two `read` ops (the data, then one `EAGAIN`). After T8 the
/// short read clears readiness, so the next poll is Pending without a syscall.
#[cfg(unix)]
#[test]
fn short_read_clears_readiness_one_read_op() {
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        b.write_all(&[7_u8; 600]).unwrap();
        let ops = Cell::new(0_usize);
        let mut buf = vec![0_u8; 16 * 1024];
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("the response is read")
        .unwrap();
        assert_eq!(n, 600);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(sized_read(&reg, &ops, &mut buf, &mut cx).is_pending());
        let expected = if SHORT_CLEARS { 1 } else { 2 };
        assert_eq!(
            ops.get(),
            expected,
            "a short read clears readiness: no EAGAIN read follows it"
        );
    });
}

#[cfg(unix)]
#[test]
fn short_read_then_more_data_wakes() {
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        b.write_all(b"first").unwrap();
        let ops = Cell::new(0_usize);
        let mut buf = vec![0_u8; 1024];
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("the first bytes are read")
        .unwrap();
        assert_eq!(&buf[..n], b"first");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            b.write_all(b"more").unwrap();
            b
        });
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("bytes after a short read wake the reader")
        .unwrap();
        assert_eq!(&buf[..n], b"more");
        drop(writer.join().unwrap());
    });
}

#[cfg(unix)]
#[test]
fn short_read_then_fin_is_seen() {
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        b.write_all(b"last").unwrap();
        let ops = Cell::new(0_usize);
        let mut buf = vec![0_u8; 1024];
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("the last bytes are read")
        .unwrap();
        assert_eq!(&buf[..n], b"last");
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            b.shutdown(std::net::Shutdown::Write).unwrap();
            b
        });
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("a FIN after a short read is seen")
        .unwrap();
        assert_eq!(n, 0, "end of stream");
        drop(closer.join().unwrap());
    });
}

#[cfg(unix)]
#[test]
fn short_write_then_drain_resumes() {
    const TOTAL: usize = 8 << 20;
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        let reader = std::thread::spawn(move || {
            let mut got = 0_usize;
            let mut chunk = vec![0_u8; 64 * 1024];
            std::thread::sleep(Duration::from_millis(50));
            while got < TOTAL {
                let n = b.read(&mut chunk).unwrap();
                assert!(n > 0, "the writer never closes early");
                got += n;
            }
            got
        });
        let payload = vec![9_u8; TOTAL];
        let mut sent = 0_usize;
        let mut short = false;
        while sent < TOTAL {
            let rest = &payload[sent..];
            let n = tokio::time::timeout(
                HANG,
                futures::future::poll_fn(|cx| {
                    reg.poll_io_sized(Direction::Write, rest.len(), cx, |mut s| s.write(rest))
                }),
            )
            .await
            .expect("a drained peer re-drives the writer")
            .unwrap();
            short |= n < rest.len();
            sent += n;
        }
        assert!(short, "8 MiB does not fit the socket buffers in one write");
        assert_eq!(reader.join().unwrap(), TOTAL);
    });
}

#[cfg(unix)]
#[test]
fn large_response_read_counts() {
    const TOTAL: usize = 110 * 1024;
    worker().block_on(async {
        let (a, mut b) = pair();
        socket2::SockRef::from(&a)
            .set_recv_buffer_size(1 << 20)
            .unwrap();
        socket2::SockRef::from(&b)
            .set_send_buffer_size(1 << 20)
            .unwrap();
        let reg = register(a).unwrap();
        let writer = std::thread::spawn(move || {
            b.write_all(&vec![5_u8; TOTAL]).unwrap();
            b
        });
        let b = writer.join().unwrap();
        let ops = Cell::new(0_usize);
        let mut buf = vec![0_u8; 16 * 1024];
        let mut got = 0_usize;
        while got < TOTAL {
            got += tokio::time::timeout(
                HANG,
                futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
            )
            .await
            .expect("the response is read")
            .unwrap();
        }
        assert_eq!(got, TOTAL);
        let data_ops = ops.get();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(sized_read(&reg, &ops, &mut buf, &mut cx).is_pending());
        assert!(
            ops.get() <= 8,
            "110 KiB in 16 KiB reads: at most 8 read ops"
        );
        if SHORT_CLEARS {
            assert_eq!(
                ops.get(),
                data_ops,
                "the drained socket makes no EAGAIN read"
            );
        }
        drop(b);
    });
}

/// The gate is tokio 1.53.3's own (`io/poll_evented.rs`): epoll and kqueue clear on a short
/// transfer; mio's poll(2) backend never does.
#[cfg(unix)]
#[test]
fn short_clears_matches_tokio_gate() {
    #[cfg(all(
        not(mio_unsupported_force_poll_poll),
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "freebsd"
        )
    ))]
    const {
        assert!(
            SHORT_CLEARS,
            "epoll/kqueue: a short transfer clears readiness"
        );
    }
    #[cfg(any(
        mio_unsupported_force_poll_poll,
        target_os = "aix",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "nto"
    ))]
    const {
        assert!(!SHORT_CLEARS, "poll(2): only WouldBlock clears readiness")
    };
}

/// IOCP is level-triggered: the sized form is exactly `poll_io`, a short read proves nothing.
#[cfg(windows)]
#[test]
fn poll_io_sized_delegates() {
    worker().block_on(async {
        let (a, mut b) = pair();
        let reg = register(a).unwrap();
        b.write_all(&[7_u8; 600]).unwrap();
        let ops = Cell::new(0_usize);
        let mut buf = vec![0_u8; 16 * 1024];
        let n = tokio::time::timeout(
            HANG,
            futures::future::poll_fn(|cx| sized_read(&reg, &ops, &mut buf, cx)),
        )
        .await
        .expect("the response is read")
        .unwrap();
        assert_eq!(n, 600);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(sized_read(&reg, &ops, &mut buf, &mut cx).is_pending());
        assert_eq!(ops.get(), 2, "Windows keeps today's WouldBlock-only clear");
    });
}
