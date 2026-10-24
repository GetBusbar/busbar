// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY PENDING IS WOKEN, OFF A TASK TOO: a socket registered by a thread that merely ENTERED a
//! runtime it does not drive (a dispatcher worker inside the control runtime's context, while the
//! control thread waits synchronously on that worker's op) goes on the process's one reactor the
//! root installed, so its readiness wakes the caller. Registered on the entered runtime instead,
//! its waker never fires while that runtime's own thread is blocked: the boot's `ready` of an auth
//! plugin fetching its key set over the host connector waited out its deadline that way.
//!
//! Its own test binary: the process reactor is one per process, set once.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake};
use std::time::Duration;

use busbar_core_connector::io::{install_process_reactor, register, Direction};

/// A waker that reports each wake on a channel.
struct Signal(mpsc::Sender<()>);

impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        let _ = self.0.send(());
    }
}

/// A runtime driven by a thread of its own for the life of the process: the root's connector
/// I/O thread.
fn driven_reactor() -> tokio::runtime::Handle {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let handle = rt.handle().clone();
    std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));
    handle
}

#[test]
fn a_socket_registered_off_a_task_inside_an_undriven_runtime_is_woken_by_the_process_reactor() {
    install_process_reactor(driven_reactor());
    // The control runtime: entered by the worker below, never driven while the test waits (its
    // thread is the one blocked on the worker's op).
    let control = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (mut b, _) = l.accept().unwrap();
    a.set_nonblocking(true).unwrap();

    let (woke, wakes) = mpsc::channel();
    let entered = control.handle().clone();
    let worker = std::thread::spawn(move || {
        let _inside = entered.enter();
        let reg = register(a).expect("registered");
        let waker = Arc::new(Signal(woke)).into();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0_u8; 8];
        assert!(
            reg.poll_io(Direction::Read, &mut cx, |mut s| s.read(&mut buf))
                .is_pending(),
            "nothing written yet"
        );
        reg
    });
    let reg = worker.join().unwrap();
    b.write_all(b"ready").unwrap();
    assert!(
        wakes.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the pending read was never woken: its socket sits on a reactor nobody drives"
    );
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut buf = [0_u8; 8];
    match reg.poll_io(Direction::Read, &mut cx, |mut s| s.read(&mut buf)) {
        Poll::Ready(Ok(n)) => assert_eq!(&buf[..n], b"ready"),
        other => panic!("the woken read did not read: {other:?}"),
    }
    drop(control);
}
