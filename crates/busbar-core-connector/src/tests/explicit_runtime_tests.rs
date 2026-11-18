// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit runtime ownership survives polling outside that runtime and in a foreign runtime.

use std::future::{pending, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::Program;
use busbar_contract::io_host::{IoHost, Spawn};
use tokio::runtime::{Builder, Runtime};

use crate::hostio::{Admission, HostIo};
use crate::io::{register_on, timeout_on, Direction};

const BOUND: Duration = Duration::from_secs(10);
const OWNER: u64 = 395;

fn configured() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap()
}

fn foreign() -> Runtime {
    // Deliberately no I/O or timer driver: accidentally choosing this runtime must fail.
    Builder::new_current_thread().build().unwrap()
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

#[test]
fn explicit_deadlines_expire_without_an_ambient_driver() {
    let runtime = configured();
    assert!(tokio::runtime::Handle::try_current().is_err());
    let deadline = timeout_on(runtime.handle(), Duration::from_millis(10), pending::<()>());
    assert!(futures::executor::block_on(deadline).is_err());
    let foreign = foreign();
    foreign.block_on(async {
        let deadline = timeout_on(runtime.handle(), Duration::from_millis(10), pending::<()>());
        assert!(deadline.await.is_err());
    });
}

#[test]
fn explicit_registration_wakes_a_foreign_runtime_after_a_pending_read() {
    let runtime = configured();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let foreign = foreign();
    let registered = {
        let _foreign = foreign.enter();
        register_on(runtime.handle(), stream).unwrap()
    };
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let peer = scope.spawn(move || {
            receive.recv_timeout(BOUND).unwrap();
            peer.write_all(b"x").unwrap();
        });
        let mut send = Some(send);
        let mut bytes = [0; 1];
        let read = poll_fn(|cx| {
            let result =
                registered.poll_io(Direction::Read, cx, |mut socket| socket.read(&mut bytes));
            if result.is_pending() {
                if let Some(send) = send.take() {
                    send.send(()).unwrap();
                }
            }
            result
        });
        assert_eq!(
            foreign
                .block_on(timeout_on(runtime.handle(), BOUND, read))
                .unwrap()
                .unwrap(),
            1
        );
        assert!(
            send.is_none(),
            "the real read must have suspended before the peer wrote"
        );
        assert_eq!(bytes, *b"x");
        peer.join().unwrap();
    });
}

#[test]
fn retained_host_io_listens_and_registers_accepted_sockets_on_its_runtime() {
    let runtime = configured();
    let host = Arc::new(HostIo::new_on(runtime.handle().clone()));
    let retained = Arc::clone(&host);
    drop(host);
    retained.admit(ticket(1), Admission::Bind("127.0.0.1:0".into()));
    let (listener, address) = retained.listen(OWNER, ticket(1), "127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(address.as_str()).unwrap();
    let foreign = foreign();
    foreign.block_on(async {
        let accept = poll_fn(|cx| retained.accept(OWNER, ticket(2), listener, cx.waker()));
        let (stream, _) = timeout_on(runtime.handle(), BOUND, accept)
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 1];
        let cx = Context::from_waker(Waker::noop());
        assert!(retained
            .read(OWNER, stream, &mut bytes, cx.waker())
            .is_pending());
        peer.write_all(b"y").unwrap();
        let read = poll_fn(|cx| retained.read(OWNER, stream, &mut bytes, cx.waker()));
        assert_eq!(
            timeout_on(runtime.handle(), BOUND, read)
                .await
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(bytes, *b"y");
        retained.close(OWNER, stream).unwrap();
    });
    retained.retire_listener(listener);
    assert_eq!(retained.held(), 0);
}

#[test]
fn explicit_host_open_has_a_real_pending_deadline_on_a_foreign_runtime() {
    let runtime = configured();
    let host = HostIo::new_on(runtime.handle().clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    host.admit(ticket(3), Admission::Dial(address.clone()));
    let stream = host.open(OWNER, ticket(3), &address).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let mut bytes = [0; 1];
    let mut pending_observed = false;
    let read = poll_fn(|cx| {
        let result = host.read(OWNER, stream, &mut bytes, cx.waker());
        pending_observed |= result.is_pending();
        result
    });
    let result = foreign().block_on(timeout_on(
        runtime.handle(),
        Duration::from_millis(20),
        read,
    ));
    assert!(result.is_err());
    assert!(pending_observed);
    host.close(OWNER, stream).unwrap();
    assert_eq!(host.held(), 0);
}

#[cfg(unix)]
fn echo_program() -> Program {
    // The program `{"command": "/bin/cat"}` settings read to, written directly: this file names no
    // serde_json (no-serde-json ratchet, ci/serde-json-w3.allow).
    Program {
        command: "/bin/cat".into(),
        cwd: None,
        args: Vec::new(),
        env: Vec::new(),
        env_refs: Vec::new(),
    }
}

#[cfg(windows)]
fn echo_program() -> Program {
    let system_root = std::env::var("SystemRoot").unwrap();
    Program {
        command: std::path::Path::new(&system_root)
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
            .to_string_lossy()
            .into_owned(),
        args: vec!["-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-Command".into(),
            "$b=[Console]::OpenStandardInput().ReadByte();[Console]::OpenStandardOutput().WriteByte([byte]$b)".into()],
        env: [("SystemRoot".into(), system_root)].into_iter().collect(),
        cwd: None,
        env_refs: Vec::new(),
    }
}

#[test]
fn explicit_host_process_and_pipes_work_off_runtime_and_on_a_foreign_runtime() {
    let runtime = configured();
    let host = HostIo::new_on(runtime.handle().clone());
    let program = echo_program();
    host.admit(
        ticket(4),
        Admission::Spawn(program.clone(), crate::spawn_env::HeldEnv::written_only()),
    );
    let args: Vec<_> = program.args.iter().map(String::as_str).collect();
    let env: Vec<_> = program
        .env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    assert!(tokio::runtime::Handle::try_current().is_err());
    let child = host
        .spawn(
            OWNER,
            ticket(4),
            &Spawn {
                program: &program.command,
                args: &args,
                env: &env,
            },
        )
        .unwrap();
    let mut bytes = [0; 1];
    assert!(matches!(
        host.read(OWNER, child, &mut bytes, Waker::noop()),
        Poll::Pending
    ));
    foreign().block_on(async {
        let write = poll_fn(|cx| host.write(OWNER, child, b"z", cx.waker()));
        assert_eq!(
            timeout_on(runtime.handle(), BOUND, write)
                .await
                .unwrap()
                .unwrap(),
            1
        );
        let read = poll_fn(|cx| host.read(OWNER, child, &mut bytes, cx.waker()));
        assert_eq!(
            timeout_on(runtime.handle(), BOUND, read)
                .await
                .unwrap()
                .unwrap(),
            1
        );
    });
    assert_eq!(bytes, *b"z");
    host.close(OWNER, child).unwrap();
    assert_eq!(host.held(), 0);
}
