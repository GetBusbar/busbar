// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's I/O (`io.*`): it reaches only what was admitted for the op that asks, a handle is its
//! maker's alone, and the bytes move both ways over a real socket and a real program.

use std::future::poll_fn;
use std::task::Poll;

use busbar_contract::abi::host::io::{DIR_READ, DIR_WRITE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::Program;
use busbar_contract::io_host::{IoHost, IoRefusal, Spawn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const OWNER: u64 = 1;

fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: 0x00ff_0000 + n,
        generation: 1,
    }
}

fn worker() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn nothing_is_opened_bound_or_spawned_that_was_not_admitted() {
    worker().block_on(async {
        let io = HostIo::new();
        // RED: no admission at all.
        assert!(matches!(
            io.open(OWNER, ticket(1), "127.0.0.1:9"),
            Err(IoRefusal::Refused(_))
        ));
        // RED: another address than the one admitted.
        io.admit(ticket(1), Admission::Dial(vec!["127.0.0.1:8".into()]));
        assert!(matches!(
            io.open(OWNER, ticket(1), "127.0.0.1:9"),
            Err(IoRefusal::Refused(_))
        ));
        io.admit(ticket(2), Admission::Bind("127.0.0.1:0".into()));
        assert!(matches!(
            io.listen(OWNER, ticket(3), "127.0.0.1:0"),
            Err(IoRefusal::Refused(_))
        ));
        let spawn = Spawn {
            program: "/bin/cat",
            args: &[],
            env: &[],
        };
        assert!(matches!(
            io.spawn(OWNER, ticket(4), &spawn),
            Err(IoRefusal::Refused(_))
        ));
        assert_eq!(io.held(), 0);
    });
}

#[test]
fn an_admitted_dial_moves_bytes_both_ways_and_a_handle_is_its_makers_alone() {
    worker().block_on(async {
        let far = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = far.local_addr().unwrap().to_string();
        let io = HostIo::new();
        io.admit(ticket(10), Admission::Dial(vec![at.clone()]));
        let h = io.open(OWNER, ticket(10), &at).unwrap();
        assert_eq!(io.settle(ticket(10)).0, Some(h));
        let (mut peer, _) = far.accept().await.unwrap();
        poll_fn(|cx| io.ready(OWNER, h, DIR_WRITE, cx.waker()))
            .await
            .unwrap();
        let n = poll_fn(|cx| io.write(OWNER, h, b"ping", cx.waker()))
            .await
            .unwrap();
        assert_eq!(n, 4);
        let mut got = [0_u8; 4];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        peer.write_all(b"pong").await.unwrap();
        poll_fn(|cx| io.ready(OWNER, h, DIR_READ, cx.waker()))
            .await
            .unwrap();
        let mut buf = [0_u8; 16];
        let n = poll_fn(|cx| io.read(OWNER, h, &mut buf, cx.waker()))
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
        let (_, peer_at) = io.ends(OWNER, h).unwrap();
        assert_eq!(peer_at, at);
        // RED: another owner reaches nothing of it.
        assert!(io.close(OWNER + 1, h).is_err());
        let mut buf = [0_u8; 1];
        let waker = std::task::Waker::noop();
        assert!(matches!(
            io.read(OWNER + 1, h, &mut buf, waker),
            Poll::Ready(Err(_))
        ));
        io.close(OWNER, h).unwrap();
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    });
}

#[test]
fn an_admitted_program_is_spawned_bare_and_killed_with_its_handle() {
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program {
            command: "/bin/cat".into(),
            args: Vec::new(),
            env: Vec::new(),
        };
        io.admit(ticket(20), Admission::Spawn(program));
        let h = io
            .spawn(
                OWNER,
                ticket(20),
                &Spawn {
                    program: "/bin/cat",
                    args: &[],
                    env: &[],
                },
            )
            .unwrap();
        assert!(io.program_id(h).is_some());
        poll_fn(|cx| io.write(OWNER, h, b"line\n", cx.waker()))
            .await
            .unwrap();
        let mut buf = [0_u8; 16];
        let n = poll_fn(|cx| io.read(OWNER, h, &mut buf, cx.waker()))
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"line\n");
        assert!(!io.program_exited(h));
        io.close(OWNER, h).unwrap();
        assert_eq!(io.held(), 0);
    });
}
