// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio CARRIER's own battery: what the carrier promises, driven through the contract's
//! `Carrier` trait exactly as the host drives it — a dialled program's pipes carry bytes both ways
//! exactly, the program is started with exactly the argument vector and environment the destination
//! declared and nothing inherited, a relative path and an address are refused before anything is
//! spawned, the process's own standard input and output are handed out once, and closing a connection ends it.

use std::task::Context;

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierPoll, Dest};

use crate::StdioCarrier;

/// Poll one carrier method to its answer, on the calling task.
async fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    std::future::poll_fn(|cx| method(cx)).await
}

async fn write_all(c: &StdioCarrier, conn: u64, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|cx| c.poll_write(conn, cx, &bytes[at..]))
            .await
            .expect("write");
    }
    wait(|cx| c.poll_flush(conn, cx)).await.expect("flush");
}

async fn read_exact(c: &StdioCarrier, conn: u64, n: usize) -> Vec<u8> {
    let mut all = Vec::with_capacity(n);
    let mut buf = vec![0_u8; 1024];
    while all.len() < n {
        let got = wait(|cx| c.poll_read(conn, cx, &mut buf))
            .await
            .expect("read");
        assert!(got > 0, "the pipe ended after {} of {n} bytes", all.len());
        all.extend_from_slice(&buf[..got]);
    }
    all
}

async fn read_to_end(c: &StdioCarrier, conn: u64) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; 1024];
    loop {
        match wait(|cx| c.poll_read(conn, cx, &mut buf)).await {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read failed: {e:?}"),
        }
    }
}

fn payload(len: usize) -> Vec<u8> {
    // Every byte value, newlines and carriage returns included: a carrier frames nothing.
    (0..len).map(|i| (i as u8).wrapping_mul(37)).collect()
}

/// A dialled program's pipes carry bytes both ways EXACTLY — every byte value, the delimiter a line
/// framing would have split on included — in however many reads the pipe hands them over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialled_programs_pipes_carry_every_byte_exactly() {
    let c = StdioCarrier::new();
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/cat",
            args: &[],
            env: &[],
        })
        .expect("spawn");
    let sent = payload(100_000);
    let ((), r) = tokio::join!(write_all(&c, conn, &sent), read_exact(&c, conn, sent.len()));
    assert_eq!(r, sent);
    assert_eq!(
        c.arrival(conn).map(|f| (f.peer, f.local_port)),
        Some(("/bin/cat".to_string(), 0))
    );
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
    assert_eq!(
        wait(|cx| c.poll_write(conn, cx, b"x")).await,
        Err(TransportError::Closed),
        "a closed connection takes no bytes"
    );
    assert_eq!(c.arrival(conn), None);
}

/// The program starts with EXACTLY the declared argument vector and environment: the environment is
/// cleared first, so the child sees the declared variable and nothing the node itself carries.
#[tokio::test]
async fn the_child_sees_its_declared_argv_and_env_and_nothing_else() {
    std::env::set_var("BUSBAR_STDIO_CARRIER_INHERITED", "leak");
    let c = StdioCarrier::new();
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sh",
            args: &[
                "-c",
                "printf '%s|%s|%s' \"$0\" \"$DECLARED\" \"$BUSBAR_STDIO_CARRIER_INHERITED\"",
                "first-arg",
            ],
            env: &[("DECLARED", "yes")],
        })
        .expect("spawn");
    assert_eq!(read_to_end(&c, conn).await, b"first-arg|yes|");
    let conn = c
        .dial(&Dest::Program {
            program: "/usr/bin/env",
            args: &[],
            env: &[],
        })
        .expect("spawn");
    assert_eq!(
        read_to_end(&c, conn).await,
        b"",
        "an empty declaration is an empty environment"
    );
}

/// A bare program name is refused — it would be resolved through a search path nobody declared —
/// and so is an address: a pipe reaches a program, never a place. Neither spawns anything.
#[tokio::test]
async fn a_relative_program_and_an_address_are_refused_before_anything_spawns() {
    let c = StdioCarrier::new();
    assert_eq!(
        c.dial(&Dest::Program {
            program: "cat",
            args: &[],
            env: &[],
        }),
        Err(TransportError::AddressRefused)
    );
    assert_eq!(
        c.dial(&Dest::Authority("127.0.0.1:1")),
        Err(TransportError::AddressRefused)
    );
    assert!(c.conns.lock().unwrap().is_empty());
}

/// The process has exactly one stdin and one stdout: the one listener hands them out once, and
/// `Closed` after — never a second connection over the same pipes.
#[tokio::test]
async fn the_processs_own_stdin_and_stdout_are_handed_out_once() {
    let c = StdioCarrier::new();
    let (listener, addr) = c.listen("ignored").unwrap();
    assert_eq!(addr, crate::carrier::OWN_PROCESS);
    let (conn, peer) = wait(|cx| c.poll_accept(listener, cx)).await.unwrap();
    assert_eq!(peer, crate::carrier::OWN_PROCESS);
    assert_eq!(
        wait(|cx| c.poll_accept(listener, cx)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_accept(listener + 1, cx)).await,
        Err(TransportError::Closed)
    );
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
}

/// An unknown connection is closed on every method, and closing is idempotent.
#[tokio::test]
async fn an_unknown_connection_is_closed_and_close_is_idempotent() {
    let c = StdioCarrier::new();
    let mut buf = [0_u8; 4];
    assert_eq!(
        wait(|cx| c.poll_read(99, cx, &mut buf)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_write(99, cx, b"x")).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_flush(99, cx)).await,
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| c.poll_close(99, cx, CloseReason::Normal)).await,
        Ok(())
    );
    assert_eq!(c.arrival(99), None);
}

/// Closing a connection kills the child it owns: a child that would otherwise outlive the session
/// (here, one that sleeps) is gone, and a read parked on its pipe wakes to see the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_a_connection_kills_its_child_and_wakes_a_parked_read() {
    let c = std::sync::Arc::new(StdioCarrier::new());
    let conn = c
        .dial(&Dest::Program {
            program: "/bin/sleep",
            args: &["30"],
            env: &[],
        })
        .expect("spawn");
    let reader = {
        let c = std::sync::Arc::clone(&c);
        tokio::spawn(async move {
            let mut buf = [0_u8; 8];
            wait(|cx| c.poll_read(conn, cx, &mut buf)).await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal))
        .await
        .unwrap();
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
        .await
        .expect("the parked read wakes")
        .unwrap();
    assert!(
        matches!(parked, Ok(0) | Err(TransportError::Closed)),
        "{parked:?}"
    );
}
