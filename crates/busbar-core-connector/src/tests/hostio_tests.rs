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

/// A name lookup that wedges (`getaddrinfo` that never returns) answers `Err` within its bound: the
/// caller is let go and the wedged thread is never joined. RED before the bound: the lookup was
/// joined with none, and this call never returned. A lookup that answers in time is answered.
#[test]
fn a_wedged_name_lookup_fails_within_its_bound_and_an_answer_in_time_is_kept() {
    let bound = std::time::Duration::from_millis(300);
    let slack = std::time::Duration::from_secs(1);
    let (release, wedge) = std::sync::mpsc::channel::<()>();
    let began = std::time::Instant::now();
    let answer = within(bound, move || {
        // The planted wedge: blocks until the test lets it go, far past the bound.
        let _ = wedge.recv_timeout(std::time::Duration::from_secs(600));
        Ok(vec![IpAddr::from([127, 0, 0, 1])])
    });
    let took = began.elapsed();
    drop(release);
    let refused = answer.expect_err("a wedged lookup is a resolution failure");
    assert!(refused.contains("no answer within"), "{refused}");
    assert!(took >= bound, "waited its bound: {took:?}");
    assert!(took < bound + slack, "returned within its bound: {took:?}");

    let one = IpAddr::from([192, 0, 2, 7]);
    assert_eq!(within(bound, move || Ok(vec![one])), Ok(vec![one]));
    assert!(within(bound, || panic!("the lookup died")).is_err());
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
            env_refs: Vec::new(),
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

/// The spawn's resolver in this cell: an `env` reference reads its variable, nothing else resolves.
fn env_only(r: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
    r.env_var()
        .and_then(|v| std::env::var(v).ok())
        .ok_or_else(|| format!("{} does not resolve", r.describe()))
}

/// RED (SECURITY ruling 2026-10-07: a member's env resolves at the spawn): the carrier hands the
/// host's `io.spawn` the program's WRITTEN environment only; the admitted program's references
/// resolve inside the host's spawn, so the value exists in the child's environment and nowhere the
/// carrier reaches. A reference that does not resolve spawns nothing.
#[test]
fn a_programs_environment_reference_resolves_inside_the_hosts_spawn() {
    const VAR: &str = "BUSBAR_HOSTIO_SPAWN_SECRET";
    std::env::set_var(VAR, "hostio-spawn-value");
    let _ = crate::compose::install_spawn_secrets(env_only);
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program {
            command: "/usr/bin/env".into(),
            args: Vec::new(),
            env: vec![("DECLARED".to_owned(), "yes".to_owned())],
            env_refs: vec![(
                "WHOLE".to_owned(),
                busbar_contract::secret_ref::SecretRef::env(VAR),
            )],
        };
        io.admit(ticket(30), Admission::Spawn(program.clone()));
        let h = io
            .spawn(
                OWNER,
                ticket(30),
                &Spawn {
                    program: "/usr/bin/env",
                    args: &[],
                    env: &[("DECLARED", "yes")],
                },
            )
            .unwrap();
        let mut out = Vec::new();
        loop {
            let mut buf = [0_u8; 256];
            let n = poll_fn(|cx| io.read(OWNER, h, &mut buf, cx.waker()))
                .await
                .unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        let mut lines: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        assert_eq!(
            lines,
            vec![
                "DECLARED=yes".to_owned(),
                "WHOLE=hostio-spawn-value".to_owned()
            ]
        );
        io.close(OWNER, h).unwrap();

        // RED: a reference that does not resolve spawns nothing, and its refusal names the
        // reference, never a value.
        let unresolved = Program {
            env_refs: vec![(
                "MISSING".to_owned(),
                busbar_contract::secret_ref::SecretRef::env("BUSBAR_HOSTIO_SPAWN_UNSET_VAR"),
            )],
            ..program
        };
        io.admit(ticket(31), Admission::Spawn(unresolved));
        match io.spawn(
            OWNER,
            ticket(31),
            &Spawn {
                program: "/usr/bin/env",
                args: &[],
                env: &[("DECLARED", "yes")],
            },
        ) {
            Err(IoRefusal::Refused(why)) => {
                assert!(why.contains("MISSING"), "{why}");
                assert!(!why.contains("hostio-spawn-value"), "{why}");
            }
            other => panic!("an unresolved reference spawned: {other:?}"),
        }
        assert_eq!(io.held(), 0);
    });
}
