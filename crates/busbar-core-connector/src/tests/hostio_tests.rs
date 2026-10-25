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

use crate::support::worker;

use super::*;

const OWNER: u64 = 1;

fn ticket(n: u32) -> Ticket {
    Ticket {
        slot: 0x00ff_0000 + n,
        generation: 1,
    }
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
        io.admit(
            ticket(20),
            Admission::Spawn(program, crate::spawn_env::HeldEnv::written_only()),
        );
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

/// The config-time proof the cells' declarations hold.
fn scope() -> busbar_contract::config_time::ConfigScope {
    busbar_contract::config_time::ConfigScope::config_time()
}

/// Spawn the admitted `/usr/bin/env` on `t` and read its whole output, sorted.
async fn env_lines(io: &HostIo, t: u32) -> Result<Vec<String>, IoRefusal> {
    let h = io.spawn(
        OWNER,
        ticket(t),
        &Spawn {
            program: "/usr/bin/env",
            args: &[],
            env: &[("DECLARED", "yes")],
        },
    )?;
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
    io.close(OWNER, h).unwrap();
    let mut lines: Vec<String> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    Ok(lines)
}

/// THE HELD ENVIRONMENT (ARCHITECT ruling 2026-10-13, row 166): the carrier hands the host's
/// `io.spawn` the program's WRITTEN environment only; the admitted program's references were
/// resolved at config time and are held, so the value exists in the host's records and the child's
/// environment and nowhere the carrier reaches. A reference that did not resolve spawns nothing.
#[test]
fn a_programs_environment_reference_is_held_for_the_hosts_spawn() {
    const VAR: &str = "BUSBAR_HOSTIO_SPAWN_SECRET";
    std::env::set_var(VAR, "hostio-spawn-value");
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
        let held = crate::spawn_env::HeldEnv::load(
            &program.env_refs,
            Some(crate::spawn_env::counting_env),
            &scope(),
        );
        assert!(
            !format!("{held:?}").contains("hostio-spawn-value"),
            "a held environment names no value"
        );
        io.admit(ticket(30), Admission::Spawn(program.clone(), held));
        assert_eq!(
            env_lines(&io, 30).await.unwrap(),
            vec![
                "DECLARED=yes".to_owned(),
                "WHOLE=hostio-spawn-value".to_owned()
            ]
        );

        // RED: a reference that does not resolve spawns nothing, and its refusal names the
        // reference, never a value.
        let unresolved = Program {
            env_refs: vec![(
                "MISSING".to_owned(),
                busbar_contract::secret_ref::SecretRef::env("BUSBAR_HOSTIO_SPAWN_UNSET_VAR"),
            )],
            ..program
        };
        let held = crate::spawn_env::HeldEnv::load(
            &unresolved.env_refs,
            Some(crate::spawn_env::counting_env),
            &scope(),
        );
        io.admit(ticket(31), Admission::Spawn(unresolved, held));
        match env_lines(&io, 31).await {
            Err(IoRefusal::Refused(why)) => {
                assert!(why.contains("MISSING"), "{why}");
                assert!(!why.contains("hostio-spawn-value"), "{why}");
            }
            other => panic!("an unresolved reference spawned: {other:?}"),
        }
        assert_eq!(io.held(), 0);
    });
}

/// RED (ARCHITECT ruling 2026-10-13, row 166): A SPAWN RESOLVES NOTHING. A spawn serves a request
/// (a member's first lease, a respawn, a program need's every open), so the program's references
/// resolve ONCE, at the load, and every spawn after it loads what is held: two spawns, still one
/// resolution. RED before: `io.spawn` resolved every reference at every spawn.
///
/// And A ROTATED SECRET REACHES THE FIRST NEW CHILD AFTER THE NEXT REFRESH: the variable changed,
/// the next spawn still hands the value the load resolved; after the refresher's pass the next
/// spawn hands the new one. A reference gone at a refresh refuses every spawn after it.
#[test]
fn a_spawn_resolves_nothing_and_a_rotation_reaches_the_first_child_after_the_refresh() {
    const VAR: &str = "BUSBAR_HOSTIO_SPAWN_ROTATED";
    std::env::set_var(VAR, "before-rotation");
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program {
            command: "/usr/bin/env".into(),
            args: Vec::new(),
            env: vec![("DECLARED".to_owned(), "yes".to_owned())],
            env_refs: vec![(
                "ROTATED".to_owned(),
                busbar_contract::secret_ref::SecretRef::env(VAR),
            )],
        };
        let held = crate::spawn_env::HeldEnv::load(
            &program.env_refs,
            Some(crate::spawn_env::counting_env),
            &scope(),
        );
        let loaded = crate::spawn_env::resolutions_of(VAR);
        assert!(loaded >= 1, "the load resolved the reference");
        let want = |v: &str| vec!["DECLARED=yes".to_owned(), format!("ROTATED={v}")];
        for t in [40, 41] {
            io.admit(ticket(t), Admission::Spawn(program.clone(), held.clone()));
            assert_eq!(env_lines(&io, t).await.unwrap(), want("before-rotation"));
        }
        assert_eq!(
            crate::spawn_env::resolutions_of(VAR),
            loaded,
            "a spawn resolved a reference"
        );

        std::env::set_var(VAR, "after-rotation");
        io.admit(ticket(42), Admission::Spawn(program.clone(), held.clone()));
        assert_eq!(
            env_lines(&io, 42).await.unwrap(),
            want("before-rotation"),
            "a rotation reaches no child before the refresh"
        );
        crate::spawn_env::refresh_all();
        io.admit(ticket(43), Admission::Spawn(program.clone(), held.clone()));
        assert_eq!(env_lines(&io, 43).await.unwrap(), want("after-rotation"));

        std::env::remove_var(VAR);
        crate::spawn_env::refresh_all();
        io.admit(ticket(44), Admission::Spawn(program, held));
        match env_lines(&io, 44).await {
            Err(IoRefusal::Refused(why)) => {
                assert!(why.contains("ROTATED"), "{why}");
                assert!(!why.contains("rotation"), "{why}");
            }
            other => panic!("a reference gone at the refresh spawned: {other:?}"),
        }
        assert_eq!(io.held(), 0);
    });
}
