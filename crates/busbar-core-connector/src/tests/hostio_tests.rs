// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's I/O (`io.*`): it reaches only what was admitted for the op that asks, a handle is its

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

#[test]
fn a_manually_constructed_program_cannot_bypass_the_working_directory_guard() {
    worker().block_on(async {
        let io = HostIo::new();
        for directory in ["relative", "", " /tmp", "/tmp ", "/tmp\0invalid"] {
            let mut program =
                Program::from_settings(&serde_json::json!({"command": "/bin/cat"})).unwrap();
            program.cwd = Some(directory.to_owned());
            io.admit_for(
                ticket(94),
                Admission::Spawn(program, crate::spawn_env::HeldEnv::written_only()),
                Some(OWNER),
            );
            assert!(
                matches!(
                    io.spawn(
                        OWNER,
                        ticket(94),
                        &Spawn {
                            program: "/bin/cat",
                            args: &[],
                            env: &[]
                        }
                    ),
                    Err(IoRefusal::Refused(_))
                ),
                "a direct host Program bypassed cwd validation: {directory:?}"
            );
            assert_eq!(io.settle(ticket(94)).0, None);
            assert_eq!(io.held(), 0);
        }
    });
}

#[test]
fn replacing_a_ticket_grant_does_not_lend_the_new_suppliers_program_to_the_old_owner() {
    worker().block_on(async {
        let io = HostIo::new();
        let old = Program::from_settings(&serde_json::json!({"command": "/bin/cat"})).unwrap();
        let new = Program::from_settings(&serde_json::json!({"command": "/bin/cat", "cwd": "/", "env": {"PRIVATE": "replacement-value"}})).unwrap();
        let held = crate::spawn_env::HeldEnv::written_only();
        io.admit_for(ticket(93), Admission::Spawn(old, held.clone()), Some(OWNER));
        let old_handle = io.spawn(OWNER, ticket(93), &Spawn { program: "/bin/cat", args: &[], env: &[] }).unwrap();
        io.admit_for(ticket(93), Admission::Spawn(new, held), Some(OWNER + 1));
        let request = Spawn { program: "/bin/cat", args: &[], env: &[("PRIVATE", "replacement-value")] };
        assert!(matches!(io.spawn(OWNER, ticket(93), &request), Err(IoRefusal::Refused(_))));
        assert_eq!(io.held(), 1, "the old supplier spawned the replacement recipe");
        let new_handle = io.spawn(OWNER + 1, ticket(93), &request).unwrap();
        assert_ne!(new_handle, old_handle);
        assert_eq!(io.settle(ticket(93)), (Some(new_handle), None));
        assert!(io.program_receipt(OWNER + 1, new_handle));
        assert!(!io.program_receipt(OWNER, new_handle));
        io.close(OWNER, old_handle).unwrap();
        io.close(OWNER + 1, new_handle).unwrap();
        assert_eq!(io.held(), 0);
    });
}

#[test]
fn an_omitted_program_directory_inherits_and_a_missing_directory_spawns_nothing() {
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program::from_settings(&serde_json::json!({"command": "/bin/pwd"})).unwrap();
        io.admit_for(
            ticket(91),
            Admission::Spawn(program.clone(), crate::spawn_env::HeldEnv::written_only()),
            Some(OWNER),
        );
        for wrong in [
            Spawn {
                program: "/bin/pwd",
                args: &["unexpected"],
                env: &[],
            },
            Spawn {
                program: "/bin/pwd",
                args: &[],
                env: &[("UNDECLARED", "value")],
            },
        ] {
            assert!(matches!(
                io.spawn(OWNER, ticket(91), &wrong),
                Err(IoRefusal::Refused(_))
            ));
            assert_eq!(
                io.held(),
                0,
                "a changed private launch recipe spawned a child"
            );
        }
        let handle = io
            .spawn(
                OWNER,
                ticket(91),
                &Spawn {
                    program: "/bin/pwd",
                    args: &[],
                    env: &[],
                },
            )
            .unwrap();
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut output = Vec::new();
            loop {
                let mut bytes = [0; 256];
                let n = poll_fn(|cx| io.read(OWNER, handle, &mut bytes, cx.waker()))
                    .await
                    .unwrap();
                if n == 0 {
                    break;
                }
                output.extend_from_slice(&bytes[..n]);
            }
            output
        })
        .await;
        io.close(OWNER, handle).unwrap();
        assert_eq!(
            String::from_utf8(output.unwrap()).unwrap().trim_end(),
            std::env::current_dir()
                .unwrap()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap()
        );
        let mut missing = program;
        missing.cwd = Some(
            std::env::temp_dir()
                .join(format!(
                    "busbar-absent-cwd-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
                .to_str()
                .unwrap()
                .to_owned(),
        );
        io.admit_for(
            ticket(92),
            Admission::Spawn(missing, crate::spawn_env::HeldEnv::written_only()),
            Some(OWNER),
        );
        assert!(matches!(
            io.spawn(
                OWNER,
                ticket(92),
                &Spawn {
                    program: "/bin/pwd",
                    args: &[],
                    env: &[]
                }
            ),
            Err(IoRefusal::Failed(_))
        ));
        assert_eq!(io.settle(ticket(92)).0, None);
        assert_eq!(io.held(), 0, "a failed chdir retained a program handle");
    });
}

#[test]
fn an_admitted_program_runs_in_its_configured_working_directory() {
    worker().block_on(async {
        let io = HostIo::new();
        let directory = std::env::temp_dir().join(format!(
            "busbar-program-cwd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let program = Program::of_member(&serde_json::json!({
            "command": "/bin/pwd",
            "cwd": directory.to_str().unwrap(),
        }))
        .unwrap()
        .unwrap();
        io.admit(
            ticket(90),
            Admission::Spawn(program, crate::spawn_env::HeldEnv::written_only()),
        );
        let handle = io
            .spawn(
                OWNER,
                ticket(90),
                &Spawn {
                    program: "/bin/pwd",
                    args: &[],
                    env: &[],
                },
            )
            .unwrap();
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut output = Vec::new();
            loop {
                let mut bytes = [0; 256];
                let length = poll_fn(|cx| io.read(OWNER, handle, &mut bytes, cx.waker()))
                    .await
                    .unwrap();
                if length == 0 {
                    break;
                }
                output.extend_from_slice(&bytes[..length]);
            }
            output
        })
        .await;
        io.close(OWNER, handle).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        assert_eq!(
            String::from_utf8(output.unwrap()).unwrap().trim_end(),
            directory.to_str().unwrap(),
            "the host ignored the admitted working directory"
        );
    });
}

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

        assert!(matches!(
            io.open(OWNER, ticket(1), "127.0.0.1:9"),
            Err(IoRefusal::Refused(_))
        ));

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

/// A released handle is never made again: its slot holds the next handle under a new generation,
#[test]
fn a_released_handle_is_never_made_again() {
    worker().block_on(async {
        let io = HostIo::new();
        io.admit(ticket(50), Admission::Bind("127.0.0.1:0".into()));
        let (old, _) = io.listen(OWNER, ticket(50), "127.0.0.1:0").unwrap();
        io.close(OWNER, old).unwrap();
        io.admit(ticket(51), Admission::Bind("127.0.0.1:0".into()));
        let (new, _) = io.listen(OWNER, ticket(51), "127.0.0.1:0").unwrap();
        assert_ne!(new, old, "a released handle was made again");
        assert!(matches!(io.ends(OWNER, old), Err(IoRefusal::Refused(_))));
        assert!(matches!(io.close(OWNER, old), Err(IoRefusal::Refused(_))));
        assert!(io.ends(OWNER, new).is_ok());
        io.close(OWNER, new).unwrap();
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
        let peer_at = io.ends(OWNER, h).unwrap().peer;
        assert_eq!(peer_at, at);

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
            cwd: None,
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

/// RED (a program carrier's end, coordinator ruling (A)): `io.ends` on a program's handle answers the program's
#[test]
fn a_programs_own_exit_is_answered_by_ends_while_a_descendant_holds_its_output() {
    worker().block_on(async {
        let io = HostIo::new();
        let args = ["-c".to_owned(), "sleep 5 & exit 3".to_owned()];
        let program = Program {
            command: "/bin/sh".into(),
            cwd: None,
            args: args.to_vec(),
            env: Vec::new(),
            env_refs: Vec::new(),
        };
        io.admit(
            ticket(21),
            Admission::Spawn(program, crate::spawn_env::HeldEnv::written_only()),
        );
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let h = io
            .spawn(
                OWNER,
                ticket(21),
                &Spawn {
                    program: "/bin/sh",
                    args: &argv,
                    env: &[],
                },
            )
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        let ends = loop {
            let ends = io.ends(OWNER, h).unwrap();
            if ends.exit.is_some() || std::time::Instant::now() > deadline {
                break ends;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert_eq!(
            ends.exit,
            Some(3),
            "the program's own exit was not answered"
        );
        assert_eq!((ends.port, ends.peer.as_str()), (0, ""));

        let mut buf = [0_u8; 16];
        let waker = std::task::Waker::noop();
        let read = io.read(OWNER, h, &mut buf, waker);
        assert!(read.is_pending(), "the pipe ended: {read:?}");
        io.close(OWNER, h).unwrap();
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

/// THE HELD ENVIRONMENT: the carrier hands the host's `io.spawn` the program's WRITTEN environment
#[test]
fn a_programs_environment_reference_is_held_for_the_hosts_spawn() {
    const VAR: &str = "BUSBAR_HOSTIO_SPAWN_SECRET";
    std::env::set_var(VAR, "hostio-spawn-value");
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program {
            command: "/usr/bin/env".into(),
            cwd: None,
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

/// A SPAWN RESOLVES NOTHING. A spawn serves a request (a member's first lease, a respawn, a program
#[test]
fn a_spawn_resolves_nothing_and_a_rotation_reaches_the_first_child_after_the_refresh() {
    const VAR: &str = "BUSBAR_HOSTIO_SPAWN_ROTATED";
    std::env::set_var(VAR, "before-rotation");
    worker().block_on(async {
        let io = HostIo::new();
        let program = Program {
            command: "/usr/bin/env".into(),
            cwd: None,
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

/// RED (transport ABI defect 2): `reap` releases every handle its owner still holds, as `close`
#[test]
fn reap_releases_every_handle_of_its_owner_and_no_other() {
    worker().block_on(async {
        let io = HostIo::new();
        io.admit(ticket(30), Admission::Bind("127.0.0.1:0".into()));
        let (listener, at) = io.listen(OWNER, ticket(30), "127.0.0.1:0").unwrap();
        let original = std::sync::Arc::downgrade(&io.handles.get(listener).unwrap());
        io.admit(ticket(31), Admission::Bind("127.0.0.1:0".into()));
        let (other, other_at) = io.listen(OWNER + 1, ticket(31), "127.0.0.1:0").unwrap();
        assert_eq!(io.held(), 2);
        io.reap(OWNER);
        assert_eq!(io.held(), 1, "the owner's listener is released");
        assert!(
            original.upgrade().is_none(),
            "reaped entry remains alive at {at}, other {other_at}"
        );
        assert!(
            tokio::net::TcpStream::connect(&at).await.is_err(),
            "the reaped listener still accepts at {at}, other {other_at}"
        );
        assert!(matches!(io.close(OWNER, other), Err(IoRefusal::Refused(_))));
        io.close(OWNER + 1, other)
            .expect("another owner's handle stays");
        assert_eq!(io.held(), 0);
    });
}

/// Linux can stop a listening socket while a fork holds its close-on-exec descriptor before
#[cfg(target_os = "linux")]
#[test]
fn a_retired_listener_stops_accepting_while_a_fork_copy_of_its_descriptor_is_open() {
    worker().block_on(async {
        for retirement in ["reap", "close", "retire"] {
            let io = HostIo::new();
            io.admit(ticket(60), Admission::Bind("127.0.0.1:0".into()));
            let (handle, at) = io.listen(OWNER, ticket(60), "127.0.0.1:0").unwrap();
            let entry = io.handles.get(handle).unwrap();
            let Kind::Listener(listener) = &entry.kind else {
                panic!("listen returned a different handle kind");
            };

            let inherited = listener.get_ref().try_clone().unwrap();
            let original = std::sync::Arc::downgrade(&entry);
            drop(entry);

            drop(tokio::net::TcpStream::connect(&at).await.unwrap());
            match retirement {
                "reap" => io.reap(OWNER),
                "close" => io.close(OWNER, handle).unwrap(),
                "retire" => io.retire_listener(handle),
                _ => unreachable!(),
            }
            assert_eq!(io.held(), 0);
            assert!(
                original.upgrade().is_none(),
                "{retirement} retained the entry"
            );
            assert!(
                tokio::net::TcpStream::connect(&at).await.is_err(),
                "{retirement} left the copied socket listening at {at}"
            );

            drop(inherited);
        }
    });
}
