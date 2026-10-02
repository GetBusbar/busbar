// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The spawn carrier holds 1.5.5's carrier rules: an absolute path only, no shell, the environment
//! cleared to exactly what was declared, the child's standard error the host's own, and the child
//! killed when its connection is dropped. Each test is RED on a carrier that drops its rule.

use std::time::{Duration, Instant};

use futures::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::support::worker;

/// Set only in the re-run of this test binary that [`the_childs_standard_error_is_the_hosts_own`]
/// makes, so the child's standard error lands where the parent test can read it.
const STDERR_RUN: &str = "BUSBAR_SPAWN_STDERR_RUN";
const MARKER: &str = "spawn-carrier-stderr-marker";

async fn read_all(s: &mut Spawned) -> Vec<u8> {
    let mut v = Vec::new();
    s.read_to_end(&mut v).await.expect("the child's output");
    v
}

#[test]
fn a_program_that_is_not_an_absolute_path_is_refused_before_anything_runs() {
    worker().block_on(async {
        for program in ["sh", "./sh", "bin/sh", ""] {
            assert!(
                matches!(spawn(program, &[], &[]), Err(Refusal::NotAbsolute)),
                "{program:?}"
            );
        }
    });
}

#[test]
fn a_spawn_off_a_worker_is_refused() {
    assert!(matches!(
        spawn("/bin/sh", &[], &[]),
        Err(Refusal::NotOnAWorker)
    ));
}

/// The test process has PATH, HOME and more set; the child sees exactly the declared variable.
#[test]
fn the_child_gets_exactly_the_declared_environment() {
    worker().block_on(async {
        let mut s = spawn("/usr/bin/env", &[], &[("ONLY", "1")]).unwrap();
        assert_eq!(read_all(&mut s).await, b"ONLY=1\n");
    });
}

/// No shell: an argument is the argument, never expanded or split.
#[test]
fn arguments_reach_the_program_verbatim() {
    worker().block_on(async {
        let mut s = spawn("/bin/echo", &["$HOME; echo injected"], &[]).unwrap();
        assert_eq!(read_all(&mut s).await, b"$HOME; echo injected\n");
    });
}

/// The child's standard input and output are the connection: bytes written come back, and closing
/// the write half ends the child's input.
#[test]
fn the_connection_is_the_childs_standard_input_and_output() {
    worker().block_on(async {
        let mut s = spawn("/bin/cat", &[], &[]).unwrap();
        s.write_all(b"ping\n").await.unwrap();
        s.close().await.unwrap();
        assert_eq!(read_all(&mut s).await, b"ping\n");
    });
}

/// The half of [`the_childs_standard_error_is_the_hosts_own`] that runs in the re-run binary; a no-op
/// in an ordinary run.
#[test]
fn stderr_run_spawns_a_child_that_writes_to_standard_error() {
    if std::env::var_os(STDERR_RUN).is_none() {
        return;
    }
    worker().block_on(async {
        let script = format!("echo {MARKER} >&2");
        let mut s = spawn("/bin/sh", &["-c", &script], &[]).unwrap();
        read_all(&mut s).await;
    });
}

/// The child's standard error is inherited, as 1.5.5's carrier left it: what it writes there reaches
/// the host's own standard error (a carrier that sent it to null, or piped it unread, loses it).
#[test]
fn the_childs_standard_error_is_the_hosts_own() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "spawn::tests::stderr_run_spawns_a_child_that_writes_to_standard_error",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(STDERR_RUN, "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(MARKER),
        "the child's standard error reached the host's: {out:?}"
    );
}

/// Dropping the connection kills the child: it is gone (or a zombie awaiting its reap) at once,
/// never left running its 30 seconds.
#[test]
fn dropping_the_connection_kills_the_child() {
    worker().block_on(async {
        let s = spawn("/bin/sleep", &["30"], &[]).unwrap();
        let pid = s.id().expect("running").to_string();
        drop(s);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let ps = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid])
                .output()
                .unwrap();
            let stat = String::from_utf8_lossy(&ps.stdout).trim().to_owned();
            if stat.is_empty() || stat.starts_with('Z') {
                break;
            }
            assert!(Instant::now() < deadline, "pid {pid} still runs: {stat}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
}

// ── through the connection table ────────────────────────────────────────────────────────────────

mod table {
    use std::sync::Arc;

    use busbar_contract::conn::{ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc};

    use crate::registry::{Entry, Transports};
    use crate::support::{worker, TestDoor};
    use crate::{Connector, Program, DEFAULT_CLASS};

    const OWNER: InstanceId = InstanceId(1);
    const NEED: NeedId = NeedId(0);

    /// A connector whose `bytes` entry frames a program's pipe (the identity test framer: every
    /// byte the child writes comes back as frame bytes).
    fn table() -> Connector {
        let view = Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap();
        Connector::serving(
            view,
            Arc::new(crate::LiteralsOnly),
            None,
            Arc::new(|_: busbar_contract::conn::Ticket| {}),
        )
    }

    fn program(path: &str, args: &[&str], env: &[(&str, &str)]) -> Program {
        Program {
            path: path.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            env: env
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    /// The first `n` bytes the connection delivers.
    async fn read_n(c: &Connector, id: ConnId, n: usize) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buf = [0_u8; 256];
        while got.len() < n {
            match c.read(OWNER, id, 7, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                Ok(p) => got.extend_from_slice(&buf[..p.len]),
                Err(e) => panic!("read: {e:?}"),
            }
        }
        got
    }

    /// RED (C19-TAIL SPAWN-REPOINT): a need declared with a program opens like any other
    /// connection: the child is spawned under the carrier's rules and its pipe framed, the opening
    /// body written to its standard input and its output read back through the table.
    #[test]
    fn a_need_declared_with_a_program_opens_through_the_table() {
        worker().block_on(async {
            let c = table();
            c.declare_program(
                OWNER,
                NEED,
                "bytes",
                DEFAULT_CLASS,
                program("/bin/cat", &[], &[]),
            );
            let desc = OpenDesc {
                body: b"ping\n",
                ..OpenDesc::default()
            };
            let id = c.open(OWNER, NEED, &desc).expect("the program opens");
            assert_eq!(c.write(OWNER, id, b"pong\n", true), Ok(5));
            let got = read_n(&c, id, 10).await;
            assert_eq!(got, b"ping\npong\n");
            c.close(OWNER, id).unwrap();
        });
    }

    /// The declared environment, and nothing else, reaches a program opened through the table.
    #[test]
    fn a_program_opened_through_the_table_gets_exactly_its_declared_environment() {
        worker().block_on(async {
            let c = table();
            c.declare_program(
                OWNER,
                NEED,
                "bytes",
                DEFAULT_CLASS,
                program("/usr/bin/env", &[], &[("ONLY", "1")]),
            );
            let id = c.open(OWNER, NEED, &OpenDesc::default()).unwrap();
            assert_eq!(read_n(&c, id, 7).await, b"ONLY=1\n");
        });
    }

    /// The plugin names no program: on a program need, any target but the declared path is
    /// refused; on a need declared without one, a path is not a destination at all.
    #[test]
    fn a_plugin_named_program_is_refused() {
        worker().block_on(async {
            let c = table();
            c.declare_program(
                OWNER,
                NEED,
                "bytes",
                DEFAULT_CLASS,
                program("/bin/cat", &[], &[]),
            );
            let other = OpenDesc {
                target: "/bin/sh",
                ..OpenDesc::default()
            };
            assert_eq!(c.open(OWNER, NEED, &other), Err(ConnError::Refused));
            c.declare_over(OWNER, NeedId(1), "bytes");
            assert_eq!(c.open(OWNER, NeedId(1), &other), Err(ConnError::Refused));
        });
    }
}
