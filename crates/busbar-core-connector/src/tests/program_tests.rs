// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEMBER PROGRAMS through the connection table (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): one
//! long-lived program per (instance, need, member), every open on the member a lease on it.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, Program,
};

use crate::registry::{Entry, Transports};
use crate::support::{worker, Knobs, TestDoor};
use crate::Connector;

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(1);

fn connector() -> Connector {
    connector_over(TestDoor::identity("bytes"))
}

/// A connector whose `bytes` entry is `door`.
fn connector_over(door: TestDoor) -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(door),
        alpn: Vec::new(),
    }])
    .unwrap();
    Connector::serving(
        view,
        Arc::new(crate::LiteralsOnly(crate::guard::Guard::default())),
        None,
        Arc::new(|_| {}),
    )
}

/// The member-program need, in `class`.
fn need(class: u32) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: "bytes".to_owned(),
        auth: String::new(),
        target_from: busbar_contract::section::MEMBER_PROGRAM.to_owned(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// A shell program: `script` run by `/bin/sh -c`, with `env`.
fn sh(script: &str, env: &[(&str, &str)]) -> Program {
    Program {
        command: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// Answers each line it reads with its process id and the line.
const ECHO_PID: &str = "while read l; do echo \"$$ $l\"; done";

fn declare(c: &Connector, members: &[(&str, Program)]) -> Result<(), ConnError> {
    let programs: Vec<(String, Program)> = members
        .iter()
        .map(|(n, p)| ((*n).to_owned(), p.clone()))
        .collect();
    c.declare_member_programs(
        OWNER,
        NEED,
        &need(EGRESS_OPERATOR_INFRASTRUCTURE),
        &programs,
    )
}

fn open(c: &Connector, target: &str, body: &[u8]) -> Result<ConnId, ConnError> {
    c.open(
        OWNER,
        NEED,
        &OpenDesc {
            target,
            body,
            ..OpenDesc::default()
        },
    )
}

/// One read, retried while it pends (up to ten seconds).
async fn read(
    c: &Connector,
    id: ConnId,
    buf: &mut [u8],
) -> Result<busbar_contract::conn::Piece, ConnError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match c.read(OWNER, id, 7, buf) {
            Err(ConnError::Pending) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            other => return other,
        }
    }
}

/// The lease's HEAD: the generation of the program it reaches.
async fn generation(c: &Connector, id: ConnId) -> u64 {
    let mut buf = [0_u8; 64];
    let piece = read(c, id, &mut buf).await.expect("the head");
    assert_eq!(
        piece.kind,
        PieceKind::Fields,
        "a lease's first piece is its head"
    );
    assert_eq!(
        piece.status,
        Some(busbar_contract::transport::wire::WireStatusClass::Success)
    );
    let block = std::str::from_utf8(&buf[..piece.len]).unwrap().to_owned();
    block
        .strip_prefix("generation: ")
        .and_then(|g| g.trim_end().parse().ok())
        .unwrap_or_else(|| panic!("a generation field: {block:?}"))
}

/// The next whole line the lease reads (`None` once the program ended).
async fn line(c: &Connector, id: ConnId, held: &mut Vec<u8>) -> Option<String> {
    let mut buf = [0_u8; 256];
    loop {
        if let Some(at) = held.iter().position(|b| *b == b'\n') {
            let l: Vec<u8> = held.drain(..=at).collect();
            return Some(String::from_utf8_lossy(&l[..at]).into_owned());
        }
        match read(c, id, &mut buf).await {
            Ok(p) if p.kind == PieceKind::Body => held.extend_from_slice(&buf[..p.len]),
            Ok(p) if p.kind == PieceKind::Completion => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

/// Write `text` as one message on the lease, and read back the process id the program answers.
async fn pid_of(c: &Connector, id: ConnId, text: &str) -> String {
    let mut msg = text.as_bytes().to_vec();
    msg.push(b'\n');
    assert_eq!(c.write(OWNER, id, &msg, false, false), Ok(msg.len()));
    let mut held = Vec::new();
    let l = line(c, id, &mut held).await.expect("an answer");
    let (pid, echoed) = l.split_once(' ').expect("`<pid> <line>`");
    assert_eq!(echoed, text);
    pid.to_owned()
}

/// Whether process `pid` is gone (or a zombie: it ended and waits to be reaped).
fn gone(pid: &str) -> bool {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .expect("ps runs");
    let stat = String::from_utf8_lossy(&out.stdout);
    stat.trim().is_empty() || stat.trim().starts_with('Z')
}

async fn until_gone(pid: &str) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !gone(pid) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    gone(pid)
}

/// RED: two exchanges on one member, one after the other, reach ONE running program (one pid, one
/// generation): closing an open leaves the program running for the next. Another member runs its
/// own program.
#[test]
fn opens_on_one_member_share_one_program_and_members_run_their_own() {
    worker().block_on(async {
        let c = connector();
        declare(
            &c,
            &[("one", sh(ECHO_PID, &[])), ("two", sh(ECHO_PID, &[]))],
        )
        .unwrap();
        let a = open(&c, "one", b"").unwrap();
        assert_eq!(generation(&c, a).await, 1);
        let first = pid_of(&c, a, "a").await;
        c.close(OWNER, a).unwrap();
        assert!(!gone(&first), "closing an open leaves the program running");
        // A target with a path names the member before its first `/`.
        let b = open(&c, "one/rpc", b"").unwrap();
        assert_eq!(generation(&c, b).await, 1, "the same generation");
        assert_eq!(pid_of(&c, b, "b").await, first, "the same program");
        let other = open(&c, "two", b"").unwrap();
        assert_eq!(generation(&c, other).await, 1);
        let second = pid_of(&c, other, "c").await;
        assert_ne!(second, first, "a member runs its own program");
        c.close(OWNER, b).unwrap();
        c.close(OWNER, other).unwrap();
        assert_eq!(
            open(&c, "three", b""),
            Err(ConnError::Refused),
            "a member the need does not name is refused"
        );
    });
}

/// RED: every frame the program writes reaches every open lease of its generation (the plugin
/// correlates by its own ids); an open's body is its first message.
#[test]
fn a_frame_reaches_every_open_lease_and_an_opens_body_is_its_first_message() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("one", sh(ECHO_PID, &[]))]).unwrap();
        let a = open(&c, "one", b"").unwrap();
        assert_eq!(generation(&c, a).await, 1);
        let b = open(&c, "one", b"from-b\n").unwrap();
        assert_eq!(generation(&c, b).await, 1);
        let (mut ha, mut hb) = (Vec::new(), Vec::new());
        let at_a = line(&c, a, &mut ha).await.expect("a reads b's answer");
        let at_b = line(&c, b, &mut hb).await.expect("b reads its own answer");
        assert_eq!(at_a, at_b);
        assert!(at_a.ends_with(" from-b"), "{at_a}");
        c.close(OWNER, a).unwrap();
        c.close(OWNER, b).unwrap();
    });
}

/// RED (finding 13): a lease opened while the program is part way through one frame does not read
/// that frame's rest as though it began there (on one shared child, another exchange's answer
/// taken as its own): its first body bytes begin a frame. The lease already reading the frame reads
/// it whole.
#[test]
fn a_lease_opened_mid_frame_reads_from_the_next_frame() {
    worker().block_on(async {
        let c = connector_over(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                piece: Some(16),
                ..Knobs::default()
            },
        ));
        let long = "A".repeat(100);
        let script = format!("read x; echo {long}; read y; echo second; cat >/dev/null");
        declare(&c, &[("one", sh(&script, &[]))]).unwrap();
        let a = open(&c, "one", b"go\n").unwrap();
        assert_eq!(generation(&c, a).await, 1);
        let mut buf = [0_u8; 64];
        let first = read(&c, a, &mut buf)
            .await
            .expect("the long frame's first piece");
        assert_eq!(first.kind, PieceKind::Body);
        assert!(!first.end, "the long frame arrives in pieces");
        let mut ha = buf[..first.len].to_vec();
        let b = open(&c, "one", b"next\n").unwrap();
        assert_eq!(generation(&c, b).await, 1);
        let mut hb = Vec::new();
        assert_eq!(
            line(&c, b, &mut hb).await.as_deref(),
            Some("second"),
            "the lease opened mid-frame took the rest of a frame it never saw begin"
        );
        assert_eq!(
            line(&c, a, &mut ha).await,
            Some(long),
            "a reads its frame whole"
        );
        c.close(OWNER, a).unwrap();
        c.close(OWNER, b).unwrap();
    });
}

/// RED: a program that ends ends every lease of its generation; the next open spawns it anew — the
/// next generation, another process — once the restart backoff has passed.
#[test]
fn a_program_that_ends_is_a_new_generation_on_the_next_open() {
    worker().block_on(async {
        let c = connector();
        // Answers one line, then exits.
        declare(&c, &[("one", sh("read l; echo \"$$ $l\"", &[]))]).unwrap();
        let a = open(&c, "one", b"").unwrap();
        assert_eq!(generation(&c, a).await, 1);
        let first = pid_of(&c, a, "a").await;
        let mut held = Vec::new();
        assert_eq!(line(&c, a, &mut held).await, None, "the program ended");
        c.close(OWNER, a).unwrap();
        assert!(until_gone(&first).await);
        // Past the first restart's backoff.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let b = open(&c, "one", b"").unwrap();
        assert_eq!(generation(&c, b).await, 2, "a new generation");
        let second = pid_of(&c, b, "b").await;
        assert_ne!(second, first);
        c.close(OWNER, b).unwrap();
    });
}

/// RED: a re-declaration (a config apply) retires a member whose program changed or that is gone:
/// no open reaches it again and its program is killed once its last open closes; an unchanged
/// member keeps its running program.
#[test]
fn a_redeclaration_kills_a_changed_or_removed_members_program() {
    worker().block_on(async {
        let c = connector();
        declare(
            &c,
            &[
                ("kept", sh(ECHO_PID, &[])),
                ("changed", sh(ECHO_PID, &[])),
                ("removed", sh(ECHO_PID, &[])),
            ],
        )
        .unwrap();
        let mut pids = Vec::new();
        for name in ["kept", "changed", "removed"] {
            let id = open(&c, name, b"").unwrap();
            generation(&c, id).await;
            pids.push(pid_of(&c, id, name).await);
            c.close(OWNER, id).unwrap();
        }
        // An open lease on the changed member drains: its program dies when the lease closes.
        let draining = open(&c, "changed", b"").unwrap();
        generation(&c, draining).await;
        declare(
            &c,
            &[
                ("kept", sh(ECHO_PID, &[])),
                ("changed", sh(ECHO_PID, &[("NEW", "1")])),
            ],
        )
        .unwrap();
        assert!(
            until_gone(&pids[2]).await,
            "the removed member's program is killed"
        );
        assert_eq!(open(&c, "removed", b""), Err(ConnError::Refused));
        assert!(
            !gone(&pids[1]),
            "a retired member with an open lease drains"
        );
        c.close(OWNER, draining).unwrap();
        assert!(until_gone(&pids[1]).await, "and is killed when it closes");
        let kept = open(&c, "kept", b"").unwrap();
        assert_eq!(generation(&c, kept).await, 1);
        assert_eq!(
            pid_of(&c, kept, "again").await,
            pids[0],
            "unchanged: the same program"
        );
        let changed = open(&c, "changed", b"").unwrap();
        assert_eq!(
            generation(&c, changed).await,
            1,
            "the changed member's own first program"
        );
        assert_ne!(pid_of(&c, changed, "new").await, pids[1]);
        c.close(OWNER, kept).unwrap();
        c.close(OWNER, changed).unwrap();
    });
}

/// RED: a member's program inherits ONLY the environment its registration states.
#[test]
fn a_members_program_inherits_only_its_stated_environment() {
    worker().block_on(async {
        let c = connector();
        let env = Program {
            command: "/usr/bin/env".to_owned(),
            args: Vec::new(),
            env: vec![("DECLARED".to_owned(), "yes".to_owned())],
        };
        declare(&c, &[("shown", env)]).unwrap();
        let id = open(&c, "shown", b"").unwrap();
        generation(&c, id).await;
        let mut held = Vec::new();
        let mut lines = Vec::new();
        while let Some(l) = line(&c, id, &mut held).await {
            lines.push(l);
        }
        assert_eq!(lines, vec!["DECLARED=yes".to_owned()]);
        c.close(OWNER, id).unwrap();
    });
}

/// RED: a member-program need is carried only as a program need is (operator infrastructure, no
/// auth, absolute commands, the member-program path), and an open on it carries no fields.
#[test]
fn a_member_program_need_is_refused_unless_declared_as_written() {
    worker().block_on(async {
        let c = connector();
        let programs = vec![("one".to_owned(), sh(ECHO_PID, &[]))];
        for refused in [
            need(EGRESS_OPEN_WEB),
            ReadNeed {
                auth: "bearer".into(),
                ..need(EGRESS_OPERATOR_INFRASTRUCTURE)
            },
            ReadNeed {
                target_from: "settings.*.url".into(),
                ..need(EGRESS_OPERATOR_INFRASTRUCTURE)
            },
        ] {
            assert_eq!(
                c.declare_member_programs(OWNER, NEED, &refused, &programs),
                Err(ConnError::Refused)
            );
            assert!(open(&c, "one", b"").is_err());
        }
        let bare = vec![(
            "one".to_owned(),
            Program {
                command: "sh".into(),
                args: Vec::new(),
                env: Vec::new(),
            },
        )];
        assert_eq!(
            c.declare_member_programs(OWNER, NEED, &need(EGRESS_OPERATOR_INFRASTRUCTURE), &bare),
            Err(ConnError::Refused)
        );
        declare(&c, &[("one", sh(ECHO_PID, &[]))]).unwrap();
        assert_eq!(
            c.open(
                OWNER,
                NEED,
                &OpenDesc {
                    target: "one",
                    fields: &[("authorization", b"x".as_slice())],
                    ..OpenDesc::default()
                }
            ),
            Err(ConnError::Refused),
            "no field rides a pipe"
        );
    });
}

/// The restart policy, at exact instants (the previous release's crash-loop policy): a backoff
/// doubling from 100ms after each end, and five ends inside a minute stop the restarts.
#[test]
fn the_restart_policy_backs_off_and_stops_a_crash_loop() {
    let mut s = super::Supervisor::default();
    let t0 = std::time::Instant::now();
    assert!(s.may_restart(t0));
    s.crashed(t0);
    assert!(!s.may_restart(t0 + Duration::from_millis(99)));
    assert!(s.may_restart(t0 + Duration::from_millis(100)));
    let t1 = t0 + Duration::from_millis(100);
    s.crashed(t1);
    assert!(!s.may_restart(t1 + Duration::from_millis(199)));
    assert!(s.may_restart(t1 + Duration::from_millis(200)));
    for n in 2..5 {
        s.crashed(t1 + Duration::from_secs(n));
    }
    assert!(
        !s.may_restart(t1 + Duration::from_secs(3600)),
        "five ends inside a minute stop the restarts"
    );
    // Ends that age out of the window do not count toward the five.
    let mut aged = super::Supervisor::default();
    for n in 0..4 {
        aged.crashed(t0 + Duration::from_secs(n));
    }
    aged.crashed(t0 + Duration::from_secs(120));
    assert!(aged.may_restart(t0 + Duration::from_secs(121)));
}

/// The bound the connector holds on lease `id` (`None` = spent by the answer, or never set).
fn due(c: &Connector, id: ConnId) -> Option<std::time::Instant> {
    c.slab
        .get(OWNER, id)
        .expect("a live lease")
        .1
        .due
        .lock()
        .expect("due")
        .as_ref()
        .map(|d| d.at)
}

/// The test's own hand on lease `id`'s bound: moved to `at`, as the clock would bring it there.
fn set_due(c: &Connector, id: ConnId, at: std::time::Instant) {
    *c.slab
        .get(OWNER, id)
        .expect("a live lease")
        .1
        .due
        .lock()
        .expect("due") = Some(crate::Due { at, timer: None });
}

fn open_bounded(c: &Connector, target: &str) -> ConnId {
    c.open(
        OWNER,
        NEED,
        &OpenDesc {
            target,
            body: b"ask\n",
            timeout_ms: 300,
            ..OpenDesc::default()
        },
    )
    .unwrap()
}

/// RED (ARCHITECT timeout ruling, step 2): a lease's bound runs past its head, which the host serves
/// the instant the lease opens, to the program's own first bytes: a program that takes the request
/// and never answers is a timeout once the bound passes.
///
/// The bound is moved by the test's own hand, never raced on the wall clock. The earlier form opened
/// with a live 300ms bound, took its `started` only after `open` returned, and polled the head and
/// the answer every 5ms: on a loaded runner the head read could land past the bound (the head itself
/// a timeout), or the timeout could land under 300ms from a `started` taken after the bound began.
#[test]
fn a_leases_bound_runs_past_its_head_to_the_programs_answer() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("mute", sh("cat >/dev/null", &[]))]).unwrap();
        let before = std::time::Instant::now();
        let id = open_bounded(&c, "mute");
        let after = std::time::Instant::now();
        // The open's `timeout_ms` is the bound, from the open.
        let at = due(&c, id).expect("the open is bounded");
        assert!(
            at >= before + Duration::from_millis(300) && at <= after + Duration::from_millis(300),
            "the bound is the open's timeout_ms from the open"
        );
        // Held off while the head is read: no load on the runner puts the head past it.
        set_due(
            &c,
            id,
            std::time::Instant::now() + Duration::from_secs(3600),
        );
        assert_eq!(generation(&c, id).await, 1, "the head is served at once");
        assert!(due(&c, id).is_some(), "the head does not spend the bound");
        let mut buf = [0_u8; 64];
        assert_eq!(
            c.read(OWNER, id, 7, &mut buf),
            Err(ConnError::Pending),
            "short of the bound, the mute program's answer pends"
        );
        // The bound passes with no answer begun: the read is a timeout.
        set_due(&c, id, std::time::Instant::now());
        assert_eq!(c.read(OWNER, id, 7, &mut buf), Err(ConnError::Timeout));
        c.close(OWNER, id).unwrap();
    });
}

/// The RED arm of the bound above, on the same hand: a bound set below the answer's arrival is a
/// timeout, and a bound held past it ends at the answer (its first bytes spend the bound).
#[test]
fn a_leases_bound_below_the_answer_is_a_timeout_and_the_answer_spends_it() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("echo", sh(ECHO_PID, &[]))]).unwrap();
        let mut buf = [0_u8; 64];

        let id = open_bounded(&c, "echo");
        set_due(
            &c,
            id,
            std::time::Instant::now() + Duration::from_secs(3600),
        );
        assert_eq!(generation(&c, id).await, 1);
        let piece = read(&c, id, &mut buf).await.expect("the answer");
        assert_eq!(piece.kind, PieceKind::Body);
        assert!(due(&c, id).is_none(), "the answer spends the bound");
        c.close(OWNER, id).unwrap();

        let id = open_bounded(&c, "echo");
        set_due(
            &c,
            id,
            std::time::Instant::now() + Duration::from_secs(3600),
        );
        generation(&c, id).await;
        set_due(&c, id, std::time::Instant::now());
        assert_eq!(
            c.read(OWNER, id, 7, &mut buf),
            Err(ConnError::Timeout),
            "a bound passed before the answer is read is a timeout"
        );
        c.close(OWNER, id).unwrap();
    });
}
