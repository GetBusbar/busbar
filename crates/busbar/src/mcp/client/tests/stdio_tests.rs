// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio child's supervision state machine — `spawning → ready → draining → dead`, with crash
//! detection, bounded restart backoff and a circuit-breaker for a crash-looping child — and one
//! real spawn.
//!
//! The policy is driven by an injected clock, so the crash-storm case is asserted at exact times.
//! A supervision policy verified by sleeping is a supervision policy verified at one timing.

use crate::mcp::client::stdio::{ChildState, RestartPolicy, StdioRefusal, Supervisor};
// Used ONLY by the `cfg(unix)` spawning tests below, so the import carries the same gate. Without
// it the Windows build fails on `unused_imports` under `-D warnings` — which is the gate working:
// an import that only one platform needs should say so.
#[cfg(unix)]
use crate::mcp::client::stdio::StdioChild;
#[cfg(unix)]
use std::time::Duration;

fn policy() -> RestartPolicy {
    RestartPolicy {
        base_backoff_ms: 100,
        max_backoff_ms: 1_000,
        breaker_threshold: 4,
        window_ms: 10_000,
    }
}

#[test]
fn only_ready_accepts_a_dispatch() {
    let states = [
        (ChildState::Spawning, false),
        (ChildState::Ready, true),
        (ChildState::Draining, false),
        (ChildState::Dead, false),
    ];
    assert_eq!(states.len(), 4, "every state must be covered");
    for (s, expected) in states {
        assert_eq!(s.accepts_dispatch(), expected, "{s:?}");
    }
}

#[test]
fn a_spawning_child_is_never_written_to() {
    let s = Supervisor::spawning(policy());
    assert_eq!(s.state(), ChildState::Spawning);
    assert_eq!(
        s.may_dispatch(),
        Err(StdioRefusal::NotReady(ChildState::Spawning))
    );
}

#[test]
fn draining_refuses_new_calls_and_ready_cannot_undo_it() {
    let mut s = Supervisor::spawning(policy());
    s.ready();
    assert!(s.may_dispatch().is_ok());
    s.drain();
    assert_eq!(
        s.may_dispatch(),
        Err(StdioRefusal::NotReady(ChildState::Draining))
    );
    // A late readiness signal must not resurrect a draining child — the drain is a decision, not a
    // health observation, and a race between the two must resolve in favour of the decision.
    s.ready();
    assert_eq!(s.state(), ChildState::Draining);
}

#[test]
fn the_backoff_grows_exponentially_and_is_capped() {
    let expected = [(1u64, 100u64), (2, 200), (3, 400)];
    for (crash_no, delay) in expected {
        let mut s = Supervisor::spawning(policy());
        for i in 1..=crash_no {
            s.crashed(i * 1_000);
        }
        let now = crash_no * 1_000;
        assert_eq!(
            s.may_restart(now),
            Err(StdioRefusal::Backoff {
                remaining_ms: delay
            }),
            "crash #{crash_no} must back off {delay}ms"
        );
        // ...and the restart is permitted once the delay has elapsed.
        assert!(s.may_restart(now + delay).is_ok());
    }
}

/// THE ANTI-FORK-BOMB. A child that crashes on startup crashes on every startup; an unbounded
/// restart loop turns that into a fork bomb with a config file behind it.
#[test]
fn a_crash_looping_child_trips_the_breaker_and_stays_tripped() {
    let mut s = Supervisor::spawning(policy());
    for i in 1..=3 {
        s.crashed(i * 100);
        assert!(
            s.tripped().is_none(),
            "crash {i} must not trip a threshold-4 breaker"
        );
    }
    s.crashed(400);
    let why = s
        .tripped()
        .expect("the 4th crash inside the window trips it");
    assert!(
        why.contains("4 crashes"),
        "the reason must be countable: {why}"
    );
    // Tripped means tripped: no amount of waiting reopens it.
    assert!(matches!(
        s.may_restart(u64::MAX),
        Err(StdioRefusal::BreakerOpen(_))
    ));
    assert!(matches!(
        s.may_dispatch(),
        Err(StdioRefusal::BreakerOpen(_))
    ));
}

/// The window is a TIME window. Crashes spread thinly do not trip it, which is what keeps a
/// long-lived process with occasional restarts serving.
#[test]
fn crashes_outside_the_window_age_out() {
    let mut s = Supervisor::spawning(policy());
    for i in 0..10 {
        // One crash every 20s, with a 10s window: never two inside one window.
        s.crashed(i * 20_000);
        assert!(
            s.tripped().is_none(),
            "crash at {}ms must not trip",
            i * 20_000
        );
    }
}

/// A successful start does NOT clear the crash history. Clearing it on every start is how a breaker
/// is written that never trips: crash, restart, serve one call, crash.
#[test]
fn serving_between_crashes_does_not_clear_the_window() {
    let mut s = Supervisor::spawning(policy());
    for i in 1..=4 {
        s.ready();
        s.crashed(i * 100);
    }
    assert!(
        s.tripped().is_some(),
        "a crash-serve-crash loop must still trip the breaker"
    );
}

/// Only an OPERATOR reopens it. A self-resetting breaker is the same fork bomb on a longer period.
#[test]
fn only_an_explicit_reset_reopens_the_breaker() {
    let mut s = Supervisor::spawning(policy());
    for i in 1..=4 {
        s.crashed(i * 100);
    }
    assert!(s.tripped().is_some());
    s.reset();
    assert!(s.tripped().is_none());
    assert_eq!(s.state(), ChildState::Spawning);
    assert!(s.may_restart(0).is_ok());
}

/// A REAL SPAWN, a real pipe, a real JSON-RPC round trip. The state machine above is the policy; this
/// is the proof that the process half works at all.
// ── THE THREE SPAWNING TESTS BELOW NEED A POSIX SHELL, SO THEY ARE UNIX-ONLY ────────────────────
//
// The fixture is `/bin/sh -c 'read line; printf ...'` — a one-line JSON-RPC server that keeps the
// test's child out of the build graph. A comment here used to claim `sh` is present on every
// platform this crate builds for. It is not: Windows is a CI target, `/bin/sh` does not exist
// there, and the full tier caught it on a merge the branch tier had passed.
//
// WHAT WINDOWS THEREFORE DOES NOT COVER, stated rather than left to be discovered: the spawn, the
// pipe plumbing and the `Spawning -> Ready -> Draining -> Dead` transitions are proven on unix
// only. The transport itself is not unix-only — an operator on Windows configures a Windows
// command and the same machine drives it — so this is a TEST-COVERAGE gap, not a capability one.
// Closing it properly means a portable child (re-invoking the test binary through
// `std::env::current_exe()` with an env var, rather than a shell), which is a real change and is
// tracked separately. `cfg(unix)` is the honest interim: it says Windows is uncovered here instead
// of pretending a `cmd.exe` rewrite exercises the same thing.
#[cfg(unix)]
#[tokio::test]
async fn a_real_child_is_spawned_and_answers_one_request() {
    // A one-line JSON-RPC server: read a line, ignore it, answer. Using `sh` keeps the fixture out
    // of the build graph, at the cost of the unix-only gate explained above.
    let mut child = StdioChild::spawn(
        "/bin/sh",
        &[
            "-c".to_string(),
            r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n'"#.to_string(),
        ],
        policy(),
    )
    .await
    .expect("spawn");

    // A dispatch before readiness is refused — the write would land in a pipe nobody is reading yet.
    assert!(child
        .call(b"{}", Duration::from_secs(5))
        .await
        .unwrap_err()
        .contains("Spawning"));

    child.supervisor.ready();
    let out = child
        .call(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            Duration::from_secs(5),
        )
        .await
        .expect("the child answers");
    let parsed = crate::mcp::client::jsonrpc::parse_response(&out);
    assert_eq!(
        parsed,
        crate::mcp::client::jsonrpc::RpcOutcome::Result(serde_json::json!({"content": []}))
    );
}

/// A child that closes its stdout is an ERROR, not a hang and not an empty success.
#[cfg(unix)]
#[tokio::test]
async fn a_child_that_says_nothing_is_an_error_rather_than_a_hang() {
    let mut child = StdioChild::spawn(
        "/bin/sh",
        &["-c".to_string(), "exit 0".to_string()],
        policy(),
    )
    .await
    .expect("spawn");
    child.supervisor.ready();
    let err = child
        .call(b"{}", Duration::from_secs(5))
        .await
        .expect_err("a closed stdout must be an error");
    assert!(
        err.contains("closed its stdout") || err.contains("write to stdio MCP child"),
        "unexpected error: {err}"
    );
}

/// The timeout is bounded and it BITES. A child that stops answering is indistinguishable from a
/// child that is slow, and the only safe reading of that ambiguity on a dispatch path is bounded.
#[cfg(unix)]
#[tokio::test]
async fn a_silent_child_hits_the_timeout() {
    let mut child = StdioChild::spawn(
        "/bin/sh",
        &["-c".to_string(), "read line; sleep 30".to_string()],
        policy(),
    )
    .await
    .expect("spawn");
    child.supervisor.ready();
    let err = child
        .call(b"{}", Duration::from_millis(150))
        .await
        .expect_err("the timeout must bite");
    assert!(err.contains("did not answer within the timeout"), "{err}");
}
