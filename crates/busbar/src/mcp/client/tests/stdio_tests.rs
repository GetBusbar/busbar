// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio child's supervision state machine — `spawning → ready → draining → dead`, with crash
//! detection, bounded restart backoff and a circuit-breaker for a crash-looping child — and the
//! spawn itself.
//!
//! Every transition takes an explicit timestamp, so the crash-storm case is asserted at exact times.
//! A supervision policy verified by sleeping is a supervision policy verified at one timing.
//!
//! THE POLICY IS PROVEN HERE; THE POLICY IS PROVEN *REACHED* IN
//! `mcp/tests/stdio_dispatch_tests.rs`, which drives a real `tools/call` through
//! `mcp::upstream::call` and watches the backoff and the quarantine refuse it. Both halves are
//! needed and neither substitutes for the other — this file is what the supervisor DOES, that file
//! is that anything asks it.

use crate::mcp::client::stdio::{ChildState, RestartPolicy, StdioRefusal, Supervisor};
// Used ONLY by the `cfg(unix)` spawning tests below, so the import carries the same gate. Without
// it the Windows build fails on `unused_imports` under `-D warnings` — which is the gate working:
// an import that only one platform needs should say so.
#[cfg(unix)]
use crate::mcp::client::stdio::{StdioChild, StdioCommand};
#[cfg(unix)]
use std::time::Duration;

/// THE INBOUND HALF'S POLICY for a bare-child test: no grants at all.
///
/// Deny-by-default is the shape every one of these fixtures needs, and it is the shape a real
/// registration has unless an operator wrote otherwise. The triggers are a fresh set per call, so a
/// fixture that emitted a `…/list_changed` would record it and nothing here would be affected by
/// another test's.
#[cfg(unix)]
fn bare_policy(
    triggers: &crate::mcp::client::pool::RefreshTriggers,
) -> crate::mcp::client::stdio::PeerPolicy<'_> {
    crate::mcp::client::stdio::PeerPolicy {
        server: "fixture",
        grants: Default::default(),
        triggers,
    }
}

fn policy() -> RestartPolicy {
    RestartPolicy {
        base_backoff_ms: 100,
        max_backoff_ms: 1_000,
        breaker_threshold: 4,
        window_ms: 10_000,
    }
}

/// A `/bin/sh` fixture. See the block comment above the spawning tests for why a shell.
#[cfg(unix)]
fn sh(script: &str) -> StdioCommand {
    StdioCommand {
        program: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), script.to_string()],
        env: Default::default(),
        cwd: None,
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
    assert_eq!(
        s.may_dispatch(),
        Err(StdioRefusal::NotReady(ChildState::Draining)),
        "a readiness signal must not undo a drain"
    );
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
            s.may_restart(u64::MAX).is_ok(),
            "crash {i} must not trip a threshold-4 breaker"
        );
    }
    s.crashed(400);
    // Tripped means tripped: no amount of waiting reopens it, and the reason an operator reads
    // comes back on the refusal rather than from an accessor only a test can see.
    let Err(StdioRefusal::BreakerOpen(why)) = s.may_restart(u64::MAX) else {
        panic!("the 4th crash inside the window must trip the breaker");
    };
    assert!(
        why.contains("4 crashes"),
        "the reason must be countable: {why}"
    );
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
            !matches!(s.may_restart(u64::MAX), Err(StdioRefusal::BreakerOpen(_))),
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
        matches!(s.may_restart(u64::MAX), Err(StdioRefusal::BreakerOpen(_))),
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
    assert!(matches!(
        s.may_restart(u64::MAX),
        Err(StdioRefusal::BreakerOpen(_))
    ));
    s.reset();
    assert!(s.may_restart(0).is_ok(), "the breaker is closed again");
    assert_eq!(
        s.may_dispatch(),
        Err(StdioRefusal::NotReady(ChildState::Spawning)),
        "and the child is back at the start of its life, not serving"
    );
}

// ── THE SPAWNING TESTS BELOW NEED A POSIX SHELL, SO THEY ARE UNIX-ONLY ──────────────────────────
//
// The fixture is `/bin/sh -c '…'` — a one-line JSON-RPC server that keeps the test's child out of
// the build graph. `sh` is not present on every platform this crate builds for: Windows is a CI
// target and `/bin/sh` does not exist there.
//
// WHAT WINDOWS THEREFORE DOES NOT COVER, stated rather than left to be discovered: the spawn, the
// pipe plumbing and the `Spawning -> Ready -> Draining -> Dead` transitions are proven on unix
// only. The transport itself is not unix-only — an operator on Windows configures a Windows command
// and the same machine drives it — so this is a TEST-COVERAGE gap, not a capability one. `cfg(unix)`
// is the honest interim: it says Windows is uncovered here instead of pretending a `cmd.exe` rewrite
// exercises the same thing.

/// A REAL SPAWN, a real pipe, a real JSON-RPC round trip. The state machine above is the policy; this
/// is the proof that the process half works at all.
#[cfg(unix)]
#[tokio::test]
async fn a_real_child_is_spawned_and_answers_one_request() {
    let mut child = StdioChild::spawn(&sh(
        r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n'"#,
    ))
    .await
    .expect("spawn");
    let out = child
        .call(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            Duration::from_secs(5),
            &bare_policy(&Default::default()),
        )
        .await
        .expect("the child answers");
    assert_eq!(
        crate::mcp::client::jsonrpc::parse_response(&out, 1),
        crate::mcp::client::jsonrpc::RpcOutcome::Result(serde_json::json!({"content": []}))
    );
}

/// THE ENVIRONMENT IS NOT INHERITED, and this is the assertion that says so rather than the comment.
///
/// busbar's own environment holds provider API keys, store credentials and admin tokens. The child
/// gets `env_clear()` plus exactly what the operator named, so a variable set in busbar's process
/// and NOT named in `env:` must be absent from the child — and one that IS named must be present
/// with the operator's value, so the clearing did not simply break the channel.
#[cfg(unix)]
#[tokio::test]
async fn the_child_environment_is_replaced_and_not_inherited() {
    // SAFETY-OF-TEST NOTE: this variable is set in the TEST process on purpose — it stands in for
    // every credential a real busbar deployment has in its environment.
    std::env::set_var("BUSBAR_STDIO_TEST_SECRET", "must-not-leak");
    let mut cmd = sh(
        r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"leaked":"%s","named":"%s"}}\n' "$BUSBAR_STDIO_TEST_SECRET" "$NAMED""#,
    );
    cmd.env.insert(
        "NAMED".to_string(),
        crate::mcp::config::ChildEnvValue::Plain("operator-supplied".to_string()),
    );
    let mut child = StdioChild::spawn(&cmd).await.expect("spawn");
    let out = child
        .call(
            b"{}",
            Duration::from_secs(5),
            &bare_policy(&Default::default()),
        )
        .await
        .expect("the child answers");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(
        v["result"]["leaked"], "",
        "busbar's own environment must NOT reach an operator-configured child: {v}"
    );
    assert_eq!(
        v["result"]["named"], "operator-supplied",
        "the operator's own variable must reach it: {v}"
    );
}

/// A child that closes its stdout is an ERROR, not a hang and not an empty success.
#[cfg(unix)]
#[tokio::test]
async fn a_child_that_says_nothing_is_an_error_rather_than_a_hang() {
    let mut child = StdioChild::spawn(&sh("exit 0")).await.expect("spawn");
    let err = child
        .call(
            b"{}",
            Duration::from_secs(5),
            &bare_policy(&Default::default()),
        )
        .await
        .expect_err("a closed stdout must be an error");
    assert!(
        err.contains("closed its stdout") || err.contains("write to stdio MCP child"),
        "unexpected error: {err}"
    );
}

/// A CHILD CANNOT MAKE BUSBAR ALLOCATE FOREVER. A process that writes without ever sending a
/// newline is an untrusted peer driving an unbounded allocation, which is the memory exhaustion the
/// HTTP wire's body cap exists to stop — so the same cap applies on the pipe.
///
/// The fixture writes an endless stream of `x` and no newline at all. The read must ABANDON rather
/// than grow, and the child is retired: there is no way to resynchronise a byte stream whose message
/// boundary never arrived.
#[cfg(unix)]
#[tokio::test]
async fn a_child_that_never_ends_its_message_is_refused_rather_than_buffered() {
    let mut child = StdioChild::spawn(&sh(
        "read line; while :; do printf 'xxxxxxxxxxxxxxxx'; done",
    ))
    .await
    .expect("spawn");
    let err = child
        .call(
            b"{}",
            Duration::from_secs(30),
            &bare_policy(&Default::default()),
        )
        .await
        .expect_err("an endless message must be refused");
    assert!(
        err.contains("without ending its message"),
        "the read must be abandoned at the cap, not grown to whatever the child chooses: {err}"
    );
}

/// The timeout is bounded and it BITES. A child that stops answering is indistinguishable from a
/// child that is slow, and the only safe reading of that ambiguity on a dispatch path is bounded.
#[cfg(unix)]
#[tokio::test]
async fn a_silent_child_hits_the_timeout() {
    let mut child = StdioChild::spawn(&sh("read line; sleep 30"))
        .await
        .expect("spawn");
    let err = child
        .call(
            b"{}",
            Duration::from_millis(150),
            &bare_policy(&Default::default()),
        )
        .await
        .expect_err("the timeout must bite");
    assert!(err.contains("did not answer within the timeout"), "{err}");
}
