// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO TRANSPORT: spawn and supervise a child process, with the real lifecycle state machine
//! `mcp-design.md` §3.9c calls for.
//!
//! ## Why this is net-new engine surface and not "a seventh entry in an existing pattern"
//!
//! `crates/busbar/src/proto/` is six STATELESS HTTP families over one shared `reqwest` pool. There
//! is no process in any of them, nothing to crash, nothing to restart, and nothing to reap. A stdio
//! MCP server is a child of this process with a pipe on each side of it, and every one of those
//! properties is new. Auditor MCP-2 M is the finding, and this module is where it lands.
//!
//! The correction that comes with it: **spawn is milliseconds, not sub-100µs.** Selection and
//! dispatch carry SEPARATE budgets, and this is squarely on the dispatch side, which is explicitly
//! milliseconds-class. Nothing here is on the selection path, and the mis-analogy to the sub-100µs
//! provider pools is dropped rather than argued with.
//!
//! ## The state machine, and why each transition exists
//!
//! ```text
//!   Spawning ──ready──► Ready ──drain──► Draining ──► Dead
//!      │                  │                             ▲
//!      └──crash───────────┴──crash──────────────────────┘
//! ```
//!
//! - **`Spawning`** — the process exists, nothing has been read from it. A dispatch here waits or is
//!   refused; it is never sent, because a write to a pipe whose reader has not started is a write
//!   that succeeds and is lost.
//! - **`Ready`** — serving.
//! - **`Draining`** — the child is being retired (registry change, quarantine, shutdown). In-flight
//!   calls run to their bounded timeout, new ones are refused. This is OQ10's inferred answer made
//!   concrete: already-dispatched calls drain, not-yet-dispatched calls are refused.
//! - **`Dead`** — exited. A crash from any state lands here and starts the backoff.
//!
//! ## The restart policy is a CIRCUIT BREAKER, not a retry loop
//!
//! A child that crashes on startup will crash on every startup. An unbounded restart loop turns that
//! into a fork bomb with a config file behind it, so: exponential backoff with a ceiling, and a
//! breaker that stops restarting entirely after a threshold of crashes inside a window. A broken
//! child that stays broken must become an operator-visible refusal, not a background process
//! consuming a core.
//!
//! The backoff is computed from the crash count and the machine is driven by an injected clock, so
//! the whole policy is unit-testable without sleeping. A supervision policy verified by waiting is a
//! supervision policy verified at one timing.

use std::process::Stdio;
use std::time::Duration;

/// Where a supervised child is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildState {
    /// Spawned, not yet known-good. Never dispatched to.
    Spawning,
    /// Serving.
    Ready,
    /// Retiring: in-flight calls drain, new calls are refused.
    Draining,
    /// Exited. Eligible for restart subject to the breaker.
    Dead,
}

impl ChildState {
    /// Whether a NEW dispatch may be sent. `Ready` and nothing else — the three other states each
    /// have a specific reason a write would be wrong, and folding any of them in would make one of
    /// those reasons unenforced.
    pub(crate) fn accepts_dispatch(self) -> bool {
        matches!(self, ChildState::Ready)
    }
}

/// The operator-tunable supervision policy. Defaults are chosen to make a crash-looping child
/// visible within seconds rather than to maximise availability, because an MCP server that will not
/// start is a configuration error and hiding it behind retries delays the fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestartPolicy {
    /// First backoff after a crash.
    pub(crate) base_backoff_ms: u64,
    /// Ceiling, so exponential growth does not become "never".
    pub(crate) max_backoff_ms: u64,
    /// Crashes inside `window_ms` that trip the breaker.
    pub(crate) breaker_threshold: u32,
    /// The window the threshold is counted over.
    pub(crate) window_ms: u64,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            base_backoff_ms: 100,
            max_backoff_ms: 30_000,
            breaker_threshold: 5,
            window_ms: 60_000,
        }
    }
}

/// THE SUPERVISOR: the state machine, with no process in it.
///
/// Separating the policy from the process is what makes the policy testable. Every transition below
/// is driven by an event and a timestamp, so the crash-storm case is asserted at exact times rather
/// than approached by sleeping and hoping.
#[derive(Debug)]
pub(crate) struct Supervisor {
    state: ChildState,
    policy: RestartPolicy,
    /// Crash timestamps inside the current window, oldest first.
    crashes: Vec<u64>,
    /// Set when the breaker trips, with the reason an operator reads.
    tripped: Option<String>,
    /// Earliest time a restart may be attempted.
    restart_at_ms: u64,
}

/// Why a dispatch to a stdio child was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StdioRefusal {
    /// The child is not `Ready`.
    NotReady(ChildState),
    /// The breaker is open: the child crash-looped and is quarantined until an operator acts.
    BreakerOpen(String),
    /// The child is in backoff and the restart time has not arrived.
    Backoff { remaining_ms: u64 },
}

impl std::fmt::Display for StdioRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StdioRefusal::NotReady(s) => write!(f, "stdio MCP child is {s:?}, not Ready"),
            StdioRefusal::BreakerOpen(why) => write!(f, "stdio MCP child is quarantined: {why}"),
            StdioRefusal::Backoff { remaining_ms } => write!(
                f,
                "stdio MCP child is in restart backoff for another {remaining_ms}ms"
            ),
        }
    }
}

impl Supervisor {
    /// A supervisor for a child that has just been spawned.
    pub(crate) fn spawning(policy: RestartPolicy) -> Self {
        Self {
            state: ChildState::Spawning,
            policy,
            crashes: Vec::new(),
            tripped: None,
            restart_at_ms: 0,
        }
    }

    pub(crate) fn state(&self) -> ChildState {
        self.state
    }

    pub(crate) fn tripped(&self) -> Option<&str> {
        self.tripped.as_deref()
    }

    /// The child answered: it is serving.
    ///
    /// Deliberately does NOT clear the crash history. A child that crashes, restarts, serves one
    /// call and crashes again is crash-looping, and clearing the window on every successful start is
    /// how a breaker is written that never trips. The history ages out by TIME, which is the thing
    /// the window is a window over.
    pub(crate) fn ready(&mut self) {
        if self.state != ChildState::Draining {
            self.state = ChildState::Ready;
        }
    }

    /// Begin retiring the child: in-flight calls drain, new ones are refused.
    pub(crate) fn drain(&mut self) {
        self.state = ChildState::Draining;
    }

    /// The child exited unexpectedly at `now_ms`. Records the crash, computes the backoff, and trips
    /// the breaker if the threshold is reached inside the window.
    pub(crate) fn crashed(&mut self, now_ms: u64) {
        self.state = ChildState::Dead;
        let window_start = now_ms.saturating_sub(self.policy.window_ms);
        self.crashes.retain(|t| *t >= window_start);
        self.crashes.push(now_ms);
        let n = self.crashes.len() as u32;
        if n >= self.policy.breaker_threshold {
            self.tripped = Some(format!(
                "{n} crashes within {}ms; restarts stopped until an operator re-approves",
                self.policy.window_ms
            ));
            return;
        }
        self.restart_at_ms = now_ms.saturating_add(self.backoff_ms(n));
    }

    /// Exponential backoff from the crash count, capped. `n` is 1-based (the first crash gets the
    /// base delay), and the shift is saturating so a long-lived process with many crashes cannot
    /// overflow into a small delay — the arithmetic bug that turns a backoff into a spin.
    fn backoff_ms(&self, n: u32) -> u64 {
        let shift = n.saturating_sub(1).min(20);
        self.policy
            .base_backoff_ms
            .saturating_mul(1u64 << shift)
            .min(self.policy.max_backoff_ms)
    }

    /// May a restart be attempted at `now_ms`?
    pub(crate) fn may_restart(&self, now_ms: u64) -> Result<(), StdioRefusal> {
        if let Some(why) = &self.tripped {
            return Err(StdioRefusal::BreakerOpen(why.clone()));
        }
        if now_ms < self.restart_at_ms {
            return Err(StdioRefusal::Backoff {
                remaining_ms: self.restart_at_ms - now_ms,
            });
        }
        Ok(())
    }

    /// May a dispatch be sent right now?
    pub(crate) fn may_dispatch(&self) -> Result<(), StdioRefusal> {
        if let Some(why) = &self.tripped {
            return Err(StdioRefusal::BreakerOpen(why.clone()));
        }
        if !self.state.accepts_dispatch() {
            return Err(StdioRefusal::NotReady(self.state));
        }
        Ok(())
    }

    /// An operator has re-approved the child: clear the breaker and the history.
    ///
    /// An explicit act, never a timeout. A breaker that resets itself turns "this child is broken"
    /// into "this child is broken every few minutes", which is the same fork bomb on a longer
    /// period.
    pub(crate) fn reset(&mut self) {
        self.tripped = None;
        self.crashes.clear();
        self.restart_at_ms = 0;
        self.state = ChildState::Spawning;
    }
}

/// A LIVE stdio child: the process, its pipes, and its supervisor.
///
/// The framing is newline-delimited JSON, which is what MCP stdio specifies: one JSON-RPC message
/// per line, and a message may therefore contain no raw newline. `serde_json::to_vec` never emits
/// one, so busbar's writes are conforming by construction; a child that writes a bare newline inside
/// a message is producing a message busbar will read as two, and the second one fails to parse —
/// which is a refusal rather than a misread.
pub(crate) struct StdioChild {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<tokio::process::ChildStdout>,
    pub(crate) supervisor: Supervisor,
}

impl StdioChild {
    /// Spawn `program` with `args`.
    ///
    /// `stderr` is INHERITED rather than piped. A piped stderr nobody drains fills its pipe buffer
    /// and blocks the child mid-write, which presents as a hang rather than as an error — the worst
    /// available failure mode. Inheriting sends it to busbar's own stderr where an operator can see
    /// it, which is where a child's diagnostics belong.
    pub(crate) async fn spawn(
        program: &str,
        args: &[String],
        policy: RestartPolicy,
    ) -> Result<Self, String> {
        use tokio::io::BufReader;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Reaped by tokio when the handle drops, which is the zombie-reaping obligation of
            // the state machine above discharged by the runtime rather than by hand.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawn stdio MCP server `{program}`: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "stdio MCP child has no stdin pipe".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "stdio MCP child has no stdout pipe".to_string())?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            supervisor: Supervisor::spawning(policy),
        })
    }

    /// Send one JSON-RPC message and read one back, bounded by `timeout`.
    ///
    /// The timeout is not optional and has no "unlimited" spelling. A child that stops answering is
    /// indistinguishable from a child that is slow, and the only safe reading of that ambiguity on a
    /// dispatch path is the bounded one.
    pub(crate) async fn call(&mut self, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        self.supervisor
            .may_dispatch()
            .map_err(|refusal| refusal.to_string())?;
        let write = async {
            self.stdin.write_all(body).await?;
            self.stdin.write_all(b"\n").await?;
            self.stdin.flush().await
        };
        tokio::time::timeout(timeout, write)
            .await
            .map_err(|_| {
                "stdio MCP child did not accept the request within the timeout".to_string()
            })?
            .map_err(|e| format!("write to stdio MCP child: {e}"))?;
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line);
        let n = tokio::time::timeout(timeout, read)
            .await
            .map_err(|_| "stdio MCP child did not answer within the timeout".to_string())?
            .map_err(|e| format!("read from stdio MCP child: {e}"))?;
        if n == 0 {
            return Err("stdio MCP child closed its stdout".to_string());
        }
        Ok(line.into_bytes())
    }

    /// Whether the child has exited, without blocking. Drives the `crashed` transition.
    pub(crate) fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }
}

#[cfg(test)]
#[path = "tests/stdio_tests.rs"]
mod stdio_tests;
