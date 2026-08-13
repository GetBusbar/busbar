// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STDIO TRANSPORT: spawn and supervise a child process, with a real lifecycle state machine
//! rather than a fire-and-forget spawn — a child that is never reaped is a leak, and one that is
//! written to before it is ready loses the write silently.
//!
//! ## Why this is net-new engine surface and not "a seventh entry in an existing pattern"
//!
//! `crates/busbar/src/proto/` is six STATELESS HTTP families over one shared `reqwest` pool. There
//! is no process in any of them, nothing to crash, nothing to restart, and nothing to reap. A stdio
//! MCP server is a CHILD OF THIS PROCESS with a pipe on each side of it, and every one of those
//! properties is new.
//!
//! ## THE SECURITY POSTURE, because this module spawns a process from operator config
//!
//! The SSRF guard is the defence on the HTTP wire and it does not apply here: there is no address,
//! no resolver and no redirect. What stands in its place is four decisions, each of them fail-closed
//! and each of them enforced where it can be seen:
//!
//! 1. **No shell, ever.** [`StdioCommand::program`] is passed to `Command::new` and the arguments go
//!    through `.args()`. There is no `sh -c`, no string that is split on spaces, and therefore no
//!    metacharacter with meaning. An operator who wants a shell writes `/bin/sh` as the program.
//! 2. **The program is an ABSOLUTE PATH, refused at boot otherwise** (`mcp::config`). A bare name
//!    would be resolved through `PATH`, which makes the binary that actually runs a property of the
//!    environment busbar was started in rather than of the file the operator wrote.
//! 3. **The environment is NOT INHERITED.** `env_clear()` runs first and only
//!    [`StdioCommand::env`] is put back. busbar's own process environment holds provider API keys,
//!    store credentials and admin tokens; handing that whole set to an operator-configured child
//!    would make every stdio registration a credential exfiltration primitive, and it would do it
//!    silently. An operator who needs a variable names it.
//! 4. **The arguments come from CONFIG ONLY.** Nothing on the dispatch path can add to, reorder or
//!    substitute into them — a tool call's `arguments` reach the child as JSON on its stdin, which
//!    is data, and never as `argv`, which is not.
//!
//! The fifth decision is the crash-loop policy below, and it is a security control too: an unbounded
//! restart loop against a binary that always fails is a fork bomb with a config file behind it.
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
//!   calls run to their bounded timeout, new ones are refused.
//! - **`Dead`** — exited. A crash from any state lands here and starts the backoff.
//!
//! ## The restart policy is a CIRCUIT BREAKER, not a retry loop
//!
//! A child that crashes on startup will crash on every startup: exponential backoff with a ceiling,
//! and a breaker that stops restarting entirely after a threshold of crashes inside a window. A
//! broken child that stays broken must become an operator-visible refusal, not a background process
//! consuming a core.
//!
//! The backoff is computed from the crash count and every transition takes a timestamp, so the whole
//! policy is assertable at exact times rather than approached by sleeping and hoping.
//!
//! ## THE SUPERVISOR OUTLIVES THE CHILD, deliberately
//!
//! [`ChildSlot`] holds the [`Supervisor`] beside an `Option<StdioChild>`. A quarantine that lived on
//! the child would be forgotten the moment the child was dropped, which is the moment it is always
//! reached — so the breaker would reset itself on exactly the event it exists to count.

use super::jsonrpc::OutboundRequest;
use super::wire::{McpWire, TransportError, TransportResponse, WireLeg};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

/// THE SPAWN RECIPE, exactly as the operator wrote it and validated at boot.
///
/// Every field is operator-supplied and none of it is reachable from a request. See the module
/// header for the four decisions this type is the carrier of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StdioCommand {
    /// The ABSOLUTE path of the binary. `mcp::config` refuses a relative one at boot.
    pub(crate) program: String,
    /// The argument vector, verbatim. No shell, no splitting, no substitution.
    pub(crate) args: Vec<String>,
    /// THE WHOLE environment the child gets. Not additions to busbar's — see the module header.
    ///
    /// Held UNRESOLVED: a secret arm is a reference until [`StdioChild::spawn`] reads it, so the
    /// snapshot this rides on never holds plaintext and rotating the secret needs no restart.
    pub(crate) env: BTreeMap<String, super::super::config::ChildEnvValue>,
    /// The working directory. `None` ⇒ busbar's own, which is the platform default and is stated
    /// rather than assumed because a child that resolves relative paths is resolving them against
    /// whatever directory the operator happened to start busbar in.
    pub(crate) cwd: Option<String>,
}

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

/// The supervision policy. Defaults are chosen to make a crash-looping child visible within seconds
/// rather than to maximise availability, because an MCP server that will not start is a
/// configuration error and hiding it behind retries delays the fix.
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
/// Separating the policy from the process is what makes the policy testable. Every transition is
/// driven by an event and a timestamp, so the crash-storm case is asserted at exact times rather
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
    /// A supervisor for a child that has not been spawned yet.
    pub(crate) fn spawning(policy: RestartPolicy) -> Self {
        Self {
            state: ChildState::Spawning,
            policy,
            crashes: Vec::new(),
            tripped: None,
            restart_at_ms: 0,
        }
    }

    // THERE ARE NO `state()` / `tripped()` ACCESSORS, and their absence is deliberate. Both existed
    // and both were read only by tests, which is the shape that lets a state machine's observable
    // behaviour drift from the behaviour anything acts on. Every question about this supervisor is
    // asked through `may_dispatch` or `may_restart` — the two the dispatch path itself asks — so a
    // test cannot assert on a state that no caller could ever have refused on.

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

/// A LIVE stdio child: the process and its pipes.
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
}

impl std::fmt::Debug for StdioChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pid and NOTHING else. An argv or an environment printed into a debug line is an
        // operator's configuration in a log, and this type holds both indirectly.
        write!(f, "StdioChild {{ pid: {:?} }}", self.child.id())
    }
}

impl StdioChild {
    /// Spawn the operator's command.
    ///
    /// `stderr` is INHERITED rather than piped. A piped stderr nobody drains fills its pipe buffer
    /// and blocks the child mid-write, which presents as a hang rather than as an error — the worst
    /// available failure mode. Inheriting sends it to busbar's own stderr where an operator can see
    /// it, which is where a child's diagnostics belong.
    pub(crate) async fn spawn(cmd: &StdioCommand) -> Result<Self, String> {
        use tokio::io::BufReader;
        // RESOLVED HERE, at spawn, and nowhere earlier. A failure names the VARIABLE and never the
        // value: the error string reaches a log, and the value is the secret.
        let mut env: Vec<(&str, String)> = Vec::with_capacity(cmd.env.len());
        for (name, value) in &cmd.env {
            let resolved = match value {
                super::super::config::ChildEnvValue::Plain(s) => s.clone(),
                super::super::config::ChildEnvValue::Secret(r) => {
                    crate::config::secret::resolve_builtin_string(r).map_err(|e| {
                        format!("stdio MCP server's `env.{name}` could not be resolved: {e}")
                    })?
                }
            };
            env.push((name.as_str(), resolved));
        }
        let mut builder = tokio::process::Command::new(&cmd.program);
        builder
            .args(&cmd.args)
            // THE WHOLE environment, not additions to busbar's. See the module header, decision 3.
            .env_clear()
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Reaped by tokio when the handle drops, which is the zombie-reaping obligation of the
            // state machine above discharged by the runtime rather than by hand.
            .kill_on_drop(true);
        if let Some(dir) = &cmd.cwd {
            builder.current_dir(dir);
        }
        let mut child = builder
            .spawn()
            // The program path is quoted because it is the operator's own text and naming it is the
            // whole diagnostic; the environment and argv are NOT, because they are secrets and
            // arguments respectively and this string reaches a log.
            .map_err(|e| format!("spawn stdio MCP server `{}`: {e}", cmd.program))?;
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
        })
    }

    /// Send one JSON-RPC message and read one back, bounded by `timeout`.
    ///
    /// The timeout is not optional and has no "unlimited" spelling. A child that stops answering is
    /// indistinguishable from a child that is slow, and the only safe reading of that ambiguity on a
    /// dispatch path is the bounded one.
    pub(crate) async fn call(&mut self, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        use tokio::io::AsyncWriteExt as _;
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
        // CAPPED, and this is a defence rather than a tidiness rule. A child process is an untrusted
        // peer exactly as an upstream HTTP server is, and it can write forever without ever sending a
        // newline — `read_line` on that is an unbounded allocation driven by the peer, which is a
        // memory exhaustion busbar hands itself. The HTTP wire already caps its body with
        // `proxy::read_capped`; this is the same bound, from the same knob, on the other channel.
        let read = read_capped_line(
            &mut self.stdout,
            crate::proxy::max_upstream_buffered_bytes(),
        );
        tokio::time::timeout(timeout, read)
            .await
            .map_err(|_| "stdio MCP child did not answer within the timeout".to_string())?
    }

    /// Whether the child has exited, without blocking. Drives the `crashed` transition.
    pub(crate) fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }
}

/// ONE newline-terminated message from a child, refusing at `cap` bytes.
///
/// Hand-rolled over `fill_buf`/`consume` rather than `read_line`, because `read_line` is exactly the
/// primitive being avoided: it grows until the peer sends a newline, and the peer decides whether it
/// ever does.
///
/// The three ends are three different answers on purpose. A newline is a message. EOF with nothing
/// buffered is a child that closed its stdout, which is the crash signal the supervisor counts. EOF
/// with a PARTIAL message is a failure and not a short message — a truncated JSON-RPC response is not
/// parsed, which is the same rule `super::transport` applies to a truncated HTTP body.
async fn read_capped_line(
    reader: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    cap: usize,
) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncBufReadExt as _;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| format!("read from stdio MCP child: {e}"))?;
        if available.is_empty() {
            if out.is_empty() {
                return Err("stdio MCP child closed its stdout".to_string());
            }
            return Err(
                "stdio MCP child closed its stdout mid-message; a truncated JSON-RPC response is \
                 not parsed"
                    .to_string(),
            );
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(i) => {
                out.extend_from_slice(&available[..i]);
                reader.consume(i + 1);
                return Ok(out);
            }
            None => {
                let n = available.len();
                out.extend_from_slice(available);
                reader.consume(n);
            }
        }
        if out.len() > cap {
            return Err(format!(
                "stdio MCP child wrote more than {cap} bytes without ending its message; the read \
                 is abandoned rather than grown to whatever the child chooses"
            ));
        }
    }
}

/// ONE REGISTRATION'S child, and the supervisor that outlives it.
#[derive(Debug)]
pub(crate) struct ChildSlot {
    supervisor: Supervisor,
    child: Option<StdioChild>,
    /// The recipe the live child was ACTUALLY spawned with, so an operator's edit to `command:` is
    /// noticed. Without it a config apply would leave the old binary serving under the new
    /// registration — the change would appear to have been made and would not have been.
    spawned_with: Option<StdioCommand>,
}

impl ChildSlot {
    fn new() -> Self {
        Self {
            supervisor: Supervisor::spawning(RestartPolicy::default()),
            child: None,
            spawned_with: None,
        }
    }
}

/// EVERY LIVE stdio child busbar owns, keyed by registration id.
///
/// ONE CHILD PER REGISTRATION, and calls to it are SERIALISED by the per-slot lock. That is not a
/// throughput compromise made for simplicity: a child's stdout is a single byte stream, and two
/// request/response pairs interleaved on it can only be told apart by demultiplexing on the JSON-RPC
/// id — which is a second correlation table beside the per-dispatch one `jsonrpc::parse_response`
/// deliberately does not have. Serialising is the honest shape until there is a reader task to own
/// that table.
#[derive(Debug, Default)]
pub(crate) struct StdioPool {
    slots: std::sync::Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<ChildSlot>>>>,
}

impl StdioPool {
    /// The slot for `server`, created empty on first use. Registration does not spawn: a child
    /// starts on the first dispatch that is actually authorised to reach it, so a registered but
    /// never-called server costs no process.
    pub(crate) fn slot(&self, server: &str) -> Arc<tokio::sync::Mutex<ChildSlot>> {
        let mut slots = match self.slots.lock() {
            Ok(s) => s,
            // A poisoned lock means a panic inside a previous holder. Recovering the map is right:
            // the guarded value is a map of handles, none of which a panic can leave half-written.
            Err(p) => p.into_inner(),
        };
        Arc::clone(
            slots
                .entry(server.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(ChildSlot::new()))),
        )
    }

    /// How many registrations have a slot. Bounded by the config, which is why there is no eviction
    /// policy here and no cap: an operator cannot write an unbounded `tools:` map at runtime.
    pub(crate) fn len(&self) -> usize {
        match self.slots.lock() {
            Ok(s) => s.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    /// DROP EVERY CHILD WHOSE REGISTRATION IS GONE. Called on every config apply, from
    /// `AppHandle::swap`, because the pool deliberately outlives an apply and the catalogue does not:
    /// without this, deleting a `tools:` entry would leave its process running forever, unreferenced
    /// and unreachable, which is a leak an operator has no way to see or stop.
    ///
    /// Synchronous, and it takes no child lock: it drops the map's `Arc`s. A slot with a call in
    /// flight holds its own `Arc`, so that call finishes and the child dies when it returns —
    /// `kill_on_drop` is what turns the last drop into a reaped process. That is exactly the drain
    /// semantics the state machine specifies, obtained from ownership rather than from a flag.
    pub(crate) fn retain(&self, keep: &std::collections::BTreeSet<String>) {
        let mut slots = match self.slots.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        slots.retain(|id, _| keep.contains(id));
    }
}

/// Milliseconds on a MONOTONIC clock, shared by every supervisor in the process.
///
/// Monotonic and not wall-clock: a backoff computed from a clock an operator can step backwards is a
/// backoff an operator can accidentally turn into a spin.
fn now_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    // `as u64` after a millisecond conversion: 2^64 ms is half a billion years of uptime.
    start.elapsed().as_millis() as u64
}

/// THE STDIO WIRE — the dispatch arm [`crate::transport::Transport::Stdio`] hands work to.
///
/// Zero-sized: the children live in the pool that rides on [`WireLeg`], so this is the supervision
/// POLICY applied to one call and nothing else.
pub(crate) struct StdioWire;

#[async_trait::async_trait]
impl McpWire for StdioWire {
    async fn send(
        &self,
        leg: &WireLeg<'_>,
        req: &OutboundRequest,
    ) -> Result<TransportResponse, TransportError> {
        // A registration whose transport is stdio ALWAYS carries a command: `mcp::config` refuses
        // one that does not at boot, and `mcp::catalogue` carries it onto the snapshot. Reaching
        // this arm means the two disagreed, which is a bug in busbar and not an operator error, so
        // it refuses rather than inventing a program to run.
        let Some(cmd) = leg.command else {
            return Err(TransportError::Supervision(
                "this registration is stdio but carries no command; busbar will not guess one"
                    .to_string(),
            ));
        };
        let slot = leg.pool.children.slot(leg.server);
        let mut slot = slot.lock().await;

        // (1) IS THERE A LIVE CHILD? A child that has already exited is dropped here rather than
        // written to: writing to a dead pipe is the failure mode that presents as a lost message.
        if slot.child.as_mut().is_some_and(|c| c.exited()) {
            slot.supervisor.crashed(now_ms());
            slot.child = None;
        }

        // (2) HAS THE OPERATOR CHANGED THE RECIPE? The pool outlives a config apply on purpose, so a
        // child spawned from the previous `command:` would otherwise keep serving under the new
        // registration — an edit that appears to have been made and has not been. The running child
        // is DRAINED rather than killed mid-word: this call already holds the only lock, so there is
        // nothing in flight, and dropping it here is the drain completing.
        //
        // AND IT IS THE OPERATOR RE-APPROVAL THE BREAKER WAITS FOR. `Supervisor::reset` is documented
        // as an explicit act and never a timeout, and this is that act: a changed `command:` is an
        // operator naming THIS child and saying they have fixed it. It fires only when the recipe
        // itself differs, so touching an unrelated key does not re-arm a fork bomb — which is the
        // property that would be lost by resetting on every apply.
        if slot
            .spawned_with
            .as_ref()
            .is_some_and(|previous| previous != cmd)
        {
            slot.supervisor.drain();
            slot.child = None;
            slot.spawned_with = None;
            slot.supervisor.reset();
        }

        // (3) SPAWN, subject to the breaker and the backoff. Both refusals are the supervisor's own
        // and neither of them reaches anything, which is what makes a quarantined child cost zero.
        if slot.child.is_none() {
            slot.supervisor
                .may_restart(now_ms())
                .map_err(|r| TransportError::Supervision(r.to_string()))?;
            match StdioChild::spawn(cmd).await {
                Ok(child) => {
                    slot.child = Some(child);
                    slot.spawned_with = Some(cmd.clone());
                    // The pipes are open and the reader is this task, so the child is dispatchable.
                    // The FIRST call is the readiness probe: a program that exits immediately fails
                    // that call and lands on the crash arm below, which is where a child that
                    // cannot start belongs.
                    slot.supervisor.ready();
                }
                Err(e) => {
                    // A spawn that FAILS is a crash for the breaker's purposes. It has to be: a
                    // missing binary or a permission error repeats on every attempt, and a breaker
                    // that only counted processes that managed to start would never trip on the one
                    // failure mode that is guaranteed to be permanent.
                    slot.supervisor.crashed(now_ms());
                    return Err(TransportError::Io(e));
                }
            }
        }

        // (4) THE GATE. Held separately from the spawn above because a `Draining` child has a live
        // process and still may not be dispatched to.
        slot.supervisor
            .may_dispatch()
            .map_err(|r| TransportError::Supervision(r.to_string()))?;

        // (5) THE CALL. The URL and the headers on `req` are not sent: stdio has no request line and
        // no header block, and the credential the HTTP wire would put in an `Authorization` header
        // has no carrier here. That is not a silent drop — `mcp::config` refuses a stdio
        // registration that configures one, so no credential can reach this point to be lost.
        let child = slot
            .child
            .as_mut()
            .expect("a child was spawned or found live above");
        match child.call(&req.body, leg.timeout).await {
            Ok(body) => Ok(TransportResponse { status: 200, body }),
            Err(e) => {
                // ANY failure of the exchange retires the child. A stdio peer has no way to say "that
                // request failed but I am fine": the stream is the connection, so a write or read
                // that failed leaves busbar unable to say where in the byte stream the next answer
                // starts. Reusing it would risk serving one caller another caller's payload.
                slot.supervisor.crashed(now_ms());
                slot.child = None;
                Err(TransportError::Io(e))
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/stdio_tests.rs"]
mod stdio_tests;
