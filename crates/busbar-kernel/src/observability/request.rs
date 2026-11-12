// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST DEBUG SUMMARY: one `request finished` event at DEBUG under the target
//! [`TARGET`], carrying what an operator needs to diagnose one request end to end: who asked for
//! what, how governance decided, every attempt the walk made (its lane, provider, upstream status,
//! latency and why it failed over), and how the request ended.
//!
//! # Cost
//!
//! OFF (the default `info`): a unit asks [`enabled`] once when it starts. Below DEBUG that is the
//! `tracing` macro's static and global max-level comparison, before any callsite is touched; the
//! unit then carries `None` and every recording site below is a branch on that `None`. No
//! allocation, no clock read, no formatting and no field is computed.
//!
//! ON: the unit carries one boxed [`Trail`]; each attempt clones its lane and provider names and
//! reads the clock at its start and end; the event is emitted once, when the unit ends. Its fields
//! are native `tracing` values; the attempt list renders through [`Attempts`]'s `Display`, which
//! runs inside the subscriber only when the event is written.
//!
//! # What it never carries
//!
//! No request or response body, no header, no credential, no hook message text: only names the
//! operator configured (pool, lane, provider, plane), the caller's key id (attribution, never a
//! credential; the governance log lines have always named it), reason codes from the closed
//! vocabulary, statuses and durations.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// The target the summary is emitted under: `RUST_LOG=info,busbar::request=debug` turns on the
/// summary alone.
pub const TARGET: &str = "busbar::request";

/// Whether the per-request summary is enabled: decided once per unit.
#[inline]
#[must_use]
pub fn enabled() -> bool {
    tracing::enabled!(target: "busbar::request", tracing::Level::DEBUG)
}

/// One attempt the walk made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptNote {
    /// The member (lane) the walk picked.
    pub lane: String,
    /// The provider serving it.
    pub provider: String,
    /// The status the far end answered (`0`: none arrived).
    pub status: u32,
    /// Attempt start to its end, microseconds.
    pub elapsed_us: u64,
    /// How the attempt ended: `complete`, `retry`, `cut`, `failed`, `cancelled`, ...
    pub outcome: &'static str,
    /// Why the walk failed over from it, where it did and the walk named a reason.
    pub failover: Option<&'static str>,
}

/// The attempts of one unit, shared with each attempt's timing while it runs.
pub type AttemptLog = Arc<Mutex<Vec<AttemptNote>>>;

/// One attempt's note while it is in flight.
#[derive(Debug)]
pub struct AttemptTrail {
    log: AttemptLog,
    note: AttemptNote,
    start: Instant,
    done: bool,
}

impl AttemptTrail {
    /// Open an attempt's note on `lane` through `provider`.
    #[must_use]
    pub fn open(log: AttemptLog, lane: &str, provider: &str) -> Self {
        Self {
            log,
            note: AttemptNote {
                lane: lane.to_owned(),
                provider: provider.to_owned(),
                status: 0,
                elapsed_us: 0,
                outcome: "abandoned",
                failover: None,
            },
            start: Instant::now(),
            done: false,
        }
    }

    /// The far end's status, where its first status-bearing piece states one.
    pub fn status(&mut self, status: u32) {
        if self.note.status == 0 {
            self.note.status = status;
        }
    }

    /// Why the walk is failing over from this attempt.
    pub fn failover(&mut self, reason: Option<&'static str>) {
        self.note.failover = reason;
    }

    /// Close the note with `outcome`; later calls are no-ops.
    pub fn close(&mut self, outcome: &'static str) {
        if self.done {
            return;
        }
        self.done = true;
        self.note.outcome = outcome;
        self.note.elapsed_us = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.note.clone());
    }
}

impl Drop for AttemptTrail {
    fn drop(&mut self) {
        self.close("abandoned");
    }
}

/// What a unit gathers for its summary while the summary is enabled.
#[derive(Debug)]
pub struct Trail {
    started: Instant,
    /// Its attempts, in order.
    pub attempts: AttemptLog,
    /// How the walk ended: its terminal's name and, where it has one, its detail.
    pub walk: Option<(&'static str, Option<&'static str>)>,
}

impl Trail {
    /// A trail for a unit starting now, when the summary is enabled; `None` otherwise.
    #[inline]
    #[must_use]
    pub fn start() -> Option<Box<Self>> {
        enabled().then(|| {
            Box::new(Self {
                started: Instant::now(),
                attempts: Arc::new(Mutex::new(Vec::new())),
                walk: None,
            })
        })
    }

    /// Microseconds since the unit started.
    #[must_use]
    pub fn elapsed_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    /// The attempts so far.
    #[must_use]
    pub fn attempts(&self) -> Vec<AttemptNote> {
        self.attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The attempt list as the summary renders it: `lane(provider) status latency outcome[:reason]`,
/// comma-separated, e.g. `openai-east(openai) 429 112ms retry:rate_limited, claude(anthropic) 200
/// 840ms complete`. `-` for an empty list (the unit made no attempt).
#[derive(Debug)]
pub struct Attempts<'a>(pub &'a [AttemptNote]);

impl std::fmt::Display for Attempts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("-");
        }
        for (i, a) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", a.lane)?;
            if !a.provider.is_empty() {
                write!(f, "({})", a.provider)?;
            }
            if a.status != 0 {
                write!(f, " {}", a.status)?;
            }
            let ms = a.elapsed_us / 1000;
            if ms == 0 {
                write!(f, " {}us {}", a.elapsed_us, a.outcome)?;
            } else {
                write!(f, " {ms}ms {}", a.outcome)?;
            }
            if let Some(reason) = a.failover {
                write!(f, ":{reason}")?;
            }
        }
        Ok(())
    }
}

/// Everything the summary states, borrowed from the unit and its host at the unit's end.
#[derive(Debug, Default)]
pub struct Summary<'a> {
    /// The correlation id the unit's `forward` span and hooks carry, where one was minted.
    pub request_id: Option<u64>,
    /// The kernel's unit key.
    pub unit_id: u64,
    /// The plane instance.
    pub plane: &'a str,
    /// The caller's dialect (ingress protocol).
    pub ingress: Option<&'a str>,
    /// The operation class.
    pub op: Option<&'a str>,
    /// What the request named (its model or pool entry), as the plane decoded it.
    pub requested: Option<&'a str>,
    /// The pool it was routed over (after any budget downgrade).
    pub pool: Option<&'a str>,
    /// The governance key id, where a key admitted it.
    pub key_id: Option<&'a str>,
    /// The governance decision: `admitted`, `downgraded`, `ungoverned`, or `refused`.
    pub governance: &'a str,
    /// The pool a budget downgrade moved it to.
    pub downgraded_to: Option<&'a str>,
    /// The routing hook that ordered or restricted the walk.
    pub route_policy: Option<&'a str>,
    /// The member that served the last attempt.
    pub lane: Option<&'a str>,
    /// Its provider.
    pub provider: Option<&'a str>,
    /// How the unit ended: `completed`, `refused`, `failed`, `aborted`, `timed_out`, `abandoned`.
    pub outcome: &'a str,
    /// The step it stopped at, for a refusal or failure.
    pub step: Option<&'a str>,
    /// The reason code, for a refusal or failure.
    pub reason: Option<&'a str>,
    /// How the walk ended: `done`, `exhausted`, `vetoed`, `failed`, `cancelled`, `retired`.
    pub walk: Option<&'a str>,
    /// The walk terminal's detail (an exhaustion's shed, a failure's reason).
    pub walk_detail: Option<&'a str>,
    /// The status the caller was answered with (`0`: none was stated).
    pub status: u32,
    /// Any answer byte reached the caller as a stream.
    pub streamed: bool,
    /// The far end cut the answer.
    pub cut: bool,
    /// Every attempt, in order.
    pub attempts: &'a [AttemptNote],
    /// Unit start to end, microseconds.
    pub latency_us: u64,
}

/// Emit the summary. Callers build it only when [`enabled`] held at the unit's start.
pub fn finished(s: &Summary<'_>) {
    tracing::debug!(
        target: "busbar::request",
        request_id = s.request_id,
        unit_id = s.unit_id,
        plane = s.plane,
        ingress = s.ingress,
        op = s.op,
        requested = s.requested,
        pool = s.pool,
        key_id = s.key_id,
        governance = s.governance,
        downgraded_to = s.downgraded_to,
        route_policy = s.route_policy,
        lane = s.lane,
        provider = s.provider,
        attempts = s.attempts.len(),
        tried = %Attempts(s.attempts),
        walk = s.walk,
        walk_detail = s.walk_detail,
        outcome = s.outcome,
        step = s.step,
        reason = s.reason,
        status = s.status,
        streamed = s.streamed,
        cut = s.cut,
        latency_ms = s.latency_us / 1000,
        latency_us = s.latency_us,
        "request finished"
    );
}

#[cfg(test)]
#[path = "../tests/request_summary_tests.rs"]
mod tests;
