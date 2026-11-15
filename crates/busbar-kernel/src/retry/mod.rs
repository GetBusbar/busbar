// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Non-upstream retries: the one place a store, secret, auth, export, push, admin or probe retry is decided (IF §12.3).
//! Upstream attempts are the walk's and never come here.

// The backoff shape core already has (IF §12.3 round 33: every `RetryPolicy` schedule uses it). These names were
// `busbar_kernel::retry::*` before this module existed (`pub use busbar_contract::retry;`), and stay so.
pub use busbar_contract::retry::{spread, unit, Backoff, FLOOR};
pub use busbar_plugin_loader::ports::PortError;

use std::time::Duration;

use busbar_plugin_abi::fail::{failed, CallError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrySite {
    StoreRead,
    StoreScan,
    StoreCommit,
    StoreClock,
    SecretResolve,
    AuthOutbound,
    AuthRefresh,
    ExportDeliver(u32),
    PlaneAdmin,
    PlanePush,
    PlaneProbe,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Stop,
    After(std::time::Duration),
}

/// The only place a non-upstream retry or backoff is decided (upstream member choice is the walk's, above).
/// Plugins and Need handlers never retry (I3). StoreCommit (round 30): an uncertain commit is retried with the same
/// slot, seq and candidate bytes while the slot is held; the store replays the recorded verdict, or answers FENCED or
/// STALE (STORE-TRANSACTIONS §2.7).
/// Round 21: `err`'s `Failed.retry_after_s` is the backend's own Retry-After when the plugin stated it (§4.1);
/// the policy may wait at least that long (clamped by its own maximum) or give up, never shorter.
/// Round 23: `AuthOutbound` is asked by the credential cache once per failed mint, with `attempt` = the key's
/// failure streak, and its answer is that key's failure window (§12.2 rule 4), not an inline re-call: no
/// request waits on a retried mint. Its schedule (K3): After(min(300 s, max(30 s × 2^(attempt − 1),
/// retry_after_s))) for every `Failed` and `Call(Deadline)`, Stop for anything else. This is the home of the
/// dropped SDK-DEDUPE-AUTH D6 (`Host::mint_retry`, MINT_BACKOFF_DEFAULT/MAX): the same decision, in core.
/// Round 33 (AGREED CHUNK-CONTRACT Q5): `ExportDeliver(stream)`, every stream, `attempt` = the delivery's
/// (§8.5): every `Failed` but F_LIMIT, and `Call(Deadline)`, → After(min(300 s, max(Backoff::new(250 ms, 60 s)
/// .delay(attempt, retry::unit()), retry_after_s))); a Retry-After above 300 s is not cut short: the pump holds
/// the instance's breaker cell open for the stated time. REFUSED, FAULT and F_LIMIT → Stop. Non-content streams
/// Stop after attempt 3 (dev's MAX_ATTEMPTS, now with backoff); STREAM_CONTENT (1.6.x) is bounded by
/// `REDELIVERY_HORIZON_S`, not by a count. There is no `ExportChunk` site: content uses `ExportDeliver(9)`.
pub trait RetryPolicy: Send + Sync + 'static {
    fn next(&self, site: RetrySite, attempt: u32, err: &PortError) -> Retry;
}

/// The longest any one wait is (IF §12.3: the Retry-After clamp and the AuthOutbound window ceiling).
pub const MAX_WAIT: Duration = Duration::from_secs(300);
/// The first `AuthOutbound` failure window; it doubles per further failure (IF §12.3 round 23).
pub const AUTH_WINDOW: Duration = Duration::from_secs(30);
/// Attempts a non-content export delivery gets (dev's `MAX_ATTEMPTS`).
pub const EXPORT_ATTEMPTS: u32 = 3;
/// Attempts a store, secret, auth-refresh or admin call gets (one call plus two retries).
pub const CALL_ATTEMPTS: u32 = 3;
/// Attempts a queued push gets before it is dropped.
pub const PUSH_ATTEMPTS: u32 = 8;
/// The `STREAM_CONTENT` id (IF §8.5): bounded by the redelivery horizon, not by a count.
const STREAM_CONTENT: u32 = 9;

const EXPORT_BACKOFF: Backoff = Backoff::new(Duration::from_millis(250), Duration::from_secs(60));
const CALL_BACKOFF: Backoff = Backoff::new(Duration::from_millis(200), Duration::from_secs(10));
const PUSH_BACKOFF: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
const PROBE_BACKOFF: Backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));

/// The production [`RetryPolicy`]. The jitter draw is a field so a test can pin a schedule.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    draw: fn() -> f64,
}

impl Policy {
    /// Full jitter from the OS random source ([`unit`]).
    #[must_use]
    pub const fn new() -> Self {
        Self { draw: unit }
    }

    /// A policy whose jitter draw is `draw` (uniform in `[0, 1)`).
    #[must_use]
    pub const fn with_draw(draw: fn() -> f64) -> Self {
        Self { draw }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// A failure a later attempt can cure: any FAILED answer, or the chain's deadline.
fn is_transient(err: &PortError) -> bool {
    matches!(
        err,
        PortError::Failed { .. } | PortError::Call(CallError::Deadline)
    )
}

/// The backend's own Retry-After, zero if it stated none (always so for `Call`).
fn retry_after(err: &PortError) -> Duration {
    match err {
        PortError::Failed {
            retry_after_s: Some(s),
            ..
        } => Duration::from_secs(*s),
        _ => Duration::ZERO,
    }
}

fn is_limit(err: &PortError) -> bool {
    matches!(err, PortError::Failed { code, .. } if *code == failed::F_LIMIT)
}

impl Policy {
    /// `min(MAX_WAIT, max(backoff delay, Retry-After))`: never shorter than the backend asked.
    fn wait(&self, backoff: Backoff, attempt: u32, err: &PortError) -> Retry {
        let jittered = backoff.delay(attempt, (self.draw)());
        Retry::After(jittered.max(retry_after(err)).min(MAX_WAIT))
    }

    fn bounded(&self, backoff: Backoff, max: u32, attempt: u32, err: &PortError) -> Retry {
        if attempt >= max || !is_transient(err) || is_limit(err) {
            Retry::Stop
        } else {
            self.wait(backoff, attempt, err)
        }
    }
}

impl RetryPolicy for Policy {
    fn next(&self, site: RetrySite, attempt: u32, err: &PortError) -> Retry {
        let _ = (site, attempt, err);
        todo!("W1-K3: the schedules")
    }
}
#[cfg(test)]
mod tests;
