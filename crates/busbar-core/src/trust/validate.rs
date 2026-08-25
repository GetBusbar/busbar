// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORDERED REQUEST VALIDATOR — its transport-neutral half now lives in
//! [`busbar_substrate::trust::validate`] (Phase-B B1). This module re-exports that half unchanged so
//! every `crate::trust::validate::*` call site resolves as before, and keeps the ONE piece that names
//! a core type: [`Standing`], the standing-permission primitive that re-resolves a principal against
//! [`crate::governance::GovState`]. Core builds substrate's now-`pub` [`Refusal`] into [`Lapsed`];
//! the dependency is one-directional (substrate never names `Standing`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_api::VirtualKey;

// Glob, so a name only a plane consumer or a test uses (e.g. `reason`, `Ask`) never reads as an
// unused import when that consumer is compiled out.
pub use busbar_substrate::trust::validate::*;

/// A DECISION MADE AT OPEN AND TRUSTED WHILE OPEN — the standing-permission primitive.
///
/// A long-lived response (a poll loop, a detached runner) cannot re-run the whole of
/// [`validate_request`] per frame, because most of its inputs are re-derived per frame anyway. What
/// it must NOT do is carry the PRINCIPAL forward: an `Arc<VirtualKey>` cloned into a `'static`
/// future is an identity resolved once and believed for the whole life of the stream, so a key
/// deleted for compromise does not bite until the stream ends.
///
/// So this holds the principal's ID and re-resolves it, rather than holding the principal. The
/// re-resolution is an in-memory index read — no store round trip, nothing to await — which is what
/// makes it affordable on every poll.
///
/// **THE BOUND IS PART OF THE CONTRACT AND IS NOT A CONSOLATION.** `lifetime` is what makes the
/// class of thing this guards finite: whatever cannot be re-checked cannot outlive it. Callers pass
/// their own hard cap so the two numbers are provably the same one.
#[derive(Clone, Debug)]
pub struct Standing {
    /// The principal ID, NOT the principal. `None` only where governance is disabled.
    principal: Option<String>,
    snapshot: Snapshot,
    opened_at: Instant,
    lifetime: Duration,
}

/// WHAT A LONG-LIVED RESPONSE'S RELATIONSHIP TO THE SNAPSHOT IS, and it is not the same for all of
/// them — which is why it is a type rather than a number that some caller passes `0` for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Snapshot {
    /// PINNED. The response was admitted under one snapshot and must not outlive it: everything it
    /// will do was decided against that snapshot, so a move is a lapse.
    PinnedTo(u64),
    /// WATCHING. A move is what this response EXISTS TO REPORT, not a lapse.
    ///
    /// Only honest where the response re-derives everything it says from the LIVE snapshot on every
    /// frame — which is exactly what makes the move harmless, and is a property of the caller that
    /// the caller states here rather than one this module can check.
    Watching,
}

/// A `Standing` permission that no longer stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lapsed {
    /// The principal is gone, disabled or expired — re-resolved, not remembered.
    Identity(Refusal),
    /// The snapshot the request was admitted under has been replaced.
    Generation(Refusal),
    /// The hard cap was reached. Not a failure: a long-lived response with no end is one a client
    /// cannot tell from a hung one.
    Expired,
}

impl Standing {
    /// OPEN. Takes the principal only to read its ID off — the value is deliberately not stored.
    pub fn opened(principal: Option<&VirtualKey>, snapshot: Snapshot, lifetime: Duration) -> Self {
        Self {
            principal: principal.map(|p| p.id.clone()),
            snapshot,
            opened_at: Instant::now(),
            lifetime,
        }
    }

    /// RE-ASK, and hand back the principal AS IT IS NOW.
    ///
    /// The returned key is what the frame's grant must be read from. Returning it rather than a bare
    /// `Ok(())` is what stops a caller re-checking here and then reading a stale copy anyway.
    pub fn still_permitted(
        &self,
        governance: Option<&crate::governance::GovState>,
        live: u64,
        now: u64,
    ) -> Result<Option<Arc<VirtualKey>>, Lapsed> {
        if self.opened_at.elapsed() >= self.lifetime {
            return Err(Lapsed::Expired);
        }
        if let Snapshot::PinnedTo(admitted) = self.snapshot {
            if admitted != live {
                return Err(Lapsed::Generation(Refusal::GenerationMoved {
                    admitted,
                    live,
                }));
            }
        }
        let Some(id) = self.principal.as_deref() else {
            // Governance is off, so there is no principal and nothing to re-resolve.
            return Ok(None);
        };
        // Fail CLOSED on a governance runtime that has gone away underneath an open response: a
        // principal that was enforced at open and cannot be re-resolved now is not a principal this
        // frame may be written under.
        let resolved = governance
            .and_then(|g| g.lookup_by_sub(id))
            .ok_or_else(|| {
                Lapsed::Identity(Refusal::IdentityNotLive {
                    principal: id.to_string(),
                })
            })?;
        if !resolved.is_live()
            || !resolved.enabled
            || resolved.expires_at.is_some_and(|exp| now >= exp)
        {
            return Err(Lapsed::Identity(Refusal::IdentityNotLive {
                principal: id.to_string(),
            }));
        }
        Ok(Some(resolved))
    }
}

#[cfg(test)]
#[path = "tests/validate_tests.rs"]
mod validate_tests;
