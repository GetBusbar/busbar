// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE DEMOTION RECORD — what makes a quarantine outlive the process that noticed it.
//!
//! ## The hole this closes, stated exactly
//!
//! A drift quarantine is DERIVED, never stored: `crate::trust::Approval::state` compares the
//! operator's standing approval against the last observation, and a state nobody stores is a state
//! nothing can leave stale. That is the right design and it has one consequence — the observation is
//! in process memory, so a restarted process has none, and a server with no observation answers
//! [`crate::mcp::client::catalogue::LiveDigest::Unsighted`], which dispatches against the digest the
//! operator WROTE IN CONFIG.
//!
//! That fallback is correct and must stay: a deployment that never runs a refresh has only the
//! operator's declarative approval, and treating "we have never looked" as "it moved" would empty
//! the catalogue of every such deployment on the day it shipped. But it is correct only for a server
//! NOBODY LOOKED AT. For a server somebody looked at and DEMOTED it is wrong, and before this
//! existed nothing on disk told those two apart — so a restart handed a demoted upstream its
//! approval back until the next unattended sweep looked again.
//!
//! ## Which is why the record is a fact, not a state
//!
//! What is written is not "this server is quarantined". It is "a live observation of this server
//! disagreed with the approval, at this time" — an OBSERVATION that outlives the process, in exactly
//! the way the in-memory sighting was always meant to and could not. It is replayed at boot as
//! [`crate::trust::Sighting::Demoted`], the derivation runs unchanged on top of it, and the
//! quarantine falls out of the same comparison it always did. Nothing acquires a stored trust state.
//!
//! The boot replay itself — [`crate::mcp::demotion::hydrate`] — stays in the MCP plane for now,
//! because it reaches into `crate::mcp::client` to seed the live sightings cache. This module holds
//! only the pure core state: the row store and the one settle rule.
//!
//! Two things follow, and both are deliberate:
//!
//! - A server with NO record replays as nothing at all, so it is `Never` sighted and the declarative
//!   fallback applies to it exactly as before. The absence of a row is not a demotion.
//! - The record is CLEARED by the first observation that agrees with the approval again, which is
//!   how an operator's remedy takes effect: they fix the upstream, the sweep looks, the row goes.
//!   Nothing else clears it — in particular a restart does not, which is the whole point.
//!
//! ## What a deployment with no durable store gets
//!
//! Exactly what it had. [`busbar_api::Store`]'s methods here are defaulted to accept-and-keep-
//! nothing, so with no sink attached — or with a backend that implements none of them, which is the
//! same thing from here — the write is discarded and the boot read is empty. The quarantine is then
//! process-local and bounded by one sweep interval, which is the pre-existing behaviour. As
//! everywhere else on this seam, a write's `Ok(())` is not evidence of durability: the engine finds
//! out what its backend kept by READING IT BACK at boot.

use crate::plane::store::{decode, demotion_record, PlaneStore, KIND_DEMOTION};
use busbar_api::{McpDemotionRow, PlaneSelector};
use std::sync::{Arc, Mutex};

/// The durable demotion record's write side. No `Debug`: `dyn Store` is not `Debug`, deliberately —
/// a backend must not be obliged to render itself, and one that did would be a place a credential
/// could surface in a log.
#[derive(Default)]
pub struct PlaneQuarantine {
    sink: Mutex<Option<Arc<dyn PlaneStore>>>,
}

impl PlaneQuarantine {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Attach the configured governance store. Called once at boot, on the instance that is carried
    /// across every later config apply — a demotion is evidence, not intent, so an unrelated config
    /// edit must not be able to detach the thing that remembers it.
    pub(crate) fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Poison-recovering, like every other request-path lock in this process: the value behind it is
    /// an `Option<Arc<_>>` that a panic cannot have torn, and cascading the poison would take the
    /// quarantine record out of service for the life of the process over an unrelated panic.
    fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// RECORD that a live observation of `server` disagreed with the approval.
    ///
    /// A failure is reported and swallowed rather than propagated, and the choice is the same one
    /// the durable call log makes: the demotion is ALREADY IN FORCE in this process the moment the
    /// sweep derives it, so a store hiccup costs durability across a restart and never costs the
    /// refusal itself. What it must not be is silent — a deployment whose quarantines are not
    /// surviving restarts has to be able to find that out.
    pub(crate) fn record(&self, server: &str, reason: &str, now: u64) {
        let Some(store) = self.sink() else {
            return;
        };
        let row = McpDemotionRow {
            server: server.to_string(),
            reason: reason.to_string(),
            recorded_at: now,
        };
        if let Err(e) = demotion_record(&row).and_then(|rec| store.upsert_plane_record(&rec)) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_DEMOTION_WRITE_FAILED,
                server = %server,
                reason = %reason,
                error = %e,
                "the durable MCP demotion record could NOT be written: this upstream is demoted in \
                 THIS process and a restart will re-open it until the next sweep looks again"
            );
        }
    }

    /// CLEAR `server`'s record — what an observation that agrees with the approval does. Clearing an
    /// absent row is a no-op at the store, so this runs on every agreeing observation rather than
    /// the engine tracking whether it had demoted.
    pub(crate) fn clear(&self, server: &str) {
        let Some(store) = self.sink() else {
            return;
        };
        if let Err(e) = store.delete_plane_record(KIND_DEMOTION, server) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_DEMOTION_CLEAR_FAILED,
                server = %server,
                error = %e,
                "the durable MCP demotion record for this upstream could NOT be cleared: it is \
                 serving again in THIS process, and a restart would re-establish a quarantine the \
                 operator has already worked"
            );
        }
    }

    /// EVERY recorded demotion. Empty when no store is attached, when the backend keeps none, and
    /// when there genuinely are none — three situations that are indistinguishable from here and
    /// have the same correct outcome, which is that nothing is replayed.
    pub(crate) fn list(&self) -> Vec<McpDemotionRow> {
        let Some(store) = self.sink() else {
            return Vec::new();
        };
        let read = store
            .list_plane_records(KIND_DEMOTION, &PlaneSelector::All)
            .and_then(|bodies| bodies.iter().map(|body| decode(body)).collect());
        match read {
            Ok(rows) => rows,
            Err(e) => {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_DEMOTIONS_UNREAD,
                    error = %e,
                    "the durable MCP demotion records could NOT be read at boot; any upstream this \
                     deployment had demoted is re-opened until the first sweep looks again"
                );
                Vec::new()
            }
        }
    }
}

/// SETTLE the durable record against what an observation just derived. THE ONE RULE, written once.
///
/// Both things that take a live observation of an MCP upstream call this — the unattended sweep and
/// the operator's `connect` verb — and they call it rather than each deciding for itself, because
/// two copies of this rule is how one of them comes to record a demotion the other never clears. An
/// operator who works a remedy through `connect` and sees `approved` must not find the upstream
/// quarantined again at the next restart.
///
/// ONLY `Quarantined` records, and the narrowness is deliberate. `Error` is an upstream that could
/// not be reached, which is transient and re-derived by the next look; persisting it would turn a
/// network blip into a quarantine that survives restarts. `Suspended` is the operator's own standing
/// decision and already lives in config. `Pending` is an unpinned registration, which serves nothing
/// for a reason that has nothing to do with drift. What is durable here is the one fact nothing else
/// keeps: the upstream was observed serving something other than what was approved.
///
/// And ONLY `Approved` clears. Every other state leaves the row exactly as it is — an upstream that
/// has stopped answering has not stopped drifting, and clearing on it would let a demoted upstream
/// buy its approval back by going dark.
pub(crate) fn settle(demotions: &PlaneQuarantine, server: &str, state: crate::trust::TrustState) {
    match state {
        // The WALL clock, not the sweep's monotonic tick: this timestamp is read by an operator
        // after a restart, and a tick would be meaningless to them.
        crate::trust::TrustState::Quarantined => {
            demotions.record(server, state.word(), crate::state::now())
        }
        crate::trust::TrustState::Approved => demotions.clear(server),
        _ => {}
    }
}

#[cfg(test)]
#[path = "tests/demotion_tests.rs"]
mod demotion_tests;
