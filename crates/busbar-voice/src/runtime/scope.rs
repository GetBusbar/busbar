// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION-LIFETIME SESSION STATE — a thin binding over the neutral
//! `busbar_kernel::plane_host::SessionScope` (design `plane4-duplex-session.md` §4). One voice session owns ONE durable handle
//! in the process-wide `DurableHandleEngine`, keyed by `(owner, id)`. The owner is load-bearing: a
//! second session bound to the same `id` under a DIFFERENT owner collapses to the exact same
//! indistinguishable refusal (`HandleDenied::NotYours` / `ScopedMutateError::NotYours`) — a foreign
//! owner can neither read, resume, nor evict the handle, and cannot even tell it exists. That
//! anti-enumeration contract is carried up from the engine unchanged; this module only stamps the
//! session's `(owner, id)` into the row and drives open → bump → close.

use busbar_contract::records::{PlaneDisposition, PlaneRecord, RecordStoreResult};
use busbar_kernel::plane::handle_engine::{
    ChainPosition, DurableHandleEngine, HandleEngineError, HandleMeta, Mutation, RehydrateCounts,
    RehydrateOutcome, ScopedMutateError, SealedEvent, SubmitRecord, SweepBounds,
};
use busbar_kernel::plane::store::PlaneStore;
use busbar_kernel::plane_host::SessionScope;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The durable-audit kind stamped on a voice session's records — matches `PLANE_DECLARATION.audit_kind`.
const VOICE_SESSION_KIND: &str = "voice_session";

/// Retain a live session for an hour of idle, an hour past terminal, and cap the working set — plain,
/// generous bounds for a long-lived carrier (the plane's own retention policy, not a wire fact).
fn session_bounds() -> SweepBounds {
    SweepBounds {
        abandon_secs: 3_600,
        terminal_ttl_secs: 3_600,
        max_retained: 4_096,
    }
}

/// THE OPAQUE DURABLE ROW for one voice session — the neutral engine stores it as `Arc<dyn Any>`; the
/// plane owns its shape. Carries the session `(owner, id)` (the engine's scoped key), a monotonic
/// `turns` cursor bumped per settled turn, and whether the session has reached its terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceSessionRow {
    /// The session id — the working-set key (must equal the [`SessionScope::id`]).
    pub id: String,
    /// The principal the session is attributed to (must equal the [`SessionScope::owner`]).
    pub owner: String,
    /// Monotonic turn counter — bumped each metered turn.
    pub turns: u64,
    /// Unix seconds of the last mutation (the retention age key).
    pub updated_at: u64,
    /// Whether the session has settled into its terminal state (gates eviction).
    pub terminal: bool,
    /// The provider's `rtc_<call_id>` correlation key for a browser-WebRTC session — the `Location`
    /// header the SDP broker preserved from `POST /v1/realtime/calls`. It ties the brokered media call
    /// and busbar's sideband control socket to the SAME session, so governance applied here provably
    /// governs the media that flows there. `None` until the SDP broker sets it (and for topologies
    /// with no brokered media call). `#[serde(default)]` so a row written before this field existed
    /// rehydrates cleanly.
    #[serde(default)]
    pub rtc_call_id: Option<String>,
}

impl VoiceSessionRow {
    fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: VOICE_SESSION_KIND.to_string(),
            id: self.id.clone(),
            parent: None,
            seq: self.turns,
            ts: self.updated_at,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            // The durable body IS the row: a boot rehydrate reconstructs the working-set entry from it
            // (see [`rehydrate_sessions`]). An in-memory-only posture (no sink attached) simply never
            // reads it back; the encode is infallible for these scalar fields.
            body: serde_json::to_vec(self).unwrap_or_default(),
        }
    }

    fn meta(&self) -> HandleMeta {
        HandleMeta {
            owner: self.owner.clone(),
            updated_at: self.updated_at,
            terminal: self.terminal,
            cursor: self.turns,
        }
    }

    fn arc(self) -> Arc<dyn std::any::Any + Send + Sync> {
        Arc::new(self)
    }
}

/// A VOICE SESSION'S DURABLE BINDING — the [`SessionScope`] plus the plane's row shape. Open it at
/// session start, bump it per settled turn, close it (owner-gated, terminal-only) at teardown.
pub struct SessionHandle {
    scope: SessionScope,
}

impl SessionHandle {
    /// Bind a session to the durable handle keyed by `id`, attributed to `owner`, in `engine`. Pure
    /// binding — touches the engine only on [`open`](Self::open) / [`bump_turn`](Self::bump_turn) /
    /// [`close`](Self::close). Use to attach to a boot-rehydrated handle, or before [`open`](Self::open)
    /// submits a fresh one.
    #[must_use]
    pub fn bind(
        engine: Arc<DurableHandleEngine>,
        owner: impl Into<String>,
        id: impl Into<String>,
    ) -> Self {
        SessionHandle {
            scope: SessionScope::new(engine, owner, id),
        }
    }

    /// The principal this session's handle is attributed to.
    #[must_use]
    pub fn owner(&self) -> &str {
        self.scope.owner()
    }

    /// The opaque handle id this session is bound to.
    #[must_use]
    pub fn id(&self) -> &str {
        self.scope.id()
    }

    /// OPEN the session's durable handle at genesis, stamping the row with THIS session's `(owner, id)`
    /// — the binding contract the scope documents (a genesis under a diverging owner/id would leave the
    /// session unable to read what it just opened).
    pub fn open(&self, now: u64) -> Result<(), HandleEngineError> {
        let row = VoiceSessionRow {
            id: self.scope.id().to_string(),
            owner: self.scope.owner().to_string(),
            turns: 0,
            updated_at: now,
            terminal: false,
            rtc_call_id: None,
        };
        self.scope.open(
            now,
            session_bounds(),
            |_pos: &ChainPosition| {
                let record = row.record();
                let meta = row.meta();
                Ok(SubmitRecord {
                    id: row.id.clone(),
                    row: row.clone().arc(),
                    meta,
                    row_record: record.clone(),
                    event: Some(SealedEvent {
                        record,
                        tail_hash: format!("voice-genesis-{}", row.id),
                    }),
                })
            },
            // An ACTIVE session idle past `abandon_secs` is ABANDONED TERMINAL by the retention
            // sweep, so the sweep's terminal-TTL rule can then evict it. Opting out (`None`) left
            // every session whose teardown never ran — a dropped socket, a one-shot pass whose
            // sideband never came — ACTIVE for ever: the cap rule evicts only terminal rows, so the
            // working set grew without bound. Explicit teardown ([`SessionHandle::finish`]) is the
            // fast path; this is the backstop that makes it not the only one.
            |_id, row, _pos, now| abandon_idle(row, now),
            // No durable sink attached in this build ⇒ no sweep-time failures to report.
            |_id, _e| {},
        )?;
        Ok(())
    }

    /// Read the current durable row through the engine's SCOPED read — a foreign-owner session is
    /// refused with the one indistinguishable `NotYours`, never learning whether the handle exists.
    pub fn get(&self) -> Option<VoiceSessionRow> {
        self.scope
            .get()
            .ok()
            .and_then(|row| row.downcast_ref::<VoiceSessionRow>().cloned())
    }

    /// BUMP the turn cursor (owner-gated mutate) — the per-turn durable checkpoint. Returns the new
    /// turn count, or the scoped mutate error (`NotYours` for a foreign owner).
    pub fn bump_turn(&self, now: u64) -> Result<u64, ScopedMutateError> {
        let row = self.scope.mutate(|row, _pos| {
            let cur = row
                .downcast_ref::<VoiceSessionRow>()
                .expect("voice session row");
            let mut next = cur.clone();
            next.turns += 1;
            next.updated_at = now;
            Ok(Some(mutation_for(next)))
        })?;
        Ok(row
            .downcast_ref::<VoiceSessionRow>()
            .map(|r| r.turns)
            .unwrap_or_default())
    }

    /// STAMP the `rtc_<call_id>` correlation key (owner-gated mutate) — the SDP broker calls this with
    /// the `Location` header it preserved from `POST /v1/realtime/calls`, so the durable row and the
    /// sideband dial provably name the same brokered media call. A foreign owner is refused with the one
    /// indistinguishable `NotYours`, exactly as every other mutate on this handle.
    pub fn set_rtc_call_id(&self, rtc_call_id: &str, now: u64) -> Result<(), ScopedMutateError> {
        self.scope.mutate(|row, _pos| {
            let cur = row
                .downcast_ref::<VoiceSessionRow>()
                .expect("voice session row");
            let mut next = cur.clone();
            next.rtc_call_id = Some(rtc_call_id.to_string());
            next.updated_at = now;
            Ok(Some(mutation_for(next)))
        })?;
        Ok(())
    }

    /// Drive the session TERMINAL (owner-gated) so it can be evicted — the settle step before close.
    pub fn settle_terminal(&self, now: u64) -> Result<(), ScopedMutateError> {
        self.scope.mutate(|row, _pos| {
            let cur = row
                .downcast_ref::<VoiceSessionRow>()
                .expect("voice session row");
            let mut next = cur.clone();
            next.terminal = true;
            next.updated_at = now;
            Ok(Some(mutation_for(next)))
        })?;
        Ok(())
    }

    /// TEAR the session DOWN: drive it terminal, then evict it — the one call a serving site makes
    /// when its pump returns. Returns `true` when the handle was this session's and is now gone.
    ///
    /// Every serving site used to drop its handle unsettled, so its durable row stayed ACTIVE after
    /// the socket was gone and nothing but the retention sweep could ever end it.
    pub fn finish(&self, now: u64) -> bool {
        self.settle_terminal(now).is_ok() && self.close()
    }

    /// CLOSE the session: evict the terminal handle from the working set (owner-gated, terminal-only),
    /// leaving durable rows behind. Returns `true` only when this session owns the handle AND it was
    /// terminal; a foreign owner or a still-active handle returns `false`.
    pub fn close(&self) -> bool {
        self.scope.close()
    }
}

/// BOOT-REHYDRATE the durable `voice_session` working-set from `store` into `engine` — the
/// [`crate::PLANE_HOOKS`] `hydrate` step, mirroring the A2A task-set restore. Reads every persisted
/// `voice_session` row through the neutral [`DurableHandleEngine::rehydrate`] seam and, per row:
/// installs an ACTIVE session back into the working set, counts (and leaves) a TERMINAL one, and counts
/// (and skips) a row whose durable body cannot be decoded — so one unreadable row never aborts the
/// whole restore. Only a store-level list failure is fatal (propagated). Returns the neutral counts.
///
/// This restores the DURABLE binding a resumed session reattaches to via [`SessionHandle::bind`]; the
/// live carrier/socket of a session cannot survive a restart, so a rehydrated session is a durable
/// record to reattach or reconcile, not a live pump — exactly the A2A task-restore contract.
pub fn rehydrate_sessions(
    engine: &DurableHandleEngine,
    store: &dyn PlaneStore,
) -> RecordStoreResult<RehydrateCounts> {
    engine.rehydrate(store, VOICE_SESSION_KIND, |_store, body| {
        // Decode the row the durable body IS; an undecodable body is counted unreadable, never fatal.
        match serde_json::from_slice::<VoiceSessionRow>(body) {
            Ok(row) if row.terminal => Ok(RehydrateOutcome::Terminal),
            Ok(row) => Ok(RehydrateOutcome::Active {
                id: row.id.clone(),
                meta: row.meta(),
                row: row.clone().arc(),
                // Voice sessions carry no resumable event chain beyond genesis in this build.
                pos: ChainPosition::genesis(),
                event_unreadable: 0,
            }),
            Err(_) => Ok(RehydrateOutcome::Unreadable),
        }
    })
}

/// The retention sweep's transition for an idle ACTIVE voice session: the same row, terminal, stamped
/// at `now`. `None` for a row that is not a voice session's (nothing this plane can speak for).
fn abandon_idle(row: &(dyn std::any::Any + Send + Sync), now: u64) -> Option<Mutation> {
    let cur = row.downcast_ref::<VoiceSessionRow>()?;
    let mut next = cur.clone();
    next.terminal = true;
    next.updated_at = now;
    Some(mutation_for(next))
}

/// Wall-clock Unix seconds — the clock a serving site stamps its teardown with. The retention sweep
/// ages a row by these same seconds, so a teardown stamped on another clock would age wrongly.
#[must_use]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mutation_for(next: VoiceSessionRow) -> Mutation {
    let record = next.record();
    let meta = next.meta();
    Mutation {
        row: Some(next.arc()),
        meta: Some(meta),
        row_record: Some(record),
        event: None,
    }
}
