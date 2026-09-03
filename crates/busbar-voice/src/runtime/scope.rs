// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION-LIFETIME SESSION STATE — a thin binding over the neutral
//! `busbar_substrate::plane_host::SessionScope` (design `plane4-duplex-session.md` §4). One voice session owns ONE durable handle
//! in the process-wide `DurableHandleEngine`, keyed by `(owner, id)`. The owner is load-bearing: a
//! second session bound to the same `id` under a DIFFERENT owner collapses to the exact same
//! indistinguishable refusal (`HandleDenied::NotYours` / `ScopedMutateError::NotYours`) — a foreign
//! owner can neither read, resume, nor evict the handle, and cannot even tell it exists. That
//! anti-enumeration contract is carried up from the engine unchanged; this module only stamps the
//! session's `(owner, id)` into the row and drives open → bump → close.

use busbar_api::{PlaneDisposition, PlaneRecord};
use busbar_substrate::plane::handle_engine::{
    ChainPosition, DurableHandleEngine, HandleEngineError, HandleMeta, Mutation, ScopedMutateError,
    SealedEvent, SubmitRecord, SweepBounds,
};
use busbar_substrate::plane_host::SessionScope;
use std::sync::Arc;

/// The durable-audit kind stamped on a voice session's records — matches `PLANE_DECL.audit_kind`.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
            body: Vec::new(),
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
            // No sweep-time abandon transition for a voice session; teardown is explicit.
            |_id, _row, _pos, _now| None,
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

    /// CLOSE the session: evict the terminal handle from the working set (owner-gated, terminal-only),
    /// leaving durable rows behind. Returns `true` only when this session owns the handle AND it was
    /// terminal; a foreign owner or a still-active handle returns `false`.
    pub fn close(&self) -> bool {
        self.scope.close()
    }
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
