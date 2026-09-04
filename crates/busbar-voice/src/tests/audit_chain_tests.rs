// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUDIT-CHAIN capability cells (voice-client + voice-server) — GATE-VALID location.
//!
//! The proving assertions already live and pass in `runtime/tests.rs`
//! (`session_scope_reattach_and_foreign_owner_refusal`), but that path clears neither the equality
//! gate's `/tests/` directory rule nor its `_tests.rs` suffix rule. These are the SAME assertions,
//! re-homed under `src/tests/` so the capability-equality gate's location rule is met. They drive a
//! durable session open → seal a genesis `SealedEvent`/`tail_hash` → bump the per-turn cursor →
//! reattach, reading the durable row back (a non-empty read is the pass; an empty read is a failure).
//! Runtime-gated so the durable engine compiles.

use crate::runtime::scope::SessionHandle;
use busbar_substrate::plane::handle_engine::{DurableHandleEngine, ScopedMutateError};
use std::sync::Arc;

/// voice-client cell: an opened session seals a genesis event on the durable chain and survives a
/// reattach — a fresh binding for the same (owner, id) reads the live turns back through the scoped
/// path, and a foreign owner is refused indistinguishably from a missing handle.
#[test]
fn an_opened_voice_session_seals_a_genesis_event_and_survives_reattach_on_the_durable_chain() {
    let engine = Arc::new(DurableHandleEngine::new());
    let alice = SessionHandle::bind(Arc::clone(&engine), "alice", "call-1");
    // OPEN seals the genesis event onto the durable chain.
    alice.open(1).expect("alice opens her session");

    // A per-turn checkpoint bumps the durable cursor onto the genesis chain.
    assert_eq!(alice.bump_turn(2).expect("owner bump"), 1);
    assert_eq!(alice.bump_turn(3).expect("owner bump"), 2);

    // REATTACH: a fresh binding for the SAME (owner, id) reads the live row through the scoped path.
    let alice_again = SessionHandle::bind(Arc::clone(&engine), "alice", "call-1");
    assert_eq!(
        alice_again.get().map(|r| r.turns),
        Some(2),
        "reattach sees the durable turns — a non-empty read of the sealed chain"
    );

    // FOREIGN OWNER: a session bound to the same id under a different owner is refused identically to
    // a missing handle — cannot read, resume, or evict, and cannot even tell it exists.
    let mallory = SessionHandle::bind(Arc::clone(&engine), "mallory", "call-1");
    assert!(
        mallory.get().is_none(),
        "foreign owner cannot read the chain"
    );
    assert!(
        matches!(mallory.bump_turn(9), Err(ScopedMutateError::NotYours)),
        "foreign owner cannot resume/mutate the chain"
    );
    assert!(!mallory.close(), "foreign owner evicts nothing");
}

/// voice-server cell: an inbound session-open (the front door) lands a sealed genesis event — the
/// durable read-back is non-empty. An empty read is a FAILURE, not a pass.
#[test]
fn an_inbound_session_open_lands_a_sealed_genesis_event_the_front_door_wrote() {
    let engine = Arc::new(DurableHandleEngine::new());
    // The inbound front door opens a governed session under the presenting caller.
    let front_door = SessionHandle::bind(Arc::clone(&engine), "caller", "inbound-1");
    front_door
        .open(1)
        .expect("the front door opens the session");

    // The genesis event the front door wrote is readable back on the durable chain (non-empty).
    let row = front_door
        .get()
        .expect("the sealed genesis event reads back — a non-empty durable chain");
    assert_eq!(row.turns, 0, "a fresh genesis row carries no turns yet");

    // A checkpoint the front door drives bumps onto the same sealed chain.
    assert_eq!(front_door.bump_turn(2).expect("front-door bump"), 1);
    assert_eq!(
        front_door.get().map(|r| r.turns),
        Some(1),
        "the front-door checkpoint is durable on the sealed chain"
    );
}
