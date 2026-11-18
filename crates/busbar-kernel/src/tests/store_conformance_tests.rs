// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's in-memory store keeps the contract every store keeps: the shared Store v4 conformance
//! cases (`persistence::conformance`) run against it here, each over a fresh dataset, as
//! every store's suite runs them against its real backend. Two cases are core's own: the
//! long-horizon no-growth run (a million commits, which take seconds in memory and hours against
//! a database) and the counter-wrap case at every width boundary.

use busbar_contract::persistence::conformance as cases;

use crate::real_store::memory_backend::MemoryBackend;

#[tokio::test]
async fn detached_original_after_reuse() {
    cases::detached_original_after_reuse(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn initialize_lost_reply() {
    cases::initialize_lost_reply(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn initialize_race_lost_reply() {
    cases::initialize_race_lost_reply(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn register_race() {
    cases::register_race(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn duplicate_and_conflict_replay() {
    cases::duplicate_and_conflict_replay(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn zombie_fenced_in_doubt() {
    cases::zombie_fenced_in_doubt(&MemoryBackend::default()).await;
}

#[tokio::test]
async fn clean_exit_and_crash() {
    cases::clean_exit_and_crash(&MemoryBackend::default()).await;
}

/// The shared count, as every store runs it.
#[tokio::test]
async fn no_growth() {
    assert!(
        cases::no_growth(
            &MemoryBackend::default(),
            cases::NO_GROWTH_COMMITS,
            cases::NO_GROWTH_PEAK
        )
        .await
    );
}

/// The long horizon: a million commits, the bound asserted at every cycle, the clock jumped at
/// the midpoint.
#[tokio::test]
async fn no_growth_over_a_long_horizon() {
    assert!(
        cases::no_growth(
            &MemoryBackend::default(),
            cases::LONG_HORIZON_COMMITS,
            cases::NO_GROWTH_PEAK
        )
        .await
    );
}

#[tokio::test]
async fn counter_wrap() {
    cases::counter_wrap(&MemoryBackend::default()).await;
}
