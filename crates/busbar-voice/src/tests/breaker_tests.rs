// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-PROVIDER, the voice-client dial leg — the `breaker-trip` / `breaker-fastfail` cells,
//! DIRECT-DRIVEN. No live serving path calls [`dial_provider`] yet, so these prove the cells by
//! driving the wired dial path directly against the substrate's in-memory fixture host, whose
//! `(pool, lane)` breaker cells sit behind the same `breaker_admit` / `breaker_record_*` seam the
//! production dispatch admits/records through (and are read back off the same host).
//!
//! 1. TRIP: a provider dial busbar's own net-guard refuses is a DEFINITIVE (hard-down) failure, so it
//!    records into the ONE host cell and OPENS it on the first failure.
//! 2. FAST-FAIL: with that cell OPEN, a fresh dial is refused at admission BEFORE any socket — the
//!    fast-fail leg, with the cell's own cooldown as `Retry-After`.
//!
//! RED before the wiring: `dial_provider` never touched the breaker at all, so a dead provider left
//! no cell to trip and a fresh dial waited out the full dial timeout against a target already known
//! down.

use crate::topology::{dial_provider, stream_breaker_key, DialProviderError};
use busbar_substrate::breaker::{CanonicalSignal, StatusClass};
use busbar_substrate::net_guard::GuardPolicy;
use busbar_substrate::plane_host::BreakerHost;
use busbar_substrate::store::BreakerState;
use busbar_substrate::testkit::fixture_host::FixtureHost;

/// A canonical hard-down signal — the disposition a definitive provider failure (auth/billing, or a
/// busbar-side guard refusal) folds to, which OPENS the cell on the first record.
fn hard_down() -> CanonicalSignal {
    CanonicalSignal {
        class: StatusClass::Auth,
        provider_signal: None,
        retry_after: None,
    }
}

#[tokio::test]
async fn a_hard_down_provider_records_into_the_core_cell_and_opens_it() {
    let host = FixtureHost::new();
    let pool = stream_breaker_key("openai-realtime");

    // The cell starts Closed — no failure recorded yet.
    assert_eq!(
        host.breaker_state(&pool, 0),
        BreakerState::Closed,
        "the provider cell is Closed before any dial"
    );

    // A dial busbar's OWN net-guard refuses (a public loopback under the fail-closed default is an
    // internal target) is a DEFINITIVE failure: `dial_provider` records the hard-down signal into the
    // ONE host cell through the host seam, and the cell OPENS on this first failure.
    let refused = dial_provider(&host, &pool, 0, "wss://127.0.0.1/", GuardPolicy::default())
        .await
        .err();
    assert!(
        matches!(refused, Some(DialProviderError::Dial(_))),
        "the guard-refused dial fails: {refused:?}"
    );
    assert!(
        matches!(host.breaker_state(&pool, 0), BreakerState::Open { .. }),
        "the provider's host cell must be Open after a definitive dial failure — the record wired \
         into dial_provider fired"
    );
}

#[tokio::test]
async fn a_tripped_provider_cell_refuses_before_the_dial() {
    let host = FixtureHost::new();
    let pool = stream_breaker_key("openai-realtime");

    // TRIP the cell through the same host seam a dial-leg failure records through.
    host.breaker_record_signal(&pool, 0, &hard_down());
    assert!(
        matches!(host.breaker_state(&pool, 0), BreakerState::Open { .. }),
        "the cell is Open (tripped) before the fresh dial"
    );

    // A fresh dial against the tripped cell is refused at ADMISSION — `dial_provider` returns
    // `BreakerOpen` with the cell's own cooldown, and NEVER dials (the target below is unreachable; a
    // `Connect`/`Dial` error here would prove the admit did NOT fast-fail).
    let refused = dial_provider(
        &host,
        &pool,
        0,
        "ws://127.0.0.1:9/",
        GuardPolicy {
            allow_private: true,
            allow_plaintext: true,
            ..GuardPolicy::default()
        },
    )
    .await
    .err();
    match refused {
        Some(DialProviderError::BreakerOpen { retry_after_secs }) => {
            assert!(
                retry_after_secs >= 1,
                "the fast-fail carries the cell's own Retry-After"
            );
        }
        other => panic!("a tripped cell must fast-fail BreakerOpen before the dial, got {other:?}"),
    }
}
