// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE D2 LEASE BILLING ORACLE — a byte/scalar-pinned regression backstop for the voice plane's
//! money path, the sibling of the LLM-plane money oracles (`crossproto_delivery_billing_tests`,
//! `on_exhausted`, `usage_tap`; `egress_differential` is TLS/SPKI parity, NOT billing). It mirrors that
//! rigor: it drives one full `cost_reserve` → `price_usage` → `cost_settle` (×N) → exhaust-at-cap →
//! hard-close SEQUENCE over the PRODUCTION host lease (`HostMeteringPort` + [`MockMeteringHost`], the
//! same shape `build_runtime` binds), pinning the EXACT nanodollar scalar at every step so any drift in
//! the lease arithmetic reddens CI with a clear expected-vs-actual.
//!
//! This is NOT a re-test of the per-unit lease cases the runtime/topology suites already cover
//! (`local_lease_exhausts_at_cap_and_refuse_all_denies`, `host_lease_reserves_settles_and_hard_closes_at_the_real_cap`,
//! `host_port_refuse_all_fails_the_session_closed`, `abnormal_close_releases_the_reserve_via_the_by_value_guard`).
//! It is ONE end-to-end pinned narrative of a session's whole money life — the reserved estimate+fee, the
//! priced per-turn debits, the running settled balance, the cap decision, the terminal closed state, plus
//! the two fail-closed legs (refuse-all denies at the door; the by-value guard releases the reserve on
//! abnormal close with no double-refund). A prior 4-model audit CONFIRMED this math is clean; this oracle
//! PINS it so it stays clean.
//!
//! The [`MockMeteringHost`] prices every reserved usage unit at 1 nano, so a turn's folded usage_units
//! sum IS its nanodollar cost — the arithmetic is legible in the assert, and the pinned scalar traces
//! straight back to the input frame.

use crate::ir::usage::IrDuplexUsage;
use crate::runtime::metering::{
    HostMeteringPort, LeaseState, MeteringLease, MeteringPort, MockMeteringHost,
};
use busbar_substrate::plane_host::MeteringHost;
use std::sync::Arc;

/// A priced per-turn increment: fold an `IrDuplexUsage` frame onto the four reserved keys, price it
/// through the lease's host pricing leg (1 nano/unit), and return the exact nanodollar debit. This is the
/// `price_usage`-before-`settle` step the live per-frame handler runs; the oracle settles EXACTLY this.
fn priced(lease: &dyn MeteringLease, usage: IrDuplexUsage) -> u64 {
    lease
        .price_usage("gpt-realtime", &usage.to_billing_usage())
        .expect("a priced model returns Some")
}

/// THE ORACLE — one session's whole money life, every scalar pinned.
#[test]
fn voice_d2_lease_billing_oracle() {
    // ── LEG 0 — REFUSE-ALL DENIES AT THE DOOR (fail closed, zero charge) ────────────────────────────
    // A `Some(0)` cap is a refuse-all budget: the reserve is denied, the session never opens, and NO
    // lease is ever minted — the money path cannot charge a byte against a zero budget.
    {
        let host = Arc::new(MockMeteringHost::default());
        let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);
        assert!(
            port.reserve(900, 100, Some(0)).is_none(),
            "refuse-all (Some(0)) cap denies the reserve — the session never opens"
        );
        assert_eq!(
            host.minted_count(),
            0,
            "a refused session mints NO lease: zero reserve, zero fee, zero charge"
        );
    }

    // ── THE SESSION — reserve → settle ×3 → exhaust → hard-close ─────────────────────────────────────
    let host = Arc::new(MockMeteringHost::default());
    let port = HostMeteringPort::new(Arc::clone(&host) as Arc<dyn MeteringHost>);

    // ── LEG 1 — RESERVE: estimate + flat fee debited ONCE up front ──────────────────────────────────
    // estimate = 1_000 nanos (the coarse up-front over-estimate) and fee = 200 nanos (the once-per-session
    // flat fee). cap = 15 nanos is the TRUE budget ceiling — deliberately INDEPENDENT of the reserved
    // audit tap: exhaustion is judged against the cap ONLY, never against `reserved`, so the fee is never
    // double-counted into the ceiling.
    let estimate = 1_000u64;
    let fee = 200u64;
    let cap = 15u64;
    let lease = port
        .reserve(estimate, fee, Some(cap))
        .expect("a real (non-refuse-all) cap opens the lease");

    // reserved = estimate + fee = 1_000 + 200 = 1_200. WHY: the reserve debits the over-estimate PLUS the
    // flat fee exactly once at session open, as a single audit tap; the fee lives in `reserved`, NOT in
    // the cap.
    assert_eq!(
        host.reserved_of(1),
        Some(1_200),
        "reserved = estimate(1_000) + fee(200) = 1_200, charged once at open"
    );
    // Nothing has been settled or closed yet.
    assert_eq!(
        lease.settled_nanos(),
        0,
        "no turn settled before the first frame"
    );
    assert_eq!(
        host.closed_ids(),
        Vec::<u64>::new(),
        "the lease is open — not closed"
    );

    // ── LEG 2 — SETTLE turn 1 (under cap → Live) ────────────────────────────────────────────────────
    // Turn 1 usage: audio_out 3 + text_out 4 fold onto `output` = 7 units → priced 7 nanos.
    let d1 = priced(
        &*lease,
        IrDuplexUsage {
            audio_out: 3,
            text_out: 4,
            ..IrDuplexUsage::default()
        },
    );
    assert_eq!(
        d1, 7,
        "turn 1: output (3+4) priced at 1 nano/unit = 7 nanos"
    );
    assert_eq!(
        lease.settle(d1),
        LeaseState::Live,
        "settled 7 < cap 15 → Live (carrier stays open)"
    );
    assert_eq!(
        lease.settled_nanos(),
        7,
        "running balance after turn 1 = 0 + 7 = 7"
    );
    // The reserve/fee audit tap is UNTOUCHED by settle — the fee is not re-debited per turn.
    assert_eq!(
        host.reserved_of(1),
        Some(1_200),
        "reserved unchanged by settle — the flat fee is charged once, never per-turn"
    );

    // ── LEG 3 — SETTLE turn 2 (still under cap → Live) ──────────────────────────────────────────────
    // Turn 2 usage: audio_out 2 → `output` = 2, text_in 3 → `input` = 3, total 5 units → priced 5 nanos.
    let d2 = priced(
        &*lease,
        IrDuplexUsage {
            audio_out: 2,
            text_in: 3,
            ..IrDuplexUsage::default()
        },
    );
    assert_eq!(
        d2, 5,
        "turn 2: output(2) + input(3) priced at 1 nano/unit = 5 nanos"
    );
    assert_eq!(
        lease.settle(d2),
        LeaseState::Live,
        "settled 12 < cap 15 → Live"
    );
    assert_eq!(
        lease.settled_nanos(),
        12,
        "running balance after turn 2 = 7 + 5 = 12"
    );

    // ── LEG 4 — SETTLE turn 3 CROSSES the cap → Exhausted → HARD CLOSE ──────────────────────────────
    // Turn 3 usage: audio_out 5 → `output` = 5 units → priced 5 nanos. 12 + 5 = 17 ≥ cap 15.
    let d3 = priced(
        &*lease,
        IrDuplexUsage {
            audio_out: 5,
            ..IrDuplexUsage::default()
        },
    );
    assert_eq!(d3, 5, "turn 3: output(5) priced at 1 nano/unit = 5 nanos");
    assert_eq!(
        lease.settle(d3),
        LeaseState::Exhausted,
        "settled 17 ≥ cap 15 → Exhausted — the plane MUST hard-close the carrier"
    );
    assert_eq!(
        lease.settled_nanos(),
        17,
        "running balance after turn 3 = 12 + 5 = 17"
    );
    // Exhaustion is judged against the cap (15), NEVER against reserved (1_200): reserved is 80× the cap
    // yet plays no part in the exhaustion decision.
    assert!(
        LeaseState::Exhausted.must_close(),
        "Exhausted demands a carrier hard-close"
    );

    // ── LEG 5 — IDEMPOTENT AFTER EXHAUSTION (once dry, stays dry) ────────────────────────────────────
    // A late settle that races the hard-close still accrues its exact increment but the lease stays
    // Exhausted — it never flips back to Live, so no post-exhaustion turn escapes the close.
    assert_eq!(
        lease.settle(1),
        LeaseState::Exhausted,
        "a settle past exhaustion stays Exhausted (17 + 1 = 18 ≥ cap 15)"
    );
    assert_eq!(
        lease.settled_nanos(),
        18,
        "the late increment still accrues exactly: 17 + 1 = 18"
    );

    // ── LEG 6 — TERMINAL CLOSED STATE: the by-value guard releases the reserve ONCE ──────────────────
    // The topology `run()` frame owns a by-value `LeaseCloseGuard`; dropping it (as run() does on EVERY
    // exit — EOF, the hard-close race, or a panic unwinding through it) closes the host lease
    // deterministically, decoupled from the settle handle's refcount-gated `Drop`.
    let guard = lease.close_guard();
    assert_eq!(
        host.closed_ids(),
        Vec::<u64>::new(),
        "minting the guard does not close — the lease is still open"
    );
    drop(guard); // exactly what run() does on exit
    assert_eq!(
        host.closed_ids(),
        vec![1],
        "the by-value guard closed lease 1 exactly once — the reserve is released"
    );
    assert_eq!(
        host.reserved_of(1),
        None,
        "the closed lease's registry entry is gone — no reserve leaks"
    );

    // ── LEG 7 — NO DOUBLE-REFUND: the settle handle's later drop is a harmless no-op ─────────────────
    // The lingering `HostLease` handle's own `Drop` fires cost_close a SECOND time; the registry entry is
    // already gone, so it is an idempotent `None` — the reserve is not released (refunded) twice.
    drop(lease);
    assert_eq!(
        host.closed_ids(),
        vec![1],
        "the settle handle's later close is idempotent — lease 1 closed ONCE, no double-refund"
    );
}
