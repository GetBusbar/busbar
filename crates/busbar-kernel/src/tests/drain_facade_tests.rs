// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPILE-TIME PROOF for the W1.e drain facade (DECISIONS #27b).
//!
//! Every Teller workflow step (`qa/teller-steps.json`: arrival, decode, authenticate, verify,
//! approve, admit, route, meter, audit, exit) must be importable through the single stable
//! per-step re-export surface in [`crate::drain`]. If any step's facade path stops resolving —
//! because a step's core implementation module was renamed or relocated WITHOUT updating the one
//! facade line — this module fails to compile. That is the whole guarantee: consumers name the
//! stable `busbar_kernel::drain::<step>::…` path, so a step relocates to its unit crate in ANY order
//! by editing exactly one line in `drain.rs` and nothing downstream moves.
//!
//! These are `use` paths, not behavior: the facade is a pure re-export (additive/dormant), so this
//! proof exercises the SEAM, not the shipped execution path (which is byte-untouched).

// ── one representative re-export per step, proving the facade resolves to core's real module ──
#[allow(unused_imports)]
use crate::drain::{
    admit::{cost as _admit_cost, limits as _admit_limits},
    approve::governance as _approve_governance,
    arrival::{ingress as _arrival_ingress, limits as _arrival_limits},
    audit::{
        audit as _audit_chain, audit_ring as _audit_ring, calllog as _audit_calllog,
        lineage as _audit_lineage,
    },
    authenticate::{auth as _auth, auth_cache as _auth_cache},
    decode::{ingress as _decode_ingress, proto as _decode_proto},
    exit::{calllog as _exit_calllog, ingress as _exit_ingress},
    meter::billing as _meter_billing,
    route::{
        egress as _route_egress, egress_auth as _route_egress_auth, failover as _route_failover,
        proto as _route_proto, proxy as _route_proxy,
    },
    verify::{breaker as _verify_breaker, trust as _verify_trust},
};

/// Naming each facade path in an executable position forces the compiler to resolve the whole
/// per-step surface, so this test going green IS the "every core step importable via the new
/// facade module" proof. It asserts nothing at runtime — the compile is the assertion.
#[test]
fn every_teller_step_is_importable_through_the_drain_facade() {
    // The `use` block above names every step's facade path; if a step were missing from the facade
    // the crate would not compile and this test could not exist. The compile is the assertion.
}

/// THE FACADE DOES NOT DOCUMENT A SWAP THAT ALREADY HAPPENED ELSEWHERE (item 289).
///
/// The header used to describe relocating the authenticate step as a pending one-line edit here
/// ("swap `pub use crate::auth;` for `pub use busbar_kernel_identity;`") and to call itself the
/// target consumers migrate onto. The relocated crate was already live in the composition root and
/// its consumers went around the facade, so a maintainer reading it concluded the step had not moved
/// and fixed only `crate::auth`. While the binary depends on the relocated crate, the facade must say
/// so and must not present that swap as still to come.
#[test]
fn the_facade_names_the_relocated_authenticate_step_it_does_not_point_at() {
    let binary = include_str!("../../../busbar/Cargo.toml");
    let facade = include_str!("../drain.rs");
    let relocated_is_live = binary
        .lines()
        .any(|l| l.trim_start().starts_with("busbar-kernel-identity"));
    if !relocated_is_live {
        return;
    }
    assert!(
        !facade.contains("for `pub use busbar_kernel_identity;`"),
        "drain.rs still presents the authenticate swap as pending while the binary runs the relocated crate"
    );
    assert!(
        !facade.contains("stable target consumers migrate ONTO"),
        "drain.rs still claims consumers migrate onto it; they migrated around it"
    );
    assert!(
        facade.contains("ALREADY RELOCATED") && facade.contains("`busbar-kernel-identity`"),
        "drain.rs's authenticate step must say it already runs from `busbar-kernel-identity`"
    );
}
