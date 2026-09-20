// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPILE-TIME PROOF for the W1.e drain facade (DECISIONS #27b).
//!
//! Every Teller workflow step (`qa/teller-steps.json`: arrival, decode, authenticate, verify,
//! approve, admit, route, meter, audit, exit) must be importable through the single stable
//! per-step re-export surface in [`crate::drain`]. If any step's facade path stops resolving —
//! because a step's core implementation module was renamed or relocated WITHOUT updating the one
//! facade line — this module fails to compile. That is the whole guarantee: consumers name the
//! stable `busbar_core::drain::<step>::…` path, so a step relocates to its unit crate in ANY order
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
