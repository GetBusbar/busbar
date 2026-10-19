// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (Q128 plugin-loader u68 HIGH, the L1 ruling): transport is one bidirectional kind, and each
//! transport DECLARES in its tail every op it serves (accept, dial, detach, adopt). The suite
//! exercises every declared op, asserts every undeclared op refuses, never lets a framer pass by
//! refusing an op it declared, and holds a spec-required table: a scheme whose spec requires an op
//! (http and https serve inbound) is RED when its transport does not declare it. A transport that
//! declares no op is not judged yet.

use serde_json::json;

use busbar_contract::abi::transport::{
    FACT_ACCEPTS as ACCEPTS, FACT_ADOPTS as ADOPTS, FACT_DETACHES as DETACHES, FACT_DIALS as DIALS,
};

use super::{declared_ops_faults, OP_BITS};

/// The inputs of a framer that frames both sides and gives an upgrade up and takes one.
fn both_sides() -> serde_json::Value {
    json!({
        "dial": { "emit": "e", "wire": "w", "ingest": "", "frames": [] },
        "refuse": { "bytes": "r", "wire": "w" },
        "detach": { "ingest": "i", "detached": "d" },
        "adopt": { "leftover": "l", "frames": [] },
    })
}

/// The inputs of a framer that frames dialled connections only.
fn dial_only() -> serde_json::Value {
    json!({
        "dial": { "emit": "e", "wire": "w", "ingest": "", "frames": [] },
        "refuse": "refused",
        "detach": "refused",
        "adopt": "refused",
    })
}

#[test]
fn red_a_transport_that_declares_no_op_is_not_judged_yet() {
    assert_eq!(OP_BITS, ACCEPTS | DIALS | DETACHES | ADOPTS);
    assert!(declared_ops_faults(0, &["http"], &dial_only()).is_empty());
}

#[test]
fn red_a_framer_never_passes_by_refusing_an_op_it_declared() {
    let faults = declared_ops_faults(ACCEPTS | DIALS, &["tcp-frame"], &dial_only());
    assert!(
        faults.iter().any(|f| f.contains("accept")),
        "a declared accept stated refused passes: {faults:?}"
    );
    let mut k = both_sides();
    k["detach"] = json!("refused");
    let faults = declared_ops_faults(OP_BITS, &["tcp-frame"], &k);
    assert!(faults.iter().any(|f| f.contains("detach")), "{faults:?}");
}

#[test]
fn red_an_undeclared_op_must_refuse() {
    // Detach and adopt framed, but not declared: the suite would exercise ops the transport does
    // not state.
    let faults = declared_ops_faults(ACCEPTS | DIALS, &["tcp-frame"], &both_sides());
    assert!(faults.iter().any(|f| f.contains("detach")), "{faults:?}");
    assert!(faults.iter().any(|f| f.contains("adopt")), "{faults:?}");
}

#[test]
fn red_a_scheme_whose_spec_requires_inbound_must_declare_accept() {
    let faults = declared_ops_faults(DIALS, &["http", "https"], &dial_only());
    assert!(
        faults
            .iter()
            .any(|f| f.contains("http") && f.contains("accept")),
        "an http framer that declares no accept side passes: {faults:?}"
    );
    let mut k = both_sides();
    k["detach"] = json!("refused");
    k["adopt"] = json!("refused");
    assert!(
        declared_ops_faults(ACCEPTS | DIALS, &["http", "https"], &k).is_empty(),
        "a framer serving both sides of http is judged whole"
    );
}

#[test]
fn red_a_consistent_declaration_has_no_fault() {
    assert!(declared_ops_faults(OP_BITS, &["ws"], &both_sides()).is_empty());
}
