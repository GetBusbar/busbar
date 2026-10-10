// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S OWN DECLARATIONS AGREE WITH EACH OTHER — facts asked where the declarations live.
//!
//! Each is a compile-time fact of this crate: a schema nothing can reach, a completed call metered
//! under a class the plane does not have, a meter class sized from a side the door does not report
//! it from, and a claim set whose credential alternatives disagree. None depends on a configuration,
//! a store or a request, so none needs a node to answer it. Contract only — nothing here names the
//! kernel. (The record-leg pin that read legs off the unserved `Plane::verify`/`route` was retired
//! with that impl, finding 12.)

use busbar_contract::ids::ClassDirection;
use busbar_contract::plane::PlaneMeta;
use busbar_plane_mcp::tool_meta::CLASS_TOOL_CALLS;
use busbar_plane_mcp::{tool_records as records, McpPlane};

/// Every schema the plane declares carries at least one operation — a schema with none is one no
/// leg can ever reach, and a record written under it is a record nothing reads back.
#[test]
fn every_declared_record_schema_carries_operations() {
    let schemas = <McpPlane as PlaneMeta>::RECORD_SCHEMAS;
    assert!(
        !schemas.is_empty(),
        "non-vacuity: the plane declares record schemas, and an empty list answers nothing"
    );
    for schema in schemas {
        assert!(
            !records::operations_for(*schema).is_empty(),
            "the plane declares the unreachable schema {schema}"
        );
    }
}

/// The class a completed call is metered under is one the plane declares.
///
/// The plane's served path ledgers each answered call under this class; a class the declaration
/// does not carry is one no rate-card entry, class cap or usage row can name.
#[test]
fn the_plane_declares_the_class_a_completed_call_is_metered_under() {
    assert!(
        <McpPlane as PlaneMeta>::METER_CLASSES
            .iter()
            .any(|class| class.key == CLASS_TOOL_CALLS),
        "the mcp plane does not declare the class {CLASS_TOOL_CALLS}"
    );
}

/// Every claim that carries a credential scheme declares the same alternatives, so there is ONE
/// set the authenticate step narrows within, whichever claim a request arrived on.
#[test]
fn every_credentialed_claim_declares_the_same_scheme_alternatives() {
    let credentialed: Vec<&[&'static str]> = <McpPlane as PlaneMeta>::CLAIMS
        .iter()
        .filter(|claim| claim.scheme.is_some())
        .map(|claim| claim.scheme_alternatives)
        .collect();
    assert!(
        !credentialed.is_empty(),
        "non-vacuity: the plane declares at least one claim that carries a scheme"
    );
    let first = credentialed[0];
    for alternatives in &credentialed {
        assert_eq!(
            alternatives, &first,
            "the mcp plane's claims declare different scheme alternatives"
        );
    }
}

/// Both declared meter classes are sized from the ANSWER, because the served door reports both off
/// the answer: a call is counted once the upstream has answered the round, and the byte count is
/// the answered document's own length (`tool_door.rs`, `Pending::counted`). A class that declared
/// the request and was reported from the answer would have a rate card pricing one side of the
/// exchange at the size of the other. The surviving half of the retired
/// `the_metering_step_reports_what_it_read`, which drove the unserved `Plane::meter`.
#[test]
fn both_meter_classes_are_sized_from_the_answer() {
    let classes = <McpPlane as PlaneMeta>::METER_CLASSES;
    assert!(
        !classes.is_empty(),
        "non-vacuity: the plane declares meter classes"
    );
    for class in classes {
        assert_eq!(
            class.direction,
            ClassDirection::Response,
            "{} is reported off the answer and declares another side",
            class.key
        );
    }
}
