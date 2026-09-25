// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S OWN DECLARATIONS AGREE WITH EACH OTHER — four facts asked where the declarations
//! live.
//!
//! Each of the four is a compile-time fact of this crate: a schema nothing can reach, a leg naming
//! an operation its schema never declared, a completed call metered under a class the plane does not
//! have, and a claim set whose credential alternatives disagree. None depends on a configuration, a
//! store or a request, so none needs a node to answer it: a test that runs on every build of this
//! crate answers each one before any binary is linked. Contract only — nothing here names the
//! kernel. (The composition root's pre-unification mcp unit asked the same four at boot, over the
//! same constants.)
//!
//! The leg check reads the legs off the plane's own `verify` and `route` for every operation class
//! it declares — this crate's test seal builds the unit reaching the plan needs — and keeps a
//! written-down table as the pin those legs must equal, so a plan that starts or stops touching a
//! record is a reviewed change.

mod common;

use std::collections::BTreeSet;

use busbar_contract::dest::DestinationFacts;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::plane::{Plane, PlaneMeta};
use busbar_plane_mcp::meta::CLASS_TOOL_CALLS;
use busbar_plane_mcp::{records, McpPlane};
use common::Scaffold;

/// Every record leg this plane's plans reach, written down.
///
/// The pin the plans are compared against, in both directions: a plan that starts reaching a pair
/// not listed here, or stops reaching one that is, is a change to what an operation touches in the
/// node's own records, and it is reviewed here rather than discovered in a store.
const PLANNED_LEGS: &[(RecordSchemaId, &str)] = &[
    (records::SCHEMA_CATALOGUE, records::OP_GET),
    (records::SCHEMA_CATALOGUE, records::OP_PUT),
    (records::SCHEMA_CATALOGUE, records::OP_SCAN),
    (records::SCHEMA_DEMOTION, records::OP_GET),
    (records::SCHEMA_DEMOTION, records::OP_SCAN),
    (records::SCHEMA_APPROVAL, records::OP_REDEEM),
    (records::SCHEMA_CALL, records::OP_APPEND),
    (records::SCHEMA_TASK, records::OP_GET),
    (records::SCHEMA_TASK, records::OP_PUT),
    (records::SCHEMA_SETTINGS, records::OP_GET),
];

/// The record legs the plane itself names, read off `verify` and `route` for every operation class
/// it declares.
fn reached_record_legs() -> BTreeSet<(&'static str, &'static str)> {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let mut reached = BTreeSet::new();
    for op in <McpPlane as PlaneMeta>::OP_CLASSES {
        let unit = busbar_contract::unit::Unit::new(
            &seal,
            busbar_contract::UnitKey::new(1),
            busbar_contract::unit::Origin::Client,
            None,
            None,
            busbar_contract::wire::Direction::Inbound,
            Some(common::principal()),
            *op,
            busbar_contract::bounded::Ir::new(b"{}", &[]),
            busbar_contract::bounded::Facts::new(),
            None,
        );
        let sealed = plane.verify(&unit, &ctx);
        let plan = plane.route(&unit, &ctx);
        for destination in
            std::iter::once(&sealed).chain(plan.legs.as_slice().iter().map(|leg| &leg.destination))
        {
            if let DestinationFacts::PlaneRecord { schema, op } = destination {
                reached.insert((schema.as_str(), *op));
            }
        }
    }
    reached
}

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

/// Every record leg the plane's own plans reach names an operation its schema declares, the legs
/// reached are exactly the written-down set, and every declared schema is reached by some plan.
///
/// A leg naming an undeclared operation would be refused by the trust unit on every request that
/// planned it: an operation whose plan depends on that refusal is an operation that never works.
#[test]
fn every_record_leg_the_plans_reach_is_one_its_schema_declares() {
    let reached = reached_record_legs();
    for (schema, op) in &reached {
        assert!(
            records::operations_for(RecordSchemaId::new(schema)).contains(op),
            "a route leg names an undeclared {op} on {schema}"
        );
    }
    let pinned: BTreeSet<(&str, &str)> = PLANNED_LEGS
        .iter()
        .map(|(schema, op)| (schema.as_str(), *op))
        .collect();
    assert_eq!(
        reached, pinned,
        "the record legs the plans reach moved; the written-down set is reviewed with them"
    );
    for (schema, op) in PLANNED_LEGS {
        assert!(
            records::operations_for(*schema).contains(op),
            "the written-down leg {op} on {schema} is not declared"
        );
    }
    for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
        assert!(
            reached.iter().any(|(s, _)| *s == schema.as_str()),
            "{schema} is declared and no plan reaches it"
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
