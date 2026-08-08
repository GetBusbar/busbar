// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE: busbar-owned canonical types, and this plane's instantiation of the plane-neutral
//! trust lifecycle.
//!
//! ## The canonical type is ours, and that is a ruling rather than a taste
//!
//! A plane owns ONE canonical internal type: protocol in, canonical type, protocol out. For A2A that
//! type is busbar-owned structs MIRRORING the A2A specification, never a third party's generated
//! wire types. The protocol is versioned and moving, and a generated type would let a specification
//! revision ripple out of the reader and into the registry, the catalogue cache and the audit
//! records. Mirroring contains a revision to the edge.
//!
//! A2A has ONE wire format today, so it earns no superset intermediate representation. The rule is
//! that a plane earns one at its SECOND wire format and not before.
//!
//! ## What this plane does NOT rebuild
//!
//! The trust lifecycle. [`crate::trust`] is the plane-neutral machine, written with the pinned
//! artifact as a type parameter; this plane supplies an artifact ([`pin::CardPin`]) and nothing else.
//! `tests/reuse_tests.rs` drives one transition table over this plane's REAL artifact and a
//! single-value transport pin of the shape the sibling plane offers, so the claim that the machine
//! generalised is a test over production code rather than an assertion nobody can check.

// NO PRODUCTION CALLER YET, and deliberately so, matching the posture of the lifecycle this plane
// parameterises. The canonical form and the identity pin are what a wire reader, a registry section
// and an admin verb are each built ON TOP of, and they are the parts worth settling first: a
// fingerprint whose definition moves after an operator has approved one invalidates every approval
// in the deployment.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod anomaly;
pub(crate) mod canonical;
pub(crate) mod card;
pub(crate) mod jws;
pub(crate) mod pin;
