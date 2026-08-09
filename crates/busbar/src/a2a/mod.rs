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

// PART OF THIS PLANE NOW HAS A PRODUCTION CALLER AND PART OF IT STILL DOES NOT, and the attribute
// below is what keeps the second half honest rather than hidden.
//
// [`plane`] and [`scheduler`] are DRIVEN: `main` lowers `agents:` into a registry and spawns the
// re-verification job, so `verify::reverify_once`, `reverify::due`, `reverify::settle`,
// `registry::apply_anomaly_breaker`, `anomaly::evaluate`, `fetch`, `jws` and `pin` are all reached
// by a running deployment rather than by tests alone.
//
// The RECEIVING hot path is not: `serve`, `inbound`, `catalogue`, `meter`, `task`, `taskstore`,
// `provenance`, `pushnotify` and `verbs` are decisions with no router calling them. They are not
// dead code that nobody wants — they are the parts a wire reader is built ON TOP of, and settling
// them first is deliberate, because a fingerprint whose definition moves after an operator has
// approved one invalidates every approval in the deployment. The attribute stays until the last of
// them is mounted, and shrinking rather than deleting it is how the remaining gap stays visible.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod anomaly;
pub(crate) mod canonical;
pub(crate) mod card;
pub(crate) mod catalogue;
pub(crate) mod config;
pub(crate) mod creds;
pub(crate) mod fetch;
pub(crate) mod inbound;
pub(crate) mod jws;
pub(crate) mod meter;
pub(crate) mod pin;
pub(crate) mod plane;
pub(crate) mod provenance;
pub(crate) mod pushnotify;
pub(crate) mod registry;
pub(crate) mod reverify;
pub(crate) mod scheduler;
pub(crate) mod serve;
pub(crate) mod task;
pub(crate) mod taskstore;
pub(crate) mod transport;
pub(crate) mod verbs;
pub(crate) mod verify;
