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

// THE RECEIVING HOT PATH NOW HAS A ROUTER. What used to be a plane-wide `allow(dead_code)` with a
// list of nine unmounted modules in its prose is gone from this file, because the thing it was
// describing is gone: [`ingress`] mounts `GET`/`POST /a2a/agents/{agent_id}` and this plane's RFC
// 9728 metadata document, and a request arriving there is authenticated by the shared middleware
// against [`crate::plane::PlaneAdmission`], authorised by [`inbound::authorize`], filtered by
// [`catalogue::inbound_catalogue`], attributed by [`meter::Attribution`], recorded through
// [`task`]/[`taskstore`]/[`provenance`], and served through [`serve::rewrite_card`].
//
// TWELVE OF THIS PLANE'S TWENTY-FOUR MODULES still contain surface with no production caller, and
// each now carries its OWN narrowed attribute at the top of its own file, stating what is driven and
// what is not. Twelve do not, and are warning-clean for the first time: `ingress`, `serve`,
// `inbound`, `plane`, `scheduler`, `reverify`, `verify`, `fetch`, `anomaly`, `jws`, `card` and
// `canonical`. The residue is coherent rather than scattered — it is the DELEGATING direction, the
// operator-driven trust verbs, push-notification delivery, and the task verbs a completion relay
// would drive.
//
// Narrowing this way is the point. A plane-wide attribute made an unused item ANYWHERE here
// invisible, including in the modules a request now goes through; per-file, a new gap in a mounted
// module is a warning again, and the file that still has one has to say why.

pub(crate) mod anomaly;
pub(crate) mod canonical;
pub(crate) mod card;
pub(crate) mod catalogue;
pub(crate) mod config;
pub(crate) mod creds;
pub(crate) mod fetch;
pub(crate) mod inbound;
pub(crate) mod ingress;
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
