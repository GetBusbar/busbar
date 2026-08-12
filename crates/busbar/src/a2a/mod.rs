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
// AND THE ROUTER NOW RELAYS. [`relay`] is the hop `ingress::rpc` makes to the registered backend
// agent: it guards and pins the target through the SAME `fetch::resolve_and_pin` the card fetch
// uses, RE-ASKS the trust question against the live registry immediately before the socket so a
// mid-flight demotion is not something an in-flight request escapes, presents BUSBAR'S OWN leased
// credential or none, and turns every way the hop can fail into a busbar-attributed error rather
// than a Task envelope for work that never started. A single answer comes back under busbar's task
// identity; a streamed one comes back as SSE, event by event, under the same identity. An INTERRUPT
// comes back as itself and the task is persisted paused, which on an asynchronous plane is the
// NORMAL path rather than an edge case. Every outcome lands on the per-task provenance chain.
//
// AND THE TRUST VERBS ARE REACHABLE. `POST /agents/{name}/connect` is the shared
// [`crate::admin::planeverbs::connect`] mounted over this plane's [`verbs::A2aAgents`], and
// `POST /agents/{name}/approve` is [`verbs::approve`]; together they are what takes a registration
// out of the fail-closed `Pending` its only constructor puts it in. Before that, [`verbs::connect`]
// was written, unit-tested and callable from nothing: `A2aPlane::from_config` rightly refuses to
// lift a declared pin into an approval, so a busbar booted from YAML fronted agents it could never
// serve, and every A2A test in the tree passed while it did. The shape is not merely LIKE the MCP
// plane's — the sequence is literally the same code, which is the only version of "the same shape"
// that cannot drift.
//
// MODULES WITH RESIDUAL SURFACE THAT NO PRODUCTION PATH CALLS still carry their OWN narrowed
// attribute at the top of their own file, stating what is driven and what is not. The residue is
// coherent rather than scattered — it is the trust verbs `connect` did not bring with it (`sync`,
// `suspend`, `resume`), push-notification DELIVERY (registration is live; delivery is not), and the
// task-read verbs.
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
pub(crate) mod idmap;
pub(crate) mod inbound;
pub(crate) mod ingress;
pub(crate) mod jws;
pub(crate) mod meter;
pub(crate) mod pin;
pub(crate) mod plane;
pub(crate) mod provenance;
pub(crate) mod pushdeliver;
pub(crate) mod pushnotify;
pub(crate) mod registry;
pub(crate) mod relay;
pub(crate) mod rpcerror;
// THE CADENCE MOVED, and the plane keeps its spelling. `super::reverify::…` still resolves, so no
// call site in this plane changed — but there is now exactly ONE cadence in the tree and the MCP
// refresh timer drives the same `due` this one does. See the standing rule: unify the duplicate
// before a second copy can drift from the first.
pub(crate) use crate::trust::reverify;
pub(crate) mod serve;
pub(crate) mod sign;
pub(crate) mod spki;
pub(crate) mod task;
pub(crate) mod taskstore;
pub(crate) mod transport;
pub(crate) mod verbs;
pub(crate) mod verify;
