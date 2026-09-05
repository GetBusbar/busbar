// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # The composition root
//!
//! Three axes — transport (how bytes move), plane (what bytes mean), unit (what the kernel does
//! about them) — are each blind to the other two. Something has to be the one thing that knows all
//! three, and this is it. A transport cannot name a plane, a plane cannot name a unit, a unit
//! cannot name a plane; the binary names every one of them, once, here.
//!
//! ## What each file is
//!
//! - [`kernel`] — the authority. `Kernel::new()` takes the seal, `Registration::new()` opens the
//!   interner, and `ProductionUnits` is the one implementor of the kernel's `Units` trait in the
//!   whole tree. Every token a unit is lent is minted from the kernel, for the length of one call.
//! - [`registry`] — the boot seal. Seven transports registered bottom-up and five planes registered
//!   over them, then `check_claims`, `precedence_order` and `check_composition` answered before any
//!   listener is bound. A cross-plane claim overlap is a boot refusal, not a runtime surprise.
//! - [`vocabulary`] — the leak-once interner. Every config-derived open-vocabulary key becomes a
//!   `&'static str` exactly once, at registration, and never again. A leak per dial or per frame is
//!   a defect, so this module seals itself and refuses to intern afterwards.
//! - [`durability`] — the WAL branch, the ledger's dual write and the audit unit's two streams.
//!   Without a configured data directory nothing is probed, nothing is opened and no file appears:
//!   constructing an on-disk journal *is* the decision to write to a disk.
//! - [`transports`] — one provisioned listener per configured address. The transport-key unit
//!   resolves the material through the secret plugin, journals the access, and hands back a handle
//!   that carries a slot number and a fingerprint and no bytes at all.
//! - [`adapters`] — the seams where two units name the same object at two widths, plus the boot
//!   assertion that the two hand-kept metric label banks still agree.
//! - [`policy`] — the values the units take from configuration rather than from a `Default`.
//! - [`units_voice`] — one plane, switched over: a live voice session as a sequence of ordinary
//!   units. The handshake that opens it, the per-frame turns the pump dispatches, the hold that is
//!   the session's metering lease, and four seams to the half of the plane that owns sockets.
//!
//! ## The order
//!
//! Boot runs kernel, interner, transports, planes, the two boot checks, then the CLI flags — in
//! that order, because `--validate` reads the plane and protocol lists and every axis must be
//! installed before any reader. Configuration resolves next, and every config-derived key is
//! interned before anything registers one.
//!
//! ## What is deliberately not here
//!
//! No protocol knowledge, no wire shaping, no money rule. The root builds objects and hands them
//! to each other; every decision belongs to the unit, plane or transport that owns it. A function
//! in this module that made a judgement about a request would be the root doing a unit's job.

// The root is BUILT before any plane is SWITCHED onto it, so for the length of that window every
// item here is constructed by its own tests and by nothing else. That is the point of the ordering
// — the shape is proved against the real traits while the serving path is untouched — and the
// allow is what lets the window exist without the compiler treating "not switched yet" as "dead".
// It comes off with the last plane switch, when `main()` calls into this module.
#![allow(dead_code)]

pub mod adapters;
pub mod durability;
pub mod kernel;
pub mod ledger_identity;
pub mod migration;
pub mod policy;
pub mod registry;
pub mod transports;
pub mod units_a2a;
#[cfg(feature = "root-mcp")]
pub mod units_mcp;
pub mod units_voice;
pub mod vocabulary;
