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
//! - [`linked`] — the one registration path: every linked entry the manifest names, folded into the
//!   kernel's registration seams axis by axis. The root names no plugin; `build.rs` turns the
//!   manifest's `linked` tables into the [`linked::Linked`] tables this module reads.
//! - [`registry`] — the boot seal. The linked transports registered bottom-up and the linked planes'
//!   claims over them, then `check_claims`, `precedence_order` and `check_composition` answered
//!   before any listener is bound. It names no transport and no plane: both come from the linked
//!   tables. A cross-plane claim overlap is a boot refusal, not a runtime surprise.
//! - [`durability`] — the WAL branch, the ledger's dual write and the audit unit's two streams.
//!   Without a configured data directory nothing is probed, nothing is opened and no file appears:
//!   constructing an on-disk journal *is* the decision to write to a disk.
//! - [`transports`] — the loop's dispatch seam: the one place a unit's Route step reaches the
//!   surface that already answers it, counted.
//! - [`adapters`] — the seams where two units name the same object at two widths, plus the boot
//!   assertion that the two hand-kept metric label banks still agree.
//! - [`policy`] — the values the units take from configuration rather than from a `Default`.
//! - `plane_decision` — the decision plane's registry declaration. The one plane whose crate may
//!   not write its own: a pure plane's manifest may name `busbar-contract` and nothing else, and a
//!   `PlaneDecl` is a kernel type, so the root writes it. It declares identity only — no claim, no
//!   audience, no runtime slot — which is what puts `decisions:` in the section fold without
//!   mounting a door the plane has no unit path to answer on.
//! - [`cli`] — the flag surface: everything busbar answers on the command line and exits,
//!   plus the config/providers path scanners the serving half reads through the SAME rule.
//!   It sits under the root because the binary crate's audit scopes are `src/root` and
//!   `src/main.rs` and nothing else; a module at `src/cli.rs` would be in no scope at all.
//! - [`units_admin`] — the admin plane's twelve steps, and the one seam an admin operation's body
//!   is reached through. The root drives the loop; the operation's own logic stays where it lives.
//! - the node — the root's half of a unit a plane's arrival hands it: the kernel, the in-flight
//!   table, the one Route seam its leg is driven through and the book its money settles onto. The
//!   unit itself is the plane's; the module is the one the manifest's `root-units` table names.
//! - [`gauntlet_install`] and [`gauntlet_kernel`] — the kernel-loop runner every plane's gauntlet
//!   rides (DECISIONS #28), and its install under each linked plane's capability key.
//! - [`auth_bindings`], [`ledger_identity`], [`migration`], [`otlp`] — the authenticate unit's three
//!   handed-in seams, the reconciliation identity against the previous release's rows, the first
//!   boot after an upgrade, and the span exporter.
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
pub mod auth_bindings;
pub mod cli;
pub mod durability;
pub mod gauntlet_install;
pub mod gauntlet_kernel;
#[cfg(any(test, feature = "test-harness"))]
pub mod harness;
pub mod kernel;
pub mod keyset;
pub mod ledger_identity;
pub mod linked;
pub mod migration;
pub mod otlp;
#[cfg(feature = "plane-decision")]
pub mod plane_decision;
// The node a plane's units run through: compiled when a linked plane rides the `node` axis, read
// off the same manifest table the root folds (the generated `linked_axis_node` cfg).
#[cfg(linked_axis_node)]
pub mod plane_node;
pub mod policy;
pub mod registry;
pub mod transports;
#[cfg(feature = "root-admin")]
pub mod units_admin;

// The per-call metering shadow on the plane-neutral kernel bridge: a plane whose one flat charge
// fires inside `drive` rides `gauntlet_kernel::run_gauntlet_via_kernel` byte- and money-identically
// to the substrate gauntlet.
#[cfg(test)]
#[path = "tests/percall_meter_shadow.rs"]
mod percall_meter_shadow;
