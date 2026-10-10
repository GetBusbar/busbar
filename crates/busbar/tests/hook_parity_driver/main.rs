// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 HOOK PARITY SUITE, ON THE DRIVER (`BUSBAR-1.6.0.md` Part 3, section 12, "The switch":
//! the flip's gate is every hook test green on the driver; Appendix A: the hook parity suite is the
//! 184 v1.5.5 hook tests).
//!
//! The plane-origin tests of `v1.5.5`, each under its 1.5.5 name, with the values 1.5.5 asserted,
//! run with the plane under proof served on the plane driver: its REAL door, linked and loaded
//! through the one loader, driven by the kernel's plane driver with its hook stage bound
//! (`plane_driver::hooks`), every hook a 1.5.5 test's own in-process policy. What a hook sees of the
//! request is what the plane's `project` wrote; what the caller is answered is what the plane
//! rendered. The tests of kernel, loader and ranking origin are unchanged by the plane's path and
//! run in their own crates.
//!
//! THE COMPOSITION ROOT NAMES NO PLANE (BUSBAR-1.6.0.md THE DESIGN, the root is `Family::Neutral`),
//! so this suite is only the driver half: the rig (`rig.rs`) and the kernel's shared test steps. The
//! cases, written in the plane's own dialects, live in the plane's crate and are compiled in here
//! as `proofs` from the manifest's `[package.metadata.busbar.driver-proofs]` row (`build.rs` writes
//! the one `#[path]`); the plane under proof is the one whose Statement declares the `pools` map,
//! found by what it states, never by name.
//!
//! Development-only, like the switch it proves: built with a plane's development-only fold switch
//! (`linked_fold_on_driver`).

#![cfg(linked_fold_on_driver)]

// The linked plane doors (`LINKED_PLANE_DOORS`), generated from the manifest.
include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

// The plane-owned cases (`mod proofs`), generated from the manifest.
include!(concat!(env!("OUT_DIR"), "/driver_proofs.rs"));

#[path = "../../../busbar-kernel/tests/common/mod.rs"]
mod common;

mod rig;
