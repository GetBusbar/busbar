// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 HOOK PARITY SUITE, ON THE DRIVER (`BUSBAR-1.6.0.md` Part 3, section 12, "The switch":
//! "The llm flip's gate is every hook test green on the driver — 184: the 70 of llm origin through
//! `project`, the 114 of kernel, loader and ranking origin"; Appendix A: "the hook parity suite is
//! the 184 v1.5.5 hook tests").
//!
//! The llm-origin tests of `v1.5.5` (`crates/busbar/src/proxy/tests/hook_seam_tests.rs` and
//! `hook_opt_in_projection_tests.rs` at the tag), each under its 1.5.5 name, with the values 1.5.5
//! asserted, run with llm served on the plane driver: the REAL llm plane door, linked and loaded
//! through the one loader, driven by the kernel's plane driver with its hook stage bound
//! (`plane_driver::hooks`), every hook a 1.5.5 test's own in-process policy. What a hook sees of
//! the request is what the plane's `project` wrote; what the caller is answered is what the plane
//! rendered. The 114 of kernel, loader and ranking origin are unchanged by the plane's path and run
//! in their own crates (`busbar-kernel` hooks tests, the plugin loader's hook tests, the ranking
//! hook's tests).
//!
//! Built wherever the plane serving the `pools` map is linked (its row rides the node axis:
//! `linked_axis_node`).

#![cfg(linked_axis_node)]

// The linked plane doors (`LINKED_PLANE_DOORS`), generated from the manifest: the plane under proof
// is the one whose Statement declares the `pools` map, found by what it states, never by name.
include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

#[path = "../../../busbar-kernel/tests/common/mod.rs"]
mod common;

mod held;
mod policies;
mod ported;
mod projection;
mod rig;
mod seam;
