// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLISHED CONFORMANCE SUITE, run over this plane (TODO ABI-b4; OWNER 2026-10-03: plugins
//! test themselves against busbar's published suite). The linked door (`plane_door::door`) and
//! this crate's dropped-in image (the `decisions_door` example `cdylib`, which `cargo test --test
//! conformance` does not build: build it first with `cargo build -p busbar-plane-decisions
//! --example decisions_door`), each through the one loader, driven by busbar-plugin-loader's plane
//! script over `conformance.json`, every step at its pinned crossing count, the two folds equal.
//! This is the plugin's own both-ways witness at the path every plugin repo keeps it
//! (`tests/conformance.rs`, the file kind-isolation's witness grant names), so the plane repo
//! (GetBusbar/busbar-plane-decisions) takes it as it is once the plane is extracted.

busbar_plugin_loader::conformance_suite! {
    door: busbar_plane_decisions::plane_door::door,
    cdylib: "decisions_door",
    inputs: include_str!("conformance.json"),
}
