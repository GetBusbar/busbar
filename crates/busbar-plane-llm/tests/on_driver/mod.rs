// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S DRIVER PROOFS: the 1.5.5 hook tests of llm origin, each under its 1.5.5 name and
//! asserting the values 1.5.5 asserted, kept here, in the plane's own crate, where the dialect names
//! they are written in belong (BUSBAR-1.6.0.md Law 5; ARCHITECT ruling on #464: the composition root
//! names zero plane or dialect instance vocabulary).
//!
//! They are proven through the plugin door: the composition root's `hook_parity_driver` suite links
//! this plane's door, loads it through the one loader, drives it on the kernel's plane driver with the
//! hook stage bound, and compiles these cases beside its rig (the root's manifest row
//! `[package.metadata.busbar.driver-proofs]`, which its `build.rs` turns into the one `#[path]` the
//! suite includes). The kernel and the loader are the root's to link, never a plane's, so the cases
//! are compiled into the root's test binary rather than this crate's: this directory has no
//! `main.rs`, and `cargo test -p busbar-plane-llm` does not build it.
//!
//! Development-only, like the switch it proves: compiled only under the plane's fold switch
//! (`llm-on-driver`).

pub(crate) mod held;
pub(crate) mod policies;
pub(crate) mod projection;
pub(crate) mod seam;
pub(crate) mod wire;
