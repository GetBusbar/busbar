// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel-owned literals of the node's own surface.
//!
//! Closed structure, not open vocabulary. The lean-core rule forbids the kernel comparing against a
//! key a plugin varies; these are not that. They are the shape of the node's own surface, fixed by
//! the design and pinned byte for byte by the parity battery, and a plane that has to claim one has
//! no way to name it otherwise: a plugin's manifest may name this crate and nothing else in the
//! workspace, so a literal shared between a kernel-side crate and a plugin crate has to live here
//! or be transcribed by hand in both. It was transcribed by hand, with a hand-written assertion
//! guarding the copy that could not check the original.

/// The one prefix every kernel admin verb is mounted under.
pub const ADMIN_PREFIX: &str = "/api/v1/admin";
