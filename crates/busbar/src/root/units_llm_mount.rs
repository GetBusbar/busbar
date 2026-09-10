// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the other two planes' mounts carry the same
// line: a mount is composition of the SERVING path, and it names items that exist only under this
// feature. Declared in `root/mod.rs` under `root-llm` instead, so a plane-gated module is not named
// from code under a different feature.
#![cfg(feature = "root-llm-serve")]

//! THE LLM PLANE'S MOUNT: this plane's claim table, this plane's leg, and this plane's media type.
//!
//! The body a mount needs is [`crate::root::plane_mount`] and none of it is about this plane. What
//! belongs here is the three answers only this plane can give, and they arrive in the commit that
//! writes them; this file exists from the seam commit so the module declaration beside it names
//! something that compiles.
