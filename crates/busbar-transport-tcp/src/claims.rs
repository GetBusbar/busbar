// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport claims at registration.
//!
//! `PLUGIN-TREE.md` §2 step 2: a transport's registration claim is its `COMPOSES_OVER` — the
//! lower wires it may be layered over. The boot's `check_composition` reads exactly this list
//! against the layer each instance was actually built on, and a name outside it refuses the boot.
//!
//! `tcp` is the bottom of the lattice: it opens its own socket and composes over nothing, so its
//! claim is the empty list.

/// The lower wires this transport composes over. Empty: `tcp` is a base wire.
pub const COMPOSES_OVER: &[&str] = &[];
