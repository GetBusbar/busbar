// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport claims at registration.
//!
//! `PLUGIN-TREE.md` §2 step 2: a transport's registration claim is its `COMPOSES_OVER` — the
//! lower wires it may be layered over. The boot's `check_composition` reads exactly this list
//! against the layer each instance was actually built on, and a name outside it refuses the boot.
//!
//! `stdio` is a base wire: it is either the process's own stdin/stdout or a spawned child's pipes,
//! so it composes over nothing and its claim is the empty list.

/// The lower wires this transport composes over. Empty: `stdio` is a base wire.
pub const COMPOSES_OVER: &[&str] = &[];
