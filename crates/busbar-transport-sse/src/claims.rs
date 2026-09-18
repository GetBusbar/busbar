// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport claims at registration.
//!
//! `PLUGIN-TREE.md` §2 step 2: a transport's registration claim is its `COMPOSES_OVER` — the
//! lower wires it may be layered over. The boot's `check_composition` reads exactly this list
//! against the layer each instance was actually built on, and a name outside it refuses the boot.
//!
//! `sse` is a reading of an `http` response: it opens no socket of its own and is only ever built
//! over the `http` transport it delegates to, so it composes over `http` and nothing else.

/// The lower wires this transport composes over.
pub const COMPOSES_OVER: &[&str] = &["http"];
