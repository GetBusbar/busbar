// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport claims at registration.
//!
//! `PLUGIN-TREE.md` §2 step 2: a transport's registration claim is its `COMPOSES_OVER` — the
//! lower wires it may be layered over. The boot's `check_composition` reads exactly this list
//! against the layer each instance was actually built on, and a name outside it refuses the boot.
//!
//! `grpc` is the top of its own stack: it opens no socket and is built over a lower carrier —
//! `http` carries an inbound connection, `tcp` a dialled one.

/// The lower wires this transport composes over.
pub const COMPOSES_OVER: &[&str] = &["http", "tcp"];
