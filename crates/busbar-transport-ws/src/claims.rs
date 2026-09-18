// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport claims at registration.
//!
//! `PLUGIN-TREE.md` §2 step 2: a transport's registration claim is its `COMPOSES_OVER` — the lower
//! wires it may be layered over. The boot's `check_composition` reads exactly this list against the
//! layer each instance was actually built on, and a name outside it refuses the boot.
//!
//! `ws` is the TOP of its stack: an inbound upgrade arrives on `http`, an outbound `ws://` dial is
//! carried on `tcp` and an outbound `wss://` dial on `tls` — this crate adds no encryption of its
//! own, so `tls` is the only lower layer under which a secure target is honest.

/// The lower wires this transport composes over.
pub const COMPOSES_OVER: &[&str] = &["http", "tcp", "tls"];
