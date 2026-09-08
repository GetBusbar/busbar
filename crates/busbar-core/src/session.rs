// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `session` — THE SPELLING. The neutral per-session substrate itself is
//! [`busbar_substrate::session`]; this module is the name every in-core call site already writes.
//!
//! It moved for the reason its own header gives: it is the neutral mechanism two or more planes need
//! (the LLM plane's cache-affinity, the hook gate's incremental screen cache, A2A's task set), and a
//! mechanism two planes need cannot live where only the engine can name it. Nothing about the
//! substrate changed — same identity, same TTL, same pinning, same LRU, same hard bound, same
//! `now_ms`-passed-in determinism, and the same battery proving them.
//!
//! `crate::session::{SessionKey, OwnerKey, SessionStore}` resolves to the substrate's items, so
//! `state`, `appbuild`, the hook gate and the test fixture read exactly as they did.

pub use busbar_substrate::session::{OwnerKey, SessionKey, SessionStore};
