// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE PLANE'S TEST-KIT — the fixture surface this plane's own batteries drive, kept ON THE
//! PLANE. A plane is a plugin on the plane ABI and it tests ITSELF: the kernel ships no scaffolding
//! for it (1.6.0 Locked Decision #33, "the kernel never tests a plugin"), so the three doubles the
//! voice cells reach — the in-memory [`fixture_host::FixtureHost`], the
//! [`loopback_http`] provider and the [`metrics_capture`] recorder — live here rather than in
//! `busbar_kernel::testkit`, which is deleted.
//!
//! Every double reaches the engine through the SAME neutral seam production uses
//! (`busbar_kernel::plane_host::EngineHost` and friends); nothing here names a kernel *test* item.

/// The in-memory [`busbar_kernel::plane_host::EngineHost`] this plane's cells drive when no engine
/// `App` is in their closure at all: scripted hook gates/rewrites, breaker cells and a per-key ledger
/// behind the same seam production reaches.
pub mod fixture_host;

/// A loopback HTTP provider that records what it was dialed with, for this plane's egress legs.
pub mod loopback_http;

/// An in-memory `metrics` recorder + exposition render, for asserting this plane's counter emits.
pub mod metrics_capture;

/// THIS PLANE'S SERVED-LEG WITNESSES — `(capability key, [(loop step or core capability, witness)])`.
///
/// What a test binary that links this crate without naming it runs through ITS registered session
/// runner for this plane's key (the composition root's kernel-loop session rider): each witness opens
/// a session at the served door, asserts one capability or one loop step on the session it opened,
/// and returns how many session opens it expects to have reached that runner. See
/// `tests/served_witness.rs`.
pub const SERVED: (&str, &[(&str, crate::mount::served_witness::Witness)]) =
    (crate::PLANE_KEY, crate::mount::served_witness::WITNESSES);
