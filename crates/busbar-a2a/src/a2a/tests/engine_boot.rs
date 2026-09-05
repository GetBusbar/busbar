// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST-SCAFFOLDING: bind the engine's test kit. This plane's tests build the test App, mint keys,
//! read the metrics exposition, load the hook-plugin fixture and reach the built App's router, host,
//! mount table and breaker cells through the neutral
//! `busbar_substrate::testkit::engine_kit` / `engine_kit_plus` seams — trait objects the engine
//! provides and the plane only consumes. The engine's ONE implementation is bound here, in this one
//! function, in this `tests/`-path file the neutral-purity lint excludes (the twin of
//! `envelope_boot.rs` and `egress_boot.rs`), so no other file in this plane's test tree names the
//! engine crate. Swap the body and every test runs on another engine fixture unchanged.

use busbar_substrate::testkit::engine_kit_plus::EngineTestKitPlus;

/// The engine's test kit, bound once. Everything a test needs from the engine is a method on it.
pub(crate) fn engine() -> &'static dyn EngineTestKitPlus {
    &busbar_core::test_support::engine_kit::CORE_ENGINE_KIT
}
