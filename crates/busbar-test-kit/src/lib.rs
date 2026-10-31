// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST KIT: what a plugin repo runs against the busbar commit it pins. The published
//! conformance suite ([`conformance_suite!`]), the test connection tables ([`tcp_conns`],
//! [`https_conns`]), a local token issuer ([`test_issuer`]), the auth axis's stand-in
//! ([`auth_axis`]) and the composition root's door fixtures ([`root_door_fixtures`]). A
//! dev-dependency only.
//!
//! This source also compiles inside busbar-plugin-loader's own test build (`#[path]`), where the
//! suite's unit tests run over the loader's door fixtures. So it names the loader through the
//! `crate::` paths re-exported below, which resolve in both crates.
#![deny(unsafe_code)]

#[doc(hidden)]
pub use busbar_plugin_loader::{
    auth_door, dispatch, plugin_library_filename, sign, store_v3, LinkedPlugin, PluginRegistry,
};

/// The counting allocator a plugin's allocation gates install as their `#[global_allocator]`.
pub mod alloc_counter;

/// The auth axis's stand-in: a build with no composition root opens its auth rows on a
/// dispatcher of its own.
pub mod auth_axis;
/// THE PUBLISHED CONFORMANCE SUITE: every real plugin repo runs it over its linked door and its
/// built cdylib, through the one loader.
#[allow(unsafe_code)] // REVIEWED: the published suite drives raw doors and plants faults
pub mod conformance;
/// The suite's host connector over the transport doors a plugin names (`conformance_host!`).
pub mod conformance_host;
/// The framed connection-table stand-in with in-process far ends, for a build that cannot link
/// the process's connector. No TLS library: TLS stays in the connector.
pub mod https_conns;
/// The composition root's door fixtures: doors built by the contract's door macro, whose expansion
/// writes `unsafe`, kept here so the `forbid(unsafe_code)` root holds no such expansion.
#[allow(unsafe_code)] // TEST ONLY: plugin_door! fixtures the composition root's tests drive
pub mod root_door_fixtures;
/// The host-services test double: a test overrides only the services it serves.
pub mod services_double;
/// The facts the test connection tables stand in for, read from data (`stand_in.json`).
pub mod stand_in;
/// The stream connection table over real local sockets.
pub mod tcp_conns;
/// A local token issuer (an ES256 key, its JWKS, signed tokens).
pub mod test_issuer;
/// An in-memory log double: the WARN-and-above events a test's code emitted.
pub mod warn_capture;
