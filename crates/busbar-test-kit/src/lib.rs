// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST KIT: what a plugin repo runs against the busbar commit it pins. The published
//! conformance suite ([`conformance_suite!`]), the test connection tables ([`tcp_conns`],
//! [`https_conns`]) and a local token issuer ([`test_issuer`]). A dev-dependency only.
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
/// THE PUBLISHED CONFORMANCE SUITE: every real plugin repo runs it over its linked door and its
/// built cdylib, through the one loader.
#[allow(unsafe_code)] // REVIEWED: the published suite drives raw doors and plants faults
pub mod conformance;
/// The framed connection-table stand-in with in-process far ends, for a build that cannot link
/// the process's connector. No TLS library: TLS stays in the connector.
pub mod https_conns;
/// The facts the test connection tables stand in for, read from data (`stand_in.json`).
pub mod stand_in;
/// The stream connection table over real local sockets.
pub mod tcp_conns;
/// A local token issuer (an ES256 key, its JWKS, signed tokens).
pub mod test_issuer;
