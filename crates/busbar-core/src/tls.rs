// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim: the native inbound TLS listener moved to [`busbar_substrate::tls`] in the 1.6.0
//! busbar-core dissolution (byte-safe relocation — the listener reads ONLY the neutral secret-resolver
//! seam, `busbar_api::SecretResolve`, so it names no `App`/money/plane type and carried no cycle back
//! to core). It is re-exported here at its historical `crate::tls::*` path so every busbar-core and
//! `busbar` binary call site is unchanged: `main.rs`'s `tls::{install_crypto_provider,
//! build_server_config, serve, serve_plain, ConnBalancer}` and `test_support`'s
//! `crate::tls::install_crypto_provider` all resolve through this glob.
//!
//! The end-to-end TLS / mTLS tests (which drive a real listener with a builtins-only
//! `crate::config::secret::SecretResolver` — an engine type that stays in this crate — and reach the
//! listener's private balancer/backoff internals) stay here and exercise the relocated code through
//! this shim; those private items are `pub` in the substrate home solely so this crate's tests reach
//! them.

pub use busbar_substrate::tls::*;

#[cfg(test)]
#[path = "tests/tls_tests.rs"]
mod tests;
