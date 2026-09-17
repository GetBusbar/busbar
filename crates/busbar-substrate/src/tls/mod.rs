// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE place in the tree that turns a `SecretRef` into TLS PEM bytes.
//!
//! Both busbar's own inbound listener (core's `tls` module builds its cert and key with this) and the
//! A2A plane's OUTBOUND client identity (`a2a::transport::resolve_client_identities`) load their PEM
//! through this single function, so there is exactly one place that turns a
//! [`busbar_api::SecretRef`] into TLS PEM — and it is the one that already knows not to log what it
//! read. A second would be a second place for the "never echo what you read" rule to be forgotten.
//!
//! The bytes are returned raw. Parsing them (rustls cert chains, private keys, extra roots) stays
//! with each caller — core's inbound listener and the plane's `reqwest::Identity`/`Certificate`
//! builders — because the parse is where the transport-specific meaning lives; this seam owns only
//! the resolve-and-do-not-log discipline.

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
pub fn read_pem(
    resolver: &dyn busbar_api::SecretResolve,
    secret: &busbar_api::SecretRef,
    what: &str,
) -> Result<Vec<u8>, String> {
    resolver
        .resolve(secret)
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}

/// Native inbound TLS termination (+ optional mutual-TLS) for the client↔Busbar hop — the listener,
/// its rustls `ServerConfig` builder, the accept-error backoff, the slow-loris body bounds and the
/// thread-per-core connection balancer. Relocated byte-for-byte out of `busbar-core`'s `tls` module
/// (1.6.0 busbar-core dissolution) and re-exported at this module's root, so `busbar_core::tls::*`
/// keeps resolving through core's re-export shim. It reads ONLY the neutral secret-resolver seam
/// (`busbar_api::SecretResolve`, via [`read_pem`] above) — no App/money/plane coupling — which is
/// what made the move byte-safe.
pub mod listener;
pub use listener::*;
