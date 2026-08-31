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
