// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound listener moved to the composition root, `busbar::root::listener`; `read_pem` stays
//! here for its outbound callers (the connector's `tls:` block resolution and `busbar-a2a`'s
//! outbound client identity).

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
pub fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &busbar_contract::secret_ref::SecretRef,
    what: &str,
) -> Result<Vec<u8>, String> {
    resolver
        .resolve(secret)
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}
