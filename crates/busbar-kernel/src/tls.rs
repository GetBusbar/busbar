// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound listener moved to the composition root, `busbar::root::listener`; `read_pem` stays
//! here for its outbound callers (the connector's `tls:` block resolution and a plane's outbound
//! client identity).

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
///
/// Takes the config-time proof from its caller and never makes one (THE DESIGN §11.11 R4,
/// BUSBAR-1.6.0.md l.1464-1469: the secret source reads only at config time, never from a request
/// path). A reader that minted its own would be callable from anywhere and the config-scope gate
/// could not tell; the listeners' boot and a door plane's member load hold the proof and pass it.
pub fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &busbar_contract::secret_ref::SecretRef,
    what: &str,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Vec<u8>, String> {
    resolver
        .resolve_at_config(secret, scope)
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}
