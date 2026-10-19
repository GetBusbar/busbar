// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound listener moved to the composition root, `busbar::root::listener`; `read_pem` stays
//! here for its outbound callers (the connector's `tls:` block resolution and a plane's outbound
//! client identity).

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents. The PEM comes back sealed to the kernel (Part 2 #54),
/// read under its seal where it is parsed.
pub fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &busbar_contract::secret_ref::SecretRef,
    what: &str,
) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
    resolver
        .resolve_at_config(
            secret,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map(busbar_contract::secret::Resolved::sealed)
        .map_err(|e| {
            format!(
                "cannot resolve TLS {what} ({}): {e}",
                crate::config::secret::describe(&secret)
            )
        })
}
