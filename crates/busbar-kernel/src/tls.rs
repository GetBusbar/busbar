// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound listener moved to the composition root, `busbar::root::listener`; `read_pem` stays
//! here for its one caller, the connector's `tls:` block resolution. The connector is the only holder
//! of TLS keys, certificates, trust roots and mTLS identity (THE DESIGN §8, `BUSBAR-1.6.0.md`
//! l.1141), so no plane reads PEM material through this.

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
pub fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &busbar_contract::secret_ref::SecretRef,
    what: &str,
) -> Result<crate::config::secret::Held, String> {
    resolver
        .resolve_at_config(
            secret,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}
