// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The common inbound listener grammar, interpreted only at declared kind boundaries.

use crate::abi::host::conn::connector::DIRECTION_INBOUND;
use crate::abi::mechanism::rendering::ReadNeed;
use crate::{caps::KernelSeal, plugin_settings::Settings, secret_ref::SecretRef};
use serde::{Deserialize, Serialize};

/// Default bound for a plugin-owned listener.
pub const DEFAULT_MAX_CONNS: u64 = 1024;

/// Native inbound TLS configuration for the client↔Busbar hop. Absent (`Config.tls == None`) ⇒
/// Busbar serves plain HTTP exactly as before. Present ⇒ Busbar terminates TLS itself; if
/// `client_ca` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three values are SECRET REFERENCES (`{ file: … }` / `{ env: … }` / a secret module)
/// resolving to PEM bytes; they are resolved once at startup and any resolve/parse error is fatal
/// (`die`). Key bytes are never logged.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsCfg {
    /// PEM certificate chain, leaf first (e.g. fullchain.pem), as a secret reference.
    pub cert: SecretRef,
    /// PEM private key matching the leaf cert (PKCS#8, PKCS#1, or SEC1), as a secret reference.
    pub key: SecretRef,
    /// PEM CA bundle to verify client certs against. `Some` ⇒ mTLS required: a client must present
    /// a cert chaining to this CA to complete the handshake at all. `None` ⇒ server-only TLS.
    #[serde(default)]
    pub client_ca: Option<SecretRef>,
}

/// A declared inbound need, with an absent block distinguished from malformed configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerClaim {
    /// Original index in the admitted declaration, including non-inbound needs.
    pub need: u32,
    /// The declaration's settings path, used for operator diagnostics.
    pub path: String,
    /// None means the declared block was omitted. The host determines whether inheritance is legal.
    pub binding: Option<ListenerBinding>,
}

/// Typed host-owned listener facts; no plugin settings subtree leaves admission.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerBinding {
    /// Physical bind address.
    pub listen: std::net::SocketAddr,
    /// Secret references for host TLS termination; never resolved key bytes.
    pub tls: Option<TlsCfg>,
    /// Distinguishes omitted TLS from explicitly requested cleartext.
    pub tls_explicit: bool,
    /// The maximum accepted connections.
    pub max_conns: u64,
    /// Distinguishes an omitted bound from an explicitly requested bound.
    pub max_conns_explicit: bool,
}

/// Interpret only inbound blocks named by the admitted need declarations.
/// Root authority is required; generic grants cannot request settings interpretation.
///
/// ```compile_fail,E0308
/// use busbar_contract::{conn::inbound, plugin_settings::Settings, plugin::KernelSeal};
/// fn inspect(grant: &dyn KernelSeal, settings: &Settings) {
///     let _ = inbound::admit(grant, settings, &[]);
/// }
/// ```
pub fn admit(
    _: &KernelSeal,
    settings: &Settings,
    needs: &[ReadNeed],
) -> Result<Vec<ListenerClaim>, String> {
    interpret(settings, needs)
}

fn interpret(settings: &Settings, needs: &[ReadNeed]) -> Result<Vec<ListenerClaim>, String> {
    let mut claims = Vec::new();
    for (index, need) in needs.iter().enumerate() {
        if need.direction != DIRECTION_INBOUND {
            continue;
        }
        if need.target_from.is_empty() {
            return Err(format!(
                "inbound need {index} over `{}` names no settings block to listen from",
                need.transport
            ));
        }
        let path = &need.target_from;
        let block = path
            .split('.')
            .try_fold(&settings.0.0, |value, key| value.get(key));
        let binding = block.map(|block| {
            let listen = block.get("listen").and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{path}.listen: not set"))?
                .parse().map_err(|_| format!("{path}.listen: not an ip:port address"))?;
            let max_conns = match block.get("max_conns") {
                None => DEFAULT_MAX_CONNS,
                Some(value) => value.as_u64().filter(|n| *n > 0)
                    .ok_or_else(|| format!("{path}.max_conns: not a positive whole number"))?,
            };
            let tls = block.get("tls").filter(|value| !value.is_null())
                .map(TlsCfg::deserialize).transpose()
                .map_err(|_| format!("{path}.tls: invalid TLS configuration; expected cert, key and optional client_ca references"))?;
            Ok::<_,String>(ListenerBinding {
                listen, tls, max_conns,
                tls_explicit: block.get("tls").is_some(),
                max_conns_explicit: block.get("max_conns").is_some(),
            })
        }).transpose()?;
        claims.push(ListenerClaim {
            need: index
                .try_into()
                .map_err(|_| "inbound need index does not fit u32")?,
            path: path.clone(),
            binding,
        });
    }
    Ok(claims)
}

#[cfg(test)]
#[path = "../tests/inbound_tests.rs"]
mod tests;
