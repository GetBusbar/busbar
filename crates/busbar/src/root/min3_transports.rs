// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport arm of the MIN-3 boot (W2-SW-TRANSPORT; ABI-MIN3-INTERFACE §8.7, §11.2, §13 "Server-side
//! transports").
//!
//! A transport has no operator section: no config 1.5.5 accepted can hold a transport instance (IF §8.7, round 12)
//! and MIN-3 adds none, since every carrier function (listeners, sockets, TLS, ALPN, accept, dial) is core's. Every
//! admitted MIN-3 transport image is therefore one instance, named by its identity, and the walk opens it in step
//! 2c through `Registry::open_transport` like any other kind. Its settings are the deployment's value of each core
//! config path its D_SCHEMA names at top level, out of the paths 1.5.5 dealt a transport door ([`DEALT`]); a path
//! the schema names that core does not deal keeps the plugin's own default, and a path it does not name is never
//! sent (a framer's grammar refuses unknown keys). No plugin name is read anywhere here (§15.8). The old transport
//! path passes such an image over (plugin-loader `PluginRegistry::open_transport_entries`: a no-Statement row whose
//! one stamp names kind TRANSPORT), the same door-axis rule W2-SW-PLANE gave planes.
//!
//! The opened ports are retained by the complete native generation before any listener serves: the listener's
//! `alpn(ROLE_SERVER)`, the dial's `alpn(ROLE_CLIENT)` and `defaults(ROLE_CLIENT)`, the session task's
//! begin/ingest/emit/timer, and the upgrade target by D_PROTOCOL (§12.27).

use std::sync::Arc;

use busbar_kernel::config::limits::LimitsResolved;
use busbar_kernel::config::RootCfg;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{BootPhase, InstanceSpec, OpenedPort};
use busbar_ports::transport::TransportPort;

use super::{Configured, MinRegistry};

/// The section word a transport instance is keyed by (`insecure_transport` lookups). The config
/// grammar has no transport section, so every transport instance runs at the kind's defaults
/// (`limits.stream_stall_ms` 60,000 included) until it gains one.
const SECTION: &str = "transport";

/// The core config paths a transport's settings may name, in byte order: the paths 1.5.5 dealt a transport door
/// (busbar-core-connector off_path/egress.rs `DEALT`).
const DEALT: [&str; 4] = [
    "advanced.upstream_h2_prior_knowledge",
    "advanced.upstream_http1_only",
    "limits.request_body_max_bytes",
    "limits.upstream_request_timeout_secs",
];

/// One transport instance the MIN-3 boot opened.
#[derive(Clone)]
pub(crate) struct ServedTransport {
    /// The configured instance name (the image identity).
    pub(crate) instance: Arc<str>,
    pub(crate) port: Arc<dyn TransportPort>,
}

/// The unique instance declaring this protocol in an already validated generation table.
pub(crate) fn declaring<'t>(
    served: &'t [ServedTransport],
    protocol: &str,
) -> Option<&'t ServedTransport> {
    served.iter().find(|one| {
        one.port
            .protocols()
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(protocol))
    })
}

/// One transport instance per identity, with the settings its D_SCHEMA names and the kind's limits.
pub(super) fn configured(
    cfg: &RootCfg,
    registry: &MinRegistry,
    identities: &[String],
) -> Result<Vec<Configured>, String> {
    identities
        .iter()
        .map(|identity| {
            let schema = registry
                .described(identity)
                .and_then(|described| described.schema);
            let config = settings(&cfg.limits, schema.as_deref())
                .map_err(|why| format!("transport `{identity}`: {why}"))?;
            Ok(Configured {
                kind: KindCode::Transport,
                identity: identity.clone(),
                name: identity.clone(),
                config,
                limits: busbar_kernel::appbuild::instance_limits(cfg, SECTION, identity),
            })
        })
        .collect()
}

/// The settings bag of an image whose D_SCHEMA is `schema`: one compact JSON object holding the deployment's
/// value at each [`DEALT`] path the schema's top-level `properties` names. No schema, or one naming none of
/// them, is `{}`. A schema that is not a JSON object refuses (admission validated it, so this is a fault).
fn settings(limits: &LimitsResolved, schema: Option<&str>) -> Result<Vec<u8>, String> {
    use busbar_contract::json::{self, JsonValueMutTrait, JsonValueTrait, Map, Value};
    let declared: Value = match schema {
        None => Value::new(),
        Some(text) => match json::parse_value(text.as_bytes()) {
            Ok(mut schema) if schema.is_object() => {
                match schema.as_object_mut().and_then(|s| s.remove(&"properties")) {
                    None => Value::new(),
                    Some(properties) if properties.is_object() => properties,
                    Some(_) => return Err("its D_SCHEMA `properties` is not an object".to_owned()),
                }
            }
            _ => return Err("its D_SCHEMA is not a JSON object".to_owned()),
        },
    };
    let mut bag = Map::new();
    for path in DEALT.iter().filter(|path| declared.get(**path).is_some()) {
        let value = match *path {
            "advanced.upstream_h2_prior_knowledge" => {
                Value::from(limits.upstream_h2_prior_knowledge)
            }
            "advanced.upstream_http1_only" => Value::from(limits.upstream_http1_only),
            "limits.request_body_max_bytes" => {
                Value::from(u64::try_from(limits.request_body_max_bytes).unwrap_or(u64::MAX))
            }
            _ => Value::from(limits.upstream_request_timeout_secs),
        };
        bag.insert(*path, value);
    }
    json::to_vec(&bag).map_err(|error| error.to_string())
}

/// The transport ports the walk opened, each with its instance name: every `OpenedPort::Transport` among
/// `opened`, named by the spec at its plan index.
pub(super) fn opened(
    opened: &[(u32, BootPhase, Option<OpenedPort>)],
    specs: &[(KindCode, InstanceSpec<'_>)],
) -> Vec<ServedTransport> {
    opened
        .iter()
        .filter_map(|(index, _, port)| match port {
            Some(OpenedPort::Transport(port)) => {
                let (_, spec) = specs.get(usize::try_from(*index).ok()?)?;
                Some(ServedTransport {
                    instance: Arc::from(spec.name),
                    port: Arc::clone(port),
                })
            }
            _ => None,
        })
        .collect()
}

/// The served table, or the refusal: two instances declaring one D_PROTOCOL (an upgrade names a protocol, never
/// a plugin, so exactly one instance may answer it).
pub(super) fn table(served: Vec<ServedTransport>) -> Result<Vec<ServedTransport>, String> {
    for (at, one) in served.iter().enumerate() {
        for protocol in one.port.protocols() {
            if let Some(other) = declaring(&served[at + 1..], protocol) {
                return Err(format!(
                    "transport instances `{}` and `{}` both declare protocol `{protocol}`: an upgrade names a \
                     protocol, so one instance answers it; remove one of the two images",
                    one.instance, other.instance
                ));
            }
        }
    }
    Ok(served)
}

#[cfg(test)]
#[path = "tests/min3_transports.rs"]
mod tests;
