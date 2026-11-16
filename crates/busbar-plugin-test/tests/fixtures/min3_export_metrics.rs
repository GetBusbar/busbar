// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 metrics-only export fixture written the real way (ABI-MIN3-INTERFACE §7.7): it declares only
//! STREAM_METRICS and M_RENDER, one pull scope, and keeps the SDK's default `deliver` (REFUSED R_UNSUPPORTED),
//! because core never pushes on the metrics stream. No `unsafe`: the glue is `plugin!`'s output.

use busbar_plugin_abi::export::{tag, M_RENDER, SCOPE_METRICS, STREAM_METRICS};
use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{Out, Writer};
use busbar_plugin_abi::types::Bytes;
use busbar_plugin_abi::Export;

/// The metrics-only exporter.
pub struct MetricsOnly;

fn check_config(config: &[u8]) -> Result<(), Fail> {
    busbar_contract::json::parse::<std::collections::HashMap<String, String>>(config)
        .map(|_| ())
        .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
}

/// The D_SCOPE body: a `ScopeRec` (`scope`, then its reserved word) and the path core mounts it at.
fn scope_body(scope: u32, path: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + path.len());
    body.extend_from_slice(&scope.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(path.as_bytes());
    body
}

impl Open for MetricsOnly {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        config.with(check_config)?;
        Ok(MetricsOnly)
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        check_config(config)
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.methods(M_RENDER);
        d.item(tag::D_STREAMS, &[STREAM_METRICS as u8]);
        d.item(tag::D_SCOPE, &scope_body(SCOPE_METRICS, "/metrics"));
    }
}

impl Export for MetricsOnly {
    /// Every scrape renders an empty exposition.
    fn render(
        &self,
        _h: &Host,
        _scope: u32,
        _snapshot: Bytes<'_>,
        out: &mut Out<'_>,
    ) -> Result<(), Fail> {
        out.put_text(tag::CONTENT_TYPE, "text/plain; version=0.0.4")
            .map_err(Fail::from)?;
        out.put(tag::BODY, b"").map_err(Fail::from)?;
        Ok(())
    }
}

busbar_plugin_abi::plugin!(Export, MetricsOnly, name: "fixture-export-metrics");
