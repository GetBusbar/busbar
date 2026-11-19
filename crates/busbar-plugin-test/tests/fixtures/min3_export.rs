// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 export fixture written the real way (ABI-MIN3-INTERFACE §7.7): the `Export` trait, `Open` and one
//! `plugin!` line. An accepting sink: it declares the logs stream and answers every `deliver` with an ACK for
//! the whole batch (one TEXT record per line), keeping nothing. No `unsafe`: the glue is `plugin!`'s output.

use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as record, Records, Reply, Writer};
use busbar_plugin_abi::Export;

/// The accepting sink.
pub struct AckSink;

fn check_config(config: &[u8]) -> Result<(), Fail> {
    busbar_contract::json::parse::<std::collections::HashMap<String, String>>(config)
        .map(|_| ())
        .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
}

impl Open for AckSink {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        config.with(check_config)?;
        Ok(AckSink)
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        check_config(config)
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.methods(busbar_plugin_abi::export::M_DELIVER);
        d.item(
            busbar_plugin_abi::export::tag::D_STREAMS,
            &[busbar_plugin_abi::export::STREAM_LOGS as u8],
        );
    }
}

impl Export for AckSink {
    async fn deliver(
        &self,
        _h: &'static Host,
        _stream: u32,
        _delivery: u64,
        _attempt: u32,
        _lines: u32,
        batch: ChainBytes,
    ) -> Result<Reply, Fail> {
        let accepted = batch.with(|bytes| {
            Records::new(bytes)
                .filter(|rec| matches!(rec, Ok(rec) if rec.tag == record::TEXT))
                .count() as u64
        });
        let mut reply = Reply::new();
        reply
            .put_pod(
                busbar_plugin_abi::export::tag::ACK,
                &busbar_plugin_abi::export::Ack { accepted },
            )
            .map_err(Fail::from)?;
        Ok(reply)
    }
}

busbar_plugin_abi::plugin!(Export, AckSink, name: "fixture-export-a");
