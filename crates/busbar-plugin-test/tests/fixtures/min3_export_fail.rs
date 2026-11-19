// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIN-3 a failing export fixture (C-SCRUB-CUT, C-FAIL-FACTS export arms, C-WATCH-CEILING (d)), written with
//! `plugin!` like a shipped plugin (SDK-SAFE-TEST-HOST §3.4 G): the `Export` trait, `Open` and one `plugin!`
//! line. No `unsafe`: the glue is `plugin!`'s output.
//!
//! It declares the logs stream. Its config (an object; every member optional) says what `deliver` answers:
//! - `"status"`, `"code"`, `"text"`, `"retry_after_s"`, `"backend_status"`: answer REFUSED or FAILED with that
//!   code and text (the facts only on FAILED), as [`crate::min3_store::Planned`] reads them; with no
//!   `"status"` it ACKs the whole batch.
//! - `"secret"`: a secret reference (D_SECRET_PATH `/secret`) `open` resolves once, so custody registers the
//!   value in the instance's scrub set (the sink's API key).
//! - `"sleep_ms"`: block every `deliver`'s first poll this long.

use std::time::Duration;

use busbar_contract::json::{self as facade, JsonValueTrait, Value};
use busbar_plugin_abi::fail::refused::R_CONFIG;
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::need::secret;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as record, Records, Reply, Writer};
use busbar_plugin_abi::Export;

use crate::min3_store::{number, secret_handle, Planned};

/// The failing sink.
pub struct FailSink {
    planned: Option<Planned>,
    sleep: Duration,
}

fn object(config: &[u8]) -> Result<Value, Fail> {
    facade::parse_value(config)
        .ok()
        .filter(|v| v.is_object())
        .ok_or_else(|| Fail::refused_because(R_CONFIG, "config must be an object"))
}

impl Open for FailSink {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        let (sink, handle) = config.with(|bytes| {
            object(bytes).map(|v| {
                let sink = FailSink {
                    planned: Planned::of(&v),
                    sleep: Duration::from_millis(v.get("sleep_ms").and_then(number).unwrap_or(0)),
                };
                (sink, secret_handle(&v))
            })
        })?;
        if let Some(handle) = handle {
            // The sink's API key: resolved and used once, never kept (wiped on drop).
            drop(secret(handle).await?);
        }
        Ok(sink)
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        object(config).map(|_| ())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.secret_path("/secret");
        d.methods(busbar_plugin_abi::export::M_DELIVER);
        d.item(
            busbar_plugin_abi::export::tag::D_STREAMS,
            &[busbar_plugin_abi::export::STREAM_LOGS as u8],
        );
    }
}

impl Export for FailSink {
    async fn deliver(
        &self,
        _h: &'static Host,
        _stream: u32,
        _delivery: u64,
        _attempt: u32,
        _lines: u32,
        batch: ChainBytes,
    ) -> Result<Reply, Fail> {
        std::thread::sleep(self.sleep);
        if let Some(planned) = &self.planned {
            return Err(planned.fail());
        }
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

busbar_plugin_abi::plugin!(Export, FailSink, name: "fixture-export-fail");
