// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFERENCE EXPORT (export 4.0): the smallest sink that uses what the export contract's `deliver` carries
//! after the revision. `deliver`'s head is `stream u32, delivery u64, attempt u32, lines u32` and its one blob is
//! the batch (one TEXT record per line). The reference HOLDS THE HOST TO ITS OWN STATEMENT: it counts the TEXT
//! records of the batch and refuses (R_INVALID, both numbers in the text) when the count is not `lines`; when
//! it is, it acknowledges exactly `lines`. So the boundary test (`c_boundary_fleet.rs`), which drives it through
//! the engine's real export adapter, fails at this kind's boundary if the adapter packs the head in another
//! order, omits the count, or counts something other than records.
//!
//! It remembers the head of its last delivery (`last`), so a test can read back every number the host packed.

use std::sync::Mutex;

use busbar_plugin_abi::export::{self, Ack};
use busbar_plugin_abi::fail::refused::{R_CONFIG, R_INVALID};
use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{tag as record, Records, Reply, Writer};
use busbar_plugin_abi::Export;

/// The numbers of one `deliver` call, as the plugin read them from the call's head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub stream: u32,
    pub delivery: u64,
    pub attempt: u32,
    pub lines: u32,
    /// The TEXT records the batch held.
    pub found: u64,
}

/// The head of the most recent delivery to any instance of this image (tests run one at a time on it).
pub static LAST: Mutex<Option<Head>> = Mutex::new(None);

/// The reference sink: accepts the logs stream.
pub struct RefSink;

fn check_config(config: &[u8]) -> Result<(), Fail> {
    busbar_contract::json::parse::<std::collections::HashMap<String, String>>(config)
        .map(|_| ())
        .map_err(|_| Fail::refused_because(R_CONFIG, "config must be an object"))
}

impl Open for RefSink {
    async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
        config.with(check_config)?;
        Ok(RefSink)
    }

    fn check(_h: &Host, config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        check_config(config)
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.methods(export::M_DELIVER);
        d.item(export::tag::D_STREAMS, &[export::STREAM_LOGS as u8]);
    }
}

impl Export for RefSink {
    async fn deliver(
        &self,
        _h: &'static Host,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: u32,
        batch: ChainBytes,
    ) -> Result<Reply, Fail> {
        // Every record must be TEXT and must frame; the count of them is the number the host stated.
        let found = batch.with(|bytes| {
            Records::new(bytes).try_fold(0u64, |count, rec| match rec {
                Ok(rec) if rec.tag == record::TEXT => Ok(count + 1),
                _ => Err(()),
            })
        });
        let Ok(found) = found else {
            return Err(Fail::refused_because(
                R_INVALID,
                "a delivered batch is one TEXT record per line",
            ));
        };
        if let Ok(mut last) = LAST.lock() {
            *last = Some(Head {
                stream,
                delivery,
                attempt,
                lines,
                found,
            });
        }
        if found != u64::from(lines) {
            return Err(Fail::refused_because(
                R_INVALID,
                format!("the host stated {lines} lines for a delivered batch that holds {found}"),
            ));
        }
        let mut reply = Reply::new();
        reply
            .put_pod(
                export::tag::ACK,
                &Ack {
                    accepted: u64::from(lines),
                },
            )
            .map_err(Fail::from)?;
        Ok(reply)
    }
}

busbar_plugin_abi::plugin!(Export, RefSink, name: "reference-export");
