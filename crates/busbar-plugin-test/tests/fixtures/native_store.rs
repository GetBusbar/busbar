// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's own MIN-3 store fixture, written with `plugin!` like a shipped store: a fixed dataset and clock.
//! The same body is linked into the `host` test and built as the `native_store_fixture` cdylib, so one test
//! drives both images through `Registry::open_store`. It answers `info` with dataset `[1; 16]`, atomic domain
//! `[2; 16]`, clock authority `[3; 16]`, physical version 1 and ephemeral durability (FB_EPHEMERAL), and
//! `clock` with `observed_at` 41 under that authority; `read` and `commit` are unsupported and `scan` answers
//! an exhausted empty page.

use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{Out, Reply, Writer};
use busbar_plugin_abi::store as wire;
use busbar_plugin_abi::Store;

/// What `info` states.
pub const DATASET: [u8; 16] = [1; 16];
pub const DOMAIN: [u8; 16] = [2; 16];
pub const AUTHORITY: [u8; 16] = [3; 16];
/// What `clock` observes.
pub const OBSERVED_AT: u64 = 41;

pub struct Fixture;

impl Open for Fixture {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Ok(Self)
    }

    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(r#"{"type":"object"}"#);
        d.facts(wire::FB_EPHEMERAL);
    }
}

impl Store for Fixture {
    async fn read(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    async fn scan(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
        let mut reply = Reply::new();
        let done = wire::ScanDone {
            code: wire::SCAN_PAGE,
            continuation: wire::SCAN_EXHAUSTED,
            generation: 0,
        };
        reply.put_pod(wire::tag::SCAN_DONE, &done)?;
        Ok(reply)
    }

    async fn commit(&self, _h: &'static Host, _cand: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    async fn clock(&self, _h: &'static Host, _dataset: ChainBytes) -> Result<Reply, Fail> {
        let mut reply = Reply::new();
        let clock = wire::ClockRec {
            observed_at: OBSERVED_AT,
            authority: AUTHORITY,
        };
        reply.put_pod(wire::tag::CLOCK, &clock)?;
        Ok(reply)
    }

    fn info(&self, _h: &Host, out: &mut Out<'_>) -> Result<(), Fail> {
        let info = wire::InfoRec {
            dataset: DATASET,
            atomic_domain: DOMAIN,
            clock_authority: AUTHORITY,
            physical_version: 1,
            durability: wire::DUR_EPHEMERAL,
        };
        out.put_pod(wire::tag::INFO, &info)?;
        Ok(())
    }
}

busbar_plugin_abi::plugin!(Store, Fixture, name: "native-store-fixture");
