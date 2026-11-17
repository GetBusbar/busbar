// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 store image whose describe answers a pathological D_SCHEMA: 500 nested `allOf` arrays. Core's D_SCHEMA
//! validator (IF r29 l.2764) refuses it at describe, so an inspect or install of this image is refused before any
//! instance opens. Every method refuses: the image is never meant to open.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use std::sync::OnceLock;

use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{Out, Reply};
use busbar_plugin_abi::store as wire;
use busbar_plugin_abi::Store;

/// The recursion bomb: valid JSON nested deeper than any schema parser's recursion limit.
fn bomb() -> &'static str {
    static BOMB: OnceLock<String> = OnceLock::new();
    BOMB.get_or_init(|| format!("{}true{}", "{\"allOf\":[".repeat(500), "]}".repeat(500)))
}

pub struct Bomb;

impl Open for Bomb {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Err(Fail::unsupported())
    }

    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }

    fn describe(d: &mut Describe<'_>) {
        d.schema(bomb());
        d.facts(wire::FB_EPHEMERAL);
    }
}

impl Store for Bomb {
    async fn read(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    async fn scan(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    async fn commit(&self, _h: &'static Host, _cand: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    async fn clock(&self, _h: &'static Host, _dataset: ChainBytes) -> Result<Reply, Fail> {
        Err(Fail::unsupported())
    }

    fn info(&self, _h: &Host, _out: &mut Out<'_>) -> Result<(), Fail> {
        Err(Fail::unsupported())
    }
}

busbar_plugin_abi::plugin!(Store, Bomb, former_names: "schema-bomb", name: "native-schema-bomb");
busbar_plugin_abi::export!(PLUGIN);
