// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MIN-3 store image whose describe touches a `thread_local!` with a destructor on the calling worker. glibc then
//! keeps the image mapped after `dlclose` until that worker exits, which a permanent worker never does: the image
//! pins itself (DES-443 r3 §4). Its describe answers a small valid D_SCHEMA. Every method refuses: the image is
//! never meant to open.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
use busbar_plugin_abi::records::{Out, Reply};
use busbar_plugin_abi::store as wire;
use busbar_plugin_abi::Store;

/// A value whose destructor registers this image with the thread's exit handlers.
pub struct Held(u8);

impl Drop for Held {
    fn drop(&mut self) {
        self.0 = 0;
    }
}

thread_local! {
    static HELD: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    static PIN: Held = const { Held(1) };
}

pub struct Pinned;

impl Open for Pinned {
    async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        Err(Fail::unsupported())
    }

    fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        Ok(())
    }

    fn describe(d: &mut Describe<'_>) {
        PIN.with(|held| HELD.with(|cell| cell.set(held.0)));
        d.schema(r#"{"type":"object","properties":{"path":{"type":"string"}}}"#);
        d.facts(wire::FB_EPHEMERAL);
    }
}

impl Store for Pinned {
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

busbar_plugin_abi::plugin!(Store, Pinned, former_names: "tls-pin", name: "native-tls-pin");
busbar_plugin_abi::export!(PLUGIN);
