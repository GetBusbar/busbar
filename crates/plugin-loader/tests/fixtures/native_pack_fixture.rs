// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

use busbar_plugin_abi::fail::Fail;
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::need::ChainBytes;
use busbar_plugin_abi::plugin::{Endpoints, Open};
use busbar_plugin_abi::Secret;

pub struct Fixture;
impl Secret for Fixture {
    async fn resolve(
        &self,
        _host: &'static Host,
        _reference: ChainBytes,
    ) -> Result<busbar_plugin_abi::records::Reply, Fail> {
        panic!("pack must never resolve a secret")
    }
}
impl Open for Fixture {
    async fn open(_host: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
        panic!("pack must never open a plugin instance")
    }

    fn check(_host: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
        panic!("pack must never check plugin configuration")
    }

    fn describe(_describe: &mut busbar_plugin_abi::plugin::Describe<'_>) {
        panic!("pack must never describe a plugin")
    }
}

busbar_plugin_abi::plugin!(Secret, Fixture, name: "native-pack-fixture", former_names: "old-native,native");
busbar_plugin_abi::export!(PLUGIN);
