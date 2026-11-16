// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`StoreReplay`]: replay claims, one atomic put-if-absent in the core sub-namespace
//! (who.plugin, who.name, "replay"), visible to every replica (IF §12.11).

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::plane_grants::{core_caller, core_name, ReplayGuard};
use crate::plugin_records::{PluginRecords, RecordsDenied, Scope};

const TAG: &str = "replay";
/// The ttl bounds of a claim, seconds.
pub const MIN_TTL_S: u64 = 1;
pub const MAX_TTL_S: u64 = 86_400;

/// Replay claims over the plugin-records store `R`.
pub struct StoreReplay<R> {
    records: R,
}

impl<R: PluginRecords> StoreReplay<R> {
    pub fn new(records: R) -> Self {
        Self { records }
    }
}

impl<R: PluginRecords> ReplayGuard for StoreReplay<R> {
    fn claim<'a>(
        &'a self,
        who: &'a Caller<'_>,
        key: &'a [u8],
        ttl_s: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        Box::pin(async move {
            let name = core_name(who.name, TAG);
            let ns = core_caller(who, &name);
            self.records
                .claim(&ns, Scope::default(), key, b"1", ttl_s.clamp(MIN_TTL_S, MAX_TTL_S))
                .await
        })
    }
}
