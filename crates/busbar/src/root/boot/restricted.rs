// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bootstrap record and directory capabilities never acquire a Store after construction.

use busbar_kernel::plugin_records::{
    ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope,
};
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};

#[derive(Clone, Copy)]
pub(crate) struct BootstrapRecords;

impl PluginRecords for BootstrapRecords {
    fn claim_until(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _expires_at_s: u64,
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn get(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn put(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _ttl_s: u64,
    ) -> impl core::future::Future<Output = Result<(), RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn claim(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
        _value: &[u8],
        _ttl_s: u64,
    ) -> impl core::future::Future<Output = Result<bool, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn del(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _key: &[u8],
    ) -> impl core::future::Future<Output = Result<(), RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn list(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _prefix: &[u8],
        _limit: u32,
        _sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<u32, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn commit(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _ops: &[CommitOp<'_>],
    ) -> impl core::future::Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn append(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _chain: &[u8],
        _entry: &[u8],
    ) -> impl core::future::Future<Output = Result<u64, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
    fn chain(
        &self,
        _who: &Caller<'_>,
        _scope: Scope,
        _chain: &[u8],
        _after: u64,
        _limit: u32,
        _sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> impl core::future::Future<Output = Result<ChainRead, RecordsDenied>> + Send {
        std::future::ready(Err(RecordsDenied::Unavailable))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BootstrapDirectory;

impl busbar_kernel::directory::PluginDirectory for BootstrapDirectory {
    fn apply(
        &self,
        _who: &Caller<'_>,
        _need: DirNeed<'_>,
        _out: &mut NeedOut<'_>,
    ) -> impl core::future::Future<Output = Result<(), NeedErr>> + Send {
        std::future::ready(Err(NeedErr::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_kernel::plugin_records::{PluginRecords, RecordsDenied, Scope};

    #[tokio::test]
    async fn bootstrap_records_never_claim_durability_or_produce_read_values() {
        let who = busbar_kernel::plane_driver::port_intents::Namespace {
            plugin: "secret-test".into(),
            name: "source".into(),
            instance: 1,
            slot: 1,
        };
        let caller = who.caller();
        let mut called = false;
        let mut sink = |_: &[u8]| called = true;
        assert_eq!(
            BootstrapRecords
                .get(&caller, Scope::default(), b"key", &mut sink)
                .await,
            Err(RecordsDenied::Unavailable)
        );
        assert!(!called);
        assert_eq!(
            BootstrapRecords
                .claim(&caller, Scope::default(), b"key", b"value", 0)
                .await,
            Err(RecordsDenied::Unavailable)
        );
        assert_eq!(
            BootstrapRecords
                .commit(&caller, Scope::default(), &[])
                .await,
            Err(RecordsDenied::Unavailable)
        );
    }
}
