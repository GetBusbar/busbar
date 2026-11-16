// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bootstrap record and directory capabilities never acquire a Store after construction.

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
