// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ROOT-BOOT: the records handle the Need handlers are built over before the store exists.

use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;

use super::{LateRecords, PluginRecords, RecordsDenied, Scope, StoreRecords};

fn caller<'a>() -> Caller<'a> {
    Caller {
        plugin: "plane-a2a",
        kind: KindCode::Plane,
        name: "agents",
        instance: 7,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now(),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

#[tokio::test]
async fn before_the_store_opens_every_call_is_unavailable() {
    let late: LateRecords<Arc<StoreRecords>> = LateRecords::default();
    let who = caller();
    let got = late
        .get(&who, Scope::default(), b"k", &mut |_: &[u8]| {})
        .await;
    assert_eq!(got, Err(RecordsDenied::Unavailable));
    let put = late.put(&who, Scope::default(), b"k", b"v", 0).await;
    assert_eq!(put, Err(RecordsDenied::Unavailable));
}

#[tokio::test]
async fn once_installed_every_clone_answers_through_the_owner_and_the_first_install_stays() {
    let late: LateRecords<Arc<StoreRecords>> = LateRecords::default();
    let clone = late.clone();
    let owner = Arc::new(StoreRecords::new(crate::real_store::core().await));
    assert!(late.install(Arc::clone(&owner)));
    assert!(!clone.install(owner), "a second install is ignored");
    let who = caller();
    clone
        .put(&who, Scope::default(), b"k", b"v", 0)
        .await
        .expect("the installed owner takes the write");
    let mut seen = Vec::new();
    let found = late
        .get(&who, Scope::default(), b"k", &mut |v: &[u8]| {
            seen.extend_from_slice(v)
        })
        .await;
    assert_eq!(found, Ok(true));
    assert_eq!(seen, b"v");
}
