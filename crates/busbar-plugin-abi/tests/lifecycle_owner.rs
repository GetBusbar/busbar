// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![cfg(feature = "host")]

#[test]
fn sdk_and_native_lifecycle_share_the_actual_worker_marker() {
    let caller = std::thread::current().id();
    let mut text = String::from("borrowed");
    busbar_plugin_abi::host_side::lifecycle::run(|| {
        assert!(busbar_ffi::lifecycle::is_worker());
        assert!(busbar_plugin_abi::host_side::lifecycle::is_worker());
        assert_ne!(std::thread::current().id(), caller);
        text.push_str(" through SDK");
    })
    .unwrap();
    let answer = busbar_plugin_abi::host_side::lifecycle::run(|| text.as_str()).unwrap();
    assert_eq!(answer, "borrowed through SDK");
}
