// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_dispatcher_is_built_once_and_every_caller_shares_it() {
    let a = boot(3, crate::root::serve::LateServices::new());
    let b = dispatcher();
    let c = boot(9, crate::root::serve::LateServices::new());
    assert!(Arc::ptr_eq(&a, &b), "one dispatcher per process");
    assert!(Arc::ptr_eq(&a, &c), "the first build stands");
    assert!(a.workers() >= 1);
}

#[test]
fn one_plugin_worker_per_data_worker() {
    assert_eq!(config(4).workers, 4);
    assert_eq!(config(0).workers, 1, "never zero workers");
}
