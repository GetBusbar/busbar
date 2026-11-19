// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_composed_kernel_services_are_kept_for_the_driver() {
    let bootstrap = Services { kernel: None };
    assert!(
        bootstrap.kernel().is_none(),
        "bootstrap has no serving kernel"
    );
    let composed = Arc::new(KernelServices::new());
    let serving = Services::serving(Arc::clone(&composed));
    assert!(Arc::ptr_eq(&serving.kernel().expect("kept"), &composed));
    let other = Services::serving(Arc::new(KernelServices::new()));
    assert!(!Arc::ptr_eq(&other.kernel().expect("other"), &composed));
    assert!(Arc::ptr_eq(
        &serving.kernel().expect("still kept"),
        &composed
    ));
    assert!(
        bootstrap.kernel().is_none(),
        "construction grants bootstrap no authority"
    );
}

#[test]
fn admin_trust_binds_one_kernel() {
    let kernel = Arc::new(KernelServices::new());
    let services = Services::serving(Arc::clone(&kernel));
    let (decide, read) = admin_trust(&services);
    assert!(decide.as_ref().is_some_and(|k| Arc::ptr_eq(k, &kernel)));
    assert!(read.as_ref().is_some_and(|r| r.same_kernel(&kernel)));
    let (decide, read) = admin_trust(&Arc::new(Services { kernel: None }));
    assert!(decide.is_none() && read.is_none());
}
