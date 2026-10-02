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

/// THE BINARY'S DISPATCHER SERVES THE KERNEL'S HOST SERVICES, booted as `run()` boots it: the
/// dispatcher over the composition's late services, then the composition once the configuration
/// resolves. Before the composition every service answers REFUSED; after it `dest.judge` answers
/// READY with the kernel's verdicts. The RED arm: a dispatcher built with no provider (the binary
/// before U8) serves nothing, so every service answers REFUSED.
#[test]
fn the_binarys_dispatcher_serves_dest_judge_once_composed() {
    use busbar_contract::abi::host::service as svc;
    use busbar_contract::services::{Ran, Stored};

    let judged = |d: &Dispatcher, dest: &str| -> Stored {
        let services = d
            .host_services()
            .expect("the binary's dispatcher has a provider");
        match services.dest_judge(dest, crate::root::serve::DEFAULT_EGRESS_CLASS, false, None) {
            Ran::Now(stored) => stored,
            Ran::Later => panic!("an unresolved judgement answers at once"),
        }
    };
    let late = crate::root::serve::LateServices::new();
    let dispatcher = build(1, late.clone());
    assert_eq!(
        judged(&dispatcher, "https://93.184.216.34/"),
        Stored::refused(crate::root::serve::NOT_INSTALLED),
        "before the composition every service answers REFUSED"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str("providers: {}\nmodels: {}\n")
        .expect("a minimal deployment");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    let (credentials, credential_handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(&cfg, &late, credentials);
    assert_eq!(
        judged(&dispatcher, "https://93.184.216.34/"),
        Stored::ready(svc::DEST_ALLOWED)
    );
    // `records.secret` is the composition's too: REFUSED until the App's swap handle is set.
    let services = dispatcher
        .host_services()
        .expect("the binary's dispatcher has a provider");
    match services.records_secret("a-kind", "an-id", Box::new(|_| {})) {
        Ran::Now(stored) => assert_eq!(
            stored,
            Stored::refused(crate::root::credentials::NOT_READABLE)
        ),
        Ran::Later => panic!("the credential read answers at once"),
    }
    assert!(!credential_handle.is_set());
    assert_eq!(
        judged(&dispatcher, "https://169.254.169.254/latest/meta-data/"),
        Stored::ready(svc::DEST_METADATA)
    );
    assert!(
        Dispatcher::new(config(1)).host_services().is_none(),
        "RED arm: a dispatcher built with no provider serves no host service"
    );
}
