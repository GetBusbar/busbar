// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_dispatcher_is_built_once_and_every_caller_shares_it() {
    let a = boot(3, &crate::root::serve::Services::bootstrap());
    let b = dispatcher();
    let c = boot(9, &crate::root::serve::Services::bootstrap());
    assert!(Arc::ptr_eq(&a, &b), "one dispatcher per process");
    assert!(Arc::ptr_eq(&a, &c), "the first build stands");
    assert!(a.workers() >= 1);
}

#[test]
fn one_plugin_worker_per_data_worker() {
    assert_eq!(config(4).workers, 4);
    assert_eq!(config(0).workers, 1, "never zero workers");
}

#[test]
fn test_builds_watch_with_the_shipped_budgets() {
    assert_eq!(
        config(1).budgets,
        crate::root::loader::dispatch::Budgets::default()
    );
}

#[test]
fn the_binarys_dispatcher_serves_dest_judge_once_composed() {
    use busbar_contract::abi::host::service as svc;
    use busbar_contract::services::{Ran, Stored};

    let judged = |d: &Dispatcher, dest: &str| -> Stored {
        let services = d
            .host_services()
            .expect("the binary's dispatcher has a provider");
        match services.dest_judge(dest, crate::root::serve::DEFAULT_EGRESS_CLASS, 0, None) {
            Ran::Now(stored) => stored,
            Ran::Later => panic!("an unresolved judgement answers at once"),
        }
    };
    let late = crate::root::serve::Services::bootstrap();
    let bootstrap_dispatcher = build(1, &late);
    assert_eq!(
        judged(&bootstrap_dispatcher, "https://93.184.216.34/"),
        Stored::refused(crate::root::serve::NOT_INSTALLED),
        "before the composition every service answers REFUSED"
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\n",
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("a minimal deployment");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    let credentials = crate::root::credentials::AppCredentials::new(None);
    let credential_owner = credentials.clone();
    let serving = crate::root::serve::Services::serving(Arc::new(
        crate::root::serve::kernel_services(crate::root::connector::dest_judge(&cfg))
            .with_credentials(Arc::new(credentials)),
    ));
    let dispatcher = build(1, &serving);
    assert_eq!(
        judged(&bootstrap_dispatcher, "https://93.184.216.34/"),
        Stored::refused(crate::root::serve::NOT_INSTALLED),
        "constructing serving services never upgrades bootstrap authority"
    );
    assert_eq!(
        judged(&dispatcher, "https://93.184.216.34/"),
        Stored::ready(svc::DEST_ALLOWED)
    );

    let services = dispatcher
        .host_services()
        .expect("the binary's dispatcher has a provider");
    match services.records_secret("a-kind", "an-id", Box::new(|_| {})) {
        Ran::Now(stored) => assert_eq!(
            stored,
            Stored::refused(busbar_kernel::host_services::NOT_READABLE)
        ),
        Ran::Later => panic!("the credential read answers at once"),
    }
    assert!(!busbar_contract::services::CredentialRead::installed(
        &credential_owner
    ));
    assert_eq!(
        judged(&dispatcher, "https://169.254.169.254/latest/meta-data/"),
        Stored::ready(svc::DEST_METADATA)
    );
    assert!(
        Dispatcher::new(config(1), busbar_kernel::host_services::caller_binding())
            .host_services()
            .is_none(),
        "RED arm: a dispatcher built with no provider serves no host service"
    );
}
