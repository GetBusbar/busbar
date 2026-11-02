// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use busbar_kernel::config::PluginsCfg;
use busbar_plugin_loader::sign::{SigningKey, TrustPolicy};

pub use crate::root::admission::ADMISSION;

#[must_use]
pub fn release_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

pub fn trust_policy(cfg: &PluginsCfg) -> Result<TrustPolicy, String> {
    crate::root::boot::trust_policy(cfg, env!("CARGO_PKG_VERSION"))
}

// These cases are mounted in the distribution binary's unit-test target, so the
// same generated LINKED rows and boot functions that main uses own every axis.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY",
            hex::encode(release_key().verifying_key().as_bytes()),
        );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            "providers: {}\nmodels: {}\nadvanced:\n  allow_destinations: [127.0.0.1]\n",
        )
        .expect("the loopback IdP deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the loopback IdP deployment resolves");
        let judge = crate::root::connector::dest_judge(&cfg);
        let late = crate::root::serve::LateServices::new();
        let dispatcher = crate::root::dispatch::boot(1, &late);
        crate::root::doors::install_dispatcher(dispatcher);
        let (credentials, _handle) = crate::root::credentials::AppCredentials::late();
        crate::root::serve::compose(judge.clone(), &late, credentials);
        crate::register_protocols();
        crate::register_planes();
        crate::register_diagnostics();
        crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
        crate::root::connector::boot(
            crate::LINKED_TRANSPORT_DOORS,
            &crate::root::policy::client_settings(&cfg.limits),
            judge,
            &[],
        );
    });
}

pub type ExportDoor = (
    &'static str,
    &'static str,
    busbar_contract::abi::mechanism::door::DoorFn,
);

pub fn link_exports(exports: &'static [ExportDoor]) {
    use busbar_contract::export_calls::ExportAxis as _;
    install();
    for &(name, alias, _) in exports {
        assert!(
            crate::root::exports::EXPORTS.linked(name)
                || crate::root::exports::EXPORTS.linked(alias),
            "the distribution must link the export plugin {name} ({alias})",
        );
    }
}
