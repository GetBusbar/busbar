// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::PluginsCfg;
use busbar_plugin_loader::sign::{SigningKey, TrustPolicy};

#[must_use]
pub fn release_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

pub fn trust_policy(cfg: &PluginsCfg) -> Result<TrustPolicy, String> {
    crate::root::boot::trust_policy(cfg, env!("CARGO_PKG_VERSION"))
}

pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY",
            hex::encode(release_key().verifying_key().as_bytes()),
        );
        let destinations = busbar_kernel::config::Destinations {
            block_private_addresses: busbar_kernel::config::AdvancedCfg::default()
                .block_private_addresses,
            ..Default::default()
        };
        let judge = crate::root::connector::guard_for(&destinations)
            .expect("the fixture's default destination policy");
        let services = crate::root::serve::Services::serving(std::sync::Arc::new(
            crate::root::serve::kernel_services(judge.clone()).with_credentials(
                std::sync::Arc::new(crate::root::credentials::AppCredentials::new(None)),
            ),
        ));
        let dispatcher = crate::root::dispatch::boot(1, &services);
        crate::root::doors::install_dispatcher(dispatcher);
        crate::root::linked::register_stores();
        crate::register_protocols();
        crate::register_planes();
        crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
        crate::register_diagnostics();
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            "providers: {}\nmodels: {}\n",
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the loopback IdP deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the loopback IdP deployment resolves");
        assert_eq!(
            cfg.destinations(),
            destinations,
            "the fixture guard matches its deployment"
        );
        static IO: std::sync::OnceLock<crate::root::boot::process::ProcessIo> =
            std::sync::OnceLock::new();
        let io = IO.get_or_init(|| {
            crate::root::boot::process::ProcessIo::new().expect("fixture I/O executor")
        });
        crate::root::connector::boot(
            io.handle(),
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
            crate::root::exports::EXPORTS.linked(name, None)
                || crate::root::exports::EXPORTS.linked(alias, None),
            "the distribution must link the export plugin {name} ({alias})",
        );
    }
}
