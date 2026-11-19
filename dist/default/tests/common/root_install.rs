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
            block_private_addresses: busbar_kernel::config::sections::OutboundCfg::default()
                .block_private_addresses,
            blocked: Vec::new(),
            // The deployment below states no listen addresses: the engine's own are the defaults.
            listens: vec![
                busbar_kernel::config::DEFAULT_LISTEN_ADDR.to_owned(),
                busbar_kernel::config::DEFAULT_ADMIN_LISTEN_ADDR.to_owned(),
            ],
        };
        let judge = crate::root::connector::guard_for(&destinations)
            .expect("the fixture's default destination policy");
        crate::root::linked::register_stores();
        crate::register_protocols();
        crate::register_diagnostics();
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            "providers: {}\nmodels: {}\n",
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the loopback IdP deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the loopback IdP deployment resolves");
        // The deployment's own listeners join its destinations as addresses never dialled; the
        // fixture serves no listener, so its guard matches the deployment's dialling policy.
        let deployed = cfg.destinations();
        assert_eq!(
            (deployed.block_private_addresses, &deployed.blocked),
            (destinations.block_private_addresses, &destinations.blocked),
            "the fixture guard matches its deployment's dialling policy"
        );
        static IO: std::sync::OnceLock<crate::root::boot::process::ProcessIo> =
            std::sync::OnceLock::new();
        let io = IO.get_or_init(|| {
            crate::root::boot::process::ProcessIo::new().expect("fixture I/O executor")
        });
        crate::root::connector::boot(
            io.handle(),
            &crate::root::policy::client_settings(&cfg.limits),
            judge,
            &[],
        );
    });
}
