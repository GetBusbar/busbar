// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_kernel::config::min3::{Min3Config, ProvisioningCfg};
    use busbar_kernel::directory::ProvisioningFacts;

    fn config() -> Min3Config {
        let cfg: ProvisioningCfg = busbar_contract::yaml::from_str(
            "clients: [idp]\nlink: {index: email, auth: [login], refresh_ms: 1000}\nguard: {max: 50, window_s: 3600}\n",
        ).expect("policy");
        let mut config = Min3Config::default();
        config.provisioning.insert("directory".into(), cfg);
        config
    }

    fn admitted() -> Vec<ProvisioningAuth> {
        vec![
            ProvisioningAuth {
                name: "directory".into(),
                plugin: "verified-directory-image".into(),
                id: 41,
                inbound: false,
                facts: ProvisioningFacts {
                    fb_provision: true,
                    verifies: true,
                },
            },
            ProvisioningAuth {
                name: "login".into(),
                plugin: "verified-login-image".into(),
                id: 42,
                inbound: true,
                facts: ProvisioningFacts {
                    fb_provision: false,
                    verifies: true,
                },
            },
        ]
    }

    #[test]
    fn directory_specs_use_verified_stamp_and_reserved_inbound_id() {
        let specs = specifications(&config(), &admitted()).unwrap_or_else(|why| panic!("{why:?}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(&*specs[0].plugin, "verified-directory-image");
        assert_eq!(&*specs[0].name, "directory");
        assert_eq!(specs[0].link_auth_ids, vec![42]);
    }

    #[test]
    fn provisioning_refuses_unadmitted_or_non_inbound_links() {
        let mut auth = admitted();
        auth[1].inbound = false;
        assert!(specifications(&config(), &auth).is_err());
        auth.pop();
        assert!(specifications(&config(), &auth).is_err());
    }

    #[test]
    fn provisioning_refuses_missing_capability_or_verify() {
        let mut auth = admitted();
        auth[0].facts.fb_provision = false;
        assert!(specifications(&config(), &auth).is_err());
        auth[0].facts.fb_provision = true;
        auth[0].facts.verifies = false;
        assert!(specifications(&config(), &auth).is_err());
    }

    #[test]
    fn provisioning_refuses_ambiguous_runtime_reservations() {
        let mut auth = admitted();
        auth[1].id = auth[0].id;
        assert!(specifications(&config(), &auth).is_err());
        auth[1].id = 42;
        auth[1].name = auth[0].name.clone();
        assert!(specifications(&config(), &auth).is_err());
    }
}
