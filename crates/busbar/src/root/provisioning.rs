// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Provisioning composition from described images and reserved candidate instance IDs.
//! No plugin opens or background tasks occur while resolving the candidate metadata.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::config::min3::Min3Config;
use busbar_kernel::directory::{
    check_provisioning, DirectoryEvents, DirectoryRefresh, Holds, KernelDirectory,
    ProvisioningFacts, ProvisioningInstance,
};
use busbar_kernel::persistence::facade::CoreStore;

/// S4b's admitted image identity and reservation, after the describe walk.
pub(crate) struct ProvisioningAuth {
    pub(crate) name: Box<str>,
    /// Verified image stamp, never the configured module alias.
    pub(crate) plugin: Box<str>,
    /// The reservation S8 must consume for this same instance.
    pub(crate) id: u64,
    pub(crate) inbound: bool,
    pub(crate) facts: ProvisioningFacts,
}

/// S7's complete services and dormant work. Only S9 may consume `refresh.start()`.
pub(crate) struct PreparedProvisioning {
    pub(crate) directory: Arc<KernelDirectory>,
    pub(crate) holds: Arc<Holds>,
    pub(crate) refresh: DirectoryRefresh,
}

pub(crate) fn specifications(
    config: &Min3Config,
    auth: &[ProvisioningAuth],
) -> Result<Vec<ProvisioningInstance>, Vec<String>> {
    let mut by_name = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    let mut refused = Vec::new();
    for instance in auth {
        if by_name.insert(instance.name.as_ref(), instance).is_some() {
            refused.push(format!(
                "identity-providers.{}: duplicate candidate instance",
                instance.name
            ));
        }
        if by_id.insert(instance.id, instance.name.as_ref()).is_some() {
            refused.push(format!(
                "identity-providers.{}: duplicate candidate instance reservation",
                instance.name
            ));
        }
    }
    let inbound = |name: &str| by_name.get(name).is_some_and(|entry| entry.inbound);
    let mut specs = Vec::new();
    for (name, cfg) in &config.provisioning {
        let Some(instance) = by_name.get(name.as_ref()) else {
            refused.push(format!(
                "identity-providers.{name}.provisioning: no admitted candidate auth instance"
            ));
            continue;
        };
        if let Err(mut why) = check_provisioning(name, cfg, instance.facts, &inbound) {
            refused.append(&mut why);
            continue;
        }
        let link_auth_ids = cfg.link.as_ref().map_or_else(Vec::new, |link| {
            link.auth
                .iter()
                .filter_map(|name| by_name.get(name.as_ref()).map(|auth| auth.id))
                .collect()
        });
        specs.push(ProvisioningInstance {
            plugin: instance.plugin.clone(),
            name: name.clone(),
            cfg: cfg.clone(),
            link_auth_ids,
        });
    }
    if refused.is_empty() {
        Ok(specs)
    } else {
        Err(refused)
    }
}

pub(crate) async fn prepare(
    store: Arc<CoreStore>,
    events: Arc<dyn DirectoryEvents>,
    specs: Vec<ProvisioningInstance>,
) -> Result<PreparedProvisioning, String> {
    let (directory, holds, refresh) = KernelDirectory::prepare(store, events, specs).await?;
    Ok(PreparedProvisioning {
        directory: Arc::new(directory),
        holds: Arc::new(holds),
        refresh,
    })
}

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
