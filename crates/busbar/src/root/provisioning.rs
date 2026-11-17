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

impl ProvisioningAuth {
    pub(crate) fn described(
        name: &str,
        plugin: &str,
        id: u64,
        inbound: bool,
        facts: u64,
        methods: u64,
    ) -> Self {
        use busbar_plugin_abi::auth::{FB_PROVISION, M_VERIFY, M_VERIFY_IO};
        Self {
            name: name.into(),
            plugin: plugin.into(),
            id,
            inbound,
            facts: ProvisioningFacts {
                fb_provision: facts & FB_PROVISION != 0,
                verifies: methods & (M_VERIFY | M_VERIFY_IO) != 0,
            },
        }
    }
}

/// S7's complete services and dormant work. S9 starts `refresh.run()` with the generation's workers.
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

/// S9's route consumers. Every configured mount is completed from the actual opened instance;
/// a missing port or invalid describe aborts the candidate instead of silently omitting a route.
pub(crate) fn mounts(
    config: &Min3Config,
    auth: &super::min3_auth::AuthSet,
    app: &busbar_kernel::state::App,
    epoch: u64,
    body_cap: usize,
    call_budget: std::time::Duration,
    request_ids: Arc<std::sync::atomic::AtomicU64>,
) -> Result<Vec<Arc<super::provisioning_mount::ProvisionMount>>, String> {
    use super::provisioning_mount::{ClientPolicy, ProvisionMount};
    use busbar_plugin_abi::auth::{FB_PROVISION, M_SERVE, M_VERIFY, M_VERIFY_IO};

    let mut mounts = Vec::with_capacity(config.provisioning.len());
    for (name, cfg) in &config.provisioning {
        let instance = auth.get(name).ok_or_else(|| {
            format!("identity-providers.{name}.provisioning: no opened auth instance")
        })?;
        let opened = &instance.opened;
        if opened.port.facts() & FB_PROVISION == 0
            || opened.methods & (M_VERIFY | M_VERIFY_IO) == 0
            || opened.methods & M_SERVE == 0
        {
            return Err(format!(
                "identity-providers.{name}.provisioning: admitted auth lacks provision, verify or serve"
            ));
        }
        let credential_headers = opened
            .port
            .cred_headers()
            .iter()
            .map(|header| {
                axum::http::HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                    format!("identity-providers.{name}: invalid admitted credential header")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        mounts.push(Arc::new(ProvisionMount {
            name: name.clone(),
            plugin: opened.who.plugin.as_ref().into(),
            slot: opened.who.slot,
            out_of_process: opened.out_of_process,
            limits: opened.limits,
            port: Arc::clone(&opened.port),
            keys: Arc::clone(&instance.keys),
            holds: instance.holds.clone(),
            cache: Arc::clone(&auth.owners.cache),
            issued: Arc::clone(&auth.owners.issued),
            replay: Arc::clone(&auth.owners.replay),
            policy: ClientPolicy {
                instance: opened.who.instance,
                epoch,
                current_epoch: Arc::clone(&app.config_generation),
                clients: cfg.clients.clone(),
            },
            credential_headers,
            body_cap,
            timeout: if opened.limits.timeout_ms == 0 {
                call_budget
            } else {
                call_budget.min(std::time::Duration::from_millis(u64::from(
                    opened.limits.timeout_ms,
                )))
            },
            request_ids: Arc::clone(&request_ids),
        }));
    }
    Ok(mounts)
}

/// The same exact paths and methods feed physical selection and the core router's policy table.
pub(crate) fn route_lines(
    mounts: &[Arc<super::provisioning_mount::ProvisionMount>],
) -> Vec<(
    String,
    busbar_contract::abi::mechanism::route::RouteMethod,
    busbar_contract::abi::mechanism::route::RouteAuth,
)> {
    use busbar_contract::abi::mechanism::route::RouteAuth;
    mounts
        .iter()
        .flat_map(|mount| {
            super::off_path::serve::METHODS
                .into_iter()
                .map(move |method| {
                    (
                        busbar_core_admin::provision::mount_path(&mount.name),
                        method,
                        RouteAuth::None,
                    )
                })
        })
        .collect()
}

pub(crate) fn mount_routes(
    mut router: busbar_kernel::core_routes::CoreRouter,
    mounts: &[Arc<super::provisioning_mount::ProvisionMount>],
) -> busbar_kernel::core_routes::CoreRouter {
    use busbar_contract::abi::mechanism::route::RouteAuth;
    for mount in mounts {
        for method in super::off_path::serve::METHODS {
            let mounted = Arc::clone(mount);
            router = router.route(
                busbar_core_admin::provision::mount_path(&mount.name),
                method,
                RouteAuth::None,
                move |request: axum::extract::Request| {
                    let mounted = Arc::clone(&mounted);
                    async move { mounted.handle(request).await }
                },
            );
        }
    }
    router
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
    fn described_auth_requires_verify_even_when_it_can_serve() {
        use busbar_plugin_abi::auth::{FB_PROVISION, M_SERVE, M_VERIFY, M_VERIFY_IO};
        for verify in [M_VERIFY, M_VERIFY_IO] {
            let directory = ProvisioningAuth::described(
                "directory",
                "verified-directory-image",
                41,
                false,
                FB_PROVISION,
                M_SERVE | verify,
            );
            let mut auth = admitted();
            auth[0] = directory;
            let specs = specifications(&config(), &auth).expect("declared verify capability");
            assert_eq!(&*specs[0].plugin, "verified-directory-image");
            assert_eq!(specs[0].link_auth_ids, vec![42]);
        }
        let mut auth = admitted();
        auth[0] = ProvisioningAuth::described(
            "directory",
            "verified-directory-image",
            41,
            false,
            FB_PROVISION,
            M_SERVE,
        );
        assert!(
            specifications(&config(), &auth).is_err(),
            "serve cannot grant verify authority"
        );
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
