// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIT'S OPEN PATH (DES-STOREKIT r2 §2.1), harness builds only.
//!
//! One admitted store image, opened through the same open path S6 uses:
//! - a `Registry` over the production Need handlers (the `Built` S6 uses);
//! - the bootstrap Needs ([`super::Built::bootstrap_needs_for`]);
//! - `Registry::open_store` with the kernel's own seal.
//!
//! No legacy door, linked twin or test seal is involved. It is not identical to S6, and it does not
//! claim to be. The differences are:
//! - **instance:** a new instance name for every handle the kit asks for, so a second "process"
//!   reaches the same dataset through its own instance (S6 opens one configured instance);
//! - **limits:** `InstanceLimits::default()`, not the deployment's configured store limits;
//! - **purpose:** always `Canonical`, never the converting open of an unstamped 1.5.5 boot;
//! - **binder:** no secret shorthand and no reference schema, because a kit config names no secret;
//! - **guard:** the runner's, with private addresses allowed so the store reaches its CI service.

use std::sync::Arc;

use busbar_contract::persistence::PersistenceBackend;
use busbar_contract::secret_ref::Sugars;
use busbar_core_connector::guard::Guard;
use busbar_core_connector::need::network::{BootstrapConnector, NetworkInputs};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_plugin_abi::host_side::caller::InstanceLimits;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{Images, InstanceSpec, OpenPurpose, Registry};
use busbar_plugin_loader::process::ProcessResources;

use super::{BootSecrets, Built};

/// The admitted store image and the registry that opens it.
pub(crate) struct KitStore {
    built: Built,
    identity: String,
}

impl KitStore {
    /// Over `images`, which must hold one store image. The registry's binder knows no secret
    /// shorthand and no reference schema, because a kit config names no secret. `guard` judges the
    /// store's outbound connections as the deployment's guard does, through one bootstrap network
    /// owner (#298) on `runtime`, the runtime the kit drives the store on: default outbound TLS, the
    /// process proxy choice and the system resolver.
    ///
    /// # Errors
    /// No store image, or more than one.
    pub(crate) fn new(
        process: &ProcessResources,
        guard: Guard,
        images: Images,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let stores: Vec<String> = images
            .identities()
            .filter(|identity| {
                images
                    .described(identity)
                    .is_some_and(|facts| facts.kind == KindCode::Store)
            })
            .map(str::to_owned)
            .collect();
        let [identity] = <[String; 1]>::try_from(stores).map_err(|stores| {
            format!(
                "the store kit opens exactly one store image; the pack holds {}",
                stores.len()
            )
        })?;
        let sugars = Sugars::default();
        let binder: Arc<dyn ConfigBinder> =
            Arc::new(Binder::new(Arc::new(sugars.clone()), Vec::new()));
        let secrets = BootSecrets::empty(Arc::clone(&binder), Arc::clone(process.slots()));
        let registry = Arc::new(Registry::new(
            images,
            Arc::clone(&binder),
            Arc::clone(process.ids()),
        ));
        let network = super::NetworkOwner::Bootstrap(BootstrapConnector::new(NetworkInputs {
            runtime,
            guard: guard.freeze(),
            resolver: Arc::new(busbar_core_connector::guard::SystemResolver),
            trust: super::super::connector::trust_store_of(&Default::default())
                .map_err(|errors| errors.join("\n"))?,
            proxy: busbar_core_connector::proxy::from_env()?,
            resolution: Default::default(),
            observations: Arc::default(),
        }));
        Ok(Self {
            built: Built {
                registry,
                sugars,
                secrets,
                binder,
                network,
            },
            identity,
        })
    }

    /// A new instance `name` over `config_json`, through S6's open path with the differences the
    /// module documentation lists (default limits, canonical purpose).
    ///
    /// # Errors
    /// The open's refusal, as the registry states it.
    pub(crate) async fn open(
        &self,
        name: &str,
        config_json: &[u8],
    ) -> Result<Arc<dyn PersistenceBackend>, String> {
        let spec = InstanceSpec {
            purpose: OpenPurpose::Canonical,
            identity: &self.identity,
            name,
            config_json,
            limits: InstanceLimits::default(),
            public_url: None,
            caller_upstreams: &[],
            store_migration: None,
        };
        let needs = self
            .built
            .bootstrap_needs_for(Arc::clone(&self.built.secrets));
        self.built
            .registry
            .open_store(
                &spec,
                &needs,
                &self.built.secrets.refs(),
                Arc::new(|| Box::new(busbar_kernel::seal::lend())),
            )
            .await
            .map(|handle| handle.backend)
            .map_err(|error| format!("the store refused instance `{name}`: {error:?}"))
    }
}
