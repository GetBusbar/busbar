// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIT'S OPEN PATH (DES-STOREKIT r2 §2.1), harness builds only.
//!
//! One admitted store image, opened as S6 opens the configured store:
//! - [`super::build`]'s registry over the production Need handlers;
//! - the bootstrap Needs ([`super::Built::bootstrap_needs_for`]);
//! - `Registry::open_store` with the kernel's own seal.
//!
//! The only difference from S6 is the instance: the kit opens a new instance name for every handle
//! it asks for, so a second "process" reaches the same dataset through its own instance. No
//! legacy door, linked twin or test seal is involved.

use std::sync::Arc;

use busbar_contract::persistence::PersistenceBackend;
use busbar_contract::secret_ref::Sugars;
use busbar_core_connector::guard::Guard;
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
    /// store's outbound connections as the deployment's guard does.
    ///
    /// # Errors
    /// No store image, or more than one.
    pub(crate) fn new(
        process: &ProcessResources,
        guard: Guard,
        images: Images,
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
        Ok(Self {
            built: Built {
                registry,
                sugars,
                secrets,
                binder,
                guard,
            },
            identity,
        })
    }

    /// A new instance `name` over `config_json`, opened exactly as S6 opens the configured store.
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
