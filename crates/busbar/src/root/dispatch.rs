// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::serve::LateServices;

static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();

#[must_use]
pub fn config(workers: usize) -> DispatchConfig {
    DispatchConfig {
        workers: u32::try_from(workers).unwrap_or(u32::MAX).max(1),
        ..DispatchConfig::default()
    }
}

pub fn boot(workers: usize, services: &LateServices) -> Arc<Dispatcher> {
    Arc::clone(DISPATCHER.get_or_init(|| Arc::new(build(workers, services))))
}

#[must_use]
pub fn build(workers: usize, services: &LateServices) -> Dispatcher {
    let dispatcher = Dispatcher::with_slot(config(workers), services.slot());
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    dispatcher
}

#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    boot(1, &LateServices::new())
}

pub fn auth_axis(
    registry: Arc<dyn busbar_contract::plugin_rows::PluginRows>,
) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    let registry = crate::root::loader::rows::registry_arc(registry)
        .unwrap_or_else(|| Arc::new(crate::root::boot::linked_registry()));
    Arc::new(RootAuthAxis(
        crate::root::loader::auth_axis::AuthRows::new(registry, dispatcher())
            .with_conns(conns)
            .with_logs(|| crate::root::boot::plugin_logs().clone()),
    ))
}

struct RootAuthAxis(crate::root::loader::auth_axis::AuthRows);

impl busbar_contract::auth_calls::AuthAxis for RootAuthAxis {
    fn linked_names(&self) -> Vec<String> {
        self.0.linked_names()
    }

    fn answers(&self, module: &str) -> bool {
        self.0.answers(module)
    }

    fn linked(&self, module: &str) -> bool {
        self.0.linked(module)
    }

    fn operator(&self) -> Option<(String, String)> {
        self.0.operator()
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn busbar_contract::auth_calls::AuthCalls>, String> {
        self.0.open(module, label, settings)
    }

    fn credential_readers(&self) -> Vec<String> {
        self.0.credential_readers()
    }

    fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        self.0.issued_credential()
    }

    fn carriers(&self, module: &str) -> Vec<String> {
        self.0.carriers(module)
    }

    fn inbound_style(&self, module: &str) -> Option<busbar_contract::auth_calls::InboundStyle> {
        self.0.inbound_style(module)
    }

    fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        self.0.default_inbound_style()
    }

    fn outbound_styles(&self) -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
        crate::root::door_steps::declared_styles()
    }

    fn check_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        crate::root::door_steps::process_auths().check(style, credential, settings)
    }

    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        Ok(crate::root::door_steps::process_auths()
            .serving(style, settings)?
            .map(
                |(auth, decl)| busbar_contract::auth_calls::OutboundServing {
                    auth,
                    flags: decl.flags,
                    points: decl.points,
                },
            ))
    }
}

fn conns() -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    crate::root::connector::the().clone()
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;

#[cfg(all(test, linked_every_auth))]
#[path = "tests/declared_credentials.rs"]
mod declared_credentials_tests;
