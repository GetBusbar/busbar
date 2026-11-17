// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native auth owners use the selected generation's real custody and explicit operator grants.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::services::CredentialRead;
use busbar_kernel::auth::verdicts::Verdicts;
use busbar_kernel::config::min3::Min3Config;
use busbar_kernel::ingress::replay::StoreReplay;
use busbar_kernel::issued::CredentialIssued;
use busbar_kernel::plugin_records::StoreRecords;
use busbar_kernel::state::App;

use super::credentials::AppCredentials;
use super::min3_auth::{AuthOwners, OpenedAuth};
use super::min3_auth::{AuthSet, NativeChain};

/// Assemble every configured native admin position before this candidate is published.
pub(crate) fn install(app: &mut App, auth: Arc<AuthSet>, epoch: u64) -> Result<(), String> {
    let mut chains = BTreeMap::new();
    let mut unset = BTreeSet::new();
    for name in &app.admin_chain {
        if name == busbar_kernel::config::KEYS_MODULE {
            continue;
        }
        if auth.get(name).is_none()
            && app.admin_modules.operator.unset(name)
            && app
                .identity_providers
                .get(name)
                .is_none_or(|cfg| cfg.token.is_none())
        {
            unset.insert(name.clone());
            continue;
        }
        chains.insert(
            name.clone(),
            Arc::new(auth.operator_chain(app, epoch, &[name.as_str()])?),
        );
    }
    app.native_admin = Some(Arc::new(Admin { chains, unset }));
    Ok(())
}

struct Admin {
    chains: BTreeMap<String, Arc<NativeChain>>,
    unset: BTreeSet<String>,
}
impl busbar_kernel::auth::native_admin::NativeAdmin for Admin {
    fn prepare<'a>(
        &'a self,
        name: &'a str,
        cx: busbar_ports::CallCx,
        request: Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_kernel::auth::native_admin::PreparedAnswer, busbar_ports::PortError>,
    > {
        Box::pin(async move {
            if self.unset.contains(name) {
                return Ok(busbar_kernel::auth::native_admin::PreparedAnswer::NotMine);
            }
            let chain = self.chains.get(name).ok_or(busbar_ports::PortError::Call(
                busbar_plugin_abi::fail::CallError::NotDeclared,
            ))?;
            chain.prepare(cx, request).await
        })
    }
}

pub(crate) fn owners(
    app: &App,
    config: &Min3Config,
    opened: &[OpenedAuth],
    records: Arc<StoreRecords>,
) -> Result<AuthOwners, String> {
    let credentials: Arc<dyn CredentialRead> =
        Arc::new(AppCredentials::new(app.governance.clone()));
    let instances = opened.iter().map(|opened| GrantInstance {
        name: &opened.who.name,
        id: opened.who.instance,
        kind: opened.port.issued_kind(),
        verifies: opened.methods
            & (busbar_plugin_abi::auth::M_VERIFY | busbar_plugin_abi::auth::M_VERIFY_IO)
            != 0,
    });
    let grants = resolve_grants(&config.issued_kinds, instances, credentials.installed())?;
    let policy = config.verdict_cache.checked().map_err(str::to_owned)?;
    Ok(AuthOwners {
        issued: Arc::new(CredentialIssued::new(credentials, grants)),
        replay: Arc::new(StoreReplay::new(records)),
        cache: Arc::new(Verdicts::new(policy)),
    })
}

struct GrantInstance<'a> {
    name: &'a str,
    id: u64,
    kind: Option<&'a str>,
    verifies: bool,
}

fn resolve_grants<'a>(
    configured: &BTreeMap<Box<str>, BTreeSet<Box<str>>>,
    opened: impl IntoIterator<Item = GrantInstance<'a>>,
    custody_installed: bool,
) -> Result<BTreeMap<u64, BTreeSet<Box<str>>>, String> {
    let mut instances = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for instance in opened {
        if instance.id == 0 || !ids.insert(instance.id) || instances.contains_key(instance.name) {
            return Err(format!(
                "identity-providers.{}.issued_kinds: ambiguous native auth reservation",
                instance.name
            ));
        }
        instances.insert(instance.name, instance);
    }
    let mut grants = BTreeMap::new();
    for (name, kinds) in configured {
        let instance = instances.get(name.as_ref()).ok_or_else(|| {
            format!("identity-providers.{name}.issued_kinds: no opened native auth instance")
        })?;
        if name.as_ref() == busbar_kernel::config::KEYS_MODULE
            || !instance.verifies
            || kinds
                .iter()
                .any(|kind| instance.kind != Some(kind.as_ref()))
        {
            return Err(format!(
                "identity-providers.{name}.issued_kinds: grant does not match the admitted verifier"
            ));
        }
        if !kinds.is_empty() && !custody_installed {
            return Err(format!(
                "identity-providers.{name}.issued_kinds: credential custody is unavailable"
            ));
        }
        grants.insert(instance.id, kinds.clone());
    }
    Ok(grants)
}

#[cfg(test)]
#[path = "tests/min3_admin_auth.rs"]
mod tests;
