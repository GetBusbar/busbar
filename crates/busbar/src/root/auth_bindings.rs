// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The revocation set the admin door consults, bound to the governance state.
//!
//! The admin unit asks one question of the node's keys after the door identified a caller: has
//! this credential been taken away? [`AuthBindings`] carries the answer as a [`RevocationView`],
//! and [`GovernanceDirectory`] is the view for a node whose keys are busbar's own. Key
//! verification itself is the kernel auth chain's keys arm (`GovState::verify_token`).
//!
//! ## What an unbound node does
//!
//! [`AuthBindings::without_directory`] is a real posture and not a placeholder: a node that resolves
//! no busbar-minted keys has no revocation set to consult.
//!
//! ## No credential cache
//!
//! The kernel holds no verified-credential cache (THE DESIGN 11.11 R3): an auth plugin that caches
//! its verdicts does so inside itself, and the admin cache flush reaches it through its `refresh`.

use busbar_kernel_identity::RevocationView;
use std::sync::Arc;

pub struct AuthBindings {
    revocations: Option<Arc<dyn RevocationView>>,
}

impl AuthBindings {
    #[must_use]
    pub fn new(revocations: Arc<dyn RevocationView>) -> Self {
        AuthBindings {
            revocations: Some(revocations),
        }
    }

    #[must_use]
    pub(crate) fn without_directory() -> Self {
        AuthBindings { revocations: None }
    }

    #[must_use]
    pub fn revocations(&self) -> Option<&dyn RevocationView> {
        self.revocations.as_deref()
    }
}

impl std::fmt::Debug for AuthBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBindings")
            .field("revocations", &self.revocations.is_some())
            .finish()
    }
}

pub struct GovernanceDirectory {
    state: Arc<busbar_kernel::governance::GovState>,
}

impl GovernanceDirectory {
    #[must_use]
    pub fn new(state: Arc<busbar_kernel::governance::GovState>) -> Self {
        GovernanceDirectory { state }
    }
}

impl RevocationView for GovernanceDirectory {
    fn is_revoked(&self, credential: &str) -> bool {
        self.state.is_revoked(credential)
    }
}

/// THE OPERATOR CREDENTIAL, judged at process start from the auth rows the start scan admits:
/// the linked rows and the dropped-in ones alike (OPERATOR-FROM-ADMITTED-AUTH §3.1, §3.4). A start
/// whose `plugins:` block is in a pre-1.6 shape is `Deferred`: [`bind_from_planned`] binds it from
/// the migrate seam's planned config (§3.4.1).
#[must_use]
pub(crate) fn operator_binding(
    dropped: Option<&crate::root::loader::PluginRegistry>,
) -> busbar_kernel::preflight::OperatorBinding {
    if crate::root::boot::plugins_block_is_historical() {
        return busbar_kernel::preflight::OperatorBinding::Deferred;
    }
    busbar_kernel::preflight::OperatorBinding::Bound(judged_operator(dropped))
}

/// The operator judged from the linked rows, the rows of `dropped`, and the native (MIN-3) auth images the start
/// stage published ([`crate::root::native_operator`]).
#[must_use]
pub(crate) fn judged_operator(
    dropped: Option<&crate::root::loader::PluginRegistry>,
) -> busbar_kernel::preflight::Judged {
    let linked = crate::root::boot::linked_registry();
    let dropped = dropped.map_or(&[][..], crate::root::loader::PluginRegistry::loadable);
    let claims = crate::root::native_operator::NATIVE.merged(
        crate::root::loader::auth_axis::operator_claims(linked.linked().iter().chain(dropped)),
    );
    busbar_kernel::preflight::choose_operator(&claims)
}

/// A DEFERRED START'S OPERATOR (OPERATOR-FROM-ADMITTED-AUTH §3.4.1; MIGRATE-ON-BOOT r42 §3 step 2): on a start
/// whose `plugins:` block on disk is in a pre-1.6 shape, the operator credential is judged from the migrate
/// seam's planned `config` (held in memory until step 5 writes it), its `plugins:` block scanned exactly as the
/// start scan scans config.yaml, and bound before the configuration load. Any other start returns at once. A
/// start with no plan leaves the deferral unbound, so the load refuses with the deferred text.
pub(crate) fn bind_from_planned(config: &std::path::Path) -> Result<(), String> {
    use busbar_contract::yaml::ValueExt as _;
    if !crate::root::boot::plugins_block_is_historical()
        || busbar_kernel_identity::operator::judged().is_ok()
    {
        return Ok(());
    }
    let Some(planned) = crate::root::migrate::held(config) else {
        return Ok(());
    };
    let text = busbar_kernel::config::interpolate_env_with(
        &planned,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .map_err(|e| format!("config.yaml: {e}"))?;
    let doc = busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(&text)
        .map_err(|e| format!("config.yaml: {e}"))?;
    let plugins = doc
        .get("plugins")
        .cloned()
        .map(busbar_contract::yaml::from_value::<busbar_kernel::config::PluginsCfg>)
        .transpose()
        .map_err(|e| crate::root::cold::upgraded_plugins_unreadable(&e))?;
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    let registry = match &plugins {
        Some(p) if p.enabled => Some(crate::root::boot::registry(
            Vec::new(),
            Some(p),
            data_dir.as_deref(),
            &mut |_| {},
        )?),
        _ => None,
    };
    busbar_kernel::preflight::bind_deferred(judged_operator(registry.as_ref()))
}

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;
