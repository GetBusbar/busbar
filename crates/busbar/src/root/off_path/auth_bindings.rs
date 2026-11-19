// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential's binding at process start (OPERATOR-FROM-ADMITTED-AUTH §3.1, §3.4,
//! §3.4.1): off the request path. [`operator_binding`] runs once, in `main` before the configuration
//! load; [`bind_from_planned`] runs once, on a start whose `plugins:` block is pre-1.6, from the
//! migrate seam's planned config. `auth_bindings` re-exports both under their old names.

/// THE OPERATOR CREDENTIAL, judged at process start from the native auth images the start stage
/// admitted (OPERATOR-FROM-ADMITTED-AUTH §3.1, §3.4). A start whose `plugins:` block is in a pre-1.6
/// shape is `Deferred`: [`bind_from_planned`] binds it from the migrate seam's planned config
/// (§3.4.1).
#[must_use]
pub(crate) fn operator_binding() -> busbar_kernel::preflight::OperatorBinding {
    if crate::root::boot::plugins_block_is_historical() {
        return busbar_kernel::preflight::OperatorBinding::Deferred;
    }
    busbar_kernel::preflight::OperatorBinding::Bound(judged_operator())
}

/// The operator judged from the native (MIN-3) auth images the start stage published
/// ([`crate::root::native_operator`]).
#[must_use]
pub(crate) fn judged_operator() -> busbar_kernel::preflight::Judged {
    busbar_kernel::preflight::choose_operator(&crate::root::native_operator::NATIVE.claims())
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
    // The planned `plugins:` block must read; the operator is judged from the native auth images.
    doc.get("plugins")
        .cloned()
        .map(busbar_contract::yaml::from_value::<busbar_kernel::config::PluginsCfg>)
        .transpose()
        .map_err(|e| crate::root::cold::upgraded_plugins_unreadable(&e))?;
    busbar_kernel::preflight::bind_deferred(judged_operator())
}
