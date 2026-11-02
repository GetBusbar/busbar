// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::service::settings_keys;
use crate::v1::contract::NamedDefView;

pub(super) const SETTINGS_KEY: &str = "settings";

fn bare_view(name: &str, module: String, settings_keys: Vec<String>) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module,
        settings_keys,
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: None,
    }
}

pub(super) fn identity_provider_view(
    name: &str,
    cfg: &busbar_kernel::config::IdentityProviderCfg,
) -> NamedDefView {
    NamedDefView {
        max_admin_scope: cfg.max_admin_scope.clone(),
        token_configured: Some(cfg.token.is_some()),
        browser_login_configured: Some(cfg.browser_login.is_some()),
        ..bare_view(name, cfg.module.clone(), settings_keys(&cfg.settings))
    }
}

pub(super) fn export_def_view(
    name: &str,
    cfg: &busbar_kernel::config::ExportDefCfg,
) -> NamedDefView {
    bare_view(name, cfg.module.clone(), settings_keys(&cfg.settings))
}

pub(super) fn unparseable_def_view(
    name: &str,
    entry: &busbar_kernel::config::overlay::UnparseableNamedDef,
) -> NamedDefView {
    NamedDefView {
        unparseable: Some(entry.error.clone()),
        ..bare_view(
            name,
            entry
                .raw
                .get("module")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string(),
            entry
                .raw
                .get(SETTINGS_KEY)
                .and_then(|s| s.as_object())
                .map(settings_keys)
                .unwrap_or_default(),
        )
    }
}
