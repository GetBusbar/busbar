// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Projections of one named-map DEFINITION onto the shared read view.
//!
//! One module because they answer one question — what may a read-only admin see about a named
//! definition — and they answer it under one rule: a secret REFERENCE collapses to a boolean and a
//! `settings:` bag collapses to its KEY NAMES, so the two places a credential could leak are closed
//! by construction rather than by each projection remembering. Keeping them together is what makes
//! that rule checkable by reading one file; a new section's projection lands here beside the others.

use super::contract::NamedDefView;
use super::service::settings_keys;

/// Project one `identity-providers:` DEFINITION onto the shared named-map view. The `token:` secret
/// REFERENCE is collapsed to a boolean here and the `settings:` bag to its KEY NAMES — the two
/// places a secret could leak, closed by construction.
pub(super) fn identity_provider_view(
    name: &str,
    cfg: &crate::config::IdentityProviderCfg,
) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module: cfg.module.clone(),
        settings_keys: settings_keys(&cfg.settings),
        max_admin_scope: cfg.max_admin_scope.clone(),
        token_configured: Some(cfg.token.is_some()),
        browser_login_configured: Some(cfg.browser_login.is_some()),
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: None,
    }
}

/// Project one `export:` DEFINITION onto the shared named-map view. An exporter carries neither a
/// trust ceiling nor a credential FIELD, so those are omitted from the body entirely — but its
/// `settings:` bag routinely carries one (a `generic-webhook`'s `auth_header.value`), so the bag is
/// projected as KEY NAMES exactly as the identity-provider view projects it.
pub(super) fn export_def_view(name: &str, cfg: &crate::config::ExportDefCfg) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module: cfg.module.clone(),
        settings_keys: settings_keys(&cfg.settings),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: None,
    }
}

/// Project one `agents:` DEFINITION onto the shared named-map view.
///
/// The backend `url:` is NOT projected. It is the real remote endpoint, this surface is reachable
/// at read-only admin scope, and "which third party is behind this name" is exactly the fact the
/// rewrite-through-busbar posture exists to keep on the server side. What IS projected is what an
/// operator auditing trust needs and cannot get anywhere else: which root the entry is pinned to,
/// whether a fingerprint has been approved yet, and how often it is re-checked.
pub(super) fn agent_def_view(name: &str, cfg: &crate::a2a::config::AgentDefCfg) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module: String::new(),
        settings_keys: Vec::new(),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: Some(
            serde_json::to_value(cfg.pin.mechanism)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
        ),
        fingerprint_pinned: Some(cfg.pin.fingerprint.is_some()),
        reverify_ttl: Some(
            cfg.reverify_ttl
                .clone()
                .unwrap_or_else(|| crate::a2a::config::DEFAULT_REVERIFY_TTL.to_string()),
        ),
        unparseable: None,
    }
}

/// Project one overlay definition this binary CANNOT parse onto the same named-map view, explicitly
/// FLAGGED (`unparseable`). Such an entry is stored in the overlay but dropped at every rebuild, so
/// it is not live anywhere — before this it was invisible to every read surface and announced only
/// by a boot log line, which an operator who does not tail logs can never discover. `module` and
/// `settings_keys` are a best-effort projection of the RAW stored document (still key names only, so
/// the no-secret-in-a-read-scope rule holds even for a document that failed to parse).
pub(super) fn unparseable_def_view(
    name: &str,
    entry: &crate::config::overlay::UnparseableNamedDef,
) -> NamedDefView {
    NamedDefView {
        name: name.to_string(),
        module: entry
            .raw
            .get("module")
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_string(),
        settings_keys: entry
            .raw
            .get("settings")
            .and_then(|s| s.as_object())
            .map(settings_keys)
            .unwrap_or_default(),
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: Some(entry.error.clone()),
    }
}
