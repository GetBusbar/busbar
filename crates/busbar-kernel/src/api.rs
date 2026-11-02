// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Serialize;

pub use busbar_contract::surface::ADMIN_PREFIX;

#[cfg_attr(not(feature = "openapi-schema"), allow(dead_code))]
pub fn ap(rel: &str) -> String {
    format!("{ADMIN_PREFIX}{rel}")
}

/// ONE definition of ONE 1.5.3 named-DEFINITION map: the read shape of the GENERIC named-map CRUD
/// (`GET /api/v1/admin/identity-providers[/{name}]`, `GET /api/v1/admin/export[/{name}]`, and
/// `tools:`/`agents:` when they land).
///
/// Deliberately ONE view for every section rather than one per kind: the sections share the frozen
/// `{module, settings}` spine and differ only by optional kind-specific fields, which are
/// `skip_serializing_if`-omitted for a section that has none. So `/export` serves exactly
/// `{name, module, settings_keys}` while `/identity-providers` additionally carries its ceiling,
/// and a new section adds fields here (additive) instead of a parallel view + a parallel handler.
///
/// SECRETS ARE NEVER PROJECTED, by construction, and that claim covers the `settings:` bag too,
/// which is why this view carries `settings_keys` and NOT the bag itself. A `token:` is a SECRET
/// REFERENCE collapsed to a boolean, and the module's opaque settings are a bag an operator
/// legitimately puts a credential VALUE in (an OIDC `client_secret`, a webhook `auth_header` value),
/// so projecting it verbatim would hand every READ-ONLY admin credential the deployment's secrets
/// through `GET /identity-providers/{name}` / `GET /export/{name}`. Projecting the KEY NAMES keeps
/// the introspection the read surface exists for ("what is configured here?") with no field a value
/// could ride out on: the same discipline `token_configured` already applies to the reference.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct NamedDefView {
    /// The instance NAME: the map key, and the token every reference site uses.
    pub name: String,
    /// The `module:` backing this instance (a built-in name or a signed-plugin name/alias).
    ///
    /// ALWAYS present, matching 1.5.5's wire shape byte-for-byte (`required` includes `module`,
    /// schema type `"string"`, never nullable): 1.5.5 had no named-map section whose entries
    /// carried no module, so it has no representation for one, and the ruling is 1:1 with 1.5.5
    /// rather than inventing a new shape. EMPTY-STRINGED, not omitted, for a section whose entries
    /// are not plugin instances -- today `agents:`, whose entries describe endpoints somebody else
    /// runs (`NamedMapSection::requires_module`). Every section that HAS a module requires it to be
    /// non-empty, so an empty string is unambiguous for "no module" without a `skip_serializing_if`
    /// that would shrink `required` below 1.5.5's.
    pub module: String,
    /// The KEY NAMES of the module's opaque settings bag, sorted, WITHOUT their values, the
    /// redacted projection of `settings:`. Operator/API-owned and never interpreted here, but also
    /// never a place a VALUE can leak from: a settings value may be a credential (see the type doc),
    /// and this surface is reachable at READ-ONLY admin scope. An empty bag ⇒ an empty list. The
    /// values are readable only where they are writable: the config file and the config overlay.
    pub settings_keys: Vec<String>,
    /// `identity-providers` ONLY: the per-provider ADMIN CEILING (`read-only` | `full`). There is no
    /// `none` token: `Scope::parse_ceiling` rejects it, because a ceiling
    /// caps what a grant can reach and cannot express the absence of one.
    /// `None` ⇒ the definition names no ceiling, so the most restrictive default applies. Omitted
    /// entirely for a section that carries no ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_admin_scope: Option<String>,
    /// `identity-providers` ONLY: whether a `token:` secret REFERENCE is configured (the operator
    /// credential). The reference itself is never projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi-schema", schemars(description = token_configured_description()))]
    pub token_configured: Option<bool>,
    /// `identity-providers` ONLY: whether a `browser_login:` block is configured, the presence that
    /// puts a button on the hosted login page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_login_configured: Option<bool>,
    /// `agents` ONLY: which authenticity root this registration is pinned to (`jws_issuer_key` |
    /// `cert_spki` | `mtls` | `unpinned`). Projected because an operator scanning a registration
    /// list needs to SEE which entries have no root; a mechanism that could only be discovered by
    /// reading the config file is a mechanism nobody audits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_mechanism: Option<String>,
    /// `agents` ONLY: whether an approved card FINGERPRINT is pinned yet. A registration with a
    /// root but no fingerprint is the normal state of a fresh entry awaiting approval, and it is
    /// the state an operator most needs to be able to see.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_pinned: Option<bool>,
    /// `agents` ONLY: the re-verification cadence this registration carries, as written. The
    /// backend `url:` is deliberately NOT projected here: it is the real remote endpoint and is
    /// never client-visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverify_ttl: Option<String>,
    /// Set ONLY on an entry that is STORED in the config overlay but could NOT be parsed into this
    /// section's typed config by this binary (a downgrade whose struct lost a field, a hand-edited
    /// overlay); the value is the parse error. Such an entry is dropped at every rebuild, so it is
    /// NOT live: `module`/`settings_keys` are the raw stored document's best-effort projection, not
    /// a resolved definition. Present so the drop is DISCOVERABLE here rather than only in a boot
    /// log line. Absent (and omitted from the body) for every live definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparseable: Option<String>,
}

#[cfg(feature = "openapi-schema")]
fn token_configured_description() -> String {
    format!(
        "`identity-providers` ONLY: whether a `token:` secret REFERENCE is configured (the built-in\n`{}` operator credential). The reference itself is never projected.",
        crate::config::operator_provider()
    )
}

#[cfg(feature = "openapi-schema")]
pub fn set_response_schema(
    paths: &mut serde_json::Map<String, serde_json::Value>,
    abs_path: &str,
    method: &str,
    status: &str,
    schema: serde_json::Value,
) {
    let Some(op) = paths.get_mut(abs_path).and_then(|p| p.get_mut(method)) else {
        return;
    };

    let Some(resp_map) = op
        .get_mut(concat!("respon", "ses"))
        .and_then(|r| r.as_object_mut())
    else {
        return;
    };
    let entry = resp_map
        .entry(status.to_string())
        .or_insert_with(|| serde_json::json!({"description": "OK"}));
    if let Some(obj) = entry.as_object_mut() {
        obj.insert(
            "content".to_string(),
            serde_json::json!({"application/json": {"schema": schema}}),
        );
    }
}
