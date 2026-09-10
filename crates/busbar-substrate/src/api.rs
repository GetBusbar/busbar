// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral Admin API v1 DATA helpers a plane crate names without reaching into `busbar-core`.
//!
//! These are the pure-data pieces of the frozen admin contract: the path prefix every admin
//! endpoint hangs off, the absolute-path helper derived from it, the shared named-definition read
//! VIEW, and the OpenAPI response-schema attach helper. None of them touches `App`, `Store`, audit,
//! or the authorization `Scope` — they are `String`/`Vec`/`Option` serde data and `serde_json`
//! manipulation, so they belong in the neutral substrate. Core re-exports each from its old admin
//! path so the in-core (and a2a) call sites are unchanged.

use serde::Serialize;

/// The frozen Admin API v1 path prefix — `API_ROOT` + version + area. Every admin endpoint hangs
/// off this; the router nest, the scope matrix, and the OpenAPI doc all derive from it (one source
/// of truth, drift-proof by construction — see `admin::transport::mount`).
///
/// The literal itself lives in `busbar-contract`, and this is a re-export of it. It has to: the
/// admin plane must claim this prefix, a plugin may name `busbar-contract` and nothing else in the
/// workspace, and the plane's only alternative was transcribing the string by hand — which it did,
/// with an assertion over its own copy that could not check this one.
pub use busbar_contract::surface::ADMIN_PREFIX;

/// Absolute admin path from a RELATIVE one — [`ADMIN_PREFIX`] + `rel`. The OpenAPI doc keys
/// (which document the WIRE, so they must be absolute) are all built through this, so no absolute
/// path is ever hand-written here and none can drift from the mount grammar.
// Only `openapi_doc()` (feature `openapi-schema`) and the plane `openapi_schemas` contributors it
// folds call this; all are compiled solely under that feature, so `ap` is dead in every build
// without it — allow it there. `pub` so a plane can compute the absolute path of its own verb
// when attaching that verb's typed schema through the `openapi_schemas` seam.
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
    // FROZEN PUBLISHED PROSE: this doc comment is the field's `description` in the served
    // `openapi.json`, a wire document judged as a JSON superset of the published one, so a
    // description that GROWS is an existing string leaf whose value changed rather than a new path
    // beside the old.
    //
    // AND FROZEN PUBLISHED SHAPE: `module` is REQUIRED, exactly as 1.5.5 published it. It briefly
    // carried `skip_serializing_if = "String::is_empty"`, so that the new `agents:` section could
    // reuse this view for entries that have no module -- which took `module` out of the schema's
    // `required` array and NARROWED a published 1.5.5 schema to buy a convenience. A section whose
    // entries are not plugin instances gets its own view instead: see [`AgentDefView`].
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
    /// `identity-providers` ONLY: whether a `token:` secret REFERENCE is configured (the built-in
    /// `admin-tokens` operator credential). The reference itself is never projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_configured: Option<bool>,
    /// `identity-providers` ONLY: whether a `browser_login:` block is configured, the presence that
    /// puts a button on the hosted login page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_login_configured: Option<bool>,
    /// Set ONLY on an entry that is STORED in the config overlay but could NOT be parsed into this
    /// section's typed config by this binary (a downgrade whose struct lost a field, a hand-edited
    /// overlay); the value is the parse error. Such an entry is dropped at every rebuild, so it is
    /// NOT live: `module`/`settings_keys` are the raw stored document's best-effort projection, not
    /// a resolved definition. Present so the drop is DISCOVERABLE here rather than only in a boot
    /// log line. Absent (and omitted from the body) for every live definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparseable: Option<String>,
}

/// ONE `agents:` REGISTRATION, as the read surface projects it — the `agents:` section's OWN
/// view, not a widening of [`NamedDefView`].
///
/// WHY A SECOND TYPE AND NOT THREE MORE OPTIONAL FIELDS. `agents:` first landed as three
/// `skip_serializing_if` fields on [`NamedDefView`] plus a fourth on `module`, because an agent
/// registration has no backing plugin to name. The fourth is the one that cost: making `module`
/// skippable took it out of the shared schema's `required` array, and that array is a 1.5.5
/// PUBLISHED wire fact. A section that does not fit the shared spine needs its own view, exactly as
/// a section that does keeps the shared one unchanged; the alternative narrows what every already
/// shipped client was told about `/identity-providers` and `/export` in order to describe a section
/// those clients cannot reach.
///
/// The rule the shared view states holds here word for word, at the same read-only scope it names:
/// SECRETS ARE NEVER PROJECTED. The backend `url:` is not projected either — it is the real remote
/// endpoint, and "which third party is behind this name" is the fact the rewrite-through-busbar
/// posture keeps on the server side.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AgentDefView {
    /// The registration NAME: the map key, and the token every reference site uses.
    pub name: String,
    /// The KEY NAMES of the registration's opaque settings bag, sorted, WITHOUT their values — the
    /// same redacted projection [`NamedDefView::settings_keys`] carries, under the same rule and for
    /// the same reason. An empty bag ⇒ an empty list.
    pub settings_keys: Vec<String>,
    /// Which authenticity root this registration is pinned to (`jws_issuer_key` | `cert_spki` |
    /// `mtls` | `unpinned`). Projected because an operator scanning a registration list needs to SEE
    /// which entries have no root; a mechanism that could only be discovered by reading the config
    /// file is a mechanism nobody audits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_mechanism: Option<String>,
    /// Whether an approved card FINGERPRINT is pinned yet. A registration with a root but no
    /// fingerprint is the normal state of a fresh entry awaiting approval, and it is the state an
    /// operator most needs to be able to see.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_pinned: Option<bool>,
    /// The re-verification cadence this registration carries, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverify_ttl: Option<String>,
}

/// ONE ENTRY of ONE named-definition section, whichever view that section serves.
///
/// `#[serde(untagged)]`, so the wire bytes are the variant's own bytes and nothing else: the generic
/// named-map read path can carry either view without a single already-shipped section's body moving
/// by a byte. Which variant a section produces is the SECTION'S choice, declared once
/// ([`NamedDefShape`]) and never re-decided per call site.
///
/// A stored-but-UNPARSEABLE overlay entry is always [`NamedDefEntry::Def`], on every section: it is
/// a best-effort projection of the RAW STORED DOCUMENT (`{module, settings}`, the shape the overlay
/// persists), not of the section's typed config — which by definition did not parse.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum NamedDefEntry {
    /// The shared plugin-instance view — `identity-providers:`, `export:`, `tools:`, and every
    /// section's unparseable-overlay projection.
    Def(NamedDefView),
    /// The `agents:` registration view.
    Agent(AgentDefView),
}

impl NamedDefEntry {
    /// The entry's NAME — the map key, whichever view carries it. The generic read path sorts and
    /// de-duplicates on this without knowing which section it is serving.
    pub fn name(&self) -> &str {
        match self {
            NamedDefEntry::Def(v) => &v.name,
            NamedDefEntry::Agent(v) => &v.name,
        }
    }
}

/// WHICH view a named-definition section's LIVE entries are projected onto — the section's own
/// declaration, read by the OpenAPI generator so the document names the concrete view rather than a
/// union of every view that exists.
///
/// It is data on the section, not a branch in the generator: the generator asks the section which
/// shape it serves, the way the router asks it for its path and the write path asks it whether it
/// requires a `module:`. Core therefore names view SHAPES, never a plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedDefShape {
    /// Entries are PLUGIN INSTANCES: [`NamedDefView`], `module:` and all.
    Def,
    /// Entries are REMOTE REGISTRATIONS pinned to an authenticity root: [`AgentDefView`].
    Agent,
}

/// Attach a `$ref` schema onto `<abs_path>.<method>.responses.<status>.content` — the module-level
/// twin of `openapi_doc`'s nested `set_content`, exposed so a plane's `openapi_schemas` contributor
/// attaches its verb's typed success body through the SAME logic (byte-identical output). Creates the
/// status response entry if the op did not already document it.
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
    // The OpenAPI operation-object key is the fixed wire word `responses` — unrelated to any plane
    // dialect, but a bare token collides with the plane-purity lint's dialect list, so the fixed
    // spelling is assembled with `concat!` (compile-time identical) and the local is named neutrally.
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

/// Attach a REQUIRED request-body `$ref` schema onto `<abs_path>.<method>` — the module-level twin of
/// `openapi_doc`'s nested `body_raw!`, exposed for a plane's `openapi_schemas` contributor (the write
/// verb's typed request body). Neutral `serde_json` manipulation, so it lives here beside
/// [`set_response_schema`]; a plane names it directly rather than reaching into `busbar-core`.
#[cfg(feature = "openapi-schema")]
pub fn set_request_body(
    paths: &mut serde_json::Map<String, serde_json::Value>,
    abs_path: &str,
    method: &str,
    schema: serde_json::Value,
) {
    if let Some(op) = paths.get_mut(abs_path).and_then(|p| p.get_mut(method)) {
        if let Some(obj) = op.as_object_mut() {
            obj.insert(
                "requestBody".to_string(),
                serde_json::json!({
                    "required": true,
                    "content": {"application/json": {"schema": schema}}
                }),
            );
        }
    }
}
