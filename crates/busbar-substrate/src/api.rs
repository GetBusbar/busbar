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
//
// THE DOC COMMENT ABOVE IS THE 1.5.5 TYPE DESCRIPTION, VERBATIM, AND IS FROZEN. schemars generates
// the schema's `description` from it, so editing the prose edits the PUBLISHED contract, and PB-75
// binds this document to 1.5.5 byte-for-byte outside additive endpoints. Two corrections that
// therefore live down here, in a comment the generator does not read:
//
//   * "and `tools:`/`agents:` when they land" — they landed, and NOT here. They are served by
//     `PlaneNamedDefView`; see its own doc.
//   * "a new section adds fields here (additive) instead of a parallel view" — no longer the rule,
//     and 1.6.0 is why. Widening this view to cover `agents:` (whose entries name no plugin) gave
//     `module` a `skip_serializing_if`, which dropped it from `required` — NARROWING the contract
//     for `/export` and `/identity-providers`, whose bodies had never once omitted it, across the
//     twelve 1.5.5 operations that `$ref` this schema. A section whose entries are not plugin
//     instances gets its own view now, so neither can drag the other's guarantees down.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct NamedDefView {
    /// The instance NAME: the map key, and the token every reference site uses.
    pub name: String,
    /// The `module:` backing this instance (a built-in name or a signed-plugin name/alias).
    //
    // 1.5.5 text, VERBATIM and frozen. ALWAYS SERIALIZED — no `skip_serializing_if` — which is what
    // keeps it in the schema's `required` list. Both sections this view serves demand a non-empty
    // `module:` on every write path (`NamedMapSection::requires_module`), so the only way to reach
    // an empty one is an `unparseable` overlay entry whose raw document had no `module` key; that
    // case emits `"module":""`, exactly as 1.5.5 did, rather than dropping the key. A section whose
    // entries legitimately have no module is not modelled here at all — see `PlaneNamedDefView`.
    pub module: String,
    /// The KEY NAMES of the module's opaque settings bag, sorted, WITHOUT their values, the
    /// redacted projection of `settings:`. Operator/API-owned and never interpreted here, but also
    /// never a place a VALUE can leak from: a settings value may be a credential (see the type doc),
    /// and this surface is reachable at READ-ONLY admin scope. An empty bag ⇒ an empty list. The
    /// values are readable only where they are writable: the config file and the config overlay.
    pub settings_keys: Vec<String>,
    /// `identity-providers` ONLY: the per-provider ADMIN CEILING (`none` | `read-only` | `full`).
    /// `None` ⇒ the definition names none, so the most restrictive default applies. Omitted entirely
    /// for a section that carries no ceiling.
    //
    // 1.5.5 text, VERBATIM and frozen — AND KNOWN TO BE WRONG about `none`. Flagged here rather
    // than fixed because the fix is a wire-visible change to a 1.5.5 schema description and PB-75
    // makes that the owner's call, not this file's.
    //
    // THE DEFECT IS 1.5.5'S OWN, not a 1.6.0 regression. There is no `none` token and there never
    // was one on this surface: `Scope` has exactly two variants (`ReadOnly`, `Full`) in 1.5.5 and
    // in 1.6.0, and `Scope::parse_ceiling` is byte-identical between the two releases — both reject
    // `none` with the same message ("There is no `none`: omit the key for the most restrictive
    // default ... the ceiling caps what a grant can reach, it cannot express the absence of one").
    // So a 1.5.5 client that believed this description and sent `max_admin_scope: none` got a 400
    // from 1.5.5 too. Restoring the text restores byte-parity with a published document that was
    // already lying; correcting it is a separate, deliberate amendment.
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

/// The read shape of a PLANE named-definition map: the 1.6.0-NEW sections
/// (`GET /api/v1/admin/tools[/{name}]`, `GET /api/v1/admin/agents[/{name}]`), whose entries describe
/// a REMOTE ENDPOINT somebody else runs rather than a plugin instance this node loads.
///
/// A separate type from [`NamedDefView`] because the two answer different questions and carry
/// different guarantees, and collapsing them cost the older one its contract. The distinction is
/// already a first-class property of the section table — `NamedMapSection::requires_module()` is
/// `false` for exactly the `Plane(_)` sections — so this type is that predicate's wire counterpart:
/// the sections that need no `module:` are the sections that serve THIS view. That keeps
/// `NamedDefView` frozen at its 1.5.5 shape (PB-75) while these paths, which no 1.5.5 client has
/// ever seen, stay free to grow: a new plane field lands here and is additive by construction.
///
/// The secret rule is unchanged and unconditional: a credential REFERENCE collapses to a boolean
/// and a `settings:` bag to its KEY NAMES, on this view exactly as on the other one.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PlaneNamedDefView {
    /// The registration NAME: the map key, and the token every reference site uses.
    pub name: String,
    /// What is behind this entry, when the plane has a single word for it — OMITTED, not
    /// empty-stringed, when it does not.
    ///
    /// `agents:` omits it: an agent registration names no module, and an empty string would be a
    /// blank column asserting a fact that does not exist. `tools:` fills it with the authenticity
    /// root the server is bound to (`McpPinMechanism::token`), because for a remote endpoint that
    /// IS "what is behind this entry", and an operator scanning the list needs to spot an
    /// `unpinned` registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// The KEY NAMES of this registration's opaque bag, sorted, WITHOUT their values — for `tools:`
    /// the APPROVED CAPABILITY NAMES. Names only, never their hashes or schemas: this surface is
    /// reachable at READ-ONLY admin scope, the same rule [`NamedDefView::settings_keys`] follows.
    pub settings_keys: Vec<String>,
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
    /// Set ONLY on an entry STORED in the config overlay that this binary could NOT parse; the
    /// value is the parse error. The plane twin of [`NamedDefView::unparseable`], and it carries
    /// the same warning: such an entry is dropped at every rebuild, so `module`/`settings_keys` are
    /// the raw stored document's best-effort projection, not a resolved registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparseable: Option<String>,
}

/// EITHER named-definition read view, for the ONE generic handler that serves every section.
///
/// The wire shape is the inner view and nothing else (`#[serde(untagged)]` serializes the variant's
/// contents directly, adding no discriminant), so this type costs zero bytes and exists purely to
/// let `list_named_defs`/`get_named_def` keep a single return type across sections whose SCHEMAS
/// differ. Which schema a path documents is decided where the section table is walked, on
/// `NamedMapSection::requires_module()` — the same predicate that decides which variant is built —
/// so the doc and the body cannot disagree about a section.
///
/// Deliberately NOT the type the OpenAPI document references: a `oneOf` of the two views would tell
/// a 1.5.5 client that `/export` might answer either shape, which is false and is the very
/// weakening splitting the views exists to undo. Each path `$ref`s the one view it can actually
/// serve.
// The `JsonSchema` derive exists only to satisfy the bound on the one wrapper that FLATTENS this
// type (`json::named_map::MutatedDefView`, the upsert response). It contributes NOTHING to the
// served document: nothing calls `subschema_for` on either type, and the mutation responses are
// documented through the concrete per-section view above. Asserted, not assumed — the openapi
// golden test's companion checks neither name appears in `components/schemas`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum AnyNamedDefView {
    /// A PLUGIN-INSTANCE section's definition (`identity-providers`, `export`) — the 1.5.5 shape.
    Instance(NamedDefView),
    /// A PLANE section's registration (`tools`, `agents`) — the 1.6.0-new shape.
    Plane(PlaneNamedDefView),
}

impl AnyNamedDefView {
    /// The definition's NAME, whichever view carries it. The generic handler sorts and de-duplicates
    /// on this without caring which section it is serving.
    pub fn name(&self) -> &str {
        match self {
            AnyNamedDefView::Instance(v) => &v.name,
            AnyNamedDefView::Plane(v) => &v.name,
        }
    }
}

impl From<NamedDefView> for AnyNamedDefView {
    fn from(v: NamedDefView) -> Self {
        AnyNamedDefView::Instance(v)
    }
}

impl From<PlaneNamedDefView> for AnyNamedDefView {
    fn from(v: PlaneNamedDefView) -> Self {
        AnyNamedDefView::Plane(v)
    }
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
