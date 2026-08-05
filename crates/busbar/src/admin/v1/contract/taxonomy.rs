// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-endpoint ERROR TAXONOMY — the single declaration `openapi.json` is a projection of.
//!
//! `openapi_doc()` does not author response prose: it ENUMERATES [`declared_errors`] to emit each
//! operation's 4xx responses, so a status a handler can emit is impossible to omit and a documented
//! response no handler emits is impossible to keep. A class-level test
//! (`admin::tests::declared_error_set_is_exactly_what_the_handlers_emit`) captures the errors the
//! handlers ACTUALLY emit at the one wire choke point (`err_json`) and asserts that captured set
//! equals this declaration — under-claim AND over-claim both fail, at `(operation, ErrKind, Cond)`
//! granularity. The operations it walks are read out of the committed `openapi.json`, so an endpoint
//! cannot escape the audit by never being added to a hand-maintained list.
//!
//! 401 / 403 (generic under-scope) / 405 / 429 / 500 are ALGORITHMIC: stamped on every operation by
//! `openapi_doc()` because every operation can emit them. They are deliberately NOT declarable here
//! (see [`err_kind_of`], which classifies them as `None`).
//!
//! WHICH items are live here depends on TWO independent cfgs: `openapi-schema` (the CI-only feature
//! that compiles the generator) selects the declaration + phrasing + projection, and `test` selects
//! the emission tagging, the recording layer, and the class-level drift audit's own inputs. The
//! SHIPPED binary needs neither — it serves the pre-generated `openapi.json` — so items gated on
//! `any(test, feature = "openapi-schema")` or `feature = "openapi-schema"` alone are genuinely ABSENT
//! from a release build, not merely suppressed. `Cond` itself stays UNGATED: `err_json_cond`, a real
//! production function, takes one as a parameter, so the enum is live in every build; only its
//! `phrase()` method (openapi-schema doc prose) is gated.

#[cfg(any(test, feature = "openapi-schema"))]
use super::{AdminError, Scope};
#[cfg(any(test, feature = "openapi-schema"))]
use crate::config::named_map::{NamedMapSection, NamedMapShape};

// ── ERROR TAXONOMY → OpenAPI PROJECTION (design D) ───────────────────────────────────────────────
//
// The per-endpoint 4xx error set is DECLARED here, once, as data — never hand-authored beside each
// operation in `openapi_doc()`. `openapi_doc()` ENUMERATES `declared_errors` to emit the 400/404/409
// responses; a class-level test (`json::tests`) asserts the declaration equals the set the handlers
// can actually emit (no under-claim, no over-claim). 401/403/429/500 stay ALGORITHMIC (stamped on
// every op) and are deliberately NOT in this table — see `openapi_doc`.

/// The DOC dimension of `AdminError`: its discriminant WITHOUT payload. Each `ErrKind` maps 1:1 to a
/// frozen `code` + HTTP status by reusing `AdminError`'s frozen tables (no second mapping). Only the
/// per-endpoint-DECLARABLE kinds live here; the algorithmic ones (`Unauthorized`/`Forbidden` under-
/// scope/`MethodNotAllowed`/`RateLimited`/`Internal`) are classified as `Algorithmic` by the
/// `ErrKind ↔ AdminError` exhaustiveness bridge (`err_kind_of`), which FAILS TO COMPILE if a new
/// `AdminError` variant is added without a decision here.
#[cfg(any(test, feature = "openapi-schema"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum ErrKind {
    /// A named resource does not exist (`not_found`, 404).
    NotFound,
    /// The request is structurally invalid (`invalid_request`, 400).
    Validation,
    /// RETRYABLE optimistic-concurrency staleness (`version_conflict`, 409).
    VersionConflict,
    /// A TERMINAL state conflict (`conflict`, 409).
    Conflict,
    /// The `forbidden` (403) kind. After the 1.5.2 scope collapse there is NO per-endpoint
    /// `Forbidden` declaration left (the hook-escalation refinement — its only site — is gone; every
    /// 403 is now the generic under-scope response `openapi_doc` stamps algorithmically). The variant
    /// stays real for the `ErrKind ↔ AdminError` bridge (`err_kind_of`, test-only), so it is only
    /// CONSTRUCTED under `test`; narrow-suppress the dead-code lint in the openapi-schema-only build
    /// rather than deleting a kind the frozen taxonomy still recognizes.
    #[cfg_attr(not(test), allow(dead_code))]
    Forbidden,
}

#[cfg(any(test, feature = "openapi-schema"))]
impl ErrKind {
    /// A representative `AdminError` for this kind — used only to READ its frozen `code`/`http_status`
    /// (payloads are empty; the doc dimension carries no message).
    fn as_admin_error(self) -> AdminError {
        match self {
            ErrKind::NotFound => AdminError::not_found(""),
            ErrKind::Validation => AdminError::Validation(String::new()),
            ErrKind::VersionConflict => AdminError::VersionConflict(String::new()),
            ErrKind::Conflict => AdminError::Conflict(String::new()),
            ErrKind::Forbidden => AdminError::Forbidden {
                needed: Scope::Full,
            },
        }
    }

    /// The FROZEN stable code for this kind (reuses `AdminError::code`).
    pub(crate) fn code(self) -> &'static str {
        self.as_admin_error().code()
    }

    /// The HTTP status for this kind (reuses `AdminError::http_status`).
    pub(crate) fn status(self) -> u16 {
        self.as_admin_error().http_status()
    }
}

/// The `ErrKind ↔ AdminError` EXHAUSTIVENESS BRIDGE. Every `AdminError` variant is classified either
/// as a per-endpoint-DECLARABLE `ErrKind` (appears in `declared_errors`) or as `None` = ALGORITHMIC
/// (stamped on every op by `openapi_doc`, never declared per-endpoint). Adding an `AdminError`
/// variant WON'T COMPILE until it is classified here — so the taxonomy can never grow a code the doc
/// dimension doesn't know about. This subsumes and strengthens
/// `openapi_error_enum_matches_admin_error_codes`.
// Only reached from #[cfg(test)] call sites (err_json_tagged's test-only tag stamp) — unlike
// declared_responses/declared_errors, it is never called from openapi_doc's body, so it needs no
// feature alternative.
#[cfg(test)]
pub(crate) fn err_kind_of(e: &AdminError) -> Option<ErrKind> {
    match e {
        AdminError::NotFound { .. } => Some(ErrKind::NotFound),
        AdminError::Validation(_) => Some(ErrKind::Validation),
        AdminError::VersionConflict(_) => Some(ErrKind::VersionConflict),
        AdminError::Conflict(_) => Some(ErrKind::Conflict),
        AdminError::Forbidden { .. } => Some(ErrKind::Forbidden),
        // ALGORITHMIC (stamped on every op, never per-endpoint declared):
        AdminError::Unauthorized => None,
        AdminError::MethodNotAllowed => None,
        AdminError::RateLimited => None,
        AdminError::Internal => None,
        // Emitted by exactly one operation today (`GET /plugins?type=store`'s catalog-scan-gate
        // timeout), same posture as `RateLimited` above (which is likewise only ACTUALLY emitted by
        // mutation endpoints despite being classified algorithmic): documenting it per-endpoint would
        // be one entry with no cross-endpoint reuse, so it rides the same global 5xx bucket as
        // `Internal` rather than growing the declared-error machinery for a single call site.
        AdminError::Unavailable(_) => None,
    }
}

/// The CATALOG of trigger conditions, each with a canonical human phrasing (`phrase`). A condition is
/// reusable across endpoints (e.g. `StaleIfMatch` reads identically everywhere), so descriptions stop
/// being retyped-and-drifting prose. A `Cond` is a CLOSED enum — an endpoint cannot invent a bogus
/// condition, and its phrasing can never contradict its `ErrKind`'s status.
/// Named in the production signature `err_json_cond(e: &AdminError, cond: Cond)`, so the enum type
/// itself is always live — but most individual variants are only CONSTRUCTED inside `declared_errors`
/// (gated: `any(test, feature = "openapi-schema")`), so a release build without either cfg on sees
/// most variants as unconstructed. Narrow suppression rather than deleting the enum's dead_code
/// visibility entirely, since the type stays real in every build.
#[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Cond {
    StaleIfMatch,
    MalformedIfMatch,
    UnknownResource,
    MalformedBody,
    InvalidTree,
    BaseDefined,
    GrantChange,
    BoundKeys,
    StillParent,
    GovernanceOff,
    NoSigningKey,
    IdempotencyInFlight,
    AtKeyCap,
    ParentWithoutGroup,
    KeyExpiryFields,
    RebindTargetMissing,
    HookNoAck,
    SettingsPush,
    MalformedCursor,
    MissingRequiredQuery,
    InvalidQueryValue,
    NonNumericPath,
    InvalidConfig,
    UnknownModule,
    LockoutSelf,
    NoDiskBase,
    UntrustedUpload,
    InvalidFilename,
    NotLoadable,
    Overlong,
    NothingToRotate,
    /// A restart was requested but nothing would bring busbar back up.
    NoSupervisor,
    /// A restart was requested but the process has no shutdown channel to drain.
    NotRestartable,
    UnknownSection,
    NameCollision,
    InvalidLabels,
    /// A named-map mutation tried to RAISE an `identity-providers.<name>.max_admin_scope` trust
    /// ceiling. Refused outright over the API (1.5.3 unit D) — the ceiling is operator FILE policy.
    TrustCeilingRaise,
    /// A named-map DELETE would leave a DANGLING REFERENCE: another config site still names the
    /// definition by bare name (e.g. `auth.chain`).
    StillReferenced,
}

impl Cond {
    /// The single canonical human phrasing for this condition — written ONCE. Every endpoint that
    /// declares a `(kind, cond)` renders identically.
    #[cfg(feature = "openapi-schema")]
    pub(crate) fn phrase(self) -> &'static str {
        match self {
            Cond::StaleIfMatch => "stale `If-Match` (re-read and retry)",
            Cond::MalformedIfMatch => "malformed `If-Match` header",
            Cond::UnknownResource => "unknown resource",
            Cond::MalformedBody => "malformed body / unknown field",
            Cond::InvalidTree => "invalid tree — dangling/cyclic parent or depth",
            Cond::BaseDefined => "base-defined (edit config.yaml)",
            Cond::GrantChange => "grant change on an existing definition",
            Cond::BoundKeys => "one or more keys are still bound (rebind/delete them first)",
            Cond::StillParent => "another group still names it as parent",
            Cond::GovernanceOff => "governance is not enabled on this server",
            Cond::NoSigningKey => "no signing key is configured for signed-token minting",
            Cond::IdempotencyInFlight => "an `Idempotency-Key` request is already in flight",
            Cond::AtKeyCap => "the group is at the `limits.max_keys_per_principal` cap",
            Cond::ParentWithoutGroup => "`parent` was given without `group`",
            Cond::KeyExpiryFields => "bad `expires_in` / `expires_at`",
            Cond::RebindTargetMissing => "the rebind target group does not exist",
            Cond::HookNoAck => "the hook did not acknowledge; nothing committed",
            Cond::SettingsPush => "a config change landed during the settings push — retry",
            Cond::MalformedCursor => "malformed or foreign pagination `cursor`",
            Cond::MissingRequiredQuery => "missing or unknown required query parameter",
            Cond::InvalidQueryValue => "invalid query-parameter value",
            Cond::NonNumericPath => "non-numeric path segment",
            Cond::InvalidConfig => "invalid config; nothing changed",
            Cond::UnknownModule => "unknown module / malformed body",
            Cond::LockoutSelf => "the new chain would lock the caller out",
            Cond::NoDiskBase => {
                "ephemeral busbar: no disk config to read, merge onto, or revert to"
            }
            Cond::UntrustedUpload => "the upload is untrusted and not opted-in",
            Cond::InvalidFilename => "invalid plugin filename",
            Cond::NotLoadable => {
                "the artifact is not loadable — bad archive/manifest, or it fails structure/trust \
                 validation"
            }
            Cond::Overlong => "an id or name exceeds its length cap",
            Cond::NothingToRotate => "no signing key is configured; nothing to rotate",
            Cond::NoSupervisor => {
                "no process supervisor was detected, so exiting would leave busbar down; re-send \
                 with `confirm: true` if a supervisor will restart it"
            }
            Cond::NotRestartable => {
                "this process has no shutdown channel, so it cannot restart itself"
            }
            Cond::UnknownSection => {
                "unknown overlay section (expected `groups`|`hooks`|`root`|`plugin_versions`)"
            }
            Cond::InvalidLabels => {
                "invalid mint-time `labels` — a reserved or non-Prometheus label name, or too \
                 many/too long"
            }
            Cond::TrustCeilingRaise => {
                "raising `max_admin_scope` is refused over the admin API — the trust ceiling is \
                 operator file policy; lower it here, raise it in config.yaml"
            }
            Cond::StillReferenced => {
                "another config section still references this definition by bare name (remove the \
                 reference first)"
            }
            Cond::NameCollision => {
                "the plugin name/alias collides with an already-installed plugin under a different \
                 filename"
            }
        }
    }
}

/// A documentable failure: which `AdminError` kind (→ frozen code + status) and the endpoint-specific
/// CONDITION that triggers it. Both are enums, so a declaration can neither invent a status nor drift
/// into prose that contradicts the code.
#[cfg(any(test, feature = "openapi-schema"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct DocErr {
    pub(crate) kind: ErrKind,
    pub(crate) cond: Cond,
}

/// Method tag for the `declared_errors` match (the doc dimension only cares about the verb).
#[cfg(any(test, feature = "openapi-schema"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum MethodTag {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

// Every real caller needs EITHER `openapi-schema` (the `openapi_doc`-body call, and the
// `json/tests` consistency tests, both gated on that feature alone) OR `test` PLUS
// `auth-admin-tokens` (the `admin::tests` taxonomy-drift audit, which itself requires that
// feature — see its `mod tests;` gate). Plain `cfg(test)` alone is NOT a real caller: under
// `--no-default-features` (auth-admin-tokens off) that left this compiled but unreachable,
// tripping `-D dead-code` in CI.
#[cfg(any(feature = "openapi-schema", all(test, feature = "auth-admin-tokens")))]
impl MethodTag {
    /// Parse an OpenAPI operation key (`"get"`, `"post"`, …) back into a tag. `None` for the `x-*`
    /// specification extensions that share the path-item object with real operations. Called from
    /// `openapi_doc`'s own body, so it is reachable under `feature = "openapi-schema"` alone.
    pub(crate) fn from_op_key(key: &str) -> Option<MethodTag> {
        Some(match key {
            "get" => MethodTag::Get,
            "post" => MethodTag::Post,
            "put" => MethodTag::Put,
            "patch" => MethodTag::Patch,
            "delete" => MethodTag::Delete,
            _ => return None,
        })
    }
}

// The lowercase OpenAPI operation key for this verb. Only called from #[cfg(test)] sites
// (the taxonomy drift audit in json/mod.rs and admin/tests/tests.rs) — unlike `from_op_key`, never
// from openapi_doc's own body — so it needs no feature alternative.
#[cfg(test)]
impl MethodTag {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            MethodTag::Get => "get",
            MethodTag::Post => "post",
            MethodTag::Put => "put",
            MethodTag::Patch => "patch",
            MethodTag::Delete => "delete",
        }
    }
}

/// Classify an HTTP method into a `MethodTag`. `None` for a verb the admin surface never routes —
/// such a request can only be the router's 405 fallback, which is algorithmic, not declarable. Only
/// reached from the test-only recording layer (`json/mod.rs::record_declared_error`).
#[cfg(test)]
pub(crate) fn method_tag(m: &axum::http::Method) -> Option<MethodTag> {
    use axum::http::Method;
    Some(match *m {
        Method::GET => MethodTag::Get,
        Method::POST => MethodTag::Post,
        Method::PUT => MethodTag::Put,
        Method::PATCH => MethodTag::Patch,
        Method::DELETE => MethodTag::Delete,
        _ => return None,
    })
}

/// THE ONE PLACE an endpoint's emittable 4xx error set is named. `openapi_doc()` enumerates this
/// (through [`declared_responses`]) to emit every body-specific 400 / 403-escalation / 404 / 409;
/// the class-level drift test asserts it equals what the handlers can actually emit. `rel` is the
/// RELATIVE (post-`ADMIN_PREFIX`) path.
///
/// A templated READ (`{…}` in `rel`) with no arm of its own gets a default `[NotFound /
/// UnknownResource]`, so a trivial single-resource GET needs no entry and cannot forget its 404.
///
/// NOT listed here (and not listable): 401, the generic under-scope 403, 405, 429 and 500 — every
/// operation can emit them, so `openapi_doc()` stamps them algorithmically. (1.5.2 scope collapse
/// removed the only per-endpoint `Forbidden` declaration — the hook-escalation refusal — since a
/// non-`full` caller can no longer reach a hook mutation at all.)
#[cfg(any(test, feature = "openapi-schema"))]
pub(crate) fn declared_errors(method: MethodTag, rel: &str) -> &'static [DocErr] {
    use Cond::*;
    use ErrKind::*;
    use MethodTag::*;
    macro_rules! de {
        ($($k:ident / $c:ident),* $(,)?) => {
            &[$(DocErr { kind: $k, cond: $c }),*]
        };
    }
    match (method, rel) {
        // ── Hooks (definition lifecycle) ──────────────────────────────────────────────────────
        (Post, "/hooks") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Conflict / BaseDefined,
            Conflict / GrantChange,
            VersionConflict / StaleIfMatch,
        ],
        (Put, "/hooks/{name}") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / GrantChange,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/hooks/{name}") => de![
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Patch, "/hooks/{name}/settings") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / HookNoAck,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / SettingsPush,
            VersionConflict / StaleIfMatch,
        ],
        // ── Groups (the limit tree) ───────────────────────────────────────────────────────────
        (Post, "/groups") => de![
            Validation / InvalidTree,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Put, "/groups/{name}") => de![
            Validation / InvalidTree,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Patch, "/groups/{name}") => de![
            Validation / InvalidTree,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/groups/{name}") => de![
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / StillParent,
            Conflict / BoundKeys,
            VersionConflict / StaleIfMatch,
        ],
        // ── Plugins (dynamic-library store plugins) ───────────────────────────────────────────
        (Post, "/plugins") => de![
            Validation / MalformedBody,
            Validation / InvalidFilename,
            Validation / NotLoadable,
            Conflict / UntrustedUpload,
            Conflict / NameCollision,
        ],
        // `POST /plugins/reload` 400s when the rebuild-from-disk fails — an on-disk config that has
        // gone invalid since boot. This used to be undeclared because no fixture could drive it,
        // which left `openapi.json` hiding a response clients hit. `TestApp::disk_paths` gives a
        // snapshot real disk truth, so `drive_plugin_reload_errors` now witnesses it.
        (Post, "/plugins/reload") => de![Validation / InvalidConfig],
        (Post, "/plugins/rollback") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidFilename,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / NotLoadable,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/plugins/{file}") => {
            de![Validation / InvalidFilename, NotFound / UnknownResource,]
        }
        // Stateless preview of a candidate tarball (checklist item 4, question #7) — every failure
        // mode is a malformed/oversized/untrusted-shaped INPUT, never a state conflict (it writes
        // nothing and conflict-checks nothing), so `Validation` is its only declarable kind.
        (Post, "/plugins/inspect") => de![Validation / MalformedBody],
        // ── Config plane ──────────────────────────────────────────────────────────────────────
        (Put, "/admin-auth") => de![
            Validation / UnknownModule,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Conflict / LockoutSelf,
            VersionConflict / StaleIfMatch,
        ],
        (Post, "/config/apply") => de![
            Validation / InvalidConfig,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            VersionConflict / StaleIfMatch,
        ],
        (Post, "/config/reload") => de![Validation / InvalidConfig, Validation / NoDiskBase,],
        (Post, "/config/rollback") => de![
            Validation / InvalidConfig,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            VersionConflict / StaleIfMatch,
        ],
        (Put, "/config/settings") => de![
            Validation / InvalidConfig,
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            VersionConflict / StaleIfMatch,
        ],
        (Post, "/config/validate") => de![Validation / MalformedBody],
        (Post, "/auth/cache/flush") => de![Validation / MalformedBody],
        (Delete, "/overlay/{section}") => de![
            Validation / UnknownSection,
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            Validation / InvalidConfig,
            VersionConflict / StaleIfMatch,
        ],
        (Get, "/config/diff") => de![
            Validation / MissingRequiredQuery,
            NotFound / UnknownResource,
        ],
        (Get, "/config/versions/{v}") => {
            de![Validation / NonNumericPath, NotFound / UnknownResource,]
        }
        // ── List GETs whose query string can be rejected at the door ──────────────────────────
        (Get, "/audit") => de![Validation / MalformedCursor],
        (Get, "/config/versions") => de![Validation / MalformedCursor],
        (Get, "/plugins") => de![Validation / MissingRequiredQuery],
        (Get, "/pools") => de![Validation / InvalidQueryValue],
        (Get, "/usage") => de![Validation / InvalidQueryValue],
        // ── Virtual keys (surface B, unified onto this taxonomy by design D route 2) ──────────
        (Get, "/keys") => de![Validation / MalformedCursor, Validation / InvalidQueryValue,],
        (Post, "/keys") => de![
            Validation / MalformedBody,
            Validation / Overlong,
            Validation / InvalidLabels,
            Validation / KeyExpiryFields,
            Validation / ParentWithoutGroup,
            Validation / InvalidTree,
            Conflict / GovernanceOff,
            Conflict / NoSigningKey,
            Conflict / IdempotencyInFlight,
            Conflict / AtKeyCap,
            Conflict / BaseDefined,
        ],
        (Get, "/keys/{id}") => de![
            Validation / Overlong,
            NotFound / UnknownResource,
            NotFound / GovernanceOff,
        ],
        (Patch, "/keys/{id}") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / Overlong,
            Validation / RebindTargetMissing,
            NotFound / UnknownResource,
            Conflict / GovernanceOff,
            Conflict / AtKeyCap,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/keys/{id}") => de![
            Validation / MalformedIfMatch,
            Validation / Overlong,
            NotFound / UnknownResource,
            Conflict / GovernanceOff,
            VersionConflict / StaleIfMatch,
        ],
        (Get, "/keys/{id}/usage") => de![
            Validation / Overlong,
            NotFound / UnknownResource,
            NotFound / GovernanceOff,
        ],
        (Post, "/keys/{id}/rotate") => de![
            NotFound / UnknownResource,
            Conflict / GovernanceOff,
            Conflict / IdempotencyInFlight,
        ],
        (Post, "/keys/{id}/revoke") => de![
            Validation / Overlong,
            NotFound / UnknownResource,
            Conflict / GovernanceOff,
        ],
        (Post, "/signing-key/rotate") => de![Conflict / GovernanceOff, Conflict / NothingToRotate,],
        (Post, "/restart") => de![
            Validation / MalformedBody,
            Conflict / NoSupervisor,
            Conflict / NotRestartable,
        ],
        // ── The GENERIC named-DEFINITION maps (`/identity-providers`, `/export`; `tools`/`agents`
        //    later) ────────────────────────────────────────────────────────────────────────────
        // Declared per route SHAPE, not per section, and reached through the SAME
        // `NamedMapSection::parse_rel` seam the router mounts from. That is what makes a new
        // section additive here: adding the variant adds its five operations' declarations with
        // no arm of their own. The one asymmetry is the identity-providers TRUST CEILING, which is
        // keyed off `has_trust_ceiling()` rather than off the section's name.
        (m, r) if NamedMapSection::parse_rel(r).is_some() => {
            let (section, shape) = NamedMapSection::parse_rel(r).expect("just matched");
            named_map_declared_errors(m, section, shape)
        }
        // A templated READ with no arm of its own answers 404 for an unknown resource and nothing
        // else; every other operation carries only the algorithmic responses.
        _ => {
            if method == Get && rel.contains('{') {
                de![NotFound / UnknownResource]
            } else {
                &[]
            }
        }
    }
}

/// The declared 4xx set for ONE generic named-map operation, keyed on the route SHAPE (+ the trust
/// ceiling predicate) rather than on the section — see the arm in [`declared_errors`].
///
/// Every listed condition is emitted with its `Cond` NAMED (`err_json_cond`) by
/// `admin::v1::json::named_map`, so each declaration is witness-backed at condition granularity and
/// none of them needs a `COND_WITNESS_DEBT` row.
#[cfg(any(test, feature = "openapi-schema"))]
fn named_map_declared_errors(
    method: MethodTag,
    section: NamedMapSection,
    shape: NamedMapShape,
) -> &'static [DocErr] {
    use Cond::*;
    use ErrKind::*;
    use MethodTag::*;
    macro_rules! de {
        ($($k:ident / $c:ident),* $(,)?) => {
            &[$(DocErr { kind: $k, cond: $c }),*]
        };
    }
    match (method, shape) {
        // PUT is an UPSERT (create-or-replace), so it has no `not_found`.
        (Put, NamedMapShape::Item) if section.has_trust_ceiling() => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            Conflict / BaseDefined,
            Conflict / TrustCeilingRaise,
            VersionConflict / StaleIfMatch,
        ],
        (Put, NamedMapShape::Item) => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, NamedMapShape::Item) if section.has_trust_ceiling() => de![
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / StillReferenced,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, NamedMapShape::Item) => de![
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        (Patch, NamedMapShape::Settings) => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
        ],
        // The single-definition READ 404s on an unknown name; the collection READ takes no input
        // it could reject.
        (Get, NamedMapShape::Item) => de![NotFound / UnknownResource],
        _ => &[],
    }
}

/// PROJECT the declaration onto OpenAPI `responses` entries: `(status, description)` pairs, one per
/// distinct HTTP status the endpoint declares. Conditions that share a status are GROUPED into that
/// one response (matching the wire shape a single `409` has always had), and within a status the
/// clauses are grouped by their frozen `code` — so a reader always sees which code goes with which
/// condition, and no endpoint can word the same condition two different ways.
///
/// This is the ONLY producer of 4xx response text in the document. `openapi_doc()` calls it and
/// writes the result verbatim; there is no per-endpoint prose left to drift.
#[cfg(feature = "openapi-schema")]
pub(crate) fn declared_responses(method: MethodTag, rel: &str) -> Vec<(String, String)> {
    let declared = declared_errors(method, rel);
    // Status → ordered list of (code, phrase), de-duplicated, in declaration order.
    let mut by_status: Vec<(u16, Vec<(&'static str, &'static str)>)> = Vec::new();
    for de in declared {
        let (status, code, phrase) = (de.kind.status(), de.kind.code(), de.cond.phrase());
        let slot = match by_status.iter_mut().find(|(s, _)| *s == status) {
            Some(slot) => &mut slot.1,
            None => {
                by_status.push((status, Vec::new()));
                &mut by_status.last_mut().expect("just pushed").1
            }
        };
        if !slot.contains(&(code, phrase)) {
            slot.push((code, phrase));
        }
    }
    by_status.sort_by_key(|(status, _)| *status);
    by_status
        .into_iter()
        .map(|(status, clauses)| {
            // Within one status, group the phrases under their code: "`code`: a, b | `code2`: c".
            let mut by_code: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
            for (code, phrase) in clauses {
                match by_code.iter_mut().find(|(c, _)| *c == code) {
                    Some((_, phrases)) => phrases.push(phrase),
                    None => by_code.push((code, vec![phrase])),
                }
            }
            let description = by_code
                .into_iter()
                .map(|(code, phrases)| format!("`{code}`: {}", phrases.join(", ")))
                .collect::<Vec<_>>()
                .join(" | ");
            (status.to_string(), description)
        })
        .collect()
}

/// TEST-ONLY capture of the errors the handlers ACTUALLY emit, so the class-level drift test can
/// compare the declaration against reality instead of against a human's reading.
///
/// Two halves, both hanging off the ONE wire choke point (`json::err_json`) plus the recording layer
/// the v1 router installs in a test build:
/// - **under-claim is fatal ON THE SPOT**: the layer PANICS when a response carries a declarable
///   `ErrKind` the endpoint's `declared_errors` does not list, so EVERY test in the suite is a
///   driver for that direction — no accumulation, no test-ordering dependency;
/// - **over-claim** needs a witness, so every observed `(rel, method, kind, cond?)` is accumulated
///   here and the class test asserts each declared entry was seen at least once.
#[cfg(test)]
pub(crate) mod observed {
    use super::{Cond, ErrKind, MethodTag};
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    /// The tag `err_json` stamps onto an error response so the recording layer (which knows the
    /// matched route, which `err_json` does not) can attribute it to an operation. `cond` is set at
    /// the shared seams that name their condition; a handler-body error leaves it `None`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) struct Tag {
        pub(crate) kind: ErrKind,
        pub(crate) cond: Option<Cond>,
    }

    /// One witnessed emission: the operation plus the taxonomy entry it produced.
    pub(crate) type Emission = (String, MethodTag, ErrKind, Option<Cond>);

    static WITNESSED: Mutex<BTreeSet<Emission>> = Mutex::new(BTreeSet::new());

    /// Every emission the process has witnessed so far. Its only caller is the `auth-admin-tokens`
    /// -gated taxonomy-drift audit in `admin::tests` (`record`, right below, has a real caller
    /// independent of that feature, so the gate lives here rather than on the whole module).
    #[cfg(feature = "auth-admin-tokens")]
    pub(crate) fn snapshot() -> BTreeSet<Emission> {
        WITNESSED.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Record one observed emission (called by the router's recording layer).
    pub(crate) fn record(rel: &str, method: MethodTag, tag: Tag) {
        if let Ok(mut set) = WITNESSED.lock() {
            set.insert((rel.to_string(), method, tag.kind, tag.cond));
        }
    }
}
