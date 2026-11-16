// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
use super::{AdminError, Scope};
#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
use busbar_kernel::config::named_map::{NamedMapSection, NamedMapShape};

/// The DOC dimension of `AdminError`: its discriminant WITHOUT payload. Each `ErrKind` maps 1:1 to a
/// frozen `code` + HTTP status by reusing `AdminError`'s frozen tables (no second mapping). Only the
/// per-endpoint-DECLARABLE kinds live here; the algorithmic ones (`Unauthorized`/`Forbidden` under-
/// scope/`MethodNotAllowed`/`RateLimited`/`Internal`) are classified as `Algorithmic` by the
/// `ErrKind ↔ AdminError` exhaustiveness bridge (`err_kind_of`), which FAILS TO COMPILE if a new
/// `AdminError` variant is added without a decision here.
#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ErrKind {
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
    Forbidden,
    /// A usage read over a class the rate card in force does not price (`unpriced_class`, 409).
    UnpricedClass,
}

#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
impl ErrKind {
    fn as_admin_error(self) -> AdminError {
        match self {
            ErrKind::NotFound => AdminError::not_found(""),
            ErrKind::Validation => AdminError::Validation(String::new()),
            ErrKind::VersionConflict => AdminError::VersionConflict(String::new()),
            ErrKind::Conflict => AdminError::Conflict(String::new()),
            ErrKind::Forbidden => AdminError::Forbidden {
                needed: Scope::Full,
            },
            ErrKind::UnpricedClass => AdminError::UnpricedClass {
                lane: String::new(),
                class: None,
            },
        }
    }

    pub fn code(self) -> &'static str {
        self.as_admin_error().code()
    }

    pub fn status(self) -> u16 {
        self.as_admin_error().http_status()
    }
}

#[cfg(test)]
pub use crate::test_support::err_kind_of;

/// The CATALOG of trigger conditions, each with a canonical human phrasing (`phrase`). A condition is
/// reusable across endpoints (e.g. `StaleIfMatch` reads identically everywhere), so descriptions stop
/// being retyped-and-drifting prose. A `Cond` is a CLOSED enum — an endpoint cannot invent a bogus
/// condition, and its phrasing can never contradict its `ErrKind`'s status.
/// Named in the production signature `err_json_cond(e: &AdminError, cond: Cond)`, so the enum type
/// itself is always live — but most individual variants are only CONSTRUCTED inside `declared_errors`
/// (gated: `any(test, feature = "openapi-schema")`), so a release build without either cfg on sees
/// most variants as unconstructed there; the enum is exported (`v1::contract::taxonomy`), so its
/// variants stay live in every build.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Cond {
    StaleIfMatch,
    ArchiveChanged,
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
    RecoveryConflict,
    AtKeyCap,
    /// A PATCH would re-enable a revoked key. Revoked is terminal (BUSBAR-4044).
    KeyRevoked,
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
    /// ceiling. Refused outright over the API (1.5.3) — the ceiling is operator FILE policy.
    TrustCeilingRaise,
    /// A write would create, re-point, re-key or remove a definition backed by the operator
    /// credential, or touch the plugin admission set that decides it. The operator credential is
    /// operator FILE policy (OPERATOR-FROM-ADMITTED-AUTH §3.6): set only in config.yaml.
    OperatorFilePolicy,
    /// A named-map DELETE would leave a DANGLING REFERENCE: another config site still names the
    /// definition by bare name (e.g. `auth.chain`).
    StillReferenced,
    /// A usage read reached a class the rate card in force does not price (#42).
    Unpriced,
    /// A restart-only admin config change on an in-memory (Ephemeral) Store: the restart that
    /// would apply it is the same event that erases it, so it is refused, not silently lost.
    RestartUnreachable,
    /// A plugin refused an op in its own words, or an instance open failed in the plugin
    /// (`plugin_rejected`); its text and condition word are in `details`.
    PluginRejected,
    /// `telemetry.enabled: false` was set explicitly, so the metric registry is off.
    TelemetryDisabled,
}

impl Cond {
    /// The closed reason this condition puts on the wire (`error.reason`): its snake-case name.
    /// An exhaustive match, so a new condition does not compile until it is named here and in
    /// `busbar_kernel::admin::reasons::REASONS`.
    pub fn reason(self) -> &'static str {
        match self {
            Cond::StaleIfMatch => "stale_if_match",
            Cond::ArchiveChanged => "archive_changed",
            Cond::MalformedIfMatch => "malformed_if_match",
            Cond::UnknownResource => "unknown_resource",
            Cond::MalformedBody => "malformed_body",
            Cond::InvalidTree => "invalid_tree",
            Cond::BaseDefined => "base_defined",
            Cond::GrantChange => "grant_change",
            Cond::BoundKeys => "bound_keys",
            Cond::StillParent => "still_parent",
            Cond::GovernanceOff => "governance_off",
            Cond::NoSigningKey => "no_signing_key",
            Cond::IdempotencyInFlight => "idempotency_in_flight",
            Cond::RecoveryConflict => "recovery_conflict",
            Cond::AtKeyCap => "at_key_cap",
            Cond::KeyRevoked => "key_revoked",
            Cond::ParentWithoutGroup => "parent_without_group",
            Cond::KeyExpiryFields => "key_expiry_fields",
            Cond::RebindTargetMissing => "rebind_target_missing",
            Cond::HookNoAck => "hook_no_ack",
            Cond::SettingsPush => "settings_push",
            Cond::MalformedCursor => "malformed_cursor",
            Cond::MissingRequiredQuery => "missing_required_query",
            Cond::InvalidQueryValue => "invalid_query_value",
            Cond::NonNumericPath => "non_numeric_path",
            Cond::InvalidConfig => "invalid_config",
            Cond::UnknownModule => "unknown_module",
            Cond::LockoutSelf => "lockout_self",
            Cond::NoDiskBase => "no_disk_base",
            Cond::UntrustedUpload => "untrusted_upload",
            Cond::InvalidFilename => "invalid_filename",
            Cond::NotLoadable => "not_loadable",
            Cond::Overlong => "overlong",
            Cond::NothingToRotate => "nothing_to_rotate",
            Cond::NoSupervisor => "no_supervisor",
            Cond::NotRestartable => "not_restartable",
            Cond::UnknownSection => "unknown_section",
            Cond::NameCollision => "name_collision",
            Cond::InvalidLabels => "invalid_labels",
            Cond::TrustCeilingRaise => "trust_ceiling_raise",
            Cond::OperatorFilePolicy => "operator_file_policy",
            Cond::StillReferenced => "still_referenced",
            Cond::Unpriced => "unpriced",
            Cond::RestartUnreachable => "restart_unreachable",
            Cond::PluginRejected => "plugin_rejected",
            Cond::TelemetryDisabled => "telemetry_disabled",
        }
    }

    #[cfg(feature = "openapi-schema")]
    pub fn phrase(self) -> &'static str {
        match self {
            Cond::ArchiveChanged => "reviewed plugin archive changed or is missing",
            Cond::StaleIfMatch => "stale `If-Match` (re-read and retry)",
            Cond::MalformedIfMatch => "malformed `If-Match` header",
            Cond::UnknownResource => "unknown resource",
            Cond::MalformedBody => "malformed body / unknown field",
            Cond::InvalidTree => "invalid tree: dangling/cyclic parent or depth",
            Cond::BaseDefined => "base-defined (edit config.yaml)",
            Cond::GrantChange => "grant change on an existing definition",
            Cond::BoundKeys => "one or more keys are still bound (rebind/delete them first)",
            Cond::StillParent => "another group still names it as parent",
            Cond::GovernanceOff => "governance is not enabled on this server",
            Cond::NoSigningKey => "no signing key is configured for signed-token minting",
            Cond::RecoveryConflict => {
                "the retained operation, recovery version, verdict or resolution authority conflicts with the request"
            }
            Cond::IdempotencyInFlight => "an `Idempotency-Key` request is already in flight",
            Cond::AtKeyCap => "the group is at the `limits.max_keys_per_principal` cap",
            Cond::KeyRevoked => "the key is revoked, and a revoked key is never re-enabled",
            Cond::ParentWithoutGroup => "`parent` was given without `group`",
            Cond::KeyExpiryFields => "bad `expires_in` / `expires_at`",
            Cond::RebindTargetMissing => "the rebind target group does not exist",
            Cond::HookNoAck => "the hook did not acknowledge; nothing committed",
            Cond::SettingsPush => "a config change landed during the settings push; retry",
            Cond::MalformedCursor => "malformed pagination `cursor`",
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
                "the artifact is not loadable: bad archive/manifest, or it fails structure/trust \
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
                static PROSE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
                    format!(
                        "unknown overlay section (expected one of {})",
                        busbar_kernel::config::overlay::OverlaySection::valid_names()
                    )
                });
                PROSE.as_str()
            }
            Cond::InvalidLabels => {
                "invalid mint-time `labels`: a reserved or non-Prometheus label name, or too \
                 many/too long"
            }
            Cond::TrustCeilingRaise => {
                "raising `max_admin_scope` is refused over the admin API; the trust ceiling is \
                 operator file policy; lower it here, raise it in config.yaml"
            }
            Cond::OperatorFilePolicy => {
                "the operator credential is operator file policy; set or change it in config.yaml \
                 and POST /config/reload"
            }
            Cond::StillReferenced => {
                "another config section still references this definition by bare name (remove the \
                 reference first)"
            }
            Cond::Unpriced => {
                "a rate card is configured and names no price for a class this usage reached \
                 (an unpriced class refuses; it never reads 0)"
            }
            Cond::RestartUnreachable => {
                "restart-only change on an in-memory Store (set it in config.yaml or configure a \
                 durable store)"
            }
            Cond::NameCollision => {
                "the plugin name/alias collides with an already-installed plugin under a different \
                 filename"
            }
            Cond::PluginRejected => {
                "a plugin refused the request in its own words (its text and condition are in `details`)"
            }
            Cond::TelemetryDisabled => {
                "the operator set telemetry.enabled: false, so the metric registry is off"
            }
        }
    }
}

/// A documentable failure: which `AdminError` kind (→ frozen code + status) and the endpoint-specific
/// CONDITION that triggers it. Both are enums, so a declaration can neither invent a status nor drift
/// into prose that contradicts the code.
#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct DocErr {
    pub kind: ErrKind,
    pub cond: Cond,
}

/// Method tag for the `declared_errors` match (the doc dimension only cares about the verb).
#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MethodTag {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
impl MethodTag {
    pub fn from_op_key(key: &str) -> Option<MethodTag> {
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

#[cfg(test)]
pub use crate::test_support::method_tag;

#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
pub fn declared_errors(method: MethodTag, rel: &str) -> &'static [DocErr] {
    use Cond::*;
    use ErrKind::*;
    use MethodTag::*;
    macro_rules! de {
        ($($k:ident / $c:ident),* $(,)?) => {
            &[$(DocErr { kind: $k, cond: $c }),*]
        };
    }
    match (method, rel) {
        (Post, "/ledger/recovery/list") => de![Validation / MalformedBody],
        (Post, "/ledger/recovery/resolve") => {
            de![Validation / MalformedBody, Conflict / RecoveryConflict]
        }
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
        (Put, "/hooks/{name}/attachments/{target}") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Validation / InvalidConfig,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/hooks/{name}/attachments/{target}") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Validation / InvalidConfig,
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

        (Post, "/tools/{name}/connect") => {
            de![
                Validation / InvalidConfig,
                Validation / PluginRejected,
                NotFound / UnknownResource,
            ]
        }

        (Post, "/agents/{name}/connect") => {
            de![Validation / PluginRejected, NotFound / UnknownResource,]
        }
        (Post, "/agents/{name}/approve") => de![
            Validation / MalformedBody,
            Validation / InvalidConfig,
            Validation / PluginRejected,
            NotFound / UnknownResource,
        ],

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

        (Post, "/plugins") => de![
            Validation / MalformedBody,
            Validation / InvalidFilename,
            Validation / NotLoadable,
            Conflict / UntrustedUpload,
            Conflict / NameCollision,
        ],

        (Post, "/plugins/reload") => de![Validation / InvalidConfig],
        (Post, "/plugins/rollback") => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidFilename,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / NotLoadable,
            Conflict / ArchiveChanged,
            VersionConflict / StaleIfMatch,
        ],
        (Delete, "/plugins/{file}") => {
            de![
                Validation / InvalidFilename,
                Validation / InvalidQueryValue,
                NotFound / UnknownResource,
                Conflict / ArchiveChanged,
            ]
        }

        (Post, "/plugins/inspect") => de![Validation / MalformedBody],

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
            Conflict / OperatorFilePolicy,
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
            Conflict / RestartUnreachable,
            Conflict / OperatorFilePolicy,
        ],
        (Post, "/config/validate") => {
            de![Validation / MalformedBody, Conflict / OperatorFilePolicy]
        }
        (Post, "/auth/cache/flush") => de![Validation / MalformedBody],
        (Delete, "/overlay/{section}") => de![
            Validation / UnknownSection,
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            Validation / InvalidConfig,
            // A named-map section reset that would leave base config.yaml naming a definition it
            // removes. The bulk twin of the per-entry DELETE's dangling guard.
            Conflict / StillReferenced,
            VersionConflict / StaleIfMatch,
        ],
        (Get, "/config/diff") => de![
            Validation / MissingRequiredQuery,
            NotFound / UnknownResource,
        ],
        (Get, "/config/versions/{v}") => {
            de![Validation / NonNumericPath, NotFound / UnknownResource,]
        }

        (Get, "/groups") => de![Validation / MalformedCursor],
        (Get, "/audit") => de![Validation / MalformedCursor],
        (Get, "/config/versions") => de![Validation / MalformedCursor],
        (Get, "/plugins/{file}/schema") => de![
            Validation / InvalidQueryValue,
            Validation / InvalidFilename,
            Validation / NotLoadable,
            NotFound / UnknownResource,
            Conflict / ArchiveChanged,
        ],
        (Get, "/plugins") => de![Validation / MissingRequiredQuery],
        (Get, "/pools") => de![Validation / InvalidQueryValue],
        (Get, "/usage") => de![
            Validation / InvalidQueryValue,
            Validation / MalformedCursor,
            UnpricedClass / Unpriced
        ],
        (Get, "/groups/{name}/usage") => {
            de![NotFound / UnknownResource, UnpricedClass / Unpriced]
        }

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
            Conflict / KeyRevoked,
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
            UnpricedClass / Unpriced,
        ],
        (Post, "/keys/{id}/rotate") => de![
            Validation / Overlong,
            Validation / KeyExpiryFields,
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
            Validation / MalformedIfMatch,
            VersionConflict / StaleIfMatch,
            Conflict / NoSupervisor,
            Conflict / NotRestartable,
        ],

        (m, r) if NamedMapSection::parse_rel(r).is_some() => {
            let (section, shape) = NamedMapSection::parse_rel(r).expect("just matched");
            named_map_declared_errors(m, section, shape)
        }

        _ => {
            if method == Get && rel.contains('{') {
                de![NotFound / UnknownResource]
            } else {
                &[]
            }
        }
    }
}

#[cfg(any(test, feature = "openapi-schema", feature = "test-support"))]
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
        (Put, NamedMapShape::Item) if section.has_trust_ceiling() => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            Conflict / BaseDefined,
            Conflict / TrustCeilingRaise,
            Conflict / OperatorFilePolicy,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],
        (Put, NamedMapShape::Item) => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],
        (Delete, NamedMapShape::Item) if section.has_trust_ceiling() => de![
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / StillReferenced,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],
        (Delete, NamedMapShape::Item) => de![
            Validation / MalformedIfMatch,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],
        (Patch, NamedMapShape::Settings) if section.has_trust_ceiling() => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            Conflict / OperatorFilePolicy,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],
        (Patch, NamedMapShape::Settings) => de![
            Validation / MalformedBody,
            Validation / MalformedIfMatch,
            Validation / InvalidConfig,
            Validation / NoDiskBase,
            NotFound / UnknownResource,
            Conflict / BaseDefined,
            VersionConflict / StaleIfMatch,
            Conflict / RestartUnreachable,
        ],

        (Get, NamedMapShape::Item) => de![NotFound / UnknownResource],
        _ => &[],
    }
}

#[cfg(feature = "openapi-schema")]
pub fn declared_responses(method: MethodTag, rel: &str) -> Vec<(String, String)> {
    let declared = declared_errors(method, rel);

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

#[cfg(test)]
pub mod observed {
    use super::{Cond, ErrKind};

    /// The tag `err_json` stamps onto an error response so the recording layer (which knows the
    /// matched route, which `err_json` does not) can attribute it to an operation. `cond` is set at
    /// the shared seams that name their condition; a handler-body error leaves it `None`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Tag {
        pub kind: ErrKind,
        pub cond: Option<Cond>,
    }
}
