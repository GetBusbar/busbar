// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed kernel-verb table.
//!
//! Every variant of [`KernelVerb`] is one of three things:
//!
//! - one of the **66 legacy operations** mechanically derived from 1.5.5's `openapi.json` at the
//!   tag (49 paths, 34 read-only / 32 full) — see [`LEGACY_VERBS`], and the conformance test in
//!   `tests/table_matches_openapi.rs` that fails the build if this list and the committed fixture
//!   ever disagree, by even one operation or one scope;
//! - one of the **17 new 1.6.0 verbs** named in the architecture document — see [`NEW_VERBS`];
//! - one of the **five 1.6.0 ledger views** — see [`LEDGER_VERBS`]. These are reads of what the
//!   ledger already holds, so they are the one group of 1.6.0 additions that is `ReadOnly` rather
//!   than `Full`, and the only group that is never posture-gated: reading a figure changes nothing,
//!   so there is no mutation for dual control to check. They carry no legacy row because they are
//!   new surface, and the document that describes them is a separate additive one for the same
//!   reason — the 1.5.5 document's bytes are pinned;
//! - one of the **named non-admin surfaces** (the self-serve token exchange, the browser token
//!   exchange, the two model listings, and the four unauthenticated/data-plane-keyed surfaces) —
//!   see [`NAMED_SURFACES`]. These are not part of the admin `openapi.json` table (they are not
//!   admin-scoped mutations at all) and are excluded from the openapi conformance check for that
//!   reason, but they are still verbs this crate is asked to execute, so the closed enum names them
//!   too.
//!
//! No fourth kind exists, and nothing outside this module may construct a [`KernelVerb`] value
//! other than by naming one of these variants — the enum is exhaustively matched everywhere, so
//! adding an operation means adding it here, in the open.

/// The two-rung authorization scope every verb requires. Mirrors 1.5.5's `Scope` exactly (a strict
/// chain: `ReadOnly` is satisfied by anything, `Full` only by `Full`) — reproduced here rather than
/// imported because this crate depends on nothing but `busbar-caps`, and the scope model is three
/// lines of logic, not a seam worth a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbScope {
    /// Every read, plus the two stateless dry-run POSTs (`config/validate`, `plugins/inspect`).
    ReadOnly,
    /// Every mutation.
    Full,
}

impl VerbScope {
    /// The stable wire token (matches 1.5.5's `Scope::as_str`).
    pub fn as_str(self) -> &'static str {
        match self {
            VerbScope::ReadOnly => "read-only",
            VerbScope::Full => "full",
        }
    }

    /// Does holding `self` satisfy a requirement of `needed`?
    pub fn allows(self, needed: VerbScope) -> bool {
        match needed {
            VerbScope::ReadOnly => true,
            VerbScope::Full => self == VerbScope::Full,
        }
    }
}

/// One row of the legacy (1.5.5-derived) verb table: an HTTP method + path pair (as 1.5.5's
/// `openapi.json` names them, ADMIN_PREFIX-relative is not needed here because the fixture's paths
/// are already absolute), the operation id 1.5.5 assigned it, and the scope `required_scope`
/// resolves for it. Both are pinned by the git object hash of the fixture the design names —
/// `testing/shadow-oracle/fixtures/openapi-1.5.5.json` — and checked byte-for-byte in
/// `tests/table_matches_openapi.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyVerbRow {
    /// The verb this row names.
    pub verb: KernelVerb,
    /// HTTP method, as the fixture spells it (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`).
    pub method: &'static str,
    /// The absolute path, exactly as `openapi.json` names it.
    pub path: &'static str,
    /// 1.5.5's own `operationId` for this path+method, kept so the conformance test can report a
    /// mismatch by the name an operator would recognise.
    pub operation_id: &'static str,
    /// The scope `required_scope(method, path)` resolves to for this row (PB-62: pinned, derived
    /// from method alone except the two stateless dry-run POSTs named in [`READ_ONLY_POST_PATHS`]).
    pub scope: VerbScope,
}

/// The two `POST` paths that are read-only dry-runs rather than mutations (1.5.5's
/// `required_scope` carve-out, reproduced verbatim). Every other `POST`/`PUT`/`PATCH`/`DELETE` is
/// `Full`; every `GET`/`HEAD` is `ReadOnly`.
pub const READ_ONLY_POST_PATHS: &[&str] = &[
    "/api/v1/admin/config/validate",
    "/api/v1/admin/plugins/inspect",
];

/// Resolve the scope a (method, path) pair requires, using exactly 1.5.5's rule: every read is
/// `ReadOnly`; the two stateless dry-run POSTs are `ReadOnly`; everything else is `Full`. This is
/// the SAME function the table-generation macro below calls, so the table and the rule can never
/// name two different scopes for one row.
const fn scope_for(method: &str, path: &str) -> VerbScope {
    // `const fn` cannot call `str::eq_ignore_ascii_case` conveniently over a slice, and every method
    // in the fixture is already upper-case, so a direct byte compare is exact and simple.
    if str_eq(method, "GET") || str_eq(method, "HEAD") {
        return VerbScope::ReadOnly;
    }
    if str_eq(path, "/api/v1/admin/config/validate")
        || str_eq(path, "/api/v1/admin/plugins/inspect")
    {
        return VerbScope::ReadOnly;
    }
    VerbScope::Full
}

/// `const`-context string equality (stable `str::eq` is not `const fn`).
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// One row per legacy verb, method+path+operation id, scope resolved by [`scope_for`] so it can
/// never be hand-typed out of step with the rule.
macro_rules! legacy_row {
    ($verb:ident, $method:literal, $path:literal, $opid:literal) => {
        LegacyVerbRow {
            verb: KernelVerb::$verb,
            method: $method,
            path: $path,
            operation_id: $opid,
            scope: scope_for($method, $path),
        }
    };
}

/// The closed kernel-verb table.
///
/// Three groups, in the order the module doc names them: 66 legacy verbs, 17 new verbs, then the
/// named non-admin surfaces. `#[non_exhaustive]` is deliberately NOT used — the whole point of a
/// closed table is that a `match` on this enum fails to compile the day a new operation is added
/// without updating this file, and a wildcard arm would silently swallow that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelVerb {
    // ---- legacy: config ----
    /// `GET /api/v1/admin/config`
    GetConfig,
    /// `POST /api/v1/admin/config/apply`
    PostConfigApply,
    /// `GET /api/v1/admin/config/diff`
    GetConfigDiff,
    /// `POST /api/v1/admin/config/reload`
    PostConfigReload,
    /// `POST /api/v1/admin/config/rollback`
    PostConfigRollback,
    /// `GET /api/v1/admin/config/settings`
    GetConfigSettings,
    /// `PUT /api/v1/admin/config/settings`
    PutConfigSettings,
    /// `POST /api/v1/admin/config/validate`
    PostConfigValidate,
    /// `GET /api/v1/admin/config/versions`
    GetConfigVersions,
    /// `GET /api/v1/admin/config/versions/{v}`
    GetConfigVersionsV,
    // ---- legacy: admin-auth ----
    /// `GET /api/v1/admin/admin-auth`
    GetAdminAuth,
    /// `PUT /api/v1/admin/admin-auth`
    PutAdminAuth,
    // ---- legacy: audit / auth / models / info / usage / openapi ----
    /// `GET /api/v1/admin/audit`
    GetAudit,
    /// `GET /api/v1/admin/auth`
    GetAuth,
    /// `POST /api/v1/admin/auth/cache/flush`
    PostAuthCacheFlush,
    /// `GET /api/v1/admin/models`
    GetModels,
    /// `GET /api/v1/admin/info`
    GetInfo,
    /// `GET /api/v1/admin/usage`
    GetUsage,
    /// `GET /api/v1/admin/openapi.json`
    GetOpenapiJson,
    // ---- legacy: export ----
    /// `GET /api/v1/admin/export`
    GetExport,
    /// `DELETE /api/v1/admin/export/{name}`
    DeleteExportName,
    /// `GET /api/v1/admin/export/{name}`
    GetExportName,
    /// `PUT /api/v1/admin/export/{name}`
    PutExportName,
    /// `PATCH /api/v1/admin/export/{name}/settings`
    PatchExportNameSettings,
    // ---- legacy: groups ----
    /// `GET /api/v1/admin/groups`
    GetGroups,
    /// `POST /api/v1/admin/groups`
    PostGroups,
    /// `DELETE /api/v1/admin/groups/{name}`
    DeleteGroupsName,
    /// `GET /api/v1/admin/groups/{name}`
    GetGroupsName,
    /// `PATCH /api/v1/admin/groups/{name}`
    PatchGroupsName,
    /// `PUT /api/v1/admin/groups/{name}`
    PutGroupsName,
    /// `GET /api/v1/admin/groups/{name}/usage`
    GetGroupsNameUsage,
    // ---- legacy: hooks ----
    /// `GET /api/v1/admin/hooks`
    GetHooks,
    /// `POST /api/v1/admin/hooks`
    PostHooks,
    /// `DELETE /api/v1/admin/hooks/{name}`
    DeleteHooksName,
    /// `GET /api/v1/admin/hooks/{name}`
    GetHooksName,
    /// `PUT /api/v1/admin/hooks/{name}`
    PutHooksName,
    /// `GET /api/v1/admin/hooks/{name}/health`
    GetHooksNameHealth,
    /// `GET /api/v1/admin/hooks/{name}/schema`
    GetHooksNameSchema,
    /// `PATCH /api/v1/admin/hooks/{name}/settings`
    PatchHooksNameSettings,
    /// `GET /api/v1/admin/hooks/{name}/status`
    GetHooksNameStatus,
    // ---- legacy: identity providers ----
    /// `GET /api/v1/admin/identity-providers`
    GetIdentityProviders,
    /// `DELETE /api/v1/admin/identity-providers/{name}`
    DeleteIdentityProvidersName,
    /// `GET /api/v1/admin/identity-providers/{name}`
    GetIdentityProvidersName,
    /// `PUT /api/v1/admin/identity-providers/{name}`
    PutIdentityProvidersName,
    /// `PATCH /api/v1/admin/identity-providers/{name}/settings`
    PatchIdentityProvidersNameSettings,
    // ---- legacy: keys ----
    /// `GET /api/v1/admin/keys`
    GetKeys,
    /// `POST /api/v1/admin/keys`
    PostKeys,
    /// `DELETE /api/v1/admin/keys/{id}`
    DeleteKeysId,
    /// `GET /api/v1/admin/keys/{id}`
    GetKeysId,
    /// `PATCH /api/v1/admin/keys/{id}`
    PatchKeysId,
    /// `POST /api/v1/admin/keys/{id}/revoke`
    PostKeysIdRevoke,
    /// `POST /api/v1/admin/keys/{id}/rotate`
    PostKeysIdRotate,
    /// `GET /api/v1/admin/keys/{id}/usage`
    GetKeysIdUsage,
    // ---- legacy: overlay ----
    /// `DELETE /api/v1/admin/overlay/{section}`
    DeleteOverlaySection,
    // ---- legacy: plugins ----
    /// `GET /api/v1/admin/plugins`
    GetPlugins,
    /// `POST /api/v1/admin/plugins`
    PostPlugins,
    /// `POST /api/v1/admin/plugins/inspect`
    PostPluginsInspect,
    /// `POST /api/v1/admin/plugins/reload`
    PostPluginsReload,
    /// `POST /api/v1/admin/plugins/rollback`
    PostPluginsRollback,
    /// `DELETE /api/v1/admin/plugins/{file}`
    DeletePluginsFile,
    /// `GET /api/v1/admin/plugins/{file}/schema`
    GetPluginsFileSchema,
    // ---- legacy: pools / providers ----
    /// `GET /api/v1/admin/pools`
    GetPools,
    /// `GET /api/v1/admin/pools/{name}`
    GetPoolsName,
    /// `GET /api/v1/admin/providers`
    GetProviders,
    // ---- legacy: restart / signing key ----
    /// `POST /api/v1/admin/restart`
    PostRestart,
    /// `POST /api/v1/admin/signing-key/rotate`
    PostSigningKeyRotate,

    // ---- 1.6.0 new verbs (17) ----
    /// Verify a claim/signature outside the normal request path.
    Verify,
    /// Read plane facts (a plane's own declared facts surface).
    PlaneFacts,
    /// Write a `PlaneRecord` entry.
    PlaneRecordWrite,
    /// Set the operator public key (irreducible; admitted under `unset` with the admin credential).
    SetOperatorKey,
    /// Set the M-of-N key-loss escrow (irreducible).
    SetEscrow,
    /// Deliberately break the journal chain (disaster recovery; irreducible; off-node CLI also
    /// exists on a stopped node).
    ChainBreak,
    /// Restore the store from backup (disaster recovery; irreducible; off-node CLI also exists).
    StoreRestore,
    /// Reseal the epoch floor after a chain break/restore (irreducible; off-node CLI also exists).
    ResealEpochFloor,
    /// Flip dual-control posture between `single` and `required` (irreducible).
    SetDualControl,
    /// Set a bucket's overdraft ceiling.
    SetOverdraftCeiling,
    /// Set `dispute_max_age`.
    SetDisputeMaxAge,
    /// Commit the schema/version upgrade (irreducible).
    CommitUpgrade,
    /// Resolve an open dispute (irreducible above `adjust_threshold`).
    ResolveDispute,
    /// Resolve a slice-level dispute.
    ResolveSlice,
    /// Manually adjust a ledger figure (irreducible above `adjust_threshold`).
    Adjust,
    /// Export the deployment keyset, sealed to a recipient public key (irreducible; the one verb
    /// admitted under `operator: unset` besides `SetOperatorKey`).
    ExportKeyset,
    /// The maker-checker approval verb (checked, not itself dual-controlled).
    Approve,

    // ---- 1.6.0 ledger views (5) ----
    /// `GET /api/v1/admin/ledger/totals` — what the ledger posted, per bucket, day, lane and
    /// provider.
    GetLedgerTotals,
    /// `GET /api/v1/admin/ledger/checkpoints` — the sealed checkpoint figures.
    GetLedgerCheckpoints,
    /// `GET /api/v1/admin/ledger/reconciliation` — the residual of the ledger's postings against
    /// the previous release's rows, row by row.
    GetLedgerReconciliation,
    /// `GET /api/v1/admin/ledger/migration` — the marker the first boot after the upgrade sealed.
    GetLedgerMigration,
    /// `GET /api/v1/admin/ledger/openapi.json` — the additive document describing the 1.6.0
    /// operations, served beside the 1.5.5 document rather than inside it.
    GetLedgerOpenapiJson,

    // ---- named non-admin surfaces ----
    /// `POST /auth/token` — the self-serve exchange (exempt from dual control in both postures).
    PostAuthToken,
    /// `GET /auth/token` — the browser exchange (unauthenticated exact-path bypass; dispatches on
    /// `?logout` / `?code` / `?method` / `?refresh`).
    GetAuthToken,
    /// `GET /v1/models`
    GetV1Models,
    /// `GET /v1beta/models`
    GetV1BetaModels,
    /// `GET /stats`
    GetStats,
    /// `GET /healthz` (unconditional auth bypass on both listeners).
    GetHealthz,
    /// `GET /metrics` (present only when `export.prometheus` is configured).
    GetMetrics,
    /// `GET /metrics/hooks` (present only when `metrics::enabled()`).
    GetMetricsHooks,
}

/// The 66 legacy rows, in the exact order 1.5.5's `openapi.json` lists them (alphabetised by path,
/// then by method — the same order the fixture-derived listing in
/// `tests/table_matches_openapi.rs` compares against). Editing a row here without updating the
/// fixture, or vice versa, is exactly what the conformance test exists to catch.
pub const LEGACY_VERBS: &[LegacyVerbRow] = &[
    legacy_row!(
        GetAdminAuth,
        "GET",
        "/api/v1/admin/admin-auth",
        "GetAdminAuth"
    ),
    legacy_row!(
        PutAdminAuth,
        "PUT",
        "/api/v1/admin/admin-auth",
        "PutAdminAuth"
    ),
    legacy_row!(GetAudit, "GET", "/api/v1/admin/audit", "GetAudit"),
    legacy_row!(GetAuth, "GET", "/api/v1/admin/auth", "GetAuth"),
    legacy_row!(
        PostAuthCacheFlush,
        "POST",
        "/api/v1/admin/auth/cache/flush",
        "PostAuthCacheFlush"
    ),
    legacy_row!(GetConfig, "GET", "/api/v1/admin/config", "GetConfig"),
    legacy_row!(
        PostConfigApply,
        "POST",
        "/api/v1/admin/config/apply",
        "PostConfigApply"
    ),
    legacy_row!(
        GetConfigDiff,
        "GET",
        "/api/v1/admin/config/diff",
        "GetConfigDiff"
    ),
    legacy_row!(
        PostConfigReload,
        "POST",
        "/api/v1/admin/config/reload",
        "PostConfigReload"
    ),
    legacy_row!(
        PostConfigRollback,
        "POST",
        "/api/v1/admin/config/rollback",
        "PostConfigRollback"
    ),
    legacy_row!(
        GetConfigSettings,
        "GET",
        "/api/v1/admin/config/settings",
        "GetConfigSettings"
    ),
    legacy_row!(
        PutConfigSettings,
        "PUT",
        "/api/v1/admin/config/settings",
        "PutConfigSettings"
    ),
    legacy_row!(
        PostConfigValidate,
        "POST",
        "/api/v1/admin/config/validate",
        "PostConfigValidate"
    ),
    legacy_row!(
        GetConfigVersions,
        "GET",
        "/api/v1/admin/config/versions",
        "GetConfigVersions"
    ),
    legacy_row!(
        GetConfigVersionsV,
        "GET",
        "/api/v1/admin/config/versions/{v}",
        "GetConfigVersionsV"
    ),
    legacy_row!(GetExport, "GET", "/api/v1/admin/export", "GetExport"),
    legacy_row!(
        DeleteExportName,
        "DELETE",
        "/api/v1/admin/export/{name}",
        "DeleteExportName"
    ),
    legacy_row!(
        GetExportName,
        "GET",
        "/api/v1/admin/export/{name}",
        "GetExportName"
    ),
    legacy_row!(
        PutExportName,
        "PUT",
        "/api/v1/admin/export/{name}",
        "PutExportName"
    ),
    legacy_row!(
        PatchExportNameSettings,
        "PATCH",
        "/api/v1/admin/export/{name}/settings",
        "PatchExportNameSettings"
    ),
    legacy_row!(GetGroups, "GET", "/api/v1/admin/groups", "GetGroups"),
    legacy_row!(PostGroups, "POST", "/api/v1/admin/groups", "PostGroups"),
    legacy_row!(
        DeleteGroupsName,
        "DELETE",
        "/api/v1/admin/groups/{name}",
        "DeleteGroupsName"
    ),
    legacy_row!(
        GetGroupsName,
        "GET",
        "/api/v1/admin/groups/{name}",
        "GetGroupsName"
    ),
    legacy_row!(
        PatchGroupsName,
        "PATCH",
        "/api/v1/admin/groups/{name}",
        "PatchGroupsName"
    ),
    legacy_row!(
        PutGroupsName,
        "PUT",
        "/api/v1/admin/groups/{name}",
        "PutGroupsName"
    ),
    legacy_row!(
        GetGroupsNameUsage,
        "GET",
        "/api/v1/admin/groups/{name}/usage",
        "GetGroupsNameUsage"
    ),
    legacy_row!(GetHooks, "GET", "/api/v1/admin/hooks", "GetHooks"),
    legacy_row!(PostHooks, "POST", "/api/v1/admin/hooks", "PostHooks"),
    legacy_row!(
        DeleteHooksName,
        "DELETE",
        "/api/v1/admin/hooks/{name}",
        "DeleteHooksName"
    ),
    legacy_row!(
        GetHooksName,
        "GET",
        "/api/v1/admin/hooks/{name}",
        "GetHooksName"
    ),
    legacy_row!(
        PutHooksName,
        "PUT",
        "/api/v1/admin/hooks/{name}",
        "PutHooksName"
    ),
    legacy_row!(
        GetHooksNameHealth,
        "GET",
        "/api/v1/admin/hooks/{name}/health",
        "GetHooksNameHealth"
    ),
    legacy_row!(
        GetHooksNameSchema,
        "GET",
        "/api/v1/admin/hooks/{name}/schema",
        "GetHooksNameSchema"
    ),
    legacy_row!(
        PatchHooksNameSettings,
        "PATCH",
        "/api/v1/admin/hooks/{name}/settings",
        "PatchHooksNameSettings"
    ),
    legacy_row!(
        GetHooksNameStatus,
        "GET",
        "/api/v1/admin/hooks/{name}/status",
        "GetHooksNameStatus"
    ),
    legacy_row!(
        GetIdentityProviders,
        "GET",
        "/api/v1/admin/identity-providers",
        "GetIdentityProviders"
    ),
    legacy_row!(
        DeleteIdentityProvidersName,
        "DELETE",
        "/api/v1/admin/identity-providers/{name}",
        "DeleteIdentityProvidersName"
    ),
    legacy_row!(
        GetIdentityProvidersName,
        "GET",
        "/api/v1/admin/identity-providers/{name}",
        "GetIdentityProvidersName"
    ),
    legacy_row!(
        PutIdentityProvidersName,
        "PUT",
        "/api/v1/admin/identity-providers/{name}",
        "PutIdentityProvidersName"
    ),
    legacy_row!(
        PatchIdentityProvidersNameSettings,
        "PATCH",
        "/api/v1/admin/identity-providers/{name}/settings",
        "PatchIdentityProvidersNameSettings"
    ),
    legacy_row!(GetInfo, "GET", "/api/v1/admin/info", "GetInfo"),
    legacy_row!(GetKeys, "GET", "/api/v1/admin/keys", "GetKeys"),
    legacy_row!(PostKeys, "POST", "/api/v1/admin/keys", "PostKeys"),
    legacy_row!(
        DeleteKeysId,
        "DELETE",
        "/api/v1/admin/keys/{id}",
        "DeleteKeysId"
    ),
    legacy_row!(GetKeysId, "GET", "/api/v1/admin/keys/{id}", "GetKeysId"),
    legacy_row!(
        PatchKeysId,
        "PATCH",
        "/api/v1/admin/keys/{id}",
        "PatchKeysId"
    ),
    legacy_row!(
        PostKeysIdRevoke,
        "POST",
        "/api/v1/admin/keys/{id}/revoke",
        "PostKeysIdRevoke"
    ),
    legacy_row!(
        PostKeysIdRotate,
        "POST",
        "/api/v1/admin/keys/{id}/rotate",
        "PostKeysIdRotate"
    ),
    legacy_row!(
        GetKeysIdUsage,
        "GET",
        "/api/v1/admin/keys/{id}/usage",
        "GetKeysIdUsage"
    ),
    legacy_row!(GetModels, "GET", "/api/v1/admin/models", "GetModels"),
    legacy_row!(
        GetOpenapiJson,
        "GET",
        "/api/v1/admin/openapi.json",
        "GetOpenapiJson"
    ),
    legacy_row!(
        DeleteOverlaySection,
        "DELETE",
        "/api/v1/admin/overlay/{section}",
        "DeleteOverlaySection"
    ),
    legacy_row!(GetPlugins, "GET", "/api/v1/admin/plugins", "GetPlugins"),
    legacy_row!(PostPlugins, "POST", "/api/v1/admin/plugins", "PostPlugins"),
    legacy_row!(
        PostPluginsInspect,
        "POST",
        "/api/v1/admin/plugins/inspect",
        "PostPluginsInspect"
    ),
    legacy_row!(
        PostPluginsReload,
        "POST",
        "/api/v1/admin/plugins/reload",
        "PostPluginsReload"
    ),
    legacy_row!(
        PostPluginsRollback,
        "POST",
        "/api/v1/admin/plugins/rollback",
        "PostPluginsRollback"
    ),
    legacy_row!(
        DeletePluginsFile,
        "DELETE",
        "/api/v1/admin/plugins/{file}",
        "DeletePluginsFile"
    ),
    legacy_row!(
        GetPluginsFileSchema,
        "GET",
        "/api/v1/admin/plugins/{file}/schema",
        "GetPluginsFileSchema"
    ),
    legacy_row!(GetPools, "GET", "/api/v1/admin/pools", "GetPools"),
    legacy_row!(
        GetPoolsName,
        "GET",
        "/api/v1/admin/pools/{name}",
        "GetPoolsName"
    ),
    legacy_row!(
        GetProviders,
        "GET",
        "/api/v1/admin/providers",
        "GetProviders"
    ),
    legacy_row!(PostRestart, "POST", "/api/v1/admin/restart", "PostRestart"),
    legacy_row!(GetUsage, "GET", "/api/v1/admin/usage", "GetUsage"),
    legacy_row!(
        PostSigningKeyRotate,
        "POST",
        "/api/v1/admin/signing-key/rotate",
        "PostSigningKeyRotate"
    ),
];

/// The 17 new 1.6.0 verbs, in the order the architecture document names them.
pub const NEW_VERBS: &[KernelVerb] = &[
    KernelVerb::Verify,
    KernelVerb::PlaneFacts,
    KernelVerb::PlaneRecordWrite,
    KernelVerb::SetOperatorKey,
    KernelVerb::SetEscrow,
    KernelVerb::ChainBreak,
    KernelVerb::StoreRestore,
    KernelVerb::ResealEpochFloor,
    KernelVerb::SetDualControl,
    KernelVerb::SetOverdraftCeiling,
    KernelVerb::SetDisputeMaxAge,
    KernelVerb::CommitUpgrade,
    KernelVerb::ResolveDispute,
    KernelVerb::ResolveSlice,
    KernelVerb::Adjust,
    KernelVerb::ExportKeyset,
    KernelVerb::Approve,
];

/// The five 1.6.0 ledger views, in the order the admin surface lists them.
///
/// Kept as their own list rather than folded into [`NEW_VERBS`] because membership of that list is
/// what makes a verb posture-gated and `Full`-scoped, and neither is true of a read. A view answers
/// with figures the ledger already holds: it mutates nothing, so there is no maker-checker step for
/// dual control to interpose, and it needs no more authority than the legacy `GET /usage` that
/// reads the same money from the other side.
pub const LEDGER_VERBS: &[KernelVerb] = &[
    KernelVerb::GetLedgerTotals,
    KernelVerb::GetLedgerCheckpoints,
    KernelVerb::GetLedgerReconciliation,
    KernelVerb::GetLedgerMigration,
    KernelVerb::GetLedgerOpenapiJson,
];

/// The named non-admin surfaces, each pinned by its own handler in 1.5.5, not by this crate's
/// verb-execution rules (see the module doc).
pub const NAMED_SURFACES: &[KernelVerb] = &[
    KernelVerb::PostAuthToken,
    KernelVerb::GetAuthToken,
    KernelVerb::GetV1Models,
    KernelVerb::GetV1BetaModels,
    KernelVerb::GetStats,
    KernelVerb::GetHealthz,
    KernelVerb::GetMetrics,
    KernelVerb::GetMetricsHooks,
];

/// The irreducible set, required in both dual-control postures (architecture doc: "Irreducible
/// set, required in both postures"). `Adjust` and `ResolveDispute` are irreducible only ABOVE
/// `adjust_threshold` — that quantity is not decidable from the verb alone, so callers that need
/// the threshold-gated form check it themselves (see [`crate::posture`]); they are still listed
/// here so the closed set names every verb the document calls irreducible, with the caveat carried
/// in this doc comment rather than silently dropped.
pub const IRREDUCIBLE_VERBS: &[KernelVerb] = &[
    KernelVerb::ChainBreak,
    KernelVerb::StoreRestore,
    KernelVerb::CommitUpgrade,
    KernelVerb::SetDualControl,
    KernelVerb::ResealEpochFloor,
    KernelVerb::SetOperatorKey,
    KernelVerb::SetEscrow,
    KernelVerb::ExportKeyset,
    KernelVerb::Adjust,
    KernelVerb::ResolveDispute,
];

/// The two verbs admitted under `operator: unset` (every other irreducible verb is refused until
/// the ceremony completes).
pub const ADMITTED_UNDER_UNSET: &[KernelVerb] =
    &[KernelVerb::SetOperatorKey, KernelVerb::ExportKeyset];
