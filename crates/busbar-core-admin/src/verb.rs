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
//! - one of the **13 new 1.6.0 verbs** named in the architecture document — see [`NEW_VERBS`];
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
    /// The scope `required_scope(method, path)` resolves to for this row: pinned here rather than
    /// recomputed, and derived from the method alone except for the two stateless dry-run POSTs
    /// named inline in [`scope_for`] (1.5.5's `required_scope` carve-out, reproduced verbatim).
    /// Every other `POST`/`PUT`/`PATCH`/`DELETE` is `Full`; every `GET`/`HEAD` is `ReadOnly`.
    pub scope: VerbScope,
}

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
/// Three groups, in the order the module doc names them: 66 legacy verbs, 13 new verbs, then the
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
    /// Deliberately break the journal chain (disaster recovery; irreducible; off-node CLI also
    /// exists on a stopped node).
    ChainBreak,
    /// Restore the store from backup (disaster recovery; irreducible; off-node CLI also exists).
    StoreRestore,
    /// Reseal the epoch floor after a chain break/restore (irreducible; off-node CLI also exists).
    ResealEpochFloor,
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
    /// `POST /api/v1/admin/ledger/amend-rate-history` — append a signed, back-dated correction to
    /// the dated rate-card history (irreducible). It out-ranks the entry it corrects and rewrites
    /// nothing; recompute reprices the corrected window against the new entry.
    AmendRateHistory,

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

    // ---- the three 1.6.0 audit-chain reads ----
    /// `GET /api/v1/admin/audit/head` — the chain's tip: position, digest, signature, key
    /// identifier and clock. The one fact an external party timestamps and counter-signs.
    GetAuditHead,
    /// `GET /api/v1/admin/audit/range` — records by position, each carrying every field its digest
    /// was taken over, so a puller VERIFIES the chain rather than trusting an answer about it.
    GetAuditRange,
    /// `GET /api/v1/admin/audit/keys` — the public keys the chain is signed with, published so a
    /// verifier never has to ask us for the key out of band.
    GetAuditKeys,

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

/// The 13 new 1.6.0 verbs: the twelve money-governance verbs, plus `amend_rate_history` — the
/// signed, back-dated rate-card correction the dated-history design adds to the irreducible set.
/// `set_operator_key`, `set_escrow`, `set_dual_control`, `export_keyset` and `approve` left 1.6.0
/// by the owner's 2026-09-08 ruling (ARCHITECTURE section 4.7): they are not verbs, and their paths are
/// the unmounted `404`.
pub const NEW_VERBS: &[KernelVerb] = &[
    KernelVerb::Verify,
    KernelVerb::PlaneFacts,
    KernelVerb::PlaneRecordWrite,
    KernelVerb::ChainBreak,
    KernelVerb::StoreRestore,
    KernelVerb::ResealEpochFloor,
    KernelVerb::SetOverdraftCeiling,
    KernelVerb::SetDisputeMaxAge,
    KernelVerb::CommitUpgrade,
    KernelVerb::ResolveDispute,
    KernelVerb::ResolveSlice,
    KernelVerb::Adjust,
    KernelVerb::AmendRateHistory,
];

/// WHETHER THIS BUILD BINDS AN EFFECT TO `verb` — the one question the administrative mount asks
/// before it takes a request into the loop, and the one the generated document asks before it
/// describes an operation.
///
/// A new verb whose effect is not bound is NOT SERVED: the mount hands it to the surface's own
/// fallback, which answers the unmounted `404` byte for byte and seals no audit row, and the
/// document does not describe it. Walking it through the gates to a `404` after its audit row was
/// written told the operator that something was admitted and then did nothing. Every verb outside
/// [`NEW_VERBS`] is answered by a surface that exists, so it is bound. Binding one of the others is
/// a new arm here in the same commit that lands its effect (and strikes its
/// `qa/unconstructed.toml` row).
#[must_use]
pub const fn effect_bound(verb: KernelVerb) -> bool {
    match verb {
        // Their effect lands on the store (`Verbs::chain_break` / `store_restore` /
        // `reseal_epoch_floor`).
        KernelVerb::ChainBreak | KernelVerb::StoreRestore | KernelVerb::ResealEpochFloor => true,
        // Their effect lands on the node's amendment journal (the composition root's
        // `execute_new_verb`).
        KernelVerb::Adjust | KernelVerb::AmendRateHistory => true,
        // Any other new verb is unbound until an arm above says otherwise: a verb added to
        // `NEW_VERBS` is unserved by default, never served onto a surface with no handler for it.
        _ => !is_new_verb(verb),
    }
}

/// Whether `verb` is one of [`NEW_VERBS`] (a `const` membership test for [`effect_bound`]).
const fn is_new_verb(verb: KernelVerb) -> bool {
    let mut i = 0;
    while i < NEW_VERBS.len() {
        if NEW_VERBS[i] as u16 == verb as u16 {
            return true;
        }
        i += 1;
    }
    false
}

/// The two new verbs the architecture document binds as `GET` — "POST for every mutating
/// verb, GET for the two read-only verbs (`verify`, `plane_facts`)".
///
/// They stay members of [`NEW_VERBS`] because they ARE two of them, and the operator
/// ceremony still reaches them through the same gate every other new verb runs (neither is in
/// [`IRREDUCIBLE_VERBS`], so that gate admits them). What being named here changes is everything
/// that follows from a verb being a read rather than a mutation: the scope it asks for, the mutation
/// budget it does not draw, and the maker-checker step it has nothing to wait for. A read held
/// behind an approval is not delayed, it is refused forever — nobody can approve a mutation that
/// does not exist.
pub const READ_ONLY_NEW_VERBS: &[KernelVerb] = &[KernelVerb::Verify, KernelVerb::PlaneFacts];

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

/// THE THREE AUDIT-CHAIN READS, in the order the admin surface lists them.
///
/// Their own list, for the same reason the ledger views have one: membership of [`NEW_VERBS`] is
/// what makes a verb posture-gated and `Full`-scoped, and neither is true of a read. These three
/// answer with what the node has already sealed — the head, a window of records, the public keys.
/// They mutate nothing, so there is no maker-checker step for dual control to interpose, and a read
/// held behind an approval is not delayed, it is refused forever.
///
/// They are also the one group whose whole purpose is to be read by somebody who does NOT trust the
/// node: an auditor, a counter-signing service, an operator with `curl` behind a firewall. Gating
/// them behind a full-scope credential would mean the only party who can check the evidence is the
/// party the evidence is about.
pub const AUDIT_VERBS: &[KernelVerb] = &[
    KernelVerb::GetAuditHead,
    KernelVerb::GetAuditRange,
    KernelVerb::GetAuditKeys,
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
    KernelVerb::ResealEpochFloor,
    KernelVerb::Adjust,
    KernelVerb::ResolveDispute,
    // `amend_rate_history` rewrites what the past cost, so D38 seals it irreducible.
    KernelVerb::AmendRateHistory,
];

/// THE ONE JOIN between this enum's spelling of a verb and the admin table's spelling of it.
///
/// The two were written against the same list and spell it two ways — one in the enumeration's Rust
/// casing, one in the operation-name casing the closed table's rows carry. This is where they meet.
///
/// It lived in the composition root until 1.6.0, which is what made it a SEAM: the table was
/// declared here and completed there, joined by `verb_name(v) == row.verb` over a `_ => ""` arm, so
/// a row nobody wrote an arm for resolved to the empty string and the failure surfaced as a silent
/// test red rather than as a compile error. Neither side could see that the other was incomplete
/// (`docs/design/BUSBAR-1.6.0.md:2064` names it: "a list that must agree with code, with nothing
/// forcing the agreement"). Both spellings live in THIS crate — the enum above, the rows in
/// [`crate::admin_codec`] — so the join belongs here too, where it can be checked against the rows
/// at compile time. It is, in both directions: see the `const` assertions in
/// `admin_codec/verbs.rs`, which refuse to build a table whose rows and names disagree.
///
/// `None` is NOT "no name was written for this verb". It is "this verb is not joined by name at
/// all" — the 66 legacy operations and the 8 named surfaces carry a row in the pinned 1.5.5
/// document and are joined on the method and path that document pinned, which is stronger than a
/// casing convention either side may change. The compile-time check above is what keeps `None` a
/// statement rather than an omission: a 1.6.0 verb that reached it would fail the build.
/// `docs/design/BUSBAR-1.6.0.md:2079` — A GAP AND A FAILURE MUST NEVER BE THE SAME OUTPUT — is why
/// this returns an option rather than an empty string: a missing thing and a present-but-empty
/// thing were indistinguishable, and the empty string matched no row, so the verb refused.
#[must_use]
pub const fn verb_name(verb: KernelVerb) -> Option<&'static str> {
    Some(match verb {
        // The 13 money-governance verbs.
        KernelVerb::Verify => "verify",
        KernelVerb::PlaneFacts => "plane_facts",
        KernelVerb::PlaneRecordWrite => "plane_record_write",
        KernelVerb::ChainBreak => "chain_break",
        KernelVerb::StoreRestore => "store_restore",
        KernelVerb::ResealEpochFloor => "reseal_epoch_floor",
        KernelVerb::SetOverdraftCeiling => "set_overdraft_ceiling",
        KernelVerb::SetDisputeMaxAge => "set_dispute_max_age",
        KernelVerb::CommitUpgrade => "commit_upgrade",
        KernelVerb::ResolveDispute => "resolve_dispute",
        KernelVerb::ResolveSlice => "resolve_slice",
        KernelVerb::Adjust => "adjust",
        KernelVerb::AmendRateHistory => "amend_rate_history",
        // The 5 ledger views.
        KernelVerb::GetLedgerTotals => "get_ledger_totals",
        KernelVerb::GetLedgerCheckpoints => "get_ledger_checkpoints",
        KernelVerb::GetLedgerReconciliation => "get_ledger_reconciliation",
        KernelVerb::GetLedgerMigration => "get_ledger_migration",
        KernelVerb::GetLedgerOpenapiJson => "get_ledger_openapi_json",
        // The 3 audit-chain reads.
        KernelVerb::GetAuditHead => "get_audit_head",
        KernelVerb::GetAuditRange => "get_audit_range",
        KernelVerb::GetAuditKeys => "get_audit_keys",
        // Joined by method and path, never by name — see the doc above.
        _ => return None,
    })
}
