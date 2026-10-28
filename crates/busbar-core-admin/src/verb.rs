// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed kernel-verb table: ONE const [`TABLE`] of rows, and everything else a filter over it.
//!
//! Every [`KernelVerb`] has exactly one [`VerbRow`] carrying its method, path, name, class, scope
//! and whether this build binds an effect to it. The class says which of five groups it is in:
//!
//! - [`Class::Legacy`]: the 66 operations derived from 1.5.5's `openapi.json` (49 paths, 34
//!   read-only / 32 full); `tests/table_matches_openapi.rs` fails if these rows and the committed
//!   fixture disagree by one operation, one scope or one name;
//! - [`Class::New`]: the 12 new 1.6.0 verbs. The scope is the 1.5.5 rule on the method: the three
//!   `GET` ones are read-only, the rest are `Full` mutations;
//! - [`Class::Ledger`]: the five 1.6.0 ledger views, reads of what the ledger already holds;
//! - [`Class::Audit`]: the three 1.6.0 audit-chain reads (pull, never push);
//! - [`Class::Named`]: the non-admin surfaces (token exchanges, model listings, stats, health,
//!   metrics). They are not part of the admin `openapi.json` table and never resolve through it.
//!
//! [`LEGACY_VERBS`], [`NEW_VERBS`], [`LEDGER_VERBS`], [`AUDIT_VERBS`] and [`NAMED_SURFACES`] are
//! const filters of [`TABLE`] by class. The enum is exhaustively matched everywhere, so adding an
//! operation means adding a variant and a row here, in the open.

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

/// Which group of the module doc a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// One of the 66 operations of 1.5.5's `openapi.json`.
    Legacy,
    /// One of the 12 new 1.6.0 verbs.
    New,
    /// One of the five 1.6.0 ledger views.
    Ledger,
    /// One of the three 1.6.0 audit-chain reads.
    Audit,
    /// A named non-admin surface.
    Named,
}

/// One row of the closed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerbRow {
    /// The verb this row names.
    pub verb: KernelVerb,
    /// HTTP method, upper-case.
    pub method: &'static str,
    /// The absolute path, `{param}` segments and all.
    pub path: &'static str,
    /// The operation name: 1.5.5's `operationId` in snake case for a legacy row, the design's own
    /// spelling for the rest.
    pub name: &'static str,
    /// The group the row belongs to.
    pub class: Class,
    /// The scope `required_scope(method, path)` resolves to: every `GET`/`HEAD` and the two
    /// stateless dry-run POSTs are `ReadOnly`, everything else `Full`.
    pub scope: VerbScope,
    /// Whether this build binds an effect to the verb. A new verb whose effect is not bound is NOT
    /// SERVED: the mount hands it to the surface's own fallback (the unmounted `404`, no audit
    /// row) and the generated document does not describe it.
    pub bound: bool,
}

/// 1.5.5's scope rule for a (method, path): every read is `ReadOnly`; the two stateless dry-run
/// POSTs are `ReadOnly`; everything else is `Full`.
const fn scope_for(method: &str, path: &str) -> VerbScope {
    match (method.as_bytes(), path.as_bytes()) {
        (b"GET" | b"HEAD", _)
        | (_, b"/api/v1/admin/config/validate" | b"/api/v1/admin/plugins/inspect") => {
            VerbScope::ReadOnly
        }
        _ => VerbScope::Full,
    }
}

const fn row(
    verb: KernelVerb,
    method: &'static str,
    path: &'static str,
    name: &'static str,
    class: Class,
) -> VerbRow {
    // A named surface is never checked against the two-rung scope model (see `Verbs::execute`);
    // it is `ReadOnly` only so `required_scope` stays total.
    let scope = match class {
        Class::Named => VerbScope::ReadOnly,
        _ => scope_for(method, path),
    };
    VerbRow {
        verb,
        method,
        path,
        name,
        class,
        scope,
        bound: true,
    }
}

/// The closed kernel-verb enumeration. `#[non_exhaustive]` is deliberately NOT used — a `match` on
/// it fails to compile the day an operation is added without updating the code that handles it.
/// Every variant has one row in [`TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelVerb {
    // ---- legacy: config ----
    GetConfig,
    PostConfigApply,
    GetConfigDiff,
    PostConfigReload,
    PostConfigRollback,
    GetConfigSettings,
    PutConfigSettings,
    PostConfigValidate,
    GetConfigVersions,
    GetConfigVersionsV,
    // ---- legacy: admin-auth ----
    GetAdminAuth,
    PutAdminAuth,
    // ---- legacy: audit / auth / models / info / usage / openapi ----
    GetAudit,
    GetAuth,
    PostAuthCacheFlush,
    GetModels,
    GetInfo,
    GetUsage,
    GetOpenapiJson,
    // ---- legacy: export ----
    GetExport,
    DeleteExportName,
    GetExportName,
    PutExportName,
    PatchExportNameSettings,
    // ---- legacy: groups ----
    GetGroups,
    PostGroups,
    DeleteGroupsName,
    GetGroupsName,
    PatchGroupsName,
    PutGroupsName,
    GetGroupsNameUsage,
    // ---- legacy: hooks ----
    GetHooks,
    PostHooks,
    DeleteHooksName,
    GetHooksName,
    PutHooksName,
    GetHooksNameHealth,
    GetHooksNameSchema,
    PatchHooksNameSettings,
    GetHooksNameStatus,
    // ---- legacy: identity providers ----
    GetIdentityProviders,
    DeleteIdentityProvidersName,
    GetIdentityProvidersName,
    PutIdentityProvidersName,
    PatchIdentityProvidersNameSettings,
    // ---- legacy: keys ----
    GetKeys,
    PostKeys,
    DeleteKeysId,
    GetKeysId,
    PatchKeysId,
    PostKeysIdRevoke,
    PostKeysIdRotate,
    GetKeysIdUsage,
    // ---- legacy: overlay ----
    DeleteOverlaySection,
    // ---- legacy: plugins ----
    GetPlugins,
    PostPlugins,
    PostPluginsInspect,
    PostPluginsReload,
    PostPluginsRollback,
    DeletePluginsFile,
    GetPluginsFileSchema,
    // ---- legacy: pools / providers ----
    GetPools,
    GetPoolsName,
    GetProviders,
    // ---- legacy: restart / signing key ----
    PostRestart,
    PostSigningKeyRotate,

    // ---- 1.6.0 new verbs (12) ----
    Verify,
    PlaneFacts,
    PlaneRecordWrite,
    ChainBreak,
    StoreRestore,
    ResealEpochFloor,
    CommitUpgrade,
    Adjust,
    AmendRateHistory,
    GetTrust,
    TrustApprove,
    TrustRevoke,

    // ---- 1.6.0 ledger views (5) ----
    GetLedgerTotals,
    GetLedgerCheckpoints,
    GetLedgerReconciliation,
    GetLedgerMigration,
    GetLedgerOpenapiJson,

    // ---- the three 1.6.0 audit-chain reads ----
    GetAuditHead,
    GetAuditRange,
    GetAuditKeys,

    // ---- named non-admin surfaces ----
    PostAuthToken,
    GetAuthToken,
    GetV1Models,
    GetV1BetaModels,
    GetStats,
    GetHealthz,
    GetMetrics,
    GetMetricsHooks,
}

macro_rules! table {
    ($($class:ident $verb:ident $method:literal $path:literal $name:literal;)*) => {
        &[$(row(KernelVerb::$verb, $method, $path, $name, Class::$class)),*]
    };
}

/// THE table, one row per line: class, verb, method, path, name. Legacy rows first, in the order
/// 1.5.5's `openapi.json` lists them (alphabetised by path, then method), then the 1.6.0 additions,
/// then the named surfaces. `verify` and `plane_facts` are bound `GET` and read-only (BUSBAR-1.6.0.md,
/// CG-56); the other new money-governance paths are a judgment call, `POST /api/v1/admin/<kebab>`,
/// except `amend_rate_history` (bound under `/ledger/` by the dated rate-card-history design) and
/// the trust verbs (ARCHITECT 2026-10-06).
pub const TABLE: &[VerbRow] = table! {
    Legacy GetAdminAuth "GET" "/api/v1/admin/admin-auth" "get_admin_auth";
    Legacy PutAdminAuth "PUT" "/api/v1/admin/admin-auth" "put_admin_auth";
    Legacy GetAudit "GET" "/api/v1/admin/audit" "get_audit";
    Legacy GetAuth "GET" "/api/v1/admin/auth" "get_auth";
    Legacy PostAuthCacheFlush "POST" "/api/v1/admin/auth/cache/flush" "post_auth_cache_flush";
    Legacy GetConfig "GET" "/api/v1/admin/config" "get_config";
    Legacy PostConfigApply "POST" "/api/v1/admin/config/apply" "post_config_apply";
    Legacy GetConfigDiff "GET" "/api/v1/admin/config/diff" "get_config_diff";
    Legacy PostConfigReload "POST" "/api/v1/admin/config/reload" "post_config_reload";
    Legacy PostConfigRollback "POST" "/api/v1/admin/config/rollback" "post_config_rollback";
    Legacy GetConfigSettings "GET" "/api/v1/admin/config/settings" "get_config_settings";
    Legacy PutConfigSettings "PUT" "/api/v1/admin/config/settings" "put_config_settings";
    Legacy PostConfigValidate "POST" "/api/v1/admin/config/validate" "post_config_validate";
    Legacy GetConfigVersions "GET" "/api/v1/admin/config/versions" "get_config_versions";
    Legacy GetConfigVersionsV "GET" "/api/v1/admin/config/versions/{v}" "get_config_versions_v";
    Legacy GetExport "GET" "/api/v1/admin/export" "get_export";
    Legacy DeleteExportName "DELETE" "/api/v1/admin/export/{name}" "delete_export_name";
    Legacy GetExportName "GET" "/api/v1/admin/export/{name}" "get_export_name";
    Legacy PutExportName "PUT" "/api/v1/admin/export/{name}" "put_export_name";
    Legacy PatchExportNameSettings "PATCH" "/api/v1/admin/export/{name}/settings" "patch_export_name_settings";
    Legacy GetGroups "GET" "/api/v1/admin/groups" "get_groups";
    Legacy PostGroups "POST" "/api/v1/admin/groups" "post_groups";
    Legacy DeleteGroupsName "DELETE" "/api/v1/admin/groups/{name}" "delete_groups_name";
    Legacy GetGroupsName "GET" "/api/v1/admin/groups/{name}" "get_groups_name";
    Legacy PatchGroupsName "PATCH" "/api/v1/admin/groups/{name}" "patch_groups_name";
    Legacy PutGroupsName "PUT" "/api/v1/admin/groups/{name}" "put_groups_name";
    Legacy GetGroupsNameUsage "GET" "/api/v1/admin/groups/{name}/usage" "get_groups_name_usage";
    Legacy GetHooks "GET" "/api/v1/admin/hooks" "get_hooks";
    Legacy PostHooks "POST" "/api/v1/admin/hooks" "post_hooks";
    Legacy DeleteHooksName "DELETE" "/api/v1/admin/hooks/{name}" "delete_hooks_name";
    Legacy GetHooksName "GET" "/api/v1/admin/hooks/{name}" "get_hooks_name";
    Legacy PutHooksName "PUT" "/api/v1/admin/hooks/{name}" "put_hooks_name";
    Legacy GetHooksNameHealth "GET" "/api/v1/admin/hooks/{name}/health" "get_hooks_name_health";
    Legacy GetHooksNameSchema "GET" "/api/v1/admin/hooks/{name}/schema" "get_hooks_name_schema";
    Legacy PatchHooksNameSettings "PATCH" "/api/v1/admin/hooks/{name}/settings" "patch_hooks_name_settings";
    Legacy GetHooksNameStatus "GET" "/api/v1/admin/hooks/{name}/status" "get_hooks_name_status";
    Legacy GetIdentityProviders "GET" "/api/v1/admin/identity-providers" "get_identity_providers";
    Legacy DeleteIdentityProvidersName "DELETE" "/api/v1/admin/identity-providers/{name}" "delete_identity_providers_name";
    Legacy GetIdentityProvidersName "GET" "/api/v1/admin/identity-providers/{name}" "get_identity_providers_name";
    Legacy PutIdentityProvidersName "PUT" "/api/v1/admin/identity-providers/{name}" "put_identity_providers_name";
    Legacy PatchIdentityProvidersNameSettings "PATCH" "/api/v1/admin/identity-providers/{name}/settings" "patch_identity_providers_name_settings";
    Legacy GetInfo "GET" "/api/v1/admin/info" "get_info";
    Legacy GetKeys "GET" "/api/v1/admin/keys" "get_keys";
    Legacy PostKeys "POST" "/api/v1/admin/keys" "post_keys";
    Legacy DeleteKeysId "DELETE" "/api/v1/admin/keys/{id}" "delete_keys_id";
    Legacy GetKeysId "GET" "/api/v1/admin/keys/{id}" "get_keys_id";
    Legacy PatchKeysId "PATCH" "/api/v1/admin/keys/{id}" "patch_keys_id";
    Legacy PostKeysIdRevoke "POST" "/api/v1/admin/keys/{id}/revoke" "post_keys_id_revoke";
    Legacy PostKeysIdRotate "POST" "/api/v1/admin/keys/{id}/rotate" "post_keys_id_rotate";
    Legacy GetKeysIdUsage "GET" "/api/v1/admin/keys/{id}/usage" "get_keys_id_usage";
    Legacy GetModels "GET" "/api/v1/admin/models" "get_models";
    Legacy GetOpenapiJson "GET" "/api/v1/admin/openapi.json" "get_openapi_json";
    Legacy DeleteOverlaySection "DELETE" "/api/v1/admin/overlay/{section}" "delete_overlay_section";
    Legacy GetPlugins "GET" "/api/v1/admin/plugins" "get_plugins";
    Legacy PostPlugins "POST" "/api/v1/admin/plugins" "post_plugins";
    Legacy PostPluginsInspect "POST" "/api/v1/admin/plugins/inspect" "post_plugins_inspect";
    Legacy PostPluginsReload "POST" "/api/v1/admin/plugins/reload" "post_plugins_reload";
    Legacy PostPluginsRollback "POST" "/api/v1/admin/plugins/rollback" "post_plugins_rollback";
    Legacy DeletePluginsFile "DELETE" "/api/v1/admin/plugins/{file}" "delete_plugins_file";
    Legacy GetPluginsFileSchema "GET" "/api/v1/admin/plugins/{file}/schema" "get_plugins_file_schema";
    Legacy GetPools "GET" "/api/v1/admin/pools" "get_pools";
    Legacy GetPoolsName "GET" "/api/v1/admin/pools/{name}" "get_pools_name";
    Legacy GetProviders "GET" "/api/v1/admin/providers" "get_providers";
    Legacy PostRestart "POST" "/api/v1/admin/restart" "post_restart";
    Legacy PostSigningKeyRotate "POST" "/api/v1/admin/signing-key/rotate" "post_signing_key_rotate";
    Legacy GetUsage "GET" "/api/v1/admin/usage" "get_usage";
    New Verify "GET" "/api/v1/admin/verify" "verify";
    New PlaneFacts "GET" "/api/v1/admin/plane-facts" "plane_facts";
    New PlaneRecordWrite "POST" "/api/v1/admin/plane-record-write" "plane_record_write";
    New ChainBreak "POST" "/api/v1/admin/chain-break" "chain_break";
    New StoreRestore "POST" "/api/v1/admin/store-restore" "store_restore";
    New ResealEpochFloor "POST" "/api/v1/admin/reseal-epoch-floor" "reseal_epoch_floor";
    New CommitUpgrade "POST" "/api/v1/admin/commit-upgrade" "commit_upgrade";
    New Adjust "POST" "/api/v1/admin/adjust" "adjust";
    New AmendRateHistory "POST" "/api/v1/admin/ledger/amend-rate-history" "amend_rate_history";
    New GetTrust "GET" "/api/v1/admin/trust" "get_trust";
    New TrustApprove "POST" "/api/v1/admin/trust/approve" "trust_approve";
    New TrustRevoke "POST" "/api/v1/admin/trust/revoke" "trust_revoke";
    Ledger GetLedgerTotals "GET" "/api/v1/admin/ledger/totals" "get_ledger_totals";
    Ledger GetLedgerCheckpoints "GET" "/api/v1/admin/ledger/checkpoints" "get_ledger_checkpoints";
    Ledger GetLedgerReconciliation "GET" "/api/v1/admin/ledger/reconciliation" "get_ledger_reconciliation";
    Ledger GetLedgerMigration "GET" "/api/v1/admin/ledger/migration" "get_ledger_migration";
    Ledger GetLedgerOpenapiJson "GET" "/api/v1/admin/ledger/openapi.json" "get_ledger_openapi_json";
    Audit GetAuditHead "GET" "/api/v1/admin/audit/head" "get_audit_head";
    Audit GetAuditRange "GET" "/api/v1/admin/audit/range" "get_audit_range";
    Audit GetAuditKeys "GET" "/api/v1/admin/audit/keys" "get_audit_keys";
    Named PostAuthToken "POST" "/auth/token" "post_auth_token";
    Named GetAuthToken "GET" "/auth/token" "get_auth_token";
    Named GetV1Models "GET" "/v1/models" "get_v1_models";
    Named GetV1BetaModels "GET" "/v1beta/models" "get_v1beta_models";
    Named GetStats "GET" "/stats" "get_stats";
    Named GetHealthz "GET" "/healthz" "get_healthz";
    Named GetMetrics "GET" "/metrics" "get_metrics";
    Named GetMetricsHooks "GET" "/metrics/hooks" "get_metrics_hooks";
};

const fn count(class: Class) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < TABLE.len() {
        if TABLE[i].class as u8 == class as u8 {
            n += 1;
        }
        i += 1;
    }
    n
}

/// The rows of one class, in table order.
const fn rows_of<const N: usize>(class: Class) -> [VerbRow; N] {
    let mut out = [TABLE[0]; N];
    let (mut i, mut n) = (0, 0);
    while i < TABLE.len() {
        if TABLE[i].class as u8 == class as u8 {
            out[n] = TABLE[i];
            n += 1;
        }
        i += 1;
    }
    out
}

/// The verbs of one class, in table order.
const fn verbs_of<const N: usize>(class: Class) -> [KernelVerb; N] {
    let rows = rows_of::<N>(class);
    let mut out = [TABLE[0].verb; N];
    let mut i = 0;
    while i < N {
        out[i] = rows[i].verb;
        i += 1;
    }
    out
}

/// The 66 legacy rows.
pub const LEGACY_VERBS: &[VerbRow] = &rows_of::<{ count(Class::Legacy) }>(Class::Legacy);

/// The 12 new 1.6.0 verbs: scope is the method rule, so the `GET` ones are reads and the rest are
/// `Full` mutations. Membership is what spends the mutation budget in `Verbs::admit`.
pub const NEW_VERBS: &[KernelVerb] = &verbs_of::<{ count(Class::New) }>(Class::New);

/// The five 1.6.0 ledger views. A view mutates nothing and needs no more authority than the legacy
/// `GET /usage` that reads the same money from the other side.
pub const LEDGER_VERBS: &[KernelVerb] = &verbs_of::<{ count(Class::Ledger) }>(Class::Ledger);

/// The three audit-chain reads. Their whole purpose is to be read by somebody who does NOT trust
/// the node, so gating them behind a full-scope credential would defeat them.
pub const AUDIT_VERBS: &[KernelVerb] = &verbs_of::<{ count(Class::Audit) }>(Class::Audit);

/// The named non-admin surfaces, each pinned by its own handler in 1.5.5.
pub const NAMED_SURFACES: &[KernelVerb] = &verbs_of::<{ count(Class::Named) }>(Class::Named);

/// The row for `verb`.
#[must_use]
pub fn row_of(verb: KernelVerb) -> Option<&'static VerbRow> {
    TABLE.iter().find(|r| r.verb == verb)
}

/// The admin rows (every class but [`Class::Named`]): the ones a request line can resolve to.
pub fn admin_rows() -> impl Iterator<Item = &'static VerbRow> {
    TABLE.iter().filter(|r| r.class != Class::Named)
}

/// The admin verb a templated (method, path) names.
#[must_use]
pub fn verb_for(method: &str, path: &str) -> Option<KernelVerb> {
    admin_rows()
        .find(|r| r.method == method && r.path == path)
        .map(|r| r.verb)
}

/// Whether this build binds an effect to `verb` — the one question the administrative mount asks
/// before it takes a request into the loop, and the one the generated document asks before it
/// describes an operation. A verb with no row is not bound.
#[must_use]
pub fn effect_bound(verb: KernelVerb) -> bool {
    row_of(verb).is_some_and(|r| r.bound)
}

/// The operation name of a 1.6.0 verb (new, ledger or audit), the spelling its row carries. `None`
/// for the 66 legacy operations and the named surfaces: those are joined on the method and path
/// the pinned 1.5.5 document fixed, which is stronger than a casing convention. A gap and a
/// failure must never be the same output, hence an option rather than an empty string.
#[must_use]
pub fn verb_name(verb: KernelVerb) -> Option<&'static str> {
    row_of(verb)
        .filter(|r| !matches!(r.class, Class::Legacy | Class::Named))
        .map(|r| r.name)
}
