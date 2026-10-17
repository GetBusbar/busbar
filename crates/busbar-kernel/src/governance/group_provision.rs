// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Group tree building + auto-provisioning — CORE governance/config infrastructure.
//!
//! RELOCATED out of `admin/v1/service.rs` (`build_with_group`, `pool_known`,
//! `MAX_GROUP_NAME_LEN`) and `admin/v1/json/handlers.rs` (`plan_mint_group`,
//! `persist_provisioned_group`) — 1.6.0 de-alias, stage 2a. This is the config-apply-transaction's
//! governance-group-provisioning LOGIC that `auth::self_keys` (core, the self-serve token-exchange
//! seam) calls to auto-provision a `user:<sub>` personal budget leaf before minting — routing
//! through it via `crate::admin::v1::json::{plan_mint_group, persist_provisioned_group}` was the
//! last core→admin edge this stage exists to cut.
//!
//! `Result<_, crate::config::transaction::TxnError>` throughout (was `AdminError`, admin-surface
//! vocabulary): `AdminError: From<TxnError>` (`admin/v1/contract/mod.rs`) maps every variant these
//! functions raise 1:1, so every existing admin call site's wire error is byte-identical — only the
//! Rust error type these functions themselves carry changed.

use std::sync::Arc;

use crate::config::transaction::TxnError;
use crate::state::App;

/// Upper bound on a group name — a registry key persisted to the overlay + every audit row.
/// Generous over any real `org/dept/team/user:<sub>` name.
pub const MAX_GROUP_NAME_LEN: usize = 256;

/// Whether `p` names a live pool, read through the NEUTRAL pool label space (`EngineTablesView`) so
/// this core group-validator names no plane table type. The `validate_groups` `pool_exists` predicate.
pub fn pool_known(app: &App, p: &str) -> bool {
    app.engine_tables_view()
        .pools()
        .iter()
        .any(|(n, _)| *n == p)
}

/// Build the next `App` snapshot with `name` created-or-replaced in the group registry — the pure
/// core of `POST`/`PUT /api/v1/admin/groups`. VALIDATE-AT-THE-DOOR: the mutated registry is run
/// through the SAME `validate_groups` boot uses (parent references exist, the parent chain is
/// acyclic — any depth, the cycle check is the bound), so a bad group (dangling/cyclic parent) is a
/// `400` that changes nothing. On success the enforcement projection is rebuilt via
/// `CostModel::with_groups` (reusing the rate card + fee unchanged) so the new limits are live after
/// the swap; the governance LEDGER survives (it is Arc-shared, not rebuilt), so past accrual is
/// preserved across the change.
pub fn build_with_group(
    current: &App,
    name: &str,
    cfg: crate::config::GroupCfg,
) -> Result<App, TxnError> {
    if name.trim().is_empty() {
        return Err(TxnError::Validation("group name must not be empty".into()));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(TxnError::Validation(format!(
            "group name is {} chars; must be <= {MAX_GROUP_NAME_LEN}",
            name.len()
        )));
    }
    // Build the candidate registry and validate it WHOLE before mutating the snapshot — a group's
    // legality (parent exists, chain acyclic) is a property of the tree, not the single entry.
    let mut groups = current.groups_registry.clone();
    groups.insert(name.to_string(), cfg);
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(&groups, &|p| pool_known(current, p), &mut errors);
    if !errors.is_empty() {
        return Err(TxnError::Validation(format!(
            "invalid group `{name}`: {}",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// Resolve — and if needed AUTO-PROVISION — the group a `POST /keys` mint binds to (self-service).
/// The mint-time group contract, one place, shared by the key handler:
///
/// - group EXISTS, no `parent` given → bind as-is (`Ok(None)`, nothing to provision).
/// - group EXISTS, `parent` given → the given parent MUST equal the group's actual parent, else
///   `409 conflict` (a portal must not silently re-home an existing leaf under a different team).
/// - group MISSING, `parent` given → return the CANDIDATE `App` that creates it as a leaf under
///   `parent`, limits stamped from the nearest-ancestor `child_default` (inherit-only when none),
///   via the SAME `build_with_group` validate-at-the-door path every group write uses (so
///   validation / cost rebuild / base-shadow guard all hold).
/// - group MISSING, no `parent` → today's `400` (an unknown group with nowhere to root it).
///
/// PURE and SYNCHRONOUS: it decides against the snapshot it is handed and returns a plan. It takes
/// no lock and performs no swap — the caller runs it INSIDE `config_transaction`, so the existence
/// check, the provisioning swap and the key's store write share ONE continuous lock hold. The
/// earlier shape took the mutation lock itself and RELEASED it on return, which is exactly why the
/// mint had to re-acquire and re-verify the group by hand; there is nothing left to re-verify
/// because the lock is never released between the check and the bind. `parent` is capped at
/// `MAX_GROUP_NAME_LEN` (a registry key / audit row).
pub fn plan_mint_group(
    current: &Arc<App>,
    group: &str,
    parent: Option<&str>,
    actor: &str,
) -> Result<Option<Arc<App>>, TxnError> {
    // Fast path: the group already exists (existence is the ENFORCEMENT truth — `cost.group_named`,
    // the exact check every request admission uses — so a mint never binds a group the chain can't
    // resolve). If a `parent` was named it must match the existing parent (never silently re-home an
    // existing leaf); the parent value comes from the config registry, which agrees with the cost
    // model in production (both rebuilt together on every apply).
    if current.cost.group_named(group).is_some() {
        if let Some(want) = parent {
            let actual = current
                .groups_registry
                .get(group)
                .and_then(|g| g.parent.clone());
            if actual.as_deref() != Some(want) {
                return Err(TxnError::Conflict(format!(
                    "group `{group}` already exists with parent {}; the mint named parent `{want}` \
                     — a mint cannot re-home an existing group (PATCH the group to re-parent it, or \
                     drop `parent` to bind as-is)",
                    actual
                        .map(|p| format!("`{p}`"))
                        .unwrap_or_else(|| "<root>".into()),
                )));
            }
        }
        return Ok(None);
    }
    // The group does NOT exist. Without a `parent` there is nowhere to root it — today's 400 stands
    // (mirrors the pre-auto-provision message, but points at the self-service `parent:` field).
    let Some(parent) = parent else {
        return Err(TxnError::Validation(format!(
            "group '{group}' does not exist in the top-level groups block; either configure it \
             first, or pass `parent: <existing-group>` to auto-provision it as a leaf (e.g. \
             `parent: team-payments` creates {group} under team-payments and binds the key)"
        )));
    };
    if parent.len() > MAX_GROUP_NAME_LEN {
        return Err(TxnError::Validation(format!(
            "parent name is {} chars; must be <= {}",
            parent.len(),
            MAX_GROUP_NAME_LEN
        )));
    }
    // The named parent must exist — build_with_group's validate-at-the-door would reject a dangling
    // parent as a 400, but name it precisely here (the mint's parent, not an opaque tree error).
    // Existence via the enforcement truth (cost), matching the group existence check above.
    if current.cost.group_named(parent).is_none() {
        return Err(TxnError::Validation(format!(
            "cannot auto-provision `{group}`: its `parent: {parent}` does not exist in the \
             top-level groups block; name an existing team/org group"
        )));
    }
    // A base-config group name is file-owned — the additive overlay cannot durably shadow it, so a
    // mint must not materialize one at runtime (mirrors POST /groups). Vanishingly unlikely for a
    // `user:<sub>` leaf, but the guard is uniform across every write path.
    if current.base_group_names.contains(group) {
        return Err(TxnError::Conflict(format!(
            "group `{group}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    // ANTI-SPRAWL CEILING ON THE TREE'S SHAPE. `max_keys_per_principal` bounds
    // how many keys a group holds but says nothing about how many GROUPS exist, so a `mint`-scope
    // credential could grow the limit tree without bound — every auto-provisioned `user:<sub>` leaf
    // is a new enforcement bucket, a new version-log entry and a new persisted overlay row.
    // `limits.max_auto_provisioned_groups` (0 = unlimited, the default) caps the runtime group set
    // this path may grow. Checked HERE, inside the transaction, against the same fresh snapshot the
    // existence check reads, so N concurrent self-mints cannot jointly overshoot. Explicitly
    // configured groups are unaffected: only auto-provisioning is gated.
    let ceiling = current.max_auto_provisioned_groups;
    if ceiling > 0 && current.groups_registry.len() >= ceiling {
        return Err(TxnError::Conflict(format!(
            "cannot auto-provision `{group}`: this server already has {} group(s), at the \
             `limits.max_auto_provisioned_groups` ceiling of {ceiling}. Delete an unused group, \
             raise the ceiling, or bind the key to an existing group",
            current.groups_registry.len(),
        )));
    }
    let leaf = crate::config::groups::provision_child(&current.groups_registry, parent);
    match build_with_group(current, group, leaf) {
        Ok(next) => Ok(Some(Arc::new(next))),
        Err(e) => {
            // Same audit row the explicit `POST /groups` writes when its build is rejected.
            crate::audit_ring::AUDIT.record_by(
                "group.provision",
                &format!("group:{group}"),
                crate::audit_ring::OUTCOME_REJECTED,
                actor,
            );
            Err(e)
        }
    }
}

/// The overlay persist a mint's auto-provisioned group leaf commits (PERSIST-then-SWAP, fail-closed
/// — the same discipline and the same wording as an explicit `POST /groups`).
pub fn persist_provisioned_group(
    installed: Arc<App>,
    group: String,
    actor: String,
) -> impl FnOnce() -> Result<(), String> + Send + 'static {
    move || {
        crate::config::overlay::persist_groups(
            installed.overlay_path.as_deref(),
            &installed.groups_registry,
            None,
            Some(&group),
            &installed.base_group_names,
        )
        .map_err(|e| {
            crate::audit_ring::AUDIT.record_by(
                "group.provision",
                &format!("group:{group}"),
                crate::audit_ring::OUTCOME_REJECTED,
                &actor,
            );
            format!("group could not be persisted to the overlay: {e}; nothing was changed")
        })
    }
}
