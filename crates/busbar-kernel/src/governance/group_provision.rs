// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::config::transaction::TxnError;
use crate::state::App;

pub const MAX_GROUP_NAME_LEN: usize = 256;

pub fn pool_known(app: &App, p: &str) -> bool {
    app.engine_tables_view()
        .pools()
        .iter()
        .any(|(n, _)| *n == p)
}

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

pub fn plan_mint_group(
    current: &Arc<App>,
    group: &str,
    parent: Option<&str>,
    actor: &str,
) -> Result<Option<Arc<App>>, TxnError> {
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

    if current.cost.group_named(parent).is_none() {
        return Err(TxnError::Validation(format!(
            "cannot auto-provision `{group}`: its `parent: {parent}` does not exist in the \
             top-level groups block; name an existing team/org group"
        )));
    }

    if current.base_group_names.contains(group) {
        return Err(TxnError::Conflict(format!(
            "group `{group}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }

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
            format!("group persistence to the Store overlay was not confirmed: {e}; the running group tree is unaffected")
        })
    }
}
