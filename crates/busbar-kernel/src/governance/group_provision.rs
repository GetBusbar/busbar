// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;
use std::sync::Arc;

use crate::config::transaction::TxnError;
use crate::state::App;

pub const MAX_GROUP_NAME_LEN: usize = 256;

/// A refused group change: the error path renders its message once, here.
fn refusal(kind: fn(String) -> TxnError, args: fmt::Arguments<'_>) -> TxnError {
    crate::cold::governance::runtime::group_provision_refusal(kind, args)
}

/// An existing group's parent as a refusal names it: `` `name` ``, or `<root>`.
struct ParentName<'a>(Option<&'a str>);

impl fmt::Display for ParentName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(p) => write!(f, "`{p}`"),
            None => f.write_str("<root>"),
        }
    }
}

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
    crate::off_path::governance::runtime::group_provision_build(current, name, cfg)
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
                .and_then(|g| g.parent.as_deref());
            if actual != Some(want) {
                return Err(refusal(
                    TxnError::Conflict,
                    format_args!(
                        "group `{group}` already exists with parent {}; the mint named parent \
                         `{want}` — a mint cannot re-home an existing group (PATCH the group to \
                         re-parent it, or drop `parent` to bind as-is)",
                        ParentName(actual),
                    ),
                ));
            }
        }
        return Ok(None);
    }

    let Some(parent) = parent else {
        return Err(refusal(
            TxnError::Validation,
            format_args!(
                "group '{group}' does not exist in the top-level groups block; either configure it \
                 first, or pass `parent: <existing-group>` to auto-provision it as a leaf (e.g. \
                 `parent: team-payments` creates {group} under team-payments and binds the key)"
            ),
        ));
    };
    if parent.len() > MAX_GROUP_NAME_LEN {
        return Err(refusal(
            TxnError::Validation,
            format_args!(
                "parent name is {} chars; must be <= {}",
                parent.len(),
                MAX_GROUP_NAME_LEN
            ),
        ));
    }

    if current.cost.group_named(parent).is_none() {
        return Err(refusal(
            TxnError::Validation,
            format_args!(
                "cannot auto-provision `{group}`: its `parent: {parent}` does not exist in the \
                 top-level groups block; name an existing team/org group"
            ),
        ));
    }

    if current.base_group_names.contains(group) {
        return Err(refusal(
            TxnError::Conflict,
            format_args!(
                "group `{group}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            ),
        ));
    }

    let ceiling = current.max_auto_provisioned_groups;
    if ceiling > 0 && current.groups_registry.len() >= ceiling {
        return Err(refusal(
            TxnError::Conflict,
            format_args!(
                "cannot auto-provision `{group}`: this server already has {} group(s), at the \
                 `limits.max_auto_provisioned_groups` ceiling of {ceiling}. Delete an unused \
                 group, raise the ceiling, or bind the key to an existing group",
                current.groups_registry.len(),
            ),
        ));
    }
    let leaf = crate::config::groups::provision_child(&current.groups_registry, parent);
    match build_with_group(current, group, leaf) {
        Ok(next) => Ok(Some(Arc::new(next))),
        Err(e) => {
            let resource = crate::cold::governance::runtime::group_provision_resource(group);
            crate::audit_ring::AUDIT.record_by(
                "group.provision",
                &resource,
                crate::audit_ring::OUTCOME_REJECTED,
                actor,
            );
            Err(e)
        }
    }
}

pub async fn persist_provisioned_group_async(
    installed: Arc<App>,
    group: String,
    actor: String,
) -> Result<(), String> {
    let persisted = crate::config::overlay::persist_groups_async(
        installed.overlay_path.as_deref(),
        &installed.groups_registry,
        None,
        Some(&group),
        &installed.base_group_names,
    )
    .await;
    persisted.map_err(|error| {
        let resource = crate::cold::governance::runtime::group_provision_resource(&group);
        crate::audit_ring::AUDIT.record_by(
            "group.provision",
            &resource,
            crate::audit_ring::OUTCOME_REJECTED,
            &actor,
        );
        crate::cold::governance::runtime::group_provision_persist_refusal(&error)
    })
}
