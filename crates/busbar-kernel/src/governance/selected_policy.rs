// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable selected-rate configuration. Compilation never creates dispatch authority,
//! consumes money, or owns rate counters. Only the authenticated current-policy resolver may
//! construct ResolvedSelectedRules; plain configuration and target metadata cannot do so.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::groups::{valid_selected_identifier, GroupCfg, LimitCfg, LimitMetric};
use crate::cost::CostModel;

use super::selected_resource::RateMetric;

const MAX_APPLICABLE: usize = 32;

pub use crate::plane_driver::image_identity::PlaneImageIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SelectedTargetKind {
    Registration,
    Model,
}

/// Borrowed configuration facts from the candidate generation's actual target producers.
/// Root supplies CatalogPlan targets and admitted registration definitions with the image's
/// validated attempt-accounting capability. This is not selection or authentication authority.
#[derive(Clone, Copy, Debug)]
pub struct SelectedTargetConfig<'a> {
    pub instance: &'a str,
    pub kind: SelectedTargetKind,
    pub pool: &'a str,
    pub member: &'a str,
    pub resource: Option<&'a str>,
    pub attempt_accounting: bool,
}

#[derive(Clone)]
struct CompiledRule {
    id: Box<str>,
    instance: Box<str>,
    resource: Box<str>,
    metric: LimitMetric,
    threshold: u64,
    // None means this publication activates the scope. This avoids per-row mutation at swap.
    activated_minute: Option<u64>,
}

/// Configuration compiled before the publication gate. It retains only its predecessor's
/// identity marker, never a policy history, targets map or rate cells.
pub struct PendingSelectedPolicy {
    groups: BTreeMap<String, Box<[CompiledRule]>>,
    cost: Arc<CostModel>,
    previous: Option<Arc<()>>,
}

pub struct SelectedPolicy {
    groups: BTreeMap<String, Box<[CompiledRule]>>,
    cost: Arc<CostModel>,
    revision: u64,
    activated_minute: u64,
    identity: Arc<()>,
}

impl SelectedPolicy {
    /// Run against the same validated groups, CostModel and actual target set that the
    /// candidate App will publish. Ordinary group/pool validation remains with its owner.
    pub fn compile(
        groups: &BTreeMap<String, GroupCfg>,
        cost: Arc<CostModel>,
        targets: &[SelectedTargetConfig<'_>],
        previous: Option<&Self>,
    ) -> Result<PendingSelectedPolicy, Vec<String>> {
        let mut errors = Vec::new();
        crate::config::groups::validate_groups(groups, &|_| true, &mut errors);
        if groups.len() != cost.groups().len() {
            errors.push("selected policy and current group model differ".into());
        }
        for (name, group) in groups {
            let matching = cost.group_named(name).is_some_and(|runtime| {
                runtime.enabled == group.enabled
                    && runtime
                        .parent
                        .and_then(|index| cost.groups().get(index))
                        .map(|parent| parent.name.as_str())
                        == group.parent.as_deref()
            });
            if !matching {
                errors.push(format!(
                    "groups.{name}: selected policy does not match current group model"
                ));
            }
        }
        // Temporary validation indexes are dropped before publication; actual target metadata
        // remains solely in the candidate's existing routing/catalog owners.
        let mut actual = BTreeMap::new();
        let mut resources = BTreeMap::new();
        for target in targets {
            if !valid_selected_identifier(target.instance)
                || target
                    .resource
                    .is_some_and(|resource| !valid_selected_identifier(resource))
                || target.pool.is_empty()
                || target.member.is_empty()
            {
                errors.push("selected target contains an invalid configured identity".into());
                continue;
            }
            let key = (target.instance, target.kind, target.pool, target.member);
            let value = (target.resource, target.attempt_accounting);
            if actual.insert(key, value).is_some_and(|old| old != value) {
                errors.push("one actual selected target has conflicting resource metadata".into());
            }
            if let Some(resource) = target.resource {
                resources
                    .entry((target.instance, resource))
                    .and_modify(|supported| *supported &= target.attempt_accounting)
                    .or_insert(target.attempt_accounting);
            }
        }
        let mut compiled = BTreeMap::new();
        for (name, group) in groups {
            let mut rows = Vec::new();
            for limit in &group.limits {
                if let Some(row) = compile_row(name, limit, &resources, &mut errors) {
                    rows.push(row);
                }
            }
            if let Some(template) = &group.child_default {
                for limit in &template.limits {
                    let _ = compile_row(name, limit, &resources, &mut errors);
                }
            }
            if let Some(old) = previous {
                for row in &mut rows {
                    row.activated_minute = old
                        .groups
                        .get(name)
                        .and_then(|rules| {
                            rules.iter().find(|old_row| {
                                old_row.id == row.id
                                    && old_row.instance == row.instance
                                    && old_row.resource == row.resource
                                    && old_row.metric == row.metric
                            })
                        })
                        .map(|old_row| old_row.activated_minute.unwrap_or(old.activated_minute));
                }
            }
            compiled.insert(name.clone(), rows.into_boxed_slice());
        }
        // Invalid graph errors must precede a walk; never silently stop a cyclic traversal.
        if !errors.is_empty() {
            return Err(errors);
        }
        for name in groups.keys() {
            let mut counts = BTreeMap::new();
            let mut cursor = Some(name.as_str());
            while let Some(group_name) = cursor {
                if let Some(rows) = compiled.get(group_name) {
                    for row in rows.iter() {
                        *counts
                            .entry((row.instance.as_ref(), row.resource.as_ref()))
                            .or_insert(0usize) += 1;
                    }
                }
                cursor = groups
                    .get(group_name)
                    .and_then(|group| group.parent.as_deref());
            }
            if counts.values().any(|count| *count > MAX_APPLICABLE) {
                errors.push(format!(
                    "groups.{name}: more than 32 applicable selected-resource rules"
                ));
            }
            // A provisioned child inherits the nearest template plus this complete parent chain.
            if let Some(template) = crate::config::groups::resolve_child_default(groups, name) {
                for limit in &template.limits {
                    if let Some(selected) = &limit.selected {
                        *counts
                            .entry((selected.instance(), selected.resource()))
                            .or_insert(0) += 1;
                    }
                }
                if counts.values().any(|count| *count > MAX_APPLICABLE) {
                    errors.push(format!("groups.{name}.child_default: child would exceed 32 applicable selected-resource rules"));
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(PendingSelectedPolicy {
            groups: compiled,
            cost,
            previous: previous.map(|policy| Arc::clone(&policy.identity)),
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn activated_minute(&self) -> u64 {
        self.activated_minute
    }
    pub fn cost_generation(&self) -> u64 {
        self.cost.generation()
    }
}

fn compile_row(
    group: &str,
    limit: &LimitCfg,
    resources: &BTreeMap<(&str, &str), bool>,
    errors: &mut Vec<String>,
) -> Option<CompiledRule> {
    let selected = limit.selected.as_ref()?;
    if !limit.valid_selected_shape() {
        errors.push(format!("groups.{group}: invalid selected-resource rule"));
        return None;
    }
    match resources.get(&(selected.instance(), selected.resource())) {
        None => errors.push(format!("groups.{group}: selected rule `{}` names an unavailable instance/resource", selected.id())),
        Some(false) if limit.metric == LimitMetric::Tokens => errors.push(format!("groups.{group}: selected token rule `{}` requires attempt accounting on every matching target", selected.id())),
        _ => {}
    }
    Some(CompiledRule {
        id: selected.id().into(),
        instance: selected.instance().into(),
        resource: selected.resource().into(),
        metric: limit.metric,
        threshold: limit.amount,
        activated_minute: None,
    })
}

impl PendingSelectedPolicy {
    /// O(1) move at the actual publication boundary, after sampling the shared governor clock.
    /// Root must use its admission gate and atomically publish the resulting complete App.
    pub fn activate(
        self,
        previous: Option<&SelectedPolicy>,
        revision: u64,
        minute: u64,
    ) -> Result<SelectedPolicy, &'static str> {
        let same_predecessor = match (&self.previous, previous) {
            (None, None) => true,
            (Some(expected), Some(actual)) => Arc::ptr_eq(expected, &actual.identity),
            _ => false,
        };
        if !same_predecessor
            || revision == 0
            || previous.is_some_and(|old| revision <= old.revision || minute < old.activated_minute)
        {
            return Err("selected policy publication has a stale predecessor, revision or clock");
        }
        Ok(SelectedPolicy {
            groups: self.groups,
            cost: self.cost,
            revision,
            activated_minute: minute,
            identity: Arc::new(()),
        })
    }
}

/// Only the current authenticated resolver in this module may construct this bound result.
/// No public constructor or raw key/rule-vector adapter exists.
pub(crate) struct ResolvedSelectedRules {
    key_id: Box<str>,
    instance: Box<str>,
    resource: Option<Box<str>>,
    rows: Box<[ResolvedSelectedRule]>,
    policy_revision: u64,
    activated_minute: u64,
}

pub(crate) struct ResolvedSelectedRule {
    group_id: Box<str>,
    rule_id: Box<str>,
    metric: RateMetric,
    threshold: u64,
    policy_revision: u64,
    activated_minute: u64,
}

impl ResolvedSelectedRules {
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }
    pub(crate) fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
    pub(crate) fn rows(&self) -> &[ResolvedSelectedRule] {
        &self.rows
    }
    pub(crate) fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub(crate) fn activated_minute(&self) -> u64 {
        self.activated_minute
    }
}

impl ResolvedSelectedRule {
    pub(crate) fn group_id(&self) -> &str {
        &self.group_id
    }
    pub(crate) fn rule_id(&self) -> &str {
        &self.rule_id
    }
    pub(crate) fn metric(&self) -> RateMetric {
        self.metric
    }
    pub(crate) fn threshold(&self) -> u64 {
        self.threshold
    }
    pub(crate) fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub(crate) fn activated_minute(&self) -> u64 {
        self.activated_minute
    }
}

#[cfg(test)]
#[path = "tests/selected_policy.rs"]
mod tests;
