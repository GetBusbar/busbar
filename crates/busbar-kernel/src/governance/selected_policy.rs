// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable selected-rate configuration. Compilation never creates dispatch authority,
//! consumes money, or owns rate counters. Only the authenticated current-policy resolver may
//! construct ResolvedSelectedRules; plain configuration and target metadata cannot do so.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::groups::{valid_selected_identifier, GroupCfg, LimitCfg, LimitMetric};
use crate::cost::CostModel;
use crate::plane_driver::port_upstream::TargetIdentity;
use crate::plane_driver::PreparedRateAttempt;
use crate::state::App;

use super::current_credential::CurrentCredentialRefusal;
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

/// Current-policy refusal occurs before the governor owns any reservation or prepared token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedPolicyRefusal {
    CurrentAuthority(CurrentCredentialRefusal),
    CurrentGroup(busbar_contract::caps::ReasonCode),
    StalePolicyTarget,
    InvalidBinding,
}

impl From<CurrentCredentialRefusal> for SelectedPolicyRefusal {
    fn from(cause: CurrentCredentialRefusal) -> Self {
        match cause {
            CurrentCredentialRefusal::ForeignAuthority => Self::InvalidBinding,
            other => Self::CurrentAuthority(other),
        }
    }
}

struct CurrentRequest<'a> {
    key: Arc<busbar_contract::records::VirtualKey>,
    seat: &'a crate::plane_driver::port::PortSeat,
}

impl SelectedPolicy {
    pub(crate) fn matches_cost(&self, cost: &Arc<CostModel>) -> bool {
        Arc::ptr_eq(&self.cost, cost)
    }

    /// Resolve only under AppHandle's short admission gate, from its one current App load.
    /// This borrows the original attempt; refusal leaves its monetary custody untouched.
    pub(crate) fn resolve_current(
        &self,
        current: &App,
        prepared: &PreparedRateAttempt,
        now: u64,
    ) -> Result<ResolvedSelectedRules, SelectedPolicyRefusal> {
        use SelectedPolicyRefusal::{InvalidBinding, StalePolicyTarget};
        let receipt = prepared.receipt();
        let selected = prepared.selection();
        if !receipt.accepts_walk(selected.walk()) {
            return Err(InvalidBinding);
        }
        let origin = prepared.original_route().ok_or(InvalidBinding)?;
        if origin.route() != prepared.route() {
            return Err(InvalidBinding);
        }
        let CurrentRequest { key, seat } = self.current_request(current, receipt, origin, now)?;
        if !seat
            .request_routes
            .allows_current_selection(receipt, selected, &key)
        {
            return Err(StalePolicyTarget);
        }
        check_current_target(
            seat,
            selected.target(),
            selected.definition().ok_or(InvalidBinding)?,
        )?;
        self.bind_rows(&key, prepared.instance(), prepared.resource())
    }

    /// Read-only candidate evidence for hooks. It grants no dispatch and creates no holds.
    /// Metadata must come from the actual original candidate/TargetDefinition; authority
    /// remains the admitted request plus its retained original route and current credential.
    pub(crate) fn resolve_headroom(
        &self,
        current: &App,
        receipt: &crate::plane_driver::request_admission::AdmittedRequest,
        origin: &crate::plane_driver::route_identity::OriginalPlaneRoute,
        candidate: &crate::plane_driver::port_upstream::Candidate,
        definition: &crate::upstreams::UpstreamDef,
        now: u64,
    ) -> Result<ResolvedSelectedRules, SelectedPolicyRefusal> {
        let CurrentRequest { key, seat } = self.current_request(current, receipt, origin, now)?;
        if !seat
            .request_routes
            .allows_current_candidate(receipt, candidate, &key)
        {
            return Err(SelectedPolicyRefusal::StalePolicyTarget);
        }
        check_current_target(seat, candidate, definition)?;
        self.bind_rows(
            &key,
            receipt.context().instance(),
            candidate.resource.as_deref(),
        )
    }

    /// One shared authentication/image check for reservation and read-only headroom.
    /// Refresh scheduling belongs outside the gate; current_key uses hydrated cached state.
    fn current_request<'a>(
        &self,
        current: &'a App,
        receipt: &crate::plane_driver::request_admission::AdmittedRequest,
        origin: &crate::plane_driver::route_identity::OriginalPlaneRoute,
        now: u64,
    ) -> Result<CurrentRequest<'a>, SelectedPolicyRefusal> {
        use SelectedPolicyRefusal::{InvalidBinding, StalePolicyTarget};
        if !current
            .selected_policy
            .as_ref()
            .is_some_and(|policy| std::ptr::eq(self, policy.as_ref()))
            || !Arc::ptr_eq(&self.cost, &current.cost)
        {
            return Err(InvalidBinding);
        }
        let governance = current.governance.as_ref().ok_or(InvalidBinding)?;
        if !receipt.is_live()
            || !receipt.matches_governance(governance)
            || !valid_selected_identifier(&receipt.key().id)
            || !valid_selected_identifier(receipt.context().instance())
            || !origin.accepts(receipt.context(), origin.route())
        {
            return Err(InvalidBinding);
        }
        let mut seats = current
            .port_seats
            .iter()
            .filter(|seat| seat.instance == receipt.context().instance());
        let seat = seats.next().ok_or(StalePolicyTarget)?;
        if seats.next().is_some() || !origin.matches_current(seat) {
            return Err(StalePolicyTarget);
        }
        // Installed only by one-shot original signed request registration. Unsupported native
        // provider current authority never falls back to a key lookup or signed generation.
        let key = receipt
            .signed_authority()
            .ok_or(InvalidBinding)?
            .current_key(governance, now, seat.audience.as_deref())
            .map_err(SelectedPolicyRefusal::from)?;
        if key.id != receipt.key().id {
            return Err(InvalidBinding);
        }
        Ok(CurrentRequest { key, seat })
    }

    fn bind_rows(
        &self,
        key: &busbar_contract::records::VirtualKey,
        instance: &str,
        resource: Option<&str>,
    ) -> Result<ResolvedSelectedRules, SelectedPolicyRefusal> {
        Ok(ResolvedSelectedRules {
            key_id: key.id.clone().into_boxed_str(),
            instance: instance.into(),
            resource: resource.map(Box::from),
            rows: self.applicable_rows(key, instance, resource)?,
            policy_revision: self.revision,
            activated_minute: self.activated_minute,
        })
    }

    /// Pure row projection after the resolver has checked actual current authority. This
    /// cannot construct a bound result or reserve anything on its own.
    fn applicable_rows(
        &self,
        key: &busbar_contract::records::VirtualKey,
        instance: &str,
        resource: Option<&str>,
    ) -> Result<Box<[ResolvedSelectedRule]>, SelectedPolicyRefusal> {
        use busbar_contract::caps::ReasonCode;
        use SelectedPolicyRefusal::{CurrentGroup, InvalidBinding};
        let chain = self
            .cost
            .chain_for(key)
            .map_err(|_| CurrentGroup(ReasonCode::ScopeDenied))?;
        let mut rows = Vec::new();
        for &index in chain.group_indices() {
            let group = self.cost.groups().get(index).ok_or(InvalidBinding)?;
            if !group.enabled {
                return Err(CurrentGroup(ReasonCode::GroupFrozen));
            }
            let rules = self.groups.get(&group.name).ok_or(InvalidBinding)?;
            for rule in rules.iter().filter(|rule| {
                rule.instance.as_ref() == instance && Some(rule.resource.as_ref()) == resource
            }) {
                if rows.len() == MAX_APPLICABLE {
                    return Err(InvalidBinding);
                }
                let metric = match rule.metric {
                    LimitMetric::Requests => RateMetric::Requests,
                    LimitMetric::Tokens => RateMetric::Tokens,
                    _ => return Err(InvalidBinding),
                };
                rows.push(ResolvedSelectedRule {
                    group_id: group.name.clone().into_boxed_str(),
                    rule_id: rule.id.clone(),
                    metric,
                    threshold: rule.threshold,
                    policy_revision: self.revision,
                    activated_minute: rule.activated_minute.unwrap_or(self.activated_minute),
                });
            }
        }
        Ok(rows.into_boxed_slice())
    }

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
                errors.push(
                    crate::cold::governance::selected_policy::selected_policy_group_mismatch(name),
                );
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
                errors.push(
                    crate::cold::governance::selected_policy::selected_policy_too_many_rules(name),
                );
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
                    errors.push(crate::cold::governance::selected_policy::selected_policy_child_too_many_rules(name));
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

fn check_current_target(
    seat: &crate::plane_driver::port::PortSeat,
    original: &crate::plane_driver::port_upstream::Candidate,
    original_definition: &crate::upstreams::UpstreamDef,
) -> Result<(), SelectedPolicyRefusal> {
    use SelectedPolicyRefusal::{InvalidBinding, StalePolicyTarget};
    if original
        .resource
        .as_deref()
        .is_some_and(|value| !valid_selected_identifier(value))
    {
        return Err(InvalidBinding);
    }
    let target = seat
        .upstream
        .as_ref()
        .and_then(|upstream| upstream.target(&original.pool, &original.qualified_member))
        .ok_or(StalePolicyTarget)?;
    if target.identity != original.identity
        || target.resource != original.resource
        || target.provider != original.provider
        || target.base_path != original.base_path
        || target.flags != original.flags
        || target.params != original.params
        || (matches!(original.identity, TargetIdentity::Registration)
            && target.registered_upstream.as_deref() != Some(original.upstream.as_ref()))
    {
        return Err(StalePolicyTarget);
    }
    let current_definition = target
        .definition
        .as_ref()
        .ok_or(StalePolicyTarget)?
        .as_arc();
    if original_definition.resource != original.resource
        || current_definition.resource != target.resource
        || !compatible_definition(original_definition, current_definition)
    {
        return Err(StalePolicyTarget);
    }
    Ok(())
}

/// Compare actual retained destination policy, not a plane projection or Arc identity.
/// The selected pair already fixes target identity; model allocation names may change when
/// unrelated routes are inserted. Registration names are checked separately by the resolver.
fn compatible_definition(
    original: &crate::upstreams::UpstreamDef,
    current: &crate::upstreams::UpstreamDef,
) -> bool {
    use crate::upstreams::{StdioCommand, UpstreamDef, UpstreamTls};
    let UpstreamDef {
        name: _,
        resource,
        allow_private,
        url,
        command,
        tls,
        auth,
    } = original;
    let UpstreamTls {
        pin_spki,
        client_identity,
        trust,
    } = tls;
    resource == &current.resource
        && allow_private == &current.allow_private
        && url == &current.url
        && auth == &current.auth
        && pin_spki == &current.tls.pin_spki
        && client_identity == &current.tls.client_identity
        && match (trust, &current.tls.trust) {
            (None, None) => true,
            (Some(a), Some(b)) => a.sha256 == b.sha256 && a.der == b.der,
            _ => false,
        }
        && match (command, &current.command) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                let StdioCommand {
                    argv,
                    env,
                    cwd,
                    pin,
                    idle_s,
                } = a;
                argv == &b.argv
                    && env == &b.env
                    && cwd == &b.cwd
                    && pin == &b.pin
                    && idle_s == &b.idle_s
            }
            _ => false,
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
        errors.push(crate::cold::governance::selected_policy::selected_policy_invalid_rule(group));
        return None;
    }
    match resources.get(&(selected.instance(), selected.resource())) {
        None => errors.push(
            crate::cold::governance::selected_policy::selected_policy_unavailable_target(
                group,
                selected.id(),
            ),
        ),
        Some(false) if limit.metric == LimitMetric::Tokens => errors.push(
            crate::cold::governance::selected_policy::selected_policy_token_accounting(
                group,
                selected.id(),
            ),
        ),
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
    pub(crate) fn matches_candidate(
        &self,
        cost: &Arc<CostModel>,
        previous: Option<&SelectedPolicy>,
    ) -> bool {
        Arc::ptr_eq(&self.cost, cost)
            && match (&self.previous, previous) {
                (None, None) => true,
                (Some(expected), Some(actual)) => Arc::ptr_eq(expected, &actual.identity),
                _ => false,
            }
    }

    /// Install only on the owned initial App before AppHandle exists. Reload replacement
    /// must use AppHandle's publication gate and the actual predecessor instead.
    pub fn install_initial(self, app: &mut App) -> Result<(), &'static str> {
        if app.selected_policy.is_some()
            || self.previous.is_some()
            || !Arc::ptr_eq(&self.cost, &app.cost)
        {
            return Err("initial selected policy does not belong to this unpublished App");
        }
        let governance = app
            .governance
            .as_ref()
            .ok_or("initial selected policy requires the application's shared governance")?;
        let minute = governance
            .selected_rates()
            .activation_minute()
            .map_err(|_| "initial selected policy activation clock is unavailable")?;
        app.selected_policy = Some(Arc::new(self.activate(None, 1, minute)?));
        Ok(())
    }

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
