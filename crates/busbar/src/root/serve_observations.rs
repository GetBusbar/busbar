// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::section::{usage_observation_policies, USAGE_OBSERVATIONS_KEY};
use busbar_kernel::plane_driver::ObservationPolicy;

pub(super) fn parse(
    instance: &str,
    section: &serde_yaml::Value,
    facts: &DoorFacts,
    pools: &DoorPools,
) -> Result<BTreeMap<String, ObservationPolicy>, String> {
    let Some(value) = section.get(USAGE_OBSERVATIONS_KEY) else {
        return Ok(BTreeMap::new());
    };
    let configured = usage_observation_policies(value.clone())
        .map_err(|e| format!("{instance}.{USAGE_OBSERVATIONS_KEY}: {e}"))?;
    if configured.len() > 256 {
        return Err("too many observation upstream bindings".into());
    }
    let mut policies = BTreeMap::new();
    for (member, policy) in configured {
        if !pools.entries().contains(&member)
            || policy.accounting_namespace.is_empty()
            || policy.accounting_namespace.len() > 1024
            || policy.reserve_nanos == 0
            || policy.classes.is_empty()
            || policy.classes.len() > 64
            || policy.rated_subjects.len() > 15
        {
            return Err(format!(
                "{instance}.{USAGE_OBSERVATIONS_KEY}.{member}: invalid bounded accounting policy"
            ));
        }
        let mut classes = Vec::new();
        for name in policy.classes {
            let index = facts
                .classes
                .iter()
                .position(|class| class == &name)
                .ok_or_else(|| format!("{instance}: observation class '{name}' is undeclared"))?
                as u32;
            if facts.fee_units.contains(&index) {
                return Err("gateway fees cannot be observation classes".into());
            }
            if classes.contains(&index) {
                return Err("repeated observation class".into());
            }
            classes.push(index);
        }
        let serving_subject = crate::root::door_steps::plane_lane(&facts.plane, &member);
        let rated_subjects = policy
            .rated_subjects
            .iter()
            .map(|lane| crate::root::door_steps::plane_lane(&facts.plane, lane))
            .collect();
        policies.insert(
            member.clone(),
            ObservationPolicy {
                instance: instance.to_owned(),
                destination: member,
                serving_subject,
                accounting_namespace: policy.accounting_namespace,
                classes,
                rated_subjects,
                reserve_nanos: u128::from(policy.reserve_nanos),
                ordered_revisions: policy.ordered_revisions,
            },
        );
    }
    Ok(policies)
}

/// Carries only root-owned policy, selected after normal member authorization.
pub(super) struct UnitBinding<'a> {
    pub served: &'a ServedPlane,
    pub live: &'a DoorLive,
    pub unit: busbar_contract::UnitKey,
    pub selected_member: OnceLock<String>,
}
impl UnitBinding<'_> {
    pub fn selected(&self, member: &str) -> bool {
        if self.selected_member.get().is_some_and(|old| old != member) {
            return false;
        }
        let Some(policy) = self.live.observations.get(member) else {
            return true;
        };
        let Some(caller) = self.served.live.plugin.service_caller() else {
            return false;
        };
        let _ = self.selected_member.set(member.to_owned());
        self.served
            .kernel
            .register_observation_unit(
                &caller,
                self.unit,
                Arc::clone(&self.served.money),
                policy.clone(),
            )
            .is_ok()
    }
}
impl Drop for UnitBinding<'_> {
    fn drop(&mut self) {
        if let Some(caller) = self.served.live.plugin.service_caller() {
            self.served
                .kernel
                .unregister_observation_unit(&caller, self.unit);
        }
    }
}
