// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane section's usage-observation policies, parsed once per generation.

use std::collections::BTreeMap;

use busbar_contract::kept::Text;
use busbar_contract::section::{usage_observation_policies, USAGE_OBSERVATIONS_KEY};
use busbar_contract::yaml::ValueExt as _;
use busbar_kernel::plane_driver::ObservationPolicy;

use crate::root::door_steps::{DoorFacts, DoorPools};

pub(crate) fn parse(
    instance: &str,
    section: &busbar_contract::yaml::Value,
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
            let refusal = format!(
                "{instance}.{USAGE_OBSERVATIONS_KEY}.{member}: invalid bounded accounting policy"
            );
            return Err(refusal);
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
        // The policy's names are made shared once here, as the generation is parsed: a scope's
        // binding shares them afterwards.
        let shared = |name: &str| Text::from(std::sync::Arc::<str>::from(name));
        let serving_subject = shared(&crate::root::door_steps::plane_lane(
            facts.plane.lane_prefix(),
            &member,
        ));
        let rated_subjects = policy
            .rated_subjects
            .iter()
            .map(|lane| {
                shared(&crate::root::door_steps::plane_lane(
                    facts.plane.lane_prefix(),
                    lane,
                ))
            })
            .collect();
        policies.insert(
            member.clone(),
            ObservationPolicy {
                instance: shared(instance),
                destination: shared(&member),
                serving_subject,
                accounting_namespace: shared(&policy.accounting_namespace),
                classes,
                rated_subjects,
                reserve_nanos: u128::from(policy.reserve_nanos),
                ordered_revisions: policy.ordered_revisions,
            },
        );
    }
    Ok(policies)
}
