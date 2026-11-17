// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Capture selected-rate configuration from the same admitted candidate that builds seats.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::config::groups::GroupCfg;
use busbar_kernel::config::RootCfg;
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::selected_policy::{
    PendingSelectedPolicy, SelectedPolicy, SelectedTargetConfig, SelectedTargetKind,
};
use busbar_kernel::plane_driver::port_egress::SeatPool;
use busbar_kernel::plane_driver::provider_catalog::ProviderCatalogs;
use busbar_kernel::upstreams::{ConfiguredUpstreams, Declared, Upstreams};
use busbar_plugin_abi::plane as p;
use busbar_plugin_abi::records::{Records, Reply, Writer};
use busbar_plugin_abi::types::KindCode;

use super::boot::images::FileImages;
use super::min3_boot::Configured;

struct CapturedTarget {
    instance: String,
    kind: SelectedTargetKind,
    pool: String,
    member: String,
    resource: Option<Box<str>>,
    attempt_accounting: bool,
}

/// Temporary candidate facts, consumed before publication. This is not a routing store or
/// request authority. Only the immutable compiled rules survive in the published App.
pub(crate) struct CapturedSelectedPolicy {
    groups: BTreeMap<String, GroupCfg>,
    targets: Vec<CapturedTarget>,
}

impl CapturedSelectedPolicy {
    pub(crate) fn compile(
        self,
        cost: Arc<CostModel>,
        previous: Option<&SelectedPolicy>,
    ) -> Result<PendingSelectedPolicy, Vec<String>> {
        let targets: Vec<_> = self
            .targets
            .iter()
            .map(|target| SelectedTargetConfig {
                instance: &target.instance,
                kind: target.kind,
                pool: &target.pool,
                member: &target.member,
                resource: target.resource.as_deref(),
                attempt_accounting: target.attempt_accounting,
            })
            .collect();
        SelectedPolicy::compile(&self.groups, cost, &targets, previous)
    }
}

pub(crate) fn capture(
    files: &FileImages,
    cfg: &RootCfg,
    instances: &[Configured],
    catalogs: &ProviderCatalogs,
    declarations: &BTreeMap<String, Declared>,
    registrations: &BTreeMap<String, SeatPool>,
) -> Result<CapturedSelectedPolicy, String> {
    let mut admitted = BTreeMap::new();
    for instance in instances.iter().filter(|one| one.kind == KindCode::Plane) {
        let described = files
            .images
            .described(&instance.identity)
            .filter(|one| one.kind == KindCode::Plane)
            .ok_or("selected policy plane has no admitted image description")?;
        let supported = supports_tokens(&described)?;
        if admitted
            .insert(
                instance.name.as_str(),
                (instance.identity.as_str(), supported),
            )
            .is_some()
        {
            return Err("selected policy candidate repeats a plane instance".into());
        }
    }
    let mut targets = Vec::new();
    for (instance, pool) in registrations {
        let (_, supported) = admitted
            .get(instance.as_str())
            .ok_or("selected policy registration has no admitted plane")?;
        let declaration = declarations
            .get(instance)
            .ok_or("selected policy registration lost its declared definitions")?;
        targets.extend(registration_targets(
            instance,
            pool,
            &declaration.definitions,
            *supported,
        )?);
    }
    for (instance, plan) in catalogs {
        let (identity, supported) = admitted
            .get(instance.as_str())
            .ok_or("selected policy catalog has no admitted plane")?;
        if plan.instance != *instance || plan.image != *identity {
            return Err("selected policy catalog differs from its actual candidate image".into());
        }
        for ((pool, member), target) in plan.targets() {
            targets.push(CapturedTarget {
                instance: instance.clone(),
                kind: SelectedTargetKind::Model,
                pool: pool.clone(),
                member: member.clone(),
                resource: target.resource.clone(),
                attempt_accounting: *supported,
            });
        }
    }
    Ok(CapturedSelectedPolicy {
        groups: cfg.groups.clone(),
        targets,
    })
}

fn registration_targets(
    instance: &str,
    pool: &SeatPool,
    definitions: &ConfiguredUpstreams,
    attempt_accounting: bool,
) -> Result<Vec<CapturedTarget>, String> {
    if pool.pool != instance {
        return Err("selected policy registration pool belongs to another instance".into());
    }
    pool.probe_members()
        .into_iter()
        .map(|member| {
            let definition = definitions
                .get(member.name())
                .ok_or("selected policy walk member has no actual registration definition")?;
            Ok(CapturedTarget {
                instance: instance.into(),
                kind: SelectedTargetKind::Registration,
                pool: member.pool,
                member: member.qualified_member,
                resource: definition.resource.clone(),
                attempt_accounting,
            })
        })
        .collect()
}

/// Reuse the loader's exact declaration decoder over retained admitted describe records.
/// A fact bit without physical token classes is not a selected token-accounting capability.
fn supports_tokens(described: &busbar_plugin_loader::instance::Described) -> Result<bool, String> {
    let mut frame = Reply::new();
    for (tag, body) in &described.items {
        frame
            .put(*tag, body)
            .map_err(|_| "selected policy image description exceeds its record bound")?;
    }
    let plane = busbar_plugin_loader::adapters::plane::decode_describe(
        Records::new(frame.as_bytes()),
        described.methods,
        described.facts,
    )
    .map_err(|error| format!("selected policy image description: {}", error.0))?;
    Ok(described.facts & p::FB_ATTEMPT_USAGE != 0
        && plane
            .usage_classes
            .iter()
            .any(|class| class.unit == p::UNIT_TOKENS))
}

#[cfg(test)]
#[path = "tests/min3_selected_policy.rs"]
mod tests;
