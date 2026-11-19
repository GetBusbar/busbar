// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Materialize the candidate's provider destinations without choosing a request route.
//!
//! Root supplies allocations from the same namespace as its actual registrations. This helper
//! never allocates IDs, infers a registered name from a provider/model string, opens credentials,
//! installs a table, or supplies a default pool. The model table is deliberately separate from
//! CHANNEL's registration table. Root retains both it and the exact target association with the
//! candidate image lease, and publishes only after connector/money/hook preparation succeeds.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::conn::codes::KEEP_ALL_EXCEPT_DENIED;
use busbar_contract::conn::NeedId;
use busbar_contract::dest::DestinationId;
use busbar_contract::json;
use busbar_contract::transport::trust::Anchors;
use busbar_kernel::auth_bindings::native::SelectedRouteKey;
use busbar_kernel::auth_bindings::ProviderBindings;
use busbar_kernel::config::{min3::UpstreamCfg, RootCfg};
use busbar_kernel::plane_driver::port_egress::{
    MemberTarget, SeatMember, SeatPool, TargetDefinition, Targets,
};
use busbar_kernel::plane_driver::port_upstream::TargetIdentity;
use busbar_kernel::plane_driver::provider_catalog::{CatalogPlan, ProviderAuthSelection};
use busbar_kernel::plane_driver::{MemberRoute, ResponseKeep};
use busbar_kernel::upstreams::{ConfiguredUpstreams, UpstreamAuth, UpstreamDef};
use busbar_plugin_abi::auth::{STYLE_CALLER, STYLE_PER_REQUEST, STYLE_SCOPE};
use serde::Serialize;
use tokio::sync::Semaphore;

use super::min3_outbound_auth::{AdmittedStyle, Prepared, SelectedRow, Selection};

/// The root allocator's exact association; all three identities are mandatory.
#[derive(Clone)]
pub(crate) struct Allocation {
    pub(crate) destination: DestinationId,
    pub(crate) need: NeedId,
    pub(crate) upstream: Box<str>,
}

/// Key is (actual walk pool, fully qualified logical member), never wire model/request alias.
pub(crate) type Allocations = BTreeMap<(String, String), Allocation>;

/// The same association feeds resource inventory, actual egress and selected probes.
#[derive(Clone)]
pub(crate) struct Association {
    pub(crate) destination: DestinationId,
    pub(crate) attempt_timeout_ms: Option<u64>,
    pub(crate) context_max: Option<usize>,
    pub(crate) credential_mode: busbar_contract::config::UpstreamCreds,
}

struct StagedRow {
    key: SelectedRouteKey,
    allocation: Allocation,
    definition: Arc<UpstreamDef>,
    target: MemberTarget,
    provider: String,
    connection_required: bool,
    attempt_timeout_ms: Option<u64>,
    context_max: Option<usize>,
    credential_mode: busbar_contract::config::UpstreamCreds,
}

/// Private preparation facts. They cannot be used as a runnable target table before auth seal.
pub(crate) struct StagedCatalog {
    instance: String,
    rows: BTreeMap<(String, String), StagedRow>,
    auth_rows: Vec<SelectedRow>,
    capacity: BTreeMap<DestinationId, Arc<Semaphore>>,
}

/// Fully associated routes, still unpublished. Root supplies the exact configured pool policies,
/// actual price/admission receipts, connector declarations and image lease before activation.
pub(crate) struct SealedCatalog {
    pub(crate) instance: String,
    pub(crate) associations: BTreeMap<(String, String), Association>,
    pub(crate) targets: Targets,
    pub(crate) routes: BTreeMap<DestinationId, MemberRoute>,
    pub(crate) members: Vec<SeatMember>,
    /// One semaphore per logical model, shared by that model's destinations across its pools.
    pub(crate) capacity: BTreeMap<DestinationId, Arc<Semaphore>>,
}

impl StagedCatalog {
    /// Gather every plane's rows and call min3_outbound_auth::prepare once for the generation.
    pub(crate) fn take_auth_rows(&mut self) -> Vec<SelectedRow> {
        std::mem::take(&mut self.auth_rows)
    }

    /// An exact auth association is required even for an explicitly keyless provider. A table
    /// missing this pool/member/destination fails before any connector declaration or publication.
    pub(crate) fn seal(self, auth: &Prepared) -> Result<SealedCatalog, String> {
        let mut routes = BTreeMap::new();
        let mut members = Vec::new();
        let mut associations = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for (pair, row) in self.rows {
            let binding = auth.for_route(&row.key, row.allocation.destination)?;
            let url = row
                .definition
                .url
                .as_ref()
                .ok_or("catalog definition has no destination")?;
            routes.insert(
                row.allocation.destination,
                MemberRoute {
                    connection_required: row.connection_required,
                    need: row.allocation.need,
                    base_url: url.to_string(),
                    auth: Some(binding),
                    provider: busbar_contract::kept::Text::from(Arc::<str>::from(row.provider)),
                    keep: ResponseKeep {
                        mode: KEEP_ALL_EXCEPT_DENIED,
                        kept: Vec::new(),
                        denied: Vec::new(),
                    },
                    rides: Vec::new(),
                    // Canonical configured-provider reach is anchored to this route's exact URL.
                    // It does not change metadata, own-listener, TLS, redirects or OPEN_WEB policy.
                    anchors: Anchors {
                        private_reach: row.definition.allow_private,
                        ..Anchors::default()
                    },
                    ride_anchors: Vec::new(),
                    spelled: Vec::new(),
                },
            );
            members.push(SeatMember {
                destination: row.allocation.destination,
                upstream: row.definition.name.clone(),
                need: row.allocation.need,
                url: url.clone(),
            });
            associations.insert(
                pair.clone(),
                Association {
                    destination: row.allocation.destination,
                    attempt_timeout_ms: row.attempt_timeout_ms,
                    context_max: row.context_max,
                    credential_mode: row.credential_mode,
                },
            );
            // Retain the definition in the closure too: replacing a generation's registry
            // cannot alter the actual entry from which this target was constructed.
            targets.insert(pair, (row.definition, row.target));
        }
        let targets: Targets = Arc::new(move |pool, member| {
            targets
                .get(&(pool.to_owned(), member.to_owned()))
                .map(|(_, target)| target.clone())
        });
        Ok(SealedCatalog {
            instance: self.instance,
            associations,
            targets,
            routes,
            members,
            capacity: self.capacity,
        })
    }
}

/// Build actual configured model entries once for this candidate. `registered` and its table
/// are the root's already allocated registration domain, not an operator-supplied list of IDs.
/// Provider auth selections were resolved from this same candidate's admitted image descriptions.
/// No selected request authority is created by this operation.
pub(crate) fn prepare(
    config: &RootCfg,
    plan: &CatalogPlan,
    allocations: &Allocations,
    registered: &SeatPool,
    registered_definitions: &ConfiguredUpstreams,
    bindings: &ProviderBindings,
    styles: &BTreeMap<Box<str>, AdmittedStyle>,
) -> Result<StagedCatalog, String> {
    if registered.pool != plan.instance {
        return Err("catalog registration reservation belongs to another plane".into());
    }
    if allocations
        .keys()
        .any(|key| !plan.targets().contains_key(key))
    {
        return Err("catalog has an unowned allocation".into());
    }
    if registered_definitions
        .names()
        .any(|name| plan.select(name).is_some())
    {
        return Err("registration and catalog have an ambiguous configured selector".into());
    }
    let mut destinations: BTreeSet<_> = registered.routes.keys().copied().collect();
    let mut needs: BTreeSet<_> = registered
        .members
        .iter()
        .map(|member| member.need)
        .collect();
    let mut names: BTreeSet<Box<str>> = registered_definitions.names().map(Box::from).collect();
    let mut rows = BTreeMap::new();
    let mut auth_rows = Vec::new();
    let mut model_capacity = BTreeMap::<String, Arc<Semaphore>>::new();
    let mut capacity = BTreeMap::new();
    for (pair, target) in plan.targets() {
        let allocation = allocations
            .get(pair)
            .ok_or("catalog route has a missing allocation")?;
        if !destinations.insert(allocation.destination) {
            return Err("catalog destination collision with another selected route".into());
        }
        if !needs.insert(allocation.need) {
            return Err("catalog need collision with another selected route".into());
        }
        if !names.insert(allocation.upstream.clone()) {
            return Err("catalog upstream name collision with another configured route".into());
        }
        let provider = config
            .providers
            .get(&target.provider)
            .ok_or("catalog provider is absent from its candidate")?;
        let key = SelectedRouteKey {
            plane: plan.instance.as_str().into(),
            pool: pair.0.as_str().into(),
            member: pair.1.as_str().into(),
        };
        let required = !provider.api_key.is_none()
            || !matches!(&target.auth_selection, ProviderAuthSelection::Implicit);
        let attempt = plan
            .attempt_key(&pair.0, &pair.1)
            .ok_or("catalog auth selection has no target")?;
        let (selection, upstream_auth) = if required {
            let name = bindings
                .by_attempt
                .get(&attempt)
                .ok_or("required provider binding is absent")?;
            let style = styles
                .get(name)
                .ok_or("required provider style is not admitted")?;
            (
                Selection::Required(attempt),
                Some(UpstreamAuth {
                    instance: name.clone(),
                    cache_max_s: None,
                    connect_callback: None,
                    caller: style.flags & STYLE_CALLER != 0,
                    scoped: style.flags & STYLE_SCOPE != 0,
                    per_request: style.flags & STYLE_PER_REQUEST != 0,
                }),
            )
        } else {
            if bindings.by_attempt.contains_key(&attempt) {
                return Err("keyless catalog route has an unexpected auth binding".into());
            }
            (Selection::None, None)
        };

        // Reuse the existing typed registration reader for URL/name validation. This is core's
        // materialization of an existing provider, not a new plane/operator configuration bag.
        #[derive(Serialize)]
        struct Connection<'a> {
            url: &'a str,
            allow_private: bool,
        }
        let entry = json::to_value(&Connection {
            url: &provider.base_url,
            allow_private: true,
        })
        .map_err(|_| "configured provider destination cannot be represented")?;
        let mut definition = UpstreamDef::from_config_at(
            &allocation.upstream,
            &format!("providers.{}", target.provider),
            &entry,
            &UpstreamCfg {
                resource: target.resource.clone(),
                ..UpstreamCfg::default()
            },
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .map_err(|why| {
            format!(
                "configured provider destination or allocated upstream name is invalid: {}",
                why.join("; ")
            )
        })?;
        definition.auth = upstream_auth;
        let definition = Arc::new(definition);
        let member_target = MemberTarget {
            definition: Some(TargetDefinition::new(Arc::clone(&definition))),
            resource: definition.resource.clone(),
            identity: TargetIdentity::Model {
                dialect: target.dialect.as_str().into(),
                model: target.wire_model.as_str().into(),
            },
            registered_upstream: Some(definition.name.clone()),
            provider: target.projection.as_ref().into(),
            base_path: target.base_path.as_str().into(),
            flags: 0,
            params: target.params.clone(),
        };
        if let Some(limit) = target.max_concurrent {
            if limit == 0 || limit > Semaphore::MAX_PERMITS {
                return Err(
                    "catalog concurrency limit is outside the runtime capacity range".into(),
                );
            }
            let slots = model_capacity
                .entry(target.model.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(limit)));
            capacity.insert(allocation.destination, Arc::clone(slots));
        }
        auth_rows.push(SelectedRow {
            key: key.clone(),
            destination: allocation.destination,
            upstream: definition.name.clone(),
            selection,
            mode: target.credential_mode,
            cache_max_s: None,
        });
        rows.insert(
            pair.clone(),
            StagedRow {
                key,
                allocation: allocation.clone(),
                definition,
                target: member_target,
                provider: target.provider.clone(),
                connection_required: target.credential_mode
                    == busbar_contract::config::UpstreamCreds::Connection,
                attempt_timeout_ms: target.attempt_timeout_ms,
                context_max: target.context_max,
                credential_mode: target.credential_mode,
            },
        );
    }
    Ok(StagedCatalog {
        instance: plan.instance.clone(),
        rows,
        auth_rows,
        capacity,
    })
}

#[cfg(test)]
#[path = "tests/provider_catalog_routes.rs"]
mod tests;
