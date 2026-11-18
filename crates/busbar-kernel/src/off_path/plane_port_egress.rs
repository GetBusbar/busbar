// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::port_egress`' off-path code: a plane instance's walked pool, composed once per seat
//! composition from its configured upstreams, its probe rows, and how a configured upstream reads as the
//! plane's `Target`. A session only walks what was composed here.

use std::sync::Arc;

use busbar_contract::conn::NeedId;
use busbar_kernel_egress::ports::DestinationId;

use crate::plane_driver::port_egress::{
    MemberTarget, ProbeTarget, SeatMember, SeatPool, TargetDefinition, Targets,
};
use crate::plane_driver::{MemberRoute, ResponseKeep};

impl SeatPool {
    /// The pool `instance` walks over `upstreams`.
    ///
    /// # Errors
    /// An upstream states a TLS check this path cannot enforce (more than one `pin_spki`, or a `client_identity`).
    pub fn of(
        instance: &str,
        upstreams: &crate::upstreams::ConfiguredUpstreams,
    ) -> Result<Self, String> {
        use crate::upstreams::Upstreams;
        use busbar_contract::abi::host::conn::connector::KEEP_ALL_EXCEPT_DENIED;
        let mut members = Vec::new();
        let mut walked = Vec::new();
        let mut routes = foldhash::HashMap::default();
        for name in upstreams.names() {
            let Some(def) = upstreams.get(name) else {
                continue;
            };
            let Some(url) = def.url.as_deref() else {
                continue;
            };
            if def.tls.client_identity.is_some() {
                return Err(format!(
                    "`upstreams.{name}.tls.client_identity` is set, and plane `{instance}` cannot present a client \
                     identity to an upstream yet: remove it or reach the upstream another way"
                ));
            }
            let key_pin = match def.tls.pin_spki.as_slice() {
                [] => None,
                [one] => Some(busbar_contract::abi::sdk::digest::tagged(one)),
                _ => {
                    return Err(format!(
                        "`upstreams.{name}.tls.pin_spki` names more than one key, and plane `{instance}` can hold \
                         an upstream to one pinned key only: keep the key the server presents now"
                    ));
                }
            };
            let index =
                u32::try_from(members.len()).map_err(|_| "too many upstreams".to_owned())?;
            let destination = DestinationId::new(u64::from(index));
            let lane = format!("{instance}{}{name}", crate::governance::PLANE_LANE_SEP);
            walked.push(busbar_kernel_egress::Member::new(destination, lane, 1));
            routes.insert(
                destination,
                MemberRoute {
                    connection_required: false,
                    need: NeedId(index),
                    base_url: url.to_owned(),
                    auth: None,
                    provider: busbar_contract::kept::Text::from(std::sync::Arc::<str>::from(name)),
                    keep: ResponseKeep {
                        mode: KEEP_ALL_EXCEPT_DENIED,
                        kept: Vec::new(),
                        denied: Vec::new(),
                    },
                    rides: Vec::new(),
                    anchors: busbar_contract::transport::trust::Anchors {
                        extra_anchors: def
                            .tls
                            .trust
                            .as_ref()
                            .map(|anchor| anchor.der.clone())
                            .unwrap_or_default(),
                        key_pin,
                        client_identity: None,
                        private_reach: def.allow_private,
                    },
                    ride_anchors: Vec::new(),
                    spelled: Vec::new(),
                },
            );
            members.push(SeatMember {
                destination,
                upstream: name.into(),
                need: NeedId(index),
                url: url.into(),
            });
        }
        // The pool is keyed by its own name: one shared text for both.
        let mut pools = foldhash::HashMap::default();
        let pool = busbar_kernel_egress::Pool::new(instance, walked);
        pools.insert(pool.name.clone(), pool);
        Ok(Self {
            pool: instance.to_owned(),
            pools,
            routes,
            members,
        })
    }

    /// The probe service's members: each walked member's destination and configured upstream name.
    #[must_use]
    pub fn probe_members(&self) -> Vec<ProbeTarget> {
        self.members
            .iter()
            .map(|member| ProbeTarget {
                destination: member.destination,
                pool: self.pool.clone(),
                qualified_member: format!(
                    "{}{}{}",
                    self.pool,
                    crate::governance::PLANE_LANE_SEP,
                    member.upstream
                ),
            })
            .collect()
    }
}

/// How a configured upstream reads as the plane's `Target` (§6.1): an upstream the instance's table names is a
/// bare target (no plane-owned provider keys, base path or parameters: an upstream carries none, IF §12.1); any
/// other name is not this instance's and the walk passes it over.
#[must_use]
pub fn upstream_targets(
    instance: &str,
    upstreams: Arc<dyn crate::upstreams::Upstreams>,
) -> Targets {
    let pool = instance.to_owned();
    let prefix = format!("{instance}{}", crate::governance::PLANE_LANE_SEP);
    Arc::new(move |selected_pool, member| {
        if selected_pool != pool {
            return None;
        }
        let name = member.strip_prefix(&prefix)?;
        let upstream = upstreams.get(name)?;
        let mut target = MemberTarget::bare();
        target.registered_upstream = Some(name.into());
        target.resource.clone_from(&upstream.resource);
        target.definition = Some(TargetDefinition::new(upstream));
        Some(target)
    })
}
