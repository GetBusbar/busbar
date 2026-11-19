// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth step of a native ROUTE_UPGRADE request (§12.27 step 2, "core runs the route's auth
//! class on the head exactly as for any request"). It runs the same steps a DATA request runs
//! before money: the bound-carrier scan, chain verification, identity freshness, the governed key
//! under the live generation and the replay claim. An upgrade route selects no resources, opens no
//! unit and charges nothing here; what follows is either core's refusal before any 101
//! ([`crate::inbound::native::CompletingPhysicalRequest::refuse_upgrade`]) or the hand-over
//! ([`crate::inbound::native::CompletingPhysicalRequest::complete_upgrade`]).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use busbar_contract::records::VirtualKey;
use busbar_contract::route::METHOD_GET;
use busbar_contract::services::Caller;
use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, ROUTE_UPGRADE};
use busbar_ports::CallCx;

use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use super::native_data::{refuse_bound_carriers, withheld_carriers, DataRefused};
use crate::inbound::native::{
    DataPreparation, DataPreparationDenied, DataPreparationSuccess, RequestBinding, RouteBinding,
    RouteTarget,
};
use crate::plane_driver::port::PortSeat;
use crate::plane_driver::port_routes::Mounted;
use crate::state::{AdmissionLease, App};

/// One canonical upgrade route token and its candidate's actual data chain. No App Arc cycle.
pub struct NativeUpgradeRoute {
    binding: Arc<RouteBinding>,
    caller: Caller,
    chain: Arc<NativeChain>,
    /// The carriers every request on this route withholds from the plane.
    withheld: Arc<[Box<str>]>,
    /// The audience the route's plane is bound to: a bearer that states one must state this.
    audience: Option<Arc<str>>,
}

impl NativeUpgradeRoute {
    /// Only what the native path can honour: the plane's own declared ROUTE_UPGRADE route,
    /// methods exactly GET (§8.6), auth exactly AUTH_PRINCIPAL, and the route's effective chain
    /// (§12.11: the instances reading its D_ROUTE_CRED_HEADER when it declares one, else the data
    /// chain), which root resolved into the route token's auth instances.
    /// Whether this path can admit the upgrade route `mounted` on `seat` at all, before any owner
    /// exists: the route-shape half of [`Self::bind`]. Err names what it lacks. A route this path
    /// cannot admit is never served unadmitted: the listener leaves it unmounted.
    pub fn admits(_app: &App, _seat: &PortSeat, mounted: &Mounted) -> Result<(), &'static str> {
        if mounted.flags != ROUTE_UPGRADE || mounted.methods != METHOD_GET || mounted.catalog {
            return Err("the native upgrade path admits a GET upgrade route only");
        }
        if mounted.auth != AUTH_PRINCIPAL || mounted.effective != AUTH_PRINCIPAL {
            return Err("the native upgrade path admits principal routes only");
        }
        Ok(())
    }

    pub fn bind(
        app: &App,
        seat: &PortSeat,
        binding: Arc<RouteBinding>,
        chain: Arc<NativeChain>,
    ) -> Result<Arc<Self>, DataRefused> {
        let RouteTarget::Plane(target) = binding.target() else {
            return Err(DataRefused::Unsupported);
        };
        let mounted = target.mounted();
        if Self::admits(app, seat, mounted).is_err() || !chain.is_data() {
            return Err(DataRefused::Unsupported);
        }
        if !seat.driver.caller().same_incarnation(target.caller())
            || !seat
                .driver
                .routes()
                .upgrade
                .iter()
                .any(|route| route == mounted)
            || !chain.matches_names(target.auth_instances())
        {
            return Err(DataRefused::Binding);
        }
        let withheld = withheld_carriers(&chain, mounted.cred_header.as_deref());
        Ok(Arc::new(Self {
            caller: target.caller().clone(),
            binding,
            chain,
            withheld,
            audience: seat.audience.as_deref().map(Arc::from),
        }))
    }

    /// The route token this completion was bound to.
    pub fn binding(&self) -> &Arc<RouteBinding> {
        &self.binding
    }

    /// The carriers every request on this route withholds from the plane (a refusal render
    /// included, and the hand-over's `request`).
    pub fn withheld(&self) -> &Arc<[Box<str>]> {
        &self.withheld
    }

    fn cred_header(&self) -> Option<&str> {
        match self.binding.target() {
            RouteTarget::Plane(target) => target.mounted().cred_header.as_deref(),
            _ => None,
        }
    }

    /// Consumes the original physical preparation latch before verification. A credential,
    /// policy or replay refusal is a denial ([`UpgradeRefused::Denied`]): the physical request is
    /// spent and nothing can authorize it later; any other failure cancels it.
    pub async fn authorize(
        self: &Arc<Self>,
        preparation: DataPreparation,
        cx: CallCx,
    ) -> Result<UpgradeAuthorization, UpgradeRefused> {
        let binding = preparation.binding().clone();
        let result = self.verify(&binding, cx).await;
        let (prepared, lease, key) = match result {
            Ok(parts) => parts,
            Err(reason) if reason.refusal(false).is_some() => {
                return Err(match preparation.deny() {
                    Ok(denied) => UpgradeRefused::Denied {
                        preparation: denied,
                        reason,
                    },
                    Err(_) => UpgradeRefused::Failed(DataRefused::Cancelled),
                })
            }
            Err(reason) => return Err(UpgradeRefused::Failed(reason)),
        };
        let preparation = preparation
            .authorize()
            .map_err(|_| UpgradeRefused::Failed(DataRefused::Cancelled))?;
        Ok(UpgradeAuthorization {
            preparation,
            binding,
            route: self.clone(),
            prepared,
            _lease: lease,
            key,
            deadline: cx.deadline,
        })
    }

    async fn verify(
        &self,
        binding: &Arc<RequestBinding>,
        cx: CallCx,
    ) -> Result<(Arc<PreparedNativeIdentity>, AdmissionLease, Arc<VirtualKey>), DataRefused> {
        // One reading for this step's two deadlines: the binding's own and the call's.
        let live_at = binding
            .check_live_now()
            .map_err(|_| DataRefused::Cancelled)?;
        if !Arc::ptr_eq(binding.route(), &self.binding)
            || cx.request_id != binding.invocation().request_id().get()
            || binding.deadline().is_some_and(|at| cx.deadline > at)
            || live_at >= cx.deadline
        {
            return Err(DataRefused::Binding);
        }
        let snapshot = binding.snapshot().map_err(|_| DataRefused::Capacity)?;
        if !snapshot.request().same_request(binding.request()) {
            return Err(DataRefused::Binding);
        }
        refuse_bound_carriers(&snapshot, &self.chain, self.cred_header())?;
        if let Some(audience) = self.audience.as_deref() {
            super::native_data::refuse_foreign_audience(&snapshot, &self.chain, audience)?;
        }
        let prepared = self
            .chain
            .prepare_snapshot(cx, snapshot)
            .await
            .map_err(|_| DataRefused::Unavailable)?;
        binding.check_live().map_err(|_| DataRefused::Cancelled)?;
        let NativePreparedAnswer::Identity(prepared) = prepared else {
            return Err(DataRefused::Credential);
        };
        let mut key = None;
        let lease = binding
            .handle()
            .admit_current(binding.app(), binding.invocation(), |app| {
                let now = crate::store::now();
                prepared.fresh(now).map_err(|_| DataRefused::Policy)?;
                if !prepared.belongs_to(&self.chain)
                    || app.config_generation.load(Ordering::Acquire) != self.chain.epoch()
                {
                    return Err(DataRefused::Binding);
                }
                key = Some(super::native_data::governed_key(
                    app,
                    &prepared,
                    &self.chain,
                    now,
                )?);
                Ok(())
            })
            .map_err(|_| DataRefused::Policy)?;
        match prepared.claim_classified().await {
            super::native_admin::NativeReplayClaim::Claimed => {}
            super::native_admin::NativeReplayClaim::Duplicate => return Err(DataRefused::Replay),
            super::native_admin::NativeReplayClaim::Unknown(_) => {
                return Err(DataRefused::Unavailable)
            }
            super::native_admin::NativeReplayClaim::Inconsistent => {
                return Err(DataRefused::Binding)
            }
        }
        // The replay claim above may have waited: this step's one reading for both deadlines.
        let live_at = binding
            .check_live_now()
            .map_err(|_| DataRefused::Cancelled)?;
        if live_at >= cx.deadline {
            return Err(DataRefused::Cancelled);
        }
        Ok((prepared, lease, key.ok_or(DataRefused::Policy)?))
    }
}

/// Why an upgrade request was not authorized.
pub enum UpgradeRefused {
    /// Credential, policy or replay: the original preparation was spent as denied.
    Denied {
        preparation: DataPreparationDenied,
        reason: DataRefused,
    },
    /// Anything else (cancelled, deadline, binding, unavailable verifier): the request is cancelled.
    Failed(DataRefused),
}
impl UpgradeRefused {
    pub fn reason(&self) -> DataRefused {
        match self {
            Self::Denied { reason, .. } => *reason,
            Self::Failed(reason) => *reason,
        }
    }
}
impl std::fmt::Debug for UpgradeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpgradeRefused")
            .field("reason", &self.reason())
            .finish()
    }
}

/// Privately minted after the chain, the governed key and the replay claim. It is the only input
/// that lets core answer an upgrade request ([`crate::inbound::native::CompletingPhysicalRequest::
/// refuse_upgrade`]) or hand it over ([`crate::inbound::native::CompletingPhysicalRequest::
/// complete_upgrade`]).
pub struct UpgradeAuthorization {
    preparation: DataPreparationSuccess,
    binding: Arc<RequestBinding>,
    route: Arc<NativeUpgradeRoute>,
    prepared: Arc<PreparedNativeIdentity>,
    _lease: AdmissionLease,
    key: Arc<VirtualKey>,
    deadline: Instant,
}
impl std::fmt::Debug for UpgradeAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpgradeAuthorization")
            .finish_non_exhaustive()
    }
}
impl UpgradeAuthorization {
    pub(crate) fn preparation(&self) -> &DataPreparationSuccess {
        &self.preparation
    }
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn route(&self) -> &Arc<NativeUpgradeRoute> {
        &self.route
    }
    /// The plane instance the route belongs to.
    pub fn caller(&self) -> &Caller {
        &self.route.caller
    }
    /// The verified identity the plane's `request` is handed (§12.27 step 2).
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.prepared.identity()
    }
    /// The charged request snapshot the identity was verified on: the head the plane is handed.
    pub fn snapshot(&self) -> &Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot> {
        self.prepared.snapshot()
    }
    /// The carriers the route's chain judged: withheld from the plane.
    pub fn withheld(&self) -> &Arc<[Box<str>]> {
        self.route.withheld()
    }
    /// The governed key the identity resolved to.
    pub fn principal(&self) -> &Arc<VirtualKey> {
        &self.key
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[cfg(test)]
#[path = "tests/native_upgrade_tests.rs"]
mod tests;
