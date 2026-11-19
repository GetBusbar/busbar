// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native listener topology from configured binds and actual D_LISTENER_SLOT suppliers.
//! This does not convert native ports into legacy framing claims or bind a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::route::AuthPoints;
use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_kernel::state::App;

use super::boot::ListenerNeeds;
use super::loader::boot::{BindOwner, InboundBind};
use super::min3_boot::transports::ServedTransport;
use super::min3_framers::NativeFramers;
use super::min3_physical::{assemble_admin_slot, assemble_slot, NativeSlots, SlotOwners};
use super::serve::{ChainAuth, Served};

pub(crate) struct NativeListenerPlan {
    needs: ListenerNeeds,
    suppliers: BTreeMap<String, ServedTransport>,
    /// The admitted instance declaring D_PROTOCOL `websocket` (§12.27's upgrade target), if any.
    websocket: Option<ServedTransport>,
}

/// The protocol a ROUTE_UPGRADE route is handed to (§12.27).
const UPGRADE_PROTOCOL: &str = "websocket";

impl std::fmt::Debug for NativeListenerPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeListenerPlan")
            .field("binds", &self.needs.binds.len())
            .field("slots", &self.suppliers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl NativeListenerPlan {
    pub(crate) fn new(needs: ListenerNeeds, framers: &NativeFramers) -> Result<Self, String> {
        if !needs.needs.is_empty() {
            return Err("native inbound Need routes have no complete physical producer".into());
        }
        if needs.root_required && !needs.binds.iter().any(|bind| bind.at == "listen") {
            return Err("required native root data bind is absent".into());
        }
        let mut suppliers = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        for bind in &needs.binds {
            if bind.owner != BindOwner::Root
                || !matches!(bind.at.as_str(), "listen" | "admin_listen")
            {
                return Err(format!("{}: native listener class is unsupported", bind.at));
            }
            if !addresses.insert(bind.listen) {
                return Err("native listener binds share the same socket address".into());
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                suppliers.entry(bind.at.clone())
            {
                entry.insert(framers.for_slot(&bind.at)?);
            }
        }
        Ok(Self {
            needs,
            suppliers,
            websocket: framers.for_protocol(UPGRADE_PROTOCOL),
        })
    }

    pub(crate) fn binds(&self) -> &[InboundBind] {
        &self.needs.binds
    }

    pub(crate) fn supplier(&self, slot: &str) -> Option<&ServedTransport> {
        self.suppliers.get(slot)
    }

    /// All slots must finish before the caller installs any map on the candidate App.
    pub(crate) fn assemble(
        &self,
        app: &App,
        served: &Served,
        owners: &SlotOwners,
    ) -> Result<NativeSlots, String> {
        // §12.27: every upgrade route is mounted (auth on the head, then 400/501 before any 101).
        // Handing one over needs the adopter the websocket transport brings (E9b); until it is
        // linked, a candidate whose upgrade route could reach an admitted websocket instance is
        // refused rather than served as if it upgraded.
        upgrades_honoured(
            served
                .ports
                .iter()
                .any(|seat| !seat.driver.routes().upgrade.is_empty()),
            self.websocket.as_ref(),
        )?;
        let mut slots = BTreeMap::new();
        for (name, supplier) in &self.suppliers {
            let slot = if name == "admin_listen" {
                assemble_admin_slot(app, name, supplier.port.clone())?
            } else {
                if app
                    .plugin_routes
                    .descriptors()
                    .iter()
                    .any(|route| route.auth != RouteAuth::Admin)
                {
                    return Err(
                        "native plugin Need routes have no complete physical producer".into(),
                    );
                }
                let core = core_lines(app, served);
                if owners.core.as_ref() != core.as_slice() {
                    return Err(
                        "native listener core policy differs from the actual candidate mounts"
                            .into(),
                    );
                }
                if served
                    .ports
                    .iter()
                    .flat_map(|seat| served_routes(seat))
                    .any(|route| route.cred_header.is_some())
                {
                    return Err("native route credential-header chain selection is not retained by this candidate".into());
                }
                if let Some(native) = &served.native {
                    if !Arc::ptr_eq(&native.auth, &owners.auth)
                        || !Arc::ptr_eq(&native.inventories, &owners.inventories)
                    {
                        return Err(
                            "native listener owners belong to another serving candidate".into()
                        );
                    }
                } else if !served.ports.is_empty() {
                    return Err("native served ports have no retained boot owners".into());
                }
                let chain = configured_chain(app, owners)?;
                let mounts = super::serve::data_mounts(served.clone(), &chain, &core)?;
                let guests = mounts.data.guests.clone();
                // The projection must not omit a declared route merely because its verbs
                // are unsupported by the actual HTTP mount. Assembly will check full masks.
                for seat in &served.ports {
                    for route in served_routes(seat) {
                        if !guests.lines().iter().any(|line| {
                            matches!(&line.claimant, busbar_kernel::guest::Claimant::Plane(instance) if instance == &seat.instance)
                                && line.route.rung == route.route
                                && line.route.methods == route.methods
                        }) {
                            return Err("native listener does not cover a complete declared plane route".into());
                        }
                    }
                }
                assemble_slot(
                    app,
                    name,
                    supplier.port.clone(),
                    guests,
                    mounts,
                    owners,
                    self.websocket.clone(),
                )?
            };
            slots.insert(name.clone(), slot);
        }
        if served
            .ports
            .iter()
            .any(|seat| served_routes(seat).next().is_some())
            && !self.suppliers.contains_key("listen")
        {
            return Err("native served data routes have no configured data listener".into());
        }
        Ok(slots)
    }
}

/// Upgrade routes are served only where every answer they can give is honest: with no admitted
/// websocket instance each authorized upgrade request is answered 501; with one, it would have to
/// be handed over, and no hand-over adopter is linked yet.
fn upgrades_honoured(upgrades: bool, websocket: Option<&ServedTransport>) -> Result<(), String> {
    match (upgrades, websocket) {
        (true, Some(websocket)) => Err(format!(
            "native plane upgrade hand-over to websocket transport `{}` is not linked",
            websocket.instance
        )),
        _ => Ok(()),
    }
}

/// The routes a seat serves on the data listener: its data routes and its upgrade routes.
fn served_routes(
    seat: &busbar_kernel::plane_driver::port::PortSeat,
) -> impl Iterator<Item = &busbar_kernel::plane_driver::port_routes::Mounted> {
    let routes = seat.driver.routes();
    routes.data.iter().chain(&routes.upgrade)
}

/// The same actual root handlers and provisioning mounts used by PreparedListener.
pub(crate) fn core_lines(app: &App, served: &Served) -> Vec<(String, RouteMethod, RouteAuth)> {
    let mut core = busbar_kernel::base_data_core_lines(app);
    if let Some(native) = &served.native {
        core.extend(super::provisioning::route_lines(&native.provisioning));
    }
    core
}

fn configured_chain(app: &App, owners: &SlotOwners) -> Result<Vec<ChainAuth>, String> {
    let config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .ok_or("native listener has no actual root configuration projection")?;
    config
        .data_chain
        .iter()
        .map(|name| {
            let instance = owners
                .auth
                .get(name)
                .ok_or_else(|| format!("{name}: data chain has no actual opened native auth"))?;
            if instance.opened.methods
                & (busbar_plugin_abi::auth::M_VERIFY | busbar_plugin_abi::auth::M_VERIFY_IO)
                == 0
            {
                return Err(format!("{name}: native data auth cannot verify"));
            }
            let points =
                if instance.opened.port.facts() & busbar_plugin_abi::auth::FB_NEEDS_BODY != 0 {
                    AuthPoints::HEAD_BODY
                } else {
                    AuthPoints::HEAD
                };
            Ok((name.clone(), points))
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/min3_listener_plan.rs"]
mod tests;
