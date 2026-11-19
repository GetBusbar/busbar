// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native listener topology from configured binds and actual D_LISTENER_SLOT suppliers.
//! This does not convert native ports into legacy framing claims or bind a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::route::AuthPoints;
use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_kernel::auth::native_data::NativeDataRoute;
use busbar_kernel::auth::native_upgrade::NativeUpgradeRoute;
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
        if !served.planes.is_empty() {
            return Err("native listener plan cannot carry legacy served plane claims".into());
        }
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
                let route_chains = route_chains(app, served, owners)?;
                // The native listener completes a core route only as public or admin: a core route
                // that takes a data key has no producer here, so it is not mounted (one line) and is
                // answered as an unknown route is, never served unauthenticated.
                let served_core: Vec<_> = core
                    .iter()
                    .filter(|(path, method, auth)| {
                        let keyed = *auth == RouteAuth::Key;
                        if keyed {
                            tracing::warn!(
                                "core route '{} {path}' is not served: the native listener has no producer for a key-authenticated core route",
                                method.as_str()
                            );
                        }
                        !keyed
                    })
                    .cloned()
                    .collect();
                let mounts = super::serve::door_mounts_planned(
                    served.clone(),
                    || super::kernel::ROOT_CARD.pin(),
                    &chain,
                    &route_chains,
                    &served_core,
                    &[],
                    &[],
                )?;
                let guests = mounts.data.guests.clone();
                // The projection must not omit a declared route merely because its verbs
                // are unsupported by the actual HTTP mount. Assembly will check full masks.
                for seat in &served.ports {
                    for route in served_routes(seat) {
                        // A route that is not served is not mounted, by the ruling above.
                        let not_served = route_chains
                            .get(&seat.instance)
                            .and_then(|routes| routes.get(&route.route))
                            .is_some_and(Option::is_none);
                        if not_served {
                            continue;
                        }
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
    chain_points(owners, &config.data_chain)
}

/// One opened auth instance as the route rule reads it: its configured name and the D_CRED_HEADER
/// names its image declares.
pub(crate) struct Reader<'a> {
    pub(crate) name: &'a str,
    pub(crate) cred_headers: &'a [Box<str>],
}

impl Reader<'_> {
    fn reads(&self, header: &str) -> bool {
        self.cred_headers
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(header))
    }
}

/// The opened auth instances, in opening order, that a plane route's chain may be chosen from.
/// SECURITY: an instance opened only for the admin chain (named in `auth.admin_auth`, not in the
/// data chain, not named by any route's `auth_instances`) is never one: an operator credential is
/// never verified on a data or plane route.
pub(crate) fn route_readers<'a>(
    opened: impl IntoIterator<Item = (&'a str, &'a [Box<str>])>,
    data_chain: &[String],
    admin_chain: &[String],
    explicit: &busbar_kernel::config::min3::RouteAuthInstances,
) -> Vec<Reader<'a>> {
    let named = |name: &str, list: &[String]| list.iter().any(|entry| entry == name);
    opened
        .into_iter()
        .filter(|(name, _)| {
            !named(name, admin_chain)
                || named(name, data_chain)
                || explicit
                    .values()
                    .any(|names| names.iter().any(|entry| &**entry == *name))
        })
        .map(|(name, cred_headers)| Reader { name, cred_headers })
        .collect()
}

/// The routes whose effective chain is not the data chain: by plane instance and route id, the
/// chain's instance names (`Some`), or `None` for a route that is not served.
pub(crate) type RouteNames = BTreeMap<String, BTreeMap<u32, Option<Vec<String>>>>;

/// §12.11 "Route credential header", as the engine owner ruled it (a configuration must boot: a
/// route no opened instance can judge is not mounted, fail closed; the boot refuses only an explicit
/// operator mistake). For each served plane route, first match wins:
/// 1. the operator's `<plane>.routes.<id>.auth_instances`: each name must be an opened auth instance
///    and, on a route that declares D_ROUTE_CRED_HEADER `h`, one whose image declares D_CRED_HEADER
///    `h`; anything else refuses the candidate naming the route;
/// 2. the route declares `h`: every opened instance whose image declares `h`, in opening order;
///    when none does, the route is **not served** (`None`): it is not mounted, and a request to it is
///    answered exactly as a request to no route is;
/// 3. otherwise the data chain (no entry).
///
/// An explicit entry for a route id the plane instance does not declare refuses the candidate.
/// Instances chosen by arm 2 never join the data chain.
pub(crate) fn plan_route_names<'a>(
    routes: impl IntoIterator<
        Item = (
            &'a str,
            &'a busbar_kernel::plane_driver::port_routes::Mounted,
        ),
    >,
    readers: &[Reader<'_>],
    explicit: &busbar_kernel::config::min3::RouteAuthInstances,
) -> Result<RouteNames, String> {
    let mut out = RouteNames::new();
    let mut declared = std::collections::BTreeSet::new();
    for (instance, route) in routes {
        declared.insert((instance, route.route));
        let header = route.cred_header.as_deref();
        let names = match explicit.get(&(Box::from(instance), route.route)) {
            Some(names) => {
                let mut chain = Vec::with_capacity(names.len());
                for name in names {
                    let reader = readers
                        .iter()
                        .find(|reader| reader.name == &**name)
                        .ok_or_else(|| {
                            format!(
                                "{instance}.routes.{}.auth_instances names '{name}', which is not a configured auth instance",
                                route.route
                            )
                        })?;
                    if let Some(header) = header.filter(|header| !reader.reads(header)) {
                        return Err(format!(
                            "{instance}.routes.{}.auth_instances names '{name}', which does not read the route's credential header '{header}'",
                            route.route
                        ));
                    }
                    chain.push(name.to_string());
                }
                Some(chain)
            }
            None => {
                let Some(header) = header else {
                    continue;
                };
                let chain: Vec<String> = readers
                    .iter()
                    .filter(|reader| reader.reads(header))
                    .map(|reader| reader.name.to_owned())
                    .collect();
                (!chain.is_empty()).then_some(chain)
            }
        };
        out.entry(instance.to_owned())
            .or_default()
            .insert(route.route, names);
    }
    if let Some((instance, route)) = explicit
        .keys()
        .find(|(instance, route)| !declared.contains(&(&**instance, *route)))
    {
        return Err(format!(
            "{instance}.routes.{route}: plane instance '{instance}' serves no route {route}"
        ));
    }
    Ok(out)
}

/// The one line logged, at boot and on every apply, for a route that is not served.
pub(crate) fn unserved_line(instance: &str, route: u32, header: &str) -> String {
    format!(
        "route '{instance}/{route}' is not served: no configured auth instance reads '{header}'"
    )
}

/// The one line logged, at boot and on every apply, for a route no native path can admit.
pub(crate) fn unadmitted_line(instance: &str, route: u32, pattern: &str, why: &str) -> String {
    format!("route '{instance}/{route}' ({pattern}) is not served: {why}")
}

/// The effective chains of `served`'s routes against this candidate's opened auth instances, and the
/// routes not served (no instance reads their credential header, or no native path admits them),
/// each logged once here (boot and apply both assemble through this).
fn route_chains(
    app: &App,
    served: &Served,
    owners: &SlotOwners,
) -> Result<super::port_mount::RouteChains, String> {
    let config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .ok_or("native listener has no actual root configuration projection")?;
    let readers = route_readers(
        owners
            .auth
            .in_opened_order()
            .map(|(name, instance)| (name, instance.opened.port.cred_headers())),
        &config.data_chain,
        &app.admin_chain,
        &config.route_auth_instances,
    );
    let names = plan_route_names(
        served
            .ports
            .iter()
            .flat_map(|seat| served_routes(seat).map(move |route| (seat.instance.as_str(), route))),
        &readers,
        &config.route_auth_instances,
    )?;
    let mut chains = super::port_mount::RouteChains::new();
    for seat in &served.ports {
        let routes = names.get(&seat.instance);
        for route in served_routes(seat) {
            // `Some(Some(names))`: the route's own chain; `Some(None)`: no instance reads its
            // credential header; `None`: it runs the data chain.
            let own = routes.and_then(|routes| routes.get(&route.route));
            // Each route not served is not mounted, with one line saying why; the first reason
            // that applies is the one logged.
            let unserved = if let Some(None) = own {
                let header = route.cred_header.as_deref().unwrap_or_default();
                Some(unserved_line(&seat.instance, route.route, header))
            } else if let Err(why) = if route.flags & busbar_plugin_abi::plane::ROUTE_UPGRADE != 0 {
                // Nothing is served without its admission.
                NativeUpgradeRoute::admits(app, seat, route)
            } else {
                NativeDataRoute::admits(app, seat, route)
            } {
                Some(unadmitted_line(
                    &seat.instance,
                    route.route,
                    &route.pattern,
                    why,
                ))
            } else if own.is_none() && config.data_chain.is_empty() {
                // `auth.chain: []` (the operator's open relay) has no native producer yet: neither
                // native path can verify the anonymous principal, so the route is not mounted
                // rather than served unjudged.
                Some(unadmitted_line(
                    &seat.instance,
                    route.route,
                    &route.pattern,
                    "auth.chain is empty and the native path has no producer for the anonymous principal yet",
                ))
            } else {
                None
            };
            let chain = match (unserved, own) {
                (Some(line), _) => {
                    tracing::warn!("{line}");
                    None
                }
                (None, Some(Some(names))) => Some(chain_points(owners, names)?),
                (None, _) => continue,
            };
            chains
                .entry(seat.instance.clone())
                .or_default()
                .insert(route.route, chain);
        }
    }
    Ok(chains)
}

/// The chain entries of `names`, each an opened native auth instance that can verify.
fn chain_points(owners: &SlotOwners, names: &[String]) -> Result<Vec<ChainAuth>, String> {
    names
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
