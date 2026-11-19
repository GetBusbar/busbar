// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native listener topology from configured binds and actual D_LISTENER_SLOT suppliers.
//! This does not convert native ports into legacy framing claims or bind a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use busbar_contract::route::AuthPoints;
use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_kernel::auth::admission_table::NotMounted;
use busbar_kernel::auth::native_chain::ANONYMOUS;
use busbar_kernel::auth::native_data::NativeDataRoute;
use busbar_kernel::auth::native_upgrade::NativeUpgradeRoute;
use busbar_kernel::auth::route_record::CallerState;
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
        // Handing one over is the connection supervisor's adopt step (`listener_native_handover.rs`,
        // owner decision 18): a candidate with upgrade routes and an admitted websocket instance is
        // served, and with no such instance every authorized upgrade request is answered 501.
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
                let (chain, built_in) = configured_chain(app, owners)?;
                let route_chains = route_chains(app, served, owners)?;
                // A core route that takes a data key is served: the data chain verifies its caller
                // (`listener_native_corekey.rs`), the handler is given the verified key, no unit.
                let served_core: Vec<_> = core.to_vec();
                let mounts = super::serve::data_mounts(
                    served.clone(),
                    &chain,
                    &built_in,
                    &route_chains,
                    &served_core,
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
/// be handed over, which the listener does (the hand-over is linked: owner decision 18). Kept as
/// the one place a candidate's upgrade routes are judged against its transports.
fn upgrades_honoured(_upgrades: bool, _websocket: Option<&ServedTransport>) -> Result<(), String> {
    Ok(())
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

/// The configured data chain's entries (its opened instances) and the built-in members it names.
fn configured_chain(
    app: &App,
    owners: &SlotOwners,
) -> Result<(Vec<ChainAuth>, Vec<String>), String> {
    let config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .ok_or("native listener has no actual root configuration projection")?;
    let built_in = config
        .data_chain
        .iter()
        .filter(|name| busbar_kernel::auth::native_chain::BuiltIn::is(name))
        .cloned()
        .collect();
    Ok((chain_points(owners, &config.data_chain)?, built_in))
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
                // An empty chain is the open relay, which only `auth.chain: []` configures; a
                // route's own list never opens a route.
                if names.is_empty() {
                    return Err(format!(
                        "{instance}.routes.{}.auth_instances is empty; name at least one configured auth instance",
                        route.route
                    ));
                }
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
            // A route that admits a ticket alone never runs its chain (core's ticket verifier
            // judges it), so no instance reading its credential header is not a reason to leave
            // it unmounted; its admission below still decides.
            let ticket_alone = {
                use busbar_kernel::auth::route_record::Who;
                route.record.who.has(Who::TICKET) && !route.record.who.has(Who::PRINCIPAL)
            };
            let unserved = if matches!(own, Some(None)) && !ticket_alone {
                let header = route.cred_header.as_deref().unwrap_or_default();
                Some(unserved_line(&seat.instance, route.route, header))
            } else if super::min3_physical::is_signed_route(route) {
                // A signed route is the signed class's, never the data path's: it is mounted
                // exactly where its whole path exists (its own chain covers and bounds the body).
                signed_admits(app, seat, route, own, owners)
                    .err()
                    .map(|why| unadmitted_line(&seat.instance, route.route, &route.pattern, why))
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
            } else {
                // With `auth.chain: [anonymous]` (the operator's open relay) a route that runs the data
                // chain is served as the anonymous principal, through admission like any other
                // (the built-in chain member `anonymous`: `NativeChain::data_admitting_anonymous`). A
                // route that keeps state per caller is no exception: auth is plane-agnostic, and the
                // anonymous caller's state is keyed by its session's handle (`port_intents::handle_scope`).
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

/// Whether a signed route's whole path exists under this candidate; `Err`: why it is not mounted.
/// Its signature verifier is its own chain (`own`: the opened instances that read its signature
/// header, or the operator's `auth_instances` for it) and never the data chain: a signed route
/// with no chain of its own has no verifier. Every member must cover the body and state its
/// bound (`D_BODY_MAX`), none may be a built-in member, no hook may be bound, and the operator's
/// class must be the route's own (`NativeSignedRoute::admits`, the same judgement its binding
/// makes again in `assemble_slot`).
fn signed_admits(
    app: &App,
    seat: &busbar_kernel::plane_driver::port::PortSeat,
    route: &busbar_kernel::plane_driver::port_routes::Mounted,
    own: Option<&Option<Vec<String>>>,
    owners: &SlotOwners,
) -> Result<(), &'static str> {
    use busbar_kernel::auth::native_signed_route::{NativeSignedRoute, SignedUnmounted};
    let members = match own {
        Some(Some(names)) => Some(
            super::min3_physical::signed_members(&owners.auth, names)
                .map_err(SignedUnmounted::reason)?,
        ),
        Some(None) | None => None,
    };
    NativeSignedRoute::admits(
        seat,
        route,
        members.as_deref(),
        super::min3_physical::signed_body_cap(app),
    )
    .map(|_bound| ())
    .map_err(SignedUnmounted::reason)
}

/// The chain entries of `names`, each an opened native auth instance that can verify. The chain's
/// built-in members (`anonymous`, `keys`) name no opened instance and are not entries.
fn chain_points(owners: &SlotOwners, names: &[String]) -> Result<Vec<ChainAuth>, String> {
    names
        .iter()
        .filter(|name| !busbar_kernel::auth::native_chain::BuiltIn::is(name))
        .map(|name| {
            let instance = owners
                .auth
                .get(name)
                .ok_or_else(|| format!("{name}: data chain has no actual opened native auth"))?;
            if instance.opened.methods & busbar_plugin_abi::auth::M_VERIFY == 0 {
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
