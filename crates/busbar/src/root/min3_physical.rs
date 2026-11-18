// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Candidate-only assembly of physical listener tokens and their actual native DATA owners.
//! S9 publishes the resulting slot map with the same App and supplies the canonical resolver.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{method_bit, METHOD_HEAD, PATH_EXACT, PATH_PATTERN};
use busbar_kernel::auth::native_data::{DataRouteOwners, NativeDataRoute};
use busbar_kernel::door::UnitKeyMint;
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth};
use busbar_kernel::inbound::native::{PhysicalPlan, RequestBinding, RouteBinding, RouteTarget};
use busbar_kernel::plane_driver::port::{PortDriver, PortSeat};
use busbar_kernel::plane_driver::port_egress::Targets;
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::resource_admission::ResourceInventory;
use busbar_kernel::router::PreparedListener;
use busbar_kernel::state::App;
use busbar_kernel::upstreams::Upstreams;
use busbar_ports::plane::PlaneIn;
use busbar_ports::transport::TransportPort;

use super::min3_auth::AuthSet;
use super::serve::DoorMounts;

/// These are the configured sources already used by this candidate's actual seat egress.
#[derive(Clone)]
pub(crate) struct InventoryInputs {
    pub(crate) upstreams: Arc<dyn Upstreams>,
    pub(crate) targets: Targets,
    pub(crate) byte_limit: usize,
}

pub(crate) type Inventories = BTreeMap<(String, u32), Arc<ResourceInventory>>;
pub(crate) type NativeSlots = BTreeMap<String, Arc<NativeSlot>>;

/// Read the opened plane's pure configuration inventory for an actual declared route. The
/// empty identity is the inventory operation's ABI input, never a request authorization.
pub(crate) fn build_inventory(
    driver: &PortDriver,
    route: &Mounted,
    epoch: u64,
    inputs: &InventoryInputs,
) -> Result<Arc<ResourceInventory>, String> {
    if inputs.byte_limit == 0
        || route.resource_kinds.is_empty()
        || !driver
            .routes()
            .data
            .iter()
            .any(|declared| declared == route)
    {
        return Err(
            "native inventory requires an actual resource route and finite output limit".into(),
        );
    }
    let request = PlaneIn {
        route: route.route,
        flags: 0,
        auth: 0,
        method: "",
        path: "",
        query: "",
        headers: &[],
        identity: &[],
        request_id: 0,
        carrier: 0,
        work: "",
        ticket_record: &[],
    };
    let wire = driver
        .port()
        .resource_facts(
            busbar_plugin_abi::plane::RESOURCE_INVENTORY,
            &request,
            &[],
            inputs.byte_limit,
        )
        .map_err(|_| "native plane inventory was refused".to_string())?;
    if wire.len() > inputs.byte_limit {
        return Err("native plane inventory exceeded its configured output limit".into());
    }
    ResourceInventory::from_wire(
        driver.caller(),
        epoch,
        route.resource_kinds.clone(),
        &wire,
        Arc::clone(&inputs.upstreams),
        Arc::clone(&inputs.targets),
        inputs.byte_limit,
    )
    .map_err(|_| "native plane inventory does not match configured registration targets".into())
}

/// Build once per complete candidate; listener slots share these same inventory Arcs.
pub(crate) fn build_inventories(
    seats: &[PortSeat],
    epoch: u64,
    inputs: &BTreeMap<String, InventoryInputs>,
) -> Result<Inventories, String> {
    let mut inventories = BTreeMap::new();
    for seat in seats {
        if !seat
            .driver
            .routes()
            .data
            .iter()
            .any(|route| !route.resource_kinds.is_empty())
        {
            continue;
        }
        let source = inputs.get(&seat.instance).ok_or_else(|| {
            format!(
                "{}: native inventory has no configured sources",
                seat.instance
            )
        })?;
        for route in &seat.driver.routes().data {
            if route.resource_kinds.is_empty() {
                continue;
            }
            let inventory = build_inventory(&seat.driver, route, epoch, source)?;
            if inventories
                .insert((seat.instance.clone(), route.route), inventory)
                .is_some()
            {
                return Err("native inventory has duplicate instance/route ownership".into());
            }
        }
    }
    Ok(inventories)
}

/// Owned inputs from one complete candidate. `epoch` is S9's actual reserved publication
/// epoch; callers must not derive it from config_version, process generation, or current+1.
pub(crate) struct SlotOwners {
    pub(crate) auth: Arc<AuthSet>,
    pub(crate) epoch: u64,
    pub(crate) inventories: Arc<Inventories>,
    pub(crate) keys: Arc<UnitKeyMint>,
    pub(crate) core: Arc<[(String, RouteMethod, RouteAuth)]>,
}

/// One same-slot prepared dispatcher and its exact route tokens. No Arc<App> is retained,
/// so publishing this owner inside App cannot create an App/listener ownership cycle.
pub(crate) struct NativeSlot {
    slot: Box<str>,
    prepared: Arc<PreparedListener>,
    data: Vec<(Arc<RouteBinding>, Arc<NativeDataRoute>)>,
}
impl std::fmt::Debug for NativeSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSlot")
            .field("slot", &self.slot)
            .field("data_routes", &self.data.len())
            .finish_non_exhaustive()
    }
}
impl NativeSlot {
    pub(crate) fn slot(&self) -> &str {
        &self.slot
    }
    pub(crate) fn prepared(&self) -> &Arc<PreparedListener> {
        &self.prepared
    }
    pub(crate) fn data_for(
        &self,
        binding: &RequestBinding,
    ) -> Result<Arc<NativeDataRoute>, String> {
        if !Arc::ptr_eq(binding.prepared(), &self.prepared) {
            return Err("native request belongs to another prepared listener".into());
        }
        self.data
            .iter()
            .find(|(route, _)| Arc::ptr_eq(route, binding.route()))
            .map(|(_, data)| Arc::clone(data))
            .ok_or_else(|| "native request has no DATA completion for its actual route".into())
    }
}

fn declared_core_auth(
    line: &Line,
    core: &[(String, RouteMethod, RouteAuth)],
) -> Result<RouteAuth, String> {
    if !matches!(line.claimant, Claimant::Clean(_))
        || line.upgrade.is_some()
        || !line.route.fields.is_empty()
        || !matches!(line.auth, LineAuth::None)
        || line.route.path_form
            != if line.route.path.contains('{') {
                PATH_PATTERN
            } else {
                PATH_EXACT
            }
    {
        return Err("native core line does not match an actual core route declaration".into());
    }
    let mut methods = 0;
    let mut auth = None;
    for (path, method, class) in core {
        if path != &line.route.path {
            continue;
        }
        let bit = core_method_mask(*method) & line.route.methods;
        if bit == 0 {
            continue;
        }
        if methods & bit != 0 || auth.is_some_and(|old| old != *class) {
            return Err("native core declaration has ambiguous methods or authorization".into());
        }
        methods |= bit;
        auth = Some(*class);
    }
    if methods != line.route.methods || methods == 0 {
        return Err("native core declaration does not cover the full physical line".into());
    }
    match auth {
        Some(class @ (RouteAuth::None | RouteAuth::Admin)) => Ok(class),
        _ => Err("native core key authorization has no completed class producer".into()),
    }
}

fn core_method_mask(method: RouteMethod) -> u32 {
    // CoreRouter and axum resolve HEAD onto GET. Keep that actual public/admin behavior.
    method_bit(method.as_str())
        | if method == RouteMethod::Get {
            METHOD_HEAD
        } else {
            0
        }
}

/// Assemble only after the actual DoorMounts and candidate inventories exist. Every sealed
/// guest must have a supported complete class; unsupported guests refuse the whole candidate.
pub(crate) fn assemble_slot(
    app: &App,
    slot: &str,
    transport: Arc<dyn TransportPort>,
    guests: GuestList,
    mounts: DoorMounts,
    owners: &SlotOwners,
) -> Result<Arc<NativeSlot>, String> {
    let DoorMounts {
        data: dispatch,
        routes,
        refusals,
        refuse_by_path,
    } = mounts;
    let plugins = app.plugin_routes.for_listener(&guests);
    let prepared = PreparedListener::new(
        app,
        &plugins,
        routes,
        refusals,
        refuse_by_path,
        slot == "listen",
    )?
    .with_data(dispatch.clone())
    .with_dispatch_layer(super::listener::deferred_dispatch_layer);
    let prepared = if slot == "listen" {
        match dispatch.served.native.as_ref() {
            Some(native) => prepared.with_core_routes(|routes| {
                super::provisioning::mount_routes(routes, &native.provisioning)
            }),
            None => prepared,
        }
    } else {
        prepared
    };
    let actual_core: Vec<_> = prepared
        .core_lines()
        .map(|(path, method, auth)| (path.to_owned(), method, auth))
        .collect();
    let seats = &dispatch.served.ports;
    let mut bindings = Vec::with_capacity(guests.lines().len());
    for line in guests.lines() {
        if line.upgrade.is_some() {
            return Err("native physical upgrade completion is unavailable".into());
        }
        let binding = match &line.claimant {
            Claimant::Plane(instance) => {
                let mut matching = seats.iter().filter(|seat| &seat.instance == instance);
                let seat = matching
                    .next()
                    .ok_or_else(|| format!("{instance}: no actual native plane seat"))?;
                if matching.next().is_some() {
                    return Err("native plane seat ownership is ambiguous".into());
                }
                let route = seat
                    .driver
                    .routes()
                    .data
                    .iter()
                    .find(|route| route.route == line.route.rung)
                    .ok_or_else(|| {
                        format!("{instance}: physical line has no actual native route")
                    })?;
                let LineAuth::Chain(names, _) = &line.auth else {
                    return Err("native principal route has no resolved native auth chain".into());
                };
                RouteBinding::plane(
                    line.clone(),
                    seat.driver.caller().clone(),
                    route.clone(),
                    names
                        .iter()
                        .map(|name| name.clone().into_boxed_str())
                        .collect(),
                )
            }
            Claimant::Clean(_) => {
                let actual = declared_core_auth(line, &actual_core)?;
                if declared_core_auth(line, &owners.core)? != actual {
                    return Err(
                        "candidate core policy disagrees with its actual mounted handler".into(),
                    );
                }
                RouteBinding::core(line.clone(), actual)
            }
            Claimant::Need(_, _) => {
                return Err("native inbound Need route has no complete physical producer".into())
            }
        }
        .map_err(|_| "native physical line does not match its actual route owner".to_string())?;
        bindings.push(binding);
    }
    let plan = PhysicalPlan::new(slot.into(), transport, guests, bindings)
        .map_err(|_| "native physical plan does not cover the complete slot".to_string())?;
    let mut data = Vec::new();
    for binding in plan.routes() {
        let RouteTarget::Plane(target) = binding.target() else {
            continue;
        };
        let seat = seats
            .iter()
            .find(|seat| seat.driver.caller().same_incarnation(target.caller()))
            .ok_or_else(|| "native physical route lost its plane incarnation".to_string())?;
        let generation = dispatch
            .generation
            .as_ref()
            .ok_or_else(|| "native DATA route has no actual serving generation".to_string())?;
        let inventory = owners
            .inventories
            .get(&(seat.instance.clone(), target.mounted().route))
            .ok_or_else(|| "native DATA route has no actual configured inventory".to_string())?;
        let chain = owners
            .auth
            .data_chain(owners.epoch, target.auth_instances())?;
        let native = NativeDataRoute::bind(
            app,
            seat,
            Arc::clone(binding),
            DataRouteOwners {
                generation: Arc::clone(generation),
                inventory: Arc::clone(inventory),
                chain: Arc::new(chain),
                keys: Arc::clone(&owners.keys),
                routes: Arc::clone(&seat.request_routes),
            },
        )
        .map_err(|_| {
            "native DATA route class or actual candidate owners are unsupported".to_string()
        })?;
        data.push((Arc::clone(binding), native));
    }
    let prepared = prepared
        .with_physical(plan)
        .map_err(|_| "native physical plan was already attached".to_string())?;
    Ok(Arc::new(NativeSlot {
        slot: slot.into(),
        prepared: Arc::new(prepared),
        data,
    }))
}

/// The dedicated operator slot is built from the existing real admin mount and its own
/// declaration table. A data router or caller-supplied route list cannot stand in for it.
pub(crate) fn assemble_admin_slot(
    app: &App,
    slot: &str,
    transport: Arc<dyn TransportPort>,
) -> Result<Arc<NativeSlot>, String> {
    if app.native_admin.is_none() {
        return Err("operator slot has no actual native admin authority".into());
    }
    if app
        .plugin_routes
        .descriptors()
        .iter()
        .any(|route| route.auth == RouteAuth::Admin)
    {
        return Err("native plugin admin Need routes have no complete physical producer".into());
    }
    let prepared = PreparedListener::new_admin(app)?
        .with_dispatch_layer(super::listener::deferred_dispatch_layer);
    let core: Vec<_> = prepared
        .core_lines()
        .map(|(path, method, auth)| (path.to_owned(), method, auth))
        .collect();
    if !core.iter().any(|(_, _, auth)| *auth == RouteAuth::Admin) {
        return Err("operator slot has no actual mounted admin handlers".into());
    }
    let mut lines = Vec::with_capacity(core.len());
    let mut bindings = Vec::with_capacity(core.len());
    for (at, (path, method, auth)) in core.into_iter().enumerate() {
        if auth == RouteAuth::Key {
            return Err("operator core key route has no completed native class producer".into());
        }
        let line = Line {
            route: busbar_kernel::guest::Route {
                methods: core_method_mask(method),
                path_form: if path.contains('{') {
                    PATH_PATTERN
                } else {
                    PATH_EXACT
                },
                path,
                fields: Vec::new(),
                rung: u32::try_from(at).map_err(|_| "too many operator routes")?,
            },
            claimant: Claimant::Clean("core/admin".into()),
            dialect: 0,
            auth: LineAuth::None,
            upgrade: None,
            offered: busbar_contract::abi::auth::AuthPoints::EMPTY,
        };
        bindings.push(
            RouteBinding::core(line.clone(), auth)
                .map_err(|_| "operator route does not match its actual declaration")?,
        );
        lines.push(line);
    }
    let guests = GuestList::seal(lines)
        .map_err(|_| "actual operator routes cannot share one physical slot")?;
    let plan = PhysicalPlan::new(slot.into(), transport, guests, bindings)
        .map_err(|_| "operator physical plan does not cover its complete declaration table")?;
    let prepared = prepared
        .with_physical(plan)
        .map_err(|_| "operator physical plan was already attached")?;
    Ok(Arc::new(NativeSlot {
        slot: slot.into(),
        prepared: Arc::new(prepared),
        data: Vec::new(),
    }))
}

#[cfg(test)]
#[path = "tests/min3_physical.rs"]
mod tests;
