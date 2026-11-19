// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The serving generation's native nested-route table, built off the request path: once per
//! published generation, by [`DataRoutes::new`] (itself called from `off_path::serve` while the
//! generation is composed, before it goes live). The request path (`serve::native_nests`) only
//! matches against what this built.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::route::{method_bit, PATH_EXACT, PATH_PATTERN};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::plane_driver::port_routes::PortRoutes;

use crate::root::serve::native_nests::NativeNests;
use crate::root::serve::{DataRoutes, DispatchSnapshot, DoorNests};

impl DataRoutes {
    pub(crate) fn new(snapshot: DispatchSnapshot) -> Result<Arc<Self>, String> {
        let snapshot = Arc::new(snapshot);
        let native = Arc::new(NativeNests::new(&snapshot)?);
        let kernel = snapshot
            .served
            .planes
            .first()
            .map(|plane| Arc::clone(&plane.kernel))
            .or_else(|| {
                snapshot
                    .served
                    .ports
                    .first()
                    .map(|seat| Arc::clone(seat.driver.core()))
            });
        let generation = match kernel {
            Some(kernel) => {
                if snapshot
                    .served
                    .planes
                    .iter()
                    .any(|other| !Arc::ptr_eq(&kernel, &other.kernel))
                    || snapshot
                        .served
                        .ports
                        .iter()
                        .any(|seat| !Arc::ptr_eq(&kernel, seat.driver.core()))
                {
                    return Err("listener planes do not share the same core services".into());
                }
                if snapshot
                    .served
                    .planes
                    .iter()
                    .any(|plane| plane.driver.invocation_caller().is_none())
                {
                    return Err("listener plane has no admitted invocation owner".into());
                }
                let runtime =
                    tokio::runtime::Handle::try_current().map_err(|error| error.to_string())?;
                Some(Arc::new(
                    busbar_kernel::host_services::ServingGeneration::try_new(
                        kernel,
                        Arc::new(DoorNests {
                            routes: Arc::clone(&snapshot),
                            native,
                            runtime,
                            detached: busbar_kernel::detached::worker_detached(),
                        }),
                    )
                    .map_err(|_| "native routing generation counter exhausted".to_owned())?,
                ))
            }
            None => None,
        };
        Ok(Arc::new(Self {
            snapshot,
            generation,
        }))
    }
}

impl NativeNests {
    pub(crate) fn new(snapshot: &DispatchSnapshot) -> Result<Self, String> {
        let ports: Vec<_> = snapshot
            .served
            .ports
            .iter()
            .map(|seat| (seat.instance.as_str(), seat.driver.routes()))
            .collect();
        Self::from_guests(snapshot.guests.lines(), &ports)
    }

    /// The nest table of a generation whose sealed guest list already holds the ports' own data
    /// lines (the native listener mounts them, each with its effective chain): those lines give way
    /// to the nest's own line for the same route, and a port data route with no line there (a route
    /// the listener left unmounted) is no nest destination either.
    pub(in crate::root) fn from_guests(
        guests: &[Line],
        ports: &[(&str, &PortRoutes)],
    ) -> Result<Self, String> {
        let mounted: Vec<(&str, u32)> = guests
            .iter()
            .filter_map(|line| port_data(line, ports))
            .collect();
        let others = guests
            .iter()
            .filter(|line| port_data(line, ports).is_none())
            .cloned()
            .collect();
        Self::seal(others, ports, |instance, route| {
            mounted.iter().any(|(i, r)| *i == instance && *r == route)
        })
    }

    /// `mounted`: whether a port's data route (instance, route id) is served at all.
    pub(in crate::root) fn seal(
        mut lines: Vec<Line>,
        ports: &[(&str, &PortRoutes)],
        mounted: impl Fn(&str, u32) -> bool,
    ) -> Result<Self, String> {
        let mut destinations = BTreeMap::new();
        for (seat, (instance, routes)) in ports.iter().enumerate() {
            for route in routes.data.iter().filter(|r| mounted(instance, r.route)) {
                // Match exactly the verbs exposed by the native HTTP data mount.
                let methods = crate::root::port_mount::methods_of(route.methods)
                    .iter()
                    .fold(0, |mask, method| mask | method_bit(method.as_str()));
                if methods == 0 {
                    continue;
                }
                let key = (instance.to_string(), route.route);
                if destinations.insert(key, seat).is_some()
                    || lines.iter().any(|line| {
                        line.claimant == Claimant::Plane(instance.to_string())
                            && line.route.rung == route.route
                    })
                {
                    return Err("native nested route repeats an admitted plane route".into());
                }
                lines.push(Line {
                    route: Route {
                        methods,
                        path_form: if route.pattern.contains('{') {
                            PATH_PATTERN
                        } else {
                            PATH_EXACT
                        },
                        path: route.pattern.to_string(),
                        fields: Vec::new(),
                        rung: route.route,
                    },
                    claimant: Claimant::Plane(instance.to_string()),
                    dialect: 0,
                    auth: LineAuth::None,
                    upgrade: None,
                    offered: busbar_contract::route::AuthPoints::EMPTY,
                });
            }
        }
        let guests = GuestList::seal(lines)
            .map_err(|why| format!("native nested route table refused: {why:?}"))?;
        Ok(Self {
            guests,
            destinations,
        })
    }
}

/// The (instance, route id) of a port's own data line; None for every other line.
fn port_data<'l>(line: &'l Line, ports: &[(&str, &PortRoutes)]) -> Option<(&'l str, u32)> {
    let Claimant::Plane(instance) = &line.claimant else {
        return None;
    };
    ports
        .iter()
        .any(|(name, routes)| {
            *name == instance.as_str() && routes.data.iter().any(|r| r.route == line.route.rung)
        })
        .then_some((instance.as_str(), line.route.rung))
}
