// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The serving generation's native nested-route table, built off the request path: once per
//! published generation, by [`DataRoutes::new`] (itself called from `off_path::serve` while the
//! generation is composed, before it goes live). The request path (`serve::native_nests`) only
//! matches against what this built.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
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
        Self::seal(snapshot.guests.lines().to_vec(), &ports)
    }

    pub(in crate::root) fn seal(
        mut lines: Vec<Line>,
        ports: &[(&str, &PortRoutes)],
    ) -> Result<Self, String> {
        let mut destinations = BTreeMap::new();
        for (seat, (instance, routes)) in ports.iter().enumerate() {
            for route in &routes.data {
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
                    offered: busbar_contract::abi::auth::AuthPoints::EMPTY,
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
