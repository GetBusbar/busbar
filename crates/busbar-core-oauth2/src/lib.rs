// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod cimd;
pub mod config;
pub mod consent;

mod hosted_login;
pub mod plane;
pub mod policy;
pub mod routes;
pub mod shared;
pub mod signer;

#[cfg(test)]
pub mod testkit;

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
#[cfg(test)]
#[path = "tests/device_routes_tests.rs"]
mod device_routes_tests;
#[cfg(test)]
#[path = "tests/flow_tests.rs"]
mod flow_tests;
#[cfg(test)]
#[path = "tests/mount_tests.rs"]
mod mount_tests;
#[cfg(test)]
#[path = "tests/reload_tests.rs"]
mod reload_tests;

pub trait Connections: 'static {
    fn table() -> Option<Table>;
}

/// One connection table as a fetch reaches it.
#[derive(Clone)]
pub struct Table {
    /// The identity this crate's needs are declared and opened under.
    pub owner: busbar_contract::conn::InstanceId,
    /// Where the needs are declared.
    pub declared: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>,
    /// Where the connections are opened and read.
    pub conns: std::sync::Arc<dyn busbar_contract::conn::PollConns>,
}

pub struct NoConnections;

impl Connections for NoConnections {
    fn table() -> Option<Table> {
        None
    }
}

pub fn install<C: Connections>() {
    busbar_kernel::auth::login::seam::install(hosted_login::SEAM);
    busbar_kernel::oauth_as::seam::install_as_plane_seam(
        busbar_kernel::oauth_as::seam::AsPlaneSeam {
            check: config::seam_check,
            build: plane::seam_build::<C>,
            mount: routes::seam_mount,
            verify_dpop: plane::seam_verify_dpop,
        },
    );
}
