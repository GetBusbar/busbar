// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod cimd;
pub mod config;
pub mod consent;
pub mod crypto_provider;
/// Core's PKCE/state/nonce minting (IF §12.12 round 22, C-LOGIN-PKCE): the one definition, called by the hosted login
/// and by the caller-connection BEGIN. It lives in `busbar_kernel::connections::pkce` (this crate depends on the
/// kernel, never the reverse); this is the IF's path to it.
pub mod pkce {
    pub use busbar_kernel::connections::pkce::{
        code_challenge_s256, random_b64url, STATE_BYTES, VERIFIER_BYTES,
    };
}

mod cold;
mod hosted_login;
mod mount;
// The operator approval pages (admin listener): off the data listener's request path.
mod operator;
mod page;
mod sweep;
// The plane's build, generation hand-over and sweep; its request path is the marked `plane::serve`.
pub mod plane;
pub mod policy;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod routes;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
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
#[cfg(test)]
#[path = "tests/store_failure_tests.rs"]
mod store_failure_tests;

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
            input_schema: config::input_schema,
            check: config::seam_check,
            build: plane::seam_build::<C>,
            mount: mount::seam_mount,
            mount_operator: mount::seam_mount_operator,
            verify_dpop: plane::seam_verify_dpop,
        },
    );
}
