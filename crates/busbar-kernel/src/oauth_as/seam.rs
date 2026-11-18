// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::core_routes::CoreRouter;
use busbar_contract::SecretRef;

type AsPlaneBuildFn =
    fn(
        busbar_contract::yaml::Value,
        Vec<(String, String)>,
        Vec<String>,
        Option<Arc<dyn Any + Send + Sync>>,
        Arc<crate::persistence::facade::CoreStore>,
        String,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn Any + Send + Sync>, String>> + Send>>;

type AsPlaneCheckFn = fn(&busbar_contract::yaml::Value) -> Result<Vec<(String, SecretRef)>, String>;

/// One DPoP presentation, lent for the length of its verification: the request's own method,
/// path, token and proof, borrowed from the request (no copy of a credential is made to verify it).
pub struct DpopPresentation<'a> {
    pub method: &'a str,

    pub path: &'a str,
    pub token: &'a str,
    pub proof: &'a str,
}

/// An `oauth_as:` block its owner has ACCEPTED ([`AsPlaneSeam::check`]), carried by `RootCfg`: the
/// opaque block itself, and the secret references the owner listed in it. `resolve` makes one only
/// from a block that passed, so holding one means the owner already validated it.
#[derive(Debug)]
pub struct CheckedAsBlock {
    pub block: busbar_contract::yaml::Value,
    pub secret_refs: Vec<(String, SecretRef)>,
    /// The admin listener's origin ([`admin_origin`]): where the authorization server's operator
    /// approval pages live, and the address it publishes for them.
    pub admin_origin: String,
}

type AsDpopVerifyFn = for<'a> fn(
    &'a Arc<dyn Any + Send + Sync>,
    DpopPresentation<'a>,
) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

pub struct AsPlaneSeam {
    /// Owner-produced raw oauth_as user-input schema; separate from resolved server state.
    pub input_schema: fn() -> serde_json::Value,

    pub check: AsPlaneCheckFn,

    pub build: AsPlaneBuildFn,

    pub mount: fn(CoreRouter, Option<&Arc<dyn Any + Send + Sync>>) -> CoreRouter,

    /// The operator approval pages (`/oauth/device`, `/oauth/consent`), mounted on the ADMIN listener
    /// at boot whether or not `oauth_as:` is on: their paths are fixed, and each handler reads the
    /// current plane and answers 404 while the authorization server is off.
    pub mount_operator: fn(CoreRouter) -> CoreRouter,

    pub verify_dpop: AsDpopVerifyFn,
}

static SEAM: OnceLock<AsPlaneSeam> = OnceLock::new();

static HOSTED_LOGIN: OnceLock<crate::auth::login::seam::LoginSeam> = OnceLock::new();

pub(crate) fn install_hosted_login(seam: crate::auth::login::seam::LoginSeam) {
    let _ = HOSTED_LOGIN.set(seam);
}

pub(crate) fn hosted_login() -> Option<&'static crate::auth::login::seam::LoginSeam> {
    HOSTED_LOGIN.get()
}

pub fn install_as_plane_seam(seam: AsPlaneSeam) {
    assert!(
        SEAM.set(seam).is_ok(),
        "install_as_plane_seam called twice: there is one composition root, and it registers once"
    );
}

/// The installed owner's raw user-input grammar, absent when this build has no OAuth owner.
pub fn input_schema() -> Option<serde_json::Value> {
    SEAM.get().map(|owner| (owner.input_schema)())
}

pub(crate) fn seam() -> Option<&'static AsPlaneSeam> {
    SEAM.get()
}

/// The admin listener's origin, as the operator's browser reaches it: `http(s)://{admin_listen}`,
/// `https` exactly when `admin_tls` is set. The authorization server serves its operator approval
/// pages there and publishes that address.
///
/// Derived ONLY from a loopback `admin_listen` with a port (`127.0.0.1:8081`, `localhost:8081`,
/// `[::1]:8081`): that address is reached on the host, over `ssh -L` or over `kubectl port-forward`,
/// all of which keep host and port, so the derived origin is exactly what the browser uses. Any other
/// bind (a wildcard, a LAN address, a name behind NAT, an ingress or a mesh) gives no address busbar
/// can know, so it is refused rather than guessed.
pub fn admin_origin(admin_listen: &str, admin_tls: bool) -> Result<String, String> {
    let refuse = || {
        format!(
            "oauth_as: admin_listen `{admin_listen}` is not a loopback address with a port. oauth_as \
             serves its operator approval pages on the admin listener and publishes its address; \
             busbar can only know that address when admin_listen is loopback. Bind admin_listen \
             to 127.0.0.1 with a port (for example `127.0.0.1:8081`) and reach it with \
             ssh -L or kubectl port-forward."
        )
    };
    let (host, port) = admin_listen.rsplit_once(':').ok_or_else(refuse)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(refuse)?;
    let loopback = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
    };
    if !loopback || !crate::config::bind_is_loopback(admin_listen) {
        return Err(refuse());
    }
    let scheme = if admin_tls { "https" } else { "http" };
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Mount the operator approval pages on an ADMIN router, when this build links an OAuth owner.
pub(crate) fn mount_operator(router: CoreRouter) -> CoreRouter {
    match SEAM.get() {
        Some(seam) => (seam.mount_operator)(router),
        None => router,
    }
}

static CLOCK_WORK: std::sync::Mutex<Vec<std::sync::Weak<dyn crate::tick::ClockWork>>> =
    std::sync::Mutex::new(Vec::new());

pub(crate) fn hold_clock_work(work: std::sync::Weak<dyn crate::tick::ClockWork>) {
    let mut held = CLOCK_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.retain(|w| w.strong_count() > 0);
    held.push(work);
}

pub(crate) fn clock_work() -> Vec<Arc<dyn crate::tick::ClockWork>> {
    let mut held = CLOCK_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.retain(|w| w.strong_count() > 0);
    held.iter().filter_map(std::sync::Weak::upgrade).collect()
}
