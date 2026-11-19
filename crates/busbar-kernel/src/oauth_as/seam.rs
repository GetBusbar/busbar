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

/// One DPoP presentation at a protected resource of this deployment that states its own URL: the
/// request's method, the URL it was received at, and the token and proof it carried, all lent
/// for the length of the judgement (no copy of a credential is made to judge it).
pub struct DpopAtResource<'a> {
    pub method: &'a str,
    /// The request's URL as the resource states it: its public origin and the path as received,
    /// with no query and no fragment. The proof's `htu` must name it (RFC 9449 s4.3 (9)).
    pub htu: &'a str,
    pub token: &'a str,
    pub proof: &'a str,
}

/// Why a DPoP presentation at a protected resource was not proven. For the log only: every one
/// of them is the same refusal to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopRefused {
    /// Not a compact JWS this server will read (malformed, over the size it reads, a `crit` it
    /// does not implement, or a `jti` longer than it will remember).
    Malformed,
    /// The proof's `typ` is not `dpop+jwt`.
    NotAProof,
    /// The proof's `alg` is not an asymmetric algorithm this server verifies.
    Algorithm,
    /// The proof's `jwk` is absent, not a public key, or not a key of its `alg`.
    ProofKey,
    /// The signature does not verify under the proof's own key.
    Signature,
    /// `htm` is not the request's method.
    Method,
    /// `htu` is not the request's URL.
    Uri,
    /// `iat` is absent or outside the window.
    Stale,
    /// `jti` is absent or empty.
    Jti,
    /// `ath` is absent or is not the hash of the presented access token.
    AccessTokenHash,
    /// The proof key's thumbprint is not the token's `cnf.jkt` (or the token names none).
    KeyBinding,
    /// This server does not hold the token: revoked, expired, or never issued here.
    NotHeld,
    /// This `jti` was already proven under this key.
    Replayed,
}

impl DpopRefused {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "proof_malformed",
            Self::NotAProof => "proof_typ",
            Self::Algorithm => "proof_alg",
            Self::ProofKey => "proof_jwk",
            Self::Signature => "proof_signature",
            Self::Method => "proof_htm",
            Self::Uri => "proof_htu",
            Self::Stale => "proof_iat",
            Self::Jti => "proof_jti",
            Self::AccessTokenHash => "proof_ath",
            Self::KeyBinding => "proof_key_not_cnf_jkt",
            Self::NotHeld => "token_not_held",
            Self::Replayed => "proof_replayed",
        }
    }
}

/// What the authorization server answers about one [`DpopAtResource`]. Only `Proven` is ever an
/// admission, and a proven token still has to pass the resource's own chain (signature, issuer,
/// expiry) and its audience check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopVerdict {
    /// The proof is a whole RFC 9449 s4.3 proof for this method and URL, inside the `iat` window,
    /// its `ath` is the hash of this token, its key's thumbprint is this token's `cnf.jkt`, this
    /// server holds the token, and its `jti` was claimed just now for the first time.
    Proven,
    Refused(DpopRefused),
    /// The server's store could not answer (the token record, or the single-use claim).
    Unavailable,
}

type AsDpopProveFn = for<'a> fn(
    &'a Arc<dyn Any + Send + Sync>,
    DpopAtResource<'a>,
) -> Pin<Box<dyn Future<Output = DpopVerdict> + Send + 'a>>;

/// What the authorization server answers a protected resource of this same deployment about one
/// access token presented for `resource` (`AsPlaneSeam::access_standing`). The answer only ever
/// narrows what the resource admits: a live token still has to pass the resource's own chain
/// (signature, issuer, expiry) and its audience check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessStanding {
    /// Not a token that names this server as its issuer: the resource judges it as it judges any
    /// other issuer's.
    NotMine,
    /// This server issued it, its store still holds it, it is unexpired, and the grant's RFC 8707
    /// resource indicators name `resource` exactly (or the grant named none).
    Live,
    /// It names this server as its issuer and the server does not hold it for `resource`:
    /// revoked, expired, never issued, or granted for another resource.
    Dead,
    /// The server's store could not answer. Never an admission.
    Unavailable,
}

type AsAccessStandingFn = for<'a> fn(
    &'a Arc<dyn Any + Send + Sync>,
    &'a str,
    &'a str,
) -> Pin<Box<dyn Future<Output = AccessStanding> + Send + 'a>>;

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

    /// `(plane, presentation)`: the same judgement as `verify_dpop` (one implementation, one
    /// single-use store) for a resource that states the URL its request was received at, with
    /// the reason a presentation was not proven ([`DpopVerdict`]).
    pub prove_dpop: AsDpopProveFn,

    /// `(plane, access token, resource)`: the standing of an access token at a protected resource
    /// of this deployment, read from the server's own store ([`AccessStanding`]).
    pub access_standing: AsAccessStandingFn,
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
