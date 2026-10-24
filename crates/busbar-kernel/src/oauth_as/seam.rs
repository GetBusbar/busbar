// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM the kernel's router and app build call through to reach the authorization server's
//! runtime object and mount its routes, without naming its crate: the reverse edge Cargo refuses
//! (`busbar-core-oauth2` depends on `busbar-kernel`, never the other way).
//!
//! Registered once by the composition root, the discipline `plane::registry::install_planes`
//! documents for the registry planes. `oauth_as` is a SINGLETON (no named-definition map, no
//! scope-kind grants, no admin CRUD verbs), so it rides this small bespoke fn-pointer set rather
//! than the full `PlaneDecl` vocabulary, which would force several of its fields to fictions here.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::core_routes::CoreRouter;
use busbar_contract::SecretRef;

/// The plane's runtime-build entry point (the type of [`AsPlaneSeam::build`]), named as an alias so
/// the fn-pointer signature reads once here rather than inline in the struct field. Behaviour is
/// identical to the inline type; the alias exists only to keep the field legible (and satisfy
/// `clippy::type_complexity`).
type AsPlaneBuildFn = fn(
    &serde_yaml::Value,
    Vec<(String, String)>,
    Vec<String>,
    Option<&Arc<dyn Any + Send + Sync>>,
    Option<Arc<dyn busbar_contract::store_calls::StoreCalls>>,
) -> Result<Arc<dyn Any + Send + Sync>, String>;

/// The plane's config check (the type of [`AsPlaneSeam::check`]).
type AsPlaneCheckFn = fn(&serde_yaml::Value) -> Result<Vec<(String, SecretRef)>, String>;

/// One RFC 9449 s7 presentation at a protected resource: the request line, the token from
/// `Authorization: DPoP <token>`, and the one `DPoP` proof header.
pub struct DpopPresentation {
    pub method: String,
    /// The request path; the plane makes the proof's `htu` from its own origin and this.
    pub path: String,
    pub token: String,
    pub proof: String,
}

/// An `oauth_as:` block its owner has ACCEPTED ([`AsPlaneSeam::check`]), carried by `RootCfg`: the
/// opaque block itself, and the secret references the owner listed in it. `resolve` makes one only
/// from a block that passed, so holding one means the owner already validated it.
#[derive(Debug)]
pub struct CheckedAsBlock {
    pub block: serde_yaml::Value,
    pub secret_refs: Vec<(String, SecretRef)>,
}

/// The plane's DPoP verification (the type of [`AsPlaneSeam::verify_dpop`]).
type AsDpopVerifyFn =
    fn(&Arc<dyn Any + Send + Sync>, DpopPresentation) -> Pin<Box<dyn Future<Output = bool> + Send>>;

/// The functions core calls through this seam. Every field type here is either core-owned
/// (`CoreRouter`, `SecretRef`), an opaque config value, or fully type-erased
/// (`Arc<dyn Any + Send + Sync>`), so the seam itself names no `busbar_core_oauth2` item and the
/// kernel never names the `oauth_as:` config types.
pub struct AsPlaneSeam {
    /// Hand the opaque `oauth_as:` block to its owner at config resolve: the owner parses and
    /// validates it (refusing with its own text) and returns every secret reference the block
    /// carries as `(config path, reference)`, so `--validate` and boot can resolve them.
    pub check: AsPlaneCheckFn,

    /// Build the plane's runtime object for one config generation, from the opaque `oauth_as:`
    /// block (the owner re-derives its identity), the resolved secrets keyed by the paths
    /// [`Self::check`] reported (an unresolved signing key means an ephemeral one), and this
    /// deployment's protected-resource audiences (RFC 8707 `allowed_resources`), and the PRIOR
    /// generation's object (`None` at boot): what the server holds (its records, its consent
    /// sessions, an ephemeral key) carries across the generation swap. And the deployment's
    /// configured store (its typed records and its single-use claims; `None` without one): the
    /// server keeps what it holds there, under the kernel's own record kinds, so every node on one
    /// store serves one authorization server (THE DESIGN §1, "Nodes share one store"). Also hands
    /// the plane's expired-record sweep to the kernel's one clock ([`crate::tick::on_clock`]),
    /// starting no task of its own — the seam owns the whole "how do I come alive" act, not just
    /// allocation.
    /// Returns the type-erased object `App::oauth_as` stores, or the plane's own build error
    /// rendered to a string (boot refuses with it exactly as it did when this call was inline).
    pub build: AsPlaneBuildFn,

    /// Mount the plane's routes onto the router, or return it untouched when `plane` is `None` —
    /// the zero-cost-when-off property at the routing layer, preserved unchanged by this move.
    /// `plane` is the SAME type-erased object [`Self::build`] returned; only the plane crate names
    /// its concrete type, so only it can downcast this back.
    pub mount: fn(CoreRouter, Option<&Arc<dyn Any + Send + Sync>>) -> CoreRouter,

    /// Verify a DPoP presentation at one of busbar's protected resources (`auth::dpop`): the proof
    /// (signature, `htm`, `htu`, `iat` window, `ath`), its `jti` single use, and that its key is the
    /// key the token's `cnf.jkt` names. `true` only when all hold. The authorization server owns
    /// this because it owns the key verifiers and the replay ledger; the door owns the decision.
    pub verify_dpop: AsDpopVerifyFn,
}

static SEAM: OnceLock<AsPlaneSeam> = OnceLock::new();

/// Register the authorization-server plane's seam. Called EXACTLY ONCE, by the composition root
/// (alongside `plane::registry::install_planes`), before any config is loaded. `oauth_as:` carries
/// no feature flag, so every shipped build registers this. The kernel's own test binary never links
/// `busbar-core-oauth2` (that would be the forbidden reverse edge) and so never calls this; it also
/// never configures `oauth_as:` on any `App` it builds, so an unregistered seam and an always-`None`
/// plane agree with each other there.
///
/// # Panics
/// If called more than once — one composition root, one registration, the same discipline
/// `install_planes` documents for the identical reason.
pub fn install_as_plane_seam(seam: AsPlaneSeam) {
    assert!(
        SEAM.set(seam).is_ok(),
        "install_as_plane_seam called twice: there is one composition root, and it registers once"
    );
}

/// Read the registered seam, or `None` when this binary never linked `busbar-core-oauth2`.
pub(crate) fn seam() -> Option<&'static AsPlaneSeam> {
    SEAM.get()
}

/// THE WORK HANDED TO THE KERNEL'S ONE CLOCK (`crate::tick::on_clock`), held weakly: the
/// authorization server's expired-record sweep, one per live generation. The owner keeps the work
/// alive, never the clock, so letting a generation go takes its sweep off the clock.
static CLOCK_WORK: std::sync::Mutex<Vec<std::sync::Weak<dyn crate::tick::ClockWork>>> =
    std::sync::Mutex::new(Vec::new());

/// Hold `work` on the clock (`crate::tick::on_clock`).
pub(crate) fn hold_clock_work(work: std::sync::Weak<dyn crate::tick::ClockWork>) {
    let mut held = CLOCK_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.retain(|w| w.strong_count() > 0);
    held.push(work);
}

/// Every live work on the clock, for one beat (`crate::tick::beat`); work let go leaves here.
pub(crate) fn clock_work() -> Vec<Arc<dyn crate::tick::ClockWork>> {
    let mut held = CLOCK_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.retain(|w| w.strong_count() > 0);
    held.iter().filter_map(std::sync::Weak::upgrade).collect()
}
