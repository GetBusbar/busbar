// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::core_routes::CoreRouter;
use busbar_contract::SecretRef;

type AsPlaneBuildFn = fn(
    &serde_yaml::Value,
    Vec<(String, String)>,
    Vec<String>,
    Option<&Arc<dyn Any + Send + Sync>>,
    Option<Arc<dyn busbar_contract::store_calls::StoreCalls>>,
) -> Result<Arc<dyn Any + Send + Sync>, String>;

type AsPlaneCheckFn = fn(&serde_yaml::Value) -> Result<Vec<(String, SecretRef)>, String>;

pub struct DpopPresentation {
    pub method: String,

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

type AsDpopVerifyFn =
    fn(&Arc<dyn Any + Send + Sync>, DpopPresentation) -> Pin<Box<dyn Future<Output = bool> + Send>>;

pub struct AsPlaneSeam {
    pub check: AsPlaneCheckFn,

    pub build: AsPlaneBuildFn,

    pub mount: fn(CoreRouter, Option<&Arc<dyn Any + Send + Sync>>) -> CoreRouter,

    pub verify_dpop: AsDpopVerifyFn,
}

static SEAM: OnceLock<AsPlaneSeam> = OnceLock::new();

pub fn install_as_plane_seam(seam: AsPlaneSeam) {
    assert!(
        SEAM.set(seam).is_ok(),
        "install_as_plane_seam called twice: there is one composition root, and it registers once"
    );
}

pub(crate) fn seam() -> Option<&'static AsPlaneSeam> {
    SEAM.get()
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
