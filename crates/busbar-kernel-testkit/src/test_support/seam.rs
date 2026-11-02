// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plane_driver::dispatch::PlaneAdmission;
use crate::plane_driver::slots::PlaneSlots;
use crate::plane_driver::EngineHost;
use std::any::Any;
use std::sync::Arc;

pub trait BuiltAppSeam: PlaneSlots {
    fn engine_host_of(app: &Arc<Self>) -> Arc<dyn EngineHost>;

    fn engine_host_value_of(app: Arc<Self>) -> impl EngineHost + 'static;

    fn router_of(app: Arc<Self>) -> axum::Router;

    fn plane_slot_mut(&mut self, key: &str) -> Option<&mut Arc<dyn Any + Send + Sync>>;

    fn refresh_scrape_gauges(&self);
}

pub fn engine_host<A: BuiltAppSeam + ?Sized>(app: &Arc<A>) -> Arc<dyn EngineHost> {
    A::engine_host_of(app)
}

pub fn engine_host_value<A: BuiltAppSeam + ?Sized>(
    app: &Arc<A>,
) -> impl EngineHost + 'static + use<A> {
    A::engine_host_value_of(Arc::clone(app))
}

pub fn build_router<A: BuiltAppSeam + ?Sized>(app: Arc<A>) -> axum::Router {
    A::router_of(app)
}

pub trait TestAppSeam {
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn Any>,
    ) -> &mut dyn Any;

    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn Any>>;

    #[allow(clippy::type_complexity)]
    fn register_plane_finalizer(&mut self, f: Box<dyn FnOnce(&mut dyn TestAppSeam)>);

    fn install_plane_runtime(&mut self, key: &'static str, rt: Arc<dyn Any + Send + Sync>);

    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str);

    fn admit_plane(&mut self, key: &'static str, admission: PlaneAdmission);

    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    );

    fn set_plane_defs_any(&mut self, plane_key: &'static str, defs: Arc<dyn Any + Send + Sync>);
}

pub trait TestAppSeamExt: TestAppSeam {
    fn plane_scratch<T: Any + Default>(&mut self, key: &'static str) -> &mut T {
        self.plane_scratch_any(key, &|| Box::<T>::default())
            .downcast_mut::<T>()
            .expect("plane_scratch key is used with one consistent type")
    }

    fn take_plane_scratch<T: Any + Default>(&mut self, key: &'static str) -> T {
        self.take_plane_scratch_any(key)
            .map(|b| *b.downcast::<T>().expect("plane_scratch key type"))
            .unwrap_or_default()
    }
}

impl<A: TestAppSeam + ?Sized> TestAppSeamExt for A {}

pub type ErrorSurfaceDriver = fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;

pub type ServedCallFramer =
    fn(&str, serde_json::Value) -> (axum::http::HeaderMap, serde_json::Value);

pub type VerifyGateReader = fn(&dyn PlaneSlots) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

/// ONE LINKED TEST PLANE'S SEAM ENTRY — plain data a plane's own test kit exports (as its
/// `testkit::TEST_SEAM` const), so a reader that needs every linked plane in its test binary loops
/// [`test_plane_seams`] instead of naming a plane crate.
#[derive(Clone, Copy)]
pub struct TestPlaneSeam {
    /// The plane's key, the dedupe identity of [`register_test_plane_seam`].
    pub name: &'static str,
    /// Install everything the composition root installs for this plane in production. Idempotent.
    pub install: fn(),
    /// This plane's error-surface driver, if it serves an admin surface with declared errors.
    pub error_surface_driver: Option<ErrorSurfaceDriver>,
    /// This plane's served-call framer, if it serves a front door a cross-plane test drives.
    pub served_call: Option<ServedCallFramer>,
    /// This plane's carried verify-gate reader, if its runtime object carries one across applies.
    pub verify_gate: Option<VerifyGateReader>,
}

static TEST_PLANE_SEAMS: std::sync::Mutex<Vec<&'static TestPlaneSeam>> =
    std::sync::Mutex::new(Vec::new());

pub fn register_test_plane_seam(seam: &'static TestPlaneSeam) {
    let mut seams = TEST_PLANE_SEAMS.lock().unwrap_or_else(|e| e.into_inner());
    if !seams.iter().any(|s| s.name == seam.name) {
        seams.push(seam);
    }
}

pub fn test_plane_seams() -> Vec<&'static TestPlaneSeam> {
    TEST_PLANE_SEAMS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}
