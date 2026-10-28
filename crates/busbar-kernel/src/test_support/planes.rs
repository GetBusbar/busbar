// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST BINARY'S PLANE REGISTRATIONS. A test registers a plane's `&'static PlaneDecl` the way the
//! composition root installs one in production; each change of the registered set is published as
//! the process plane list ([`crate::plane_driver::registry::publish_planes`]), so a plane registered
//! by any test is visible to every later read, whatever the test order.

use crate::plane_driver::registry::{publish_planes, PlaneDecl};
use std::sync::{Mutex, MutexGuard};

/// The planes registered so far, in registration order.
static REGISTERED: Mutex<Vec<&'static PlaneDecl>> = Mutex::new(Vec::new());

/// Held by a [`TestRegistryIsolation`] for its whole life and taken by every
/// [`register_test_plane`], so a sibling test's registration waits rather than leaking into an
/// isolated set. Lock order: this, then [`REGISTERED`].
static SERIAL: Mutex<()> = Mutex::new(());

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register `decl` into the process plane list. Idempotent by plane key.
pub fn register_test_plane(decl: &'static PlaneDecl) {
    let _serial = lock(&SERIAL);
    let mut reg = lock(&REGISTERED);
    if !reg.iter().any(|d| d.key == decl.key) {
        reg.push(decl);
        publish_planes(&reg);
    }
}

/// ISOLATE THE PROCESS PLANE LIST for one test. RAII: construction takes the serial lock and
/// replaces the registered planes with exactly the seeded set (first-wins by key); drop restores
/// the set it replaced. While it lives, a [`register_test_plane`] on another thread waits. A reader
/// on another thread reads the isolated list.
#[must_use = "the registry stays isolated only while the guard is alive"]
pub struct TestRegistryIsolation {
    _serial: MutexGuard<'static, ()>,
    saved: Vec<&'static PlaneDecl>,
}

impl TestRegistryIsolation {
    /// An isolation with no registered plane.
    pub fn empty() -> Self {
        Self::seeded(&[])
    }

    /// An isolation whose registered planes are exactly `decls` (first-wins by key).
    pub fn seeded(decls: &[&'static PlaneDecl]) -> Self {
        let serial = lock(&SERIAL);
        let mut reg = lock(&REGISTERED);
        let saved = std::mem::take(&mut *reg);
        for decl in decls {
            if !reg.iter().any(|d| d.key == decl.key) {
                reg.push(decl);
            }
        }
        publish_planes(&reg);
        drop(reg);
        Self {
            _serial: serial,
            saved,
        }
    }
}

impl Drop for TestRegistryIsolation {
    fn drop(&mut self) {
        let mut reg = lock(&REGISTERED);
        *reg = std::mem::take(&mut self.saved);
        publish_planes(&reg);
    }
}
