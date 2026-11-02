// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plane_driver::registry::{publish_planes, PlaneDecl};
use std::sync::{Mutex, MutexGuard};

static REGISTERED: Mutex<Vec<&'static PlaneDecl>> = Mutex::new(Vec::new());

static SERIAL: Mutex<()> = Mutex::new(());

fn lock<T>(m: &'static Mutex<T>) -> MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn register_test_plane(decl: &'static PlaneDecl) {
    let _serial = lock(&SERIAL);
    let mut reg = lock(&REGISTERED);
    if !reg.iter().any(|d| d.key == decl.key) {
        reg.push(decl);
        publish_planes(&reg);
    }
}

#[must_use = "the registry stays isolated only while the guard is alive"]
pub struct TestRegistryIsolation {
    _serial: MutexGuard<'static, ()>,
    saved: Vec<&'static PlaneDecl>,
}

impl TestRegistryIsolation {
    pub fn empty() -> Self {
        Self::seeded(&[])
    }

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

#[must_use]
pub fn empty_boot_context() -> crate::plane_driver::registry::BootCtx {
    crate::plane_driver::registry::BootCtx {
        store: None,
        app: None,
        handle: None,
        card_issuer: None,
    }
}
