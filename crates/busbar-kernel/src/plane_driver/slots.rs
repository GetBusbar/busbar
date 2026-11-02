// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ops::Deref;
use std::sync::Arc;

pub trait PlaneSlots {
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>>;

    fn as_any(&self) -> &dyn std::any::Any;
}

pub trait ContainerGateSink: PlaneSlots {
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    );
}

impl<P> PlaneSlots for P
where
    P: Deref,
    P::Target: PlaneSlots,
{
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        (**self).plane_slot(key)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        (**self).as_any()
    }
}

pub fn runtime_slot_key(plane_key: &str) -> &'static str {
    static INTERNED: std::sync::Mutex<std::collections::BTreeMap<String, &'static str>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let composed = format!("{plane_key}:runtime");
    let mut interned = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(k) = interned.get(&composed) {
        return k;
    }
    let leaked: &'static str = Box::leak(composed.clone().into_boxed_str());
    interned.insert(composed, leaked);
    leaked
}
