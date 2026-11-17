// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ops::Deref;
use std::sync::Arc;

pub trait PlaneSlots {
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>>;

    fn as_any(&self) -> &dyn std::any::Any;
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
    // Keyed by the plane key itself: the leaked `<plane_key>:runtime` string's own prefix, so a hit
    // composes nothing.
    static INTERNED: std::sync::Mutex<std::collections::BTreeMap<&'static str, &'static str>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let mut interned = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(k) = interned.get(plane_key) {
        return k;
    }
    let leaked = crate::cold::runtime_slot_key_first(plane_key);
    interned.insert(&leaked[..plane_key.len()], leaked);
    leaked
}
