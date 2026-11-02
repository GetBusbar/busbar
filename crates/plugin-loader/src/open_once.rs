// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};

pub struct OpenOnce<K, V> {
    map: Mutex<HashMap<K, Arc<V>>>,
}

impl<K, V> Default for OpenOnce<K, V> {
    fn default() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, V> std::fmt::Debug for OpenOnce<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenOnce").finish_non_exhaustive()
    }
}

impl<K: Eq + Hash + Clone, V> OpenOnce<K, V> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.lock().get(key).cloned()
    }

    pub fn get_or_open<E>(
        &self,
        key: &K,
        open: impl FnOnce() -> Result<V, E>,
    ) -> Result<(Arc<V>, bool), E> {
        if let Some(held) = self.get(key) {
            return Ok((held, false));
        }
        let fresh = Arc::new(open()?);
        let (kept, spare) = {
            let mut map = self.lock();
            match map.get(key) {
                Some(held) => (Arc::clone(held), Some(fresh)),
                None => {
                    map.insert(key.clone(), Arc::clone(&fresh));
                    (fresh, None)
                }
            }
        };
        let installed = spare.is_none();
        drop(spare);
        Ok((kept, installed))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, Arc<V>>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "tests/open_once_tests.rs"]
mod tests;
