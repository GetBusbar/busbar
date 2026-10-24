// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE OPENED INSTANCE PER KEY, OPENED OUTSIDE THE LOCK (`BUSBAR-1.6.0.md` THE DESIGN §11.13 M1:
//! no plugin code, `dlopen` and `open` included, runs under a host lock).
//!
//! A host that shares one opened plugin instance per key (a secret module's shared instance, an
//! auth plugin's outbound instance per binding) keeps them in a map behind a lock. Opening one is
//! plugin code: binding its door, its `open` crossing. Made under the map's lock, a slow or
//! wedged open would hold every other caller of the map behind it — every other key's lookups
//! included — and a plugin that reached back into the host from inside its `open` would relock it
//! on its own thread.
//!
//! [`OpenOnce`] looks the key up under the lock, lets the lock go to open, and re-takes it only to
//! swap the opened instance in. Two first callers of one key may both open; the first to finish
//! is kept, and every caller after it answers that one. The other's instance is dropped, after
//! the lock is let go (its own drop may cross into the plugin to close it).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};

/// One opened instance per key; see the module docs.
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
    /// No instance opened yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The instance held under `key`, if one is.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.lock().get(key).cloned()
    }

    /// The instance under `key`: the one held, else the one `open` makes, with the lock let go.
    /// The flag is `true` when this call's instance is the one installed (the caller then starts
    /// whatever runs once per instance).
    ///
    /// # Errors
    ///
    /// `open`'s; nothing is installed.
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
