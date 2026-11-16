// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLIENT-CERT DIGESTS for the pool key (IF 13): OPEN and FETCH never resolve a certificate just to
//! look up the pool.
//!
//! Keyed by `(instance, handle)`; an entry stores the custody generation it was hashed at and the
//! SHA-256 of the value. A lookup is one shard read lock and a compare with
//! `custody.generation(caller, handle)` (one Relaxed load); a mismatch or a miss resolves through
//! custody once, hashes and stores. Unbind drops the instance's entries.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use busbar_contract::abi::sdk::digest::sha256;
use busbar_kernel::custody::{CustodyDenied, SecretCustody};
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::NeedErr;

const SHARDS: usize = 16;

type Shard = RwLock<HashMap<(u64, u32), (u64, [u8; 32])>>;

/// The digests, sharded by instance.
#[derive(Debug)]
pub struct CertDigests {
    stripes: [Shard; SHARDS],
}

impl Default for CertDigests {
    fn default() -> Self {
        CertDigests {
            stripes: std::array::from_fn(|_| RwLock::new(HashMap::new())),
        }
    }
}

/// How custody's refusal reaches a plugin: a fixed status, no text (I2).
#[must_use]
pub fn custody_err(e: CustodyDenied) -> NeedErr {
    match e {
        CustodyDenied::NotFound => NeedErr::Absent,
        CustodyDenied::Unavailable => NeedErr::Unavailable,
        CustodyDenied::ForeignHandle
        | CustodyDenied::NoSuchSecretSource
        | CustodyDenied::Cycle
        | CustodyDenied::Denied => NeedErr::Denied,
    }
}

impl CertDigests {
    fn shard(&self, instance: u64) -> &Shard {
        &self.stripes[(instance % SHARDS as u64) as usize]
    }

    fn cached(&self, instance: u64, handle: u32, generation: u64) -> Option<[u8; 32]> {
        if generation == 0 {
            return None;
        }
        let shard = self
            .shard(instance)
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        shard
            .get(&(instance, handle))
            .filter(|(g, _)| *g == generation)
            .map(|(_, d)| *d)
    }

    /// The SHA-256 of the certificate the secret `handle` holds for `who`. A cache hit resolves
    /// nothing and registers nothing.
    ///
    /// # Errors
    /// Custody's refusal, mapped to a fixed status.
    pub async fn digest<C: SecretCustody>(
        &self,
        custody: &C,
        who: &Caller<'_>,
        handle: u32,
    ) -> Result<[u8; 32], NeedErr> {
        if let Some(d) = self.cached(who.instance, handle, custody.generation(who, handle)) {
            return Ok(d);
        }
        let value = custody.resolve(who, handle).await.map_err(custody_err)?;
        let digest = sha256(&value);
        // Read the generation after the resolve: a miss bumps it, and the entry must carry the one
        // that published the value just hashed.
        let generation = custody.generation(who, handle);
        if generation != 0 {
            self.shard(who.instance)
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((who.instance, handle), (generation, digest));
        }
        Ok(digest)
    }

    /// The instance is unbound: drop its entries.
    pub fn forget(&self, instance: u64) {
        self.shard(instance)
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(i, _), _| *i != instance);
    }

    /// Entries held, over every shard.
    pub fn len(&self) -> usize {
        self.stripes
            .iter()
            .map(|s| s.read().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    /// Whether no entry is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_refusals_reach_a_plugin_as_fixed_statuses() {
        assert_eq!(custody_err(CustodyDenied::NotFound), NeedErr::Absent);
        assert_eq!(
            custody_err(CustodyDenied::Unavailable),
            NeedErr::Unavailable
        );
        for e in [
            CustodyDenied::ForeignHandle,
            CustodyDenied::NoSuchSecretSource,
            CustodyDenied::Cycle,
            CustodyDenied::Denied,
        ] {
            assert_eq!(custody_err(e.clone()), NeedErr::Denied, "{e:?}");
        }
    }

    #[test]
    fn an_entry_serves_only_its_own_generation_and_dies_with_its_instance() {
        let d = CertDigests::default();
        d.shard(3).write().unwrap().insert((3, 5), (7, [9; 32]));
        assert_eq!(d.cached(3, 5, 7), Some([9; 32]));
        assert_eq!(d.cached(3, 5, 8), None, "a rotated secret");
        assert_eq!(d.cached(3, 5, 0), None, "never resolved");
        assert_eq!(d.cached(4, 5, 7), None, "another instance");
        d.forget(3);
        assert!(d.is_empty());
    }
}
