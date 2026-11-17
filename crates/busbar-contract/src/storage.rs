// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned allocation credits shared by pre-request connections and admitted responses.
//! A source is a resource capability supplied by trusted assembly, not an authentication proof.
//! Credits account requested backing storage; allocator and self-owning control overhead are
//! outside this contract. Keep storage before its credit in destruction order.

use std::fmt;
use std::sync::Arc;

/// The account could not reserve the requested storage without exceeding its capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageDenied;

impl fmt::Display for StorageDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("storage capacity is unavailable")
    }
}

impl std::error::Error for StorageDenied {}

/// The trusted host's underlying account. Application consumers receive a [`StorageSource`].
///
/// Implementations must reserve atomically or leave usage unchanged, and release precisely the
/// conserved quantity. Both methods must be free of allocation, recording, external locks and
/// waits. An implementation retains its immutable class and original admission owner, if any.
pub trait StorageAccount: Send + Sync {
    /// Reserve before allocation; overflow or capacity refusal must not change usage.
    fn try_reserve(&self, bytes: usize) -> Result<(), StorageDenied>;

    /// Return a successfully reserved quantity, at most once and after its storage retires.
    fn release(&self, bytes: usize);
}

/// Cloneable access to one immutable account origin; holding a source grants no bytes.
#[derive(Clone)]
pub struct StorageSource {
    account: Arc<dyn StorageAccount>,
}

impl StorageSource {
    /// Bind the actual host account. This is an internal assembly seam, not proof of trust.
    #[must_use]
    pub fn new(account: Arc<dyn StorageAccount>) -> Self {
        Self { account }
    }

    /// Acquire move-only credit before requesting the corresponding backing allocation.
    /// Creating a credit clones its account reference without allocating a new owner.
    pub fn try_reserve(&self, bytes: usize) -> Result<StorageCredit, StorageDenied> {
        self.account.try_reserve(bytes)?;
        Ok(StorageCredit {
            bytes,
            source: self.clone(),
        })
    }
}

impl fmt::Debug for StorageSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageSource").finish_non_exhaustive()
    }
}

/// A conserved requested-storage reservation. Moving it transfers capacity and origin custody.
/// There is no constructor, disarm operation or independent clone of an existing reservation.
#[derive(Debug)]
pub struct StorageCredit {
    bytes: usize,
    source: StorageSource,
}

impl StorageCredit {
    /// The requested allocation bytes owned by this credit, including retained spare capacity.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes
    }

    /// Whether this credit owns no bytes. Even an empty credit retains its origin.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Reserve an independent allocation from the same immutable origin.
    #[must_use]
    pub fn source(&self) -> &StorageSource {
        &self.source
    }

    /// Transfer a portion of already reserved capacity without changing total usage.
    pub fn split(&mut self, bytes: usize) -> Result<Self, StorageDenied> {
        if bytes > self.bytes {
            return Err(StorageDenied);
        }
        self.bytes -= bytes;
        Ok(Self {
            bytes,
            source: self.source.clone(),
        })
    }

    /// Combine only the same originating owner, preserving rejected credit intact.
    /// Sharing a process or class is insufficient: different request counts must stay alive.
    pub fn try_merge(&mut self, mut other: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.source.account, &other.source.account) {
            return Err(other);
        }
        let Some(combined) = self.bytes.checked_add(other.bytes) else {
            return Err(other);
        };
        self.bytes = combined;
        other.bytes = 0;
        Ok(())
    }
}

impl Drop for StorageCredit {
    fn drop(&mut self) {
        self.source.account.release(self.bytes);
    }
}
