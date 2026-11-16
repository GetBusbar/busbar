// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Login state custody for auth BEGIN/COMPLETE (IF §12.6): the frozen contract and [`StoreLoginStates`], its
//! keeper over the configured store.

use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::persistence::facade::CoreStore;
use crate::plugin_records::RecordsDenied;

/// Auth login STATE custody. Core generates state_key (32 random bytes, base64url) per BEGIN, stores the STATE
/// blob durably (CoreStore, so the callback may land on another replica) under (auth plugin, auth instance
/// **name**, state_key) for ≤ 600 s, and takes it exactly once on the callback's `state` param.
pub trait LoginStates: Send + Sync + 'static {
    fn new_key(&self) -> Box<str>;
    fn put<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
        state: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    // W0-ABI: the IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (LR-094); the stub uses its
    // replacement `busbar_contract::secure::SecureVec`.
    fn take<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>>;
}

/// How long a login STATE waits for its callback (IF §12.6: ≤ 600 s).
pub const STATE_TTL_S: u64 = 600;
/// The largest STATE blob kept (`RecordsDenied::TooLarge` above it).
pub const MAX_STATE: usize = 64 * 1024;

/// Login states over the configured store (CoreStore). W1-K5 red: held as `todo!()`.
pub struct StoreLoginStates {
    store: Arc<CoreStore>,
    clock: fn() -> u64,
}

impl StoreLoginStates {
    /// Login states over `store`, timed by the wall clock.
    #[must_use]
    pub fn new(store: Arc<CoreStore>) -> Self {
        Self::with_clock(store, crate::store::now)
    }

    /// Login states over `store`; `clock` answers UNIX seconds.
    #[must_use]
    pub fn with_clock(store: Arc<CoreStore>, clock: fn() -> u64) -> Self {
        Self { store, clock }
    }

    /// Delete expired (abandoned) login states of `auth`, at most one batch.
    pub async fn sweep_expired(&self, auth: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let _ = (auth, &self.store, self.clock);
        todo!("W1-K5")
    }
}

impl LoginStates for StoreLoginStates {
    fn new_key(&self) -> Box<str> {
        todo!("W1-K5")
    }

    fn put<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
        state: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        let _ = (auth, key, state);
        Box::pin(async move { held::<Result<(), RecordsDenied>>() })
    }

    fn take<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>> {
        let _ = (auth, key);
        Box::pin(async move { held::<Option<busbar_contract::secure::SecureVec>>() })
    }
}

/// W1-K5 red: an operation not written yet.
fn held<T>() -> T {
    todo!("W1-K5")
}

/// Every consumer that holds the one login-state owner by `Arc` (hosted login on every listener) reaches it
/// through this impl.
impl<L: LoginStates + ?Sized> LoginStates for Arc<L> {
    fn new_key(&self) -> Box<str> {
        (**self).new_key()
    }
    fn put<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
        state: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        (**self).put(auth, key, state)
    }
    fn take<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>> {
        (**self).take(auth, key)
    }
}

#[cfg(test)]
mod tests;
