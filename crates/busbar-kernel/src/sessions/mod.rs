// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Login state custody for auth BEGIN/COMPLETE (IF §12.6): the frozen contract and [`StoreLoginStates`], its
//! keeper over the configured store.

use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::{Expected, Mutation, Predicate, Request, ScopedStore};
use crate::plugin_records::store::{
    denied, envelope, expiry, label, live, opened, operation, sweep, InDoubt,
};
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
/// A state key: 32 random bytes, base64url without padding.
const KEY_BYTES: usize = 32;
const KEY_LEN: usize = 43;
const SCHEMA: &str = "busbar.login-states.v1";

/// Login states over the configured store (CoreStore), so the callback may land on any replica. Keyed by
/// (auth stamp name, auth instance name, state key) in a host-private scope of their own; each value is held
/// until `STATE_TTL_S` after its `put`, and `take` removes it under an exact predicate, so of two callbacks
/// presenting one key (on one replica or two) exactly one gets the state.
pub struct StoreLoginStates {
    store: Arc<CoreStore>,
    clock: fn() -> u64,
    in_doubt: InDoubt,
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
        Self {
            in_doubt: InDoubt::new(Arc::clone(&store)),
            store,
            clock,
        }
    }

    /// Delete expired (abandoned) login states of `auth`, at most one batch. Ok(n) = deleted. A `take` never
    /// answers an expired state; this only returns its space.
    pub async fn sweep_expired(&self, auth: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let records = self.scoped(auth)?;
        sweep(
            &self.store,
            &self.in_doubt,
            &records,
            SCHEMA,
            (self.clock)(),
        )
        .await
    }

    fn scoped(&self, auth: &Caller<'_>) -> Result<ScopedStore, RecordsDenied> {
        ScopedStore::host_private(Arc::clone(&self.store), &label(auth), [SCHEMA.to_string()])
            .and_then(|records| self.in_doubt.bind(records))
            .map_err(denied)
    }
}

/// A key `new_key` could have minted: exactly 43 base64url characters.
fn minted(key: &str) -> bool {
    key.len() == KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl LoginStates for StoreLoginStates {
    fn new_key(&self) -> Box<str> {
        use base64::Engine as _;
        use zeroize::Zeroize as _;
        let mut bytes = [0u8; KEY_BYTES];
        if busbar_contract::crypto::fill(&mut bytes).is_err() {
            // No key without randomness: the empty key is refused by `put`, so the BEGIN fails closed.
            tracing::error!("the OS randomness source failed: no login state key was minted");
            return Box::from("");
        }
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        key.into_boxed_str()
    }

    fn put<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
        state: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            if !minted(key) {
                return Err(RecordsDenied::Invalid);
            }
            if state.len() > MAX_STATE {
                return Err(RecordsDenied::TooLarge);
            }
            let records = self.scoped(auth)?;
            self.in_doubt.settle_one().await;
            let value = envelope(expiry((self.clock)(), STATE_TTL_S), state);
            let first = records.put(SCHEMA, key.as_bytes(), value).await;
            if self.in_doubt.decided(&records, first).await? {
                Ok(())
            } else {
                Err(RecordsDenied::Unavailable)
            }
        })
    }

    fn take<'a>(
        &'a self,
        auth: &'a Caller<'_>,
        key: &'a str,
    ) -> BoxFut<'a, Option<busbar_contract::secure::SecureVec>> {
        Box::pin(async move {
            if !minted(key) {
                return None;
            }
            let records = self.scoped(auth).ok()?;
            self.in_doubt.settle_one().await;
            let raw = records.get(SCHEMA, key.as_bytes()).await.ok()??;
            let request = Request {
                op: operation(&self.store).await.ok()?,
                predicates: vec![Predicate {
                    schema: SCHEMA.to_string(),
                    key: key.as_bytes().to_vec(),
                    expected: Expected::Exact(raw.clone()),
                }],
                mutations: vec![Mutation::Delete {
                    schema: SCHEMA.to_string(),
                    key: key.as_bytes().to_vec(),
                }],
            };
            let first = records.conditional_native(&request).await;
            // false: another callback took this state first.
            if !self.in_doubt.decided(&records, first).await.ok()? {
                return None;
            }
            let now = (self.clock)();
            let seal = crate::seal::lend();
            let (expires_at, state) = opened(raw.expose(&seal))?;
            if !live(expires_at, now) {
                return None;
            }
            let mut out = busbar_contract::secure::SecureVec::with_capacity(state.len()).ok()?;
            out.extend(state).ok()?;
            Some(out)
        })
    }
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
