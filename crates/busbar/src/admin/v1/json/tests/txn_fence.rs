//! THE COMPILE FENCE. This file is a NEGATIVE test: it must FAIL to compile.
//!
//! It is behind the `txn-fence-red` cargo feature and is never part of a normal build.
//! `scripts/txn-fence.sh` compiles it and asserts the compiler REJECTS it; a green compile is a
//! failed test, because it would mean the structural half of "blocking-under-the-lock is
//! impossible" had regressed.
//!
//! WHY THIS SHAPE AND NOT `trybuild`. `trybuild` (and `compile_fail` doctests) build the ui case as
//! a crate that `use`s the crate under test, which requires a LIBRARY target. `busbar` is a
//! bin-only crate (`src/main.rs` is the crate root), and `config_transaction`/`Txn` are
//! `pub(crate)`, so no external test crate can name them. Compiling this module INSIDE the real
//! crate, against the real `Txn`, is strictly stronger than a `trybuild` case would be: it type-
//! checks the actual choke point rather than a copy of its signature.
//!
//! THREE ways a body could reach a blocking store call are attempted below. Each must be rejected:
//!
//! 1. `store.list_keys()` — there is no `store` binding in a transaction body, and `Txn` exposes no
//!    accessor that yields one. `Txn` hands out a snapshot and two closure-registering methods, and
//!    nothing else.
//! 2. `txn.store()` / `txn.governance()` — no such method exists; the store is unreachable from the
//!    async side by construction, not by convention.
//! 3. `.await` inside the body — the body is a plain `FnOnce`, so awaiting (the network-under-lock
//!    class, and the way a hand-rolled site would smuggle blocking work back in) is a type error.

use std::sync::Arc;

use super::super::{config_transaction, Outcome};
use crate::admin::v1::contract::AdminError;
use crate::state::AppHandle;

/// (1) + (2): the body has no store in scope and `Txn` yields none.
pub(crate) async fn fence_no_store_in_scope(handle: &Arc<AppHandle>) -> Result<usize, AdminError> {
    config_transaction(handle, |txn| {
        // ERROR: cannot find value `store` in this scope.
        let n = store.list_keys().unwrap().len();
        // ERROR: no method named `store` found for reference `&Txn<'_>`.
        let _also = txn.store().list_keys();
        Ok(Outcome::Value(n))
    })
    .await
}

/// (3): the body is synchronous, so it cannot hold the lock across an await.
pub(crate) async fn fence_no_await_in_body(handle: &Arc<AppHandle>) -> Result<(), AdminError> {
    config_transaction(handle, |txn| {
        // ERROR: `await` is only allowed inside `async` functions and blocks.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        Ok(txn.done(()))
    })
    .await
}
