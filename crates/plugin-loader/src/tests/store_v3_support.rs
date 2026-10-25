// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the store test files share: an `op_id` allocator per caller ([`op_ids!`]), a
//! current-thread runtime ([`block_on`]) and a store door loaded on a dispatcher ([`load`]).

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, ConnTable, Dispatcher, LinkedRow, NoSink, Plugin};

/// `$vis fn $name() -> OpId`, an `op_id` allocator over node `$node`: one counter, as the kernel's
/// `door::op_id` is.
macro_rules! op_ids {
    ($vis:vis $name:ident, $node:expr) => {
        $vis fn $name() -> busbar_contract::abi::store::OpId {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            busbar_contract::abi::store::OpId::from_parts(
                $node,
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            )
        }
    };
}
pub(crate) use op_ids;

/// `f`, run to completion on a fresh current-thread runtime.
pub(crate) fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// `door` loaded as `the-instance` on `d`, at `max_inflight_cap`, over `conns`.
pub(crate) fn load(
    door: DoorFn,
    d: &Dispatcher,
    max_inflight_cap: u32,
    conns: ConnTable,
) -> Plugin<Store> {
    load_linked::<Store>(
        &LinkedRow::of(door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns,
        },
    )
    .expect("the store door loads")
}
