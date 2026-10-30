// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE'S DECLARED SECRETS ARE LENT, NOT WRITTEN INTO ITS SETTINGS (open160 ST8): a store whose
//! Statement names `password` in `secret_refs` is opened with the resolved password in
//! `OpenIn.secrets` (a `BLOB_SECRET` blob, as every other kind's `open` is), and the settings it
//! reads no longer carry it. Before, the host opened every store with no secrets, so a DSN
//! password rode the plain settings JSON.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::store::OpId;

use crate::both_ways::store_fixture::MemoryStore;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::wrap::{Hooks, Wrapped};
use crate::store_v3::LoadedStore;

/// What the store's `open` was handed: its settings.
static SEEN: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// A store that keeps what its `open` read.
struct Keeps;

impl Hooks for Keeps {
    fn open(settings: &[u8], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        SEEN.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(settings.to_vec());
        Ok(Arc::new(MemoryStore::new()))
    }
}

mod keeps {
    use busbar_contract::abi::mechanism::call::AbiStr;
    const REFS: &[AbiStr] = &[super::abi_str("password")];
    busbar_contract::store_door!(super::Wrapped<super::Keeps>, "keeps", "0", 64, secret_refs: REFS);
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x5ec7,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

#[test]
fn a_declared_store_secret_reaches_open_as_a_secret_never_in_its_settings() {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(keeps::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the door loads");
    // The settings as the kernel hands them: the declared reference already resolved in place.
    let settings = br#"{"host":"db.internal","password":"hunter2"}"#;
    let _store = LoadedStore::open(p, d, settings, mint).expect("it opens");
    let seen = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop()
        .expect("open ran");
    let read: serde_json::Value = serde_json::from_slice(&seen).expect("JSON settings");
    assert_eq!(read["host"], "db.internal", "the plain settings stay");
    assert!(
        read.get("password").is_none(),
        "the declared secret rode the plain settings `open` reads: {read}"
    );
}
