// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STORE'S SETTINGS CHECK (ARCHITECT, PORT-STORE-SQLITE findings (1) and (2)): `validate` only
//! PARSES (it never opens, connects to or migrates a store, so `--validate` leaves the operator's
//! database untouched), and a refusal's own text reaches the operator verbatim, as 1.5.5's did.

use std::sync::Arc;

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::store::OpId;

use crate::both_ways::store_fixture::MemoryStore;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin};
use crate::store_v3::wrap::{Hooks, Wrapped};
use crate::store_v3::LoadedStore;

/// The build's store, with a file-store-shaped settings check and a count of its opens.
struct Picky;

/// The store's own refusal of a non-string `db_path`, in the shape 1.5.5's file store wrote it
/// (`invalid <store> plugin config: <why>`); the operator must read these words, verbatim.
const REFUSAL: &str = "invalid picky plugin config: `db_path` must be a string, got 5";

thread_local! {
    static OPENS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn parse(settings: &[u8]) -> Result<(), String> {
    match serde_json::from_slice::<serde_json::Value>(settings) {
        Ok(v) if v.get("db_path").is_some_and(|p| !p.is_string()) => Err(REFUSAL.to_string()),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("invalid picky plugin config: {e}")),
    }
}

impl Hooks for Picky {
    fn validate(settings: &[u8]) -> Result<(), String> {
        parse(settings)
    }
    fn open(settings: &[u8], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        OPENS.with(|n| n.set(n.get() + 1));
        parse(settings)?;
        Ok(Arc::new(MemoryStore::new()))
    }
}

mod picky {
    busbar_contract::store_door!(super::Wrapped<super::Picky>, "picky", "0", 64);
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x7a11,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn load() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(picky::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the door loads");
    (p, d)
}

#[test]
fn a_store_refusal_reaches_the_operator_in_its_own_words() {
    let (p, d) = load();
    let e = LoadedStore::open(p, d, br#"{"db_path":5}"#, mint).expect_err("refused");
    // 1.5.5's open-failure line, the store's own words verbatim after it.
    assert_eq!(
        e,
        format!("plugin 'picky' open failed: {REFUSAL}"),
        "the 1.5.5 words, verbatim"
    );
}

#[test]
fn validate_parses_and_never_opens_the_store() {
    let (p, _) = load();
    let opens = || OPENS.with(std::cell::Cell::get);
    let before = opens();
    assert_eq!(
        LoadedStore::validate(&p, br#"{"db_path":"/var/lib/busbar.db"}"#),
        Ok(())
    );
    assert_eq!(
        LoadedStore::validate(&p, br#"{"db_path":5}"#),
        Err(REFUSAL.to_string())
    );
    assert_eq!(opens(), before, "validate opened the store");
}
