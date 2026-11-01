// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S FORWARD-COMPATIBILITY CASE (open160 ST14), proven on fixture stores: a durable
//! store that refuses a schema newer than its build passes; one that opens over it anyway (as the
//! postgres, mysql and valkey stores did until their review) is refused; a durable store stating no
//! way to stamp its schema is refused; an ephemeral store keeps no schema and has nothing to prove.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::abi::sdk::conn::Host;

use super::{store_newer_schema, Subject};
use crate::both_ways::store_fixture::MemoryStore;
use crate::store_v3::wrap::{Hooks, Wrapped};

/// The schema version this fixture build writes.
const BUILD: u32 = 3;

/// The fixtures' "backend": each namespace's recorded schema version.
static SCHEMA: Mutex<BTreeMap<String, u32>> = Mutex::new(BTreeMap::new());

fn namespace(settings: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(settings).expect("JSON settings");
    v["ns"].as_str().expect("settings.ns").to_string()
}

/// Open over `settings`: record this build's schema in a fresh namespace, then read it back.
fn opened(settings: &[u8], refuse_newer: bool) -> Result<Arc<MemoryStore>, String> {
    let mut m = SCHEMA.lock().unwrap_or_else(PoisonError::into_inner);
    let found = *m.entry(namespace(settings)).or_insert(BUILD);
    if refuse_newer && found > BUILD {
        return Err(format!(
            "the schema is version {found}, newer than this build's {BUILD}"
        ));
    }
    Ok(Arc::new(MemoryStore::new()))
}

/// A durable store that keeps the rule.
struct Honest;
impl Hooks for Honest {
    const EPHEMERAL: bool = false;
    fn open(settings: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        opened(settings, true)
    }
}

/// A durable store that opens over whatever schema it finds.
struct Lax;
impl Hooks for Lax {
    const EPHEMERAL: bool = false;
    fn open(settings: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        opened(settings, false)
    }
}

mod honest {
    busbar_contract::store_door!(super::Wrapped<super::Honest>, "honest", "0", 64);
}
mod lax {
    busbar_contract::store_door!(super::Wrapped<super::Lax>, "lax", "0", 64);
}

/// The fixtures' stamp: the namespace's schema one newer than the build.
fn stamp(ns: &str, _: &[u8]) {
    SCHEMA
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(ns.to_string(), BUILD + 1);
}

const INPUTS: &str = r#"{"settings": {"ns": "{fold}"}}"#;

fn subject(door: busbar_contract::abi::mechanism::door::DoorFn) -> Subject {
    Subject::new(door, "no_cdylib", INPUTS)
}

fn refused(s: &Subject) -> bool {
    catch_unwind(AssertUnwindSafe(|| store_newer_schema(s))).is_err()
}

#[test]
fn a_durable_store_refusing_a_newer_schema_passes() {
    store_newer_schema(&subject(honest::door).with_newer_schema(stamp));
}

#[test]
fn a_durable_store_opening_over_a_newer_schema_is_refused() {
    assert!(refused(&subject(lax::door).with_newer_schema(stamp)));
}

#[test]
fn a_durable_store_stating_no_stamp_is_refused() {
    assert!(refused(&subject(honest::door)));
}

#[test]
fn an_ephemeral_store_keeps_no_schema_to_stamp() {
    store_newer_schema(&subject(crate::both_ways::store_fixture::door));
}
