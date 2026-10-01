// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::plane::{CLAIM_EXACT, ROUTE_PUBLIC};

/// The bytes an `AbiStr` names, as the host reads them.
fn read(s: AbiStr) -> Vec<u8> {
    if s.ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: the SDK's arena holds `len` bytes at `ptr` while the generation is live.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec()
}

/// A snapshot built from values the "plugin" owns and drops right after publishing.
fn publish_then_drop(gens: &Generations<PlaneSnapshot>, generation: u64) -> *const PlaneSnapshot {
    let mut verb = String::from("POST");
    let mut target = format!("/echo/{generation}");
    let mut openapi = br#"{"paths":{}}"#.to_vec();
    let spec = SnapshotSpec {
        claims: vec![ClaimSpec::new(&verb, &target, "door", CLAIM_EXACT)],
        admin_routes: vec![AdminRouteSpec::new("GET", "/door/status", ROUTE_PUBLIC)],
        openapi: Some(openapi.clone()),
        audience: Some("aud".to_string()),
        resource_metadata: None,
    };
    let p = gens.publish(generation, &spec);
    // Everything the plugin owned is overwritten and dropped.
    verb.replace_range(.., "XXXX");
    target.clear();
    openapi.iter_mut().for_each(|b| *b = 0);
    drop((spec, verb, target, openapi));
    p
}

#[test]
fn a_published_snapshot_outlives_every_source_the_plugin_dropped() {
    let gens: Generations<PlaneSnapshot> = Generations::new();
    let p = publish_then_drop(&gens, 7);
    // Churn the allocator so freed memory would be reused.
    let churn: Vec<Vec<u8>> = (0..256).map(|i| vec![i as u8; 32]).collect();
    // SAFETY: the SDK holds the snapshot until `retire(7)`.
    let snap = unsafe { &*p };
    assert_eq!(snap.generation, 7);
    assert_eq!(snap.size as usize, std::mem::size_of::<PlaneSnapshot>());
    assert_eq!(snap.claims_len, 1);
    // SAFETY: as above; the list is in the same arena.
    let claim = unsafe { &*snap.claims };
    assert_eq!(read(claim.verb), b"POST");
    assert_eq!(read(claim.target), b"/echo/7");
    assert_eq!(read(claim.carrier), b"door");
    assert_eq!(claim.flags, CLAIM_EXACT);
    // SAFETY: as above.
    let route = unsafe { &*snap.admin_routes };
    assert_eq!(read(route.target), b"/door/status");
    assert_eq!(route.flags, ROUTE_PUBLIC);
    assert_eq!(snap.openapi.fmt, BLOB_JSON);
    // SAFETY: as above.
    let json = unsafe { std::slice::from_raw_parts(snap.openapi.ptr, snap.openapi.len) };
    assert_eq!(json, br#"{"paths":{}}"#);
    assert_eq!(read(snap.audience), b"aud");
    assert!(snap.resource_metadata.ptr.is_null());
    drop(churn);
}

#[test]
fn a_generation_is_held_until_its_own_retire() {
    let gens: Generations<PlaneSnapshot> = Generations::new();
    let one = publish_then_drop(&gens, 1);
    let _two = publish_then_drop(&gens, 2);
    assert_eq!(gens.live(), 2);
    // Publishing generation 2 did not free generation 1.
    // SAFETY: generation 1 is not retired.
    assert_eq!(read(unsafe { (*(*one).claims).target }), b"/echo/1");
    gens.retire(1);
    assert_eq!(gens.live(), 1);
    gens.retire(2);
    assert_eq!(gens.live(), 0);
}

#[test]
fn empty_lists_are_null_and_absent_fields_absent() {
    let gens: Generations<PlaneSnapshot> = Generations::new();
    // SAFETY: held until retire.
    let snap = unsafe { &*gens.publish(3, &SnapshotSpec::default()) };
    assert!(snap.claims.is_null() && snap.claims_len == 0);
    assert!(snap.admin_routes.is_null() && snap.admin_routes_len == 0);
    assert_eq!(snap.openapi.fmt, BLOB_ABSENT);
    assert!(snap.audience.ptr.is_null());
}

#[test]
fn generations_are_instance_state() {
    fn state<T: Send + Sync + 'static>() {}
    state::<Generations<PlaneSnapshot>>();
}

/// The payload a generation was published with is the newest live one's until a newer generation
/// is published; a holder keeps its own after `retire`, and `retire` drops the SDK's hold.
#[test]
fn the_current_payload_is_the_newest_live_generations_and_retire_drops_it() {
    let gens: Generations<PlaneSnapshot, String> = Generations::new();
    assert_eq!(gens.current(), None);
    gens.publish_with(1, &SnapshotSpec::default(), "one".to_string());
    let held = gens.current().expect("one is live");
    assert_eq!(*held, "one");
    // Not visible before its own publish; visible from it on.
    gens.publish_with(2, &SnapshotSpec::default(), "two".to_string());
    assert_eq!(gens.current().as_deref().map(String::as_str), Some("two"));
    assert_eq!(gens.at(1).as_deref().map(String::as_str), Some("one"));
    // Retiring the newest makes the older one current again; the request that held one keeps it.
    gens.retire(2);
    assert_eq!(gens.current().as_deref().map(String::as_str), Some("one"));
    gens.retire(1);
    assert_eq!((gens.current(), gens.at(1)), (None, None));
    assert_eq!(*held, "one");
    assert_eq!(
        std::sync::Arc::strong_count(&held),
        1,
        "retire dropped the SDK's hold"
    );
}

/// Two instances' keyed state are two maps: nothing one inserts is seen by the other.
#[test]
fn keyed_state_belongs_to_its_instance() {
    let first: Keyed<u64, String> = Keyed::new();
    let second: Keyed<u64, String> = Keyed::new();
    assert_eq!(first.insert(7, "a".to_string()), None);
    assert_eq!(second.get(&7), None);
    assert!(second.is_empty());
    assert_eq!(first.insert(7, "b".to_string()).as_deref(), Some("a"));
    assert_eq!(first.with(&7, |v| v.map(|s| s.len())), Some(1));
    assert_eq!(first.with_all(|m| m.len()), 1);
    assert_eq!(first.remove(&7).as_deref(), Some("b"));
    assert_eq!(first.len(), 0);
    fn state<T: Send + Sync + 'static>() {}
    state::<Keyed<u64, String>>();
    state::<Generations<PlaneSnapshot, String>>();
}

/// Two instances' generations are two holds: what one publishes, retires or answers as current is
/// never the other's, even under the same generation number.
#[test]
fn generations_belong_to_their_instance() {
    let first: Generations<PlaneSnapshot, String> = Generations::new();
    let second: Generations<PlaneSnapshot, String> = Generations::new();
    first.publish_with(1, &SnapshotSpec::default(), "first".to_string());
    assert_eq!(second.current(), None);
    assert_eq!(second.at(1), None);
    assert_eq!(second.live(), 0);
    second.publish_with(1, &SnapshotSpec::default(), "second".to_string());
    assert_eq!(
        first.current().as_deref().map(String::as_str),
        Some("first")
    );
    assert_eq!(
        second.current().as_deref().map(String::as_str),
        Some("second")
    );
    second.retire(1);
    assert_eq!(first.at(1).as_deref().map(String::as_str), Some("first"));
    assert_eq!((first.live(), second.live()), (1, 0));
}
