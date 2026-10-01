// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROPPED-IN DOOR, from this crate's own side (#2; R-FIX1): with feature `cold-dropped-in` the
//! crate exports its ONE constructor through the contract's store export macro, and the boundary the
//! `cdylib`'s frozen symbols answer through — `BUSBAR_COLD_ENTRY` — opens the same store `open` does
//! and answers a store operation the way the store answers it directly.
//!
//! Only compiled under the feature (`cargo test -p busbar-store-memory --features cold-dropped-in`): a
//! build that links this crate registers `linked::STORE` and carries no door. That the `dlopen`ed
//! `cdylib` folds every store operation byte-identically to the linked row is the loader's both-ways
//! proof; this file pins the door itself.

#![cfg(feature = "cold-dropped-in")]

use busbar_contract::abi::cold::{StoreRequest, STATUS_OK};
use busbar_contract::records::VirtualKey;
use busbar_store_memory::BUSBAR_COLD_ENTRY as DOOR;

/// One `busbar_call` over the door, answering the response JSON (the envelope's `result` when the
/// boundary wraps it).
fn call(handle: *mut std::ffi::c_void, req: &StoreRequest) -> serde_json::Value {
    let req = serde_json::to_vec(req).expect("encode the request");
    let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
    // SAFETY: a live handle from the door's own `open`, a valid request buffer and two out slots.
    let status = unsafe { (DOOR.call)(handle, req.as_ptr(), req.len(), &mut out, &mut out_len) };
    // SAFETY: the door published `out_len` bytes at `out`, which it owns until `free`.
    let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
    // SAFETY: handing the door back the buffer it allocated, once.
    unsafe { (DOOR.free)(out, out_len) };
    assert_eq!(status, STATUS_OK, "{}", String::from_utf8_lossy(&bytes));
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("response JSON");
    v.get("result").cloned().unwrap_or(v)
}

#[test]
fn the_dropped_in_door_opens_the_crates_own_store_and_answers_as_it_does() {
    // SAFETY: the kind symbol answers a `'static` NUL-terminated string.
    let kind = unsafe { std::ffi::CStr::from_ptr((DOOR.kind)().cast()) };
    assert_eq!(kind.to_str(), Ok("store"));
    // SAFETY: the handshake symbol takes no arguments and touches no state.
    let abi = unsafe { (DOOR.abi)() };
    assert_eq!(abi, busbar_contract::abi::sdk::transport_version());

    let (mut handle, mut err, mut err_len) = (std::ptr::null_mut(), std::ptr::null_mut(), 0usize);
    // SAFETY: a valid config buffer and three out slots, as the ABI states.
    let status = unsafe { (DOOR.open)(b"{}".as_ptr(), 2, &mut handle, &mut err, &mut err_len) };
    assert_eq!(status, STATUS_OK);
    assert!(!handle.is_null());

    let key = VirtualKey {
        id: "vk_door".into(),
        generation_hash: "binding:vk_door:1".into(),
        name: "door".into(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    assert_eq!(call(handle, &StoreRequest::PutKey(key.clone())), "Unit");
    let through_door = call(handle, &StoreRequest::GetKey(key.id.clone()));

    let direct = busbar_store_memory::open("{}").expect("the linked constructor");
    direct.put_key(&key).expect("put_key");
    let direct = direct.get_key(&key.id).expect("get_key");
    assert_eq!(through_door, serde_json::json!({ "Key": direct }));

    // SAFETY: the handle the door's `open` published, closed once.
    unsafe { (DOOR.close)(handle) };
}
