// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INSTANCE NUMBERING NEVER MINTS `0`, AND IS THE HANDLE'S. `InstanceId(0)` is the composition
//! root's own identity on the one connector (the authorization server's needs,
//! `root::connector::ROOT_OWNER`); a plugin instance minted `0` would open and close connections on
//! that table as the root. An instance's identity is its handle's id, so a table's wake names the
//! entry of the caller it parked for, and the root's own names none.

use busbar_contract::conn::InstanceId;

use crate::dispatch::handle::{instance_id, mint, supplier_of};
use crate::dispatch::ticket::InstanceWake;

#[test]
fn an_instance_identity_is_never_zero_and_names_its_own_entry() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let wake: &'static InstanceWake = Box::leak(Box::default());
        let id = instance_id(mint(wake).expect("the host mints a handle"));
        assert_ne!(id, InstanceId(0), "an instance was numbered as the root");
        assert!(seen.insert(id), "{id:?} was numbered twice");
        assert!(
            supplier_of(id).is_some_and(|w| std::ptr::eq(w, wake)),
            "{id:?} names another entry"
        );
    }
}

#[test]
fn the_roots_identity_and_an_unminted_one_name_no_entry() {
    assert!(
        supplier_of(InstanceId(0)).is_none(),
        "the root's own identity names an instance"
    );
    assert!(
        supplier_of(InstanceId(u64::MAX)).is_none(),
        "an identity the host never minted names an instance"
    );
}
