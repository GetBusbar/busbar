// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROPPED-IN TRANSPORT DOOR THROUGH THE REGISTRY: the in-tree transport fixture's `cdylib`, signed
//! first-party into a `plugins/` directory, is scanned, trusted, staged, `dlopen`ed once and
//! admitted through the one dispatcher's door validation — its tail read into the claims the
//! connector's registry view serves. A manifest outside the transport's version window is refused at
//! the structural gate.

use std::sync::Arc;

use crate::both_ways::{cdylib, dropped, statement, HOT_FIXTURES};
use crate::dispatch::kinds::transport::TransportFacts;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink};
use crate::sign::validate_structure;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::ROLE_FRAMER;

/// The transport fixture's cdylib bytes. Under CI a missing artifact is a failure, never a skip.
fn fixture() -> Option<Vec<u8>> {
    let krate = HOT_FIXTURES
        .iter()
        .find(|(kind, _)| *kind == "transport")
        .map(|&(_, krate)| krate)
        .expect("a `transport` row in [package.metadata.busbar.both-ways]");
    let found = cdylib(krate);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the transport fixture's cdylib is built under CI"
    );
    Some(std::fs::read(found?).expect("read the cdylib"))
}

fn bind() -> Bind {
    Bind {
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
    }
}

fn manifest() -> crate::sign::Manifest {
    statement("transport", "tcp", "tcp", busbar_contract::abi::ABI_MINOR)
}

#[test]
fn a_signed_door_tarball_is_opened_through_the_one_door() {
    let Some(lib) = fixture() else { return };
    let registry = dropped("transport-door", manifest(), &lib);
    let entries = registry
        .open_transport_entries(&bind())
        .expect("the door opens");
    assert!(entries.hot.is_empty(), "a door image is not a HOT decl");
    assert_eq!(entries.doors.len(), 1);
    let door = &entries.doors[0];
    assert_eq!(door.name(), "tcp");
    let facts = door.context::<TransportFacts>().expect("its tail");
    assert_eq!(facts.role, ROLE_FRAMER);
    assert_eq!(facts.claims, ["tcp"]);
    assert!(facts.composes_over.is_empty(), "it frames the host's socket");
    let mut i: OpenIn = blank_in();
    i.head = in_head();
    let mut o: OpenOut = blank_out();
    o.head = out_head();
    assert_eq!(
        door.call(life::OPEN, &mut Frame::new(i, o)).outcome,
        Outcome::Ready
    );
}

#[test]
fn a_manifest_outside_the_transport_version_window_is_refused() {
    validate_structure(&manifest(), b"lib", &crate::supported_abi, "")
        .expect("a transport is a kind the loader admits");
    let mut old = manifest();
    old.abi_version = busbar_contract::abi::hot::TRANSPORT_DECL_MINOR - 1;
    assert!(validate_structure(&old, b"lib", &crate::supported_abi, "").is_err());
}
