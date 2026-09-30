// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROPPED-IN TRANSPORT DOOR THROUGH THE REGISTRY: the in-tree transport fixture's `cdylib`, signed
//! first-party into a `plugins/` directory, is scanned, trusted, staged, `dlopen`ed once and
//! admitted through the one dispatcher's door validation — its tail read into the claims the
//! connector's registry view serves. A manifest outside the transport's version window is refused at
//! the structural gate.

use std::sync::Arc;

use crate::both_ways::{dropped, statement};
use crate::dispatch::kinds::transport::TransportFacts;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink};
use crate::sign::validate_structure;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::ROLE_FRAMER;

/// The test-only HOT carrier the conformance and stack witnesses below drive.
#[path = "mem_carrier.rs"]
mod mem_carrier;

/// A HOT decl's admission and its decl-backed carrier, against the linked carrier.
#[path = "transport_conformance_tests.rs"]
mod conformance;

/// The HOT carrier stacked as the host's `Transport` (`WireTransport`).
#[path = "transport_adapter_tests.rs"]
mod adapter;

/// The transport fixture's dropped-in image: this crate's `transport_door` example `cdylib`, which
/// `cargo test` builds. Under CI a missing artifact is a failure, never a skip.
fn fixture() -> Option<Vec<u8>> {
    let path = crate::dispatch_tests::example_cdylib("transport_door")?;
    Some(std::fs::read(path).expect("read the cdylib"))
}

fn bind() -> Bind {
    Bind {
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
    }
}

fn manifest() -> crate::sign::Manifest {
    statement(
        busbar_contract::abi::cold::kind::TRANSPORT,
        "door-fixture",
        "door-fixture",
        busbar_contract::abi::ABI_MINOR,
    )
}

/// The manifest as the structural gate reads a packed one: an artifact digest present.
fn packed() -> crate::sign::Manifest {
    crate::sign::Manifest {
        sha256: crate::sign::sha256_hex(b"lib"),
        ..manifest()
    }
}

#[test]
fn a_signed_door_tarball_is_opened_through_the_one_door() {
    let Some(lib) = fixture() else { return };
    let registry = dropped("door-fixture", manifest(), &lib);
    let entries = registry
        .open_transport_entries(&bind())
        .expect("the door opens");
    assert!(entries.hot.is_empty(), "a door image is not a HOT decl");
    assert_eq!(entries.doors.len(), 1);
    let door = &entries.doors[0];
    let facts = door.context::<TransportFacts>().expect("its tail");
    assert_eq!(facts.role, ROLE_FRAMER);
    assert_eq!(facts.claims, [door.name()], "one claim: its own");
    assert!(
        facts.composes_over.is_empty(),
        "it frames the host's socket"
    );
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
    validate_structure(&packed(), b"lib", &crate::supported_abi, "")
        .expect("a transport is a kind the loader admits");
    let mut old = packed();
    old.abi_version = busbar_contract::abi::hot::TRANSPORT_DECL_MINOR - 1;
    assert!(validate_structure(&old, b"lib", &crate::supported_abi, "").is_err());
}
