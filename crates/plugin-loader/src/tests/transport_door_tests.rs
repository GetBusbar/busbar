// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROPPED-IN TRANSPORT DOOR THROUGH THE REGISTRY: the neutral frame door's `cdylib`, signed
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

/// The neutral frame door (`tests/fixtures/neutral_frame_door.rs`): a dropped-in transport door
/// that frames the host's socket, built beside the test binary as this crate's example `cdylib`.
/// Under CI a missing artifact is a failure, never a skip.
fn fixture() -> Option<Vec<u8>> {
    Some(std::fs::read(fixture_path()?).expect("read the cdylib"))
}

/// Where [`fixture`] is: the neutral frame door example, which admits against its own Statement
/// rendering as a transport composing over nothing.
fn fixture_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let examples = exe.parent()?.parent()?.join("examples");
    let found = Some(examples.join(crate::plugin_library_filename("neutral_frame_door")))
        .filter(|p| p.exists())
        .filter(|p| {
            crate::dispatch::rendering_of_library(p)
                .ok()
                .flatten()
                .and_then(|stated| {
                    crate::dispatch::load_dropped::<crate::dispatch::kinds::transport::Transport>(
                        p,
                        &stated,
                        bind(),
                    )
                    .ok()
                })
                .and_then(|d| d.context::<TransportFacts>().cloned())
                .is_some_and(|f| f.composes_over.is_empty())
        });
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the neutral frame door example is built beside the test binary under CI"
    );
    found
}

fn bind() -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: None,
    }
}

/// The fixture's manifest, stating the door's Statement rendering as its signed manifest does (the
/// door is admitted against it).
fn manifest() -> crate::sign::Manifest {
    let rendering =
        fixture_path().and_then(|path| crate::dispatch::rendering_of_library(&path).ok().flatten());
    crate::sign::Manifest {
        statement: rendering.map(hex::encode),
        ..statement(
            busbar_contract::abi::mechanism::kind::TRANSPORT,
            "door-fixture",
            "door-fixture",
            busbar_contract::abi::transport::ABI_VERSION,
        )
    }
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
    assert_eq!(
        facts.role, ROLE_FRAMER,
        "the neutral door frames a byte stream; it is never a carrier"
    );
    assert_eq!(facts.claims, [door.name()], "one claim: its own");
    assert!(
        facts.composes_over.is_empty(),
        "it frames whatever carrier the connector rides"
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
    old.abi_version = busbar_contract::abi::transport::ABI_VERSION - 1;
    assert!(validate_structure(&old, b"lib", &crate::supported_abi, "").is_err());
    let mut newer = packed();
    newer.abi_version = busbar_contract::abi::transport::ABI_VERSION + 1;
    assert!(validate_structure(&newer, b"lib", &crate::supported_abi, "").is_err());
}
