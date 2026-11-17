// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The linked plane's source-owned driver proofs (`[package.metadata.busbar.driver-proofs]`), compiled
//! from the plane crate's `tests/on_driver/` through its `driver=` links metadata. They drive the
//! plane's native port on the plugin-test safe host (`Harness`, `FakeNeeds`).

#![cfg(linked_driver_proofs)]

/// THE HOST SEAT the proofs name (the plane's `tests/on_driver/mod.rs` states the contract): the plane
/// port, its refusal encoder and the safe test host, from the host crates this distribution links.
mod host_seat {
    pub use busbar_plugin_test::fake_needs::FakeNeeds;
    pub use busbar_plugin_test::suites::harness::Harness;
    pub use busbar_ports::codec::plane::encode_refusal;
    pub use busbar_ports::plane::{PlaneIn, PlaneOut, PlanePort, PlaneSession, TargetIn};
    pub use busbar_ports::{FactRef, PortError};
}

include!(concat!(env!("OUT_DIR"), "/driver_proofs.rs"));
