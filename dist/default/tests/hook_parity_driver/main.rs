// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(linked_driver_proofs)]

include!(concat!(env!("OUT_DIR"), "/linked_plane_doors.rs"));

include!(concat!(env!("OUT_DIR"), "/driver_proofs.rs"));

#[path = "../../../../crates/busbar-kernel/tests/common/mod.rs"]
mod common;

mod rig;
