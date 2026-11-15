// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! See [`super`].

/// `ConfigureCheckpoint::new`'s refusal (`hook::configure_checkpoint`).
#[cold]
pub(in crate::abi::sdk) fn invalid_configure_checkpoint() -> String {
    String::from("invalid complete hook configuration checkpoint")
}

/// One `unit.refuse` answer field or body (`Services::unit_refuse`),
/// copied out of the kernel's memory: produced only when a unit is refused.
#[cold]
pub(in crate::abi::sdk) fn refusal_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}
