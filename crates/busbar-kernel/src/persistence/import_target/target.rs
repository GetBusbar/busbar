// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current format target identity and the addresses of the format's rows.

use super::ImportError as Error;
use crate::persistence::startup;
use busbar_contract::persistence::*;

pub(crate) const FORMAT_OWNER: [u8; 16] = *b"busbar.core.v1\0\0";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetIdentity {
    pub dataset: DatasetId,
    pub owner: [u8; 16],
    pub physical: u32,
    pub logical: u32,
    pub codec: u32,
}
impl TargetIdentity {
    pub fn current(info: BackendInfo) -> Result<Self, Error> {
        // `physical` is core's format; the Store's own `physical_version` is the adapter's.
        if info.dataset.0 == [0; 16] {
            return Err(Error::Identity);
        }
        Ok(Self {
            dataset: info.dataset,
            owner: FORMAT_OWNER,
            physical: 1,
            logical: 1,
            codec: 1,
        })
    }
}
pub fn manifest_address() -> Address {
    startup::manifest_address()
}
pub fn root_address() -> Address {
    startup::root_address()
}
pub fn writer_address(writer: [u8; 16]) -> Address {
    startup::writer_address(writer)
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
