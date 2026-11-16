// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's import target is core's format; the Store's physical format is the adapter's own.

use super::{Error, TargetIdentity, FORMAT_OWNER};
use busbar_contract::persistence::{BackendInfo, DatasetId, Durability, PHYSICAL_VERSION};

fn opened(dataset: [u8; 16], physical_version: u32) -> BackendInfo {
    BackendInfo {
        dataset: DatasetId(dataset),
        atomic_domain: [3; 16],
        clock_authority: [4; 16],
        physical_version,
        durability: Durability::Local,
    }
}

#[test]
fn slot_format_store_is_a_current_import_target() {
    let target = TargetIdentity::current(opened([2; 16], PHYSICAL_VERSION))
        .expect("a slot-format Store takes core's current format");
    assert_eq!(
        target,
        TargetIdentity {
            dataset: DatasetId([2; 16]),
            owner: FORMAT_OWNER,
            physical: 1,
            logical: 1,
            codec: 1,
        }
    );
}

#[test]
fn an_unidentified_dataset_is_no_import_target() {
    assert_eq!(
        TargetIdentity::current(opened([0; 16], PHYSICAL_VERSION)),
        Err(Error::Identity)
    );
}
