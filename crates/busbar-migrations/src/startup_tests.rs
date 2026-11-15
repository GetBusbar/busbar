// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Store's physical format is the adapter's own; core's target identity is core's format.

use super::{current_target, target_identity};
use crate::{Format, CORE_FORMAT};
use busbar_contract::{
    abi::sdk::store::v4::slot::{PHYSICAL_VERSION, RECEIPT_ERA_VERSION},
    persistence::{BackendInfo, DatasetId, Durability},
};

fn opened(physical_version: u32) -> BackendInfo {
    BackendInfo {
        dataset: DatasetId([2; 16]),
        atomic_domain: [3; 16],
        clock_authority: [4; 16],
        physical_version,
        durability: Durability::Local,
    }
}

/// A fresh (or current) slot-format Store binds core's format on its dataset at preparation;
/// the readiness check must accept the very Store it was prepared on.
#[test]
fn slot_format_store_realizes_its_fresh_target() {
    let info = opened(PHYSICAL_VERSION);
    let target = current_target(info, [0; 32], [0; 32]);
    assert_eq!(target.format, CORE_FORMAT);
    assert!(target.realized_by(&info));
}

/// A 1.5.5 import into a slot-format Store targets core's format on that Store.
#[test]
fn slot_format_store_is_a_legacy_import_target() {
    let info = opened(PHYSICAL_VERSION);
    let target = target_identity(info).expect("a slot-format Store is an import target");
    assert_eq!(target.format, CORE_FORMAT);
    assert!(target.realized_by(&info));
}

/// Core neither selects nor refuses an adapter's physical format; the Store refuses its own.
#[test]
fn adapter_physical_format_is_opaque_to_the_target() {
    let target = current_target(opened(PHYSICAL_VERSION), [0; 32], [0; 32]);
    assert!(target.realized_by(&opened(RECEIPT_ERA_VERSION)));
    assert!(target.realized_by(&opened(PHYSICAL_VERSION + 1)));
}

#[test]
fn another_dataset_or_core_format_does_not_realize_the_target() {
    let info = opened(PHYSICAL_VERSION);
    let target = current_target(info, [0; 32], [0; 32]);
    let mut elsewhere = info;
    elsewhere.dataset = DatasetId([9; 16]);
    assert!(!target.realized_by(&elsewhere));
    for format in [
        Format {
            logical: CORE_FORMAT.logical + 1,
            ..CORE_FORMAT
        },
        Format {
            codec: CORE_FORMAT.codec + 1,
            ..CORE_FORMAT
        },
        Format {
            physical: CORE_FORMAT.physical + 1,
            ..CORE_FORMAT
        },
        Format {
            owner: *b"another.owner\0\0\0",
            ..CORE_FORMAT
        },
    ] {
        let mut other = target.clone();
        other.format = format;
        assert!(!other.realized_by(&info), "{format:?}");
    }
}
