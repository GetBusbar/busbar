// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn instance_metadata_retains_all_identities_and_durability_classes() {
    for durability in [Durability::Ephemeral, Durability::Local, Durability::Quorum] {
        let info = BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 9,
            durability,
        };
        let bytes = encode(info).unwrap();
        assert_eq!(decode(&bytes), Ok(info));
        for length in 0..ENCODED_SIZE {
            assert_eq!(decode(&bytes[..length]), Err(InvalidMetadata));
        }
        let mut appended = bytes.to_vec();
        appended.push(0);
        assert_eq!(decode(&appended), Err(InvalidMetadata));
    }
}

#[test]
fn malformed_instance_metadata_cannot_default_to_a_weaker_guarantee() {
    let info = BackendInfo {
        dataset: DatasetId([1; 16]),
        atomic_domain: [2; 16],
        clock_authority: [3; 16],
        physical_version: 1,
        durability: Durability::Quorum,
    };
    let original = encode(info).unwrap();
    for index in [4, 60, 61] {
        let mut bytes = original;
        bytes[index] = 255;
        assert_eq!(decode(&bytes), Err(InvalidMetadata));
    }
    for range in [8..24, 24..40, 40..56, 56..60] {
        let mut bytes = original;
        bytes[range].fill(0);
        assert_eq!(decode(&bytes), Err(InvalidMetadata));
    }
}
