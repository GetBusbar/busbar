// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT §6a: admission classifies the manifest's record format, it does not just
//! refuse. `decode` still admits only a current manifest.

use super::*;

fn manifest(format: [u32; 4], tail: u32) -> Vec<u8> {
    let mut bytes = Manifest {
        dataset: DatasetId([1; 16]),
        registrar: WriterAuthority {
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
        },
        format: RECORD_FORMAT,
    }
    .encode()
    .to_vec();
    for (at, f) in [8, 12, 16, 20].into_iter().zip(format) {
        bytes[at..at + 4].copy_from_slice(&f.to_le_bytes());
    }
    bytes[72..76].copy_from_slice(&tail.to_le_bytes());
    bytes
}

#[test]
fn the_manifest_is_classified_by_its_format_and_tail() {
    let none = |_: u32| false;
    let from_one = |f: u32| f == 1;
    let current = RECORD_FORMAT;
    assert_eq!(current, 1);
    assert_eq!(classify(&manifest([1; 4], 0), none), Format::Current);
    // 1.6.0 ships no step: a newer format or tail is NEWER, before any write.
    assert_eq!(classify(&manifest([2; 4], 0), none), Format::Newer);
    assert_eq!(classify(&manifest([1; 4], 2), none), Format::Newer);
    // An older format: Older with a step, UNSUPPORTED without.
    assert_eq!(classify(&manifest([0; 4], 0), none), Format::Unsupported);
    assert_eq!(classify(&manifest([0; 4], 0), |f| f == 0), Format::Older(0));
    assert_eq!(
        classify(&manifest([0; 4], 1), |f| f == 0),
        Format::Migrating { from: 0, to: 1 }
    );
    assert_eq!(classify(&manifest([1; 4], 0), from_one), Format::Current);
    // The four copies disagree, or the reserved tail is not zero: Corrupt.
    assert_eq!(classify(&manifest([1, 1, 2, 1], 0), none), Format::Corrupt);
    let mut reserved = manifest([1; 4], 0);
    reserved[79] = 1;
    assert_eq!(classify(&reserved, none), Format::Corrupt);
    assert_eq!(classify(&[0; 79], none), Format::Corrupt);
    let mut magic = manifest([1; 4], 0);
    magic[0] = b'X';
    assert_eq!(classify(&magic, none), Format::Unsupported);
}

#[test]
fn decode_still_admits_only_a_current_manifest() {
    assert!(Manifest::decode(&manifest([1; 4], 0)).is_ok());
    assert!(Manifest::decode(&manifest([2; 4], 0)).is_ok());
    for bytes in [
        manifest([3; 4], 0),
        manifest([1; 4], 2),
        manifest([0; 4], 0),
    ] {
        assert_eq!(
            Manifest::decode(&bytes).map(drop),
            Err(Error::UnsupportedFormat)
        );
    }
}
