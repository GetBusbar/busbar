// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::{AtRestKeys, CallerRecordContext, CallerRecordKind};

#[test]
fn caller_records_preserve_opaque_binary_and_authenticate_every_binding() {
    let keys = AtRestKeys::new(&[7; 32], None);
    let codec = keys.caller_records(4096).unwrap();
    let context = CallerRecordContext::new(
        CallerRecordKind::Prepared,
        [1; 16],
        [2; 16],
        b"caller-key",
        3,
        [4; 16],
        b"phase",
    )
    .unwrap();
    let plain = [0, 0xff, 0x80, b'S', b'E', b'C', b'R', b'E', b'T'];
    let encrypted = codec.seal(&context, &plain).unwrap();
    assert!(!encrypted.windows(plain.len()).any(|w| w == plain));
    assert_eq!(codec.open(&context, &encrypted).unwrap().as_slice(), plain);
    for (kind, dataset, domain, key, generation, operation, binding) in [
        (
            CallerRecordKind::Terminal,
            [1; 16],
            [2; 16],
            b"caller-key".as_slice(),
            3,
            [4; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [9; 16],
            [2; 16],
            b"caller-key".as_slice(),
            3,
            [4; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [1; 16],
            [9; 16],
            b"caller-key".as_slice(),
            3,
            [4; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [1; 16],
            [2; 16],
            b"other-key".as_slice(),
            3,
            [4; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [1; 16],
            [2; 16],
            b"caller-key".as_slice(),
            4,
            [4; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [1; 16],
            [2; 16],
            b"caller-key".as_slice(),
            3,
            [9; 16],
            b"phase".as_slice(),
        ),
        (
            CallerRecordKind::Prepared,
            [1; 16],
            [2; 16],
            b"caller-key".as_slice(),
            3,
            [4; 16],
            b"other".as_slice(),
        ),
    ] {
        let wrong =
            CallerRecordContext::new(kind, dataset, domain, key, generation, operation, binding)
                .unwrap();
        assert!(codec.open(&wrong, &encrypted).is_err());
    }
    assert!(codec.open(&context, b"v1:plain:SECRET").is_err());
    assert!(!format!("{codec:?}").contains("SECRET"));
}

#[test]
fn caller_record_budget_and_retained_previous_key_are_enforced() {
    let context = CallerRecordContext::new(
        CallerRecordKind::Guard,
        [1; 16],
        [2; 16],
        b"k",
        1,
        [3; 16],
        b"",
    )
    .unwrap();
    let old = AtRestKeys::new(&[1; 32], None)
        .caller_records(4096)
        .unwrap();
    let row = old.seal(&context, b"terminal-without-a-grant").unwrap();
    let retained = AtRestKeys::new(&[2; 32], Some(&[1; 32]))
        .caller_records(4096)
        .unwrap();
    assert_eq!(
        retained.open(&context, &row).unwrap().as_slice(),
        b"terminal-without-a-grant"
    );
    let retired = AtRestKeys::new(&[2; 32], None)
        .caller_records(4096)
        .unwrap();
    assert!(retired.open(&context, &row).is_err());
    let bounded = AtRestKeys::new(&[1; 32], None).caller_records(64).unwrap();
    assert!(bounded.seal(&context, &[9; 128]).is_err());
    assert!(bounded.open(&context, &row).is_err());
}
