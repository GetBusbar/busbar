// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::measurement::*;
use busbar_contract::abi::mechanism::{
    check::{check_statement, Rule},
    rendering, KindCode, MECHANISM_VERSION,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};

const CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str("requests"),
        family: abi_str("request"),
    },
    BillableClass {
        class: abi_str("duration"),
        family: abi_str("second"),
    },
];

#[test]
fn signed_common_declarations_work_for_all_seven_kinds() {
    for kind in KindCode::ALL {
        let mut st = statement("usage", "1", 1).with_measurement_classes(CLASSES);
        st.kind = kind as u32;
        st.kind_abi = kind.abi_version();
        // SAFETY: all declarations and strings have static storage.
        unsafe { check_statement(&st) }.unwrap();
        let bytes = unsafe { rendering::render(&st) }.unwrap();
        let read = rendering::read(&bytes).unwrap();
        assert_eq!(read.measurement_classes[1].family, "second");
        assert_eq!(read.measurement_classes[0].class, "requests");
        assert_eq!(read.mechanism_version, 4);
        let mut altered = st;
        const OTHER: &[BillableClass] = &[BillableClass {
            class: abi_str("other"),
            family: abi_str("request"),
        }];
        altered = altered.with_measurement_classes(OTHER);
        assert_ne!(bytes, unsafe { rendering::render(&altered) }.unwrap());
    }
}

#[test]
fn declarations_reject_duplicates_empty_invalid_and_overbound() {
    for classes in [
        vec![CLASSES[0]; 2],
        vec![BillableClass::ZERO],
        vec![BillableClass {
            class: abi_str("space name"),
            ..CLASSES[0]
        }],
        vec![BillableClass {
            family: abi_str("bad\nfamily"),
            ..CLASSES[0]
        }],
        vec![CLASSES[0]; 65],
    ] {
        assert!(unsafe { check_declarations(&classes) }.is_err());
    }
    let st = statement("usage", "1", 1);
    assert_eq!(unsafe { check_statement(&st) }, Ok(()));
    assert!(rendering::read(&unsafe { rendering::render(&st) }.unwrap())
        .unwrap()
        .measurement_classes
        .is_empty());
}

fn batch(counts: &[UnitCount]) -> MeasurementBatch {
    MeasurementBatch {
        revision: 9,
        counts: counts.as_ptr(),
        counts_len: counts.len(),
    }
}

#[test]
fn exact_fractions_bounds_sources_and_duplicate_indexes() {
    let count = UnitCount {
        class: 1,
        source: UNITS_REPORTED_MICROS,
        amount: 1_234_567,
    };
    assert_eq!(count.count().unwrap().micros(), 1_234_567);
    assert_eq!(check_counts(&[count], 2), Ok(()));
    assert_eq!(
        check_counts(&[count, count], 2).unwrap_err().rule,
        Rule::Contradiction
    );
    assert_eq!(
        check_counts(&[count], 1).unwrap_err().rule,
        Rule::IndexOutOfRange
    );
    for source in [
        UNITS_ESTIMATED,
        UNITS_FLOOR,
        UNITS_ESTIMATED_MICROS,
        UNITS_FLOOR_MICROS,
        u32::MAX,
    ] {
        assert!(check_counts(&[UnitCount { source, ..count }], 2).is_err());
    }
    assert!(check_counts(
        &[UnitCount {
            amount: u64::MAX,
            ..count
        }],
        2
    )
    .is_err());
    assert!(check_counts(&[count; 65], 2).is_err());
    // Whole and micro amounts use the same normalized storage rule as Count itself.
    for source in [UNITS_REPORTED, UNITS_REPORTED_MICROS] {
        for amount in [0, 1, i64::MAX as u64, u64::MAX] {
            let c = UnitCount {
                source,
                amount,
                ..count
            };
            assert_eq!(
                check_counts(&[c], 2).is_ok(),
                c.count().is_ok_and(|v| v.fits_a_64_bit_column())
            );
        }
    }
}

#[test]
fn batch_never_grants_authority_or_fills_omitted_classes() {
    let counts = [UnitCount {
        class: 1,
        source: UNITS_REPORTED,
        amount: 3,
    }];
    let b = batch(&counts);
    // SAFETY: counts remain live for every validation.
    unsafe {
        assert_eq!(check_batch(&b, 2, 9), Ok(()));
        assert!(check_batch(&b, 2, 0).is_err());
        assert!(check_batch(&b, 2, 8).is_err());
        assert!(check_batch(&b, 0, 9).is_err());
        assert!(check_batch(&MeasurementBatch { revision: 0, ..b }, 2, 0).is_err());
        assert_eq!(check_batch(&MeasurementBatch::ZERO, 0, 0), Ok(()));
        assert_eq!(check_batch(&batch(&[]), 2, 9), Ok(()));
        assert!(check_batch(
            &MeasurementBatch {
                counts: std::ptr::null(),
                ..b
            },
            2,
            9
        )
        .is_err());
        assert!(check_batch(
            &MeasurementBatch {
                counts: std::ptr::dangling(),
                counts_len: 65,
                ..b
            },
            2,
            9
        )
        .is_err());
    }
    assert_eq!(b.counts_len, 1); // class zero remains unobserved
}

#[test]
fn pre_measurement_layout_and_old_mechanism_renderings_are_refused() {
    assert_eq!(MECHANISM_VERSION, 4);
    let st = statement("usage", "1", 1);
    let mut bytes = unsafe { rendering::render(&st) }.unwrap();
    bytes[..8].copy_from_slice(b"BBSTMT03");
    assert!(rendering::read(&bytes)
        .unwrap_err()
        .what
        .contains("measurement"));
    bytes[..8].copy_from_slice(b"BBSTMT04");
    bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
    assert!(rendering::read(&bytes)
        .unwrap_err()
        .what
        .contains("mechanism"));
}

#[test]
fn rendering_refuses_a_missing_common_list_before_reading_it() {
    let mut st = statement("usage", "1", 1);
    st.measurement_classes_len = 1;
    // SAFETY: no non-NULL storage is claimed; validators must reject the absent list.
    unsafe {
        assert!(check_statement(&st).is_err());
        assert!(rendering::render(&st).is_err());
    }
}
