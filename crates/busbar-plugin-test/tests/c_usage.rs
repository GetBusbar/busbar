// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-USAGE (ABI-MIN3-INTERFACE §14): An undeclared USAGE class is dropped and audited.
//!
//! W1-K8A: on the kernel's one generic mapping (`plane_driver::usage`, IF §12.4). The mapping names the
//! dropped class; the plane adapter writes the audit row with it.

use busbar_contract::caps::{QuantitySource, UsageLine};
use busbar_contract::{Count, MeterClassId};
use busbar_kernel::plane_driver::usage::{
    bill, Bill, DeclaredClass, DeclaredClasses, Ending, SessionUsage,
};
use busbar_plugin_abi::plane::{UsageRec, SRC_REPORTED, UNIT_TOKENS};

const TOKENS: MeterClassId = MeterClassId::new("tokens");

#[test]
fn an_undeclared_usage_class_is_dropped_and_audited() {
    let declared = DeclaredClasses::new(vec![DeclaredClass {
        class: TOKENS,
        unit: UNIT_TOKENS,
        expected_units: f64::NAN,
    }]);
    let mut session = SessionUsage::new();
    for class in ["tokens", "images"] {
        session
            .answer(
                class,
                UsageRec {
                    amount: 3,
                    scale: 0,
                    source: SRC_REPORTED,
                },
            )
            .unwrap();
    }
    let Bill::Usage(kept) = bill(Ending::End, &session) else {
        panic!("an end with USAGE bills it");
    };
    let mapped = declared.map(&kept);
    assert_eq!(
        mapped.dropped,
        vec![Box::<str>::from("images")],
        "named for the audit"
    );
    assert_eq!(
        mapped.lines,
        vec![UsageLine {
            class: TOKENS,
            quantity: Count::from_micros(3_000_000),
            source: QuantitySource::Count,
            estimated: false,
        }]
    );
}
