// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{json, Count};
use busbar_count::json_span::{resolve_pointer, Resolved, Span};

#[test]
fn contract_and_direct_count_have_one_type_and_exact_number_wire() {
    for micros in [i128::MIN, -1, 0, 1, i128::MAX] {
        let direct = busbar_count::Count::from_micros(micros);
        let contract: Count = direct;
        let returned: busbar_count::Count = contract;
        assert_eq!(returned.micros(), micros);

        let wire = json::to_string(&direct).unwrap();
        assert_eq!(wire, direct.to_decimal_string());
        let decoded: busbar_count::Count = json::from_str(&wire).unwrap();
        assert_eq!(decoded, contract);
    }
}

#[test]
fn contract_and_direct_scanner_have_one_span_and_pointer_behavior() {
    let body = br#"{"a/b":{"~value":1,"~value":2.000001}}"#;
    let pointer = "/a~1b/~0value";
    let found = resolve_pointer(body, pointer);
    let contract: busbar_contract::spans::Resolved = found;
    let returned: Resolved = contract;
    let Resolved::Found(direct) = returned else {
        panic!("expected a resolved count span");
    };
    let contract: busbar_contract::Span = direct;
    let returned: Span = contract;
    assert_eq!(returned.of(body), b"2.000001");
    assert_eq!(
        busbar_count::Count::read_at(body, pointer).unwrap(),
        Some(Count::from_micros(2_000_001))
    );
    assert_eq!(
        resolve_pointer(br#"{"a/b": {"~value": "#, pointer),
        Resolved::NeedMore
    );
}
