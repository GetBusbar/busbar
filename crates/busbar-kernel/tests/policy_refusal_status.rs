// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::plane::{class_of, RefusalClass};
use busbar_contract::caps::ReasonCode;
use busbar_kernel::plane_driver::{class_status, refusal_status};

const POLICY: &[RefusalClass] = &[
    RefusalClass::Unreadable,
    RefusalClass::Rejected,
    RefusalClass::Unauthenticated,
    RefusalClass::Forbidden,
    RefusalClass::TooLarge,
    RefusalClass::Throttled,
    RefusalClass::Busy,
    RefusalClass::QuotaExhausted,
    RefusalClass::NotFound,
];

const NODE: &[RefusalClass] = &[
    RefusalClass::Unreachable,
    RefusalClass::Unavailable,
    RefusalClass::Timeout,
    RefusalClass::PlaneFault,
    RefusalClass::NodeFault,
];

#[test]
fn policy_and_node_classes_partition_the_classification() {
    for class in RefusalClass::ALL {
        let n = usize::from(POLICY.contains(class)) + usize::from(NODE.contains(class));
        assert_eq!(n, 1, "{class:?} is in exactly one of POLICY and NODE");
    }
}

#[test]
fn a_policy_refusal_defaults_to_a_4xx_and_a_node_state_to_a_5xx() {
    let mut wrong = Vec::new();
    for class in POLICY {
        let status = class_status(*class);
        if !(400..500).contains(&status) {
            wrong.push(format!("policy class {class:?} defaults to {status}"));
        }
    }
    for class in NODE {
        let status = class_status(*class);
        if !(500..600).contains(&status) {
            wrong.push(format!("node class {class:?} defaults to {status}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn rejected_busy_and_not_found_take_the_one_classifications_statuses() {
    assert_eq!(class_status(RefusalClass::Rejected), 400);
    assert_eq!(class_status(RefusalClass::Busy), 429);
    assert_eq!(class_status(RefusalClass::NotFound), 404);
}

#[test]
fn every_policy_reason_defaults_to_a_4xx() {
    let mut wrong = Vec::new();
    for reason in ReasonCode::ALL {
        let class = class_of(*reason);
        let status = refusal_status(*reason);
        if POLICY.contains(&class) && !(400..500).contains(&status) {
            wrong.push(format!("{reason:?} ({class:?}) defaults to {status}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
