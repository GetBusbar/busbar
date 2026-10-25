// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A POLICY REFUSAL IS A REFUSAL, NOT A SERVER FAULT.
//!
//! The kernel's default status per refusal class (`plane_driver::class_status`) is what every plane
//! that states no row of its own answers, and every reason a plane that states rows does not
//! restate. A class that refuses the CALLER'S REQUEST (the caller's
//! bytes, its authority, its size, its rate, its money, what it named, or a limit it ran into) owes
//! the caller a 4xx naming that refusal, so the caller does not retry it as though the node broke.
//! A class that is the node's own state or fault (a shut way to the destination, a node that cannot
//! take the unit now, a deadline, a panic, an internal fault) stays 5xx.
//!
//! The policy set, from the class docs (`busbar_contract::abi::plane::RefusalClass`):
//! `Unreadable` (the plane could not read the request), `Rejected` (readable, and this node will not
//! take it as asked: an unbillable name, a replayed or superseded idempotency key, a method no route
//! takes), `Unauthenticated`, `Forbidden`, `TooLarge`, `Throttled` (the caller is over its rate),
//! `Busy` (the in-flight table or the idempotency key's unit is busy: a limit the admission ran
//! into), `QuotaExhausted` (a money cap has no headroom), `NotFound` (nowhere for the request to go).
//! The node set: `Unreachable`, `Unavailable`, `Timeout`, `PlaneFault`, `NodeFault`.
//!
//! RED before the fix: `Rejected`, `Busy` and `NotFound` defaulted to 503.

use busbar_contract::abi::plane::{class_of, RefusalClass};
use busbar_contract::caps::ReasonCode;
use busbar_kernel::plane_driver::{class_status, refusal_status};

/// The classes that refuse the caller's request.
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

/// The classes that are the node's own state or fault.
const NODE: &[RefusalClass] = &[
    RefusalClass::Unreachable,
    RefusalClass::Unavailable,
    RefusalClass::Timeout,
    RefusalClass::PlaneFault,
    RefusalClass::NodeFault,
];

/// The two sets cover every class, once: a class added to the classification is placed here.
#[test]
fn policy_and_node_classes_partition_the_classification() {
    for class in RefusalClass::ALL {
        let n = usize::from(POLICY.contains(class)) + usize::from(NODE.contains(class));
        assert_eq!(n, 1, "{class:?} is in exactly one of POLICY and NODE");
    }
}

/// Every policy class defaults to a 4xx, every node class to a 5xx.
///
/// RED: a policy refusal (an unpriced class, a replayed key, a full in-flight table, a name with
/// nowhere to go) answers 503, which a caller reads as "the node broke" and retries.
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

/// The three classes that defaulted to 503 take the status the other planes already answer for
/// them (the one classification): `Rejected` 400 (the recorded 1.5.5 `no rate` 400,
/// `invalid_request_error`), `NotFound` 404 (its recorded 1.5.5 not-found 404, and the admin
/// surface's), `Busy` 429 (1.5.5's group in-flight limit, 429 `rate_limit_error`, and the admin
/// surface's).
#[test]
fn rejected_busy_and_not_found_take_the_one_classifications_statuses() {
    assert_eq!(class_status(RefusalClass::Rejected), 400);
    assert_eq!(class_status(RefusalClass::Busy), 429);
    assert_eq!(class_status(RefusalClass::NotFound), 404);
}

/// Reason by reason: every reason in a policy class defaults to a 4xx (what a plane with no row of
/// its own answers it with).
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
