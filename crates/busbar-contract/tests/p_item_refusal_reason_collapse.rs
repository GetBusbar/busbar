// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! P-ITEM: REFUSAL-REASON COLLAPSE (spec DONE item 2, `docs/design/BUSBAR-1.6.0.md`, "All P-item

use busbar_contract::abi::plane::{
    class_of, class_of_refusal, class_of_word, wire_code, RefusalClass, RefusalCode,
};
use busbar_contract::caps::ReasonCode;
use busbar_contract::unit::RefusalReason;

/// Every reason has exactly one class, read the same way from each of its three spellings.
#[test]
fn p_item_refusal_reason_collapse_every_reason_has_one_class_by_every_spelling() {
    assert_eq!(
        ReasonCode::ALL.len(),
        RefusalCode::ALL.iter().filter(|c| !c.unsent()).count()
    );
    for code in RefusalCode::ALL.iter().filter(|c| c.unsent()) {
        assert_eq!(
            busbar_contract::abi::plane::reason_of(code.code()),
            None,
            "{code:?}"
        );
    }
    for reason in ReasonCode::ALL {
        let class = class_of(*reason);
        assert_eq!(wire_code(*reason).class(), class, "{reason:?}");
        let refusal = RefusalReason::from(*reason);
        assert_eq!(ReasonCode::from(refusal), *reason, "the bridge round-trips");
        assert_eq!(
            class_of_refusal(refusal),
            class,
            "{reason:?} as a plane is handed it"
        );

        let kernel_only = matches!(
            reason,
            ReasonCode::OverdraftCeiling | ReasonCode::StaleSlice
        );
        assert_eq!(
            class_of_word(reason.as_str()),
            (!kernel_only).then_some(class),
            "{reason:?} by its spelling"
        );
    }
    assert_eq!(class_of_word("no_such_reason"), None);
}

/// Every class holds at least one reason: a class nothing lands in is a renderer arm nobody reads.
#[test]
fn p_item_refusal_reason_collapse_every_class_is_reached() {
    for class in RefusalClass::ALL {
        assert!(
            ReasonCode::ALL.iter().any(|r| class_of(*r) == *class),
            "{class:?} holds no reason"
        );
    }
}

/// The reasons 1.5.5's one surface answered keep a family of their own, and none of them is a
#[test]
fn p_item_refusal_reason_collapse_the_1_5_5_reasons_keep_their_own_family() {
    for (reason, class) in [
        (ReasonCode::RateLimited, RefusalClass::Throttled),
        (ReasonCode::OverBudget, RefusalClass::QuotaExhausted),
        (ReasonCode::GroupFrozen, RefusalClass::Forbidden),
        (ReasonCode::Unauthenticated, RefusalClass::Unauthenticated),
        (ReasonCode::DecodeFailed, RefusalClass::Unreadable),
        (
            ReasonCode::DestinationUnreachable,
            RefusalClass::Unreachable,
        ),
        (ReasonCode::BodyTooLarge, RefusalClass::TooLarge),
    ] {
        assert_eq!(class_of(reason), class, "{reason:?}");
        assert!(!class.is_node_fault(), "{reason:?} is no node fault");
    }
}

/// Only a fault of this node is a node fault. Every admission, capacity, rate, budget, breaker,
#[test]
fn p_item_refusal_reason_collapse_only_the_nodes_own_faults_are_node_faults() {
    let faults: Vec<ReasonCode> = ReasonCode::ALL
        .iter()
        .copied()
        .filter(|r| class_of(*r).is_node_fault())
        .collect();
    assert_eq!(
        faults,
        [
            ReasonCode::MeterDisputed,
            ReasonCode::HandoffMismatch,
            ReasonCode::PlanePanic,
            ReasonCode::TaskLost,
            ReasonCode::SecretPlaceholder,
            // The kernel's own `INTERNAL` refusal, which the
            // owning plane renders (1.5.5's generic 500), is a fault of this node.
            ReasonCode::Internal,
        ]
    );
}
