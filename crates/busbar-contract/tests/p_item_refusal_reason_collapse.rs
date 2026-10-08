// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! P-ITEM: REFUSAL-REASON COLLAPSE (spec DONE item 2, `docs/design/BUSBAR-1.6.0.md`, "All P-item
//! behaviours match 1.5.5"; the drive log's P1/P2, commit 470351a480; TODO L-ENG9).
//!
//! THE 1.5.5 BEHAVIOUR. 1.5.5 had one plane (owner correction 2026-09-28). On it
//! every limit reason reached the caller as its own status and kind, and none of them became an
//! internal error: a rate limit 429 `rate_limit_error`, a spent budget 429 `insufficient_quota`
//! (400 on bedrock), a frozen group 403 `permission_error` (v1.5.5
//! `crates/busbar/src/ingress/mod.rs:237-305`). The bug was a plane answering a policy refusal as
//! "this node broke", which a caller retries the wrong way.
//!
//! THE ROOT. The reason-to-family decision had been hand-copied eight times, and the copies had
//! drifted; one of them still ended in a catch-all that answered every reason it did not name as
//! internal. The fix is ONE classification
//! (`busbar_contract::abi::plane::RefusalCode::class`), with each surface holding only a
//! class-to-wire table. This file pins the classification; `xtask/tests/
//! p_item_refusal_reason_collapse.rs` reads the renderers' source and proves none of them holds a
//! reason match of its own again.

use busbar_contract::abi::plane::{
    class_of, class_of_refusal, class_of_word, wire_code, RefusalClass, RefusalCode,
};
use busbar_contract::caps::ReasonCode;
use busbar_contract::unit::RefusalReason;

/// Every reason has exactly one class, read the same way from each of its three spellings.
#[test]
fn p_item_refusal_reason_collapse_every_reason_has_one_class_by_every_spelling() {
    assert_eq!(ReasonCode::ALL.len(), RefusalCode::ALL.len());
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
        // By its spelling: every reason a plane can be handed; the kernel's own two money verdicts
        // never reach a plane (`reason_of`) and read as no reason.
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
/// node fault: each is a refusal the caller is owed by name.
#[test]
fn p_item_refusal_reason_collapse_the_1_5_5_reasons_keep_their_own_family() {
    for (reason, class) in [
        // v1.5.5 ingress/mod.rs:237-258: a rate limit is 429 `rate_limit_error`.
        (ReasonCode::RateLimited, RefusalClass::Throttled),
        // v1.5.5 ingress/mod.rs:268-285: a spent budget is `insufficient_quota`.
        (ReasonCode::OverBudget, RefusalClass::QuotaExhausted),
        // v1.5.5 ingress/mod.rs:288-297: a frozen group is 403 `permission_error`.
        (ReasonCode::GroupFrozen, RefusalClass::Forbidden),
        // The recorded 1.5.5 cells of these reasons (`request|{unauthenticated,malformed,
        // upstream_down}`, `http.crosscut|413|*`).
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
/// drain or deadline reason is a refusal the caller is told the family of.
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
        ]
    );
}
