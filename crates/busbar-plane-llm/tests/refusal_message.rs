// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sentence a refusal carries, and the family it belongs to.
//!
//! A refusal message is read by a client, so it is a small closed set of neutral sentences: one per
//! status family, chosen so that nothing a client reads tells it which of the node's internal
//! ceilings it met. The existing envelope tests assert that the DIALECT wrote the envelope and that
//! the internal reason never appears in it — both of which stay true when every reason collapses
//! onto one sentence, and the sentence a node-side fault carries is exactly the one that must not
//! collapse: "the request could not be completed" is the node admitting to its own fault, and
//! "request rejected" is the node blaming the caller for it.
//!
//! So this reads the whole closed reason set and pins the sentence each one wears.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::plane::Plane;
use busbar_contract::unit::{Refusal, RefusalReason, Step};
use busbar_plane_llm::LlmPlane;

/// Render one refusal, in one dialect, as text.
fn refusal_text(reason: RefusalReason) -> String {
    let plane = LlmPlane::EMPTY;
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let bytes = plane
        .encode_refusal(
            &Refusal {
                step: Step::Admit,
                reason,
                retry_after_secs: None,
                stream: None,
                correlates: None,
            },
            None,
            None,
            &ctx,
        )
        .expect("every dialect can express a refusal")
        .as_slice()
        .to_vec();
    String::from_utf8(bytes).expect("a refusal envelope is text")
}

/// The seven sentences, and the reason set each one belongs to.
///
/// Written out reason by reason rather than derived from the status, because deriving it here would
/// be a second copy of the very mapping under test — the test would then agree with the code by
/// construction and say nothing about it.
const FAMILIES: &[(&str, &[RefusalReason])] = &[
    (
        "Authentication failed.",
        &[
            RefusalReason::CredentialRejected,
            RefusalReason::SessionUnbound,
            RefusalReason::SchemeNotDeclared,
            RefusalReason::ChallengeExhausted,
        ],
    ),
    (
        "Not permitted.",
        &[
            RefusalReason::Revoked,
            RefusalReason::ScopeMissing,
            RefusalReason::Vetoed,
            RefusalReason::PoolNotPermitted,
        ],
    ),
    (
        "Request too large.",
        &[
            RefusalReason::BodyTooLarge,
            RefusalReason::CursorBudget,
            RefusalReason::CredentialBudget,
        ],
    ),
    (
        "Rate limited.",
        &[
            RefusalReason::InFlightCap,
            RefusalReason::SessionBudget,
            RefusalReason::OpenSlotBusy,
            RefusalReason::OverBudget,
            RefusalReason::GroupFrozen,
            RefusalReason::OverdraftCeiling,
            RefusalReason::RateLimited,
            RefusalReason::InFlight,
        ],
    ),
    (
        "Request rejected.",
        &[
            RefusalReason::NoDestination,
            RefusalReason::Unpriced,
            RefusalReason::DecodeFailed,
            RefusalReason::NoRate,
            RefusalReason::Replayed,
            RefusalReason::Superseded,
        ],
    ),
    (
        "The request could not be completed.",
        &[
            RefusalReason::MeterDisputed,
            RefusalReason::HandoffMismatch,
            RefusalReason::PlanePanic,
            RefusalReason::TaskLost,
            RefusalReason::SecretPlaceholder,
        ],
    ),
    (
        "Temporarily unavailable.",
        &[
            RefusalReason::DurabilityUnavailable,
            RefusalReason::StaleSlice,
            RefusalReason::TierMismatch,
            RefusalReason::SpillBudget,
            RefusalReason::ArenaBudget,
            RefusalReason::DestinationBudgetExhausted,
            RefusalReason::BreakerOpen,
            RefusalReason::DestinationUnreachable,
            RefusalReason::Stalled,
            RefusalReason::Drain,
            RefusalReason::ClientGone,
            RefusalReason::DeadlineExceeded,
        ],
    ),
];

/// Every reason in the closed set wears the sentence its family wears, and the whole set is walked.
#[test]
fn every_reason_carries_its_familys_sentence() {
    let mut walked = 0usize;
    for (sentence, reasons) in FAMILIES {
        for reason in *reasons {
            walked += 1;
            let text = refusal_text(*reason);
            assert!(
                text.contains(sentence),
                "{reason:?} was refused with {text} rather than with {sentence:?}"
            );
        }
    }
    assert_eq!(
        walked, 42,
        "the contract's reason set changed and these families did not"
    );
}

/// A node-side fault does not read as a caller's mistake.
///
/// The two sentences are one arm apart in the message table, and they say opposite things about
/// whose fault the refusal was: a client told "request rejected" retries with a different request,
/// which is the wrong advice for a node that lost the unit's own task.
#[test]
fn a_node_side_fault_says_so_rather_than_blaming_the_caller() {
    for reason in [
        RefusalReason::PlanePanic,
        RefusalReason::TaskLost,
        RefusalReason::MeterDisputed,
        RefusalReason::HandoffMismatch,
        RefusalReason::SecretPlaceholder,
    ] {
        let text = refusal_text(reason);
        assert!(
            text.contains("The request could not be completed."),
            "{reason:?} reads as {text}"
        );
        assert!(
            !text.contains("Request rejected."),
            "{reason:?} blames the caller for a fault of the node's"
        );
    }
    // And the caller's-mistake sentence is still reachable, so the assertion above is a difference
    // and not an absence.
    assert!(refusal_text(RefusalReason::DecodeFailed).contains("Request rejected."));
}

/// No sentence in the set is the empty string, and no two families share one.
///
/// A message table that answered one string for everything would satisfy every "the envelope is
/// the dialect's" assertion there is while telling an operator's client nothing at all.
#[test]
fn the_seven_sentences_are_seven_distinct_sentences() {
    let mut seen = std::collections::BTreeSet::new();
    for (sentence, reasons) in FAMILIES {
        assert!(!sentence.is_empty());
        assert!(seen.insert(*sentence), "{sentence:?} is spelled twice");
        assert!(!reasons.is_empty());
    }
    assert_eq!(seen.len(), 7);
}
