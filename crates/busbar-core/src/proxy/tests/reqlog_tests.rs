// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/proxy/reqlog.rs` — the model plane's RECORD.
//!
//! ## What is deliberately NOT here
//!
//! The chaining, the digest, the linkage and the verifier are `crate::audit`'s and are tested there,
//! including against a throwaway fourth record type. Re-testing them through this record would be a
//! second battery over one mechanism.
//!
//! What is here is the record's own two decisions — which fields the digest covers, and which
//! outcome word a terminal earns — plus the retention bound. **None of it proves the plane is
//! chained**: a test that calls `REQUESTS.record` itself proves the substrate and says nothing about
//! whether a customer's model request ever reaches it, which is exactly the shape the MCP call log
//! sat in for a whole release (a complete, tested, verified subsystem with no production call site).
//! The claim that the plane reaches this is made in `tests/reqlog_dispatch_tests.rs`, which drives a
//! real request through the real router and then looks.

use super::*;
use crate::audit::{digest, verify_window, ChainBreakKind};

const NOW: u64 = 1_770_000_000;

fn an_input(status: u16) -> RequestInput {
    RequestInput {
        ts: NOW,
        ingress_protocol: "anthropic".to_string(),
        pool: "fast".to_string(),
        outcome: OUTCOME_DISPATCHED,
        reason: "",
        status,
    }
}

/// A REWRITTEN STATUS IS DETECTED. The status is the field an after-the-fact edit would most want:
/// turning a 403 into a 200 rewrites a refusal into a service. It is in the digest, so it cannot be
/// changed without the record failing to hash to its own stored digest.
#[test]
fn editing_the_recorded_status_breaks_the_records_own_digest() {
    let mut chain = RequestChain::new();
    let mut record = chain.append("key-1", an_input(403));
    assert_eq!(digest(&record), record.hash, "the sealed record verifies");

    record.status = 200;
    assert_ne!(
        digest(&record),
        record.hash,
        "a status edited in place must not still hash to the stored digest — otherwise a refusal \
         can be rewritten into a success with no evidence of the edit"
    );
}

/// ONE CALLER'S EVIDENCE CANNOT BE MADE TO DEPEND ON ANOTHER'S. The scope is the principal and the
/// core verifier refuses a foreign one outright; this pins that this record type wires `scope_of` to
/// the field that means it.
#[test]
fn a_record_from_another_principal_is_refused_by_the_verifier() {
    let mut chain = RequestChain::new();
    let first = chain.append("key-1", an_input(200));
    let mut smuggled = chain.append("key-1", an_input(200));
    smuggled.principal = "key-2".to_string();
    smuggled.hash = digest(&smuggled);

    let brk = verify_window(&[first, smuggled]).expect_err("a foreign scope must break the walk");
    assert!(
        matches!(brk.kind, ChainBreakKind::ForeignScope { .. }),
        "expected a foreign-scope break, got {brk}"
    );
}

/// THE TERMINAL DECIDES THE WORD, NOT THE STATUS ALONE.
///
/// `upstream_failed` rides `dispatched`: the call went out and the far end broke, and recording that
/// as a refusal would say the opposite of what happened. The two unambiguous governance statuses get
/// their own distinguishable reasons, and everything else chains an EMPTY reason rather than a
/// guessed one — the assertion on 400 is the one that pins that restraint, because 400 is a
/// malformed body on one path and a vendor's quota shape on another.
#[test]
fn the_outcome_words_follow_the_terminal_and_the_unguessable_reason_stays_empty() {
    assert_eq!(
        outcome_of(Terminal::Admitted, 200),
        (OUTCOME_DISPATCHED, "")
    );
    assert_eq!(
        outcome_of(Terminal::Admitted, 503),
        (OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED),
        "a dispatched request whose upstream failed must not be recorded as a refusal"
    );
    assert_eq!(
        outcome_of(Terminal::Rejected, 403),
        (OUTCOME_REFUSED, REASON_NOT_GRANTED)
    );
    assert_eq!(
        outcome_of(Terminal::Rejected, 429),
        (OUTCOME_REFUSED, REASON_LIMIT_EXCEEDED),
        "a spent allowance and an absent grant are different incidents with different remedies"
    );
    assert_eq!(
        outcome_of(Terminal::Rejected, 400),
        (OUTCOME_REFUSED, ""),
        "400 is a malformed body on one path and Bedrock's quota shape on another; a reason \
         inferred from it would send an operator somewhere wrong"
    );
}

/// THE RETAINED WINDOW IS BOUNDED, AND WHAT SURVIVES IS STILL A VERIFIABLE CHAIN.
///
/// Eviction is oldest-first across the whole ring, so a principal's retained records are a
/// contiguous SUFFIX of its chain — which is why the read surface verifies a WINDOW and not a whole
/// chain. A ring that dropped from the middle would leave a hole the walk reports as a break, so
/// this asserts on the verification and not merely on the length.
#[test]
fn the_ring_is_bounded_and_the_surviving_suffix_still_verifies() {
    let log = LlmRequestLog::new();
    let principal = "key-bounded";
    for i in 0..(MAX_RETAINED_REQUESTS + 10) {
        log.record(principal, an_input(200 + (i % 3) as u16));
    }

    let kept = log.records_for(principal);
    assert_eq!(
        kept.len(),
        MAX_RETAINED_REQUESTS,
        "the process-wide window must be bounded"
    );
    assert_eq!(
        kept[0].seq, 11,
        "the OLDEST records are the ones evicted, so what remains is the tail of the chain"
    );
    log.verify_principal_chain(principal)
        .expect("the retained suffix must still verify as a window");
}
