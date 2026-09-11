// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the verify step's freshness ledger (`crate::freshness`).
//!
//! The host-vtable slots this ledger came out of had two tests between them — a store-then-hit and a
//! lead-then-follow — and both drove the whole ABI to reach it. Those stay where they are, because
//! what they prove is that the slots answer through this ledger. What they could NOT reach is the
//! ledger's own behaviour at its edges: the ttl boundary, the strict-live zero, and the release a
//! leader that never came back depends on. These pin that.

use crate::freshness::{Lookup, VerifyFreshness};

const SCOPE: u32 = 0;
const SUBJECT: &[u8] = b"counterparty-a";

/// The ledger remembers the CHECK, until the moment it does not. `now < expires` is the whole rule,
/// so the last millisecond inside the ttl is fresh and the first one at it is not.
#[test]
fn a_recorded_check_is_fresh_until_its_ttl_and_stale_at_it() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(SCOPE, SUBJECT, 1_000), Lookup::Lead);
    led.record(SCOPE, SUBJECT, 10, 1_000);
    assert_eq!(
        led.look_up(SCOPE, SUBJECT, 10_999),
        Lookup::Fresh,
        "inside the ttl the check is reused"
    );
    assert_eq!(
        led.look_up(SCOPE, SUBJECT, 11_000),
        Lookup::Lead,
        "at the expiry the subject is stale again and this caller leads the re-check"
    );
}

/// A zero ttl is STRICT-LIVE: the subject is stale again immediately. It is how a caller says "check
/// this every time" without a second switch that could disagree with the ttl.
#[test]
fn a_zero_ttl_is_stale_immediately() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(SCOPE, SUBJECT, 500), Lookup::Lead);
    led.record(SCOPE, SUBJECT, 0, 500);
    assert_eq!(
        led.look_up(SCOPE, SUBJECT, 500),
        Lookup::Lead,
        "a zero ttl never reads fresh, at any clock"
    );
}

/// SINGLE FLIGHT: the first caller at a stale subject leads and every caller behind it follows, so
/// exactly one re-check is in flight. The claim is taken in the same step as the staleness reading —
/// two callers that each read "stale" before either claimed would both lead.
#[test]
fn the_first_caller_leads_and_the_rest_follow() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Lead);
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Follow);
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Follow);
}

/// THE LEADER THAT NEVER CAME BACK. Leadership is a claim held in the ledger, so a dropped leader
/// would leave every follower waiting on a re-check nobody is running. The release clears the claim,
/// and the next caller leads rather than following a leader that no longer exists.
#[test]
fn releasing_a_dropped_leader_lets_the_next_caller_lead() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Lead);
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Follow);
    led.release(SCOPE, SUBJECT);
    assert_eq!(
        led.look_up(SCOPE, SUBJECT, 0),
        Lookup::Lead,
        "the abandoned leadership is gone and this caller takes the re-check"
    );
}

/// The release is IDEMPOTENT with the record: on the happy path both run, in either order, and the
/// ledger is left in the state the next caller should read. A release after a record must not
/// un-record the verification it was nothing to do with.
#[test]
fn a_release_after_a_record_does_not_undo_the_record() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(SCOPE, SUBJECT, 0), Lookup::Lead);
    led.record(SCOPE, SUBJECT, 10, 0);
    led.release(SCOPE, SUBJECT);
    assert_eq!(
        led.look_up(SCOPE, SUBJECT, 5_000),
        Lookup::Fresh,
        "the verification stands; the release only ever clears a claim"
    );
}

/// The subject is opaque and the scope is part of it: the same bytes under two scopes are two
/// subjects, and one going fresh says nothing about the other.
#[test]
fn the_scope_is_part_of_the_subject() {
    let led = VerifyFreshness::default();
    assert_eq!(led.look_up(1, SUBJECT, 0), Lookup::Lead);
    led.record(1, SUBJECT, 10, 0);
    assert_eq!(
        led.look_up(1, SUBJECT, 0),
        Lookup::Fresh,
        "scope 1 was verified"
    );
    assert_eq!(
        led.look_up(2, SUBJECT, 0),
        Lookup::Lead,
        "the same bytes under another scope are another subject entirely"
    );
}
