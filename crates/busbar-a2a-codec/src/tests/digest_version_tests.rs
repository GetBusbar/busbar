// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST-FRAMING VERSION A ROW THAT PREDATES THE FIELD-INJECTION FIX IS READ UNDER.
//!
//! `TaskEventRow.digest_version` decides which preimage a stored event's `hash` is re-derived from
//! when the chain is verified. Rows persisted before the fix carry NO such member, and serde fills
//! it from `default_digest_version()`. That default is the entire compatibility story for every
//! chain already on disk: read a pre-fix row under framing v2 and its hash will not reproduce, so
//! a verifiable chain reads as tampered.
//!
//! The suite beside this one round-trips an event that sets `digest_version` EXPLICITLY, so the
//! default was never taken. Mutation confirmed it: `default_digest_version` could return `0` — a
//! framing version that does not exist — with every test still green.
//!
//! What is asserted here is the ABSENT member's answer, reached the only way a pre-fix row reaches
//! it: by deserializing a body that does not contain the key.

use super::*;

/// A stored `task_event` body from BEFORE the versioned digest: every member the row had at the
/// time, and no `digest_version`. Written as literal JSON rather than by serializing a struct,
/// because a struct cannot express the member's absence — which is the whole case under test.
const PRE_FIX_ROW_BODY: &str = r#"{
    "task_id": "t-1",
    "seq": 1,
    "ts": 10,
    "kind": "task.submitted",
    "context_id": "ctx-1",
    "principal": "key-1",
    "agent_id": "",
    "state": "submitted",
    "request_id": "req-1",
    "prev_hash": "",
    "hash": "deadbeef"
}"#;

/// A row with no `digest_version` is read under the LEGACY PIPE framing, because that is the
/// framing it was actually sealed under. Any other answer makes an untampered pre-fix chain fail
/// verification.
#[test]
fn a_row_without_a_digest_version_is_read_under_the_legacy_framing() {
    let row = TaskEventRow::from_body(PRE_FIX_ROW_BODY.as_bytes())
        .expect("a pre-fix row must still decode");
    assert_eq!(
        row.digest_version, DIGEST_VERSION_LEGACY_PIPE,
        "an absent digest_version defaulted to {} — a pre-fix chain now re-derives its hashes \
         under a framing it was never sealed with, and reads as tampered",
        row.digest_version
    );
}

/// The default is a framing that EXISTS. Stated separately from the equality above because the two
/// fail differently: the assertion above catches a default that picked the wrong real version, and
/// this one catches a default of `0` — a version number no writer ever emits and no verifier has a
/// preimage for, which turns a compatibility default into an unreadable row.
#[test]
fn the_defaulted_digest_version_names_a_framing_that_exists() {
    let row = TaskEventRow::from_body(PRE_FIX_ROW_BODY.as_bytes()).expect("decodes");
    assert!(
        row.digest_version == DIGEST_VERSION_LEGACY_PIPE
            || row.digest_version == DIGEST_VERSION_LEN_PREFIXED,
        "digest_version defaulted to {}, which is not a framing this crate defines",
        row.digest_version
    );
    assert_ne!(row.digest_version, 0, "0 is not a digest framing version");
}

/// The two framings are DIFFERENT numbers, and the legacy one is the lower. If they ever collapsed
/// to one value the version gate would stop gating anything — every row would verify under
/// whichever framing the reader happened to pick.
#[test]
fn the_two_digest_framings_are_distinguishable_from_each_other() {
    assert_ne!(
        DIGEST_VERSION_LEGACY_PIPE, DIGEST_VERSION_LEN_PREFIXED,
        "the version gate cannot gate anything if both framings share a number"
    );
    // Ordering stated through `min` rather than as a bare `<` on two constants: clippy rejects an
    // `assert!` whose whole expression is const-evaluable, and the point here is the ORDER, which
    // `min` states without asking the lint to look the other way.
    assert_eq!(
        DIGEST_VERSION_LEGACY_PIPE.min(DIGEST_VERSION_LEN_PREFIXED),
        DIGEST_VERSION_LEGACY_PIPE,
        "the legacy framing must sort below the framing that replaced it"
    );
    assert_eq!(DIGEST_VERSION_LEGACY_PIPE, 1);
    assert_eq!(DIGEST_VERSION_LEN_PREFIXED, 2);
}

/// A row that STATES its framing keeps the one it states — the default must not overwrite an
/// explicit member. This is the other half of the gate: a v2 row read as v1 fails verification just
/// as surely as a v1 row read as v2.
#[test]
fn a_row_that_states_its_digest_version_keeps_it() {
    let stated = PRE_FIX_ROW_BODY.replace(
        r#""hash": "deadbeef""#,
        r#""hash": "deadbeef", "digest_version": 2"#,
    );
    let row = TaskEventRow::from_body(stated.as_bytes()).expect("decodes");
    assert_eq!(
        row.digest_version, DIGEST_VERSION_LEN_PREFIXED,
        "an explicitly stated framing was replaced by the compatibility default"
    );
}
