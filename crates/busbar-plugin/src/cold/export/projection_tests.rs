// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the EXPORT PROJECTION GRAMMAR itself — the half that needs no config document.
//!
//! The theme of every test here is the defect class this release kept surfacing — *reports success
//! while quietly not taking effect*. These four are the ones that can only be written HERE: the two
//! disclosure-gate properties, and the two anti-drift proofs that pin [`produced_fields`] to the
//! producer it claims to describe. The tests that drive the grammar through an `export:` YAML
//! document stay with the config layer that owns that document.
//!
//! PORTED, NOT REWRITTEN: each body below is the one that lived in the retiring engine's
//! `export/tests/projection_tests.rs`, with the call sites updated for the new
//! `resolve_projection` argument (the sink's own `carries`, where a table keyed on the sink's name
//! used to be) and for `build_request_log` taking its facts as one struct.

use super::{
    build_request_log, produced_fields, resolve_projection, ProjectedRecord, Projection,
    ProjectionUnion, RequestLogFacts, PRODUCED_STREAMS,
};
use crate::cold::export::{ExportField, ExportStream};

/// Assert that SOME error mentions every one of `needles` — a projection error must NAME the thing
/// it refused, not just say no.
#[track_caller]
fn assert_error_mentions(errors: &[String], needles: &[&str]) {
    assert!(
        errors.iter().any(|e| needles.iter().all(|n| e.contains(n))),
        "no error mentioned all of {needles:?}; errors were:\n{errors:#?}"
    );
}

// ── `fields:` IS AN EXHAUSTIVE OVERRIDE, AND IT MAY NOT BREAK STRUCTURE ─────────────────────────

/// THE PINNED-FIELD RULE, proven directly against the validator (the config path for `events` is
/// blocked earlier by the module rule, so this exercises the rule itself): omitting a pinned field
/// is a config error carrying the REASON, never a silent no-op and never a silent re-add.
#[test]
fn omitting_a_pinned_field_is_a_loud_error_with_the_reason() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".to_string(),
            "ts".to_string(),
            "kind".to_string(),
            "actor".to_string(),
        ]),
        false,
        &mut errors,
    );
    assert_error_mentions(&errors, &["prev_hash", "PINNED", "events", "chain"]);
    // The refusal is total: a failed projection grants nothing.
    assert!(proj.is_empty());
}

/// `fields:` is an EXHAUSTIVE OVERRIDE, never additive: a listed set replaces the stream's defaults
/// entirely, so a default field the operator did not list is NOT granted.
#[test]
fn fields_override_replaces_the_default_set_rather_than_adding_to_it() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".to_string(),
            "ts".to_string(),
            "prev_hash".to_string(),
            "kind".to_string(),
        ]),
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    let granted = proj.granted_fields(ExportStream::Events);
    assert_eq!(
        granted,
        vec![
            ExportField::Ts,
            ExportField::Seq,
            ExportField::PrevHash,
            ExportField::Kind
        ],
        "the override must be exhaustive"
    );
    // `actor`, `resource` and `outcome` are DEFAULT fields of `events` that the operator did not
    // list. Additive semantics would hand them over anyway — that is the silent widening this rule
    // exists to prevent.
    for not_listed in [
        ExportField::Actor,
        ExportField::Resource,
        ExportField::Outcome,
    ] {
        assert!(
            !proj.grants(ExportStream::Events, not_listed),
            "{} leaked into an exhaustive override that did not list it",
            not_listed.as_token()
        );
    }
}

/// A field that belongs to no subscribed stream would never arrive — loud, not ignored.
#[test]
fn field_outside_the_subscribed_streams_is_a_loud_error() {
    let mut errors = Vec::new();
    resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&[
            "seq".into(),
            "ts".into(),
            "prev_hash".into(),
            "subject".into(),
        ]),
        false,
        &mut errors,
    );
    assert_error_mentions(
        &errors,
        &["subject", "not a field of any subscribed stream"],
    );
}

// ── THE DISCLOSURE GATE: an ungranted field is never serialized ─────────────────────────────────

/// The enforcement property, stated directly: a record built to a projection carries EXACTLY the
/// granted fields. An ungranted field is dropped at the writer, so it is never serialized and
/// therefore never crosses the ABI — an over-reading sink is impossible, not merely forbidden.
#[test]
fn projected_record_cannot_carry_an_ungranted_field() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        Some(&["seq".into(), "ts".into(), "prev_hash".into(), "kind".into()]),
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");

    let mut rec = ProjectedRecord::new(proj, ExportStream::Events);
    rec.set(ExportField::Seq, 7u64)
        .set(ExportField::Ts, 1_700_000_000u64)
        .set(ExportField::PrevHash, "abc")
        .set(ExportField::Kind, "key.delete")
        // OFFERED but NOT granted — the producer may hand it over freely; the record refuses it.
        .set(ExportField::Actor, "operator@example.com")
        .set(ExportField::Resource, "key:k1");
    let payload = rec.finish();

    let obj = payload.as_object().expect("an object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["kind", "prev_hash", "seq", "ts"]);
    // Not merely absent from the map — absent from the SERIALIZED bytes, which is the property that
    // matters: the ungranted value never crosses the ABI.
    let bytes = serde_json::to_string(&payload).unwrap();
    assert!(!bytes.contains("operator@example.com"), "{bytes}");
    assert!(!bytes.contains("actor"), "{bytes}");
}

/// A record for a stream the projection does not subscribe to carries nothing at all, even for a
/// field the projection grants on ANOTHER stream — a grant is (stream, field), never a bare field.
#[test]
fn a_grant_on_one_stream_does_not_leak_into_another() {
    let mut errors = Vec::new();
    let proj = resolve_projection(
        "chain",
        "some-event-sink",
        None,
        Some(&["events".to_string()]),
        None,
        false,
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:#?}");
    assert!(proj.grants(ExportStream::Events, ExportField::Ts));

    let mut rec = ProjectedRecord::new(proj, ExportStream::Logs);
    rec.set(ExportField::Ts, 1u64).set(ExportField::Pool, "p");
    assert_eq!(rec.finish(), serde_json::json!({}));
}

/// The compute gate's zero value: an empty union wants nothing, so no producer ever runs. (The
/// end-to-end "a configured document's union is what its instances asked for" half is proven by the
/// config layer, which is where a document exists.)
#[test]
fn an_empty_union_is_the_compute_gate_closed() {
    let empty = ProjectionUnion::default();
    assert!(empty.is_empty());
    for s in ExportStream::ALL {
        assert!(!empty.wants_stream(*s));
    }
}

// ── ANTI-DRIFT: the produced-field table must match the producer it claims to describe ──────────

/// `produced_fields(Logs)` claims to be exactly what `build_request_log` fills in. Prove it against
/// the producer itself, so the table cannot drift from the code and quietly start promising a field
/// nothing writes (which is how a "no producer" gate turns into a lie).
///
/// This is the test that could not be written while the table and the producer were in different
/// crates, and it is why `build_request_log` moved here rather than to the fan-out that calls it.
#[test]
fn produced_logs_fields_match_the_request_log_producer() {
    // A projection granting EVERY documented logs field: whatever the producer writes, gets through.
    let all_logs = Projection::for_test(&[ExportStream::Logs], ExportStream::Logs.default_fields());
    let payload = build_request_log(
        all_logs,
        &RequestLogFacts {
            ts: 1,
            ingress_protocol: "openai",
            pool: "p",
            outcome: "ok",
            latency_ms: 5,
        },
    );
    let mut written: Vec<&str> = payload
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    written.sort_unstable();
    let mut claimed: Vec<&str> = produced_fields(ExportStream::Logs)
        .iter()
        .map(|f| f.as_token())
        .collect();
    claimed.sort_unstable();
    assert_eq!(
        written, claimed,
        "produced_fields(logs) does not match what build_request_log emits"
    );
}

/// Every produced-field table is a SUBSET of its stream's frozen documented default set — a table
/// entry outside it would grant a field the contract does not define.
#[test]
fn produced_fields_are_a_subset_of_the_documented_defaults() {
    for s in ExportStream::ALL {
        for f in produced_fields(*s) {
            assert!(
                s.default_fields().contains(f),
                "{} is claimed produced for {} but is not one of its documented fields",
                f.as_token(),
                s.as_token()
            );
        }
        if !PRODUCED_STREAMS.contains(s) {
            assert!(
                produced_fields(*s).is_empty(),
                "{} has no producer, so it can claim no produced fields",
                s.as_token()
            );
        }
    }
}
