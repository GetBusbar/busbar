// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The audit record's declaration, and the bytes it frames to.

use crate::records::{
    audit_suffix, legacy_row, operations_for, parse_audit_suffix, AuditFields, OPERATIONS,
    RECORD_SCHEMAS, SCHEMA_AUDIT,
};

/// The one schema this plane declares, and the two operations an answer-shaped stream admits.
#[test]
fn the_audit_schema_declares_append_and_scan_and_nothing_else() {
    assert_eq!(RECORD_SCHEMAS, &[SCHEMA_AUDIT]);
    assert_eq!(operations_for(SCHEMA_AUDIT), OPERATIONS);
    assert_eq!(operations_for(SCHEMA_AUDIT), &["append", "scan"]);
    assert!(
        operations_for(busbar_contract::ids::RecordSchemaId::new("stranger")).is_empty(),
        "a schema this plane does not declare declares no operations"
    );
}

/// The suffix is the five fields behind a LEADING vertical bar. The leading bar is owed to the
/// chain's prelude, and a suffix without it would shift every persisted digest by one separator.
#[test]
fn the_suffix_leads_with_the_separator_it_owes_the_prelude() {
    let bytes = audit_suffix(
        1_700_000_000,
        "hook.register",
        "hook:compress",
        "applied",
        "admin",
    );
    assert_eq!(
        bytes,
        b"|1700000000|hook.register|hook:compress|applied|admin".to_vec()
    );
}

/// The parse is the inverse of the frame, field for field.
#[test]
fn the_five_fields_round_trip_through_the_suffix() {
    let fields = AuditFields {
        ts: 1_700_000_060,
        action: "hook.delete".to_string(),
        resource: "hook:compress".to_string(),
        outcome: "applied".to_string(),
        principal: "admin".to_string(),
    };
    let framed = audit_suffix(
        fields.ts,
        &fields.action,
        &fields.resource,
        &fields.outcome,
        &fields.principal,
    );
    assert_eq!(parse_audit_suffix(&framed), fields);
}

/// The previous release's FLAT row is recognised, and the suffix it rebuilds is exactly the one the
/// digest on that row was sealed over — which is what lets a deployed store verify without a
/// re-seal. The frozen bytes are one of the rows the boot-verify golden replays.
#[test]
fn a_row_from_the_previous_release_rebuilds_its_own_suffix() {
    const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
    let (seq, prev_hash, hash, content) = legacy_row(AD_1).expect("the older row is recognised");
    assert_eq!(seq, 1);
    assert_eq!(prev_hash, "");
    assert_eq!(
        hash,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"
    );
    assert_eq!(
        content,
        audit_suffix(
            1_700_000_000,
            "hook.register",
            "hook:compress",
            "applied",
            "admin"
        )
    );
}

/// Bytes nothing recognises come back as nothing, rather than as a record with zeroed fields: a row
/// this stream cannot read is evidence that has to be counted and reported, not invented.
#[test]
fn bytes_the_stream_does_not_recognise_decode_to_nothing() {
    assert!(legacy_row(b"not json at all").is_none());
    assert!(
        legacy_row(br#"{"seq":1}"#).is_none(),
        "a row missing the fields the digest was sealed over is not that row"
    );
}
