// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The flat field walker (`codec/carry.rs`) over a test table: read, write, word tables, nested
//! paths, the same-dialect fidelity park and the modelled keys.

use super::*;
use crate::codec::ir::{IrRequest, IrServiceTier, IrVerbosity};
use serde_json::json;

const TIERS: &[Word] = &[
    ("standard_only", "default", Dir::Both),
    ("auto", "auto", Dir::Both),
    ("auto", "priority", Dir::Write),
];

fn hook_read(v: &Value, ir: &mut IrRequest) {
    ir.store = v.as_str().map(|s| s == "yes");
}

fn hook_write(r: &IrRequest) -> Option<Value> {
    r.store.map(|s| json!(if s { "yes" } else { "no" }))
}

const GROUP_A: &[Field] = &[
    (&["metadata"], Slot::Metadata, Codec::Plain),
    (&["tier"], Slot::ServiceTier, Codec::Words(TIERS)),
];
const GROUP_B: &[Field] = &[
    (&["text", "verbosity"], Slot::Verbosity, Codec::Plain),
    (&["user_id"], Slot::SafetyIdentifier, Codec::Plain),
    (&["alt_user_id"], Slot::SafetyIdentifier, Codec::Plain),
    (&["keep"], Slot::Store, Codec::Hook(hook_read, hook_write)),
];
const TABLE: Table = &[GROUP_A, GROUP_B];

fn read_obj(v: Value) -> IrRequest {
    let mut ir = IrRequest::default();
    read(TABLE, v.as_object().expect("object"), &mut ir);
    ir
}

fn written(ir: &IrRequest) -> Value {
    let mut out = Map::new();
    write(TABLE, ir, &mut out);
    Value::Object(out)
}

#[test]
fn reads_every_row_into_its_slot() {
    let ir = read_obj(json!({
        "metadata": {"a": "1", "b": "2"},
        "tier": "standard_only",
        "text": {"verbosity": "low", "format": {"type": "text"}},
        "user_id": "u-1",
        "keep": "yes",
    }));
    assert_eq!(
        ir.metadata,
        Some(vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string())
        ])
    );
    assert_eq!(ir.service_tier, Some(IrServiceTier::Default));
    assert_eq!(ir.verbosity, Some(IrVerbosity::Low));
    assert_eq!(ir.safety_identifier.as_deref(), Some("u-1"));
    assert_eq!(ir.store, Some(true));
    assert!(ir.extra.is_empty(), "every member reproduces: {:?}", ir.extra);
}

#[test]
fn an_earlier_row_wins_a_shared_slot() {
    let ir = read_obj(json!({"user_id": "first", "alt_user_id": "second"}));
    assert_eq!(ir.safety_identifier.as_deref(), Some("first"));
    let ir = read_obj(json!({"alt_user_id": "second"}));
    assert_eq!(ir.safety_identifier.as_deref(), Some("second"));
}

#[test]
fn writes_carried_slots_and_omits_absent_ones() {
    let ir = IrRequest {
        service_tier: Some(IrServiceTier::Priority),
        verbosity: Some(IrVerbosity::High),
        ..Default::default()
    };
    assert_eq!(
        written(&ir),
        json!({"tier": "auto", "text": {"verbosity": "high"}})
    );
    assert_eq!(written(&IrRequest::default()), json!({}));
}

#[test]
fn a_word_with_no_row_is_not_written_and_a_write_only_word_is_not_read() {
    let ir = IrRequest {
        service_tier: Some(IrServiceTier::Flex),
        ..Default::default()
    };
    assert_eq!(written(&ir), json!({}));
    assert_eq!(word_in(TIERS, "auto"), Some("auto"));
    assert_eq!(word_out(TIERS, "priority"), Some("auto"));
    let only_write: &[Word] = &[("w", "n", Dir::Write)];
    assert_eq!(word_in(only_write, "w"), None);
}

#[test]
fn a_nested_row_overlays_the_container_already_written() {
    let ir = IrRequest {
        verbosity: Some(IrVerbosity::Medium),
        ..Default::default()
    };
    let mut out = Map::new();
    out.insert("text".to_string(), json!({"format": {"type": "text"}}));
    write(TABLE, &ir, &mut out);
    assert_eq!(
        Value::Object(out),
        json!({"text": {"format": {"type": "text"}, "verbosity": "medium"}})
    );
}

#[test]
fn a_member_the_slot_cannot_reproduce_is_parked_raw_in_extra() {
    let ir = read_obj(json!({
        "metadata": {"a": 1},
        "tier": "turbo",
        "user_id": "ok",
    }));
    assert_eq!(ir.metadata, None);
    assert_eq!(ir.service_tier, None);
    assert_eq!(ir.extra.get("metadata"), Some(&json!({"a": 1})));
    assert_eq!(ir.extra.get("tier"), Some(&json!("turbo")));
    assert!(!ir.extra.contains_key("user_id"));
    // A nested row's container is the dialect's own: never parked by the walker.
    let ir = read_obj(json!({"text": {"verbosity": "loud"}}));
    assert!(ir.extra.is_empty());
}

#[test]
fn keys_are_the_single_key_paths() {
    let k: Vec<&str> = keys(TABLE).collect();
    assert_eq!(k, ["metadata", "tier", "user_id", "alt_user_id", "keep"]);
}
