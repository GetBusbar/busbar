// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The flat field walker (`codec/carry.rs`) over a test table: read, write, word tables, nested
//! paths, the same-dialect fidelity park and the modelled keys.

use super::*;
use crate::codec::ir::{IrModality, IrRequest, IrServiceTier, IrVerbosity};
use serde_json::json;

const TIERS: &[Word] = &[
    ("standard_only", "default", Dir::Both),
    ("auto", "auto", Dir::Both),
    ("auto", "priority", Dir::Write),
];

const GROUP_A: &[Field] = &[
    row(&["metadata"], Slot::Metadata, Codec::Plain).park(),
    row(&["tier"], Slot::ServiceTier, Codec::Words(TIERS)).park(),
];
const GROUP_B: &[Field] = &[
    row(&["text", "verbosity"], Slot::Verbosity, Codec::Plain).park(),
    row(&["user_id"], Slot::SafetyIdentifier, Codec::Plain).park(),
    row(&["alt_user_id"], Slot::SafetyIdentifier, Codec::Plain).park(),
    row(
        &["modes"],
        Slot::OutputModalities,
        Codec::Hook(Hook::ChatModalities),
    )
    .park(),
];
const TABLE: Table = &[GROUP_A, GROUP_B];

fn read_obj(v: Value) -> IrRequest {
    let mut ir = IrRequest::default();
    read(TABLE, v.as_object().expect("object"), &mut ir);
    ir
}

fn written(ir: &IrRequest) -> Value {
    let mut out = Map::new();
    write(TABLE, ir, Egress::default(), &mut out);
    Value::Object(out)
}

#[test]
fn reads_every_row_into_its_slot() {
    let ir = read_obj(json!({
        "metadata": {"a": "1", "b": "2"},
        "tier": "standard_only",
        "text": {"verbosity": "low", "format": {"type": "text"}},
        "user_id": "u-1",
        "modes": ["text"],
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
    assert_eq!(ir.output_modalities, Some(vec![IrModality::Text]));
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
    let one_way: &[Word] = &[("w", "n", Dir::Write), ("r", "m", Dir::Read)];
    assert_eq!(word_in(one_way, "w"), None);
    assert_eq!(word_out(one_way, "n"), Some("w"));
    assert_eq!(word_in(one_way, "r"), Some("m"));
    assert_eq!(word_out(one_way, "m"), None);
}

#[test]
fn a_nested_row_overlays_the_container_already_written() {
    let ir = IrRequest {
        verbosity: Some(IrVerbosity::Medium),
        ..Default::default()
    };
    let mut out = Map::new();
    out.insert("text".to_string(), json!({"format": {"type": "text"}}));
    write(TABLE, &ir, Egress::default(), &mut out);
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
    assert_eq!(k, ["metadata", "tier", "user_id", "alt_user_id", "modes"]);
}

const SAMPLING: &[Field] = &[
    row(&["temperature"], Slot::Temperature, Codec::Plain)
        .clamp(0.0, 1.0, "clamped", true)
        .drop_if(Cond::Thinking, "omitted", true),
    row(&["stop"], Slot::Stop, Codec::Plain).cap(2, "Test"),
    row(&["seed"], Slot::Seed, Codec::Plain),
];

fn write_sampling(ir: &IrRequest, thinking: bool) -> Value {
    let mut out = Map::new();
    write(&[SAMPLING], ir, Egress { thinking }, &mut out);
    Value::Object(out)
}

#[test]
fn modifiers_clamp_cap_and_drop_on_write() {
    let ir = IrRequest {
        temperature: Some(1.5),
        stop: vec!["a".into(), "b".into(), "c".into()],
        seed: Some(-7),
        ..Default::default()
    };
    assert_eq!(
        write_sampling(&ir, false),
        json!({"temperature": 1.0, "stop": ["a", "b"], "seed": -7})
    );
    assert_eq!(
        write_sampling(&ir, true),
        json!({"stop": ["a", "b"], "seed": -7}),
        "thinking drops the temperature row"
    );
    assert_eq!(clamp(0.7, 0.0, 1.0), (0.7, false));
    assert_eq!(clamp(-0.3, 0.0, 1.0), (0.0, true));
    let (nan, changed) = clamp(f64::NAN, 0.0, 1.0);
    assert!(nan.is_nan() && !changed);
}

#[test]
fn stop_reads_a_string_or_an_array_and_unparked_rows_never_park() {
    let mut ir = IrRequest::default();
    read(&[SAMPLING], json!({"stop": "END", "seed": 1.5}).as_object().unwrap(), &mut ir);
    assert_eq!(ir.stop, vec!["END".to_string()]);
    assert_eq!(ir.seed, None);
    assert!(ir.extra.is_empty(), "rows without park leave extra alone");
}
