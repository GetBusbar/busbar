// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pinned `content` stream schema (`busbar.content.v2`, DES-EXPORT-1.6 r3 §2) cannot drift from
//! the export vocabulary, the constant or the generated C header: the schema file is parsed and
//! compared with `ExportStream::Content`, `CONTENT_SCHEMA` and `BB_EXPORT_CONTENT_SCHEMA`.

use std::collections::BTreeSet;

use busbar_contract::export_stream::{ExportStream, CONTENT_SCHEMA};
use serde::Deserialize;

#[derive(Deserialize)]
struct Schema {
    #[serde(rename = "$id")]
    id: String,
    description: String,
    #[serde(rename = "$defs")]
    defs: Defs,
}

#[derive(Deserialize)]
struct Defs {
    line: Shape,
    header: Shape,
    exchange: Shape,
    side: Shape,
    #[serde(rename = "partRef")]
    part_ref: Shape,
}

#[derive(Deserialize)]
struct Shape {
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
    properties: std::collections::BTreeMap<String, Member>,
}

#[derive(Deserialize)]
struct Member {
    #[serde(rename = "additionalProperties")]
    additional_properties: Option<bool>,
    properties: Option<std::collections::BTreeMap<String, serde::de::IgnoredAny>>,
}

impl Shape {
    fn members(&self) -> BTreeSet<&str> {
        self.properties.keys().map(String::as_str).collect()
    }

    fn nested(&self, member: &str) -> BTreeSet<&str> {
        let member = &self.properties[member];
        assert_eq!(member.additional_properties, Some(false), "closed");
        member
            .properties
            .as_ref()
            .expect("an object member")
            .keys()
            .map(String::as_str)
            .collect()
    }
}

fn set(names: &[&'static str]) -> BTreeSet<&'static str> {
    names.iter().copied().collect()
}

const SCHEMA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/export/busbar.content.v2.schema.json"
);

fn schema() -> Schema {
    let text = std::fs::read_to_string(SCHEMA_PATH).expect("the content schema file exists");
    sonic_rs::from_str(&text).expect("the content schema file parses")
}

#[test]
fn content_schema_v2_pinned() {
    let schema = schema();

    // (1) the id is the version tag, and v1 is gone.
    assert_eq!(schema.id, CONTENT_SCHEMA);
    assert_eq!(CONTENT_SCHEMA, "busbar.content.v2");
    assert!(
        !std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/export/busbar.content.v1.schema.json"
        ))
        .exists(),
        "the v1 pin is deleted with its shape"
    );

    // (3) every shape is closed.
    for shape in [
        &schema.defs.line,
        &schema.defs.header,
        &schema.defs.exchange,
        &schema.defs.side,
        &schema.defs.part_ref,
    ] {
        assert!(!shape.additional_properties);
    }

    // (4) the line is the stream's default fields plus the identity and chunk envelope.
    let mut vocabulary: BTreeSet<&str> = ExportStream::Content
        .default_fields()
        .iter()
        .map(|f| f.as_token())
        .collect();
    vocabulary.extend(["schema", "object", "variant", "delivery", "chunk", "data"]);
    assert_eq!(schema.defs.line.members(), vocabulary);

    // (5) a literal golden list: any member change fails until the version is bumped.
    assert_eq!(
        schema.defs.line.members(),
        set(&[
            "schema",
            "correlation_id",
            "ts",
            "deployment_id",
            "node_id",
            "content_ref",
            "object",
            "variant",
            "delivery",
            "chunk",
            "data",
        ])
    );
    assert_eq!(
        schema.defs.line.nested("chunk"),
        set(&["part", "index", "of", "sha256", "encoding"])
    );
    assert_eq!(
        schema.defs.header.members(),
        set(&[
            "schema",
            "correlation_id",
            "ts",
            "deployment_id",
            "node_id",
            "object",
            "variant",
            "manifest_sha256",
            "of",
            "custody_reached",
            "custody_floor",
        ])
    );
    assert_eq!(
        schema.defs.exchange.members(),
        set(&[
            "schema",
            "record_id",
            "started_at",
            "ended_at",
            "plane",
            "dialect",
            "pool",
            "key_id",
            "groups",
            "model_requested",
            "model_served",
            "request",
            "response",
            "redaction",
            "sampling",
        ])
    );
    assert_eq!(schema.defs.side.members(), set(&["body", "parts"]));
    assert_eq!(
        schema.defs.exchange.nested("response"),
        set(&["body", "parts", "assembled", "end"])
    );
    assert_eq!(schema.defs.part_ref.members(), set(&["$part", "sha256"]));
}

/// The schema doc states the writer rules and the exact identity byte layout, so a consumer can
/// re-derive `object` and `variant` from the doc alone (DES-EXPORT-1.6 r3 §3 #226, #228).
#[test]
fn content_schema_v2_states_writer_rules_and_identity_layout() {
    let doc = schema().description;
    for needle in [
        "every number is an integer",
        "no RFC 8785",
        "never parsed",
        "CONTENT_LINE_BYTES = 983040",
        "be32(n) is n as a 4-byte big-endian unsigned integer",
        "`busbar.content.object.v1`",
        "`busbar.content.variant.v1`",
        "the fixed marker `literal`",
        "a resolved secret value is never hashed",
        "custody at the level the sink reports",
    ] {
        assert!(doc.contains(needle), "the schema doc states {needle:?}");
    }
}
