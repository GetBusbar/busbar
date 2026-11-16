// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pinned `content` stream schema (CONTENT-AUDIT-ENGINE-REVIEW section 4) cannot drift from
//! the export vocabulary: the schema file is parsed and compared with `ExportStream::Content`.

use std::collections::BTreeSet;

use busbar_contract::export_stream::{ExportStream, CONTENT_SCHEMA};
use serde::Deserialize;

#[derive(Deserialize)]
struct Schema {
    #[serde(rename = "$id")]
    id: String,
    #[serde(rename = "$defs")]
    defs: Defs,
}

#[derive(Deserialize)]
struct Defs {
    line: Shape,
    exchange: Shape,
}

#[derive(Deserialize)]
struct Shape {
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
    properties: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
}

impl Shape {
    fn members(&self) -> BTreeSet<&str> {
        self.properties.keys().map(String::as_str).collect()
    }
}

fn set(names: &[&'static str]) -> BTreeSet<&'static str> {
    names.iter().copied().collect()
}

#[test]
fn content_schema_pins_vocabulary() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/export/busbar.content.v1.schema.json"
    );
    let text = std::fs::read_to_string(path).expect("the content schema file exists");
    let schema: Schema = sonic_rs::from_str(&text).expect("the content schema file parses");

    // (1) the id is the version tag.
    assert_eq!(schema.id, CONTENT_SCHEMA);

    // (2) both shapes are closed.
    assert!(!schema.defs.line.additional_properties);
    assert!(!schema.defs.exchange.additional_properties);

    // (3) the line is the stream's default fields plus the chunk envelope.
    let mut vocabulary: BTreeSet<&str> = ExportStream::Content
        .default_fields()
        .iter()
        .map(|f| f.as_token())
        .collect();
    vocabulary.extend(["schema", "chunk", "enc", "data"]);
    assert_eq!(schema.defs.line.members(), vocabulary);

    // (4) a literal golden list: any member change fails until the version is bumped.
    assert_eq!(CONTENT_SCHEMA, "busbar.content.v1");
    assert_eq!(
        schema.defs.line.members(),
        set(&[
            "schema",
            "correlation_id",
            "ts",
            "deployment_id",
            "node_id",
            "content_ref",
            "chunk",
            "enc",
            "data",
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
}
