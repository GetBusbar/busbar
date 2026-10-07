// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODEL LISTING, rendered by this plane (ARCHITECT RULING D, 2026-10-07): for the kernel's
//! visible names, the plane picks the dialect by its own rule (the caller's fingerprint fields and
//! the path) and renders that dialect's list envelope. Pinned to the bytes the kernel answered
//! before the listing moved here (`fixtures/list_models_1_5_5.cells`, the 1.5.5 bytes), and the
//! re-homed kernel envelope tests (`busbar-kernel/tests/endpoints_cross_plane.rs`
//! `test_v1_models_anthropic_fingerprint_gets_anthropic_envelope`,
//! `test_v1_models_gemini_fingerprint_gets_gemini_envelope`).

use busbar_plane_llm::exchange::listing::{render, CONTENT_TYPE};
use serde_json::Value;

const CELLS: &str = include_str!("fixtures/list_models_1_5_5.cells");

/// The names the kernel hands over for a cell's grant, in its order (pools sorted, then the direct
/// models a visible pool reaches, sorted).
fn names_for(key: &str) -> &'static [&'static str] {
    match key {
        "pool-a" => &["pool-a", "model-a0", "model-a1"],
        "empty" => &[],
        _ => &["pool-a", "pool-b", "model-a0", "model-a1", "model-b"],
    }
}

fn head(col: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    if col == "-" {
        return Vec::new();
    }
    col.split(',')
        .map(|f| {
            let (n, v) = f.split_once('=').expect("name=value");
            (n.as_bytes().to_vec(), v.as_bytes().to_vec())
        })
        .collect()
}

fn rendered(path: &str, fields: &[(Vec<u8>, Vec<u8>)], names: &[&str]) -> Value {
    let head: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    let l = render(path, &head, names);
    serde_json::from_slice(&l.body).expect("a JSON listing")
}

/// EVERY RECORDED CELL, byte for byte: status, content type and body, for every fingerprint variant
/// and both paths, under each grant's names.
#[test]
fn every_recorded_listing_cell_renders_its_bytes() {
    let mut checked = 0;
    for line in CELLS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let cols: Vec<&str> = line.splitn(6, " | ").collect();
        assert_eq!(cols.len(), 6, "a cell has six columns: {line}");
        let fields = head(cols[1]);
        let fields: Vec<(&[u8], &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        let l = render(cols[0], &fields, names_for(cols[2]));
        assert_eq!(l.status.to_string(), cols[3], "status: {line}");
        assert_eq!(l.fields, vec![CONTENT_TYPE], "fields: {line}");
        assert_eq!(cols[4], CONTENT_TYPE.1, "content type: {line}");
        assert_eq!(String::from_utf8_lossy(&l.body), cols[5], "body: {line}");
        checked += 1;
    }
    assert_eq!(checked, 48, "every recorded cell ran");
}

/// The Anthropic SDK always sends `anthropic-version` — the same path answers in the Anthropic list
/// envelope for those callers. (Re-homed from the kernel.)
#[test]
fn test_v1_models_anthropic_fingerprint_gets_anthropic_envelope() {
    let fields = vec![(b"anthropic-version".to_vec(), b"2023-06-01".to_vec())];
    let body = rendered("/v1/models", &fields, names_for("open"));
    assert_eq!(body["has_more"], false, "Anthropic list envelope");
    let first = &body["data"][0];
    assert_eq!(first["type"], "model");
    assert_eq!(first["id"], "pool-a");
    assert!(body.get("object").is_none(), "no OpenAI envelope fields");
}

/// Gemini callers (x-goog-api-key, or the /v1beta path their SDK uses) get the Gemini models
/// envelope with `models/<id>` resource names. (Re-homed from the kernel.)
#[test]
fn test_v1_models_gemini_fingerprint_gets_gemini_envelope() {
    let fields = vec![(b"x-goog-api-key".to_vec(), b"k".to_vec())];
    let body = rendered("/v1/models", &fields, names_for("open"));
    assert_eq!(body["models"][0]["name"], "models/pool-a");
    let beta = rendered("/v1beta/models", &[], names_for("open"));
    assert_eq!(
        beta["models"][0]["name"], "models/pool-a",
        "/v1beta path implies Gemini"
    );
}

/// The credential's VALUE never steers the dialect: the kernel hands a never-kept field by name
/// alone, and a gemini caller's empty key field still names gemini.
#[test]
fn a_fingerprint_field_by_name_alone_picks_its_dialect() {
    let fields = vec![(b"x-goog-api-key".to_vec(), Vec::new())];
    let body = rendered("/v1/models", &fields, names_for("open"));
    assert_eq!(body["models"][0]["name"], "models/pool-a");
}
