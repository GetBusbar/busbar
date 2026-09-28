// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-CODE DRIFT GUARD (#83a O4): every code this plane defines is the published catalog's
//! entry of the same number, field for field — number, class, slug, title, severity, summary, action,
//! since and the retired flag. The published catalog is `docs/diagnostics.json`, which the host
//! renders from its registry and holds byte-identical to that registry with its own drift test; so a
//! constant edited here and not in the host catalog, or there and not here, fails one of the two.

use super::DIAGNOSTICS;

fn published() -> Vec<serde_json::Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");
    let text = std::fs::read_to_string(path).expect("docs/diagnostics.json is readable");
    serde_json::from_str(&text).expect("docs/diagnostics.json is a JSON array")
}

#[test]
fn every_plane_code_is_the_catalog_entry_of_its_number() {
    let catalog = published();
    for &d in DIAGNOSTICS {
        let entry = catalog
            .iter()
            .find(|e| e["number"] == u64::from(d.code))
            .unwrap_or_else(|| panic!("BUSBAR-{:04} is not in the published catalog", d.code));
        let class = format!("{:?}", d.class).to_lowercase();
        let ours = serde_json::json!({
            "code": format!("BUSBAR-{:04}", d.code),
            "number": d.code,
            "class": class,
            "slug": d.slug,
            "title": d.title,
            "severity": d.severity.as_str(),
            "summary": d.summary,
            "action": d.action,
            "since": d.since,
            "retired": d.retired,
        });
        assert_eq!(
            &ours, entry,
            "BUSBAR-{:04} differs from the published catalog entry",
            d.code
        );
    }
}

#[test]
fn the_plane_declares_fifteen_distinct_codes() {
    let mut codes: Vec<u16> = DIAGNOSTICS.iter().map(|d| d.code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 15, "a plane code is listed twice or missing");
}
