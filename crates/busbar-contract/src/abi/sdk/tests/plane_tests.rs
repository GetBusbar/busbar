// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dealt blob's section: empty, unwritten and `null` are the empty section; the section's
//! value otherwise, its sibling sections left alone; a blob that is not JSON or not a map refused.

use super::*;

#[test]
fn the_dealt_blob_is_read_at_the_planes_section() {
    assert_eq!(dealt_section(b"", "tools"), Ok(None));
    assert_eq!(dealt_section(b"{}", "tools"), Ok(None));
    assert_eq!(dealt_section(br#"{"models":{"m":{}}}"#, "tools"), Ok(None));
    assert_eq!(dealt_section(br#"{"tools":null}"#, "tools"), Ok(None));
    assert_eq!(
        dealt_section(br#"{"tools":{"servers":[1]},"models":{}}"#, "tools"),
        Ok(Some(serde_json::json!({"servers": [1]})))
    );
    assert_eq!(
        dealt_section(br#"{"tools":[]}"#, "tools"),
        Ok(Some(serde_json::json!([])))
    );
}

#[test]
fn a_blob_that_is_not_a_map_of_sections_is_refused() {
    assert_eq!(dealt_section(b"[]", "tools"), Err(NOT_A_MAP.to_string()));
    assert_eq!(dealt_section(b"7", "tools"), Err(NOT_A_MAP.to_string()));
    assert_eq!(
        dealt_section(b"{", "tools"),
        Err(serde_json::from_slice::<serde_json::Value>(b"{")
            .expect_err("not JSON")
            .to_string())
    );
    assert_eq!(
        NOT_A_MAP,
        "the dealt settings are not a map of the plane's sections"
    );
}
