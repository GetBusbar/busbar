// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the one reading of `public_url`.

use super::*;

#[test]
fn the_path_is_replaced_and_query_and_fragment_dropped() {
    assert_eq!(
        absolute("https://gw.example/some/prefix?x=1#f", "/a2a").as_deref(),
        Some("https://gw.example/a2a")
    );
}

#[test]
fn a_base_that_is_not_a_url_reads_as_none() {
    assert_eq!(absolute("not a url", "/a2a"), None);
}
