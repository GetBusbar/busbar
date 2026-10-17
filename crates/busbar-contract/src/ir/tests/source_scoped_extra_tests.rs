// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the one source-scoped extras alias, [`SourceScopedExtra`](super::SourceScopedExtra).

use super::SourceScopedExtra;
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn source_scoped_extra_namespaces_by_protocol() {
    let mut e: SourceScopedExtra = BTreeMap::new();
    e.entry("widget".into())
        .or_default()
        .insert("logprobs".into(), Value::Bool(true));
    assert!(e["widget"].contains_key("logprobs"));
    assert!(
        !e.contains_key("gadget"),
        "a foreign protocol's namespace is absent, not merged"
    );
}
