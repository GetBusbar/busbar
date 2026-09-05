// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/lossless.rs`.

use super::*;

#[test]
fn source_scoped_extra_namespaces_by_protocol() {
    let mut e: SourceScopedExtra = BTreeMap::new();
    e.entry("openai".into())
        .or_default()
        .insert("logprobs".into(), Value::Bool(true));
    assert!(e["openai"].contains_key("logprobs"));
    assert!(
        !e.contains_key("anthropic"),
        "a foreign protocol's namespace is absent, not merged"
    );
}
