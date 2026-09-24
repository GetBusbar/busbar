// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What `router.rs` says about itself, held to what it does (items 560, 561, 564).
//!
//! Each of these docs was wrong in a way a maintainer would act on: one described the exact
//! byte-equality bug the 413 reshape was fixed to remove, one sent a reader auditing the production
//! request path to a builder production never constructs, and one documented the inbound-concurrency
//! cap on the wrong function. They are read here from the source, because rustdoc attaches a doc to
//! whatever item follows it and says nothing when that is the wrong one.

const SRC: &str = include_str!("../router.rs");

/// The doc comment rustdoc attaches to the item whose declaration line starts with `item`: the
/// contiguous `///` lines directly above it (attributes between the two are skipped, as rustdoc
/// skips them).
fn doc_of(item: &str) -> String {
    let lines: Vec<&str> = SRC.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with(item))
        .unwrap_or_else(|| panic!("router.rs declares `{item}`"));
    let mut doc = Vec::new();
    for line in lines[..at].iter().rev() {
        let t = line.trim_start();
        if t.starts_with("#[") {
            continue;
        }
        match t.strip_prefix("///") {
            Some(text) => doc.push(text.trim()),
            None => break,
        }
    }
    doc.reverse();
    doc.join(" ")
}

#[test]
fn the_413_reshape_doc_says_substring_not_byte_equality() {
    let doc = doc_of("pub(crate) async fn reshape_oversized_413(");
    assert!(
        !doc.contains("exactly equal"),
        "the reshape doc describes the byte-equality match the marker's own doc calls the bug: {doc}"
    );
    assert!(doc.contains("CONTAINS"), "{doc}");
    // And the code is still the substring match the doc now names.
    assert!(SRC.contains(".windows(AXUM_BODY_LIMIT_413_MARKER.len())"));
}

#[test]
fn build_router_does_not_claim_production_calls_the_combined_builder() {
    let doc = doc_of("pub fn build_router(");
    assert!(
        !doc.contains("production (`main`) calls `build_router_with_limits`"),
        "build_router's doc sends the reader to a builder production never constructs: {doc}"
    );
    assert!(doc.contains("build_split_routers_with_limits"), "{doc}");
    let combined = doc_of("pub fn build_router_with_limits(");
    assert!(
        combined.contains("Used only by the test harness"),
        "{combined}"
    );
}

#[test]
fn the_inbound_concurrency_doc_is_on_the_function_it_describes() {
    let cap = doc_of("pub(crate) fn apply_inbound_concurrency_limit(");
    assert!(
        cap.contains("OUTERMOST inbound-concurrency cap"),
        "apply_inbound_concurrency_limit ships undocumented: {cap:?}"
    );
    assert!(cap.contains("opts OUT with `0`"), "{cap}");
    let auth = doc_of("pub(crate) fn project_auth_scope_caps(");
    assert!(
        auth.starts_with("Project the resolved `auth:` block"),
        "project_auth_scope_caps's doc opens with another function's: {auth}"
    );
    assert!(!auth.contains("inbound-concurrency"), "{auth}");
}
