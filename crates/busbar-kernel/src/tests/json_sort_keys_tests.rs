// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JSON-STACK §8 T5: the kernel's JSON facade emits the same bytes whether or not sonic-rs's
//! `sort_keys` feature is on. `dist/default` unifies `sort_keys` into the kernel's sonic-rs through
//! the llm plane (JSON-STACK §2.8 "Feature unification"); the kernel builds no owned
//! `sonic_rs::Value` object, so nothing it emits may move. CI runs this test twice: in the root
//! workspace run, and alone with `--features sonic-rs/sort_keys` (the QA tier's
//! `kernel-sort-keys` step). Both runs compare against the same literals below.

use std::collections::{BTreeMap, HashMap};

use super::*;

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Typed {
    name: String,
    count: u64,
    ratio: f64,
    tags: Vec<String>,
    by_key: BTreeMap<String, u64>,
    single: HashMap<String, i64>,
    nested: Option<Box<Typed>>,
}

/// Keys out of order on the way in; the typed map orders them, the struct keeps field order.
const TYPED_IN: &[u8] = br#"{"nested":{"name":"inner","count":0,"ratio":0.25,"tags":[],"by_key":{},"single":{},"nested":null},"single":{"k":-1},"by_key":{"z":3,"a":1,"m":2},"tags":["b","a"],"ratio":0.5,"count":7,"name":"n"}"#;

const TYPED_OUT: &str = r#"{"name":"n","count":7,"ratio":0.5,"tags":["b","a"],"by_key":{"a":1,"m":2,"z":3},"single":{"k":-1},"nested":{"name":"inner","count":0,"ratio":0.25,"tags":[],"by_key":{},"single":{},"nested":null}}"#;

#[test]
fn kernel_json_bytes_unchanged_with_sort_keys() {
    // The typed round trip: parse::<T> then to_vec / to_string.
    let typed: Typed = parse(TYPED_IN).expect("the typed fixture parses");
    let bytes = to_vec(&typed).expect("the typed fixture serialises");
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), TYPED_OUT);
    assert_eq!(to_string(&typed).unwrap(), TYPED_OUT);
    let again: Typed = parse(TYPED_OUT.as_bytes()).expect("the output parses back");
    assert_eq!(again, typed);
    let parsed_str: Typed = parse_str(TYPED_OUT).expect("parse_str reads the same text");
    assert_eq!(parsed_str, typed);

    // The one production caller, `ingress_error`: an error envelope through `to_string`.
    let (envelope, _) =
        crate::ingress::protocols::error_parts("openai", 400, "invalid_request", "bad");
    assert_eq!(
        to_string(&envelope).unwrap(),
        r#"{"error":{"message":"bad","type":"invalid_request"}}"#
    );
}
