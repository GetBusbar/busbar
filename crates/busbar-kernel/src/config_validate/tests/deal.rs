// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEAL's REDs (TODO step 9): a section reaches only its plugin, a reserved key is stripped,
//! and a refusal names the operator's file position in 1.5.5's bytes.

use super::*;
use serde_json::json;

fn doc(text: &str) -> Document {
    Document::parse(text.to_owned()).expect("the document parses")
}

fn verbs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

const DOC: &str = "\
listen: 0.0.0.0:8080
store:
  module: memory
  settings:
    p: 1
hooks:
  h1:
    module: m
    settings:
      k: 1
  h2:
    module: m
    settings:
      k: 2
tools:
  t1:
    url: a
agents:
  a1:
    url: b
";

/// RED: each plugin is dealt its own section and nothing of another's.
#[test]
fn red_a_section_reaches_only_its_plugin() {
    let d = doc(DOC);
    let tools = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(tools.settings, json!({"tools": {"t1": {"url": "a"}}}));
    assert_eq!(tools.at, vec![verbs(&["tools"])]);
    // Every stated verb the document writes, and only those.
    let both = d
        .deal(Seat::Verbs(&verbs(&["agents", "unwritten"])))
        .expect("dealt");
    assert_eq!(both.settings, json!({"agents": {"a1": {"url": "b"}}}));
    assert!(d.deal(Seat::Verbs(&verbs(&["unwritten"]))).is_none());

    let h1 = d.deal(Seat::Instance(Kind::Hook, "h1")).expect("dealt");
    assert_eq!(h1.settings, json!({"k": 1}));
    assert_eq!(h1.at, vec![verbs(&["hooks", "h1", "settings"])]);
    let store = d.deal(Seat::Instance(Kind::Store, "store")).expect("dealt");
    assert_eq!(store.settings, json!({"p": 1}));
    assert!(d.deal(Seat::Instance(Kind::Hook, "h3")).is_none());
    assert!(d.deal(Seat::Instance(Kind::Transport, "t")).is_none());
}

/// RED: the reserved core-owned sub-keys are read off a section's own level and off each of its
/// registrations, and never cross.
#[test]
fn red_a_reserved_key_is_stripped() {
    let d = doc("\
tools:
  hooks: [g]
  upstream_credentials: own
  rate_card: {x: 1}
  fees: {per_request: 1}
  work: {max_live: 4}
  t1:
    url: a
    keep: 1
    breaker: {trip: 3}
    on_exhausted: reject
    gates: [g]
    hooks: [h]
    affinity: {header_name: x}
    tier: big
    repeatable: [read]
    upstream_credentials: passthrough
");
    let s = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(
        s.settings,
        json!({"tools": {"t1": {"url": "a", "keep": 1}}})
    );
    let mut paths: Vec<String> = s.reserved.iter().map(|(p, _)| p.join(".")).collect();
    paths.sort();
    let mut want = vec![
        "tools.hooks",
        "tools.upstream_credentials",
        "tools.rate_card",
        "tools.fees",
        "tools.work",
        "tools.t1.breaker",
        "tools.t1.on_exhausted",
        "tools.t1.gates",
        "tools.t1.hooks",
        "tools.t1.affinity",
        "tools.t1.tier",
        "tools.t1.repeatable",
        "tools.t1.upstream_credentials",
    ];
    want.sort_unstable();
    assert_eq!(paths, want);
    // The kernel keeps what it read.
    assert!(s
        .reserved
        .contains(&(verbs(&["tools", "t1", "tier"]), json!("big"))));
    assert!(!is_reserved("url"));
}

/// RED: a refusal names the node's file position, in the bytes the YAML library 1.5.5 parsed with
/// prints for a refusal raised at that node.
#[test]
fn red_a_refusal_names_its_position() {
    let d = doc(DOC);
    let tools = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(d.refuse(&tools, "bad"), "tools: bad at line 16 column 3");
    assert_eq!(
        d.refusal(&verbs(&["tools", "t1"]), "nope"),
        "tools.t1: nope at line 17 column 5"
    );
    assert_eq!(
        d.position(&verbs(&["hooks", "h2", "settings", "k"])),
        Some(Position {
            line: 14,
            column: 10
        })
    );
    // No such node: the path, unpositioned.
    assert_eq!(d.position(&verbs(&["tools", "t9"])), None);
    assert_eq!(d.refusal(&verbs(&["tools", "t9"]), "r"), "tools.t9: r");

    // Byte-identical to the library's own refusal raised at the same node (1.5.5's form): a value of
    // the wrong type, refused at that value. (An unknown field is raised at its KEY, a node no
    // section path names, so it is not the comparison.)
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Entry {
        url: String,
    }
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Root {
        tools: std::collections::BTreeMap<String, Entry>,
    }
    let text = "tools:\n  t1:\n    url: [1]\n";
    let library = serde_yaml::from_str::<Root>(text).expect_err("refused");
    assert_eq!(
        doc(text).refusal(
            &verbs(&["tools", "t1", "url"]),
            "invalid type: sequence, expected a string"
        ),
        library.to_string()
    );
}

/// A stage-0 rewrite edits the value; the positions stay the ones the operator wrote.
#[test]
fn a_rewrite_keeps_the_operators_positions() {
    let mut d = doc(DOC);
    if let Some(root) = d.value_mut().as_object_mut() {
        root.remove("listen");
        root.insert("rewritten".into(), json!(true));
    }
    let tools = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(d.refuse(&tools, "bad"), "tools: bad at line 16 column 3");
}
