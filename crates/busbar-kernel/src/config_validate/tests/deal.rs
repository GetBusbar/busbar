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
    timeout: 10s
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
        "tools.t1.timeout",
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

// ── Q-STEP9-a (ARCHITECT 2026-10-07): the strip's exact depths and the generic refusal ──────────

/// Every recorded path, joined and sorted.
fn paths(s: &Section) -> Vec<String> {
    let mut p: Vec<String> = s.reserved.iter().map(|(p, _)| p.join(".")).collect();
    p.sort();
    p
}

/// RED (base: `pools` was no reserved key, so `tools.pools` crossed whole, its pools' breakers and
/// its members' tiers with it): under a declared verb `pools` is reserved and leaves the blob, and
/// the reserved keys of each pool and each member are recorded at their exact paths besides.
#[test]
fn red_each_exact_depth_is_stripped_and_recorded_at_its_path() {
    let d = doc("\
tools:
  work: {max_live: 4}
  pools:
    p1:
      members: [{name: t1, tier: big, keep: 1}, t2]
      breaker: {trip: 3}
      repeatable: [read]
      member_granted: true
  t1:
    url: a
    tier: small
");
    let s = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(s.settings, json!({"tools": {"t1": {"url": "a"}}}));
    assert_eq!(
        paths(&s),
        [
            "tools.pools",
            "tools.pools.p1.breaker",
            "tools.pools.p1.members.0.tier",
            "tools.pools.p1.repeatable",
            "tools.t1.tier",
            "tools.work",
        ]
    );
    // The kernel keeps what it read, at its path.
    assert!(s.reserved.contains(&(
        verbs(&["tools", "pools", "p1", "members", "0", "tier"]),
        json!("big")
    )));
    assert!(s
        .reserved
        .iter()
        .any(|(p, v)| p == &verbs(&["tools", "pools"])
            && v.pointer("/p1/member_granted") == Some(&json!(true))));
    assert!(is_reserved(busbar_contract::section::RESERVED_POOLS_KEY));
}

/// No recursion: a word spelled like a reserved key BELOW the four exact depths is the plane's own
/// and crosses, and nothing is recorded for it. (RED on the base only through `pools`, which crossed
/// there; the base strip did not recurse either, so the no-recursion half is a guard.)
#[test]
fn a_reserved_word_below_the_exact_depths_is_not_stripped() {
    let d = doc("\
tools:
  t1:
    url: a
    opts: {tier: x, breaker: {trip: 1}}
  pools:
    p1:
      members: [{name: t1, meta: {tier: deep}}]
      shape: {work: 1}
");
    let s = d.deal(Seat::Verbs(&verbs(&["tools"]))).expect("dealt");
    assert_eq!(
        s.settings,
        json!({"tools": {"t1": {"url": "a", "opts": {"tier": "x", "breaker": {"trip": 1}}}}})
    );
    assert_eq!(paths(&s), ["tools.pools"]);
}

/// RED (base: a pool named after a knob was stripped from the root `pools:` section as if it were
/// that knob): under the root `pools:` section every depth-1 key but 1.5.5's two section words is a
/// POOL, and crosses; its own knobs and its members' are taken at their paths.
#[test]
fn red_root_pools_named_after_a_knob_are_pools_and_cross() {
    let d = doc("\
pools:
  hooks: [g]
  upstream_credentials: own
  tier:
    members: [{model: m, tier: large}]
    breaker: {base_cooldown_secs: 3}
  work:
    members: [{model: m}]
    affinity: {header_name: x-s}
  breaker:
    members: [{model: m}]
  rate_card:
    members: [{model: m}]
    on_exhausted: reject
");
    let s = d.deal(Seat::Verbs(&verbs(&["pools"]))).expect("dealt");
    assert_eq!(
        s.settings,
        json!({"pools": {
            "tier": {"members": [{"model": "m"}]},
            "work": {"members": [{"model": "m"}]},
            "breaker": {"members": [{"model": "m"}]},
            "rate_card": {"members": [{"model": "m"}]},
        }})
    );
    assert_eq!(
        paths(&s),
        [
            "pools.hooks",
            "pools.rate_card.on_exhausted",
            "pools.tier.breaker",
            "pools.tier.members.0.tier",
            "pools.upstream_credentials",
            "pools.work.affinity",
        ]
    );
}

/// The one generic shape judge (spec :567): a map where the knob is a list or a scalar, a map
/// holding a key the knob does not read, or a `pools`/`rate_card` map holding a non-map value, is an
/// entry by that name; a well-shaped knob, a malformed knob of the right kind, and a non-reserved
/// key are not.
#[test]
fn red_a_value_plainly_not_its_knob_names_an_entry() {
    let y = |t: &str| serde_yaml::from_str::<serde_yaml::Value>(t).expect("yaml");
    for (key, entry) in [
        ("hooks", "{url: a}"),
        ("upstream_credentials", "{url: a}"),
        ("tier", "{url: a}"),
        ("gates", "{url: a}"),
        ("repeatable", "{url: a}"),
        ("breaker", "{url: a}"),
        ("on_exhausted", "{url: a}"),
        ("affinity", "{url: a}"),
        ("work", "{url: a}"),
        ("fees", "{url: a}"),
        ("pools", "{url: a}"),
        ("rate_card", "{url: a}"),
        ("timeout", "{url: a}"),
    ] {
        assert!(names_an_entry(key, &y(entry)), "{key}: {entry}");
    }
    for (key, knob) in [
        ("hooks", "[a]"),
        ("upstream_credentials", "own"),
        ("tier", "big"),
        (
            "breaker",
            "{base_cooldown_secs: 1, max_cooldown_secs: 2, trip: {}}",
        ),
        ("on_exhausted", "reject"),
        ("on_exhausted", "{queue: {max_ms: 1}}"),
        ("affinity", "{mode: session, header_name: x}"),
        ("work", "{max_live: 2, retain_s: 3}"),
        ("fees", "{per_request: 1}"),
        ("pools", "{p: {members: [a]}}"),
        ("rate_card", "{lane: {input_utok: 1}}"),
        ("timeout", "10s"),
        // Malformed, but the knob's kind: its own reader says what is wrong.
        ("hooks", "a"),
        ("work", "5"),
        // Not a reserved key.
        ("url", "{url: a}"),
    ] {
        assert!(!names_an_entry(key, &y(knob)), "{key}: {knob}");
    }
}

/// The field lists the shape judge reads are the kernel types' own: each type, handed a key it does
/// not read, names exactly the fields the judge lists.
#[test]
fn the_knob_field_lists_are_the_kernel_types_own() {
    fn expected<T: serde::de::DeserializeOwned + std::fmt::Debug>(knob: &str) -> String {
        serde_yaml::from_str::<T>("zz: 1")
            .expect_err(knob)
            .to_string()
    }
    assert!(expected::<crate::config::pools::BreakerCfg>("breaker")
        .contains("expected one of `base_cooldown_secs`, `max_cooldown_secs`, `trip`"));
    assert!(expected::<crate::config::pools::AffinityCfg>("affinity")
        .contains("expected `mode` or `header_name`"));
    assert!(expected::<crate::config::PlaneFeesCfg>("fees")
        .contains("expected `per_request` or `per_session`"));
}

/// The sentence: 1.5.5's, to the byte, for the two section words; the same form naming the
/// core-owned setting for any other reserved key.
#[test]
fn the_reserved_name_sentence_is_1_5_5s() {
    use busbar_contract::section::reserved_name_refusal;
    assert_eq!(
        reserved_name_refusal("pools", "pool", "hooks"),
        "a pool may not be named `hooks`: that key is RESERVED at the `pools:` section level \
         (the all-pools `hooks:` attach list and `upstream_credentials:` default). Rename the pool."
    );
    assert_eq!(
        reserved_name_refusal("tools", "tool", "breaker"),
        "a tool may not be named `breaker`: that key is RESERVED at the `tools:` section level \
         (the core-owned `breaker:` setting). Rename the tool."
    );
}
