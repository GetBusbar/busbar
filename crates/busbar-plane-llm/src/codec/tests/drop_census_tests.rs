// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROP-NAMES CENSUS: how many (dialect, IR name) drops are named by the IR name because the
//! dialect's map file has no row for the member (design F3 "Drops"; never silent, driven to 0).

// ───────────────────────────── the census ─────────────────────────────

/// The IR members a seam gate or a writer drops by name, with the rows each is looked up by.
const NAMED: &[(&str, &[&str])] = &[
    ("n", &[]),
    (
        "reasoning",
        &["reasoning_effort", "reasoning", "thinking_budget"],
    ),
    ("cache_control", &[]),
    ("stop", &[]),
    ("tool_choice", &[]),
    ("parallel_tool_calls", &[]),
    ("response_format", &[]),
    ("tools", &[]),
    ("metadata", &[]),
    ("top_k", &[]),
    ("top_logprobs", &[]),
    ("output_modalities", &[]),
    ("logprobs", &[]),
    ("service_tier", &[]),
    ("temperature", &[]),
    ("top_p", &[]),
];

/// The six request dialects, by the name the drop path knows each by, and the file stem of its wire
/// lock (testing/llm-conformance/wire/<stem>.wire.json).
const DIALECTS: &[(&str, &str)] = &[
    ("anthropic", "anthropic"),
    ("bedrock", "bedrock"),
    ("cohere", "cohere"),
    ("gemini", "gemini"),
    ("openai", "openai"),
    ("responses", "responses"),
];

/// Every (dialect, IR name) pair a drop could be named for is named by the caller's wire path: a
/// map-file row, or the path the dialect's reader carries the member from by code. A member the
/// dialect's reader never sets (`unread`) is never dropped from that dialect's caller. Measured 41
/// at DF-NAMES; DF-SITES drove it to 0, and it stays there.
#[test]
fn every_drop_is_named_by_the_callers_wire_path() {
    let mut unresolved = Vec::new();
    for (dialect, _) in DIALECTS {
        let unread = crate::codec::proto_codec::with_reader(dialect, |r| r.unread()).unwrap_or(&[]);
        for (name, rows) in NAMED {
            if crate::codec::drops::resolve(dialect, name, rows).is_none() && !unread.contains(name)
            {
                unresolved.push(format!("{dialect}:{name}"));
            }
        }
    }
    assert!(
        unresolved.is_empty(),
        "a drop would be named by its IR name (give the dialect a row, a request code name, or \
         declare the member unread): {unresolved:?}"
    );
}

/// An `unread` member really has no wire path in that dialect: it is not also a row or a code name.
#[test]
fn an_unread_member_has_no_wire_path() {
    for (dialect, _) in DIALECTS {
        let unread = crate::codec::proto_codec::with_reader(dialect, |r| r.unread()).unwrap_or(&[]);
        for name in unread {
            assert_eq!(
                crate::codec::drops::resolve(dialect, name, &[]),
                None,
                "{dialect} declares `{name}` unread but names a wire path for it"
            );
        }
    }
}

/// A request code name's wire path is in the dialect's wire lock (a union arm's selector may be
/// left out; below an opaque document member, the member itself is what the lock lists).
#[test]
fn every_request_code_name_is_in_the_wire_lock() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/llm-conformance/wire");
    for (dialect, stem) in DIALECTS {
        let text = std::fs::read_to_string(root.join(format!("{stem}.wire.json"))).expect("lock");
        let lock: serde_json::Value = serde_json::from_str(&text).expect("lock json");
        let paths: Vec<String> = lock["request"]
            .as_object()
            .expect("request paths")
            .keys()
            .map(|k| {
                k.split('.')
                    .filter(|step| !step.contains('='))
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect();
        let names = crate::codec::proto_codec::with_reader(dialect, |r| r.request_code_names())
            .unwrap_or(&[]);
        for (name, path) in names {
            let steps: Vec<&str> = path.split('.').collect();
            let opaque = |p: &str| {
                paths.iter().any(|l| l == p)
                    && !paths.iter().any(|l| l.starts_with(&format!("{p}.")))
            };
            let found = paths.iter().any(|l| l == path)
                || (1..steps.len()).any(|n| opaque(&steps[..n].join(".")));
            assert!(
                found,
                "{dialect}: `{name}` is named `{path}`, which its wire lock does not list"
            );
        }
    }
}
