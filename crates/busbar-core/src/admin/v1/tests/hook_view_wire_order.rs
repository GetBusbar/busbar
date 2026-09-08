// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.6.0 HOOK VIEW IS A BYTE-EXACT SUPERSET OF THE 1.5.5 ONE, AT BOTH ENDS OF THE CONTRACT.
//!
//! PB-75 binds the served surface to 1.5.5 byte-for-byte except for ADDITIVE additions. `HookView`
//! gained three fields in 1.6.0 (`phase`, `fires_at`, `groups`), and where those fields sit in the
//! struct is not cosmetic — Rust field-declaration order is read by TWO different consumers:
//!
//!   * `schemars` emits `required` in declaration order, and the additive check reads 1.5.5's
//!     `required` as a strict PREFIX of 1.6.0's. A field spliced into the middle reads as a
//!     REORDER — indistinguishable, to a machine, from a contract break.
//!   * `serde_json::to_string` (which is literally what `json::ok_json` calls on the view, with no
//!     `Value` round-trip in between) emits the object's members in declaration order. A splice
//!     shifts every later 1.5.5 member's byte offset in the served body.
//!
//! 1.6.0 originally inserted `phase`/`fires_at` at indices 7-8, between `at` and `on_error`, so
//! BOTH consumers saw a reorder. Moving the three additions below `global` restores the invariant
//! these tests pin: the 1.5.5 view is a byte-exact PREFIX of the 1.6.0 view.
//!
//! The fixture is the real `busbar-headroom` hook as an actual 1.6.0 binary served it (the
//! `admin.ops|GetHooksName|ok` shadow-oracle cell), so the field VALUES pinned here are observed,
//! not invented.

use crate::admin::v1::service::project_hook_view;
use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};

/// The `busbar-headroom` hook exactly as the recorded `GET /hooks/busbar-headroom` served it: a
/// gate, plugin transport onto its own name, `prompt: rw`, `user: no`, priority 0, 50 ms deadline,
/// `on_error: nothing`, two settings keys, no `at:`, no `phase:`, no `groups:`, not global.
fn headroom() -> HookCfg {
    let mut settings = serde_json::Map::new();
    settings.insert("target_ratio".to_string(), serde_json::json!(0.8));
    settings.insert("min_savings_pct".to_string(), serde_json::json!(10));
    HookCfg {
        kind: HookKind::Gate,
        plugin: "busbar-headroom".to_string(),
        timeout_ms: 50,
        on_error: "nothing".to_string(),
        prompt: PromptAccess::Rw,
        user: UserAccess::No,
        priority: 0,
        settings,
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// The exact `body.json` of the `admin.ops|GetHooksName|ok` oracle cell, recorded off a 1.6.0
/// release binary. The harness stores the body PARSED (a `serde_json::Value`, whose map is a
/// `BTreeMap`), so the member order here is alphabetical and carries no information — the VALUES
/// are the fixture, and the order question is settled by the two tests below against
/// `serde_json::to_string`, which is what the handler actually emits.
const RECORDED_BODY: &str = r#"{"at":null,"fires_at":["request","candidate","routing","response"],"global":false,"groups":[],"kind":"gate","name":"busbar-headroom","on_error":"nothing","phase":[],"priority":0,"prompt":"rw","settings_keys":["min_savings_pct","target_ratio"],"timeout_ms":50,"transport":{"kind":"plugin","target":"busbar-headroom"},"user":"no"}"#;

/// The 1.5.5 `HookView` members, in the 1.5.5 `required` order — the frozen 1.5.5 contract, copied
/// from `testing/shadow-oracle/fixtures/openapi-1.5.5.json`
/// (`/components/schemas/HookView/required`). NOT derived from the 1.6.0 struct, on purpose: this
/// is the thing the 1.6.0 struct is being checked AGAINST.
const V155_REQUIRED: &[&str] = &[
    "name",
    "kind",
    "transport",
    "prompt",
    "user",
    "priority",
    "at",
    "on_error",
    "timeout_ms",
    "settings_keys",
    "global",
];

/// The 1.6.0 additions, in the order they must appear AFTER the 1.5.5 block.
const V160_ADDED: &[&str] = &["phase", "fires_at", "groups"];

/// Serialize a view the way the handler does: `json::ok_json` calls `serde_json::to_string` on the
/// view DIRECTLY (no `serde_json::Value` in between), so these are the bytes on the wire.
fn wire_bytes(cfg: &HookCfg) -> String {
    serde_json::to_string(&project_hook_view("busbar-headroom", cfg, &[]))
        .expect("HookView serializes")
}

/// NO FIELD CHANGED. Every member of the served body, and every value, matches the recorded 1.6.0
/// cell. Pinned as a VALUE comparison (order-insensitive) because that is the half of the contract
/// the field move must not disturb: reordering a struct may not add, drop, rename, or re-value a
/// single member.
#[test]
fn served_hook_body_carries_exactly_the_recorded_fields_and_values() {
    let served: serde_json::Value =
        serde_json::from_str(&wire_bytes(&headroom())).expect("served body is JSON");
    let recorded: serde_json::Value =
        serde_json::from_str(RECORDED_BODY).expect("recorded body is JSON");
    assert_eq!(
        served, recorded,
        "the served GET /hooks/{{name}} body drifted from the recorded 1.6.0 cell — the field \
         reorder was supposed to be value-preserving"
    );
}

/// THE PROPERTY THE REORDER BUYS. The served 1.6.0 body opens with the eleven 1.5.5 members, in
/// the 1.5.5 order, and the three 1.6.0 additions follow — so the byte range a 1.5.5 client's
/// expectations cover is a literal PREFIX of the 1.6.0 body. Before the move this failed:
/// `phase`/`fires_at` sat at indices 7-8, between `at` and `on_error`.
#[test]
fn the_1_5_5_members_are_a_prefix_of_the_served_1_6_0_body() {
    let served = wire_bytes(&headroom());
    // Member order as EMITTED, read off the wire string rather than off the struct, so the test
    // cannot pass by agreeing with the same declaration it is auditing.
    let emitted: Vec<&str> = member_order(&served);

    let expected: Vec<&str> = V155_REQUIRED
        .iter()
        .chain(V160_ADDED.iter())
        .copied()
        .collect();
    assert_eq!(
        emitted, expected,
        "served HookView member order must be the 1.5.5 list verbatim, then the 1.6.0 additions"
    );
    assert_eq!(
        &emitted[..V155_REQUIRED.len()],
        V155_REQUIRED,
        "the 1.5.5 member sequence is no longer a prefix of the 1.6.0 body"
    );
}

/// The OpenAPI half of the same invariant, asserted against the generated document rather than the
/// committed file, so it fails on the CODE change and not merely on a stale artefact.
#[cfg(feature = "openapi-schema")]
#[test]
fn hook_view_required_is_the_1_5_5_list_then_the_additions() {
    let doc = crate::admin::v1::json::openapi_doc();
    let required: Vec<String> = doc["components"]["schemas"]["HookView"]["required"]
        .as_array()
        .expect("HookView.required is an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("required entries are strings")
                .to_string()
        })
        .collect();
    let expected: Vec<String> = V155_REQUIRED
        .iter()
        .chain(V160_ADDED.iter())
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        required, expected,
        "HookView.required must keep 1.5.5's list as a strict PREFIX — a mid-list insert reads as \
         a reorder to the additive-superset check"
    );
}

/// Top-level member names of a JSON object, in emitted order. A hand-rolled scan rather than a
/// `serde_json` parse because `serde_json::Value`'s map is a `BTreeMap` and would sort away the
/// exact property under test.
fn member_order(s: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut str_start = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
                // A key at depth 1 is followed (immediately, `to_string` emits no spaces) by ':'.
                if depth == 1 && bytes.get(i + 1) == Some(&b':') {
                    names.push(&s[str_start..i]);
                }
            }
        } else {
            match c {
                b'"' => {
                    in_string = true;
                    str_start = i + 1;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    names
}
