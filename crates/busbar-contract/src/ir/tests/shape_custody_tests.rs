// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{ContentItem, Shape, Slot};
use serde_json::json;
use std::borrow::Cow;
use std::cell::Cell;

thread_local! {
    static WATCH: Cell<bool> = const { Cell::new(false) };
    static EXPOSED: Cell<bool> = const { Cell::new(false) };
}

#[allow(clippy::ptr_arg)]
pub(super) fn retiring_count_text(text: &Cow<'_, str>) {
    if WATCH.with(Cell::get) {
        if let Cow::Owned(owned) = text {
            if owned.as_bytes().iter().any(|byte| *byte != 0) {
                EXPOSED.with(|exposed| exposed.set(true));
            }
        }
    }
}

struct Watch;
impl Drop for Watch {
    fn drop(&mut self) {
        WATCH.with(|watch| watch.set(false));
    }
}

#[test]
fn shape_counting_does_not_retire_cleartext_argument_copies() {
    let secret = json!({"credential": "shape-private-credential", "nested": ["私密🔑", "\n\""]});
    let data = ContentItem::Data {
        author: "caller",
        slot: Slot::ToolArgs(0),
        label: "arguments",
        value: &secret,
    };
    let expected = secret.to_string().chars().count();
    EXPOSED.with(|exposed| exposed.set(false));
    WATCH.with(|watch| watch.set(true));
    let watch = Watch;
    assert_eq!(Shape::counts_over(&[data]), (expected, 0));
    drop(watch);
    assert!(
        !EXPOSED.with(Cell::get),
        "counting retired an unwiped argument copy"
    );
    assert_eq!(secret["credential"], "shape-private-credential");
}

#[test]
fn shape_counts_keep_compact_json_unicode_and_system_semantics() {
    for value in [
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(-11),
        json!(1.25),
        json!("a\n\r\t\"\\\u{0000}私🔑"),
        json!({"nested": [1, null, {"é": "🔐"}], "a": true}),
        json!([]),
        json!({}),
    ] {
        let expected = value.to_string().chars().count();
        let items = [
            ContentItem::Data {
                author: "caller",
                slot: Slot::System,
                label: "",
                value: &value,
            },
            ContentItem::Text {
                author: "caller",
                slot: Slot::Turn(0),
                text: Cow::Borrowed("é🔑"),
            },
            ContentItem::Opaque {
                author: "caller",
                slot: Slot::Turn(0),
                label: "opaque",
                marker: "opaque",
            },
        ];
        assert_eq!(Shape::counts_over(&items), (expected + 2 + 6, expected));
        assert_eq!(value.to_string().chars().count(), expected);
    }
}
