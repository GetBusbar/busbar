// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The envelope frame and the operator-rewrite seat: metadata edits, transform composition, and the
//! taps-observe-the-input rule.

use super::*;
use std::cell::RefCell;

/// `set` appends a new key and replaces an existing one in place; `get` reads the first; `remove`
/// redacts and reports whether it removed anything.
#[test]
fn metadata_set_get_remove() {
    let mut frame = Frame::new(Direction::Outbound, serde_json::json!({"m": 1}));
    frame.set("x-route", "a");
    frame.set("x-corr", "c1");
    assert_eq!(frame.get("x-route"), Some("a"));

    // Replacing is in place: the key keeps its position, so the envelope order is stable.
    frame.set("x-route", "b");
    assert_eq!(frame.get("x-route"), Some("b"));
    assert_eq!(
        frame.metadata,
        vec![
            ("x-route".to_string(), "b".to_string()),
            ("x-corr".to_string(), "c1".to_string()),
        ]
    );

    assert!(frame.remove("x-route"));
    assert_eq!(frame.get("x-route"), None);
    assert!(!frame.remove("x-route"), "a second remove finds nothing");
}

/// A transform rewrites the envelope; the body is carried through untouched.
struct StampCorrelation(&'static str);
impl Transform for StampCorrelation {
    fn transform(&self, mut frame: Frame) -> Frame {
        frame.set("x-corr", self.0);
        frame
    }
}

struct Redact(&'static str);
impl Transform for Redact {
    fn transform(&self, mut frame: Frame) -> Frame {
        frame.remove(self.0);
        frame
    }
}

/// Transforms compose left to right: each sees the previous one's output, and the last one's result
/// is what carries on. The body is unchanged.
#[test]
fn transforms_compose_in_order() {
    let mut frame = Frame::new(Direction::Outbound, serde_json::json!({"body": "kept"}));
    frame.set("authorization", "secret");

    let out = rewrite(
        frame,
        &[],
        &[
            &StampCorrelation("c-42") as &dyn Transform,
            &Redact("authorization"),
        ],
    );

    assert_eq!(out.get("x-corr"), Some("c-42"));
    assert_eq!(
        out.get("authorization"),
        None,
        "the redaction ran after the stamp"
    );
    assert_eq!(out.body, serde_json::json!({"body": "kept"}));
}

/// A tap observes the frame as it ARRIVED — before any transform rewrote it — and can change
/// nothing.
#[test]
fn taps_observe_the_input_before_transforms() {
    struct Recorder(RefCell<Vec<String>>);
    impl Tap for Recorder {
        fn tap(&self, frame: &Frame) {
            // What the tap sees is the pre-rewrite envelope: no `x-corr` yet.
            self.0
                .borrow_mut()
                .push(frame.get("x-corr").unwrap_or("<none>").to_string());
        }
    }

    let recorder = Recorder(RefCell::new(Vec::new()));
    let frame = Frame::new(Direction::Inbound, serde_json::json!(null));

    let out = rewrite(
        frame,
        &[&recorder as &dyn Tap],
        &[&StampCorrelation("c-1") as &dyn Transform],
    );

    assert_eq!(recorder.0.borrow().as_slice(), ["<none>".to_string()]);
    assert_eq!(out.get("x-corr"), Some("c-1"));
}

/// No seats at all is the identity: the frame crosses unchanged.
#[test]
fn no_seats_is_the_identity() {
    let frame = Frame::new(Direction::Inbound, serde_json::json!({"a": 1}));
    let out = rewrite(frame.clone(), &[], &[]);
    assert_eq!(out, frame);
}
