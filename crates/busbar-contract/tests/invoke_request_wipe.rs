// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned invoke-request strings, JSON member names and extras included, are wiped on every exit
//! (Q24, UNSAFE-MIN §4.4). Each string in turn carries a fresh canary; the request leaves by return,
//! failure, cancellation, a clone's drop, its last shared owner or a transfer to a final owner; then
//! a scan of this process's memory must not find the canary. Wherever an owner is still alive
//! part-way, the canary must still be found. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::ir::invoke::InvokeReq;
use busbar_contract::ir::SourceScopedExtra;
use busbar_contract::secure::SecureString;
use serde_json::{Map, Value};

#[allow(dead_code)]
#[path = "../../busbar-plugin-test/src/canary_scan.rs"]
mod canary_scan;

use canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A request whose string `field` holds `secret` (its only copy); every other string is plain.
fn request(field: &str, secret: &str) -> InvokeReq {
    let pick = |name: &str, plain: &str| {
        if field == name {
            secret.to_owned()
        } else {
            plain.to_owned()
        }
    };
    let mut nested = Map::new();
    nested.insert(
        pick("nested-name", "private-nested-name"),
        Value::String(pick("nested-value", "private-nested-value")),
    );
    let mut arguments = Map::new();
    arguments.insert(
        pick("argument-name", "private-argument-name"),
        Value::Array(vec![
            Value::String(pick("argument-value", "private-argument-value")),
            Value::Object(nested),
        ]),
    );
    InvokeReq {
        tool: pick("tool", "private-tool"),
        arguments: Value::Object(arguments),
        extra: [(
            pick("extra-source", "private-source"),
            [(
                pick("extra-name", "private-extra-name"),
                Value::String(pick("extra-value", "private-extra-value")),
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect(),
    }
}

fn returned(_request: InvokeReq, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_scan_distinguishes_plain_and_wiped_strings() {
    let proof = WipeProof::text();
    let plain = proof.text_payload().as_str().to_owned();
    drop(plain);
    assert!(
        proof.canary_copies("a plain string") >= 1,
        "a plain string's freed bytes must be found"
    );

    let proof = WipeProof::text();
    let wiped =
        busbar_contract::secure::SecureString::from(proof.text_payload().as_str().to_owned());
    drop(wiped);
    proof.assert_absent("a SecureString");
}

#[test]
fn invoke_request_strings_are_wiped_on_return_failure_cancel_and_last_owner_drop() {
    for name in [
        "tool",
        "argument-name",
        "argument-value",
        "nested-name",
        "nested-value",
        "extra-source",
        "extra-name",
        "extra-value",
    ] {
        for exit in ["return", "failure", "cancel", "clone", "shared", "transfer"] {
            let what = format!("{name} on {exit}");
            let mut proof = WipeProof::text();
            let staging = proof.text_payload();
            let mut request = request(name, &staging);
            drop(staging);
            if exit == "clone" {
                let clone = request.clone();
                drop(request);
                request = clone;
            }
            match exit {
                "cancel" => {
                    let mut pending = Box::pin(async move {
                        let request = request;
                        std::future::pending::<()>().await;
                        drop(request);
                    });
                    assert_eq!(
                        pending
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Pending
                    );
                    proof.assert_held("the pending future still owns the request");
                    drop(pending);
                }
                "shared" => {
                    let shared = Arc::new(request);
                    let last = Arc::clone(&shared);
                    drop(shared);
                    proof.assert_held("the last shared owner still holds the request");
                    drop(last);
                }
                "transfer" => {
                    let final_owner = InvokeReq {
                        tool: std::mem::take(&mut request.tool),
                        arguments: std::mem::take(&mut request.arguments),
                        extra: std::mem::take(&mut request.extra),
                    };
                    drop(request);
                    proof.assert_held("the final owner still holds the request");
                    drop(final_owner);
                }
                _ => {
                    assert_eq!(
                        returned(request, exit == "failure").is_err(),
                        exit == "failure"
                    );
                }
            }
            proof.assert_absent(&what);
        }
    }
}

// ---- DES-SONIC-WIPE r3 §7.2: short canaries, wide objects, escapes, duplicates, screening ----

/// The eight request strings a canary is planted in, in turn.
const FIELDS: [&str; 8] = [
    "tool",
    "argument-name",
    "argument-value",
    "nested-name",
    "nested-value",
    "extra-source",
    "extra-name",
    "extra-value",
];

/// The six ways a request leaves.
const EXITS: [&str; 6] = ["return", "failure", "cancel", "clone", "shared", "transfer"];

/// The arguments (or an extra value) a JSON text in custody reads as. The text is the only place
/// the caller put the secret; it is wiped when dropped here.
fn secret_json(text: SecureString) -> Value {
    serde_json::from_slice(text.as_bytes()).expect("a valid fixture document")
}

/// Extras built one `(source, name, value)` at a time, as a reader adds them.
fn extra_inserted(entries: Vec<(String, String, Value)>) -> SourceScopedExtra {
    let mut extra = SourceScopedExtra::new();
    for (source, name, value) in entries {
        extra.entry(source).or_default().insert(name, value);
    }
    extra
}

/// Extras collected from `(source, name, value)` entries.
fn extra_collected(entries: Vec<(String, String, Value)>) -> SourceScopedExtra {
    entries
        .into_iter()
        .map(|(source, name, value)| (source, [(name, value)].into_iter().collect()))
        .collect()
}

/// A request with these arguments and extras; its tool name is plain.
fn request_of(arguments: Value, extra: SourceScopedExtra) -> InvokeReq {
    InvokeReq {
        tool: "private-tool".to_owned(),
        arguments,
        extra,
    }
}

/// `request` leaves by `exit` (7.1's exits); where an owner still holds it part-way, the canary
/// must still be found.
fn leave(exit: &str, mut request: InvokeReq, proof: &mut WipeProof) {
    if exit == "clone" {
        let clone = request.clone();
        drop(request);
        request = clone;
    }
    match exit {
        "cancel" => {
            let mut pending = Box::pin(async move {
                let request = request;
                std::future::pending::<()>().await;
                drop(request);
            });
            assert_eq!(
                pending
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            );
            proof.assert_held("the pending future still owns the request");
            drop(pending);
        }
        "shared" => {
            let shared = Arc::new(request);
            let last = Arc::clone(&shared);
            drop(shared);
            proof.assert_held("the last shared owner still holds the request");
            drop(last);
        }
        "transfer" => {
            let final_owner = InvokeReq {
                tool: std::mem::take(&mut request.tool),
                arguments: std::mem::take(&mut request.arguments),
                extra: std::mem::take(&mut request.extra),
            };
            drop(request);
            proof.assert_held("the final owner still holds the request");
            drop(final_owner);
        }
        _ => {
            assert_eq!(
                returned(request, exit == "failure").is_err(),
                exit == "failure"
            );
        }
    }
}

/// `text` with every character spelled as a `\u00XX` escape.
fn escaped(text: &str) -> SecureString {
    let mut out = SecureString::with_capacity(text.len() * 6);
    for byte in text.bytes() {
        std::fmt::Write::write_fmt(&mut out, format_args!("\\u{byte:04X}"))
            .expect("formatting into custody cannot fail");
    }
    out
}

/// The short positive control: a dropped, unwiped short string is found.
#[test]
fn the_short_scan_distinguishes_plain_and_wiped_strings() {
    let proof = WipeProof::short_text();
    let plain = proof.text_payload().as_str().to_owned();
    drop(plain);
    assert!(
        proof.canary_copies("a plain short string") >= 1,
        "a plain short string's freed bytes must be found"
    );

    let proof = WipeProof::short_text();
    let wiped = SecureString::from(proof.text_payload().as_str().to_owned());
    drop(wiped);
    proof.assert_absent("a short SecureString");
}

/// S-1..S-48: a short canary (inline-sized) in each field, on each exit.
#[test]
fn short_invoke_request_strings_are_wiped_on_every_exit() {
    for name in FIELDS {
        for exit in EXITS {
            let what = format!("short {name} on {exit}");
            let mut proof = WipeProof::short_text();
            let staging = proof.text_payload();
            let request = request(name, &staging);
            drop(staging);
            leave(exit, request, &mut proof);
            proof.assert_absent(&what);
        }
    }
}

/// An object of 200 short keys `k000`..`k199`; at `k137` the short canary is the key itself
/// (`in_key`) or that member's value.
fn wide_arguments(secret: &str, in_key: bool) -> SecureString {
    use std::fmt::Write as _;
    let mut text = SecureString::new();
    text.push('{');
    for at in 0..200 {
        if at > 0 {
            text.push(',');
        }
        let written = match (at == 137, in_key) {
            (true, true) => write!(text, r#""{secret}":"v{at:03}""#),
            (true, false) => write!(text, r#""k{at:03}":"{secret}""#),
            (false, _) => write!(text, r#""k{at:03}":"v{at:03}""#),
        };
        written.expect("formatting into custody cannot fail");
    }
    text.push('}');
    text
}

/// K-200: a 200-member object of short keys, the short canary one key or one value, on each exit.
#[test]
fn a_wide_object_of_short_keys_is_wiped_on_every_exit() {
    for in_key in [true, false] {
        for exit in EXITS {
            let what = format!("200 short keys (canary in a key: {in_key}) on {exit}");
            let mut proof = WipeProof::short_text();
            let staging = proof.text_payload();
            let request = request_of(
                secret_json(wide_arguments(&staging, in_key)),
                SourceScopedExtra::default(),
            );
            drop(staging);
            leave(exit, request, &mut proof);
            proof.assert_absent(&what);
        }
    }
}

/// E-1: arguments whose key or value spells the canary in `\u00XX` escapes, read from custody.
#[test]
fn escaped_argument_strings_are_wiped() {
    for short in [false, true] {
        for in_key in [true, false] {
            let what = format!("an escaped argument (short: {short}, key: {in_key})");
            let mut proof = if short {
                WipeProof::short_text()
            } else {
                WipeProof::text()
            };
            let staging = proof.text_payload();
            let canary = escaped(&staging);
            drop(staging);
            let text = if in_key {
                SecureString::from_args(format_args!(r#"{{"{}":"plain-value"}}"#, canary.as_str()))
            } else {
                SecureString::from_args(format_args!(r#"{{"plain-name":"{}"}}"#, canary.as_str()))
            };
            drop(canary);
            let request = request_of(secret_json(text), SourceScopedExtra::default());
            proof.assert_held(&format!("{what}: the request holds it"));
            drop(request);
            proof.assert_absent(&what);
        }
    }
}

/// E-2: an escaped canary in an extra value, and in the overridden first value of a duplicate key.
#[test]
fn escaped_extra_values_and_overridden_duplicates_are_wiped() {
    for short in [false, true] {
        let new_proof = || {
            if short {
                WipeProof::short_text()
            } else {
                WipeProof::text()
            }
        };

        let what = format!("an escaped extra value (short: {short})");
        let mut proof = new_proof();
        let staging = proof.text_payload();
        let canary = escaped(&staging);
        drop(staging);
        let value = secret_json(SecureString::from_args(format_args!(
            r#""{}""#,
            canary.as_str()
        )));
        drop(canary);
        let request = request_of(
            secret_json(SecureString::from("{}")),
            extra_collected(vec![(
                "private-source".to_owned(),
                "private-extra-name".to_owned(),
                value,
            )]),
        );
        proof.assert_held(&format!("{what}: the request holds it"));
        drop(request);
        proof.assert_absent(&what);

        let what = format!("an overridden duplicate member (short: {short})");
        let proof = new_proof();
        let staging = proof.text_payload();
        let canary = escaped(&staging);
        drop(staging);
        let text = SecureString::from_args(format_args!(
            r#"{{"duplicate":"{}","duplicate":"plain-value"}}"#,
            canary.as_str()
        ));
        drop(canary);
        let request = request_of(secret_json(text), SourceScopedExtra::default());
        drop(request);
        proof.assert_absent(&what);
    }
}

/// E-3: duplicate extra keys, added one at a time and collected. The key a duplicate brings in
/// is not kept; it must be wiped too.
#[test]
fn duplicate_extra_keys_are_wiped_at_both_levels() {
    type Build = fn(Vec<(String, String, Value)>) -> SourceScopedExtra;
    let builds: [(&str, Build); 2] = [("insert", extra_inserted), ("collect", extra_collected)];
    for (how, build) in builds {
        for short in [false, true] {
            for case in ["source", "name", "both"] {
                let what = format!("a duplicate {case} key ({how}, short: {short})");
                let mut proof = if short {
                    WipeProof::short_text()
                } else {
                    WipeProof::text()
                };
                let staging = proof.text_payload();
                let plain =
                    |text: &str| secret_json(SecureString::from_args(format_args!(r#""{text}""#)));
                let entries = match case {
                    "source" => vec![
                        (
                            staging.as_str().to_owned(),
                            "first-name".to_owned(),
                            plain("one"),
                        ),
                        (
                            staging.as_str().to_owned(),
                            "second-name".to_owned(),
                            plain("two"),
                        ),
                    ],
                    "name" => vec![
                        (
                            "private-source".to_owned(),
                            staging.as_str().to_owned(),
                            plain("one"),
                        ),
                        (
                            "private-source".to_owned(),
                            staging.as_str().to_owned(),
                            plain("two"),
                        ),
                    ],
                    _ => vec![
                        (
                            staging.as_str().to_owned(),
                            staging.as_str().to_owned(),
                            plain("one"),
                        ),
                        (
                            staging.as_str().to_owned(),
                            staging.as_str().to_owned(),
                            plain("two"),
                        ),
                    ],
                };
                drop(staging);
                let request = request_of(secret_json(SecureString::from("{}")), build(entries));
                proof.assert_held(&format!("{what}: the request holds the kept key"));
                drop(request);
                proof.assert_absent(&what);
            }
        }
    }
}

/// P-1: screening an invocation (its content's text, its shape, a screened projection) leaves
/// no copy of the arguments behind. The digest is pinned separately (P-2, with the hash).
#[test]
fn screening_an_invocation_leaves_no_argument_copy() {
    use busbar_contract::ir::facts::{IrFacts as _, ScreenedContent};
    for short in [false, true] {
        let what = format!("screened arguments (short: {short})");
        let proof = if short {
            WipeProof::short_text()
        } else {
            WipeProof::text()
        };
        let staging = proof.text_payload();
        let text = SecureString::from_args(format_args!(r#"{{"credential":"{}"}}"#, &*staging));
        drop(staging);
        let request = request_of(secret_json(text), SourceScopedExtra::default());
        let items = request.content();
        let shown = items[0].screenable_text().chars().count();
        let shape = request.shape();
        assert_eq!(shape.text_chars, shown);
        let screened = ScreenedContent::over(&items);
        let total: usize = screened.iter().map(|(_, text)| text.len()).sum();
        assert!(total > 0);
        drop(screened);
        drop(items);
        drop(request);
        proof.assert_absent(&what);
    }
}

/// C-1, the control that records why secret JSON is never a sonic `Value`: a map of 200 short
/// keys built from constructors (no parse, so no document arena), one key the short canary
/// staged in custody and wiped. Dropping the map leaves a copy: short strings are stored inline,
/// where no wipe reaches. If this stops finding one, revisit DES-SONIC-WIPE §2.
#[test]
fn a_sonic_map_of_short_keys_keeps_inline_copies_after_drop() {
    use busbar_contract::json;
    let proof = WipeProof::short_text();
    let staging = proof.text_payload();
    let mut map = json::Map::new();
    for at in 0..200 {
        let key = SecureString::from_args(format_args!("k{at:03}"));
        let value = SecureString::from_args(format_args!("v{at:03}"));
        if at == 137 {
            map.insert(staging.as_str(), json::Value::from(value.as_str()));
        } else {
            map.insert(key.as_str(), json::Value::from(value.as_str()));
        }
    }
    drop(staging);
    drop(map);
    assert!(
        proof.canary_copies("a dropped sonic map of short keys") >= 1,
        "sonic kept no inline copy of a short key: DES-SONIC-WIPE §2's premise changed"
    );
}
