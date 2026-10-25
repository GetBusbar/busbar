// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE READER OF A DECLARES DOCUMENT ([`Declares::from_declares_json`], ARCHITECT ruling (b),
//! 2026-10-07): what it reads and refuses, and a scan of the tree that refuses any other site
//! deserializing declares bytes straight into [`Declares`] with `serde_json`.

use super::Declares;

/// A declares document's `needs` is checked and left out of the section: the needs belong to the
/// Statement. The reader names no scheme (core names no transport, Law 1): any non-empty name
/// reads, and which ones a plugin may state is the conformance suite's check against its
/// Statement. RED ARMS: a malformed `needs` (not a list, a non-string, an empty name) is refused,
/// and any other unknown key beside a well-formed `needs` is still refused.
#[test]
fn the_reader_checks_and_drops_needs_and_refuses_every_other_unknown_key() {
    let with = Declares::from_declares_json(
        br#"{"destinations": ["url"], "needs": ["scheme-a", "scheme-b"]}"#,
    )
    .expect("a well-formed `needs` reads");
    let without =
        Declares::from_declares_json(br#"{"destinations": ["url"]}"#).expect("the same, without");
    assert_eq!(with, without, "the section carries no needs");
    assert_eq!(
        serde_json::to_value(&with).unwrap(),
        serde_json::json!({"destinations": ["url"]})
    );
    assert!(Declares::from_declares_json(br#"{"needs": []}"#).is_ok());
    for bad in [
        r#"{"needs": "scheme-a"}"#,
        r#"{"needs": [7]}"#,
        r#"{"needs": [""]}"#,
        r#"{"needs": ["scheme-a"], "series": []}"#,
        r#"{"series": []}"#,
        "not json",
    ] {
        assert!(
            Declares::from_declares_json(bad.as_bytes()).is_err(),
            "{bad} must be refused"
        );
    }
}

/// A destination's retention (`keep`, THE DESIGN: `disk.append` rotation declared per
/// destination) reads for a declared destination and rides the section; unstated, the section
/// carries none (the manifest's canonical bytes are unchanged). RED ARM: a `keep` naming a key that
/// is not a declared destination is refused.
#[test]
fn a_declared_keep_reads_for_a_declared_destination_only() {
    let read = Declares::from_declares_json(br#"{"destinations": ["path"], "keep": {"path": 0}}"#)
        .expect("a keep for a declared destination reads");
    assert_eq!(read.keep.get("path"), Some(&0));
    assert_eq!(
        serde_json::to_value(&read).unwrap(),
        serde_json::json!({"destinations": ["path"], "keep": {"path": 0}})
    );
    assert!(!Declares {
        keep: read.keep.clone(),
        ..Declares::default()
    }
    .is_empty());
    let none = Declares::from_declares_json(br#"{"destinations": ["path"]}"#).expect("reads");
    assert!(none.keep.is_empty());
    assert_eq!(
        serde_json::to_value(&none).unwrap(),
        serde_json::json!({"destinations": ["path"]})
    );
    assert!(
        Declares::from_declares_json(br#"{"destinations": ["path"], "keep": {"other": 0}}"#)
            .is_err()
    );
}

/// A hook's `hook.orders` (ARCHITECT ruling, status row 194) reads as stated; unstated, the hook
/// may order and the section carries nothing, so every manifest packed before the field existed
/// keeps its canonical bytes. RED ARMS: a non-bool `orders` and an unknown key under `hook` are
/// refused.
#[test]
fn a_declared_hook_orders_reads_and_unstated_leaves_the_bytes_unchanged() {
    let off = Declares::from_declares_json(br#"{"hook": {"orders": false}}"#).expect("reads");
    assert!(!off.hook_orders());
    assert!(!off.is_empty());
    assert_eq!(
        serde_json::to_value(&off).unwrap(),
        serde_json::json!({"hook": {"orders": false}})
    );
    let on = Declares::from_declares_json(br#"{"hook": {}}"#).expect("an empty hook reads");
    assert!(on.hook_orders(), "an unstated `orders` is true");
    let none = Declares::from_declares_json(br#"{"destinations": ["url"]}"#).expect("reads");
    assert!(none.hook.is_none() && none.hook_orders());
    assert_eq!(
        serde_json::to_value(&none).unwrap(),
        serde_json::json!({"destinations": ["url"]}),
        "no `hook` key rides a manifest that states none"
    );
    assert!(Declares::default().is_empty());
    for bad in [
        r#"{"hook": {"orders": "no"}}"#,
        r#"{"hook": {"orders": false, "x": 1}}"#,
        r#"{"hook": false}"#,
    ] {
        assert!(
            Declares::from_declares_json(bad.as_bytes()).is_err(),
            "{bad} must be refused"
        );
    }
}

/// A SIGNED manifest's `declares` is not a declares document: the manifest never carries `needs`,
/// so one that states it is refused like any other unknown key.
#[test]
fn a_signed_manifest_section_stating_needs_is_refused() {
    assert!(
        serde_json::from_value::<super::Manifest>(serde_json::json!({
            "name": "n", "alias": "n", "kind": "export", "version": "1.0.0", "publisher": "p",
            "abi_version": 1, "sha256": "", "signature": "",
            "declares": {"needs": ["scheme-a"]}
        }))
        .is_err()
    );
}
