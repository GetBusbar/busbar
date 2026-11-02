// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::Declares;

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
