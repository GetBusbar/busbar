// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{read, EXT_LISTENER_BINDINGS};

#[test]
fn selection_refuses_missing_and_ambiguous_suppliers_even_for_the_same_claim() {
    use super::{resolve, ListenerBinding};
    let binding = ListenerBinding {
        slot: "listen".into(),
        claim: "foreign-wire".into(),
    };
    assert_eq!(resolve("listen", [&binding]).unwrap(), "foreign-wire");
    assert!(resolve("other-slot", [&binding]).is_err());
    assert!(resolve("listen", [&binding, &binding]).is_err());
    assert!(resolve("listen", std::iter::empty()).is_err());
}

fn extension(bytes: &[u8]) -> Vec<u8> {
    crate::abi::mechanism::extensions::encode(&[(EXT_LISTENER_BINDINGS, bytes)])
}

#[test]
fn a_foreign_protocol_claim_can_serve_a_configuration_slot() {
    let bytes = extension(br#"[{"slot":"listen","claim":"fixture-wire"}]"#);
    let bindings = read(&bytes, &["fixture-wire"]).unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].claim, "fixture-wire");
    assert!(read(&bytes, &["other-wire"]).is_err());
}

#[test]
fn duplicate_and_malformed_bindings_are_refused() {
    for bytes in [
        br#"[{"slot":"listen","claim":"fixture-wire"},{"slot":"listen","claim":"fixture-wire"}]"#
            .as_slice(),
        br#"[{"slot":"","claim":"fixture-wire"}]"#.as_slice(),
        br#"[{"slot":"listen.path","claim":"fixture-wire"}]"#.as_slice(),
        br#"[{"slot":"listen","claim":"fixture-wire","priority":1}]"#.as_slice(),
        br#"{}"#.as_slice(),
    ] {
        assert!(read(&extension(bytes), &["fixture-wire"]).is_err());
    }
    assert!(read(&extension(&vec![b' '; 65537]), &["fixture-wire"]).is_err());
    assert!(read(&[], &[]).unwrap().is_empty());
}

fn rows(slots: impl Iterator<Item = String>) -> Vec<u8> {
    let rows: Vec<String> = slots
        .map(|slot| format!(r#"{{"slot":"{slot}","claim":"fixture-wire"}}"#))
        .collect();
    extension(format!("[{}]", rows.join(",")).as_bytes())
}

#[test]
fn the_size_row_count_and_slot_length_bounds_are_each_enforced() {
    let mut padded = br#"[{"slot":"listen","claim":"fixture-wire"}]"#.to_vec();
    assert!(read(&extension(&padded), &["fixture-wire"]).is_ok());
    padded.resize(64 * 1024, b' ');
    assert!(read(&extension(&padded), &["fixture-wire"]).is_ok());
    padded.push(b' ');
    assert_eq!(
        read(&extension(&padded), &["fixture-wire"]).unwrap_err(),
        "listener-bindings exceeds its declaration bound"
    );
    assert_eq!(
        read(&rows((0..64).map(|i| format!("s{i}"))), &["fixture-wire"])
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        read(&rows((0..65).map(|i| format!("s{i}"))), &["fixture-wire"]).unwrap_err(),
        "listener-bindings contains too many records"
    );
    assert!(read(&rows(["a".repeat(128)].into_iter()), &["fixture-wire"]).is_ok());
    assert_eq!(
        read(&rows(["a".repeat(129)].into_iter()), &["fixture-wire"]).unwrap_err(),
        "listener-bindings contains an invalid configuration slot"
    );
}
