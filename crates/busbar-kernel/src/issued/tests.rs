// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn aws() -> IssuedShape {
    IssuedShape {
        id_prefix: "AKIA".into(),
        id_len: 20,
        id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into(),
        secret_len: 40,
        secret_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".into(),
    }
}

/// Guards the issuing lookup: the declared kind's shape is minted, an undeclared kind refuses with core text.
#[test]
fn a_declared_kind_answers_its_shape_and_an_undeclared_one_refuses_with_core_text() {
    let shapes = IssuedShapes::new(vec![("sigv4", aws())]);
    assert_eq!(shapes.get("sigv4"), Some(&aws()));
    assert_eq!(shapes.for_issuing("sigv4"), Ok(&aws()));
    assert_eq!(
        IssuedShapes::new(Vec::new()).for_issuing("sigv4"),
        Err("no admitted auth plugin uses issued credentials of kind `sigv4`".to_owned())
    );
}

/// Guards the carrier order and the bearer reading of `authorization` (C-KEY-CARRIERS' core arm).
#[test]
fn a_key_is_read_from_the_first_carrier_in_order() {
    let only =
        |name: &'static str, value: &'static str| move |h: &str| (h == name).then_some(value);
    assert_eq!(
        carried_key(only("authorization", "Bearer k")),
        Some((0, "k"))
    );
    assert_eq!(
        carried_key(only("authorization", "bearer  k ")),
        Some((0, "k"))
    );
    assert_eq!(carried_key(only("x-api-key", "k")), Some((1, "k")));
    assert_eq!(carried_key(only("x-goog-api-key", "k")), Some((2, "k")));
    assert_eq!(carried_key(only("authorization", "Basic k")), None);
    assert_eq!(carried_key(only("x-api-key", "")), None);
    assert_eq!(carried_key(only("x-other", "k")), None);
    let both = |h: &str| match h {
        "authorization" => Some("Basic zz"),
        "x-api-key" => Some("k"),
        _ => None,
    };
    assert_eq!(carried_key(both), Some((1, "k")));
}
