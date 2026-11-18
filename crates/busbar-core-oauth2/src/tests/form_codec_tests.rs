// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DEPENDENCY-LADDER C6 (percent-encoding / form_urlencoded) pins the OAuth form codecs before the
//! hand loops go.

use super::form_urlencoded_pairs;

#[test]
fn form_pairs_decode_plus_escapes_and_drop_pairs_without_an_equals() {
    let pairs: Vec<(String, String)> =
        form_urlencoded_pairs("a=1&b=x+y&c=%2B&d&e=%zz&f=%C3%A9&g=%FF&=v&k=a=b&&h=%4")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let expected: Vec<(String, String)> = [
        ("a", "1"),
        ("b", "x y"),
        ("c", "+"),
        ("e", "%zz"),
        ("f", "\u{e9}"),
        ("g", "\u{fffd}"),
        ("", "v"),
        ("k", "a=b"),
        ("h", "%4"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    assert_eq!(pairs, expected);
    assert_eq!(
        form_urlencoded_pairs("x=%+41&y=%2+")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>(),
        vec![
            ("x".to_owned(), "% 41".to_owned()),
            ("y".to_owned(), "%2 ".to_owned())
        ]
    );
}
