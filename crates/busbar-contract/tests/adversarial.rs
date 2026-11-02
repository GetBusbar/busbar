// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The scanner against bytes that were written to break it.

use busbar_contract::spans::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

/// Every pointer worth pointing at a hostile body, run against one input.
const POINTERS: &[&str] = &[
    "",
    "/",
    "/a",
    "/a/b",
    "/a/0",
    "/0",
    "/0/0",
    "/items/0",
    "/items/1",
    "/items/-",
    "/items/01",
    "/items/+1",
    "/items/00",
    "/items/18446744073709551616",
    "/a~1b",
    "/a~0b",
    "/a~",
    "/a~2",
    "~",
    "a",
    "/\u{1F600}",
    "/model",
    "/usage/total_tokens",
];

/// The two invariants, for one input and one pointer.
fn probe(input: &[u8], pointer: &str) -> Resolved {
    let answer = resolve_pointer(input, pointer);
    if let Resolved::Found(span) = answer {
        assert!(
            span.start <= span.end && span.end <= input.len(),
            "span {span:?} outside {} bytes for pointer {pointer:?}",
            input.len()
        );

        assert_eq!(span.of(input), &input[span.start..span.end]);
    }
    answer
}

/// The corpus: bodies written to break the scan, each with a note on what it aims at.
fn corpus() -> Vec<Vec<u8>> {
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let literals: &[&[u8]] = &[
        b"",
        b" ",
        b" \t\r\n ",
        b"\0",
        b"1",
        b"-0",
        b"-",
        b"0123",
        b"1e",
        b"1e+",
        b"1e999999999999999999999",
        b"1.2.3e",
        b"true",
        b"tru",
        b"truex",
        b"nul",
        b"null",
        b"falsey",
        br#""a""#,
        br#""a"#,
        br#"""#,
        b"\"a\\",
        b"\"\\",
        b"\"\\u\"",
        b"\"\\u00\"",
        b"\"\\ud800\"",
        b"\"\\udc00\"",
        b"\"a\0b\"",
        b"{}",
        b"[]",
        b"{",
        b"[",
        b"}",
        b"]",
        b"{,}",
        b"[,]",
        br#"{"a":1,}"#,
        br#"[1,]"#,
        br#"{"a"}"#,
        br#"{"a":}"#,
        br#"{:1}"#,
        br#"{"a":1"#,
        br#"{"a":1,"#,
        br#"{"a":1,"b"#,
        br#"["a""#,
        br#"[1,2"#,
        br#"[1,2,"#,
        br#"{"a":[1,2}}"#,
        br#"{"a":1]"#,
        br#"[{]"#,
        br#"{]"#,
        b"[}",
        br#"{"a":1} trailing garbage"#,
        br#"{"a":1}{"a":2}"#,
        br#"garbage {"a":1}"#,
        br#"{"a":1}]"#,
        br#"{"model":"cheap","model":"dear"}"#,
        br#"{"a":1,"a":2,"a":3}"#,
        br#"{"usage":{"total_tokens":1,"total_tokens":999}}"#,
        br#"{"a/b":1,"a~b":2,"a":3}"#,
        br#"{"":1}"#,
        br#"{"~":1,"~0":2,"/":3}"#,
        b"{\"a\xff\":1,\"a\":2}",
        b"{\"a\\q\":1,\"a\":2}",
        b"{\"a\\ud800\":1,\"a\":2}",
        b"{\"a\\ud800\\ud800\":1,\"a\":2}",
        b"{\"\xc0\xaf\":1}",
        b"{\"\xe2\x82\":1}",
        br#"{"decoy":"}{[]\"","a":1}"#,
        br#"{"decoy":"\\","a":1}"#,
        br#"{"items":[10,20,30]}"#,
        br#"{"items":[]}"#,
        br#"{"items":[[1]]}"#,
        br#"{"a":1-2,"b":3}"#,
        br#"{"a":1e,"b":3}"#,
    ];
    bodies.extend(literals.iter().map(|b| b.to_vec()));

    for depth in [
        1,
        2,
        MAX_JSON_DEPTH - 2,
        MAX_JSON_DEPTH - 1,
        MAX_JSON_DEPTH,
        MAX_JSON_DEPTH + 1,
        512,
    ] {
        let mut arrays = vec![b'['; depth];
        arrays.push(b'1');
        arrays.extend(std::iter::repeat_n(b']', depth));
        bodies.push(arrays);

        bodies.push(vec![b'['; depth]);
        bodies.push(vec![b'{'; depth]);
        let mut objects = Vec::new();
        for _ in 0..depth {
            objects.extend_from_slice(br#"{"a":"#);
        }
        objects.push(b'1');
        objects.extend(std::iter::repeat_n(b'}', depth));
        bodies.push(objects);
    }

    bodies.push(vec![b'['; 10_000]);
    bodies.push(vec![b'{'; 10_000]);

    let whole = br#"{"a":{"b":[1,2,{"c":"x"}]},"items":[10,20],"model":"m\u00e9"}"#;
    for cut in 0..whole.len() {
        bodies.push(whole[..cut].to_vec());
    }
    bodies
}

#[test]
fn no_hostile_body_and_no_pointer_panics_or_names_bytes_outside_the_input() {
    for body in corpus() {
        for pointer in POINTERS {
            let _ = probe(&body, pointer);
        }

        assert!(
            scan_frontier(&body) <= body.len(),
            "frontier past the end of {} bytes",
            body.len()
        );
    }
}

#[test]
fn the_answers_the_hostile_cases_are_pinned_to() {
    let rows: &[(&[u8], &str, Resolved)] = &[
        (b"{\"a\":\"x\\", "/a", Resolved::NeedMore),
        (b"\"\\", "", Resolved::NeedMore),
        (
            b"{\"a\\u00\":1,\"a\":2}",
            "/a",
            Resolved::Found(Span::new(15, 16)),
        ),
        (b"{\"\\ud800\":1}", "/x", Resolved::Missing),
        (b"{\"\\ud800\\u0041\":1}", "/x", Resolved::Missing),
        (b"{\"\\udc00\":1}", "/x", Resolved::Missing),
        (
            br#"{"model":"cheap","model":"dear"}"#,
            "/model",
            Resolved::Found(Span::new(25, 31)),
        ),
        (
            br#"{"a/b":1,"a~b":2}"#,
            "/a~1b",
            Resolved::Found(Span::new(7, 8)),
        ),
        (
            br#"{"a/b":1,"a~b":2}"#,
            "/a~0b",
            Resolved::Found(Span::new(15, 16)),
        ),
        (br#"{"a/b":1,"a~b":2}"#, "/a~2b", Resolved::Missing),
        (br#"{"a/b":1,"a~b":2}"#, "/a~", Resolved::Missing),
        (
            br#"{"items":[10,20]}"#,
            "/items/0",
            Resolved::Found(Span::new(10, 12)),
        ),
        (br#"{"items":[10,20]}"#, "/items/01", Resolved::Missing),
        (br#"{"items":[10,20]}"#, "/items/-", Resolved::Missing),
        (br#"{"items":[10,20]}"#, "/items/+1", Resolved::Missing),
        (
            br#"{"items":[10,20]}"#,
            "/items/99999999999999999999999999",
            Resolved::Missing,
        ),
        (br#"{"a":-0}"#, "/a", Resolved::Found(Span::new(5, 7))),
        (br#"{"a":0123}"#, "/a", Resolved::Found(Span::new(5, 9))),
        (
            br#"{"a":1.2.3e,"b":1}"#,
            "/a",
            Resolved::Found(Span::new(5, 11)),
        ),
        (
            b" \t\r\n{\r\n \"a\" \t: \n 1 \r}",
            "/a",
            Resolved::Found(Span::new(17, 18)),
        ),
        (b"{\"a\":\0}", "/a", Resolved::Malformed),
        (b"{\"a\":\"\0\"}", "/a", Resolved::Found(Span::new(5, 8))),
        (
            br#"{"a":1} garbage"#,
            "/a",
            Resolved::Found(Span::new(5, 6)),
        ),
        (br#"{"a":1} garbage"#, "", Resolved::Found(Span::new(0, 7))),
        (br#"{"a":[1,2}}"#, "/a", Resolved::Malformed),
        (br#"{"a":1]"#, "/a", Resolved::Malformed),
        (br#"{"a":1}"#, "a", Resolved::Malformed),
        (br#"{"a":1}"#, "~", Resolved::Malformed),
        (br#"{"":1}"#, "/", Resolved::Found(Span::new(4, 5))),
        (br#"{"a":{"":1}}"#, "/a/", Resolved::Found(Span::new(9, 10))),
        (br#"{"a":1}"#, "/a/b", Resolved::Missing),
        (b"not json", "/a", Resolved::Missing),
    ];
    for (input, pointer, want) in rows {
        assert_eq!(
            probe(input, pointer),
            *want,
            "input {:?} pointer {pointer:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn an_array_cut_off_after_the_wanted_element_asks_for_more_as_an_object_does() {
    for (prefix, whole) in [
        (&b"[\"a\""[..], &b"[\"a\"}"[..]),
        (&b"[true"[..], &b"[truex]"[..]),
        (&b"[{}"[..], &b"[{}}"[..]),
        (&b"[[1]"[..], &b"[[1]}"[..]),
    ] {
        assert_eq!(
            resolve_pointer(prefix, "/0"),
            Resolved::NeedMore,
            "{:?} answered off a truncated array",
            String::from_utf8_lossy(prefix)
        );

        assert_eq!(
            resolve_pointer(whole, "/0"),
            Resolved::Malformed,
            "{:?}",
            String::from_utf8_lossy(whole)
        );
    }

    assert_eq!(probe(br#"[10,20]"#, "/1"), Resolved::Found(Span::new(4, 6)));
    assert_eq!(probe(br#"[10,20]"#, "/0"), Resolved::Found(Span::new(1, 3)));
}

#[test]
fn the_depth_ceiling_is_the_same_number_from_either_direction() {
    let nest = |depth: usize| {
        let mut body = vec![b'['; depth];
        body.push(b'1');
        body.extend(std::iter::repeat_n(b']', depth));
        body
    };
    for depth in 1..=MAX_JSON_DEPTH {
        let body = nest(depth);
        assert!(
            matches!(resolve_pointer(&body, ""), Resolved::Found(_)),
            "{depth} deep is inside the ceiling of {MAX_JSON_DEPTH} and did not resolve"
        );
    }
    for depth in [MAX_JSON_DEPTH + 1, MAX_JSON_DEPTH + 2, 4096] {
        let body = nest(depth);
        assert_eq!(
            resolve_pointer(&body, ""),
            Resolved::Malformed,
            "{depth} deep is past the ceiling of {MAX_JSON_DEPTH} and resolved anyway"
        );
    }
}

#[test]
fn a_hostile_unclosed_nest_is_refused() {
    for count in [10_000, 100_000] {
        let body = vec![b'['; count];
        assert_eq!(resolve_pointer(&body, "/0"), Resolved::Malformed);
    }
}

#[test]
fn a_span_never_slices_backwards_however_it_was_built() {
    let buf = b"0123456789";
    assert_eq!(Span::new(5, 2).of(buf), b"");
    assert_eq!(Span::new(20, 30).of(buf), b"");
    assert_eq!(Span::new(8, 4).of(buf), b"");
    assert_eq!(Span::new(2, 5).of(buf), b"234");
    assert_eq!(Span::new(0, 30).of(buf), buf);
}

#[test]
fn the_frontier_is_an_index_and_never_a_verdict() {
    assert_eq!(scan_frontier(br#"{"a":1}"#), 7);
    assert_eq!(scan_frontier(br#"  {"a":1}  "#), 9);
    assert_eq!(scan_frontier(br#"{"a":1} trailing"#), 7);

    assert_eq!(scan_frontier(br#"{"a":1"#), 6);
    assert_eq!(scan_frontier(br#"{"a":1]xxxx"#), 11);
    assert_eq!(scan_frontier(b""), 0);

    assert!(matches!(
        resolve_pointer(br#"{"a":1} trailing"#, ""),
        Resolved::Found(_)
    ));
    assert_eq!(resolve_pointer(br#"{"a":1"#, ""), Resolved::NeedMore);
    assert_eq!(resolve_pointer(br#"{"a":1]xxxx"#, ""), Resolved::Malformed);
}

#[test]
fn a_body_nested_to_the_v1_5_5_cap_resolves_a_top_level_pointer() {
    let mut body = br#"{"a":7,"b":"#.to_vec();
    body.extend(std::iter::repeat_n(b'[', 127));
    body.push(b'1');
    body.extend(std::iter::repeat_n(b']', 127));
    body.push(b'}');
    let found = resolve_pointer(&body, "/a");
    assert!(
        matches!(found, Resolved::Found(span) if span.of(&body) == b"7"),
        "a body 128 deep is the deepest v1.5.5 read, and /a did not resolve: {found:?}"
    );

    let mut bare = vec![b'['; 128];
    bare.push(b'1');
    bare.extend(std::iter::repeat_n(b']', 128));
    assert!(matches!(resolve_pointer(&bare, ""), Resolved::Found(_)));
}

#[test]
fn a_body_one_past_the_v1_5_5_cap_still_reports_unreadable() {
    let mut body = br#"{"a":7,"b":"#.to_vec();
    body.extend(std::iter::repeat_n(b'[', 128));
    body.push(b'1');
    body.extend(std::iter::repeat_n(b']', 128));
    body.push(b'}');
    assert_eq!(
        resolve_pointer(&body, "/a"),
        Resolved::Malformed,
        "a body 129 deep is past the v1.5.5 cap and must stay unreadable"
    );
}
