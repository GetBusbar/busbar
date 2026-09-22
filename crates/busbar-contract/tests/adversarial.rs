// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The scanner against bytes that were written to break it.
//!
//! Every case here is a body someone hostile could send: a bracket nest deeper than the stack, a
//! string that never closes, an escape cut off by the end of the buffer, a key spelled twice, a
//! pointer step that is not the index it looks like. The table is deterministic and needs no
//! external fuzzer — the point is that the answers are pinned, not that they are random.
//!
//! Two invariants hold for every row, whatever the answer is: the scan does not panic, and a
//! [`Resolved::Found`] never names bytes outside the input it was handed.

use busbar_grammar::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

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
        // And reading it back is a slice of the caller's own bytes, not a panic.
        assert_eq!(span.of(input), &input[span.start..span.end]);
    }
    answer
}

/// The corpus: bodies written to break the scan, each with a note on what it aims at.
fn corpus() -> Vec<Vec<u8>> {
    let mut bodies: Vec<Vec<u8>> = Vec::new();
    let literals: &[&[u8]] = &[
        // Nothing, and nothing but whitespace.
        b"",
        b" ",
        b" \t\r\n ",
        b"\0",
        // Scalars, whole and cut off.
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
        // Strings, whole and cut off, and escapes that end with the buffer.
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
        // Objects and arrays at the edges of their own punctuation.
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
        // Closers that do not match their openers.
        br#"{"a":[1,2}}"#,
        br#"{"a":1]"#,
        br#"[{]"#,
        br#"{]"#,
        b"[}",
        // Valid JSON followed by garbage, and garbage in front.
        br#"{"a":1} trailing garbage"#,
        br#"{"a":1}{"a":2}"#,
        br#"garbage {"a":1}"#,
        br#"{"a":1}]"#,
        // Duplicate keys, first and last differing.
        br#"{"model":"cheap","model":"dear"}"#,
        br#"{"a":1,"a":2,"a":3}"#,
        br#"{"usage":{"total_tokens":1,"total_tokens":999}}"#,
        // Keys carrying the pointer grammar's own punctuation.
        br#"{"a/b":1,"a~b":2,"a":3}"#,
        br#"{"":1}"#,
        br#"{"~":1,"~0":2,"/":3}"#,
        // Keys whose bytes are not UTF-8, or whose escapes name no character.
        b"{\"a\xff\":1,\"a\":2}",
        b"{\"a\\q\":1,\"a\":2}",
        b"{\"a\\ud800\":1,\"a\":2}",
        b"{\"a\\ud800\\ud800\":1,\"a\":2}",
        b"{\"\xc0\xaf\":1}",
        b"{\"\xe2\x82\":1}",
        // A brace and a bracket hiding inside a string.
        br#"{"decoy":"}{[]\"","a":1}"#,
        br#"{"decoy":"\\","a":1}"#,
        // Arrays for the index grammar.
        br#"{"items":[10,20,30]}"#,
        br#"{"items":[]}"#,
        br#"{"items":[[1]]}"#,
        // Numbers where the object's punctuation should be.
        br#"{"a":1-2,"b":3}"#,
        br#"{"a":1e,"b":3}"#,
    ];
    bodies.extend(literals.iter().map(|b| b.to_vec()));

    // Nesting at, either side of, and far past the depth ceiling.
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
        // Unclosed, which is the shape a hostile body actually takes.
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
    // Ten thousand open brackets, the case the crate documentation names.
    bodies.push(vec![b'['; 10_000]);
    bodies.push(vec![b'{'; 10_000]);

    // Every proper prefix of a body that carries all of it, so a truncation at any byte is covered.
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
        // The frontier is an index into the input, always.
        assert!(
            scan_frontier(&body) <= body.len(),
            "frontier past the end of {} bytes",
            body.len()
        );
    }
}

#[test]
fn the_answers_the_hostile_cases_are_pinned_to() {
    // (input, pointer, answer). Each row is a claim about WHICH answer, not merely that there was
    // one — a case that quietly became Missing where it used to be Found is the regression that
    // matters.
    let rows: &[(&[u8], &str, Resolved)] = &[
        // An escape whose backslash is the last byte does not read past the buffer.
        (b"{\"a\":\"x\\", "/a", Resolved::NeedMore),
        (b"\"\\", "", Resolved::NeedMore),
        // A `\u` with fewer than four hex digits names no character, so the key is not the token.
        (
            b"{\"a\\u00\":1,\"a\":2}",
            "/a",
            Resolved::Found(Span::new(15, 16)),
        ),
        // Surrogate halves: a high half alone, a high half followed by a non-low escape, a low half
        // alone. None of them is a character, and none of them is an arithmetic overflow.
        (b"{\"\\ud800\":1}", "/x", Resolved::Missing),
        (b"{\"\\ud800\\u0041\":1}", "/x", Resolved::Missing),
        (b"{\"\\udc00\":1}", "/x", Resolved::Missing),
        // A duplicate key answers the LAST one, which is what serde_json and the providers read.
        (
            br#"{"model":"cheap","model":"dear"}"#,
            "/model",
            Resolved::Found(Span::new(25, 31)),
        ),
        // A key containing a slash is reached with `~1`, a tilde with `~0`, and neither spelling
        // reaches the other key.
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
        // An array index is the pointer grammar's, not whatever parses.
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
        // Numbers are located, not validated: exponents, leading zeroes and `-0` are all spans.
        (br#"{"a":-0}"#, "/a", Resolved::Found(Span::new(5, 7))),
        (br#"{"a":0123}"#, "/a", Resolved::Found(Span::new(5, 9))),
        (
            br#"{"a":1.2.3e,"b":1}"#,
            "/a",
            Resolved::Found(Span::new(5, 11)),
        ),
        // Whitespace in every position JSON allows it.
        (
            b" \t\r\n{\r\n \"a\" \t: \n 1 \r}",
            "/a",
            Resolved::Found(Span::new(17, 18)),
        ),
        // A NUL byte outside a string is structure the scanner cannot read; inside one it is bytes.
        (b"{\"a\":\0}", "/a", Resolved::Malformed),
        (b"{\"a\":\"\0\"}", "/a", Resolved::Found(Span::new(5, 8))),
        // Valid JSON followed by garbage: the scanner LOCATES, so the value is still where it is.
        (
            br#"{"a":1} garbage"#,
            "/a",
            Resolved::Found(Span::new(5, 6)),
        ),
        (br#"{"a":1} garbage"#, "", Resolved::Found(Span::new(0, 7))),
        // A closer that does not match its opener is structure, and structure is refused.
        (br#"{"a":[1,2}}"#, "/a", Resolved::Malformed),
        (br#"{"a":1]"#, "/a", Resolved::Malformed),
        // A pointer that does not start with a slash is not a pointer.
        (br#"{"a":1}"#, "a", Resolved::Malformed),
        (br#"{"a":1}"#, "~", Resolved::Malformed),
        // The empty token names the empty key, at the top level and one level down.
        (br#"{"":1}"#, "/", Resolved::Found(Span::new(4, 5))),
        (br#"{"a":{"":1}}"#, "/a/", Resolved::Found(Span::new(9, 10))),
        // A step into a scalar names nothing rather than reading the scalar's bytes as a container.
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
    // The object walk will not answer until the closing brace has arrived, because bytes that have
    // not come cannot be read as this object's own punctuation. The array walk owes the same: an
    // element whose value happens to self-terminate at the last byte — a closed string, a matched
    // container, a literal — is not yet followed by anything, and what follows it decides whether
    // this is an array at all.
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
        // And the completion that makes the prefix a lie is refused, which is what the prefix could
        // not have known.
        assert_eq!(
            resolve_pointer(whole, "/0"),
            Resolved::Malformed,
            "{:?}",
            String::from_utf8_lossy(whole)
        );
    }
    // The array that did close still answers, at the last element as at the first.
    assert_eq!(probe(br#"[10,20]"#, "/1"), Resolved::Found(Span::new(4, 6)));
    assert_eq!(probe(br#"[10,20]"#, "/0"), Resolved::Found(Span::new(1, 3)));
}

#[test]
fn the_depth_ceiling_is_the_same_number_from_either_direction() {
    // The ceiling is one number, so the deepest body that resolves and the shallowest that is
    // refused have to sit either side of it whichever way the descent got there — through a
    // pointer's own steps, or through a container the scanner is merely stepping over.
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
fn a_hostile_nest_costs_time_in_proportion_to_its_length() {
    // A body that is nothing but open brackets is refused at the ceiling, so the cost of refusing
    // it cannot grow with the length of the rest. Ten times the bytes, near enough ten times the
    // work — a quadratic rescan shows up here as a hundred.
    let time = |count: usize| {
        let body = vec![b'['; count];
        let started = std::time::Instant::now();
        for _ in 0..50 {
            assert_eq!(resolve_pointer(&body, "/0"), Resolved::Malformed);
        }
        started.elapsed()
    };
    let small = time(10_000).as_secs_f64().max(1e-9);
    let large = time(100_000).as_secs_f64();
    assert!(
        large / small < 30.0,
        "ten times the brackets cost {:.1} times the time",
        large / small
    );
}

#[test]
fn a_span_never_slices_backwards_however_it_was_built() {
    // `Span::new` is public, so a span the scanner never produced can still be handed to `of` — by
    // a journal read back, or by a caller doing its own arithmetic. Reading one is an empty answer,
    // not a panic in the middle of a request.
    let buf = b"0123456789";
    assert_eq!(Span::new(5, 2).of(buf), b"");
    assert_eq!(Span::new(20, 30).of(buf), b"");
    assert_eq!(Span::new(8, 4).of(buf), b"");
    assert_eq!(Span::new(2, 5).of(buf), b"234");
    assert_eq!(Span::new(0, 30).of(buf), buf);
}

#[test]
fn the_frontier_is_an_index_and_never_a_verdict() {
    // A complete value ends where it ends, whatever follows it. Bytes that ran out mid-value, and
    // bytes that are not structure at all, both come back as the whole input — so the frontier
    // alone cannot tell "whole" from "broken", which is the reading the documentation used to
    // invite by naming a caller that does not exist.
    assert_eq!(scan_frontier(br#"{"a":1}"#), 7);
    assert_eq!(scan_frontier(br#"  {"a":1}  "#), 9);
    assert_eq!(scan_frontier(br#"{"a":1} trailing"#), 7);
    // Truncated, and structurally impossible: the same answer, and it is the length.
    assert_eq!(scan_frontier(br#"{"a":1"#), 6);
    assert_eq!(scan_frontier(br#"{"a":1]xxxx"#), 11);
    assert_eq!(scan_frontier(b""), 0);
    // The pointer answer is the one that distinguishes the three.
    assert!(matches!(
        resolve_pointer(br#"{"a":1} trailing"#, ""),
        Resolved::Found(_)
    ));
    assert_eq!(resolve_pointer(br#"{"a":1"#, ""), Resolved::NeedMore);
    assert_eq!(resolve_pointer(br#"{"a":1]xxxx"#, ""), Resolved::Malformed);
}
