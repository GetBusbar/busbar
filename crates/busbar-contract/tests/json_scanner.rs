// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON span scanner, and the budget it has to meet.

use busbar_contract::spans::{resolve_pointer, Resolved};

fn found<'b>(body: &'b [u8], pointer: &str) -> &'b [u8] {
    match resolve_pointer(body, pointer) {
        Resolved::Found(span) => span.of(body),
        other => panic!("{pointer} did not resolve: {other:?}"),
    }
}

#[test]
fn a_pointer_resolves_to_a_span_of_the_callers_own_bytes() {
    let body = br#"{"a": {"b": [1, 2, {"c": "here"}]}, "lane": "gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
    assert_eq!(found(body, "/a/b/2/c"), br#""here""#);
    assert_eq!(found(body, "/a/b/1"), b"2");
    assert_eq!(resolve_pointer(body, "/missing"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/a/b/9"), Resolved::Missing);
}

#[test]
fn an_empty_pointer_names_the_whole_document() {
    let body = br#"  {"a": 1}  "#;
    assert_eq!(found(body, ""), br#"{"a": 1}"#);
}

#[test]
fn a_truncated_document_asks_for_more_rather_than_answering() {
    let whole = br#"{"a": {"b": "value"}, "lane": "gold"}"#;
    for cut in 1..whole.len() - 1 {
        match resolve_pointer(&whole[..cut], "/lane") {
            Resolved::NeedMore | Resolved::Missing => {}
            Resolved::Found(span) => panic!("resolved at {cut} bytes to {:?}", span),
            Resolved::Malformed => panic!("a prefix of valid JSON called malformed at {cut}"),
        }
    }
    assert_eq!(found(whole, "/lane"), br#""gold""#);
}

#[test]
fn escapes_are_decoded_on_both_sides_without_allocating_anything() {
    let body = "{\"a/b\": 1, \"c~d\": 2, \"e\\\"f\": 3, \"g\u{e9}h\": 4}".as_bytes();
    assert_eq!(found(body, "/a~1b"), b"1");
    assert_eq!(found(body, "/c~0d"), b"2");
    assert_eq!(found(body, "/e\"f"), b"3");
    assert_eq!(found(body, "/g\u{e9}h"), b"4");
}

#[test]
fn a_broken_surrogate_pair_in_a_key_is_a_miss_not_an_overflow() {
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\u0041\": 1}", "/x"),
        Resolved::Missing
    );
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\uD800\": 1}", "/x"),
        Resolved::Missing
    );

    assert_eq!(
        resolve_pointer(b"{\"\\uD800\": 1}", "/x"),
        Resolved::Missing
    );
    assert_eq!(
        found("{\"\\uD83D\\uDE00\": 1}".as_bytes(), "/\u{1F600}"),
        b"1"
    );
}

#[test]
fn a_key_that_cannot_be_decoded_never_matches_the_pointer_that_prefixes_it() {
    assert_eq!(
        found(
            b"{\"model\\uD800\":\"cheap\",\"model\":\"expensive\"}",
            "/model"
        ),
        br#""expensive""#
    );
    assert_eq!(
        found(
            b"{\"usage\":{\"total_tokens\\udc00\":1,\"total_tokens\":999}}",
            "/usage/total_tokens"
        ),
        b"999"
    );
    assert_eq!(found(b"{\"\\uD800\": 1, \"\": 2}", "/"), b"2");

    assert_eq!(
        found(
            b"{\"model\xff\":\"cheap\",\"model\":\"expensive\"}",
            "/model"
        ),
        br#""expensive""#
    );

    assert_eq!(
        found(
            b"{\"model\\q\":\"cheap\",\"model\":\"expensive\"}",
            "/model"
        ),
        br#""expensive""#
    );
}

#[test]
fn a_pointer_token_that_cannot_be_decoded_never_matches_the_key_that_prefixes_it() {
    let body = br#"{"model": 1, "model~": 2, "modelx": 3}"#;
    assert_eq!(resolve_pointer(body, "/model~"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/model~x"), Resolved::Missing);
    assert_eq!(found(body, "/model"), b"1");
}

#[test]
fn a_duplicated_key_answers_the_last_one_the_way_every_parser_downstream_does() {
    let body = br#"{"model":"cheap-mini","messages":[],"model":"expensive-max"}"#;
    assert_eq!(found(body, "/model"), br#""expensive-max""#);

    let body = br#"{"usage":{"total_tokens":1,"total_tokens":999},"model":"m"}"#;
    assert_eq!(found(body, "/usage/total_tokens"), b"999");

    let body = br#"{"a":1,"a":2,"a":3}"#;
    assert_eq!(found(body, "/a"), b"3");

    let body = br#"{"a":1,"b":2,"b":3}"#;
    assert_eq!(found(body, "/a"), b"1");
}

#[test]
fn a_brace_inside_a_string_does_not_confuse_the_scan() {
    let body = br#"{"decoy": "}{[]\"", "lane": "gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
}

#[test]
fn nonsense_is_called_nonsense() {
    assert_eq!(resolve_pointer(b"not json", "/a"), Resolved::Missing);
    assert_eq!(resolve_pointer(b"{\"a\" 1}", "/a"), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"{\"a\": 1}", "a"), Resolved::Malformed);
}

#[test]
fn a_closer_that_does_not_match_its_opener_is_nonsense() {
    assert_eq!(
        resolve_pointer(br#"{"a":[1,2}}"#, "/a"),
        Resolved::Malformed
    );
    assert_eq!(resolve_pointer(br#"{"a":1]"#, "/a"), Resolved::Malformed);
    assert_eq!(
        resolve_pointer(br#"{"a":{"b":1]}"#, "/a"),
        Resolved::Malformed
    );

    assert_eq!(found(br#"{"a":[1,2]}"#, "/a"), b"[1,2]");
    assert_eq!(found(br#"{"a":{"b":[1]}}"#, "/a"), br#"{"b":[1]}"#);
}

/// Build a body of at least `bytes` bytes whose lane key is the LAST thing in it.
fn big_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes + 64);
    body.extend_from_slice(br#"{"messages":["#);
    let chunk = br#"{"role":"one","content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#;
    while body.len() < bytes {
        body.extend_from_slice(chunk);
    }
    body.extend_from_slice(br#"{"role":"one","content":"last"}],"lane":"gold"}"#);
    body
}

#[test]
fn a_body_over_a_mebibyte_with_the_lane_key_last_still_resolves() {
    let body = big_body(1 << 20);
    assert!(body.len() >= 1 << 20);
    assert_eq!(found(&body, "/lane"), br#""gold""#);

    match resolve_pointer(&body, "/lane") {
        Resolved::Found(span) => {
            assert_eq!(span.of(&body), &body[span.start..span.end]);
            assert!(span.start > (1 << 20));
        }
        other => panic!("{other:?}"),
    }
}

/// The calling thread's CPU time so far.
fn thread_cpu() -> std::time::Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; the clock id is a constant the platform defines.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "the thread's CPU clock reads");
    std::time::Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

/// The cost of each of `runs`: the fewest nanoseconds of this thread's CPU time any one of
fn costs(rounds: usize, runs: &mut [&mut dyn FnMut()]) -> Vec<f64> {
    let mut best = vec![std::time::Duration::MAX; runs.len()];
    for _ in 0..rounds {
        for (run, best) in runs.iter_mut().zip(best.iter_mut()) {
            let started = thread_cpu();
            run();
            *best = (*best).min(thread_cpu().saturating_sub(started));
        }
    }
    best.iter().map(|d| d.as_nanos().max(1) as f64).collect()
}

/// The bodies a scan is judged on: the same shape at an eighth of a mebibyte and at a mebibyte.
const SMALL: usize = 1 << 17;
const LARGE: usize = 1 << 20;

/// A full walk of `body` by a production JSON reader (serde_json, every value read and ignored):
fn reference_walk(body: &[u8]) {
    let walked: serde::de::IgnoredAny =
        serde_json::from_slice(std::hint::black_box(body)).expect("the body is JSON");
    std::hint::black_box(walked);
}

/// THE SCANNER'S BUDGET, judged as ratios a loaded machine cannot move. A wall clock on a shared
fn judge(scan: &dyn Fn(&[u8])) -> Result<String, String> {
    let (small, large) = (big_body(SMALL), big_body(LARGE));

    scan(&small);
    scan(&large);
    reference_walk(&large);
    let (mut on_small, mut on_large) = (|| scan(&small), || scan(&large));
    let mut walk = || reference_walk(&large);
    let measured = costs(15, &mut [&mut on_small, &mut on_large, &mut walk]);
    let (small_ns, large_ns, walk_ns) = (measured[0], measured[1], measured[2]);
    let size_ratio = large.len() as f64 / small.len() as f64;
    let growth = large_ns / small_ns;
    let against_walk = large_ns / walk_ns;
    let seen = format!(
        "{} bytes in {large_ns:.0} ns of CPU ({:.1} ns per KiB), {} bytes in {small_ns:.0} ns: \
         {growth:.2}x the cost for {size_ratio:.2}x the bytes; {against_walk:.3}x a full serde_json \
         walk of the same bytes",
        large.len(),
        large_ns / (large.len() as f64 / 1024.0),
        small.len(),
    );
    if growth >= 3.0 * size_ratio {
        return Err(format!("not linear: {seen}"));
    }
    if against_walk >= 10.0 {
        return Err(format!("an order of magnitude over a full walk: {seen}"));
    }
    Ok(seen)
}

/// The scan the budget is about: a body whose one interesting key is last, so the whole body is
fn scan_for_the_last_key(body: &[u8]) {
    assert!(matches!(
        resolve_pointer(std::hint::black_box(body), "/lane"),
        Resolved::Found(_)
    ));
}

/// The scanner's budget is under a microsecond per kibibyte of body scanned in a release build
#[test]
fn the_scanner_meets_its_budget_on_a_mebibyte() {
    match judge(&scan_for_the_last_key) {
        Ok(seen) => println!("json span scanner: {seen}"),
        Err(broke) => panic!("the json span scanner broke its budget: {broke}"),
    }
}

/// THE BUDGET'S RED ARM: a planted QUADRATIC scanner fails [`judge`]. It is the regression the
#[test]
fn a_quadratic_scanner_fails_the_budget() {
    fn rescanning(body: &[u8]) {
        const ARRIVAL: usize = 16 << 10;
        let mut seen = 0;
        while seen < body.len() {
            seen = (seen + ARRIVAL).min(body.len());
            let arrived = std::hint::black_box(&body[..seen]);
            std::hint::black_box(resolve_pointer(arrived, "/lane"));
        }
    }
    match judge(&rescanning) {
        Err(broke) => println!("the planted quadratic scanner is refused: {broke}"),
        Ok(seen) => panic!("a quadratic scanner met the budget: {seen}"),
    }
}

#[test]
fn an_array_index_is_the_pointer_grammars_index_and_not_whatever_parses() {
    let body = br#"{"items":[10,20,30]}"#;
    assert_eq!(found(body, "/items/1"), b"20");
    assert_eq!(resolve_pointer(body, "/items/01"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/items/+1"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/items/007"), Resolved::Missing);

    assert_eq!(found(body, "/items/0"), b"10");
}

/// Nest `depth` arrays around a `1`, and the pointer that walks down to it.
fn nested(depth: usize) -> (Vec<u8>, String) {
    let mut body = vec![b'['; depth];
    body.push(b'1');
    body.extend(std::iter::repeat_n(b']', depth));
    (body, "/0".repeat(depth))
}

#[test]
fn ten_thousand_open_brackets_are_an_answer_rather_than_a_stack_overflow() {
    let body = vec![b'['; 10_000];
    assert_eq!(resolve_pointer(&body, "/0"), Resolved::Malformed);
    assert_eq!(resolve_pointer(&body, ""), Resolved::Malformed);
}

#[test]
fn the_depth_bound_is_where_the_documentation_says_it_is() {
    let (body, pointer) = nested(128);
    assert_eq!(found(&body, &pointer), b"1", "128 deep is inside the bound");

    let (body, pointer) = nested(129);
    assert_eq!(
        resolve_pointer(&body, &pointer),
        Resolved::Malformed,
        "129 deep is past it"
    );
}
