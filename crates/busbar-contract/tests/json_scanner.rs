// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON span scanner, and the budget it has to meet.
//!
//! The case that matters is the big body whose one interesting key was serialised LAST: the whole
//! body has to be walked before the answer exists, so that is where the cost is measured.

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
            // Until the key has arrived the answer is "not yet", never a wrong span.
            Resolved::NeedMore | Resolved::Missing => {}
            Resolved::Found(span) => panic!("resolved at {cut} bytes to {:?}", span),
            Resolved::Malformed => panic!("a prefix of valid JSON called malformed at {cut}"),
        }
    }
    assert_eq!(found(whole, "/lane"), br#""gold""#);
}

#[test]
fn escapes_are_decoded_on_both_sides_without_allocating_anything() {
    // A slash inside a key is `~1` in the pointer and an ordinary character in the document; a
    // tilde is `~0`; and the document's own escapes decode too.
    let body = "{\"a/b\": 1, \"c~d\": 2, \"e\\\"f\": 3, \"g\u{e9}h\": 4}".as_bytes();
    assert_eq!(found(body, "/a~1b"), b"1");
    assert_eq!(found(body, "/c~0d"), b"2");
    assert_eq!(found(body, "/e\"f"), b"3");
    assert_eq!(found(body, "/g\u{e9}h"), b"4");
}

#[test]
fn a_broken_surrogate_pair_in_a_key_is_a_miss_not_an_overflow() {
    // A high half whose partner is not a low half: the arithmetic that combines the two would
    // subtract 0xDC00 from something smaller. Every other bad escape here answers "no character",
    // and so does this one.
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\u0041\": 1}", "/x"),
        Resolved::Missing
    );
    assert_eq!(
        resolve_pointer(b"{\"\\uD800\\uD800\": 1}", "/x"),
        Resolved::Missing
    );
    // A lone high half with nothing after it, and a well-formed pair, both still behave.
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
    // A key whose decoded prefix is the token and whose remainder is a broken escape is NOT the
    // token: the escape names no character, so the key is longer than what matched. Answering
    // otherwise lets whoever wrote the body choose which member the kernel reads, because the
    // scan stops at the first key it calls equal.
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
    // The same on the raw-byte side: a key whose remainder is not UTF-8 at all.
    assert_eq!(
        found(
            b"{\"model\xff\":\"cheap\",\"model\":\"expensive\"}",
            "/model"
        ),
        br#""expensive""#
    );
    // And a bad escape letter, which is the plainest undecodable remainder there is.
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
    // The mirror of the key side: the pointer's own escape grammar has exactly `~0` and `~1`, so a
    // token ending in a bare tilde, or in a tilde followed by anything else, names no member — not
    // the member spelled with the part before it.
    let body = br#"{"model": 1, "model~": 2, "modelx": 3}"#;
    assert_eq!(resolve_pointer(body, "/model~"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/model~x"), Resolved::Missing);
    assert_eq!(found(body, "/model"), b"1");
}

#[test]
fn a_duplicated_key_answers_the_last_one_the_way_every_parser_downstream_does() {
    // serde_json — which 1.5.5 read every body with — and the providers' own parsers all take the
    // LAST occurrence of a repeated member. Answering the first one prices and permits one model
    // while the provider serves another, which is a choice the body's author gets to make.
    let body = br#"{"model":"cheap-mini","messages":[],"model":"expensive-max"}"#;
    assert_eq!(found(body, "/model"), br#""expensive-max""#);
    // Nested, so it is the object being walked that decides and not the top level.
    let body = br#"{"usage":{"total_tokens":1,"total_tokens":999},"model":"m"}"#;
    assert_eq!(found(body, "/usage/total_tokens"), b"999");
    // Three of them, and the middle one is not the answer either.
    let body = br#"{"a":1,"a":2,"a":3}"#;
    assert_eq!(found(body, "/a"), b"3");
    // A duplicate of a key that is not the one asked for changes nothing.
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
    // A container must close with the bracket that opened it. Counting brackets without recording
    // which one opened each level answers Found over a span that is not a JSON value.
    assert_eq!(
        resolve_pointer(br#"{"a":[1,2}}"#, "/a"),
        Resolved::Malformed
    );
    assert_eq!(resolve_pointer(br#"{"a":1]"#, "/a"), Resolved::Malformed);
    assert_eq!(
        resolve_pointer(br#"{"a":{"b":1]}"#, "/a"),
        Resolved::Malformed
    );
    // The well-matched shapes still resolve.
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
    // And the span is a span of the caller's bytes, not a copy of them.
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
/// `rounds` rounds took, the runs INTERLEAVED round by round, so every run is measured on the same
/// machine at the same moments and a burst of contention lands on all of them alike.
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
/// the reference the scanner's cost is measured against, in the same build on the same machine.
fn reference_walk(body: &[u8]) {
    let walked: serde::de::IgnoredAny =
        serde_json::from_slice(std::hint::black_box(body)).expect("the body is JSON");
    std::hint::black_box(walked);
}

/// THE SCANNER'S BUDGET, judged as ratios a loaded machine cannot move. A wall clock on a shared
/// CI machine measures how many other tests held the cores; even the scanning thread's own CPU time
/// moves with them (a sibling hyperthread, a shared cache, a hypervisor's stolen time), so no fixed
/// nanosecond count is a verdict. What the budget MEANS is two things, and each is measured against
/// something that slows down exactly as the scan does:
///
/// * LINEAR: walking a body costs the same per byte at any size, so a body eight times longer
///   costs at most `3 x 8` times as much (a quadratic walk costs `8 x 8`).
/// * WITHIN AN ORDER OF MAGNITUDE of a full walk of the same bytes by serde_json: the scanner skips
///   values it does not need and is designed to be faster than a reader that visits every one, so a
///   scan costing ten such walks is a regression of an order of magnitude.
///
/// `scan` answers one body; the verdict says which bound broke, with what it measured.
fn judge(scan: &dyn Fn(&[u8])) -> Result<String, String> {
    let (small, large) = (big_body(SMALL), big_body(LARGE));
    // A warm pass of each, then the measured rounds.
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
/// walked before the answer exists.
fn scan_for_the_last_key(body: &[u8]) {
    assert!(matches!(
        resolve_pointer(std::hint::black_box(body), "/lane"),
        Resolved::Found(_)
    ));
}

/// The scanner's budget is under a microsecond per kibibyte of body scanned in a release build
/// (measured where it landed: 359 ns per KiB, 2.65 GiB/s; 4,267 ns per KiB in a debug build, and
/// `cargo test --release` is how to see the number that counts). The gate judges it by [`judge`]:
/// linear in the body, and within an order of magnitude of a full walk of the same bytes.
#[test]
fn the_scanner_meets_its_budget_on_a_mebibyte() {
    match judge(&scan_for_the_last_key) {
        Ok(seen) => println!("json span scanner: {seen}"),
        Err(broke) => panic!("the json span scanner broke its budget: {broke}"),
    }
}

/// THE BUDGET'S RED ARM: a planted QUADRATIC scanner fails [`judge`]. It is the regression the
/// budget exists to catch, a reader that re-scans the body from its first byte each time another
/// sixteen kibibytes arrive (the shape a streaming caller that forgot where it stopped has); every
/// pass is the real scanner, so only the shape of the work differs.
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
    // The pointer grammar's array index is a single `0`, or a digit string with no leading zero.
    // Rust's integer parse is more generous than that — it takes a leading `+`, and any number of
    // leading zeroes — so a token the grammar says names nothing would otherwise resolve to an
    // element, and two spellings would name one value where the grammar admits only one of them.
    let body = br#"{"items":[10,20,30]}"#;
    assert_eq!(found(body, "/items/1"), b"20");
    assert_eq!(resolve_pointer(body, "/items/01"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/items/+1"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/items/007"), Resolved::Missing);
    // Zero on its own is the one index that may start with a zero.
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
    // The depth bound is stated in the crate's own documentation as the reason it is a bound at
    // all: a hostile body that is ten thousand open brackets has to come back as a refusal, and
    // the only way to show that is to hand the scanner one.
    let body = vec![b'['; 10_000];
    assert_eq!(resolve_pointer(&body, "/0"), Resolved::Malformed);
    assert_eq!(resolve_pointer(&body, ""), Resolved::Malformed);
}

#[test]
fn the_depth_bound_is_where_the_documentation_says_it_is() {
    let (body, pointer) = nested(60);
    assert_eq!(found(&body, &pointer), b"1", "60 deep is inside the bound");

    let (body, pointer) = nested(70);
    assert_eq!(
        resolve_pointer(&body, &pointer),
        Resolved::Malformed,
        "70 deep is past it"
    );
}
