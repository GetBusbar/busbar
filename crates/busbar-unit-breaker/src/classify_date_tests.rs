// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Retry-After` HTTP-date leg, and the one class guard on the structured-type path.
//!
//! The date parser is hand-rolled — this crate depends on nothing that could parse one for it — so
//! every part of it is this crate's own to prove: the shape guard that decides a value is an
//! IMF-fixdate at all, the twelve month abbreviations, and the civil-to-epoch arithmetic under
//! them. A month that resolved to the wrong number, or a shape guard that accepted a value it
//! should have refused, turns an upstream's "come back at noon" into a cooldown of the wrong
//! length — which is a lane parked for hours, or one hammered immediately.
//!
//! Every date below is asserted against `now = 0`, so the answer IS the Unix timestamp of the
//! instant named, and each figure is one an independent calendar produces.

use std::collections::HashMap;

use crate::classify::{
    classify, normalize_raw_error, parse_retry_after, Disposition, NoopDiagnostics,
    RawUpstreamError, StatusClass,
};

fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ── the twelve months ───────────────────────────────────────────────────────────────────────────

/// Every month abbreviation RFC 9110 can carry resolves to its own month. Asserted against the
/// first instant of each month of 2021 — a common year, so no two of the twelve share a timestamp
/// and a month that resolved to its neighbour lands on a different day entirely.
#[test]
fn every_month_abbreviation_resolves_to_its_own_month() {
    let months: &[(&str, &str, u64)] = &[
        ("Fri", "Jan", 1_609_459_200),
        ("Mon", "Feb", 1_612_137_600),
        ("Mon", "Mar", 1_614_556_800),
        ("Thu", "Apr", 1_617_235_200),
        ("Sat", "May", 1_619_827_200),
        ("Tue", "Jun", 1_622_505_600),
        ("Thu", "Jul", 1_625_097_600),
        ("Sun", "Aug", 1_627_776_000),
        ("Wed", "Sep", 1_630_454_400),
        ("Fri", "Oct", 1_633_046_400),
        ("Mon", "Nov", 1_635_724_800),
        ("Wed", "Dec", 1_638_316_800),
    ];
    for (day_name, month, expected) in months {
        let value = format!("{day_name}, 01 {month} 2021 00:00:00 GMT");
        assert_eq!(
            parse_retry_after(&value, 0),
            Some(*expected),
            "{value} is the first instant of {month} 2021"
        );
    }

    // And no two of the twelve answer with the same instant.
    let mut seen: Vec<u64> = months.iter().map(|(_, _, ts)| *ts).collect();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "the twelve months are twelve instants");
}

/// A month abbreviation no calendar names is refused rather than guessed at.
#[test]
fn an_unknown_month_abbreviation_is_refused() {
    for month in ["Foo", "JAN", "jan", "Ja1", "Sept"] {
        let value = format!("Fri, 01 {month} 2021 00:00:00 GMT");
        // `Sept` is four characters, so it also fails the fixed-width shape; the rest are the
        // month lookup itself. Either way the answer is that this is not a date.
        assert_eq!(
            parse_retry_after(&value, 0),
            None,
            "{value} names no month this parser recognises"
        );
    }
}

// ── the civil-to-epoch arithmetic ───────────────────────────────────────────────────────────────

/// The dates the arithmetic has to get right: the epoch itself, RFC 9110's own worked example, a
/// leap day, and the century-rule boundary a naive leap-year test gets wrong.
#[test]
fn the_calendar_arithmetic_agrees_with_the_calendar() {
    let dates: &[(&str, u64)] = &[
        // The epoch itself.
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        // One second into it, so the seconds field is proved to reach the answer.
        ("Thu, 01 Jan 1970 00:00:01 GMT", 1),
        // One minute and one hour, likewise.
        ("Thu, 01 Jan 1970 00:01:00 GMT", 60),
        ("Thu, 01 Jan 1970 01:00:00 GMT", 3_600),
        // The example RFC 9110 itself gives for the format.
        ("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777),
        // A leap day: 2024 is a leap year, so the 29th of February exists.
        ("Thu, 29 Feb 2024 12:00:00 GMT", 1_709_208_000),
        // The century rule: 2000 IS a leap year (divisible by 400), so the 29th exists there too.
        ("Tue, 29 Feb 2000 00:00:00 GMT", 951_782_400),
        // And the day after it.
        ("Wed, 01 Mar 2000 00:00:00 GMT", 951_868_800),
        // The last second of a year, so the year rollover is proved in both directions.
        ("Fri, 31 Dec 2021 23:59:59 GMT", 1_640_995_199),
        ("Sat, 01 Jan 2022 00:00:00 GMT", 1_640_995_200),
    ];
    for (value, expected) in dates {
        assert_eq!(
            parse_retry_after(value, 0),
            Some(*expected),
            "{value} is not the instant the calendar says it is"
        );
    }
}

/// January and February are the two months the day-count algorithm shifts the year for; a shift in
/// the wrong direction lands a whole year away. Asserted as the distance between the two months
/// either side of the shift.
#[test]
fn the_year_shift_the_algorithm_makes_for_january_and_february_is_the_right_way_round() {
    let feb = parse_retry_after("Mon, 01 Feb 2021 00:00:00 GMT", 0).expect("a date");
    let mar = parse_retry_after("Mon, 01 Mar 2021 00:00:00 GMT", 0).expect("a date");
    assert_eq!(
        mar - feb,
        28 * 86_400,
        "February 2021 is twenty-eight days; a year shifted the wrong way makes it hundreds"
    );

    let jan = parse_retry_after("Fri, 01 Jan 2021 00:00:00 GMT", 0).expect("a date");
    let dec_before = parse_retry_after("Tue, 01 Dec 2020 00:00:00 GMT", 0).expect("a date");
    assert_eq!(
        jan - dec_before,
        31 * 86_400,
        "December 2020 is thirty-one days, and January is on the other side of a year boundary"
    );
}

// ── the shape guard ─────────────────────────────────────────────────────────────────────────────

/// The fixed-width shape is checked on BOTH counts, and either one failing is enough to refuse: a
/// value of the right length that does not end in `GMT` is not a UTC instant, and a value that ends
/// in `GMT` at the wrong length is not this format at all.
#[test]
fn the_shape_guard_refuses_on_either_count_alone() {
    // Right length, wrong zone. Twenty-nine bytes, so only the suffix check can refuse it.
    let wrong_zone = "Fri, 01 Jan 2021 00:00:00 UTC";
    assert_eq!(
        wrong_zone.len(),
        29,
        "the length check cannot be what refuses it"
    );
    assert_eq!(
        parse_retry_after(wrong_zone, 0),
        None,
        "a value naming a zone this parser does not read is not a date it can answer about"
    );

    // Right suffix, wrong length: a single-digit day. Only the length check can refuse it.
    let short_day = "Fri, 1 Jan 2021 00:00:00 GMT";
    assert_ne!(short_day.len(), 29);
    assert!(
        short_day.ends_with(" GMT"),
        "the suffix check cannot be what refuses it"
    );
    assert_eq!(
        parse_retry_after(short_day, 0),
        None,
        "the obsolete forms are not accepted, and a mis-sliced one would read the wrong fields"
    );

    // And a value that is too long, likewise.
    let long = "Friday, 01 Jan 2021 00:00:00 GMT";
    assert!(long.ends_with(" GMT"));
    assert_eq!(parse_retry_after(long, 0), None);
}

/// The two separators after the day name are checked separately, and either one alone is enough to
/// refuse: a value carrying the wrong punctuation is a value whose fields are not where the fixed
/// slices look for them.
#[test]
fn the_separator_guard_refuses_on_either_separator_alone() {
    // The comma is wrong, the space is right.
    let no_comma = "Fri; 01 Jan 2021 00:00:00 GMT";
    assert_eq!(no_comma.len(), 29);
    assert_eq!(
        parse_retry_after(no_comma, 0),
        None,
        "the separator after the day name is a comma"
    );

    // The comma is right, the space is wrong.
    let no_space = "Fri,x01 Jan 2021 00:00:00 GMT";
    assert_eq!(no_space.len(), 29);
    assert_eq!(
        parse_retry_after(no_space, 0),
        None,
        "and the comma is followed by a space"
    );
}

/// The `delay-seconds` form is read first and does not depend on the clock at all.
#[test]
fn the_delay_seconds_form_ignores_the_clock() {
    assert_eq!(parse_retry_after("120", 0), Some(120));
    assert_eq!(parse_retry_after("120", 1_700_000_000), Some(120));
    assert_eq!(parse_retry_after("  120  ", 0), Some(120));
    assert_eq!(parse_retry_after("0", 0), Some(0));
}

/// A date already in the past floors at zero rather than wrapping into a wait of centuries.
#[test]
fn a_date_already_past_floors_at_zero() {
    assert_eq!(
        parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 1_700_000_000),
        Some(0)
    );
}

/// Anything that is neither form at all is simply not a wait.
#[test]
fn a_value_that_is_neither_form_is_not_a_wait() {
    for value in ["", "soon", "-5", "12.5", "Fri, 01 Jan 2021 00:00:00"] {
        assert_eq!(parse_retry_after(value, 0), None, "{value:?} is not a wait");
    }
}

// ── the class guard on the structured-type path ─────────────────────────────────────────────────

/// The guard on the structured-type path is about ONE class on a 5xx, not about 5xx in general: a
/// mapped rate limit on a 503 is still a rate limit, and only a mapped context-length is suppressed
/// so it cannot mask a real upstream outage.
#[test]
fn the_class_guard_suppresses_only_context_length_on_a_5xx() {
    let map = err_map(&[
        ("throttled", "rate_limit"),
        ("too_long", "context_length"),
        ("bad_key", "auth"),
    ]);

    // A mapped rate limit on a 503 keeps the class the operator mapped it to.
    let throttled = normalize_raw_error(
        &RawUpstreamError {
            http_status: 503,
            provider_code: None,
            structured_type: Some("throttled".to_string()),
            retry_after_secs: Some(9),
        },
        &map,
        &NoopDiagnostics,
    );
    assert_eq!(
        throttled.class,
        StatusClass::RateLimit,
        "only context-length is suppressed on a 5xx; every other mapped class stands"
    );
    assert_eq!(throttled.provider_signal.as_deref(), Some("throttled"));
    assert_eq!(throttled.retry_after, Some(9));

    // A mapped hard-down class on a 5xx, likewise: the operator's mapping is what decides.
    let bad_key = normalize_raw_error(
        &RawUpstreamError {
            http_status: 500,
            provider_code: None,
            structured_type: Some("bad_key".to_string()),
            retry_after_secs: None,
        },
        &map,
        &NoopDiagnostics,
    );
    assert_eq!(bad_key.class, StatusClass::Auth);
    assert_eq!(classify(&bad_key), Disposition::HardDown);

    // A mapped context-length on a 5xx IS suppressed: the lane is penalised for the outage.
    let masked = normalize_raw_error(
        &RawUpstreamError {
            http_status: 503,
            provider_code: None,
            structured_type: Some("too_long".to_string()),
            retry_after_secs: None,
        },
        &map,
        &NoopDiagnostics,
    );
    assert_eq!(
        masked.class,
        StatusClass::ServerError,
        "a context-length mapping must never mask a real upstream outage"
    );
    assert_eq!(classify(&masked), Disposition::TransientUpstream);

    // And on a status that really is a request-size rejection it is honoured.
    let genuine = normalize_raw_error(
        &RawUpstreamError {
            http_status: 400,
            provider_code: None,
            structured_type: Some("too_long".to_string()),
            retry_after_secs: None,
        },
        &map,
        &NoopDiagnostics,
    );
    assert_eq!(genuine.class, StatusClass::ContextLength);
    assert_eq!(classify(&genuine), Disposition::ContextLength);
}
