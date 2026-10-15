// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The well-known types' JSON mapping (`pbjson-types`' own cases, and the calendar's).

use super::*;

fn ts(seconds: i64, nanos: i32) -> Timestamp {
    Timestamp { seconds, nanos }
}

/// A UTC time is written as `to_rfc3339` wrote it: the fraction in 0, 3, 6 or 9 digits.
#[test]
fn a_timestamp_is_written_as_rfc3339() {
    let cases = [
        (ts(1_478_617_629, 0), "2016-11-08T15:07:09+00:00"),
        (ts(0, 0), "1970-01-01T00:00:00+00:00"),
        (ts(-1, 0), "1969-12-31T23:59:59+00:00"),
        (
            ts(1_478_617_629, 500_000_000),
            "2016-11-08T15:07:09.500+00:00",
        ),
        (ts(1_478_617_629, 1_000), "2016-11-08T15:07:09.000001+00:00"),
        (ts(1_478_617_629, 7), "2016-11-08T15:07:09.000000007+00:00"),
        (ts(951_782_400, 0), "2000-02-29T00:00:00+00:00"),
        (ts(-62_167_219_200, 0), "0000-01-01T00:00:00+00:00"),
        (ts(-62_167_219_201, 0), "-0001-12-31T23:59:59+00:00"),
        (ts(253_402_300_800, 0), "+10000-01-01T00:00:00+00:00"),
        // A leap second: the 59th second carrying a second's worth of nanoseconds.
        (
            ts(1_483_228_799, 1_000_000_000),
            "2016-12-31T23:59:60+00:00",
        ),
    ];
    for (t, want) in cases {
        assert_eq!(
            serde_json::to_value(t).unwrap(),
            serde_json::json!(want),
            "{want}"
        );
    }
    assert!(serde_json::to_value(ts(0, -1)).is_err());
    assert!(serde_json::to_value(ts(1, 1_000_000_000)).is_err());
    assert!(!representable(i64::MAX, 0));
}

/// An RFC 3339 string reads as `parse_from_rfc3339` read it, converted to UTC.
#[test]
fn a_timestamp_is_read_from_rfc3339() {
    let cases = [
        ("2016-11-08T20:07:09+05:00", ts(1_478_617_629, 0)),
        ("2016-11-08t15:07:09z", ts(1_478_617_629, 0)),
        ("2016-11-08 15:07:09Z", ts(1_478_617_629, 0)),
        ("2016-11-08T15:07:09.5Z", ts(1_478_617_629, 500_000_000)),
        (
            "2016-11-08T15:07:09.1234567891Z",
            ts(1_478_617_629, 123_456_789),
        ),
        ("2016-11-08T10:07:09\u{2212}05:00", ts(1_478_617_629, 0)),
        ("2016-12-31T23:59:60Z", ts(1_483_228_799, 1_000_000_000)),
    ];
    for (s, want) in cases {
        assert_eq!(s.parse::<Timestamp>(), Ok(want), "{s}");
    }
    let refused = [
        ("2016-11-08T15:07", ParseError::TooShort),
        ("2016-11-08X15:07:09Z", ParseError::Invalid),
        ("2016-02-30T15:07:09Z", ParseError::OutOfRange),
        ("2016-11-08T24:07:09Z", ParseError::OutOfRange),
        ("2016-11-08T15:07:61Z", ParseError::OutOfRange),
        ("2016-11-08T15:07:09", ParseError::TooShort),
        ("2016-11-08T15:07:09+05", ParseError::TooShort),
        ("2016-11-08T15:07:09+0500", ParseError::Invalid),
        ("2016-11-08T15:07:09+05:60", ParseError::OutOfRange),
        ("2016-11-08T15:07:09+24:00", ParseError::OutOfRange),
        ("2016-11-08T15:07:09Zx", ParseError::TooLong),
        ("2016-11-08T15:07:09.Z", ParseError::Invalid),
    ];
    for (s, want) in refused {
        assert_eq!(s.parse::<Timestamp>(), Err(want), "{s}");
    }
}

/// A value is the JSON value it is; a number past a double's exact range is refused.
#[test]
fn a_value_is_the_json_value_it_is() {
    let v: Value = serde_json::from_value(serde_json::json!({
        "b": true, "n": 5, "s": "x", "l": [1.5, null], "o": { "k": "v" }, "z": null,
    }))
    .unwrap();
    let back = serde_json::to_value(&v).unwrap();
    assert_eq!(
        back,
        serde_json::json!({
            "b": true, "n": 5.0, "s": "x", "l": [1.5, null], "o": { "k": "v" }, "z": null,
        })
    );
    assert!(serde_json::from_value::<Value>(serde_json::json!(9_007_199_254_740_993_i64)).is_err());
    let nan = Value {
        kind: Some(value::Kind::NumberValue(f64::NAN)),
    };
    assert!(serde_json::to_value(&nan).is_err());
}
