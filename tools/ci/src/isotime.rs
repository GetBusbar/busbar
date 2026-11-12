//! CPython 3.12 `datetime.fromisoformat` for aware calendar-date timestamps.
//!
//! This is a direct port of `_datetimemodule.c` (`parse_isoformat_date`,
//! `parse_hh_mm_ss_ff`, `parse_isoformat_time`) including its leniency, so
//! database freshness is accepted or refused exactly as before. ISO week
//! dates and non-ASCII separators are refused (Trivy writes Go RFC 3339).

/// Byte at `i`, with the C string's NUL terminator past the end.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

fn digits(s: &[u8], mut p: usize, count: usize) -> Option<(usize, i64)> {
    let mut value = 0i64;
    for _ in 0..count {
        let c = at(s, p);
        if !c.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(c - b'0');
        p += 1;
    }
    Some((p, value))
}

/// Returns (status, [hour, minute, second], microsecond); status 1 means
/// trailing data, which callers ignore when a UTC offset follows.
fn hh_mm_ss_ff(s: &[u8], start: usize, end: usize) -> Option<(bool, [i64; 3], i64)> {
    let mut values = [0i64; 3];
    let mut p = start;
    let mut separator = true;
    for (index, slot) in values.iter_mut().enumerate() {
        let (next, value) = digits(s, p, 2)?;
        *slot = value;
        p = next;
        let c = at(s, p);
        p += 1;
        if index == 0 {
            separator = c == b':';
        }
        if p >= end {
            return Some((c != 0, values, 0));
        } else if separator && c == b':' {
            continue;
        } else if c == b'.' || c == b',' {
            break;
        } else if !separator {
            p -= 1;
        } else {
            return None;
        }
    }
    let remaining = end.saturating_sub(p);
    let parse = remaining.min(6);
    let (mut p, mut micro) = digits(s, p, parse)?;
    if parse > 0 && parse < 6 {
        micro *= [100000, 10000, 1000, 100, 10][parse - 1];
    }
    while at(s, p).is_ascii_digit() {
        p += 1;
    }
    Some((at(s, p) != 0, values, micro))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// UTC microseconds since the Unix epoch for an aware timestamp, after the
/// former scanner's `.replace('Z', '+00:00')`. None for invalid or naive input.
pub fn aware_utc_micros(text: &str) -> Option<i128> {
    let replaced = text.replace('Z', "+00:00");
    let s = replaced.as_bytes();
    let len = s.len();
    if !s.is_ascii() {
        return None;
    }
    // _find_isoformat_datetime_separator, calendar dates only.
    let separator = if len == 7 {
        7
    } else if at(s, 4) == b'-' {
        if at(s, 5) == b'W' {
            return None;
        }
        10
    } else if at(s, 4) == b'W' {
        return None;
    } else {
        8
    };
    // parse_isoformat_date
    let (mut p, year) = digits(s, 0, 4)?;
    let dashed = at(s, p) == b'-';
    if dashed {
        p += 1;
    }
    if at(s, p) == b'W' {
        return None;
    }
    let (next, month) = digits(s, p, 2)?;
    p = next;
    if dashed {
        if at(s, p) != b'-' {
            return None;
        }
        p += 1;
    }
    let (_, day) = digits(s, p, 2)?;
    if len <= separator {
        return None; // A date without a time is naive.
    }
    // parse_isoformat_time
    let start = separator + 1;
    let mut tz = start;
    loop {
        if matches!(at(s, tz), b'Z' | b'+' | b'-') {
            break;
        }
        tz += 1;
        if tz >= len {
            break;
        }
    }
    let (trailing, [hour, minute, second], micro) = hh_mm_ss_ff(s, start, tz)?;
    let _ = trailing; // Trailing time data is ignored once an offset follows.
    if tz >= len {
        return None; // Naive (or malformed) time.
    }
    let sign = if at(s, tz) == b'-' { -1 } else { 1 };
    let (rest, [tzh, tzm, tzs], tzmicro) = hh_mm_ss_ff(s, tz + 1, len)?;
    if rest {
        return None;
    }
    let offset = i128::from(sign)
        * (i128::from(tzh * 3600 + tzm * 60 + tzs) * 1_000_000 + i128::from(tzmicro));
    if offset.abs() >= 86_400_000_000 {
        return None;
    }
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let local = (i128::from(days_from_civil(year, month, day)) * 86_400
        + i128::from(hour * 3600 + minute * 60 + second))
        * 1_000_000
        + i128::from(micro);
    Some(local - offset)
}

#[cfg(test)]
mod tests {
    use super::aware_utc_micros as parse;

    #[test]
    fn matches_cpython_forms() {
        let base = parse("2026-11-10T13:03:09+00:00").unwrap();
        assert_eq!(base, 1_794_315_789_000_000);
        assert_eq!(parse("2026-11-10T13:03:09Z"), Some(base));
        assert_eq!(
            parse("2026-11-10T13:03:09.123456789Z"),
            Some(base + 123_456)
        );
        assert_eq!(parse("2026-11-10 13:03:09+00:00"), Some(base));
        assert_eq!(parse("20261110T130309+00:00"), Some(base));
        assert_eq!(parse("2026-11-10T13:03:09 +00:00"), Some(base));
        assert_eq!(parse("2026-11-10T13:03:09,5+00:00"), Some(base + 500_000));
        assert_eq!(parse("2026-11-10T13:03:09.+00:00"), Some(base));
        assert_eq!(parse("2026-11-10T18:03:09+05:00"), Some(base));
        assert_eq!(parse("2026-11-10T08:03:09-0500"), Some(base));
        for bad in [
            "2026-11-10T13:03:09",
            "2026-11-10",
            "2026-11-10T24:00:00+00:00",
            "2026-11-10T13:03:60+00:00",
            "2026-02-29T00:00:00+00:00",
            "2026-11-10T13:03:09+24:00",
            "2026-11-10T13:03:09+00:00 ",
            "2026-11-10T13:03:09+00:00Z",
            "2026-11-10T13:0309+00:00",
            "2026-W45-2T00:00:00+00:00",
            "garbage",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
