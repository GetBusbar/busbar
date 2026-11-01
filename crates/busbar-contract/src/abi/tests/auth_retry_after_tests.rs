// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An IdP's `Retry-After` on a LOGIN_OUTAGE (owner-signed 2026-10-30, OWNER-QUEUE.md item "IdP
//! errors"): the plugin's parse of the header (delta-seconds, or an HTTP-date as seconds from now,
//! RFC 9110 §10.2.3) and the reply-extensions entry it rides to the host, whole seconds as ASCII
//! decimal. Junk reads as no delay at all, never as a guess.

use super::{retry_after_extensions, retry_after_of, retry_after_secs, EXT_RETRY_AFTER};
use crate::abi::mechanism::extensions;

/// `Sun, 06 Nov 1994 08:49:37 GMT`, RFC 9110's example instant, as Unix seconds.
const NOW: u64 = 784_111_777;

#[test]
fn the_key_is_retry_after() {
    assert_eq!(EXT_RETRY_AFTER, "retry_after");
}

/// delta-seconds read as written, around optional whitespace; a value past `u64` is a very long
/// time (the host clamps it), not junk.
#[test]
fn delta_seconds_read_as_written() {
    for (v, n) in [
        (&b"120"[..], 120),
        (b"0", 0),
        (b"007", 7),
        (b" 7\t", 7),
        (b"18446744073709551615", u64::MAX),
        (b"99999999999999999999999", u64::MAX),
    ] {
        assert_eq!(
            retry_after_secs(v, NOW),
            Some(n),
            "{:?}",
            String::from_utf8_lossy(v)
        );
    }
}

/// An HTTP-date, in each of the three forms RFC 9110 §5.6.7 has a recipient accept, is the seconds
/// from `now` to it; a date already past asks for no wait.
#[test]
fn an_http_date_is_seconds_from_now() {
    for v in [
        "Sun, 06 Nov 1994 08:51:37 GMT",
        "Sunday, 06-Nov-94 08:51:37 GMT",
        "Sun Nov  6 08:51:37 1994",
        " Sun, 06 Nov 1994 08:51:37 GMT ",
    ] {
        assert_eq!(retry_after_secs(v.as_bytes(), NOW), Some(120), "{v}");
    }
    assert_eq!(
        retry_after_secs(b"Sun, 06 Nov 1994 08:49:00 GMT", NOW),
        Some(0)
    );
    assert_eq!(
        retry_after_secs(b"Thu, 01 Jan 1970 00:00:00 GMT", NOW),
        Some(0)
    );
    // A leap day, a year boundary, and a far date.
    assert_eq!(
        retry_after_secs(b"Thu, 29 Feb 2024 00:00:00 GMT", 1_709_164_800 - 60),
        Some(60)
    );
    assert_eq!(
        retry_after_secs(b"Wed, 01 Jan 2025 00:00:00 GMT", 1_735_689_600 - 3600),
        Some(3600)
    );
    assert_eq!(
        retry_after_secs(b"Fri, 31 Dec 9999 23:59:59 GMT", 0),
        Some(253_402_300_799)
    );
}

/// Anything that is neither delta-seconds nor an HTTP-date is no delay at all.
#[test]
fn junk_is_none() {
    for v in [
        &b""[..],
        b"   ",
        b"-1",
        b"+5",
        b"1.5",
        b"12s",
        b"1 2",
        b"soon",
        b"\xff120",
        b"Sun, 06 Nov 1994 08:49:37 UTC",
        b"Sun, 06 Nov 1994 08:49:37",
        b"Sun, 32 Nov 1994 08:49:37 GMT",
        b"Sun, 31 Nov 1994 08:49:37 GMT",
        b"Sun, 29 Feb 1995 08:49:37 GMT",
        b"Sun, 00 Nov 1994 08:49:37 GMT",
        b"Sun, 06 Foo 1994 08:49:37 GMT",
        b"Sun, 06 nov 1994 08:49:37 GMT",
        b"Sun, 06 Nov 1994 24:00:00 GMT",
        b"Sun, 06 Nov 1994 08:60:00 GMT",
        b"Sun, 06 Nov 1994 08:49 GMT",
        b"Sun, 06 Nov 94 08:49:37 GMT",
        b"Funday, 06 Nov 1994 08:49:37 GMT",
        b"06 Nov 1994 08:49:37 GMT",
        b"Sun, 06 Nov 1994 08:49:37 GMT trailing",
        b"Sunday, 06-Nov-1994 08:49:37 GMT",
        b"Sun Nov 6 08:49:37",
    ] {
        assert_eq!(
            retry_after_secs(v, NOW),
            None,
            "{:?}",
            String::from_utf8_lossy(v)
        );
    }
}

/// The reply-extensions entry: whole seconds as ASCII decimal under `retry_after`, read back
/// strictly. Another key beside it is passed over; anything but plain digits that fit `u64` reads
/// as absent.
#[test]
fn the_extension_carries_whole_seconds_as_ascii_decimal() {
    let blob = retry_after_extensions(120);
    assert_eq!(blob, extensions::encode(&[("retry_after", b"120")]));
    assert_eq!(retry_after_of(&blob), Some(120));
    assert_eq!(
        retry_after_of(&retry_after_extensions(u64::MAX)),
        Some(u64::MAX)
    );
    assert_eq!(retry_after_of(&[]), None);
    let both = extensions::encode(&[("scope", b"x"), ("retry_after", b"30")]);
    assert_eq!(retry_after_of(&both), Some(30));
    for junk in [
        &b""[..],
        b"-1",
        b" 120",
        b"12a",
        b"1.5",
        b"99999999999999999999999",
        b"\xff",
    ] {
        assert_eq!(
            retry_after_of(&extensions::encode(&[("retry_after", junk)])),
            None,
            "{:?}",
            String::from_utf8_lossy(junk)
        );
    }
}
