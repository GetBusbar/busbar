// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Civil-date math for the plane crates that render an epoch timestamp without pulling a date-time
//! crate into their closure.
//!
//! Both plane crates render an instant into a customer-visible field — the MCP plane's task
//! `iso8601_ms`, the A2A push notification's `status.timestamp` — and each needs the same
//! proleptic-Gregorian day→(year, month, day) split. The split is Howard Hinnant's `civil_from_days`,
//! twelve lines that are exactly correct for every day including the leap-year and century rules a
//! hand-rolled approximation gets wrong once every four years and once every hundred. It lives here,
//! in the neutral substrate both planes already depend on, so there is ONE copy rather than one per
//! plane that can drift.

/// Days since the Unix epoch → (year, month, day). Hinnant's algorithm, shifted to an era beginning
/// on 0000-03-01 so the leap day lands at the end of the era's year and needs no special case.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Whole seconds since the Unix epoch → an RFC3339 UTC instant, `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Whole seconds because the callers that render this (the A2A push notification's `status.timestamp`)
/// have no sub-second component, and a bare-second RFC3339 instant is valid and parses back to the
/// same time.
pub fn rfc3339_from_secs(secs: u64) -> String {
    // Signed arithmetic over an unsigned clock, cast once here: `div_euclid`/`rem_euclid` make the
    // day/second split correct with no special case, and they need a signed remainder. Lossless for
    // every instant this process can observe.
    let secs = secs as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

#[cfg(test)]
#[path = "tests/civil_tests.rs"]
mod tests;
