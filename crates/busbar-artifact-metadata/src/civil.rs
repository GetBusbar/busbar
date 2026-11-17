// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The last second RFC 3339 can spell, 9999-12-31T23:59:59Z.
const LAST_RFC3339_SECOND: i64 = 253_402_300_799;

/// Whole seconds since the Unix epoch → an RFC3339 UTC instant, `YYYY-MM-DDTHH:MM:SSZ`, saturating
/// at 9999-12-31T23:59:59Z.
#[must_use]
pub fn rfc3339_from_secs(secs: u64) -> String {
    let secs = i64::try_from(secs).map_or(LAST_RFC3339_SECOND, |s| s.min(LAST_RFC3339_SECOND));
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(time::Error::from)
        .and_then(|at| at.format(&Rfc3339).map_err(time::Error::from))
        .expect("a whole UTC second in 1970..=9999 always has an RFC 3339 spelling")
}
