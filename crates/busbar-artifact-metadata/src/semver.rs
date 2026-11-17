// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE VERSION COMPARATOR for plugin anti-downgrade floors (DES-359 r3, #359 SEC-L11): SemVer 2.0
//! precedence (section 11) over the version grammar [`crate::plugin::valid_semver`] reads.
//!
//! - The core is `MAJOR.MINOR.PATCH` of decimal digits. Leading zeros are admitted for compatibility
//!   (not strict SemVer) and compare numerically, without narrowing: length, then bytes.
//! - A pre-release (after the first `-`) sorts below its release. Its `.`-separated identifiers compare
//!   left to right: all-digit identifiers numerically without leading zeros or narrowing, others by
//!   ASCII bytes, numeric below alphanumeric; a shorter list of equal prefix is lower.
//! - Build metadata (after the first `+`) never counts.
//!
//! Stored floors and high-water marks are read under this same grammar, so a value admitted before is
//! never dropped. [`valid_authored`] is the stricter rule for newly authored floors and pins.

use core::cmp::Ordering;

/// `have` ≥ `floor`. An empty floor is no floor. A side whose core does not read never clears it.
#[must_use]
pub fn version_at_least(have: &str, floor: &str) -> bool {
    if floor.is_empty() {
        return true;
    }
    match (parse(have), parse(floor)) {
        (Some(have), Some(floor)) => compare(&have, &floor) != Ordering::Less,
        _ => false,
    }
}

/// A newly authored floor or pin: a readable version whose pre-release and build identifiers are all
/// non-empty and of `[0-9A-Za-z-]`.
#[must_use]
pub fn valid_authored(v: &str) -> bool {
    let (rest, build) = match v.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (v, None),
    };
    let pre = rest.split_once('-').map(|(_, pre)| pre);
    let identifiers_ok = |text: &str| {
        text.split('.')
            .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    };
    parse(v).is_some() && pre.is_none_or(identifiers_ok) && build.is_none_or(identifiers_ok)
}

struct Version<'a> {
    core: [&'a str; 3],
    pre: Option<&'a str>,
}

fn parse(v: &str) -> Option<Version<'_>> {
    let without_build = v.split_once('+').map_or(v, |(rest, _)| rest);
    let (core, pre) = match without_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (without_build, None),
    };
    let mut parts = core.split('.');
    let mut part = || {
        parts
            .next()
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    let parsed = [part()?, part()?, part()?];
    if parts.next().is_some() {
        return None;
    }
    Some(Version { core: parsed, pre })
}

fn numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn is_numeric(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}

fn compare(a: &Version<'_>, b: &Version<'_>) -> Ordering {
    for (x, y) in a.core.iter().zip(b.core.iter()) {
        let order = numeric(x, y);
        if order != Ordering::Equal {
            return order;
        }
    }
    match (a.pre, b.pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let mut xs = x.split('.');
            let mut ys = y.split('.');
            loop {
                match (xs.next(), ys.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(x), Some(y)) => {
                        let order = match (is_numeric(x), is_numeric(y)) {
                            (true, true) => numeric(x, y),
                            (true, false) => Ordering::Less,
                            (false, true) => Ordering::Greater,
                            (false, false) => x.cmp(y),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/semver_tests.rs"]
mod tests;
