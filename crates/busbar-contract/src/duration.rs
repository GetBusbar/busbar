// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `<n><unit>` duration parser shared by the plane config readers.
//!
//! Both plane config surfaces (MCP `verify_ttl`, A2A `reverify_ttl`/`backoff`) and core's admin/
//! key-TTL paths express durations as `7d`/`24h`/`30s`. One parser, in the neutral substrate, so a
//! plane crate names it without reaching into busbar-core; core re-exports it from `admin`.

/// Parse a duration string (`<n><unit>`, unit in s|m|h|d) to seconds. Bounded so an absurd value
/// cannot overflow the `exp` computation.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| "duration needs a unit (s|m|h|d), e.g. 7d".to_string())?,
    );
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}': expected <number><s|m|h|d>"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => return Err(format!("invalid duration unit '{other}': use s|m|h|d")),
    };
    n.checked_mul(mult)
        .filter(|v| *v <= 10 * 365 * 86_400)
        .ok_or_else(|| "duration is too large (max 10 years)".to_string())
}
