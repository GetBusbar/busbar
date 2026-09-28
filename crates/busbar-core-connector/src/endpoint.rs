// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENDPOINT CHECK — a pure function over an open's target, run before any dial.
//!
//! An owner-answered, accepted difference from 1.5.5: the connector refuses a cloud
//! METADATA host by name. A plugin that could reach `169.254.169.254` could read the host's cloud
//! credentials, so no need, no configuration and no plugin opens one. The check reads the target
//! the way a resolver would, so a respelling of the same address is the same address: an IPv4
//! literal in dotted, decimal, octal or hex parts (`inet_aton` rules), and an IPv6 literal, IPv4-mapped
//! or not, bracketed or bare, with or without a zone. Names compare case-blind and ignore one
//! trailing dot. Nothing here resolves a name or opens a socket.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

/// The IPv4 metadata address every major cloud serves its instance metadata on.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// The IPv6 metadata address (EC2's IMDS over IPv6).
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// The metadata names, lower-case and without a trailing dot.
const METADATA_NAMES: &[&str] = &["metadata.google.internal"];

/// Why the endpoint check refused a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointRefusal {
    /// The target names a cloud metadata host, in whatever spelling.
    MetadataHost {
        /// The host part of the target, as written.
        host: String,
    },
}

impl fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataHost { host } => write!(
                f,
                "refused: `{host}` is a cloud metadata host, which no connection may reach"
            ),
        }
    }
}

impl std::error::Error for EndpointRefusal {}

/// Check an open's `target` (`host`, `host:port`, `[v6]` or `[v6]:port`) before any dial.
///
/// # Errors
///
/// [`EndpointRefusal::MetadataHost`] when the host is a cloud metadata host in any spelling.
pub fn check(target: &str) -> Result<(), EndpointRefusal> {
    let host = host_of(target);
    if is_metadata(host) {
        return Err(EndpointRefusal::MetadataHost {
            host: host.to_owned(),
        });
    }
    Ok(())
}

/// The host part of a target: brackets and a port removed, a bare IPv6 literal kept whole.
fn host_of(target: &str) -> &str {
    let t = target.trim();
    if let Some(rest) = t.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match t.rsplit_once(':') {
        // More than one colon and no brackets: a bare IPv6 literal, no port.
        Some((h, _)) if !h.contains(':') => h,
        _ => t,
    }
}

fn is_metadata(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if METADATA_NAMES.contains(&name.as_str()) {
        return true;
    }
    if let Some(v4) = ipv4_aton(&name) {
        return v4 == METADATA_V4;
    }
    let bare = name.split('%').next().unwrap_or(&name);
    if let Ok(v6) = bare.parse::<Ipv6Addr>() {
        return v6 == METADATA_V6 || v6.to_ipv4() == Some(METADATA_V4);
    }
    false
}

/// An IPv4 literal read by `inet_aton` rules: one to four parts, each decimal, octal (leading `0`)
/// or hex (`0x`), the last part filling the remaining bytes.
fn ipv4_aton(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut vals = Vec::with_capacity(parts.len());
    for p in &parts {
        vals.push(aton_part(p)?);
    }
    let (last, head) = vals.split_last()?;
    let mut addr: u32 = 0;
    for (i, v) in head.iter().enumerate() {
        if *v > 0xff {
            return None;
        }
        addr |= v << (24 - 8 * i);
    }
    let room = 32 - 8 * head.len();
    if room < 32 && *last >> room != 0 {
        return None;
    }
    Some(Ipv4Addr::from(addr | last))
}

fn aton_part(p: &str) -> Option<u32> {
    if p.is_empty() {
        return None;
    }
    let (digits, radix) = if let Some(h) = p.strip_prefix("0x") {
        (h, 16)
    } else if p.len() > 1 && p.starts_with('0') {
        (&p[1..], 8)
    } else {
        (p, 10)
    };
    if digits.is_empty() {
        return (radix == 16).then_some(0);
    }
    u32::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
#[path = "tests/endpoint_tests.rs"]
mod tests;
