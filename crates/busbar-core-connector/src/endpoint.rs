// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENDPOINT CHECK — a pure function over an open's target, run before any dial.
//!
//! Two checks. [`named`]: a target names a host at all; every dial asks it. [`check`]: that host is
//! no cloud METADATA host, by name or in the whole IPv4 link-local range they live in, and no IPv6
//! link-local address (fe80::/10). A dial the destination judge judges ([`crate::DialJudge`]: every
//! open, declare-time admission and pinned need) asks [`named`] alone and leaves metadata and
//! link-local to the ONE guard ([`crate::guard`], THE DESIGN §5 "Destination guard — ONE check for
//! every outbound connection"), which refuses them in every class and is where the 1.5.5 provider
//! carve-outs (`allow_metadata_hosts`, `security.allow_metadata_hosts`,
//! `security.allow_all_metadata`) and an IP or CIDR allowlist entry naming the address admit them;
//! a second, stricter refusal ahead of it would make those unreachable. Only a dial no judge
//! judges ([`crate::compose::Connection::dial`], an IP literal dialled as written) asks [`check`].
//!
//! The target is read by the contract's one URL and host reader (`busbar_contract::net`) and judged
//! against its one metadata list, the list the destination guard reads too — this file kept a
//! shorter private copy that missed Azure's `168.63.129.16` and the `metadata.internal` names, and
//! read a URL-shaped target's SCHEME as its host. The reader reads the target the way a resolver
//! would, so a respelling of the same address is the same address: an IPv4 literal in dotted,
//! decimal, octal or hex parts (`inet_aton` rules), and an IPv6 literal, IPv4-mapped or not,
//! bracketed or bare, with or without a zone. Names compare case-blind and ignore one trailing dot.
//! Nothing here resolves a name or opens a socket.

use core::fmt;

use busbar_contract::net::{host_is_cloud_metadata, host_is_link_local_v6, target_host};

/// Why the endpoint check refused a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointRefusal {
    /// The target names a cloud metadata host, in whatever spelling.
    MetadataHost {
        /// The host part of the target, as the shared reader reads it.
        host: String,
    },
    /// No host can be read out of the target at all, so there is nothing to have judged.
    NoHost {
        /// The target, as written.
        target: String,
    },
}

impl fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataHost { host } => write!(
                f,
                "refused: `{host}` is a cloud metadata host, which no connection may reach"
            ),
            Self::NoHost { target } => write!(
                f,
                "refused: `{target}` names no host, so there is nothing to have checked"
            ),
        }
    }
}

impl std::error::Error for EndpointRefusal {}

/// Check an open's `target` before any dial: `host`, `host:port`, `[v6]`, `[v6]:port`, or a URL.
///
/// The host is read by the one shared reader ([`target_host`]), so a URL's scheme is never read as
/// its host (`https://169.254.169.254/` names `169.254.169.254`, not `https`), and it is judged
/// against the one metadata list ([`host_is_cloud_metadata`]: the metadata names, link-local, and
/// the Alibaba, Azure, OCI and EC2 IPv6 addresses, in every literal spelling).
///
/// # Errors
///
/// [`EndpointRefusal::MetadataHost`] when the host is a cloud metadata host in any spelling;
/// [`EndpointRefusal::NoHost`] when no host can be read.
pub fn check(target: &str) -> Result<(), EndpointRefusal> {
    let host = host_of(target)?;
    if host_is_cloud_metadata(&host) || host_is_link_local_v6(&host) {
        return Err(EndpointRefusal::MetadataHost { host });
    }
    Ok(())
}

/// Check that an open's `target` names a host, read by the one shared reader ([`target_host`]):
/// the endpoint check a judged dial asks, its metadata and link-local refusal the guard's.
///
/// # Errors
///
/// [`EndpointRefusal::NoHost`] when no host can be read.
pub fn named(target: &str) -> Result<(), EndpointRefusal> {
    host_of(target).map(drop)
}

/// The host `target` names, or the refusal naming the target.
fn host_of(target: &str) -> Result<String, EndpointRefusal> {
    target_host(target).ok_or_else(|| EndpointRefusal::NoHost {
        target: target.to_owned(),
    })
}

#[cfg(test)]
#[path = "tests/endpoint_tests.rs"]
mod tests;
