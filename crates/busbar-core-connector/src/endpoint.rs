// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENDPOINT CHECK — a pure function over an open's target, run before any dial.
//!
//! An owner-answered, accepted difference from 1.5.5: the connector refuses a cloud METADATA host
//! by name, and the whole IPv4 link-local range they live in, and (ARCHITECT, PB-100: metadata and
//! link-local are refused on every need, whatever its egress class) IPv6 link-local, fe80::/10.
//! A plugin that could reach
//! `169.254.169.254` could read the host's cloud credentials, so no need, no configuration and no
//! plugin opens one.
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

use busbar_contract::net::{host_is_cloud_metadata, target_host};

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
    let Some(host) = target_host(target) else {
        return Err(EndpointRefusal::NoHost {
            target: target.to_owned(),
        });
    };
    if host_is_cloud_metadata(&host) {
        return Err(EndpointRefusal::MetadataHost { host });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/endpoint_tests.rs"]
mod tests;
