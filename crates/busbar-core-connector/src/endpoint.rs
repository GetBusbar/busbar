// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENDPOINT CHECK — a pure function over an open's target, run before any dial.

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
pub fn check(target: &str) -> Result<(), EndpointRefusal> {
    let host = host_of(target)?;
    if host_is_cloud_metadata(&host) || host_is_link_local_v6(&host) {
        return Err(EndpointRefusal::MetadataHost { host });
    }
    Ok(())
}

/// Check that an open's `target` names a host, read by the one shared reader ([`target_host`]):
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
