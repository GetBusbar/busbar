// SPDX-License-Identifier: Apache-2.0
//! Host-only direct-Need endpoint vocabulary. CHECK facts are configuration-parser output;
//! the kernel owns freezing and admission. These types are never plugin ABI records.

use busbar_plugin_abi::need::{egress, need_flag, op};
use busbar_plugin_abi::plugin::{ENDPOINTS_MAX, ENDPOINT_DEST_MAX};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Host-owned generation lifetime; no process-wide retired-generation set.
#[derive(Clone, Debug)]
pub struct NetworkLease {
    instance: u64,
    live: Arc<AtomicBool>,
}
impl NetworkLease {
    pub fn new(instance: u64) -> Self {
        Self {
            instance,
            live: Arc::new(AtomicBool::new(true)),
        }
    }
    pub fn live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
    pub fn retire(&self) {
        self.live.store(false, Ordering::Release);
    }
}
impl PartialEq for NetworkLease {
    fn eq(&self, other: &Self) -> bool {
        self.instance == other.instance
    }
}
impl Eq for NetworkLease {}
impl std::hash::Hash for NetworkLease {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.instance, state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkEndpoint {
    pub op: u32,
    pub flags: u32,
    pub dest: Box<str>,
}

impl NetworkEndpoint {
    /// Canonical, bounded CHECK rows. Conflicting constraints at one operation/origin refuse.
    pub fn canonical_set(endpoints: &[Self]) -> Option<Box<[Self]>> {
        if endpoints.len() > ENDPOINTS_MAX {
            return None;
        }
        let mut frozen: Vec<Self> = Vec::new();
        for endpoint in endpoints {
            let canonical = Self::new(endpoint.op, endpoint.flags, &endpoint.dest)?;
            if let Some(existing) = frozen
                .iter()
                .find(|e| e.op == canonical.op && e.dest == canonical.dest)
            {
                if existing.flags != canonical.flags {
                    return None;
                }
            } else {
                frozen.push(canonical);
            }
        }
        Some(frozen.into_boxed_slice())
    }

    /// Decode a bounded CHECK endpoint into the same operation-specific authority used at dial.
    pub fn new(op: u32, flags: u32, dest: &str) -> Option<Self> {
        if dest.len() > ENDPOINT_DEST_MAX {
            return None;
        }
        Self::from_intent(op, flags, dest)
    }

    /// A live URL's path/query are not authority and retain the existing Need input bounds.
    pub fn from_intent(op: u32, flags: u32, dest: &str) -> Option<Self> {
        let known = need_flag::TLS_MASK | (0xf << 16);
        let tls = flags & need_flag::TLS_MASK;
        if flags & !known != 0 || flags >> 16 > egress::LOOPBACK_ALLOWED {
            return None;
        }
        let dest = if op == op::OPEN {
            if let Some(path) = dest.strip_prefix("unix:") {
                if tls != need_flag::TLS_NONE
                    || !path.starts_with('/')
                    || path.len() <= 1
                    || path.len() > 107
                    || path.contains('\0')
                    || path.contains("/../")
                    || path.ends_with("/..")
                    || path.contains("/./")
                    || path.ends_with("/.")
                    || path.contains("//")
                {
                    return None;
                }
                dest.into()
            } else {
                busbar_contract::net::canonical_network_authority(dest, None)?
            }
        } else if op == op::FETCH {
            if dest.contains('#')
                || dest.contains('\\')
                || dest
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            {
                return None;
            }
            let (scheme, rest) = dest.split_once("://")?;
            let (scheme, port) = if scheme.eq_ignore_ascii_case("https")
                && matches!(tls, need_flag::TLS_REQUIRED | need_flag::TLS_MUTUAL)
            {
                ("https", 443)
            } else if scheme.eq_ignore_ascii_case("http") && tls == need_flag::TLS_NONE {
                ("http", 80)
            } else {
                return None;
            };
            let authority = rest.split(['/', '?']).next()?;
            let authority =
                busbar_contract::net::canonical_network_authority(authority, Some(port))?;
            format!("{scheme}://{authority}").into_boxed_str()
        } else {
            return None;
        };
        Some(Self { op, flags, dest })
    }
}

/// One kernel-checked operation, retaining exact authority through all awaited network stages.
/// `registration` is the one-based frozen endpoint ordinal, zero for restrictive ordinary use.
#[derive(Clone, Debug)]
pub struct NetworkPermit {
    pub lease: NetworkLease,
    pub instance: u64,
    pub registration: u32,
    pub endpoint: NetworkEndpoint,
}
impl NetworkPermit {
    pub fn class(&self) -> u32 {
        self.endpoint.flags >> 16
    }
    pub fn private_reach(&self) -> bool {
        self.class() == egress::OPERATOR_INFRASTRUCTURE && self.registration != 0
    }
}
