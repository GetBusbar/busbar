// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH NEED A MEMBER DIALS (ARCHITECT ruling 2026-10-02; `BUSBAR-1.6.0.md`, the vocabulary: every
//! plugin declares its connection needs as `(transport, auth)` per direction, and the kernel
//! instantiates them through the connector). Resolved ONCE, at config load, never per request:
//! each member's outbound auth binding, the auth plugin key its route or member config names, is
//! matched against the plane instance's declared OUTBOUND needs on the `auth` element. Exactly one
//! need must match. None, or more than one, refuses the load, naming the member and the keys. Each
//! attempt then dials its member's resolved need ([`super::MemberRoute::need`]): per request, an
//! index lookup.
//!
//! The kernel names no scheme and no plane here: it compares the keys the config and the plane's
//! Statement state, byte for byte.

use std::collections::BTreeMap;

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::NeedId;

/// One member and the auth plugin key its route or member config names; empty = no auth binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberAuth<'a> {
    /// The member.
    pub member: &'a str,
    /// The auth plugin key.
    pub auth: &'a str,
}

/// Why a member's need does not resolve: the load is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedRefusal {
    /// No declared outbound need names the member's auth key.
    NoMatch {
        /// The member.
        member: String,
        /// Its auth plugin key.
        auth: String,
        /// The auth keys the plane's outbound needs declare, in declared order.
        declared: Vec<String>,
    },
    /// More than one declared outbound need names it.
    Ambiguous {
        /// The member.
        member: String,
        /// Its auth plugin key.
        auth: String,
        /// The needs that name it, in declared order.
        needs: Vec<NeedId>,
    },
}

impl std::fmt::Display for NeedRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NeedRefusal::NoMatch {
                member,
                auth,
                declared,
            } => write!(
                f,
                "member '{member}' names auth '{auth}', which no outbound need of its plane \
                 declares (declared: {})",
                declared
                    .iter()
                    .map(|a| format!("'{a}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            NeedRefusal::Ambiguous {
                member,
                auth,
                needs,
            } => write!(
                f,
                "member '{member}' names auth '{auth}', which {} outbound needs of its plane \
                 declare (needs {}); exactly one must",
                needs.len(),
                needs
                    .iter()
                    .map(|n| n.0.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl std::error::Error for NeedRefusal {}

/// THE NEED EACH MEMBER DIALS: `needs` is the plane instance's declared needs in Statement order
/// (a [`NeedId`] is a position in it); only outbound needs are matched.
///
/// # Errors
///
/// The first member whose auth key matches no outbound need, or more than one.
pub fn resolve_member_needs(
    needs: &[ReadNeed],
    members: &[MemberAuth<'_>],
) -> Result<BTreeMap<String, NeedId>, NeedRefusal> {
    let outbound: Vec<(NeedId, &str)> = needs
        .iter()
        .zip(0u32..)
        .filter(|(n, _)| n.direction == DIRECTION_OUTBOUND)
        .map(|(n, i)| (NeedId(i), n.auth.as_str()))
        .collect();
    let mut resolved = BTreeMap::new();
    for m in members {
        let matched: Vec<NeedId> = outbound
            .iter()
            .filter(|(_, auth)| *auth == m.auth)
            .map(|(id, _)| *id)
            .collect();
        match matched.as_slice() {
            [one] => {
                resolved.insert(m.member.to_string(), *one);
            }
            [] => {
                return Err(NeedRefusal::NoMatch {
                    member: m.member.to_string(),
                    auth: m.auth.to_string(),
                    declared: outbound.iter().map(|(_, a)| (*a).to_string()).collect(),
                })
            }
            _ => {
                return Err(NeedRefusal::Ambiguous {
                    member: m.member.to_string(),
                    auth: m.auth.to_string(),
                    needs: matched,
                })
            }
        }
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "tests/needs_tests.rs"]
mod tests;
