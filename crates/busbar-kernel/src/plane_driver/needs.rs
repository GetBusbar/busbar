// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH NEEDS A MEMBER DIALS (ARCHITECT ruling 2026-10-02, amended by Q-L5B-NEEDS 2026-10-03;
//! `BUSBAR-1.6.0.md` spec #3: every plugin declares its connection needs as a LIST of
//! `(transport, auth)` per direction, and the kernel instantiates them through the connector).
//! Resolved ONCE, at config load, never per request: each member's outbound auth binding, the auth
//! plugin key its route or member config names, is matched against the plane instance's declared
//! OUTBOUND needs on the `auth` element, and EVERY need it matches is bound for the member, one
//! binding per (transport, auth). None refuses the load; two matching needs over one transport are
//! one binding twice and refuse it too, naming the member and the needs. A far request names the
//! need it rides (`OnPieceOut::need`); one that names none rides the member's first bound need
//! ([`super::MemberRoute::need`]): per request, an index lookup.
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
    /// More than one declared outbound need over one transport names it.
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
                 declare over one transport (needs {}); one binding per (transport, auth)",
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

/// THE NEEDS EACH MEMBER DIALS: `needs` is the plane instance's declared needs in Statement order
/// (a [`NeedId`] is a position in it); only outbound needs are matched. Each member's bound needs,
/// in declared order: every outbound need its auth key names, at most one per transport.
///
/// # Errors
///
/// The first member whose auth key matches no outbound need, or two over one transport.
pub fn resolve_member_needs(
    needs: &[ReadNeed],
    members: &[MemberAuth<'_>],
) -> Result<BTreeMap<String, Vec<NeedId>>, NeedRefusal> {
    let outbound: Vec<(NeedId, &str, &str)> = needs
        .iter()
        .zip(0u32..)
        .filter(|(n, _)| n.direction == DIRECTION_OUTBOUND)
        .map(|(n, i)| (NeedId(i), n.auth.as_str(), n.transport.as_str()))
        .collect();
    let mut resolved = BTreeMap::new();
    for m in members {
        let matched: Vec<(NeedId, &str)> = outbound
            .iter()
            .filter(|(_, auth, _)| *auth == m.auth)
            .map(|(id, _, transport)| (*id, *transport))
            .collect();
        if matched.is_empty() {
            return Err(NeedRefusal::NoMatch {
                member: m.member.to_string(),
                auth: m.auth.to_string(),
                declared: outbound.iter().map(|(_, a, _)| (*a).to_string()).collect(),
            });
        }
        for (_, transport) in &matched {
            let twice: Vec<NeedId> = matched
                .iter()
                .filter(|(_, t)| t == transport)
                .map(|(id, _)| *id)
                .collect();
            if twice.len() > 1 {
                return Err(NeedRefusal::Ambiguous {
                    member: m.member.to_string(),
                    auth: m.auth.to_string(),
                    needs: twice,
                });
            }
        }
        resolved.insert(
            m.member.to_string(),
            matched.into_iter().map(|(id, _)| id).collect(),
        );
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "tests/needs_tests.rs"]
mod tests;
