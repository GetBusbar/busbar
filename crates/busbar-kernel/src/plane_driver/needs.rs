// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
            } => {
                write!(
                    f,
                    "member '{member}' names auth '{auth}', which no outbound need of its plane \
                     declares (declared: "
                )?;
                for (i, a) in declared.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "'{a}'")?;
                }
                f.write_str(")")
            }
            NeedRefusal::Ambiguous {
                member,
                auth,
                needs,
            } => {
                write!(
                    f,
                    "member '{member}' names auth '{auth}', which {} outbound needs of its plane \
                     declare over one transport (needs ",
                    needs.len(),
                )?;
                for (i, n) in needs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", n.0)?;
                }
                f.write_str("); one binding per (transport, auth)")
            }
        }
    }
}

impl std::error::Error for NeedRefusal {}

pub fn resolve_member_needs(
    needs: &[ReadNeed],
    members: &[MemberAuth<'_>],
) -> Result<BTreeMap<String, Vec<NeedId>>, NeedRefusal> {
    let outbound = || {
        needs
            .iter()
            .zip(0u32..)
            .filter(|(n, _)| n.direction == DIRECTION_OUTBOUND)
            .map(|(n, i)| (NeedId(i), n.auth.as_str(), n.transport.as_str()))
    };
    let mut resolved = BTreeMap::new();
    for m in members {
        let matched = || {
            outbound()
                .filter(|(_, auth, _)| *auth == m.auth)
                .map(|(id, _, transport)| (id, transport))
        };
        if matched().next().is_none() {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a member whose auth no need declares refuses the load, once"
            )]
            return Err(NeedRefusal::NoMatch {
                member: m.member.to_string(),
                auth: m.auth.to_string(),
                declared: outbound().map(|(_, a, _)| a.to_string()).collect(),
            });
        }
        for (_, transport) in matched() {
            let over = || matched().filter(move |(_, t)| *t == transport);
            if over().nth(1).is_some() {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "error: a member whose auth two needs declare over one transport refuses the load, once"
                )]
                return Err(NeedRefusal::Ambiguous {
                    member: m.member.to_string(),
                    auth: m.auth.to_string(),
                    needs: over().map(|(id, _)| id).collect(),
                });
            }
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: each member's resolved needs are kept for the load"
        )]
        resolved.insert(m.member.to_string(), matched().map(|(id, _)| id).collect());
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "tests/needs_tests.rs"]
mod tests;
