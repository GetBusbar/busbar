// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub use crate::off_path::plane_needs::resolve_member_needs;

#[cfg(test)]
#[path = "tests/needs_tests.rs"]
mod tests;
