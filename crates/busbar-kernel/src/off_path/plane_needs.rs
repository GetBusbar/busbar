// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::needs`'s off-path code: a plane's members' auth bindings resolved against its
//! declared outbound needs, once per configuration load (a refusal refuses the load).

use std::collections::BTreeMap;

use busbar_contract::conn::codes::DIRECTION_OUTBOUND;
use busbar_contract::conn::NeedId;
use busbar_contract::rendering::ReadNeed;

use crate::plane_driver::needs::{MemberAuth, NeedRefusal};

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
            return Err(NeedRefusal::NoMatch {
                member: m.member.to_string(),
                auth: m.auth.to_string(),
                declared: outbound().map(|(_, a, _)| a.to_string()).collect(),
            });
        }
        for (_, transport) in matched() {
            let over = || matched().filter(move |(_, t)| *t == transport);
            if over().nth(1).is_some() {
                return Err(NeedRefusal::Ambiguous {
                    member: m.member.to_string(),
                    auth: m.auth.to_string(),
                    needs: over().map(|(id, _)| id).collect(),
                });
            }
        }
        resolved.insert(m.member.to_string(), matched().map(|(id, _)| id).collect());
    }
    Ok(resolved)
}
