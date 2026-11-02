// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn apply_mint_ttl_ceiling(
    requested_ttl_secs: u64,
    explicit: bool,
    ceiling_secs: Option<u64>,
) -> Result<u64, String> {
    match ceiling_secs {
        None => Ok(requested_ttl_secs),
        Some(max) if requested_ttl_secs <= max => Ok(requested_ttl_secs),
        Some(max) if explicit => Err(format!(
            "requested key lifetime ({requested_ttl_secs}s) exceeds the policy ceiling \
             auth.policy.max_ttl ({max}s); request a shorter expires_in/expires_at"
        )),

        Some(max) => Ok(max),
    }
}

pub const DEFAULT_KEY_TTL_SECS: u64 = 90 * 86_400;

/// One role's RESOLVED mint ceiling (`auth.policy.mint_ceilings.<role>`), durations pre-parsed at
/// boot. All fields optional; a `None` is "no restriction from this role for that dimension".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoleCeiling {
    /// Longest TTL (secs) this role may mint. `None` = no per-role TTL cap (block cap still applies).
    pub max_ttl_secs: Option<u64>,
    /// Pools this role may mint against — 3-state (`None` = all / `Some([])` = none / `Some(list)`).
    pub allowed_pools: Option<Vec<String>>,
    /// Binding modes (wire spellings) this role may mint. `None` = no per-role mode restriction.
    pub binding_modes: Option<Vec<String>>,
}

pub fn requested_grant(
    scopes: Option<&[busbar_contract::records::ScopeRef]>,
) -> (Option<Vec<String>>, bool) {
    let Some(list) = scopes else {
        return (None, false);
    };
    let pools = list
        .iter()
        .filter(|s| s.kind == "pool")
        .map(|s| s.value.clone())
        .collect();
    (Some(pools), list.iter().any(|s| s.kind != "pool"))
}

/// The RESOLVED runtime mint policy (`auth.policy:`), built once at boot from [`AuthCfg`] and read on
/// every mint. The config half of the config-vs-store split, projected onto the App snapshot beside
/// `self_key_ttl_secs`. `Default` = the empty policy (no caps) ⇒ byte-identical pre-1.6.0 behavior.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MintPolicy {
    /// SELF-SERVE mint switch (`auth.policy.self_mint`). `None` ⇒ today's behavior (the `POST
    /// /auth/token` self-serve path is available whenever an IdP is configured); `Some(true)` makes
    /// that intent explicit; `Some(false)` DISABLES the self-serve mint path (the exchange refuses,
    /// 403). Read only by the self-serve exchange (`resolve_exchange`), never by the admin mint.
    pub self_mint: Option<bool>,
    /// Deployment-wide TTL ceiling (`auth.policy.max_ttl`). A hard cap: a per-role ceiling narrows
    /// BELOW it, never above it.
    pub block_max_ttl_secs: Option<u64>,
    /// Deployment-wide allowed binding modes (`auth.policy.binding_modes`, wire spellings). `None` =
    /// all modes allowed. Applies to every mint; a held role's list narrows it further.
    pub block_binding_modes: Option<Vec<String>>,
    /// Per-role ceilings (`auth.policy.mint_ceilings.<role>`).
    pub ceilings: std::collections::BTreeMap<String, RoleCeiling>,
}

pub struct MintRequest<'a> {
    pub roles: &'a [String],

    pub requested_pools: Option<&'a [String]>,

    pub grants_other_kinds: bool,

    pub requested_ttl_secs: u64,

    pub explicit_ttl: bool,

    pub requested_mode: Option<&'a str>,
}

impl MintPolicy {
    pub fn from_auth(auth: Option<&crate::config::AuthCfg>) -> Self {
        let Some(policy) = auth.map(|a| &a.policy) else {
            return Self::default();
        };
        let modes_to_wire = |m: &Option<Vec<crate::config::BindingMode>>| {
            m.as_ref()
                .map(|list| list.iter().map(|b| b.as_str().to_string()).collect())
        };
        MintPolicy {
            self_mint: policy.self_mint,
            block_max_ttl_secs: policy
                .max_ttl
                .as_deref()
                .and_then(|s| crate::config::parse::parse_duration_secs(s).ok()),
            block_binding_modes: modes_to_wire(&policy.binding_modes),
            ceilings: policy
                .mint_ceilings
                .iter()
                .map(|(role, c)| {
                    (
                        role.clone(),
                        RoleCeiling {
                            max_ttl_secs: c
                                .max_ttl
                                .as_deref()
                                .and_then(|s| crate::config::parse::parse_duration_secs(s).ok()),
                            allowed_pools: c.allowed_pools.clone(),
                            binding_modes: modes_to_wire(&c.binding_modes),
                        },
                    )
                })
                .collect(),
        }
    }

    fn effective_role_ceiling(&self, roles: &[String]) -> Option<RoleCeiling> {
        let held: Vec<&RoleCeiling> = roles.iter().filter_map(|r| self.ceilings.get(r)).collect();
        if held.is_empty() {
            return None;
        }

        let max_ttl_secs = if held.iter().any(|c| c.max_ttl_secs.is_none()) {
            None
        } else {
            held.iter().filter_map(|c| c.max_ttl_secs).max()
        };

        let allowed_pools = if held.iter().any(|c| c.allowed_pools.is_none()) {
            None
        } else {
            let mut set: Vec<String> = Vec::new();
            for c in &held {
                for p in c.allowed_pools.iter().flatten() {
                    if !set.contains(p) {
                        set.push(p.clone());
                    }
                }
            }
            Some(set)
        };

        let binding_modes = if held.iter().any(|c| c.binding_modes.is_none()) {
            None
        } else {
            let mut set: Vec<String> = Vec::new();
            for c in &held {
                for m in c.binding_modes.iter().flatten() {
                    if !set.contains(m) {
                        set.push(m.clone());
                    }
                }
            }
            Some(set)
        };
        Some(RoleCeiling {
            max_ttl_secs,
            allowed_pools,
            binding_modes,
        })
    }

    pub fn check_mint(&self, req: &MintRequest<'_>) -> Result<u64, String> {
        let role = self.effective_role_ceiling(req.roles);

        let role_ttl = role.as_ref().and_then(|c| c.max_ttl_secs);
        let effective_max_ttl = match (self.block_max_ttl_secs, role_ttl) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let ttl =
            apply_mint_ttl_ceiling(req.requested_ttl_secs, req.explicit_ttl, effective_max_ttl)?;

        if let Some(RoleCeiling {
            allowed_pools: Some(allowed),
            ..
        }) = role.as_ref()
        {
            match req.requested_pools {
                None => {
                    return Err(format!(
                        "the mint requests ALL pools but the caller's role ceiling \
                         (auth.policy.mint_ceilings) allows only [{}]; name an explicit subset",
                        allowed.join(", ")
                    ));
                }
                Some(requested) => {
                    if let Some(bad) = requested.iter().find(|p| !allowed.contains(p)) {
                        return Err(format!(
                            "pool '{bad}' is outside the caller's role mint ceiling \
                             (auth.policy.mint_ceilings allows [{}])",
                            allowed.join(", ")
                        ));
                    }
                }
            }

            if req.grants_other_kinds {
                return Err(format!(
                    "the mint grants scopes of a kind other than pools, but the caller's role \
                     ceiling (auth.policy.mint_ceilings) allows only the pools [{}]",
                    allowed.join(", ")
                ));
            }
        }

        let role_modes = role.as_ref().and_then(|c| c.binding_modes.as_ref());
        if let Some(mode) = req.requested_mode {
            for allowed in [self.block_binding_modes.as_ref(), role_modes]
                .into_iter()
                .flatten()
            {
                if !allowed.iter().any(|m| m == mode) {
                    return Err(format!(
                        "binding mode '{mode}' is not permitted by policy (allowed: [{}])",
                        allowed.join(", ")
                    ));
                }
            }
        }

        Ok(ttl)
    }
}

#[cfg(test)]
#[path = "tests/mint_policy_tests.rs"]
mod mint_policy_tests;
