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
        Some(max) if explicit => Err(crate::cold::governance::runtime::mint_policy_ttl_refusal(
            requested_ttl_secs,
            max,
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

/// Split a mint's requested scopes into the pool grant check_mint reads and whether any scope of
/// another kind is granted. The pools are borrowed straight from `scopes` (the `kind == "pool"`
/// entries); `None` = no explicit scopes, i.e. ALL pools.
pub fn requested_grant(
    scopes: Option<&[busbar_contract::records::ScopeRef]>,
) -> (Option<RequestedPools<'_>>, bool) {
    let Some(list) = scopes else {
        return (None, false);
    };
    (
        Some(RequestedPools(list)),
        list.iter().any(|s| s.kind != "pool"),
    )
}

/// A mint's requested scopes, borrowed; [`MintPolicy::check_mint`] reads the `kind == "pool"` entries.
#[derive(Debug, Clone, Copy)]
pub struct RequestedPools<'a>(&'a [busbar_contract::records::ScopeRef]);

impl std::ops::Deref for RequestedPools<'_> {
    type Target = [busbar_contract::records::ScopeRef];

    fn deref(&self) -> &Self::Target {
        self.0
    }
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

    /// The requested scopes; only the `kind == "pool"` entries are read. `None` = ALL pools.
    pub requested_pools: Option<&'a [busbar_contract::records::ScopeRef]>,

    pub grants_other_kinds: bool,

    pub requested_ttl_secs: u64,

    pub explicit_ttl: bool,

    pub requested_mode: Option<&'a str>,
}

/// The union (first-seen order, de-duplicated) of one list across the held role ceilings, rendered
/// `a, b, c` for a refusal message. Formats straight from the policy; nothing is merged or copied.
struct HeldUnion<'p> {
    ceilings: &'p std::collections::BTreeMap<String, RoleCeiling>,
    roles: &'p [String],
    pick: fn(&RoleCeiling) -> Option<&Vec<String>>,
}

impl std::fmt::Display for HeldUnion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let HeldUnion {
            ceilings,
            roles,
            pick,
        } = *self;
        let items = || {
            roles
                .iter()
                .filter_map(|r| ceilings.get(r))
                .flat_map(move |c| pick(c).into_iter().flatten())
        };
        let mut first = true;
        for (i, item) in items().enumerate() {
            if items().take(i).any(|seen| seen == item) {
                continue;
            }
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(item)?;
        }
        Ok(())
    }
}

/// A list rendered `a, b, c` for a refusal message.
struct Listed<'p>(&'p [String]);

impl std::fmt::Display for Listed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Listed(list) = *self;
        for (i, item) in list.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(item)?;
        }
        Ok(())
    }
}

fn pick_pools(c: &RoleCeiling) -> Option<&Vec<String>> {
    c.allowed_pools.as_ref()
}

fn pick_modes(c: &RoleCeiling) -> Option<&Vec<String>> {
    c.binding_modes.as_ref()
}

impl MintPolicy {
    pub fn from_auth(auth: Option<&crate::config::AuthCfg>) -> Self {
        crate::off_path::governance::runtime::mint_policy_from_auth(auth)
    }

    /// The ceilings of the roles the caller holds, read in place (a role without a ceiling adds none).
    fn held<'p>(&'p self, roles: &'p [String]) -> impl Iterator<Item = &'p RoleCeiling> + 'p {
        roles.iter().filter_map(|r| self.ceilings.get(r))
    }

    pub fn check_mint(&self, req: &MintRequest<'_>) -> Result<u64, String> {
        // The effective role ceiling is the most permissive of the held ceilings: a dimension is
        // capped only when EVERY held ceiling caps it (one uncapped role lifts that cap), and then
        // the cap is the union / maximum across them. No held ceiling ⇒ no role cap at all.
        let any_held = self.held(req.roles).next().is_some();
        let capped = |pick: fn(&RoleCeiling) -> Option<&Vec<String>>| {
            any_held && self.held(req.roles).all(|c| pick(c).is_some())
        };
        let held_allows = |pick: fn(&RoleCeiling) -> Option<&Vec<String>>, v: &str| {
            self.held(req.roles)
                .any(|c| pick(c).is_some_and(|list| list.iter().any(|a| a == v)))
        };
        let union = |pick: fn(&RoleCeiling) -> Option<&Vec<String>>| HeldUnion {
            ceilings: &self.ceilings,
            roles: req.roles,
            pick,
        };

        let role_ttl = if !any_held || self.held(req.roles).any(|c| c.max_ttl_secs.is_none()) {
            None
        } else {
            self.held(req.roles).filter_map(|c| c.max_ttl_secs).max()
        };
        let effective_max_ttl = match (self.block_max_ttl_secs, role_ttl) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let ttl =
            apply_mint_ttl_ceiling(req.requested_ttl_secs, req.explicit_ttl, effective_max_ttl)?;

        if capped(pick_pools) {
            match req.requested_pools {
                None => {
                    return Err(
                        crate::cold::governance::runtime::mint_policy_all_pools_refusal(&union(
                            pick_pools,
                        )),
                    );
                }
                Some(requested) => {
                    if let Some(bad) = requested
                        .iter()
                        .filter(|s| s.kind == "pool")
                        .find(|s| !held_allows(pick_pools, &s.value))
                    {
                        return Err(crate::cold::governance::runtime::mint_policy_pool_refusal(
                            &bad.value,
                            &union(pick_pools),
                        ));
                    }
                }
            }

            if req.grants_other_kinds {
                return Err(
                    crate::cold::governance::runtime::mint_policy_other_kinds_refusal(&union(
                        pick_pools,
                    )),
                );
            }
        }

        if let Some(mode) = req.requested_mode {
            if let Some(block) = self.block_binding_modes.as_deref() {
                if !block.iter().any(|m| m == mode) {
                    return Err(crate::cold::governance::runtime::mint_policy_mode_refusal(
                        mode,
                        &Listed(block),
                    ));
                }
            }
            if capped(pick_modes) && !held_allows(pick_modes, mode) {
                return Err(crate::cold::governance::runtime::mint_policy_mode_refusal(
                    mode,
                    &union(pick_modes),
                ));
            }
        }

        Ok(ttl)
    }
}

#[cfg(test)]
#[path = "tests/mint_policy_tests.rs"]
mod mint_policy_tests;
