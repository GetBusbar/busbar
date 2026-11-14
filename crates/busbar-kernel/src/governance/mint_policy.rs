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
        Some(max) if explicit => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: the over-ceiling refusal message is built only when the mint is refused"
            )]
            let msg = format!(
                "requested key lifetime ({requested_ttl_secs}s) exceeds the policy ceiling \
                 auth.policy.max_ttl ({max}s); request a shorter expires_in/expires_at"
            );
            Err(msg)
        }

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
        let Some(policy) = auth.map(|a| &a.policy) else {
            return Self::default();
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the mint policy is resolved once at boot from config"
        )]
        let modes_to_wire = |m: &Option<Vec<crate::config::BindingMode>>| {
            m.as_ref()
                .map(|list| list.iter().map(|b| b.as_str().to_string()).collect())
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the mint policy is resolved once at boot from config"
        )]
        let ceilings = policy
            .mint_ceilings
            .iter()
            .map(|(role, c)| {
                // busbar:expect(bp::clone_alloc, reason = "boot: the mint policy is resolved once at boot from config")
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
            .collect();
        MintPolicy {
            self_mint: policy.self_mint,
            block_max_ttl_secs: policy
                .max_ttl
                .as_deref()
                .and_then(|s| crate::config::parse::parse_duration_secs(s).ok()),
            block_binding_modes: modes_to_wire(&policy.binding_modes),
            ceilings,
        }
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
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "error: the refusal message is built only when the mint is refused"
                    )]
                    let msg = format!(
                        "the mint requests ALL pools but the caller's role ceiling \
                         (auth.policy.mint_ceilings) allows only [{}]; name an explicit subset",
                        union(pick_pools)
                    );
                    return Err(msg);
                }
                Some(requested) => {
                    if let Some(bad) = requested
                        .iter()
                        .filter(|s| s.kind == "pool")
                        .find(|s| !held_allows(pick_pools, &s.value))
                    {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = "error: the refusal message is built only when the mint is refused"
                        )]
                        let msg = format!(
                            "pool '{}' is outside the caller's role mint ceiling \
                             (auth.policy.mint_ceilings allows [{}])",
                            bad.value,
                            union(pick_pools)
                        );
                        return Err(msg);
                    }
                }
            }

            if req.grants_other_kinds {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "error: the refusal message is built only when the mint is refused"
                )]
                let msg = format!(
                    "the mint grants scopes of a kind other than pools, but the caller's role \
                     ceiling (auth.policy.mint_ceilings) allows only the pools [{}]",
                    union(pick_pools)
                );
                return Err(msg);
            }
        }

        if let Some(mode) = req.requested_mode {
            if let Some(block) = self.block_binding_modes.as_deref() {
                if !block.iter().any(|m| m == mode) {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "error: the refusal message is built only when the mint is refused"
                    )]
                    let msg = format!(
                        "binding mode '{mode}' is not permitted by policy (allowed: [{}])",
                        Listed(block)
                    );
                    return Err(msg);
                }
            }
            if capped(pick_modes) && !held_allows(pick_modes, mode) {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "error: the refusal message is built only when the mint is refused"
                )]
                let msg = format!(
                    "binding mode '{mode}' is not permitted by policy (allowed: [{}])",
                    union(pick_modes)
                );
                return Err(msg);
            }
        }

        Ok(ttl)
    }
}

#[cfg(test)]
#[path = "tests/mint_policy_tests.rs"]
mod mint_policy_tests;
