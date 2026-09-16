// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RESOLVED runtime mint policy (`auth.policy:`) — CORE governance/config infrastructure.
//!
//! RELOCATED out of `admin` (1.6.0 de-alias, stage 2a): this is read on the hot mint path
//! (`state.rs`'s `App::mint_policy`, `auth/exchange.rs`, `auth/token.rs`'s `mint_policy.self_mint`)
//! and built once at boot (`appbuild.rs`'s `MintPolicy::from_auth`) — none of that is admin-API
//! surface, so the type does not belong under the `admin::` namespace. Byte-identical move: every
//! value, decision and error message this module produces is unchanged: only the module path moved.
//! The admin mint handler (`admin/mod.rs`, staying put — it is the admin HTTP API's own `POST /keys`
//! handler) is the one remaining caller that still constructs a mint request against this policy;
//! it now names this neutral path instead of defining the type itself.

/// Apply the deployment-wide mint TTL ceiling (`auth.policy.max_ttl`, 1.6.0) to a resolved mint
/// lifetime. CORE-SIDE enforcement — never the UI's job (auth design review M2) — of the block-level
/// cap that bounds how long any minted token may live.
///
/// - `ceiling` is `None` ⇒ no policy cap: the requested TTL passes through unchanged (byte-identical
///   pre-1.6.0 behavior for a deployment that set no `auth.policy.max_ttl`).
/// - an EXPLICIT request (`expires_in`/`expires_at`, `explicit = true`) that exceeds the ceiling is
///   REFUSED: the operator asked, in writing, for longer than policy allows, so a loud 4xx beats
///   silently shortening what they typed.
/// - the no-expiry DEFAULT (`explicit = false`) is CLAMPED down to the ceiling: a 90-day default that
///   predates a shorter policy must not silently outlive the cap, and a default was never an explicit
///   ask to refuse.
///
/// Returns the (possibly clamped) TTL in seconds, or an error message naming the ceiling for the 4xx.
/// The per-role `mint_ceilings` narrowing composes ABOVE this by lowering `ceiling` before the call.
pub(crate) fn apply_mint_ttl_ceiling(
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
        // Default (non-explicit) over the ceiling: clamp down to the cap.
        Some(max) => Ok(max),
    }
}

/// The default signed-token lifetime when the mint body specifies neither `expires_in` nor
/// `expires_at`: 90 days. Long enough that routine use does not churn, short enough that a leaked
/// token is not valid forever (the 1.x posture: keys never expired).
pub(crate) const DEFAULT_KEY_TTL_SECS: u64 = 90 * 86_400;

/// One role's RESOLVED mint ceiling (`auth.policy.mint_ceilings.<role>`), durations pre-parsed at
/// boot. All fields optional; a `None` is "no restriction from this role for that dimension".
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RoleCeiling {
    /// Longest TTL (secs) this role may mint. `None` = no per-role TTL cap (block cap still applies).
    pub(crate) max_ttl_secs: Option<u64>,
    /// Pools this role may mint against — 3-state (`None` = all / `Some([])` = none / `Some(list)`).
    pub(crate) allowed_pools: Option<Vec<String>>,
    /// Binding modes (wire spellings) this role may mint. `None` = no per-role mode restriction.
    pub(crate) binding_modes: Option<Vec<String>>,
}

/// The RESOLVED runtime mint policy (`auth.policy:`), built once at boot from [`AuthCfg`] and read on
/// every mint. The config half of the config-vs-store split, projected onto the App snapshot beside
/// `self_key_ttl_secs`. `Default` = the empty policy (no caps) ⇒ byte-identical pre-1.6.0 behavior.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct MintPolicy {
    /// SELF-SERVE mint switch (`auth.policy.self_mint`). `None` ⇒ today's behavior (the `POST
    /// /auth/token` self-serve path is available whenever an IdP is configured); `Some(true)` makes
    /// that intent explicit; `Some(false)` DISABLES the self-serve mint path (the exchange refuses,
    /// 403). Read only by the self-serve exchange (`resolve_exchange`), never by the admin mint.
    pub(crate) self_mint: Option<bool>,
    /// Deployment-wide TTL ceiling (`auth.policy.max_ttl`). A hard cap: a per-role ceiling narrows
    /// BELOW it, never above it.
    pub(crate) block_max_ttl_secs: Option<u64>,
    /// Deployment-wide allowed binding modes (`auth.policy.binding_modes`, wire spellings). `None` =
    /// all modes allowed. Applies when the caller holds no role that restricts modes further.
    pub(crate) block_binding_modes: Option<Vec<String>>,
    /// Per-role ceilings (`auth.policy.mint_ceilings.<role>`).
    pub(crate) ceilings: std::collections::BTreeMap<String, RoleCeiling>,
}

/// A mint's ceiling-relevant shape, checked by [`MintPolicy::check_mint`].
pub(crate) struct MintRequest<'a> {
    /// The caller's asserted roles (`Principal::roles`) — the delegated-admin identity the per-role
    /// ceiling keys off.
    pub(crate) roles: &'a [String],
    /// The pools this mint requests — 3-state, as given (`None` = all).
    pub(crate) requested_pools: Option<&'a [String]>,
    /// The resolved token lifetime in seconds.
    pub(crate) requested_ttl_secs: u64,
    /// Whether the operator NAMED the lifetime (`expires_in`/`expires_at`) — an explicit over-ask is
    /// refused, a default is clamped (see [`apply_mint_ttl_ceiling`]).
    pub(crate) explicit_ttl: bool,
    /// The binding mode this mint requests (wire spelling), if any. `None` = no mode named (the admin
    /// mint path today), so the mode ceiling is not exercised.
    pub(crate) requested_mode: Option<&'a str>,
}

impl MintPolicy {
    /// Build the resolved policy from config. Durations were already proven to parse by
    /// `config_validate`; a stray unparseable value falls back to `None` (no cap) rather than
    /// fabricating a ceiling.
    pub(crate) fn from_auth(auth: Option<&crate::config::AuthCfg>) -> Self {
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

    /// The per-role ceiling composed across the caller's held roles: the MOST PERMISSIVE across the
    /// roles that carry a ceiling (holding a role grants up to its own ceiling; a caller holding two
    /// ceiling'd roles gets the union). `None` in a returned dimension = "no per-role restriction"
    /// (either no held role carries a ceiling, or a held role explicitly allows all). Returns `None`
    /// entirely when no held role has a `mint_ceilings` entry — the caller falls back to block caps.
    fn effective_role_ceiling(&self, roles: &[String]) -> Option<RoleCeiling> {
        let held: Vec<&RoleCeiling> = roles.iter().filter_map(|r| self.ceilings.get(r)).collect();
        if held.is_empty() {
            return None;
        }
        // TTL: max across roles; a role with no cap (`None`) makes the union unbounded.
        let max_ttl_secs = if held.iter().any(|c| c.max_ttl_secs.is_none()) {
            None
        } else {
            held.iter().filter_map(|c| c.max_ttl_secs).max()
        };
        // Pools: union; a role allowing ALL (`None`) makes the union all (no restriction).
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
        // Modes: union; a role with no mode restriction (`None`) makes the union unrestricted.
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

    /// Enforce the mint ceiling CORE-SIDE (auth design review M2/M4: the delegated-admin cap must
    /// live in core, never the UI). Returns the (possibly clamped) TTL in seconds, or an error
    /// message for the 4xx. Composition: the per-role ceiling narrows BELOW the block cap, never
    /// above it. A caller whose roles carry no ceiling is bound by the block caps alone.
    ///
    /// - TTL: effective max = min(block, role); an explicit over-ask is refused, a default is clamped.
    /// - Pools: if the effective allowed set is a finite list, the request must be a subset —
    ///   requesting ALL pools (`None`) under a finite ceiling is refused, an explicit subset is
    ///   allowed, and the empty set is always allowed.
    /// - Mode: if a mode is requested and the effective allowed set is a finite list, it must be a
    ///   member.
    pub(crate) fn check_mint(&self, req: &MintRequest<'_>) -> Result<u64, String> {
        let role = self.effective_role_ceiling(req.roles);

        // TTL ceiling: the tighter of block and (if present) the role cap.
        let role_ttl = role.as_ref().and_then(|c| c.max_ttl_secs);
        let effective_max_ttl = match (self.block_max_ttl_secs, role_ttl) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let ttl =
            apply_mint_ttl_ceiling(req.requested_ttl_secs, req.explicit_ttl, effective_max_ttl)?;

        // Pool ceiling: role-only (the block level carries no pool restriction).
        if let Some(RoleCeiling {
            allowed_pools: Some(allowed),
            ..
        }) = role.as_ref()
        {
            match req.requested_pools {
                // Requesting ALL pools under a finite ceiling is an over-ask.
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
        }

        // Mode ceiling: role restriction if present, else the block-level allowed set.
        let allowed_modes = role
            .as_ref()
            .and_then(|c| c.binding_modes.as_ref())
            .or(self.block_binding_modes.as_ref());
        if let (Some(mode), Some(allowed)) = (req.requested_mode, allowed_modes) {
            if !allowed.iter().any(|m| m == mode) {
                return Err(format!(
                    "binding mode '{mode}' is not permitted by policy (allowed: [{}])",
                    allowed.join(", ")
                ));
            }
        }

        Ok(ttl)
    }
}

#[cfg(test)]
#[path = "tests/mint_policy_tests.rs"]
mod mint_policy_tests;
