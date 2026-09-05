// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bucket chain: what the door walks.
//!
//! A principal's chain is its own attribution bucket, then the group it is bound to, then that
//! group's parent, and so on to the root. Each group contributes one enforcement bucket per
//! distinct window its limits use, optionally qualified to a pool. The door admits only if every
//! bucket of the chain admits — most-restrictive wins, and the answer is the same whichever order
//! the caps were written in.
//!
//! Two things about this shape are load-bearing and easy to lose in a rewrite. First, the
//! principal's own bucket carries no caps: it is there so every posting is attributed, and it is
//! charged on every admission even though it can never block. Second, a pool-qualified bucket
//! participates only when the request's effective pool EQUALS its scope — lane membership is never
//! consulted, so a pool that happens to share a member lane with another pool never triggers that
//! other pool's bucket.

// contract: BucketChain, and the resolved group topology behind it, are types the contract crate
// owns. They are declared here so the decision has something to walk while the crates land side by
// side; the integrator replaces them and deletes these.

use crate::window::WINDOW_TOTAL;

/// One enforcement bucket of a resolved chain: the ledger cell it reads and charges, the window it
/// counts in, its caps, and its pool scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBucket {
    /// The ledger bucket id: the principal's own id, or `group:<name>@<window>` with an optional
    /// `#<scope>` suffix for a pool-qualified bucket.
    pub bucket_id: String,
    /// The operator-facing group name, for the refusal. `None` for the principal's own bucket,
    /// which is why only group buckets can ever be named as blocking.
    pub group_name: Option<String>,
    /// The bucket's window word — the window sentinel and the refusal's vocabulary. The
    /// principal's own bucket is always the all-time window.
    pub window: &'static str,
    /// Request-count cap per window, if any.
    pub requests_cap: Option<u64>,
    /// Total-token cap per window, if any. Best-effort and post-paid: tokens land after the
    /// response, so the cap blocks the NEXT request once the ledgered total has crossed it.
    pub tokens_cap: Option<u64>,
    /// Uncached-input token cap per window, if any.
    pub tokens_input_cap: Option<u64>,
    /// Output token cap per window, if any.
    pub tokens_output_cap: Option<u64>,
    /// Cache-read token cap per window, if any.
    pub tokens_cache_read_cap: Option<u64>,
    /// Cache-write token cap per window, if any.
    pub tokens_cache_write_cap: Option<u64>,
    /// Spend cap per window, in cents, if any. Derived at check time from the cell's token ledger
    /// against the current rate table, plus the flat fee times the billable request count.
    pub budget_cap: Option<i64>,
    /// `Some(pool)` = this bucket accounts only traffic dispatched through that pool. `None` =
    /// group-wide: every request through the group.
    pub scope: Option<String>,
    /// Where budget-exhausted traffic goes instead of a refusal, when the governing budget limit
    /// declared a downgrade. `None` = block, the default.
    pub downgrade_to: Option<String>,
}

impl ChainBucket {
    /// A bucket with no caps at all — the shape of a principal's own attribution bucket.
    pub fn attribution(bucket_id: impl Into<String>) -> Self {
        ChainBucket {
            bucket_id: bucket_id.into(),
            group_name: None,
            window: WINDOW_TOTAL,
            requests_cap: None,
            tokens_cap: None,
            tokens_input_cap: None,
            tokens_output_cap: None,
            tokens_cache_read_cap: None,
            tokens_cache_write_cap: None,
            budget_cap: None,
            scope: None,
            downgrade_to: None,
        }
    }

    /// Whether this bucket participates in a request dispatched through `pool`. Group-wide buckets
    /// always do; a pool-qualified bucket only for its own pool, by equality on the effective pool
    /// name. Every walk — check, charge, refund, accrual — keys off this ONE predicate, so the
    /// paths can never disagree about what was charged versus what is refunded.
    pub fn applies_to_pool(&self, pool: &str) -> bool {
        match &self.scope {
            None => true,
            Some(s) => s == pool,
        }
    }

    /// Whether the bucket carries any windowed cap at all. An uncapped bucket is an attribution
    /// bucket: it is charged, and it never blocks.
    pub fn is_uncapped(&self) -> bool {
        self.requests_cap.is_none()
            && self.tokens_cap.is_none()
            && self.tokens_input_cap.is_none()
            && self.tokens_output_cap.is_none()
            && self.tokens_cache_read_cap.is_none()
            && self.tokens_cache_write_cap.is_none()
            && self.budget_cap.is_none()
    }
}

/// One group of the chain, as the freeze check and the in-flight gauges see it. These two live per
/// GROUP, not per window bucket: a group with a concurrent cap and two windowed caps takes one
/// lease, not three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainGroup {
    /// The group's name — the gauge's key, and the name a refusal prints.
    pub name: String,
    /// `false` freezes the group: every request charging through it, its own principals and every
    /// descendant's, is refused while its history is kept.
    pub enabled: bool,
    /// The instantaneous in-flight cap, if any. Never windowed and never pool-scoped.
    pub concurrent_cap: Option<u64>,
    /// The tier multiplier, in basis points, this group's bucket contributes to the chain. One per
    /// chain; mixing them is a boot refusal, which is why the constructor checks it.
    pub tier_bp: u32,
}

/// The neutral tier multiplier: one times ten thousand.
pub const STANDARD_TIER_BP: u32 = 10_000;

/// A resolved chain: the principal's attribution bucket, then every ancestor group's per-window
/// buckets, innermost first, plus the groups themselves in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketChain {
    buckets: Vec<ChainBucket>,
    groups: Vec<ChainGroup>,
    tier_bp: u32,
}

/// Why a chain could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Two groups in one chain declare different tier multipliers. One tier per chain; this is a
    /// boot refusal, never a request-time one, so no admitted request ever sees it.
    TierMismatch {
        /// The multiplier the chain started with.
        expected: u32,
        /// The one that disagreed.
        found: u32,
        /// The group that disagreed.
        group: String,
    },
}

impl BucketChain {
    /// Build a chain from its buckets and groups, innermost first, checking the one-tier-per-chain
    /// rule. Callers that already ran the boot check use [`BucketChain::unchecked`].
    pub fn new(buckets: Vec<ChainBucket>, groups: Vec<ChainGroup>) -> Result<Self, ChainError> {
        if let Some(first) = groups.first() {
            for g in &groups[1..] {
                if g.tier_bp != first.tier_bp {
                    return Err(ChainError::TierMismatch {
                        expected: first.tier_bp,
                        found: g.tier_bp,
                        group: g.name.clone(),
                    });
                }
            }
        }
        Ok(BucketChain::unchecked(buckets, groups))
    }

    /// Build a chain without re-checking the tier rule — the shape the request path uses, because
    /// the rule is a boot refusal and by then it already holds.
    pub fn unchecked(buckets: Vec<ChainBucket>, groups: Vec<ChainGroup>) -> Self {
        let tier_bp = groups.first().map_or(STANDARD_TIER_BP, |g| g.tier_bp);
        BucketChain {
            buckets,
            groups,
            tier_bp,
        }
    }

    /// Every bucket, innermost first.
    pub fn buckets(&self) -> &[ChainBucket] {
        &self.buckets
    }

    /// Every group, innermost first.
    pub fn groups(&self) -> &[ChainGroup] {
        &self.groups
    }

    /// The chain's tier multiplier in basis points — one per chain, applied once over the summed
    /// pre-tier nano-units when the hold is sized.
    pub fn tier_bp(&self) -> u32 {
        self.tier_bp
    }

    /// The buckets this request's pool participates in, in chain order. Filtered ONCE, so the
    /// check pass, the charge pass and the lock set can never disagree.
    pub fn pool_filtered(&self, pool: &str) -> Vec<&ChainBucket> {
        self.buckets
            .iter()
            .filter(|b| b.applies_to_pool(pool))
            .collect()
    }
}

// ── the config projection the chain is resolved from ────────────────────────────────────────────

/// One group's per-window enforcement bucket, before it is bound to a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBucket {
    /// The ledger bucket id this group's window writes to.
    pub bucket_id: String,
    /// The window word.
    pub window: &'static str,
    /// Request-count cap, if any.
    pub requests_cap: Option<u64>,
    /// Total-token cap, if any.
    pub tokens_cap: Option<u64>,
    /// Uncached-input token cap, if any.
    pub tokens_input_cap: Option<u64>,
    /// Output token cap, if any.
    pub tokens_output_cap: Option<u64>,
    /// Cache-read token cap, if any.
    pub tokens_cache_read_cap: Option<u64>,
    /// Cache-write token cap, if any.
    pub tokens_cache_write_cap: Option<u64>,
    /// Spend cap in cents, if any.
    pub budget_cap: Option<i64>,
    /// The pool this bucket is qualified to, if any.
    pub scope: Option<String>,
    /// The downgrade target the governing budget limit declared, if any.
    pub downgrade_to: Option<String>,
}

impl GroupBucket {
    /// A bucket for `window` with no caps set, to be filled in by the caller.
    pub fn new(bucket_id: impl Into<String>, window: &'static str) -> Self {
        GroupBucket {
            bucket_id: bucket_id.into(),
            window,
            requests_cap: None,
            tokens_cap: None,
            tokens_input_cap: None,
            tokens_output_cap: None,
            tokens_cache_read_cap: None,
            tokens_cache_write_cap: None,
            budget_cap: None,
            scope: None,
            downgrade_to: None,
        }
    }
}

/// One resolved group: its freeze flag, its in-flight cap, its per-window buckets, and its parent
/// by index, so the chain walk is index-chasing with no hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRuntime {
    /// The group's name.
    pub name: String,
    /// `false` freezes the group and every descendant.
    pub enabled: bool,
    /// The instantaneous in-flight cap, if any.
    pub concurrent_cap: Option<u64>,
    /// The tier multiplier in basis points.
    pub tier_bp: u32,
    /// The group's per-window enforcement buckets, one per distinct window its limits use. Empty
    /// for a group with only a concurrent cap, or none at all.
    pub buckets: Vec<GroupBucket>,
    /// The parent group's index in the table, if any.
    pub parent: Option<usize>,
}

impl GroupRuntime {
    /// An enabled group with no caps and no parent.
    pub fn new(name: impl Into<String>) -> Self {
        GroupRuntime {
            name: name.into(),
            enabled: true,
            concurrent_cap: None,
            tier_bp: STANDARD_TIER_BP,
            buckets: Vec::new(),
            parent: None,
        }
    }
}

/// The resolved group topology: the table the chain walk chases indices through.
#[derive(Debug, Clone, Default)]
pub struct GroupTable {
    groups: Vec<GroupRuntime>,
}

impl GroupTable {
    /// Build a table from groups already resolved in dependency order (a parent's index must be
    /// less than nothing in particular; the walk clamps on cycles either way).
    pub fn new(groups: Vec<GroupRuntime>) -> Self {
        GroupTable { groups }
    }

    /// Every group.
    pub fn groups(&self) -> &[GroupRuntime] {
        &self.groups
    }

    /// The index of a group by name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.groups.iter().position(|g| g.name == name)
    }

    /// Resolve the enforcement chain for a principal: its attribution bucket, then its group's
    /// window buckets, then the parent's, to the root, innermost first.
    ///
    /// `Err` names the missing group when the principal is bound to a group this node's config
    /// does not have. That is the fail-closed outcome and it is deliberate: minting validates the
    /// group and boot re-checks it, so this can only arise from a shared durable store whose
    /// principals reference a group another node's config no longer has — and a chain whose caps
    /// cannot be read cannot be enforced, so nothing is admitted under it.
    pub fn chain_for(
        &self,
        attribution_bucket_id: &str,
        group: Option<&str>,
    ) -> Result<BucketChain, MissingGroup> {
        let mut buckets: Vec<ChainBucket> = Vec::with_capacity(8);
        buckets.push(ChainBucket::attribution(attribution_bucket_id));
        let mut groups: Vec<ChainGroup> = Vec::new();
        let mut walked = 0usize;
        let mut next = match group {
            None => None,
            Some(name) => match self.index_of(name) {
                Some(i) => Some(i),
                None => return Err(MissingGroup(name.to_string())),
            },
        };
        while let Some(i) = next {
            if walked >= self.groups.len() {
                // A distinct-node walk cannot exceed the group count without revisiting one, which
                // is a cycle. Cycles are a validation error; clamp here defensively, never loop.
                break;
            }
            let g = &self.groups[i];
            walked += 1;
            groups.push(ChainGroup {
                name: g.name.clone(),
                enabled: g.enabled,
                concurrent_cap: g.concurrent_cap,
                tier_bp: g.tier_bp,
            });
            for b in &g.buckets {
                buckets.push(ChainBucket {
                    bucket_id: b.bucket_id.clone(),
                    group_name: Some(g.name.clone()),
                    window: b.window,
                    requests_cap: b.requests_cap,
                    tokens_cap: b.tokens_cap,
                    tokens_input_cap: b.tokens_input_cap,
                    tokens_output_cap: b.tokens_output_cap,
                    tokens_cache_read_cap: b.tokens_cache_read_cap,
                    tokens_cache_write_cap: b.tokens_cache_write_cap,
                    budget_cap: b.budget_cap,
                    scope: b.scope.clone(),
                    downgrade_to: b.downgrade_to.clone(),
                });
            }
            next = g.parent;
        }
        // The one-tier-per-chain rule is a BOOT check, not a request-time one: a config that
        // mixes multipliers is refused at boot, so by the time a request walks a chain the rule
        // already holds. Here the chain is built with whatever the innermost group declared.
        Ok(BucketChain::unchecked(buckets, groups))
    }

    /// The boot check for the one-tier-per-chain rule: every chain this table can produce carries
    /// a single tier multiplier. Run at boot; a mixed chain is a boot refusal.
    pub fn validate_tiers(&self) -> Result<(), ChainError> {
        for (i, g) in self.groups.iter().enumerate() {
            let mut walked = 0usize;
            let mut next = Some(i);
            let expected = g.tier_bp;
            while let Some(j) = next {
                if walked >= self.groups.len() {
                    break;
                }
                walked += 1;
                let cur = &self.groups[j];
                if cur.tier_bp != expected {
                    return Err(ChainError::TierMismatch {
                        expected,
                        found: cur.tier_bp,
                        group: cur.name.clone(),
                    });
                }
                next = cur.parent;
            }
        }
        Ok(())
    }
}

/// The name of a group the chain walk could not find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingGroup(pub String);
