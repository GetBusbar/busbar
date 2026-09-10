// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RESOLVED CHAINS OF A TABLE, walked once, and the cursor a request reads them through.
//!
//! [`ChainWalk::chain_for`](crate::chain::ChainWalk::chain_for) BUILDS a chain: it clones a bucket
//! id, a group name and a scope per bucket per ancestor, which is a handful of heap allocations on
//! the admission path for a value that cannot change between two requests on one group. The group
//! half of a chain is decided entirely by the group the principal names, and a resolved
//! [`GroupTable`] is immutable — rebuilt whole on a configuration apply, never patched — so the
//! walk belongs at BOOT, once per group, and a request belongs on an index-chase into the result.
//!
//! That is what a [`ChainCache`] is. It is declared HERE, beside the walk it caches, because it is
//! made of what the walk returns: the cache holds [`BucketChain`]s and the reader hands back
//! borrows of the [`ChainBucket`]s and [`ChainGroup`]s inside them. The resolved TOPOLOGY is the
//! cost unit's and the WALK is this unit's, so the memo of the walk is this unit's too.
//!
//! Nothing on the read path allocates. The one part of a chain that is genuinely per-request is the
//! principal's own attribution bucket — its id — and that is borrowed from the principal rather
//! than materialised, which is why the reader yields [`BucketView`] cursors rather than
//! `ChainBucket` values.

use std::collections::HashSet;

use crate::chain::{BucketChain, ChainBucket, ChainGroup, ChainWalk, GroupRuntime, GroupTable};
use crate::window::WINDOW_TOTAL;

/// ONE ENFORCEMENT BUCKET OF A RESOLVED CHAIN, AS A CURSOR — every field is a borrow of, or a `Copy`
/// off, a value the table owns; nothing here is a copy of the topology.
///
/// It exists because a chain has TWO sources and the enforcement walks read them uniformly. The
/// group half is a [`ChainBucket`], resolved ONCE per group when the cache is built and thereafter
/// only borrowed. The principal's own attribution bucket is its id, which is per-request and
/// belongs to the principal — materialising it as an owned bucket would be one heap allocation on
/// the admission path for a bucket that carries no caps and can never block. So the two are read
/// through this view instead, and the admission path allocates NOTHING to resolve a chain.
#[derive(Debug, Clone, Copy)]
pub struct BucketView<'a> {
    /// The store/ledger bucket id (the principal's id, or `group:<name>@<window>[#<pool>]`).
    pub bucket_id: &'a str,
    /// The operator-facing group name for diagnostics; `None` for the principal's own bucket.
    pub group_name: Option<&'a str>,
    /// The bucket's window word — the budget window's period sentinel (`total` for the principal's
    /// own attribution bucket).
    pub window: &'static str,
    /// Request-count cap per window, if any.
    pub requests_cap: Option<u64>,
    /// Total-token cap per window, if any.
    pub tokens_cap: Option<u64>,
    /// Uncached-input token cap per window, if any.
    pub tokens_input_cap: Option<u64>,
    /// Output token cap per window, if any.
    pub tokens_output_cap: Option<u64>,
    /// Cache-read token cap per window, if any.
    pub tokens_cache_read_cap: Option<u64>,
    /// Cache-write token cap per window, if any.
    pub tokens_cache_write_cap: Option<u64>,
    /// Spend cap per window in minor units, if any.
    pub budget_cap: Option<i64>,
    /// `Some(pool)` = the bucket is scope-qualified: it checks/charges/accrues ONLY when the
    /// request was dispatched through that pool. `None` = applies to every request through the
    /// group.
    pub scope: Option<&'a str>,
    /// The budget limit's downgrade target, when it declared one.
    pub downgrade_to: Option<&'a str>,
}

impl<'a> BucketView<'a> {
    /// The principal's own attribution bucket: its id, no caps, the all-time window. It is there so
    /// every posting is attributed, it is charged on every admission, and it can never block.
    pub fn attribution(attribution_bucket_id: &'a str) -> Self {
        BucketView {
            bucket_id: attribution_bucket_id,
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

    /// A cursor onto one of the walk's resolved group buckets. Borrows; copies only the caps,
    /// which are integers.
    pub fn of(b: &'a ChainBucket) -> Self {
        BucketView {
            bucket_id: &b.bucket_id,
            group_name: b.group_name.as_deref(),
            window: b.window,
            requests_cap: b.requests_cap,
            tokens_cap: b.tokens_cap,
            tokens_input_cap: b.tokens_input_cap,
            tokens_output_cap: b.tokens_output_cap,
            tokens_cache_read_cap: b.tokens_cache_read_cap,
            tokens_cache_write_cap: b.tokens_cache_write_cap,
            budget_cap: b.budget_cap,
            scope: b.scope.as_deref(),
            downgrade_to: b.downgrade_to.as_deref(),
        }
    }

    /// Whether this bucket participates in a request dispatched through `pool` — group-wide
    /// buckets always do; a pool-scoped bucket only for its own pool. Every enforcement walk
    /// (admit / charge / refund / accrue / headroom) keys off this ONE predicate so the paths
    /// can never disagree on what was charged vs what is refunded.
    pub fn applies_to_pool(&self, pool: &str) -> bool {
        self.scope.is_none_or(|s| s == pool)
    }
}

/// A resolved enforcement chain for ONE PRINCIPAL: its attribution bucket plus the GROUP HALF,
/// which is a borrow of a chain the cache resolved once and holds for its whole life.
///
/// The group half depends only on the group the principal is bound to, and a resolved table is
/// immutable — so it is walked at BOOT, once per group, and every request that arrives on that
/// group thereafter reads the same value. What is per-request is the attribution id and nothing
/// else.
#[derive(Debug, Clone, Copy)]
pub struct Chain<'a> {
    attribution_bucket_id: &'a str,
    groups: &'a BucketChain,
}

impl<'a> Chain<'a> {
    /// Every bucket of the chain, innermost first: the principal's attribution bucket, then the
    /// innermost group's window buckets, then its parent's, to the root.
    pub fn iter(&self) -> impl Iterator<Item = BucketView<'a>> {
        std::iter::once(BucketView::attribution(self.attribution_bucket_id))
            .chain(self.groups.buckets().iter().map(BucketView::of))
    }

    /// How many buckets the chain has, attribution bucket included.
    pub fn len(&self) -> usize {
        1 + self.groups.buckets().len()
    }

    /// Never empty: the attribution bucket is always there.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The chain's groups, innermost first — the freeze flag and the in-flight gauge are per
    /// GROUP, not per window bucket.
    pub fn groups(&self) -> &'a [ChainGroup] {
        self.groups.groups()
    }
}

/// EVERY CHAIN A TABLE CAN PRODUCE, WALKED ONCE, plus the index of the ids that still carry a cap.
///
/// Built beside the table it memoises and rebuilt with it: a cache resolved from one table is one
/// reading of that table's chains, and a configuration apply produces a new table and a new cache
/// rather than patching either.
#[derive(Debug, Clone)]
pub struct ChainCache {
    /// THE CHAIN PER GROUP, WALKED ONCE, indexed by the group's position in the table, so the
    /// lookup is the same index-chase the walk itself is.
    chains: Vec<BucketChain>,
    /// The chain of a principal bound to NO group: no group buckets and no groups. Held as a value
    /// rather than built per read for the same reason the rest are — an unbound principal's chain
    /// is one shape, and a read of it allocates nothing either.
    empty_chain: BucketChain,
    /// The ids of every LIVE bucket that still carries at least one windowed cap — the exact set
    /// the projection emitted, indexed for O(1) membership. This is what makes "does this ledger
    /// cell still back an enforced cap?" an IDENTITY question (is this id one of the ids the table
    /// produces?) instead of a parse of the id's internal structure.
    capped_bucket_ids: HashSet<String>,
}

impl ChainCache {
    /// Walk every group of `table` once and keep the results.
    pub fn resolve(table: &GroupTable) -> Self {
        ChainCache {
            chains: (0..table.groups().len())
                .map(|i| Self::group_chain(table, i))
                .collect(),
            empty_chain: BucketChain::unchecked(Vec::new(), Vec::new()),
            capped_bucket_ids: Self::capped_bucket_ids(table.groups()),
        }
    }

    /// The GROUP HALF of the chain that starts at `index`.
    ///
    /// The walk yields the principal's attribution bucket first and then the groups', and the
    /// attribution bucket is the one part that is NOT shareable — it is the principal's id, which
    /// is per-request. So it is walked with an empty id and dropped, and each request supplies its
    /// own through [`BucketView::attribution`], which borrows. That is the whole reason a chain
    /// read costs no allocation.
    fn group_chain(table: &GroupTable, index: usize) -> BucketChain {
        let name = table.groups()[index].name.as_str();
        let walked = table
            .chain_for("", Some(name))
            .expect("the name came from the table being walked");
        BucketChain::unchecked(walked.buckets()[1..].to_vec(), walked.groups().to_vec())
    }

    /// Index the ids of every projected bucket that carries at least one windowed cap. Built from
    /// the SAME buckets the door enforces against, so the set can never disagree with the table
    /// about which cells are load-bearing.
    fn capped_bucket_ids(groups: &[GroupRuntime]) -> HashSet<String> {
        groups
            .iter()
            .flat_map(|g| g.buckets.iter())
            .filter(|b| {
                b.requests_cap.is_some()
                    || b.tokens_cap.is_some()
                    || b.tokens_input_cap.is_some()
                    || b.tokens_output_cap.is_some()
                    || b.tokens_cache_read_cap.is_some()
                    || b.tokens_cache_write_cap.is_some()
                    || b.budget_cap.is_some()
            })
            .map(|b| b.bucket_id.clone())
            .collect()
    }

    /// Whether `bucket_id` is, RIGHT NOW, the id of a live bucket that still enforces at least one
    /// windowed cap. Pure identity: the id either is one the live table produces or it is not, so
    /// no assumption about `@`/`#` being delimiters (or a group name avoiding them) exists here.
    pub fn bucket_enforces_a_cap(&self, bucket_id: &str) -> bool {
        self.capped_bucket_ids.contains(bucket_id)
    }

    /// READ the ENFORCEMENT CHAIN for a principal: [its attribution bucket] -> its group's window
    /// buckets -> the parent's -> ... root, innermost first.
    ///
    /// A READ AND NOT A WALK, WHICH IS THE POINT. The group half of a chain is decided entirely by
    /// the group named, and the table is immutable once resolved — so the walk ran at BOOT, once
    /// per group, and this is an index-chase into the result. Nothing is allocated: the group
    /// buckets are borrowed from the cache and the attribution bucket is the principal's own id,
    /// borrowed from the principal.
    ///
    /// `Err(name)` when the principal names a group `table` does not have — the FAIL-CLOSED
    /// outcome. Minting validates the group and boot re-checks it, so this arm covers a shared
    /// durable store whose principals reference a group another node's config no longer has, and a
    /// chain whose caps cannot be read cannot be enforced.
    pub fn chain_for<'a>(
        &'a self,
        table: &GroupTable,
        attribution_bucket_id: &'a str,
        group: Option<&'a str>,
    ) -> Result<Chain<'a>, &'a str> {
        let groups = match group {
            None => &self.empty_chain,
            Some(name) => match table.index_of(name) {
                Some(i) => &self.chains[i],
                None => return Err(name),
            },
        };
        Ok(Chain {
            attribution_bucket_id,
            groups,
        })
    }
}
