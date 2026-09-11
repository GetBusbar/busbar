// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAILOVER VALUES THE CONFIG GRAMMAR NAMES: the budget defaults/bounds and the repeat-safety
//! property of an operation.
//!
//! The failover WALK -- the candidate trait, the ordering, the breaker admission and the refusal
//! taxonomy -- stays in `busbar-substrate`, because it reaches the audit vocabulary and the store.
//! What is here is only what `config::pools` reads, and `config` is a value grammar: a crate that
//! holds the grammar may not reach back up into the engine that runs on it. `busbar-substrate`
//! re-exports every item below at its historical `busbar_substrate::failover::` path.

// ── The FAILOVER BUDGET numeric defaults/bounds. Plain scalars with no config grammar attached
//    (the serialized `FailoverCfg` shape stays in core, schema-frozen). They live HERE in the neutral
//    substrate so a plane crate names the per-request failover budget without reaching into
//    `busbar-core`; core's `config` re-exports each at its historical `crate::config::*` path (so
//    `appbuild`/`config_validate`/`test_support` call sites are untouched), and the `serde` default
//    fns (`default_failover_timeout`/`default_max_hops`) read the re-export.
/// Default failover wall-clock budget (seconds) when a pool doesn't set `failover.timeout_secs`.
pub const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;
/// Upper bound (seconds) on a pool's `failover.timeout_secs`. 24h is already absurdly long for a
/// per-request failover budget — anything larger is a fat-finger typo (extra zeros). Enforced at
/// `--validate`/boot so a merely-oversized value fails CLOSED with an actionable message instead of
/// being accepted and later feeding `RequestCtx::new` a duration large enough to overflow the
/// monotonic-clock `Instant` math.
pub const MAX_FAILOVER_DEADLINE_SECS: u64 = 86_400;
/// Default maximum failover hops per request when a pool doesn't set `failover.max_hops`.
pub const DEFAULT_FAILOVER_CAP: usize = 3;

/// MAY THIS OPERATION BE PERFORMED TWICE? A property of the operation the caller named, declared by
/// the operator who vouched for it — never inferred, and never a property of the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeatable {
    /// The DEFAULT for everything an operator has not spoken about. A second execution may have a
    /// second effect, so an [`Stage::AfterDispatch`] hop is refused.
    No,
    /// The operator declared this operation safe to perform twice (a read, a search, a query).
    Yes,
}
