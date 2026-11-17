// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::count::{Count, CountError, COUNT_SCALE};
use busbar_kernel_ledger::cost::{EntryId, RawRateEra};
use foldhash::{HashMap, HashMapExt};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

type RawFeeEras = busbar_kernel_ledger::usage::FeeEras<RawRateEra>;

pub mod drain;
pub(crate) mod exact_debt;
pub mod persistence;
pub mod principal_transition;
pub mod recovery;
use exact_debt::{BudgetFlushFlight, BudgetFlushRunner, ExactUsageDelta};
mod metering_flush;
pub(crate) mod raw_recovery;
pub mod unit_checkpoint;
mod unit_checkpoint_counts;
pub use crate::off_path::governance::unit_checkpoint_store;

use crate::diagnostics::{
    diag_debug, diag_warn, GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION, LIMIT_WINDOW_UNRECOGNIZED,
};

pub const WINDOW_TOTAL: &str = "total";

pub const WINDOW_DAY: &str = "day";

pub const WINDOW_MONTH: &str = "month";

pub const WINDOW_MINUTE: &str = "minute";

pub const WINDOW_HOUR: &str = "hour";

const VK_ID_PREFIX: &str = "vk_";

pub(crate) const BINDING_MARKER_PREFIX: &str = "binding:";

pub const SELF_KEY_GROUP_PREFIX: &str = "user:";

pub const SELF_KEY_BINDING_MODE: &str = "user-bound";

pub const SELF_KEY_BINDING_MODE_APP: &str = "time-bound";

pub fn binding_marker(id: &str, generation: &str) -> String {
    crate::off_path::governance::state::mod_binding_marker(BINDING_MARKER_PREFIX, id, generation)
}

pub fn binding_generation(generation_hash: &str) -> Option<&str> {
    generation_hash
        .strip_prefix(BINDING_MARKER_PREFIX)?
        .split_once(':')
        .map(|(_id, generation)| generation)
}

pub fn generation_matches(generation_hash: &str, presented: Option<&str>) -> bool {
    match (binding_generation(generation_hash), presented) {
        (Some(held), Some(claimed)) => busbar_contract::redacted::constant_time_eq(held, claimed),
        (held, claimed) => held.is_none() && claimed.is_none(),
    }
}

pub(crate) fn generate_binding_generation() -> Result<String, busbar_contract::crypto::RngError> {
    let mut raw = [0u8; 16];
    busbar_contract::crypto::fill(&mut raw)?;
    Ok(hex::encode(raw))
}

/// One model's in-cell token counters: the CURRENT tier tokens plus the last durably-ACKNOWLEDGED
/// (flushed) tier tokens - the additive-flush baseline, per model. The model name is an
/// `Arc<str>` interned ONCE per (bucket, model) on first sight (allocate-on-miss); the per-request
/// accrual after that is a linear scan over the few models the bucket actually used plus integer
/// adds - no hashing, no allocation.
#[derive(Clone)]
pub(crate) struct ModelCell {
    pub(crate) model: std::sync::Arc<str>,
    /// The card start and optional exact entry identity captured for these counts (Q14, #79).
    /// Only legacy zero is undated; a known opening entry remains distinct. One cell per
    /// (model, era), including distinct entries that share a start.
    pub(crate) era: RawRateEra,
    /// (1.6.0 M1b) The name-keyed CURRENT unit counters — the reserved four
    /// (`input`/`output`/`cache_read`/`cache_write`) are ordinary keys beside any open unit, the
    /// sole representation now that `TierTokens` is dissolved. Sparse (a zero unit is absent).
    pub(crate) cur: std::collections::BTreeMap<String, Count>,
    /// The last durably-ACKNOWLEDGED (flushed) unit counters — the additive-flush baseline.
    pub(crate) flushed: std::collections::BTreeMap<String, Count>,
    pub(crate) flushed_era: std::collections::BTreeMap<String, Count>,
    /// Zero-sized and never read: only [`ModelCell::new`] can build one, so only it writes a
    /// `ModelCell` literal. The leading `_` marks it a marker field, like a `PhantomData`.
    _seal: model_cell_seal::Seal,
}

mod model_cell_seal {
    use super::Count;
    use std::collections::BTreeMap;

    /// Only `ModelCell::new` can build this, so only it can write a `ModelCell` literal.
    #[derive(Clone, Copy)]
    pub(super) struct Seal(());

    impl super::ModelCell {
        /// The only constructor. Refuses the poison shape: an unnamed lane with no count in
        /// `cur`, `flushed` or `flushed_era` (it prices as LaneUnpriced and carries nothing).
        /// A NAMED model with all-empty maps is allowed (dated-era split on load; correction
        /// baselines). An unnamed lane WITH counts is still built: it must stay visible and fail
        /// closed as LaneUnpriced, never be dropped (UPG-H2, lint `laneless-ledger-row`).
        pub(crate) fn new(
            model: std::sync::Arc<str>,
            era: super::RawRateEra,
            cur: BTreeMap<String, Count>,
            flushed: BTreeMap<String, Count>,
            flushed_era: BTreeMap<String, Count>,
        ) -> Option<Self> {
            let empty = !super::has_units(&cur)
                && !super::has_units(&flushed)
                && !super::has_units(&flushed_era);
            if model.is_empty() && empty {
                return None;
            }
            Some(super::ModelCell {
                model,
                era,
                cur,
                flushed,
                flushed_era,
                _seal: Seal(()),
            })
        }
    }
}

/// In-memory TOKEN-LEDGER cell for a bucket's CURRENT window - the AUTHORITATIVE hot-path
/// enforcement state. A bucket is a key's own budget bucket OR a budget-group bucket (same shape).
/// NO SPEND FIELD: money is derived at check time as `cell tokens x the card IN FORCE WHEN EACH WAS
/// EARNED` (+ the flat fee x requests per admission era). The counts are
/// segmented by card era and each era prices at the card the dated history resolves for it, so an
/// edit prices what follows it and a signed back-dated correction reprices the window it names,
/// with no data fix either way. The durable store is a write-behind
/// layer flushed off the request path. One cell per bucket (current window only; reset on
/// rollover), so growth is bucket-count-bounded (keys + group-window buckets).
#[derive(Clone, Default)]
pub(crate) struct BudgetCell {
    pub(crate) group_owners: std::collections::BTreeSet<String>,
    pub(crate) flushing: usize,
    /// Window identities still owned by off-lock flush snapshots.
    pub(crate) flushing_windows: std::collections::BTreeMap<u64, usize>,
    /// Both possible raw states of an unresolved correction. Ordinary mutations update both.
    pub(crate) correction: Option<Box<CorrectionBranch>>,
    pub(crate) window_start: u64,
    /// ADMISSION count: incremented once per admitted request, NEVER refunded. This backs the
    /// `requests`-LIMIT metric, so a caller cannot escape the requests cap by hammering failing
    /// requests (each still consumed a request slot at admission).
    pub(crate) requests: u64,
    /// BILLABLE request count: admitted requests MINUS non-2xx refunds. This backs the flat
    /// per-request-FEE component of the `budget` metric (the fee bills 2xx only), so budget spend
    /// derives from this, never from `requests`. Charged with `requests` at admission; a non-2xx
    /// outcome decrements ONLY this via `refund_bucket`.
    pub(crate) billable_requests: u64,
    /// The additive-flush watermark: durably acknowledged counts, or counts whose exact outbound
    /// debt has transferred to `budget_flushes`. That owner retains every unconfirmed chunk. Each
    /// flush transfers only the delta (current - flushed) into an owned native ledger request.
    /// Unknown outcomes retain the original operation, body and first-send custody; retries
    /// resolve that same logical receipt before publishing acknowledgement.
    pub(crate) flushed_requests: u64,
    /// The billable-request flush watermark (twin of `flushed_requests` for the fee-base counter).
    pub(crate) flushed_billable_requests: u64,
    /// Per-(model, era, tier) token counters + flush baselines. Small Vec (the models this bucket
    /// actually used), scanned linearly.
    pub(crate) models: Vec<ModelCell>,
    /// The fee base split by the card era each billable request was admitted under, so each fee
    /// prices at the card in force when that request was admitted.
    pub(crate) fee_eras: RawFeeEras,
    /// The fee eras' flush watermark (twin of `flushed_billable_requests`, per dated era).
    pub(crate) flushed_fee_eras: RawFeeEras,
    /// THE ROLLED WINDOWS' UNACKNOWLEDGED DELTAS, each under the window it was earned in. A roll to
    /// a newer window moves what the old window held past its last acknowledged flush here
    /// ([`BudgetCell::roll`]) instead of discarding it; `flush_budgets` drains them to the store
    /// under their OWN window and parks a failed one back, so a store outage across a boundary
    /// loses nothing. Empty in steady state.
    pub(crate) rolled: Vec<(u64, ExactUsageDelta)>,
    pub(crate) rolled_eras: Vec<(u64, ExactUsageDelta)>,
    pub(crate) dirty: bool,
    /// Wall-clock of the last accrual or admission charge. The eviction sweep ages cells by
    /// `window_start`, but a key's own bucket and a synthesized SSO principal's bucket both live in
    /// the all-time window (`window_start == 0`), which never ages — so those cells were retained
    /// for the process lifetime even after the key was deleted or the principal stopped appearing.
    /// `dirty` alone cannot substitute: the flusher clears it every 100ms, so a busy cell is
    /// legitimately clean and would be swept mid-use.
    pub(crate) last_touch: u64,
}

#[derive(Clone)]
pub(crate) struct CorrectionBranch {
    op_id: busbar_contract::records::OpId,
    window: u64,
    accepted: BudgetCell,
}

impl BudgetCell {
    fn mutate(&mut self, mut operation: impl FnMut(&mut Self)) {
        let mut branch = self.correction.take();
        operation(self);
        if let Some(branch) = branch.as_mut() {
            operation(&mut branch.accepted);
        }
        self.correction = branch;
    }

    pub(crate) fn fresh(window_start: u64) -> Self {
        Self {
            window_start,
            ..Self::default()
        }
    }

    fn roll(&mut self, window: u64) {
        self.mutate(|cell| {
            let (old, unacked, eras) = (
                cell.window_start,
                ExactUsageDelta::of(cell, false),
                ExactUsageDelta::of(cell, true),
            );
            let rolled = std::mem::take(&mut cell.rolled);
            let rolled_eras = std::mem::take(&mut cell.rolled_eras);
            let owners = std::mem::take(&mut cell.group_owners);
            let flushing = cell.flushing;
            let flushing_windows = std::mem::take(&mut cell.flushing_windows);
            *cell = Self::fresh(window);
            cell.group_owners = owners;
            cell.flushing = flushing;
            cell.flushing_windows = flushing_windows;
            cell.rolled = rolled;
            cell.rolled_eras = rolled_eras;
            park_window(&mut cell.rolled, old, unacked);
            park_window(&mut cell.rolled_eras, old, eras);
            cell.dirty = !cell.rolled.is_empty() || !cell.rolled_eras.is_empty();
        });
    }

    fn park(&mut self, window: u64, delta: impl std::borrow::Borrow<UsageDelta>) {
        let delta = delta.borrow();
        self.mutate(|cell| {
            park_window(
                &mut cell.rolled,
                window,
                ExactUsageDelta::from_signed(delta),
            );
        });
    }

    fn park_eras(&mut self, window: u64, delta: impl std::borrow::Borrow<UsageDelta>) {
        let delta = delta.borrow();
        self.mutate(|cell| {
            park_window(
                &mut cell.rolled_eras,
                window,
                ExactUsageDelta::from_signed(delta),
            );
        });
    }

    #[cfg(test)]
    fn unflushed(&self) -> UsageDelta {
        ExactUsageDelta::of(self, false)
            .signed()
            .expect("legacy flush checks raw debt representability")
    }

    #[cfg(test)]
    fn unflushed_eras(&self) -> UsageDelta {
        ExactUsageDelta::of(self, true)
            .signed()
            .expect("legacy flush checks raw debt representability")
    }

    #[cfg(test)]
    fn accrue(&mut self, model: &str, era: u64, units: &std::collections::BTreeMap<String, u64>) {
        let era = RawRateEra::legacy(era);
        let counts = whole_counts(units);
        // The real accrual path: an all-zero report interns no row (UPG-H2, LINT-RULES R35).
        self.accrue_raw(model, era, &counts)
            .expect("test count accrual");
    }

    fn accrue_raw(
        &mut self,
        model: &str,
        era: RawRateEra,
        units: &std::collections::BTreeMap<String, Count>,
    ) -> Result<(), CountError> {
        // Every sum is checked against the held counts before any cell changes, so a refused
        // accrual leaves the cell (and its correction branch) exactly as it was, without copying it.
        fn check(
            cell: &BudgetCell,
            model: &str,
            era: RawRateEra,
            units: &std::collections::BTreeMap<String, Count>,
        ) -> Result<(), CountError> {
            let held = cell
                .models
                .iter()
                .position(|m| &*m.model == model && m.era == era)
                .map(|i| &cell.models[i].cur);
            for (k, v) in units {
                if v.is_negative() {
                    return Err(CountError::Negative);
                }
                if !v.is_zero() {
                    let slot = held.and_then(|cur| cur.get(k)).copied().unwrap_or_default();
                    slot.checked_add(*v)?;
                }
            }
            Ok(())
        }
        fn add(
            cell: &mut BudgetCell,
            model: &str,
            era: RawRateEra,
            units: &std::collections::BTreeMap<String, Count>,
        ) {
            let at = cell
                .models
                .iter()
                .position(|m| &*m.model == model && m.era == era);
            let checked = "sum checked before the cell changed";
            let Some(i) = at else {
                // An all-zero accrual leaves the cell alone: a row with no count carries nothing,
                // and an unnamed one would price as LaneUnpriced for the whole bucket (UPG-H2).
                let mut cur = std::collections::BTreeMap::new();
                for (k, v) in units {
                    if !v.is_zero() {
                        let first = Count::default().checked_add(*v).expect(checked);
                        cur.insert(k.clone(), first);
                    }
                }
                if !cur.is_empty() {
                    cell.models.extend(ModelCell::new(
                        model.into(),
                        era,
                        cur,
                        Default::default(),
                        Default::default(),
                    ));
                }
                return;
            };
            let cur = &mut cell.models[i].cur;
            for (k, v) in units {
                if v.is_zero() {
                    continue;
                }
                match cur.get_mut(k) {
                    Some(slot) => *slot = slot.checked_add(*v).expect(checked),
                    None => {
                        let first = Count::default().checked_add(*v).expect(checked);
                        cur.insert(k.clone(), first);
                    }
                }
            }
        }
        check(self, model, era, units)?;
        if let Some(branch) = self.correction.as_deref() {
            check(&branch.accepted, model, era, units)?;
        }
        add(self, model, era, units);
        if let Some(branch) = self.correction.as_deref_mut() {
            add(&mut branch.accepted, model, era, units);
        }
        Ok(())
    }

    fn spend(
        &self,
        cost: &crate::cost::CostModel,
        include_fee: bool,
    ) -> Result<busbar_kernel_ledger::cost::Money, busbar_kernel_ledger::cost::MoneyError> {
        use busbar_kernel_ledger::usage::{price_dated_counts_raw, DatedHistory};
        let history = crate::rate_apply::dated_history();
        let dated = history.as_deref().map(DatedHistory::of);
        let fees = (self.fee_eras.split(self.billable_requests)).filter(|_| include_fee);
        let rows = self.models.iter().map(|m| (&*m.model, m.era, &m.cur));
        let start_ms = self.window_start.saturating_mul(1_000);
        price_dated_counts_raw(rows, fees, start_ms, cost.card(), dated)
    }

    /// The periodic shard sweep's model prune, on one cell (the sweep itself is off-path).
    #[cfg(test)]
    fn prune_dead_models(&mut self) {
        crate::off_path::governance::state::mod_prune_dead_models(self);
    }

    #[cfg(test)]
    fn advance_model_baselines(&mut self, acked: &[ModelCell], dated: bool) {
        self.mutate(|cell| {
            for s in acked {
                let at = (cell.models.iter()).position(|m| m.model == s.model && m.era == s.era);
                match at {
                    Some(i) => {
                        if dated {
                            cell.models[i].flushed_era = s.cur.clone();
                        } else {
                            cell.models[i].flushed = s.cur.clone();
                        }
                    }
                    None if has_units(&s.cur) => {
                        let (flushed, flushed_era) = if dated {
                            (Default::default(), s.cur.clone())
                        } else {
                            (s.cur.clone(), Default::default())
                        };
                        cell.models.extend(ModelCell::new(
                            s.model.clone(),
                            s.era,
                            std::collections::BTreeMap::new(),
                            flushed,
                            flushed_era,
                        ));
                        cell.dirty = true;
                    }
                    None => {}
                }
            }
        });
    }

    fn total_tokens(&self) -> Count {
        token_total(self.models.iter().map(|m| &m.cur))
    }

    #[cfg(test)]
    fn total_tier(&self, unit: &str) -> Count {
        Count::total(
            self.models
                .iter()
                .map(|m| class_total(&m.model, &m.cur, unit).expect("validated class total")),
        )
        .expect("total raw counts exceed Count range")
    }
}

pub(crate) const ERA_FEE_UNIT: &str = "billable_requests";

const ERA_BUCKET_PREFIX: &str = "e:";

pub(crate) const ERA_MODEL_SEP: char = '\u{1f}';

const RAW_ERA_PREFIX: &str = "busbar.raw-era.v1:";

/// An era's stored tag, written straight into whatever text holds it (no intermediate String).
struct EraTag(RawRateEra);

impl std::fmt::Display for EraTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.entry_id {
            Some(id) => write!(f, "{RAW_ERA_PREFIX}{}:{id}", self.0.effective_from),
            None => write!(f, "{}", self.0.effective_from),
        }
    }
}

pub(crate) fn era_tag(era: RawRateEra) -> String {
    era_text(EraTag(era))
}

/// The one owned rendering of a stored ledger name (era tag, era-qualified model, dated bucket).
/// Each is a key of a durable ledger row, built when that row is written, read or corrected.
pub(crate) fn era_text(name: impl std::fmt::Display) -> String {
    crate::off_path::governance::state::mod_era_text(&name)
}

pub(crate) fn parse_era_tag(tag: &str) -> RecordStoreResult<Option<RawRateEra>> {
    if let Some(body) = tag.strip_prefix(RAW_ERA_PREFIX) {
        let parsed = body.split_once(':').and_then(|(at, id)| {
            Some(RawRateEra::entry(at.parse().ok()?, EntryId::parse_hex(id)?))
        });
        return parsed
            .map(Some)
            .ok_or_else(|| RecordStoreError("malformed versioned raw rate provenance".into()));
    }
    Ok(tag.parse::<u64>().ok().map(RawRateEra::legacy))
}

pub(crate) fn era_model(era: RawRateEra, model: &str) -> String {
    era_text(format_args!("{}{ERA_MODEL_SEP}{model}", EraTag(era)))
}

fn dated_delta(delta: &UsageDelta, era: RawRateEra) -> UsageDelta {
    crate::off_path::governance::state::mod_dated_delta(delta, era)
}

fn park_window(parked: &mut Vec<(u64, ExactUsageDelta)>, window: u64, delta: ExactUsageDelta) {
    if delta.is_zero() {
        return;
    }
    if let Some(index) = parked.iter().position(|(at, _)| *at == window) {
        parked[index].1.merge(&delta);
        if parked[index].1.is_zero() {
            // Order is immaterial: every reader selects a parked window by its identity.
            parked.swap_remove(index);
        }
    } else {
        parked.push((window, delta));
    }
}

pub(crate) fn era_bucket(bucket: &str) -> String {
    let digest = busbar_contract::crypto::sha256(bucket.as_bytes());
    era_text(EraBucket(&digest[..16]))
}

/// A dated bucket's stored name: the prefix, then the lowercase hex of the digest prefix.
struct EraBucket<'a>(&'a [u8]);

impl std::fmt::Display for EraBucket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(ERA_BUCKET_PREFIX)?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

pub fn is_token_class(class: &str) -> bool {
    use crate::plane_driver::registry::{plane_decls, TOKEN_FAMILY};
    busbar_contract::records::RESERVED_UNITS.contains(&class)
        || plane_decls().iter().any(|d| {
            (d.billable_classes.iter()).any(|c| c.family == TOKEN_FAMILY && c.class == class)
        })
}

/// Project one class's raw disjoint count plus its descendants, in its owning plane only.
/// This is a reporting/cap view: never persist or price the result as raw usage.
pub fn class_total(
    lane: &str,
    counts: &std::collections::BTreeMap<String, Count>,
    class: &str,
) -> Result<Count, CountError> {
    let owner = class_owner(lane);
    Count::total(
        counts
            .iter()
            .filter(|(raw, _)| {
                if raw.as_str() == class {
                    return true;
                }
                let Some(owner) = owner else {
                    return false;
                };
                let mut child = raw.as_str();
                // Bound traversal even for an internal fixture that bypassed declaration admission.
                for _ in 0..owner.class_parents.len() {
                    let Some(edge) = owner.class_parents.iter().find(|edge| edge.child == child)
                    else {
                        break;
                    };
                    if edge.parent == class {
                        return true;
                    }
                    child = edge.parent;
                }
                false
            })
            .map(|(_, count)| *count),
    )
}

pub(crate) fn class_owner(lane: &str) -> Option<&'static crate::plane_driver::registry::PlaneDecl> {
    let (plane, _) = busbar_kernel_ledger::cost::split_plane_lane(lane);
    crate::plane_driver::registry::plane_decls()
        .iter()
        .copied()
        .find(|d| {
            if plane.is_empty() {
                d.fallback
            } else {
                d.key == plane
            }
        })
}

/// Per-class reporting views, including declared ancestor totals. These views overlap;
/// total token limits and spend must continue to use the disjoint raw counts.
pub fn token_series(
    lane: &str,
    counts: &std::collections::BTreeMap<String, Count>,
) -> Vec<(String, Count)> {
    crate::off_path::governance::state::mod_token_series(lane, counts)
}

fn token_total<'a>(
    maps: impl Iterator<Item = &'a std::collections::BTreeMap<String, Count>>,
) -> Count {
    Count::total(
        maps.flat_map(|m| m.iter())
            .filter(|(k, _)| is_token_class(k))
            .map(|(_, n)| *n),
    )
    .expect("total raw counts exceed Count range")
}

pub(crate) fn has_units(units: &std::collections::BTreeMap<String, Count>) -> bool {
    units.values().any(|count| !count.is_zero())
}

pub(crate) fn whole_count(n: u64) -> Count {
    Count::from_integer(i128::from(n)).expect("u64 whole units fit Count")
}
fn whole_counts(
    units: &std::collections::BTreeMap<String, u64>,
) -> std::collections::BTreeMap<String, Count> {
    crate::off_path::governance::state::mod_whole_counts(units)
}

/// Why an admission was refused by the group limit chain - carried to ingress so the rejection
/// NAMES the exact blocking bucket (group + metric + window). Built only on the rejection path
/// (cold), so the owned Strings are off the admit hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitBlocked {
    /// A specific limit bucket blocked: the owning group, the metric (`requests` | `tokens` |
    /// `budget` | `concurrent`), the window word (`None` for the instantaneous `concurrent`
    /// gauge), the pool scope (`Some` when a pool-qualified limit blocked - only that pool's
    /// traffic is capped), and - for a windowed limit - the seconds until its window rolls
    /// (`None` for `total`, which never rolls).
    Limit {
        group: String,
        metric: &'static str,
        window: Option<&'static str>,
        pool: Option<String>,
        /// For a BUDGET block whose limit declared `on_exhaust: downgrade`: the pool ingress
        /// should re-admit + dispatch through instead of refusing. `None` = block.
        downgrade_to: Option<String>,
        retry_after: Option<u64>,
    },
    /// A group in the chain is FROZEN (`enabled: false`): every request charging through it is
    /// rejected while its history is kept.
    Disabled(String),
    /// The key names a `group` that does not exist in this node's config - FAIL-CLOSED
    /// (mint and boot validate this; it can only arise from a shared durable store whose keys
    /// reference a group another node's config no longer has).
    MissingGroup(String),
    /// The gateway is shutting down: governed admission closed at the drain's request cut.
    Draining,
    /// The terminal backlog (finished units awaiting settlement) reached its cap.
    CustodyFull { backlog: u64, cap: u64 },
}

/// WHAT ONE ADMISSION'S FEE CHARGE REACHED, carried from the charge to its refund (the design's
/// money section: a refund returns the bucket actually charged). Per bucket, the window of the cell
/// the fee landed on — the request's own window, or the newer one a concurrent admission had
/// already rolled the cell to — the fee lane it landed on (`None`: the flat fee base), and the card
/// era it was charged under (`era_at` of the admission instant). Read back only by
/// [`GovState::refund_charge`]; a refund never re-derives any of it from a clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeCharge {
    lane: Option<String>,
    era: RawRateEra,
    cells: Vec<(String, u64)>,
    chain: Option<crate::cost::ChainPlan>,
}

impl FeeCharge {
    pub fn raw_era(&self) -> RawRateEra {
        self.era
    }

    /// The key's budget chain the admission charged through, resolved once and carried to the
    /// unit's settlement (SINGLE-PATH SP-AD1).
    pub fn chain(&self) -> Option<&crate::cost::ChainPlan> {
        self.chain.as_ref()
    }
}

/// The in-flight HOLD an admission acquires on every `concurrent`-capped group in the key's chain,
/// and the [`FeeCharge`] its fee reached.
/// RAII: dropping the grant releases the gauges, so the in-flight count can never leak - the grant
/// rides inside the request's `UsageSink` (dropped when the response stream completes / the request
/// context unwinds on any error path). The Vec is EMPTY (no allocation) for the common chain with
/// no concurrent caps.
#[derive(Default)]
pub struct AdmitGrant {
    gauges: Vec<Arc<std::sync::atomic::AtomicI64>>,
    charge: FeeCharge,
    /// The governed admission gate's count (SHUTDOWN-HANG F4a), released when the grant drops,
    /// which is after its unit's terminal checkpoint is staged.
    hold: Option<drain::GateHold>,
}

impl AdmitGrant {
    pub fn charge(&self) -> &FeeCharge {
        &self.charge
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.gauges.len()
    }
}

impl Drop for AdmitGrant {
    fn drop(&mut self) {
        for g in &self.gauges {
            g.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for AdmitGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitGrant")
            .field("gauges", &self.gauges.len())
            .finish()
    }
}

pub const REVOCATION_SYNC_TTL_SECS: u64 = 5;

const GOV_SHARDS: usize = 64;

mod sharded;
use sharded::Sharded;

#[derive(Default)]
struct GovCaches {
    revision: u64,
    key_revisions: HashMap<String, u64>,
    credential_revisions: HashMap<String, u64>,
    by_id: HashMap<String, Arc<VirtualKey>>,

    by_credential: CredentialIndex,
}

pub(crate) type CredentialIndex = HashMap<(String, String), (Arc<VirtualKey>, CredentialSecret)>;

pub struct GovState {
    /// The last authoritative observation total per bucket, per window.
    observation_view:
        RwLock<HashMap<String, HashMap<u64, crate::persistence::observations::BudgetTotal>>>,
    core: Arc<crate::persistence::facade::CoreStore>,
    identity_claims: claims::AsyncClaimSet<IdentityClaimKey>,

    caches: Arc<RwLock<GovCaches>>,

    concurrent: RwLock<HashMap<String, Arc<std::sync::atomic::AtomicI64>>>,

    admin_token_hash: RwLock<Option<String>>,

    budget: Sharded<BudgetCell>,

    recovery_book: recovery::RecoveryBook,

    unit_checkpoints: unit_checkpoint::UnitCheckpointBook,

    /// The one governed admission gate (SHUTDOWN-HANG F4a).
    admissions: Arc<drain::AdmissionGate>,

    correction_claims: claims::AsyncClaimSet<String>,

    corrections: std::sync::Mutex<HashMap<String, state::ledger_adjust::PendingCorrection>>,
    ticket_operations: tickets::TicketOperations,

    budget_flushes:
        std::sync::Mutex<std::collections::BTreeMap<(String, u64), Arc<BudgetFlushFlight>>>,

    budget_flush_runner: BudgetFlushRunner,

    deleting_budget_buckets: std::sync::Mutex<std::collections::BTreeSet<String>>,

    pending_metering: PendingMetering,

    money_view: state::money_view::MoneyView,

    signing: RwLock<Option<Arc<SigningMaterial>>>,

    at_rest: RwLock<Option<Arc<at_rest::AtRestKeys>>>,

    denylist: Arc<revocation::RevocationSync>,

    refresh_order: Arc<CacheOrder>,

    #[cfg(test)]
    identity_wait_observer: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,

    transition_self_holds: RwLock<std::collections::BTreeSet<String>>,

    caller_refs: crate::plane_driver::CallerRefs,

    deployment_caller_ref: RwLock<Option<[u8; 32]>>,

    amendments: Arc<crate::audit::amend::NodeAmendments>,

    boot_caller_ref: busbar_contract::secure::SecureArray<32>,
}

/// The order of the key caches' writes (see `GovState::refresh_order`). Every reload takes a
/// TICKET before it reads the store and every targeted patch takes one when it applies, from one
/// counter, so a higher ticket means a later start. A reload swaps only if no reload with a later
/// ticket already swapped (that one began after this caller's mutation, so it carries it) and no
/// patch with a later ticket was applied (this load may predate the patch's writes, so it reloads).
/// The mutex is held only to take a ticket and to swap or patch, never across a store call.
#[derive(Default)]
pub(crate) struct CacheOrder {
    seq: std::sync::Mutex<CacheSeq>,
}

#[derive(Default)]
struct CacheSeq {
    /// The last ticket handed out.
    next: u64,
    /// The ticket of the reload whose snapshot is in the caches.
    swapped: u64,
    /// The ticket of the last targeted patch applied.
    patched: u64,
}

pub(crate) enum CacheTurn<'a> {
    Swap(CacheTurnGuard<'a>),

    Stale,

    Reload,
}

pub(crate) struct CacheTurnGuard<'a> {
    seq: std::sync::MutexGuard<'a, CacheSeq>,
    ticket: u64,
}

impl Drop for CacheTurnGuard<'_> {
    fn drop(&mut self) {
        self.seq.swapped = self.ticket;
    }
}

impl CacheOrder {
    fn lock(&self) -> std::sync::MutexGuard<'_, CacheSeq> {
        self.seq.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn ticket(&self) -> u64 {
        let mut seq = self.lock();
        seq.next += 1;
        seq.next
    }

    pub(crate) fn turn(&self, ticket: u64) -> CacheTurn<'_> {
        let seq = self.lock();
        if ticket < seq.swapped {
            CacheTurn::Stale
        } else if ticket < seq.patched {
            CacheTurn::Reload
        } else {
            CacheTurn::Swap(CacheTurnGuard { seq, ticket })
        }
    }

    pub(crate) fn patch<R>(&self, apply: impl FnOnce() -> R) -> R {
        let mut seq = self.lock();
        seq.next += 1;
        seq.patched = seq.next;
        apply()
    }
}

pub struct SigningMaterial {
    signer: crate::governance::signing::TokenSigner,
    verifier: crate::governance::signing::TokenVerifier,
}

impl SigningMaterial {
    fn new(signer: crate::governance::signing::TokenSigner) -> Self {
        let verifier =
            crate::governance::signing::TokenVerifier::single(signer.kid(), signer.verifying_key());
        Self { signer, verifier }
    }
}

pub struct RotatedCredential {
    pub key: VirtualKey,
    pub token: busbar_contract::redacted::Secret<String>,
    pub exp: u64,
}

pub mod revocation;

pub mod claims;

pub mod at_rest;

pub mod mint_policy;

pub mod group_provision;

mod state;
pub use state::identity_runtime::{IdentityClaimKey, IdentityMutationGuard};
pub(crate) use state::key_row_expired;
pub use state::{
    metering_lane, self_subject_id, AdjustRefused, Adjustment, KeyMutationError, MintError,
    PricedBucket, UsageAdjustment, ADJUST_DOWN_BUCKET, ADJUST_UP_BUCKET,
};

pub(crate) mod tickets;
pub(crate) use tickets::{
    legacy_ticket_authorizes, legacy_ticket_expiry, legacy_ticket_record, legacy_ticket_token,
    VerifiedTicket,
};
pub use tickets::{
    ticket_record_live, ticket_records_live, TicketRefusal, TICKET_RECORD_KIND, TICKET_SPENT_KIND,
};

/// Which native asynchronous self-serve mint operation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfMintOp {
    Issue,
    Refresh,
}

/// Why the self-serve mint refused to issue: an admin's, another provider's or the subject's own
/// hold, never a store failure. The token exchange answers each one 403 with BUSBAR-4043 and the
/// reason ([`SelfMintRefusal::message`]); the hosted login shows it on its own page. Only an admin
/// clears a hold: `PATCH {enabled:true}` for a disabled key, `DELETE` (the reset) for any key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfMintRefusal {
    /// The subject holds a self-serve binding an admin disabled and has not deleted. A login or
    /// refresh must not re-enable it or route around it with a fresh key.
    Disabled,
    /// The subject's binding was minted through a different identity provider
    /// ([`busbar_contract::records::VirtualKey::idp_provider`]).
    OtherProvider,
    /// The subject's binding was revoked (denylisted). Revoked is terminal: no login, refresh or
    /// admin PATCH brings that key back; only an admin DELETE resets the subject.
    Revoked,
    /// The subject itself is held (a principal transition today), whatever its keys say.
    Held,
}

impl SelfMintRefusal {
    /// The stable token naming this hold in the admin log (`key:<id>#<token>`) and in diagnostics.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::OtherProvider => "other_provider",
            Self::Revoked => "revoked",
            Self::Held => "on_hold",
        }
    }

    /// The user-facing reason. Names no other party: not the admin, not the other provider.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Disabled => {
                "an administrator disabled it; ask your Busbar administrator to re-enable or \
                 delete it"
            }
            Self::Revoked => {
                "an administrator revoked it, and a revoked key is never re-enabled; ask your \
                 Busbar administrator to delete it so your next sign-in issues a new key"
            }
            Self::OtherProvider => {
                "it was issued through a different sign-in provider; sign in with that provider, \
                 or ask your Busbar administrator to delete it"
            }
            Self::Held => "your account is on hold; ask your Busbar administrator",
        }
    }

    /// The coded refusal the exchange body and the hosted page carry (BUSBAR-4043).
    #[must_use]
    pub fn message(self) -> String {
        crate::diagnostics::coded(
            &crate::diagnostics::SELF_MINT_HELD,
            format_args!("your self-serve key is on hold: {}", self.reason()),
        )
    }

    /// Which hold a subject with several held rows answers: the most final one.
    pub(crate) fn precedence(self) -> u8 {
        match self {
            Self::OtherProvider => 1,
            Self::Disabled => 2,
            Self::Revoked => 3,
            Self::Held => 4,
        }
    }
}

/// A self-serve mint failure: a typed refusal, or the store failing underneath the mint.
#[derive(Debug)]
pub enum SelfMintError {
    /// The mint was refused (see [`SelfMintRefusal`]); nothing was written.
    Refused(SelfMintRefusal),
    /// The store failed.
    Store(RecordStoreError),
}

impl From<RecordStoreError> for SelfMintError {
    fn from(e: RecordStoreError) -> Self {
        SelfMintError::Store(e)
    }
}

impl std::fmt::Display for SelfMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelfMintError::Refused(SelfMintRefusal::Disabled) => {
                f.write_str("self-serve mint refused: the subject's binding is disabled")
            }
            SelfMintError::Refused(SelfMintRefusal::OtherProvider) => f.write_str(
                "self-serve mint refused: the subject's binding was minted by another identity \
                 provider",
            ),
            SelfMintError::Refused(SelfMintRefusal::Revoked) => {
                f.write_str("self-serve mint refused: the subject's binding is revoked")
            }
            SelfMintError::Refused(SelfMintRefusal::Held) => {
                f.write_str("self-serve mint refused: the subject is on hold")
            }
            SelfMintError::Store(e) => e.fmt(f),
        }
    }
}

pub async fn mint_self_offloaded(
    gov: Arc<GovState>,
    op: SelfMintOp,
    user_sub: String,
    provider: String,
    allowed_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
    exp: u64,
    now: u64,
) -> Result<(VirtualKey, String), SelfMintError> {
    match op {
        SelfMintOp::Issue => {
            gov.issue_self_scoped(&user_sub, &provider, allowed_scopes, exp, now)
                .await
        }
        SelfMintOp::Refresh => {
            gov.refresh_self_scoped(&user_sub, &provider, allowed_scopes, exp, now)
                .await
        }
    }
}

pub fn synthesize_principal_key(
    principal: &crate::auth::Principal,
    bindings: Option<&std::collections::BTreeMap<String, crate::config::RoleBindingCfg>>,
) -> Option<Arc<VirtualKey>> {
    synthesize_key(principal, bindings).map(|mut key| {
        key.generation_hash = crate::off_path::governance::state::mod_principal_marker(
            PRINCIPAL_MARKER_PREFIX,
            &principal.id,
        );
        Arc::new(key)
    })
}

pub const PRINCIPAL_MARKER_PREFIX: &str = "principal:";

pub fn synthesize_bound_key(
    module: &str,
    principal: &crate::auth::Principal,
    role_bindings: &crate::config::RoleBindings,
) -> Option<Arc<VirtualKey>> {
    /// The bound marker's JSON, serialized from borrows (keys in the order `json!` sorted them).
    #[derive(serde::Serialize)]
    struct Marker<'a> {
        id: &'a str,
        module: &'a str,
        roles: &'a [String],
    }
    let mut key = synthesize_key(principal, role_bindings.get(module))?;
    // The synthesized key carries no marker yet: write the prefix and serialize the marker
    // straight after it, into the key's own generation text.
    let mut marker = std::mem::take(&mut key.generation_hash).into_bytes();
    marker.extend_from_slice(PRINCIPAL_MARKER_PREFIX.as_bytes());
    let fields = Marker {
        id: &principal.id,
        module,
        roles: &principal.roles,
    };
    busbar_contract::json::to_writer(&mut marker, &fields)
        .expect("a borrowed marker always serializes");
    key.generation_hash = String::from_utf8(marker).expect("the JSON writer writes UTF-8");
    Some(Arc::new(key))
}

pub fn bound_admission(key: &VirtualKey) -> Option<(String, crate::auth::Principal)> {
    #[derive(serde::Deserialize)]
    struct Marker {
        id: String,
        module: String,
        roles: Vec<String>,
    }
    let json = key.generation_hash.strip_prefix(PRINCIPAL_MARKER_PREFIX)?;
    let m: Marker = busbar_contract::json::parse_str(json).ok()?;
    if m.id != key.id {
        return None;
    }
    Some((
        m.module,
        crate::auth::Principal {
            id: m.id,
            name: Some(key.name.clone()),
            roles: m.roles,
            ttl_secs: None,
        },
    ))
}

pub struct LiveResolve<'a> {
    pub governance: Option<&'a GovState>,

    pub role_bindings: &'a crate::config::RoleBindings,
}

impl crate::trust::validate::GovResolve for LiveResolve<'_> {
    fn resolve_by_sub(&self, sub: &str) -> Option<Arc<VirtualKey>> {
        self.governance.and_then(|g| g.lookup_by_sub(sub))
    }

    fn resolve_bound(
        &self,
        module: &str,
        principal: &crate::auth::Principal,
    ) -> Option<Arc<VirtualKey>> {
        synthesize_bound_key(module, principal, self.role_bindings)
    }
}

pub(crate) fn granting_bindings<'a>(
    principal: &crate::auth::Principal,
    table: &'a std::collections::BTreeMap<String, crate::config::RoleBindingCfg>,
) -> GrantingBindings<'a> {
    let ungoverned = crate::config::auth::UNGOVERNED_ROLE;
    let named = |role: &&String| role.as_str() != ungoverned;
    // A principal holds a handful of roles: the granting list stays inline on the stack.
    let mut granting = GrantingBindings::new();
    granting.extend(
        principal
            .roles
            .iter()
            .filter(named)
            .filter_map(|role| table.get(role)),
    );

    let roleless = !principal.roles.iter().any(|r| named(&r));
    let only_ungoverned = table.keys().all(|r| r == ungoverned);
    match table.get(ungoverned) {
        Some(binding) if granting.is_empty() && (roleless || only_ungoverned) => {
            granting.push(binding);
            granting
        }
        _ => granting,
    }
}

/// The role bindings that grant a principal access, inline for ordinary role counts.
pub(crate) type GrantingBindings<'a> = smallvec::SmallVec<[&'a crate::config::RoleBindingCfg; 4]>;

pub(crate) fn grant_union(
    granting: &[&crate::config::RoleBindingCfg],
) -> Option<Vec<busbar_contract::records::ScopeRef>> {
    let mut union: Vec<busbar_contract::records::ScopeRef> = Vec::new();
    for b in granting {
        for scope in b.scope_grant()? {
            if !union.contains(&scope) {
                union.push(scope);
            }
        }
    }
    Some(union)
}

pub fn grant_scopes(
    pools: Option<Vec<String>>,
    plane: Option<Vec<busbar_contract::records::ScopeRef>>,
) -> Option<Vec<busbar_contract::records::ScopeRef>> {
    crate::off_path::governance::state::mod_grant_scopes(pools, plane)
}

pub fn plane_grant_kind(field: &str) -> Option<String> {
    busbar_contract::records::scope_kinds::kind_for_wire_field(field)
        .filter(|kind| !kind.is_empty() && kind != "pool")
}

pub fn plane_declares_kind(kind: &str) -> bool {
    kind != "pool" && crate::plane_driver::registry::scope_kind_index(kind).is_some()
}

pub(crate) fn pool_scopes(
    allowed_pools: Option<Vec<String>>,
) -> Option<Vec<busbar_contract::records::ScopeRef>> {
    let list = allowed_pools?;
    Some(crate::off_path::governance::state::mod_pool_scopes(list))
}

fn synthesize_key(
    principal: &crate::auth::Principal,
    bindings: Option<&std::collections::BTreeMap<String, crate::config::RoleBindingCfg>>,
) -> Option<VirtualKey> {
    if principal.id.starts_with(crate::cost::GROUP_BUCKET_PREFIX)
        || principal.id.starts_with(VK_ID_PREFIX)
    {
        diag_debug!(
            GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION,
            principal = %principal.id,
            "refusing to synthesize a governance key: principal id collides with a reserved bucket \
             namespace (group: or vk_)"
        );
        return None;
    }
    let granting = granting_bindings(principal, bindings?);
    if granting.is_empty() {
        return None;
    }

    let allowed_scopes = match grant_union(&granting) {
        Some(list) if list.is_empty() => return None,
        union => union,
    };

    let group = granting.iter().find_map(|b| b.group.clone());
    Some(VirtualKey {
        id: principal.id.clone(),

        // Each caller writes its own marker: the principal marker or the bound marker.
        generation_hash: String::new(),
        name: principal
            .name
            .clone()
            .unwrap_or_else(|| principal.id.clone()),
        allowed_scopes,
        enabled: true,
        created_at: 0,
        group,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    })
}

pub use busbar_contract::records::PlaneRequestCtx;

pub type GovCtx = busbar_contract::records::PlaneRequestCtx;

pub(crate) fn issue_credential(
    shape: &busbar_contract::auth_calls::IssuedShape,
) -> Result<(String, String), busbar_contract::crypto::RngError> {
    crate::off_path::governance::state::mod_issue_credential(shape)
}

pub fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.scope_allowed("pool", pool)
}

pub fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        WINDOW_MINUTE => now / 60 * 60,
        WINDOW_HOUR => now / 3600 * 3600,
        WINDOW_DAY => now / SECS_PER_DAY * SECS_PER_DAY,
        WINDOW_MONTH => month_window_days(now).0 * SECS_PER_DAY,
        WINDOW_TOTAL => 0,

        other => {
            diag_warn!(
                LIMIT_WINDOW_UNRECOGNIZED,
                window = other,
                "unrecognized limit window; enforcing as all-time ('total') window"
            );
            0
        }
    }
}

pub fn window_end(period: &str, now: u64) -> Option<u64> {
    match period {
        WINDOW_MINUTE => Some(now / 60 * 60 + 60),
        WINDOW_HOUR => Some(now / 3600 * 3600 + 3600),
        WINDOW_DAY => Some(now / SECS_PER_DAY * SECS_PER_DAY + SECS_PER_DAY),
        WINDOW_MONTH => Some(month_window_days(now).1 * SECS_PER_DAY),
        _ => None,
    }
}

/// The calendar month holding `now`, as (first day, first day of the next month) in days since the
/// epoch, on the `time` calendar (DEPENDENCY-LADDER C10).
fn month_window_days(now: u64) -> (u64, u64) {
    let days = now / SECS_PER_DAY;
    let date = busbar_contract::civil::date_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let start = days.saturating_sub(u64::from(date.day()) - 1);
    (start, start + u64::from(date.month().length(date.year())))
}

pub use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, RecordStoreError,
    RecordStoreResult, SecretForm, UsageDelta, VirtualKey,
};

#[cfg(test)]
pub use busbar_contract::records::UsageLedger;

#[cfg(test)]
pub use busbar_contract::records::ScopeRef;

pub use busbar_kernel_ledger::cost::PLANE_LANE_SEP;

/// One `pending_metering` entry: the counters `MeteringDelta` carries, accumulated in-memory across
/// every `record_metering` (and, for [`Self::usage_units`], every `record_usage`) call that lands on
/// this key before the next flush.
#[derive(Default, Clone)]
pub struct MeterCounts {
    pub pricing: Option<busbar_contract::records::MeteringPricingV1>,
    pub requests: u64,
    pub tokens_input: Count,
    pub tokens_output: Count,
    pub tokens_cache_read: Count,
    pub tokens_cache_write: Count,
    pub usage_units: std::collections::BTreeMap<String, Count>,
}

impl MeterCounts {
    pub fn request(units: &std::collections::BTreeMap<String, Count>) -> Self {
        let [input, output, cache_read, cache_write] = busbar_contract::records::RESERVED_UNITS
            .map(|class| units.get(class).copied().unwrap_or_default());
        Self {
            pricing: None,
            requests: 1,
            tokens_input: input,
            tokens_output: output,
            tokens_cache_read: cache_read,
            tokens_cache_write: cache_write,
            usage_units: Default::default(),
        }
    }
    pub(crate) fn try_merge(&mut self, other: &Self) -> Result<(), CountError> {
        other.validate()?;
        let pricing = match (&self.pricing, &other.pricing) {
            (None, None) => None,
            (Some(before), Some(add)) => Some(before.checked_add(add)?),
            _ => return Err(CountError::Malformed),
        };
        // Every sum is checked before any field changes, so a refused merge leaves `self` exactly
        // as it was without copying it first.
        let requests = self
            .requests
            .checked_add(other.requests)
            .ok_or(CountError::Overflow)?;
        let tokens_input = self.tokens_input.checked_add(other.tokens_input)?;
        let tokens_output = self.tokens_output.checked_add(other.tokens_output)?;
        let tokens_cache_read = self
            .tokens_cache_read
            .checked_add(other.tokens_cache_read)?;
        let tokens_cache_write = self
            .tokens_cache_write
            .checked_add(other.tokens_cache_write)?;
        for (class, n) in &other.usage_units {
            let held = self.usage_units.get(class).copied().unwrap_or_default();
            held.checked_add(*n)?;
        }
        self.pricing = pricing;
        self.requests = requests;
        self.tokens_input = tokens_input;
        self.tokens_output = tokens_output;
        self.tokens_cache_read = tokens_cache_read;
        self.tokens_cache_write = tokens_cache_write;
        let checked = "unit sum checked before the counts changed";
        for (class, n) in &other.usage_units {
            match self.usage_units.get_mut(class) {
                Some(cur) => *cur = cur.checked_add(*n).expect(checked),
                None => {
                    let first = Count::default().checked_add(*n).expect(checked);
                    self.usage_units.insert(class.clone(), first);
                }
            }
        }
        Ok(())
    }
    pub fn merge(&mut self, other: impl std::borrow::Borrow<MeterCounts>) {
        self.try_merge(other.borrow())
            .expect("metering count accumulation exceeds Count range");
    }
    fn validate(&self) -> Result<(), CountError> {
        if let Some(pricing) = &self.pricing {
            pricing.validate_counts(
                self.requests,
                self.requests,
                !self.tokens_input.is_zero()
                    || !self.tokens_output.is_zero()
                    || !self.tokens_cache_read.is_zero()
                    || !self.tokens_cache_write.is_zero()
                    || has_units(&self.usage_units),
            )?;
        }
        if [
            self.tokens_input,
            self.tokens_output,
            self.tokens_cache_read,
            self.tokens_cache_write,
        ]
        .iter()
        .chain(self.usage_units.values())
        .any(|n| n.is_negative())
        {
            Err(CountError::Negative)
        } else {
            Ok(())
        }
    }
    pub fn is_zero(&self) -> bool {
        self.requests == 0
            && !self
                .pricing
                .as_ref()
                .is_some_and(|pricing| pricing.has_fee_evidence())
            && self.tokens_input.is_zero()
            && self.tokens_output.is_zero()
            && self.tokens_cache_read.is_zero()
            && self.tokens_cache_write.is_zero()
            && !has_units(&self.usage_units)
    }
}

pub type MeterKey = (String, u64, String, String, u64, String, String);

/// Full pending identity; the unchanged common tuple remains the legacy public accrual API.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MeterIdentity {
    pub common: MeterKey,
    pub role: Option<busbar_contract::records::MeteringRole>,
}

impl From<MeterKey> for MeterIdentity {
    fn from(common: MeterKey) -> Self {
        Self { common, role: None }
    }
}
impl std::ops::Deref for MeterIdentity {
    type Target = MeterKey;
    fn deref(&self) -> &Self::Target {
        &self.common
    }
}
impl std::ops::DerefMut for MeterIdentity {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

pub const MAX_PENDING_METERING: usize = 262_144;

pub const MAX_PENDING_METERING_PER_SHARD: usize = MAX_PENDING_METERING / GOV_SHARDS;

pub(crate) const METERING_OVERFLOW_KEY_ID: &str = "__busbar_pending_overflow__";

pub(crate) const METERING_OVERFLOW_LABEL: &str = "__aggregated__";

/// A metering cell's identity, borrowed from the request that accrues to it.
#[derive(Clone, Copy)]
pub(crate) struct MeterKeyRef<'a> {
    pub(crate) key_id: &'a str,
    pub(crate) bucket: u64,
    pub(crate) model: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) priced_from_ms: u64,
    pub(crate) key_group_at_use: &'a str,
    pub(crate) version: Option<EntryId>,
}

impl MeterKeyRef<'_> {
    /// Write this identity into `probe`, reusing its buffers (`version` as
    /// `EntryId::metering_version` spells it).
    fn fill(self, probe: &mut MeterIdentity) {
        use std::fmt::Write as _;
        probe.role = None;
        probe.0.clear();
        probe.0.push_str(self.key_id);
        probe.1 = self.bucket;
        probe.2.clear();
        probe.2.push_str(self.model);
        probe.3.clear();
        probe.3.push_str(self.provider);
        probe.4 = self.priced_from_ms;
        probe.5.clear();
        probe.5.push_str(self.key_group_at_use);
        probe.6.clear();
        if let Some(id) = self.version {
            let _ = write!(probe.6, "{}{id}", EntryId::METERING_VERSION_PREFIX);
        }
    }
}

/// The key an accrual looks its cell up by: an owned key, or the thread's reused probe, which is
/// copied only when its cell is first created.
enum PendingKey<'a> {
    Owned(MeterIdentity),
    Probe(&'a MeterIdentity),
}

impl PendingKey<'_> {
    fn get(&self) -> &MeterIdentity {
        match self {
            Self::Owned(key) => key,
            Self::Probe(key) => key,
        }
    }

    fn into_key(self) -> MeterIdentity {
        match self {
            Self::Owned(key) => key,
            Self::Probe(key) => MeterIdentity {
                common: crate::cold::governance::state::mod_meter_key_first(&key.common),
                role: key.role.clone(),
            },
        }
    }
}

fn accrue_pending_checked(
    pending: &mut HashMap<MeterIdentity, MeterCounts>,
    key: PendingKey<'_>,
    add: MeterCounts,
    cap: usize,
    warn: &CoalesceWarn,
) -> Result<(), CountError> {
    add.validate()?;
    if key.get().role != add.pricing.as_ref().map(|pricing| pricing.identity()) {
        return Err(CountError::Malformed);
    }
    if let Some(cell) = pending.get_mut(key.get()) {
        cell.try_merge(&add)?;
        return Ok(());
    }
    if pending.len() < cap {
        pending.insert(key.into_key(), add);
        return Ok(());
    }
    let key = key.get();

    // The accumulator is at cap (a store outage): coalesce into the bucket's overflow sentinel.
    if key.role.is_some() {
        return Err(CountError::OutOfRange);
    }
    let sentinel: MeterIdentity =
        crate::cold::governance::state::mod_overflow_sentinel(&key.common).into();
    pending.entry(sentinel).or_default().try_merge(&add)?;
    metrics::counter!(crate::snapshot::METERING_PENDING_COALESCED_TOTAL).increment(1);

    let noted = warn.note(crate::cold::governance::state::mod_overflow_instant());
    if let Some(coalesced) = noted {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::METERING_PENDING_OVERFLOW_COALESCED,
            overflow_bucket = key.1,
            coalesced,
            "metering accumulator at cap ({cap}); coalesced {coalesced} cell(s) into the per-bucket \
             overflow sentinel — totals preserved, per-key attribution collapsed until the store \
             recovers"
        );
    }
    Ok(())
}

/// The once-per-window throttle on the overflow-coalescing warning: counts coalesced cells and
/// releases the count at most once per [`COALESCE_WARN_WINDOW`].
#[derive(Default)]
pub(crate) struct CoalesceWarn(std::sync::Mutex<(Option<std::time::Instant>, u64)>);

pub(crate) const COALESCE_WARN_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

impl CoalesceWarn {
    fn note(&self, now: std::time::Instant) -> Option<u64> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.1 += 1;
        match g.0 {
            Some(last) if now.saturating_duration_since(last) < COALESCE_WARN_WINDOW => None,
            _ => {
                g.0 = Some(now);
                Some(std::mem::take(&mut g.1))
            }
        }
    }
}

pub struct PendingMetering {
    shards: Box<[std::sync::Mutex<HashMap<MeterIdentity, MeterCounts>>; GOV_SHARDS]>,
    coalesce_warn: CoalesceWarn,

    flight: std::sync::Mutex<std::collections::VecDeque<metering_flush::MeteringWrite>>,
    flush_runner: BudgetFlushRunner,
}

impl Default for PendingMetering {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingMetering {
    /// All rows of one selected unit, staged before any mutation. Selected attribution never
    /// enters the overflow sentinel; the caller retains the whole terminal on refusal.
    fn try_accrue_selected(
        &self,
        principal: &str,
        additions: &[(MeterIdentity, MeterCounts)],
    ) -> Result<std::sync::MutexGuard<'_, HashMap<MeterIdentity, MeterCounts>>, CountError> {
        let mut map = self
            .shard_for(principal)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut staged = std::collections::BTreeMap::<MeterIdentity, MeterCounts>::new();
        for (key, add) in additions {
            if key.0 != principal
                || key.role != add.pricing.as_ref().map(|pricing| pricing.identity())
            {
                return Err(CountError::Malformed);
            }
            let value = staged.entry(key.clone()).or_insert_with(|| {
                map.get(key).cloned().unwrap_or_else(|| MeterCounts {
                    pricing: add.pricing.as_ref().map(|pricing| pricing.zeroed()),
                    ..Default::default()
                })
            });
            value.try_merge(add)?;
        }
        let added = staged.keys().filter(|key| !map.contains_key(*key)).count();
        if map
            .len()
            .checked_add(added)
            .is_none_or(|count| count > MAX_PENDING_METERING_PER_SHARD)
        {
            return Err(CountError::OutOfRange);
        }
        map.extend(staged);
        Ok(map)
    }

    pub fn new() -> Self {
        Self {
            shards: Box::new(std::array::from_fn(|_| {
                std::sync::Mutex::new(HashMap::new())
            })),
            coalesce_warn: CoalesceWarn::default(),
            flight: std::sync::Mutex::new(std::collections::VecDeque::new()),
            flush_runner: BudgetFlushRunner::default(),
        }
    }

    #[inline]
    fn shard_for(&self, key_id: &str) -> &std::sync::Mutex<HashMap<MeterIdentity, MeterCounts>> {
        &self.shards[(busbar_kernel::store::key_hash_u64(key_id) as usize) & (GOV_SHARDS - 1)]
    }

    pub fn accrue(&self, key: MeterKey, add: MeterCounts) {
        self.try_accrue(key, add)
            .expect("metering accumulation exceeds Count range");
    }

    fn try_accrue(&self, key: MeterKey, add: MeterCounts) -> Result<(), CountError> {
        let mut map = self
            .shard_for(&key.0)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        accrue_pending_checked(
            &mut map,
            PendingKey::Owned(key.into()),
            add,
            MAX_PENDING_METERING_PER_SHARD,
            &self.coalesce_warn,
        )
    }

    /// [`Self::try_accrue`] for an identity borrowed from the request: the lookup key is this
    /// thread's reused probe, and an owned key is made only when the cell is first created.
    pub(crate) fn try_accrue_ref(
        &self,
        key: MeterKeyRef<'_>,
        add: MeterCounts,
    ) -> Result<(), CountError> {
        thread_local! {
            static PROBE: std::cell::RefCell<MeterIdentity> = const {
                std::cell::RefCell::new(MeterIdentity { common: (
                    String::new(),
                    0,
                    String::new(),
                    String::new(),
                    0,
                    String::new(),
                    String::new(),
                ), role: None })
            };
        }
        PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            key.fill(&mut probe);
            let mut map = self
                .shard_for(key.key_id)
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            accrue_pending_checked(
                &mut map,
                PendingKey::Probe(&probe),
                add,
                MAX_PENDING_METERING_PER_SHARD,
                &self.coalesce_warn,
            )
        })
    }

    /// Take every shard's pending counts, one shard at a time as the caller consumes them, so
    /// they move straight into the caller's flight without an intermediate list.
    pub fn drain(&self) -> impl Iterator<Item = (MeterIdentity, MeterCounts)> + '_ {
        self.shards.iter().flat_map(|shard| {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            if map.is_empty() {
                HashMap::new()
            } else {
                std::mem::take(&mut *map)
            }
        })
    }

    /// Metering cells pending in the shards plus writes in flight: a count only, for the
    /// shutdown drain's progress line (SHUTDOWN-HANG F4 "Progress"). Never on the request path.
    #[must_use]
    pub fn pending_cells(&self) -> usize {
        let mut len = 0usize;
        for shard in self.shards.iter() {
            len += shard.lock().unwrap_or_else(|e| e.into_inner()).len();
        }
        len + self.flight.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    #[cfg(test)]
    pub fn totals(&self) -> (usize, MeterCounts) {
        let mut len = 0usize;
        let mut sum = MeterCounts::default();
        for shard in self.shards.iter() {
            let map = shard.lock().unwrap_or_else(|e| e.into_inner());
            len += map.len();
            for counts in map.values() {
                sum.merge(counts.clone());
            }
        }
        let flight = self.flight.lock().unwrap_or_else(|p| p.into_inner());
        len += flight.len();
        for write in flight.iter() {
            sum.merge(write.counts());
        }
        (len, sum)
    }
}

trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, busbar_contract::crypto::RngError> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| {
            rendered_error(RecordStoreError, format_args!("OS CSPRNG unavailable: {e}"))
        })
    }
}

/// Wrap a failure's rendered text in one of the owned-message error types (`RecordStoreError`,
/// `RecoveryError::*`, ..). The text is the error's own payload, rendered once the operation has
/// already failed; a `format_args!` carries any context without an intermediate String.
pub(crate) fn rendered_error<E>(
    wrap: impl FnOnce(String) -> E,
    error: impl std::fmt::Display,
) -> E {
    wrap(crate::cold::governance::state::mod_error_text(&error))
}

/// The ascending, de-duplicated union of two ascending streams (two maps' keys), merged lazily:
/// the same sequence as collecting both into a `BTreeSet`, without building one.
pub(crate) fn sorted_union<T: Ord, A, B>(a: A, b: B) -> impl Iterator<Item = T>
where
    A: IntoIterator<Item = T>,
    B: IntoIterator<Item = T>,
{
    let (mut a, mut b) = (a.into_iter().peekable(), b.into_iter().peekable());
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) => match x.cmp(y) {
            std::cmp::Ordering::Less => a.next(),
            std::cmp::Ordering::Greater => b.next(),
            std::cmp::Ordering::Equal => {
                b.next();
                a.next()
            }
        },
        (Some(_), None) => a.next(),
        (None, _) => b.next(),
    })
}

/// Feeds serialized bytes straight into a running digest, so a fingerprint hashes the encoding
/// without first collecting it into a buffer.
pub(crate) struct DigestWriter<'a>(pub(crate) &'a mut crate::hashing::Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// [`rendered_error`] into the store's error type: `.map_err(store_error)`.
pub(crate) fn store_error(error: impl std::fmt::Display) -> RecordStoreError {
    rendered_error(RecordStoreError, error)
}

pub fn spawn_budget_flusher(
    gov: std::sync::Arc<GovState>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
    app: Option<Arc<crate::state::AppHandle>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_budget_flusher(gov, shutdown, app, None))
}

/// The drain-mode pass's idle wait between passes (SHUTDOWN-HANG F4 [M]).
pub const DRAIN_PASS_IDLE: std::time::Duration = std::time::Duration::from_millis(10);

/// Run in the root's host maintenance scope. Keeping every flush on this future
/// preserves that scope across awaits and avoids recursively metering journal IO.
/// A shutdown signal never cancels an in-flight native write: it is observed at
/// the next loop boundary, then the same task performs the final custody drain.
///
/// With a drain `clock` (SHUTDOWN-HANG F4 [M]) the shutdown arm is the money driver: it passes
/// back to back from the first broadcast until `money_stop` (or expiry), reading the stop before
/// every unit item, then runs the final budget and metering flushes and returns. Without one
/// (tests and callers that never drain) it runs one pass and the final flushes, as before.
pub async fn run_budget_flusher(
    gov: std::sync::Arc<GovState>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    app: Option<Arc<crate::state::AppHandle>>,
    clock: Option<Arc<drain::DrainClock>>,
) {
    let interval = std::time::Duration::from_millis(crate::limits::usage_flush_interval_ms());
    purge_usage_windows(&gov).await;
    // The purge cadence rides the runtime's timer: its first tick completes at once (the boot
    // purge above is that tick); later ticks are checked, never awaited, on each flush tick.
    let mut purge_due = tokio::time::interval(USAGE_PURGE_EVERY);
    purge_due.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    purge_due.tick().await;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if futures::FutureExt::now_or_never(purge_due.tick()).is_some() {
                    purge_usage_windows(&gov).await;
                }
                resume_current_correction_verdicts(&gov, app.as_ref()).await;
                if let Err(e) = gov.flush_unit_checkpoints().await {
                    tracing::warn!(error = ?e,
                        "flush_unit_checkpoints failed; retrying next tick");
                }
                gov.flush_budgets().await;
                gov.flush_metering().await;
            }
            _ = shutdown.recv() => {
                if let Some(clock) = &clock {
                    drain_money(&gov, app.as_ref(), clock, interval).await;
                    break;
                }
                resume_current_correction_verdicts(&gov, app.as_ref()).await;
                if let Err(e) = gov.flush_unit_checkpoints().await {
                    tracing::warn!(error = ?e,
                        "shutdown: flush_unit_checkpoints failed; checkpoint data may be stale on next start");
                }
                gov.flush_budgets_final().await;
                gov.flush_metering_final().await;
                break;
            }
        }
    }
}

/// SHUTDOWN-HANG F4 [M]: money persists concurrently with the request drain, from the first
/// broadcast until `money_stop`. The unit pass reads the halt before every item, so the final
/// budget and metering flushes are never starved by a backlog that cannot drain in the budget.
async fn drain_money(
    gov: &Arc<GovState>,
    app: Option<&Arc<crate::state::AppHandle>>,
    clock: &Arc<drain::DrainClock>,
    interval: std::time::Duration,
) {
    let halt = || clock.money_stopped() || clock.expired();
    let mut money_stop = clock.money_stop_rx();
    let mut expired = clock.expired_rx();
    loop {
        resume_current_correction_verdicts(gov, app).await;
        if let Err(e) = gov.flush_unit_checkpoints_until(&halt).await {
            tracing::warn!(error = ?e, "drain: unit checkpoints remain unresolved; retrying next pass");
        }
        if halt() {
            break;
        }
        gov.flush_budgets().await;
        gov.flush_metering().await;
        clock.note_pass();
        tokio::select! {
            _ = tokio::time::sleep(interval.min(DRAIN_PASS_IDLE)) => {}
            _ = money_stop.wait_for(|s| *s) => {}
            _ = expired.wait_for(|e| *e) => {}
        }
    }
    if !clock.expired() {
        resume_current_correction_verdicts(gov, app).await;
        gov.flush_budgets_final().await;
        gov.flush_metering_final().await;
    }
}

async fn resume_current_correction_verdicts(
    gov: &Arc<GovState>,
    app: Option<&Arc<crate::state::AppHandle>>,
) {
    let cost = app.and_then(|app| {
        let snapshot = app.load();
        snapshot
            .governance
            .as_ref()
            .filter(|current| Arc::ptr_eq(current, gov))
            .map(|_| snapshot.cost.clone())
    });
    if let Some(cost) = cost {
        if let Err(error) = gov.resume_correction_verdicts(&cost).await {
            diag_warn!(crate::diagnostics::BUDGET_FLUSH_PARTIAL_FAILURE,
                error = %error, "audited correction verdict remains retained for a later flush");
        }
    }
}

pub(crate) const USAGE_WINDOW_HORIZON_SECS: u64 = 31 * SECS_PER_DAY;

pub(crate) const USAGE_PURGE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub(crate) async fn purge_usage_windows(gov: &GovState) {
    let Ok(core) = gov.core_store() else {
        return;
    };
    let now = crate::store::now();
    let before = now.saturating_sub(USAGE_WINDOW_HORIZON_SECS);
    match core.ledger().prune_usage_before(before).await {
        Ok(purged) => tracing::debug!(
            purged,
            before,
            "usage ledger: windows past the horizon purged"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "usage ledger: pruning beyond the {}-day horizon failed; retained for retry",
            USAGE_WINDOW_HORIZON_SECS / SECS_PER_DAY
        ),
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/metering_flush_custody.rs"]
mod metering_flush_custody_tests;

#[cfg(test)]
#[path = "tests/native_ledger_fixture.rs"]
mod native_ledger_fixture;

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "tests/budget_cell_tests.rs"]
mod budget_cell_tests;

#[cfg(test)]
#[path = "tests/unit_checkpoint_race_tests.rs"]
mod unit_checkpoint_race_tests;

#[cfg(test)]
#[path = "tests/budget_shard_flush_tests.rs"]
mod budget_shard_flush_tests;

#[cfg(test)]
#[path = "tests/model_cell_constructor_rule.rs"]
mod model_cell_constructor_rule;

#[cfg(test)]
#[path = "tests/metering_recovery_live_append_tests.rs"]
mod metering_recovery_live_append_tests;

#[cfg(test)]
#[path = "../tests/key_expires_at_tests.rs"]
mod key_expires_at_tests;

pub mod signing;

/// Parameters for minting a new virtual key (from the management API) - PURE AUTH: identity,
/// pool grants, at most one group binding, labels. No limits: they live on the bound group.
///
/// `Default` (1.6.0) is a construction convenience so a call site names the fields it cares about and
/// leaves the 1.6.0 provenance/mode additions (`minted_by`/`binding_mode`) at `None` via
/// `..Default::default()` — an omitted-provenance mint is byte-identical to a pre-1.6.0 one.
#[derive(Default)]
pub struct NewKeySpec {
    pub name: String,
    /// Pool grants with the intent carried intact: `None` = the mint body OMITTED
    /// `allowed_pools` = ALL pools; `Some(list)` = exactly those; `Some([])` = NO pools.
    pub allowed_pools: Option<Vec<String>>,
    /// Plane-kind grants (`allowed_{kind}s` at mint, W9): `None` = the mint named no plane-kind
    /// field; `Some(list)` = it named at least one (the list possibly empty). Combined with
    /// `allowed_pools` by [`grant_scopes`]: naming any grant field makes the key's grant exactly
    /// the scopes named, across every kind.
    pub plane_scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
    /// Optional `groups:` binding (validated to exist at mint).
    pub group: Option<String>,
    /// Optional mint-time labels echoed onto metrics (never interpreted by enforcement).
    pub labels: std::collections::BTreeMap<String, String>,
    /// PROVENANCE (1.6.0): the principal that minted this key, recorded on
    /// [`busbar_contract::records::VirtualKey::minted_by`]. `Some` for an APP/service token minted through the
    /// admin API by a (possibly delegated) admin — the token OUTLIVES its minter (review H2/H3), and
    /// this enables "list tokens minted-by X" re-attestation + mint-ceiling accounting. `None` leaves
    /// the field unset (byte-identical to a pre-1.6.0 mint).
    pub minted_by: Option<String>,
    /// The BINDING MODE (1.6.0, wire spelling) recorded on [`busbar_contract::records::VirtualKey::binding_mode`].
    /// `Some("time-bound")` for an admin-minted app/service token (bounded by `exp`, no IdP tie);
    /// `None` leaves it unset.
    pub binding_mode: Option<String>,
    /// The admin grant (ADMIN-API r5 section 2.1), recorded on [`busbar_contract::records::VirtualKey::admin`].
    /// `None` for a data-plane key.
    pub admin: Option<busbar_contract::records::AdminGrant>,
}

pub const METERING_BUCKET_SECS: u64 = 86_400;

pub fn metering_bucket(now: u64) -> u64 {
    now - (now % METERING_BUCKET_SECS)
}

/// A derived (read-time) usage view for admin/metrics consumers: `spend_cents` is COMPUTED from
/// the token ledger, each era at the card in force when it was earned, at the moment of the
/// read - never stored.
///
/// A pure three-field figure with no engine dependency at all, so it lives HERE (the neutral
/// governance vocabulary) rather than in the engine: a plane's tests read it back off the neutral
/// registry seam (`testkit::engine_kit::GovKit::usage_for`), and the engine re-exports this very
/// type as `busbar_kernel::governance::DerivedUsage` — the same type, one home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DerivedUsage {
    /// The spend derived from the token ledger at the card in force per era, truncated to whole
    /// cents.
    pub spend_cents: i64,
    /// The token count the ledger holds for the bucket.
    pub tokens: Count,
    /// The admission count the ledger holds for the bucket.
    pub requests: u64,
}

pub const SECS_PER_DAY: u64 = 86_400;

#[cfg(test)]
trait TestWholeCount {
    fn whole_for_test(self) -> u64;
}
#[cfg(test)]
impl TestWholeCount for Count {
    fn whole_for_test(self) -> u64 {
        assert_eq!(
            self.micros() % 1_000_000,
            0,
            "expected an exact whole test quantity"
        );
        u64::try_from(self.micros() / 1_000_000).expect("nonnegative test count fits u64")
    }
}

#[cfg(test)]
trait TestLedgerCounts {
    fn tokens_for_whole_test(&self, model: &str) -> Option<u64>;
    fn total_whole_tokens_for_test(&self) -> u64;
}
#[cfg(test)]
impl TestLedgerCounts for busbar_contract::records::UsageLedger {
    fn tokens_for_whole_test(&self, model: &str) -> Option<u64> {
        self.models
            .iter()
            .find(|row| row.model == model)
            .map(|row| {
                Count::total(
                    row.usage_units
                        .values()
                        .map(|n| Count::from_stored(*n, row.scale).unwrap()),
                )
                .unwrap()
                .whole_for_test()
            })
    }
    fn total_whole_tokens_for_test(&self) -> u64 {
        Count::total(self.models.iter().flat_map(|row| {
            row.usage_units
                .iter()
                .filter(|(name, _)| {
                    busbar_contract::records::RESERVED_UNITS.contains(&name.as_str())
                })
                .map(|(_, n)| Count::from_stored(*n, row.scale).unwrap())
        }))
        .unwrap()
        .whole_for_test()
    }
}

#[cfg(test)]
fn stored_whole_for_test(raw: i128, scale: u32) -> u64 {
    Count::from_stored(raw, scale).unwrap().whole_for_test()
}
