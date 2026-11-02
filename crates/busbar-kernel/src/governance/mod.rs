// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_ledger::cost::{EntryId, RawRateEra};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

type RawFeeEras = busbar_kernel_ledger::usage::FeeEras<RawRateEra>;

mod exact_debt;
pub mod recovery;
use exact_debt::{BudgetFlushFlight, BudgetFlushRunner, ExactUsageDelta};
mod metering_flush;
mod raw_recovery;

use crate::diagnostics::{
    diag_debug, diag_warn, GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION, LIMIT_WINDOW_UNRECOGNIZED,
};

pub const WINDOW_TOTAL: &str = "total";

pub const WINDOW_DAY: &str = "day";

pub const WINDOW_MONTH: &str = "month";

pub const WINDOW_MINUTE: &str = "minute";

pub const WINDOW_HOUR: &str = "hour";

const VK_ID_PREFIX: &str = "vk_";

#[cfg(test)]
const SK_SECRET_PREFIX: &str = crate::test_support::governance::SK_SECRET_PREFIX;

pub const BINDING_MARKER_PREFIX: &str = "binding:";

pub const SELF_KEY_GROUP_PREFIX: &str = "user:";

pub const SELF_KEY_BINDING_MODE: &str = "user-bound";

pub const SELF_KEY_BINDING_MODE_APP: &str = "time-bound";

pub fn binding_marker(id: &str, generation: &str) -> String {
    format!("{BINDING_MARKER_PREFIX}{id}:{generation}")
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

pub(crate) fn generate_binding_generation() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    Ok(hex::encode(raw))
}

/// One model's in-cell token counters: the CURRENT tier tokens plus the last durably-ACKNOWLEDGED
/// (flushed) tier tokens - the additive-flush baseline, per model. The model name is an
/// `Arc<str>` interned ONCE per (bucket, model) on first sight (allocate-on-miss); the per-request
/// accrual after that is a linear scan over the few models the bucket actually used plus integer
/// adds - no hashing, no allocation.
#[derive(Clone)]
struct ModelCell {
    model: std::sync::Arc<str>,
    /// The card start and optional exact entry identity captured for these counts (Q14, #79).
    /// Only legacy zero is undated; a known opening entry remains distinct. One cell per
    /// (model, era), including distinct entries that share a start.
    era: RawRateEra,
    /// (1.6.0 M1b) The name-keyed CURRENT unit counters — the reserved four
    /// (`input`/`output`/`cache_read`/`cache_write`) are ordinary keys beside any open unit, the
    /// sole representation now that `TierTokens` is dissolved. Sparse (a zero unit is absent).
    cur: std::collections::BTreeMap<String, u64>,
    /// The last durably-ACKNOWLEDGED (flushed) unit counters — the additive-flush baseline.
    flushed: std::collections::BTreeMap<String, u64>,
    flushed_era: std::collections::BTreeMap<String, u64>,
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
struct BudgetCell {
    group_owners: std::collections::BTreeSet<String>,
    flushing: usize,
    /// Window identities still owned by off-lock flush snapshots.
    flushing_windows: std::collections::BTreeMap<u64, usize>,
    /// Both possible raw states of an unresolved correction. Ordinary mutations update both.
    correction: Option<Box<CorrectionBranch>>,
    window_start: u64,
    /// ADMISSION count: incremented once per admitted request, NEVER refunded. This backs the
    /// `requests`-LIMIT metric, so a caller cannot escape the requests cap by hammering failing
    /// requests (each still consumed a request slot at admission).
    requests: u64,
    /// BILLABLE request count: admitted requests MINUS non-2xx refunds. This backs the flat
    /// per-request-FEE component of the `budget` metric (the fee bills 2xx only), so budget spend
    /// derives from this, never from `requests`. Charged with `requests` at admission; a non-2xx
    /// outcome decrements ONLY this via `refund_bucket`.
    billable_requests: u64,
    /// The additive-flush watermark: durably acknowledged counts, or counts whose exact outbound
    /// debt has transferred to `budget_flushes`. That owner retains every unconfirmed chunk. Each
    /// flush writes only the DELTA (current - flushed) via `Store::add_usage`, then advances the
    /// baselines on success, so a shared store accumulates the TRUE fleet total across nodes. On
    /// a failed flush the baseline does not advance and the cell is re-marked dirty, so the
    /// unacked delta is retried (at-least-once: an ack lost after the write landed can
    /// double-count at most one flush interval - documented).
    flushed_requests: u64,
    /// The billable-request flush watermark (twin of `flushed_requests` for the fee-base counter).
    flushed_billable_requests: u64,
    /// Per-(model, era, tier) token counters + flush baselines. Small Vec (the models this bucket
    /// actually used), scanned linearly.
    models: Vec<ModelCell>,
    /// The fee base split by the card era each billable request was admitted under, so each fee
    /// prices at the card in force when that request was admitted.
    fee_eras: RawFeeEras,
    /// The fee eras' flush watermark (twin of `flushed_billable_requests`, per dated era).
    flushed_fee_eras: RawFeeEras,
    /// THE ROLLED WINDOWS' UNACKNOWLEDGED DELTAS, each under the window it was earned in. A roll to
    /// a newer window moves what the old window held past its last acknowledged flush here
    /// ([`BudgetCell::roll`]) instead of discarding it; `flush_budgets` drains them to the store
    /// under their OWN window and parks a failed one back, so a store outage across a boundary
    /// loses nothing. Empty in steady state.
    rolled: Vec<(u64, ExactUsageDelta)>,
    rolled_eras: Vec<(u64, ExactUsageDelta)>,
    dirty: bool,
    /// Wall-clock of the last accrual or admission charge. The eviction sweep ages cells by
    /// `window_start`, but a key's own bucket and a synthesized SSO principal's bucket both live in
    /// the all-time window (`window_start == 0`), which never ages — so those cells were retained
    /// for the process lifetime even after the key was deleted or the principal stopped appearing.
    /// `dirty` alone cannot substitute: the flusher clears it every 100ms, so a busy cell is
    /// legitimately clean and would be swept mid-use.
    last_touch: u64,
}

#[derive(Clone)]
struct CorrectionBranch {
    op_id: busbar_contract::abi::store::OpId,
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

    fn fresh(window_start: u64) -> Self {
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

    fn park(&mut self, window: u64, delta: UsageDelta) {
        self.mutate(|cell| {
            park_window(
                &mut cell.rolled,
                window,
                ExactUsageDelta::from_signed(&delta),
            );
        });
    }

    fn park_eras(&mut self, window: u64, delta: UsageDelta) {
        self.mutate(|cell| {
            park_window(
                &mut cell.rolled_eras,
                window,
                ExactUsageDelta::from_signed(&delta),
            );
        });
    }

    fn unflushed(&self) -> UsageDelta {
        ExactUsageDelta::of(self, false)
            .signed()
            .expect("legacy flush checks raw debt representability")
    }

    fn unflushed_eras(&self) -> UsageDelta {
        ExactUsageDelta::of(self, true)
            .signed()
            .expect("legacy flush checks raw debt representability")
    }

    #[cfg(test)]
    fn accrue(&mut self, model: &str, era: u64, units: &std::collections::BTreeMap<String, u64>) {
        self.accrue_raw(model, RawRateEra::legacy(era), units);
    }

    fn accrue_raw(
        &mut self,
        model: &str,
        era: RawRateEra,
        units: &std::collections::BTreeMap<String, u64>,
    ) {
        self.mutate(|cell| {
            let at = cell
                .models
                .iter()
                .position(|m| &*m.model == model && m.era == era);
            let cell = match at {
                Some(i) => &mut cell.models[i],
                None => {
                    cell.models.push(ModelCell {
                        model: std::sync::Arc::from(model),
                        era,
                        cur: std::collections::BTreeMap::new(),
                        flushed: std::collections::BTreeMap::new(),
                        flushed_era: std::collections::BTreeMap::new(),
                    });
                    cell.models.last_mut().expect("just pushed")
                }
            };
            for (k, v) in units {
                if *v == 0 {
                    continue;
                }
                let slot = cell.cur.entry(k.clone()).or_insert(0);
                *slot = slot.saturating_add(*v);
            }
        });
    }

    fn spend(
        &self,
        cost: &crate::cost::CostModel,
        include_fee: bool,
    ) -> Result<busbar_kernel_ledger::cost::Money, busbar_kernel_ledger::cost::MoneyError> {
        use busbar_kernel_ledger::usage::{price_dated_raw, DatedHistory};
        let history = crate::rate_apply::dated_history();
        let now_ms = crate::store::now_ms();
        let dated = history.as_deref().map(|h| DatedHistory::of(h, now_ms));
        let fees = (self.fee_eras.split(self.billable_requests)).filter(|_| include_fee);
        let rows = self.models.iter().map(|m| (&*m.model, m.era, &m.cur));
        let start_ms = self.window_start.saturating_mul(1_000);
        price_dated_raw(rows, fees, start_ms, cost.card(), dated)
    }

    fn prune_dead_models(&mut self) {
        if self.correction.is_some() {
            return;
        }
        self.models.retain(|m| {
            units_total(&m.cur) != 0
                || units_total(&m.flushed) != 0
                || units_total(&m.flushed_era) != 0
        });
    }

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
                    None if units_total(&s.cur) != 0 => {
                        cell.models.push(ModelCell {
                            model: s.model.clone(),
                            era: s.era,
                            cur: std::collections::BTreeMap::new(),
                            flushed: if dated {
                                Default::default()
                            } else {
                                s.cur.clone()
                            },
                            flushed_era: if dated {
                                s.cur.clone()
                            } else {
                                Default::default()
                            },
                        });
                        cell.dirty = true;
                    }
                    None => {}
                }
            }
        });
    }

    fn total_tokens(&self) -> u64 {
        token_total(self.models.iter().map(|m| &m.cur))
    }

    fn total_tier(&self, unit: &str) -> u64 {
        self.models.iter().fold(0u64, |acc, m| {
            acc.saturating_add(m.cur.get(unit).copied().unwrap_or(0))
        })
    }
}

const ERA_FEE_UNIT: &str = "billable_requests";

const ERA_BUCKET_PREFIX: &str = "e:";

const ERA_MODEL_SEP: char = '\u{1f}';

const RAW_ERA_PREFIX: &str = "busbar.raw-era.v1:";

fn era_tag(era: RawRateEra) -> String {
    match era.entry_id {
        Some(id) => format!("{RAW_ERA_PREFIX}{}:{id}", era.effective_from),
        None => era.effective_from.to_string(),
    }
}

fn parse_era_tag(tag: &str) -> RecordStoreResult<Option<RawRateEra>> {
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

fn era_model(era: RawRateEra, model: &str) -> String {
    format!("{}{ERA_MODEL_SEP}{model}", era_tag(era))
}

fn dated_delta(delta: &UsageDelta, era: RawRateEra) -> UsageDelta {
    if era == RawRateEra::legacy(0) {
        return UsageDelta::default();
    }
    let mut models: Vec<_> = delta
        .models
        .iter()
        .map(|model| busbar_contract::records::ModelTokensDelta {
            model: era_model(era, &model.model),
            usage_units: model.usage_units.clone(),
        })
        .collect();
    if delta.billable_requests != 0 {
        models.push(busbar_contract::records::ModelTokensDelta {
            model: era_tag(era),
            usage_units: std::collections::BTreeMap::from([(
                ERA_FEE_UNIT.to_string(),
                delta.billable_requests,
            )]),
        });
    }
    UsageDelta {
        models,
        ..UsageDelta::default()
    }
}

fn park_window(parked: &mut Vec<(u64, ExactUsageDelta)>, window: u64, delta: ExactUsageDelta) {
    if delta.is_zero() {
        return;
    }
    if let Some(index) = parked.iter().position(|(at, _)| *at == window) {
        parked[index].1.merge(&delta);
        if parked[index].1.is_zero() {
            parked.remove(index);
        }
    } else {
        parked.push((window, delta));
    }
}

fn era_bucket(bucket: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bucket.as_bytes());
    format!("{ERA_BUCKET_PREFIX}{}", hex::encode(&digest.as_ref()[..16]))
}

pub fn is_token_class(class: &str) -> bool {
    use crate::plane_driver::registry::{plane_decls, TOKEN_FAMILY};
    busbar_contract::records::RESERVED_UNITS.contains(&class)
        || plane_decls().iter().any(|d| {
            (d.billable_classes.iter()).any(|c| c.family == TOKEN_FAMILY && c.class == class)
        })
}

pub fn token_series(
    lane: &str,
    counts: &std::collections::BTreeMap<String, u64>,
) -> Vec<(String, u64)> {
    use crate::plane_driver::registry::{plane_decls, TOKEN_FAMILY};
    let (plane, _) = busbar_kernel_ledger::cost::split_plane_lane(lane);
    let owner = plane_decls().iter().find(|d| {
        if plane.is_empty() {
            d.fallback
        } else {
            d.key == plane
        }
    });
    let mut series: Vec<(String, u64)> = owner
        .into_iter()
        .flat_map(|d| {
            (d.billable_classes.iter())
                .filter(|c| c.family == TOKEN_FAMILY && !d.fee_units.contains(&c.class))
                .map(|c| c.class)
        })
        .map(|class| (class.to_string(), counts.get(class).copied().unwrap_or(0)))
        .collect();
    for (class, n) in counts {
        if is_token_class(class) && !series.iter().any(|(named, _)| named == class) {
            series.push((class.clone(), *n));
        }
    }
    series
}

fn token_total<'a>(maps: impl Iterator<Item = &'a std::collections::BTreeMap<String, u64>>) -> u64 {
    maps.flat_map(|m| m.iter())
        .filter(|(k, _)| is_token_class(k))
        .fold(0u64, |acc, (_, v)| acc.saturating_add(*v))
}

fn units_total(units: &std::collections::BTreeMap<String, u64>) -> u64 {
    units.values().fold(0u64, |acc, v| acc.saturating_add(*v))
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
}

impl FeeCharge {
    pub fn raw_era(&self) -> RawRateEra {
        self.era
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

struct MapShard<V> {
    map: RwLock<HashMap<String, V>>,
    sweep_ticker: AtomicU32,
}

impl<V> Default for MapShard<V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            sweep_ticker: AtomicU32::new(0),
        }
    }
}

struct Sharded<V> {
    shards: Box<[MapShard<V>]>,
}

impl<V> Sharded<V> {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(GOV_SHARDS);
        shards.resize_with(GOV_SHARDS, MapShard::default);
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    #[inline]
    fn shard_for(&self, key_id: &str) -> &MapShard<V> {
        &self.shards[self.shard_index(key_id)]
    }

    #[inline]
    fn shard_index(&self, key_id: &str) -> usize {
        (busbar_kernel::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)
    }

    #[inline]
    fn shard_at(&self, idx: usize) -> &MapShard<V> {
        &self.shards[idx]
    }

    #[inline]
    fn write(&self, key_id: &str) -> std::sync::RwLockWriteGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id)
            .map
            .write()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[inline]
    fn read(&self, key_id: &str) -> std::sync::RwLockReadGuard<'_, HashMap<String, V>> {
        self.shard_for(key_id)
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn write_all(
        &self,
    ) -> impl Iterator<Item = std::sync::RwLockWriteGuard<'_, HashMap<String, V>>> {
        self.shards
            .iter()
            .map(|s| s.map.write().unwrap_or_else(|p| p.into_inner()))
    }

    #[cfg(test)]
    fn sweep_ticker_for(&self, key_id: &str) -> &AtomicU32 {
        &self.shard_for(key_id).sweep_ticker
    }

    #[cfg(test)]
    fn shard_lock_for(&self, key_id: &str) -> &RwLock<HashMap<String, V>> {
        &self.shard_for(key_id).map
    }
}

struct GovCaches {
    by_id: HashMap<String, Arc<VirtualKey>>,

    by_credential: CredentialIndex,
}

pub type CredentialIndex = HashMap<(String, String), (Arc<VirtualKey>, CredentialSecret)>;

pub struct GovState {
    store: Arc<dyn RecordStore>,

    caches: Arc<RwLock<GovCaches>>,

    concurrent: RwLock<HashMap<String, Arc<std::sync::atomic::AtomicI64>>>,

    admin_token_hash: RwLock<Option<String>>,

    budget: Sharded<BudgetCell>,

    recovery_book: recovery::RecoveryBook,

    correction_claims: claims::ClaimSet<String>,

    corrections: std::sync::Mutex<HashMap<String, state::ledger_adjust::PendingCorrection>>,

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

    mutation_claims: claims::ClaimSet<MutationKey>,

    self_mint_holds: std::sync::atomic::AtomicBool,

    store_calls: std::sync::OnceLock<Arc<dyn busbar_contract::store_calls::StoreCalls>>,

    caller_refs: crate::plane_driver::CallerRefs,

    deployment_caller_ref: RwLock<Option<[u8; 32]>>,

    amendments: Arc<crate::audit::amend::NodeAmendments>,

    boot_caller_ref: zeroize::Zeroizing<[u8; 32]>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
enum MutationKey {
    Key(String),
    Subject(String),
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
pub use state::{
    metering_lane, AdjustRefused, Adjustment, MintError, PricedBucket, UsageAdjustment,
    ADJUST_DOWN_BUCKET, ADJUST_UP_BUCKET,
};

mod tickets;
pub use tickets::{TicketRefusal, TICKET_RECORD_KIND, TICKET_SPENT_KIND};

/// Which self-serve mint operation [`mint_self_offloaded`] should run on the blocking pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfMintOp {
    Issue,
    Refresh,
}

pub const SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE: bool = false;

/// Why the self-serve mint refused to issue. Each one is an admin's or another provider's hold on the
/// subject, never a store failure; the token exchange maps every one to `Unbound` (403).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfMintRefusal {
    /// The subject holds a self-serve binding an admin disabled (or revoked) and has not deleted. A
    /// login or refresh must not re-enable it or route around it with a fresh key.
    Disabled,
    /// The subject's binding was minted through a different identity provider
    /// ([`busbar_contract::records::VirtualKey::idp_provider`]).
    OtherProvider,
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
    tokio::task::spawn_blocking(move || match op {
        SelfMintOp::Issue => gov.issue_self_scoped(&user_sub, &provider, allowed_scopes, exp, now),
        SelfMintOp::Refresh => {
            gov.refresh_self_scoped(&user_sub, &provider, allowed_scopes, exp, now)
        }
    })
    .await
    .unwrap_or_else(|e| {
        Err(SelfMintError::Store(RecordStoreError(format!(
            "self-serve mint task failed to join: {e}"
        ))))
    })
}

pub fn synthesize_principal_key(
    principal: &crate::auth::Principal,
    bindings: Option<&std::collections::BTreeMap<String, crate::config::RoleBindingCfg>>,
) -> Option<Arc<VirtualKey>> {
    synthesize_key(principal, bindings).map(Arc::new)
}

pub const PRINCIPAL_MARKER_PREFIX: &str = "principal:";

pub fn synthesize_bound_key(
    module: &str,
    principal: &crate::auth::Principal,
    role_bindings: &crate::config::RoleBindings,
) -> Option<Arc<VirtualKey>> {
    let mut key = synthesize_key(principal, role_bindings.get(module))?;
    key.generation_hash = format!(
        "{PRINCIPAL_MARKER_PREFIX}{}",
        serde_json::json!({ "id": principal.id, "module": module, "roles": principal.roles })
    );
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
    let m: Marker = serde_json::from_str(json).ok()?;
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
) -> Vec<&'a crate::config::RoleBindingCfg> {
    let ungoverned = crate::config::auth::UNGOVERNED_ROLE;
    let named = |role: &&String| role.as_str() != ungoverned;
    let granting: Vec<_> = principal
        .roles
        .iter()
        .filter(named)
        .filter_map(|role| table.get(role))
        .collect();

    let roleless = !principal.roles.iter().any(|r| named(&r));
    let only_ungoverned = table.keys().all(|r| r == ungoverned);
    match table.get(ungoverned) {
        Some(binding) if granting.is_empty() && (roleless || only_ungoverned) => vec![binding],
        _ => granting,
    }
}

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
    if pools.is_none() && plane.is_none() {
        return None;
    }
    let mut list: Vec<busbar_contract::records::ScopeRef> = pools
        .into_iter()
        .flatten()
        .map(busbar_contract::records::ScopeRef::pool)
        .collect();
    list.extend(plane.into_iter().flatten());
    Some(list)
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
    allowed_pools.map(|list| {
        list.into_iter()
            .map(busbar_contract::records::ScopeRef::pool)
            .collect()
    })
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

        generation_hash: format!("principal:{}", principal.id),
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

#[cfg(test)]
fn generate_secret() -> Result<String, getrandom::Error> {
    crate::test_support::governance::generate_secret()
}

fn draw(alphabet: &str, n: usize) -> Result<String, getrandom::Error> {
    let symbols = alphabet.as_bytes();
    if symbols.is_empty() {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf)?;
    Ok(buf
        .iter()
        .map(|&b| char::from(symbols[usize::from(b) % symbols.len()]))
        .collect())
}

pub(crate) fn issue_credential(
    shape: &busbar_contract::auth_calls::IssuedShape,
) -> Result<(String, String), getrandom::Error> {
    let tail = shape.id_len.saturating_sub(shape.id_prefix.len());
    let id = format!("{}{}", shape.id_prefix, draw(&shape.id_alphabet, tail)?);
    Ok((id, draw(&shape.secret_alphabet, shape.secret_len)?))
}

/// Exercise the production issued-shape generator with a fixture verifier's declared shape.
/// This hook carries no fixture format or implementation; those belong to the external kit.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn issue_credential_for_test(
    shape: &busbar_contract::auth_calls::IssuedShape,
) -> Result<(String, String), getrandom::Error> {
    issue_credential(shape)
}

pub fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.scope_allowed("pool", pool)
}

pub fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        WINDOW_MINUTE => now / 60 * 60,
        WINDOW_HOUR => now / 3600 * 3600,
        WINDOW_DAY => now / SECS_PER_DAY * SECS_PER_DAY,
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * SECS_PER_DAY
        }
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
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            Some((days_from_civil(ny, nm, 1) as u64) * SECS_PER_DAY)
        }
        _ => None,
    }
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, RecordStore, RecordStoreError,
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
    pub requests: u64,
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    pub tokens_cache_write: u64,
    /// The ledgered classes the token columns do not hold, by class — the budget book's own counts
    /// (see `busbar_contract::records::MeteringDelta::usage_units`).
    pub usage_units: std::collections::BTreeMap<String, u64>,
}

impl MeterCounts {
    pub fn request(units: &std::collections::BTreeMap<String, u64>) -> Self {
        let [input, output, cache_read, cache_write] = busbar_contract::records::RESERVED_UNITS
            .map(|class| units.get(class).copied().unwrap_or(0));
        Self {
            requests: 1,
            tokens_input: input,
            tokens_output: output,
            tokens_cache_read: cache_read,
            tokens_cache_write: cache_write,
            usage_units: std::collections::BTreeMap::new(),
        }
    }

    pub fn merge(&mut self, other: MeterCounts) {
        self.requests = self.requests.saturating_add(other.requests);
        self.tokens_input = self.tokens_input.saturating_add(other.tokens_input);
        self.tokens_output = self.tokens_output.saturating_add(other.tokens_output);
        self.tokens_cache_read = self
            .tokens_cache_read
            .saturating_add(other.tokens_cache_read);
        self.tokens_cache_write = self
            .tokens_cache_write
            .saturating_add(other.tokens_cache_write);
        for (class, n) in other.usage_units {
            let cur = self.usage_units.entry(class).or_insert(0);
            *cur = cur.saturating_add(n);
        }
    }

    pub fn is_zero(&self) -> bool {
        self.requests == 0
            && self.tokens_input == 0
            && self.tokens_output == 0
            && self.tokens_cache_read == 0
            && self.tokens_cache_write == 0
            && self.usage_units.values().all(|n| *n == 0)
    }
}

pub type MeterKey = (String, u64, String, String, u64, String, String);

pub const MAX_PENDING_METERING: usize = 262_144;

pub const MAX_PENDING_METERING_PER_SHARD: usize = MAX_PENDING_METERING / GOV_SHARDS;

pub const METERING_OVERFLOW_KEY_ID: &str = "__busbar_pending_overflow__";

pub const METERING_OVERFLOW_LABEL: &str = "__aggregated__";

pub fn accrue_pending(
    pending: &mut HashMap<MeterKey, MeterCounts>,
    key: MeterKey,
    add: MeterCounts,
    cap: usize,
    warn: &CoalesceWarn,
) {
    if let Some(cell) = pending.get_mut(&key) {
        cell.merge(add);
        return;
    }
    if pending.len() < cap {
        pending.insert(key, add);
        return;
    }

    let sentinel: MeterKey = (
        METERING_OVERFLOW_KEY_ID.to_string(),
        key.1,
        METERING_OVERFLOW_LABEL.to_string(),
        METERING_OVERFLOW_LABEL.to_string(),
        key.4,
        String::new(),
        key.6.clone(),
    );
    pending.entry(sentinel).or_default().merge(add);
    metrics::counter!(crate::snapshot::METERING_PENDING_COALESCED_TOTAL).increment(1);

    if let Some(coalesced) = warn.note(std::time::Instant::now()) {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::METERING_PENDING_OVERFLOW_COALESCED,
            overflow_bucket = key.1,
            coalesced,
            "metering accumulator at cap ({cap}); coalesced {coalesced} cell(s) into the per-bucket \
             overflow sentinel — totals preserved, per-key attribution collapsed until the store \
             recovers"
        );
    }
}

/// The once-per-window throttle on the overflow-coalescing warning: counts coalesced cells and
/// releases the count at most once per [`COALESCE_WARN_WINDOW`].
#[derive(Default)]
pub struct CoalesceWarn(std::sync::Mutex<(Option<std::time::Instant>, u64)>);

pub const COALESCE_WARN_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

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
    shards: Box<[std::sync::Mutex<HashMap<MeterKey, MeterCounts>>]>,
    coalesce_warn: CoalesceWarn,

    flight: std::sync::Mutex<std::collections::VecDeque<metering_flush::MeteringWrite>>,
    flushing: std::sync::Mutex<Option<std::thread::ThreadId>>,
    flush_finished: std::sync::Condvar,
}

impl Default for PendingMetering {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingMetering {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(GOV_SHARDS);
        shards.resize_with(GOV_SHARDS, || std::sync::Mutex::new(HashMap::new()));
        Self {
            shards: shards.into_boxed_slice(),
            coalesce_warn: CoalesceWarn::default(),
            flight: std::sync::Mutex::new(std::collections::VecDeque::new()),
            flushing: std::sync::Mutex::new(None),
            flush_finished: std::sync::Condvar::new(),
        }
    }

    #[inline]
    fn shard_for(&self, key_id: &str) -> &std::sync::Mutex<HashMap<MeterKey, MeterCounts>> {
        &self.shards[(busbar_kernel::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)]
    }

    pub fn accrue(&self, key: MeterKey, add: MeterCounts) {
        let mut map = self
            .shard_for(&key.0)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        accrue_pending(
            &mut map,
            key,
            add,
            MAX_PENDING_METERING_PER_SHARD,
            &self.coalesce_warn,
        );
    }

    pub fn drain(&self) -> Vec<(MeterKey, MeterCounts)> {
        let mut out = Vec::new();
        for shard in self.shards.iter() {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            if !map.is_empty() {
                out.extend(std::mem::take(&mut *map));
            }
        }
        out
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
impl<T> IntoStoreResult<T> for Result<T, getrandom::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(format!("OS CSPRNG (getrandom) unavailable: {e}")))
    }
}

#[cfg(test)]
pub use crate::test_support::store_double::MemoryStore;

pub fn spawn_budget_flusher(
    gov: std::sync::Arc<GovState>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let interval = std::time::Duration::from_millis(crate::limits::usage_flush_interval_ms());

    let flush_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    tokio::spawn(async move {
        purge_usage_windows(&gov).await;
        let mut purged_at = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if purged_at.elapsed() >= USAGE_PURGE_EVERY {
                        purge_usage_windows(&gov).await;
                        purged_at = std::time::Instant::now();
                    }
                    // `flush_budgets` runs SYNCHRONOUS SQLite writes (store `*_inner` on a std Mutex);
                    // calling it inline here would block a Tokio worker thread for the duration of the
                    // durable write. Offload to the blocking pool so the async runtime keeps serving
                    // requests. `gov` is an Arc, so clone the handle into the blocking task; we do not
                    // await the join (write-behind is fire-and-forget - a store error re-marks the cell
                    // dirty and the next tick retries).
                    //
                    // SKIP-IF-STILL-FLUSHING: acquire the flush gate with `try_lock`; if a prior flush
                    // is still in flight, this tick is a no-op (its dirty cells stay dirty and the next
                    // free tick flushes them) rather than racing a second overlapping flush. The guard
                    // is moved INTO the blocking task and dropped when the flush returns, releasing the
                    // gate for the next tick.
                    let Ok(guard) = flush_gate.clone().try_lock_owned() else {
                        continue;
                    };
                    let gov = gov.clone();
                    tokio::task::spawn_blocking(move || {
                        gov.flush_budgets();
                        gov.flush_metering();
                        drop(guard);
                    });
                }
                _ = shutdown.recv() => {
                    // Graceful shutdown: one FINAL flush so no accrued spend/requests is lost, then exit.
                    // WAIT for any in-flight periodic flush to drain first (`lock().await`) so the final
                    // flush never overlaps one - otherwise the final flush's newer snapshot could be
                    // overwritten by the older in-flight flush completing after it. This one is AWAITED
                    // (via spawn_blocking + join) rather than fire-and-forget: the task is about to break
                    // and stop ticking, so the final durable write must COMPLETE before we exit or the
                    // last window's accrued spend is lost. It still runs on the blocking pool (not inline
                    // on the worker), and a join error falls back to nothing flushed - best-effort.
                    let guard = flush_gate.clone().lock_owned().await;
                    let gov = gov.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        gov.flush_budgets_final();
                        gov.flush_metering_final();
                        drop(guard);
                    })
                    .await;
                    break;
                }
            }
        }
    })
}

pub const USAGE_WINDOW_HORIZON_SECS: u64 = 31 * SECS_PER_DAY;

pub const USAGE_PURGE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub async fn purge_usage_windows(gov: &GovState) {
    let Some(calls) = gov.store_calls() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let before = now.saturating_sub(USAGE_WINDOW_HORIZON_SECS);
    match calls.purge_usage_before(before).await {
        Ok(purged) => tracing::debug!(
            purged,
            before,
            "usage ledger: windows past the horizon purged"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "usage ledger: this store's usage windows are NOT purged past the {}-day horizon \
             (it grows until the store implements the purge); retried in an hour",
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
#[path = "tests/limits_tests.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "tests/budget_cell_tests.rs"]
mod budget_cell_tests;

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
    pub tokens: u64,
    /// The admission count the ledger holds for the bucket.
    pub requests: u64,
}

pub const SECS_PER_DAY: u64 = 86_400;
