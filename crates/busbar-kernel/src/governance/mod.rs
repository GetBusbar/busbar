// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Governance persistence. A durable `Store` seam — SEPARATE from the hot in-memory `LaneRuntime`
//! (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual keys + config, and
//! per-key usage counters (spend/tokens/requests) per budget window. Historical request logs are
//! NOT stored here (they go to the observability pipeline). The `Store` CONTRACT lives in
//! `busbar-api`; the DEFAULT backend is the in-memory `MemoryStore` (ephemeral, zero-setup), with
//! `SqliteStore` (durable) and future backends as swappable plugin crates chosen by `store.module`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use crate::diagnostics::{
    diag_debug, diag_warn, GOVERNANCE_KEY_RESERVED_NAMESPACE_COLLISION, LIMIT_WINDOW_UNRECOGNIZED,
};

// Seconds in a UTC day, for `budget_window`'s day/month arithmetic.
//
// Re-export BY IDENTITY of its canonical home, `busbar_kernel::governance::SECS_PER_DAY`: it is
// a bare calendar constant, so it belongs to the neutral governance vocabulary a plane's tests
// spell a day boundary with. `crate::governance::SECS_PER_DAY` resolves to the same value.
// Production modules that need it where layering prohibits the import (e.g. `sigv4.rs`) keep a
// private copy, as before.
//
// The re-export is `pub`: the canonical public spelling is the substrate's own, and a
// caller outside this crate names it there. Nothing outside busbar-core reaches this path.

// ── Window sentinel tokens (nouns; matched in `budget_window`). The SAME strings are the
// `groups:` config vocabulary (`per: minute|hour|day|month|total`), the ledger-bucket window
// suffix, and the metrics/error dimension - one vocabulary everywhere. ─────────────────────────────
/// The "all-time" window sentinel: a single window from epoch 0.
pub const WINDOW_TOTAL: &str = "total";
/// The "day" window sentinel: resets at UTC midnight.
pub const WINDOW_DAY: &str = "day";
/// The "month" window sentinel: resets at UTC first-of-month.
pub const WINDOW_MONTH: &str = "month";
/// The "minute" window sentinel: resets each UTC minute.
pub const WINDOW_MINUTE: &str = "minute";
/// The "hour" window sentinel: resets each UTC hour.
pub const WINDOW_HOUR: &str = "hour";

// ── Virtual-key / bearer-secret formats ──────────────────────────────────────────────────────────
/// The `"vk_"` prefix prepended to the 16-hex-char hash prefix to form a virtual-key id.
const VK_ID_PREFIX: &str = "vk_";
/// Number of hex characters from the SHA-256 hash used as the suffix of a virtual-key id.
#[cfg_attr(not(test), allow(dead_code))]
const VK_ID_HASH_PREFIX_LEN: usize = 16;
/// The `"sk-bb-"` prefix for bearer secrets returned by `generate_secret`. Gated with it: no
/// production path mints a hashed bearer secret any more.
#[cfg(any(test, feature = "test-support"))]
const SK_SECRET_PREFIX: &str = "sk-bb-";
/// The `generation_hash` prefix of a 1.5.0 signed-token binding row. A signed-token key has NO
/// hashed bearer secret: the token is the credential, and the `generation_hash` column holds
/// `binding:<id>:<generation>` — not a hash at all, a fingerprint compared post-resolution against
/// a token's `generation` claim (`generation_matches`) so a rotation can be detected. Every live key
/// is a signed-token binding (1.5.0 retired the legacy hashed-secret credential shape entirely — see
/// `docs/migration-1.5.md`), so this is the only `generation_hash` shape that exists.
pub const BINDING_MARKER_PREFIX: &str = "binding:";

/// The `group:`-less GROUP NAMESPACE for a SELF-SERVE (browser/token-exchange) key: every key a
/// principal mints for itself via `POST /auth/token` is bound to `user:<sub>`. Kept distinct so the
/// anti-sprawl `check_key_cap` can EXCLUDE self-serve keys (a principal always has exactly one — the
/// mint is an idempotent upsert on the current epoch — so it must never consume an admin key cap),
/// and so the deterministic subject id derives under a stable, non-attacker-chosen prefix.
pub const SELF_KEY_GROUP_PREFIX: &str = "user:";

/// The [`busbar_contract::records::VirtualKey::binding_mode`] recorded on a SELF-SERVE (personal) key: it is the
/// PERSONAL user-bound token (records the IdP subject for attribution, short-lived). Matches the
/// `auth.policy` `BindingMode::UserBound` wire spelling (`"user-bound"`). App/service tokens minted
/// through the admin API carry a different (or absent) mode.
pub const SELF_KEY_BINDING_MODE: &str = "user-bound";

/// The [`busbar_contract::records::VirtualKey::binding_mode`] recorded on an ADMIN-minted APP/service token: it is
/// TIME-BOUND (bounded by its `exp`, no IdP-subject tie), the app-token lifecycle that deliberately
/// OUTLIVES its minter (review H2/H3). Matches the `auth.policy` `BindingMode::TimeBound` wire
/// spelling (`"time-bound"`). Named `_APP` to contrast the self-serve personal `user-bound` key.
pub const SELF_KEY_BINDING_MODE_APP: &str = "time-bound";

/// The `generation_hash` marker for a signed-token binding at a given rotation generation.
pub fn binding_marker(id: &str, generation: &str) -> String {
    format!("{BINDING_MARKER_PREFIX}{id}:{generation}")
}

/// The rotation GENERATION carried by a binding row's `generation_hash` marker, if any. `None` for a
/// pre-generation binding marker (`binding:<id>`, minted before rotation carried a generation) —
/// only a token likewise carrying no generation may verify against it.
pub fn binding_generation(generation_hash: &str) -> Option<&str> {
    generation_hash
        .strip_prefix(BINDING_MARKER_PREFIX)?
        .split_once(':')
        .map(|(_id, generation)| generation)
}

/// Whether a presented token's generation claim matches the binding row's CURRENT generation —
/// the rotation gate on the signed-token verify path. Exact equality including the `None` case:
/// a pre-generation token (`None`) verifies only against a pre-generation binding (`None`), so a
/// rotation can never be defeated by simply omitting the claim.
pub fn generation_matches(generation_hash: &str, presented: Option<&str>) -> bool {
    binding_generation(generation_hash) == presented
}

/// THE ONE 128-bit random hex draw: 128 bits of OS CSPRNG as 32 lowercase hex chars. Fails closed on
/// no entropy, exactly like every other credential-shaped draw in this module. A fresh unguessable
/// binding GENERATION, and the ask-state nonce.
pub(crate) fn generate_binding_generation() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    Ok(hex::encode(raw))
}

/// A count's SEGMENT (MONEY-DESIGN §3b): the id of the card-history entry this node priced it with
/// (tokens at accrual, fees at admission), or `None` for the legacy remainder (counts written with
/// no entry: no history installed, or a 1.5.5 / pre-PR-B row). A segment is priced at ITS entry's
/// card and never re-resolved.
pub type Seg = Option<busbar_kernel_ledger::cost::EntryId>;

/// A segment as the spool and the sibling row spell it: 24 hex characters, or `""` for none.
pub(crate) fn seg_hex(seg: Seg) -> String {
    seg.map(|id| id.hex()).unwrap_or_default()
}

/// A segment from its spelling (`""` is the legacy remainder; anything else not an id is too).
pub(crate) fn seg_parse(text: &str) -> Seg {
    busbar_kernel_ledger::cost::EntryId::parse_hex(text)
}

/// One (model, segment)'s in-cell counters. The model name is an `Arc<str>` interned ONCE per
/// (bucket, model, segment) on first sight.
#[derive(Clone)]
struct ModelCell {
    model: std::sync::Arc<str>,
    /// The entry these counts were earned under.
    seg: Seg,
    /// The name-keyed CURRENT unit counters. Sparse (a zero unit is absent).
    cur: std::collections::BTreeMap<String, u64>,
}

/// In-memory TOKEN-LEDGER cell for a bucket's CURRENT window - the AUTHORITATIVE hot-path
/// enforcement state. A bucket is a key's own budget bucket OR a budget-group bucket (same shape).
/// NO SPEND FIELD: money is derived at check time as `cell counts x the card of the entry each was
/// earned under` (+ the flat fee x billable requests per entry). The counts are segmented by card
/// entry, and each segment prices at its entry's card (MONEY-DESIGN §3b). What reaches the store is
/// not read off the cell: every count-changing mutation emits its delta into its shard's
/// [`Pending`] map in the same critical section (MONEY-DESIGN §3c).
#[derive(Clone, Default)]
struct BudgetCell {
    window_start: u64,
    /// ADMISSION count: incremented once per admitted request, NEVER refunded (the `requests` cap).
    requests: u64,
    /// BILLABLE request count: admitted requests MINUS non-2xx refunds (the flat fee's base).
    billable_requests: u64,
    /// Per-(model, segment) counters. Small Vec, scanned linearly.
    models: Vec<ModelCell>,
    /// The fee base split by the entry each billable request was admitted under.
    fee_segs: busbar_kernel_ledger::usage::FeeSegs,
    /// Wall-clock of the last accrual or admission charge (the all-time cell's eviction age).
    last_touch: u64,
    /// ITS PENDING DELTAS since the writer's last take ([`PendCells`]). Non-empty (with the
    /// recorder's UNRECORDED set) is what keeps the sweep from evicting the cell.
    pending: PendCells,
}

impl BudgetCell {
    fn fresh(window_start: u64) -> Self {
        Self {
            window_start,
            ..Self::default()
        }
    }

    /// ROLL the cell to the newer `window`: the counts start over. Emits nothing: what the old
    /// window held was emitted as it happened. What is still pending or unsent keeps it resident.
    fn roll(&mut self, window: u64) {
        let pending = std::mem::take(&mut self.pending);
        *self = Self::fresh(window);
        self.pending = pending;
    }

    /// Whether it holds deltas not yet taken.
    fn dirty(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Accrue one response's keyed units under `model` in segment `seg`, interning the pair on
    /// first sight and each unit key on first sight of that (model, segment, unit).
    fn accrue(&mut self, model: &str, seg: Seg, units: &std::collections::BTreeMap<String, u64>) {
        let at = self
            .models
            .iter()
            .position(|m| &*m.model == model && m.seg == seg);
        let cell = match at {
            Some(i) => &mut self.models[i],
            None => {
                // Allocate ONLY on the first sight of a (bucket, model, segment).
                self.models.push(ModelCell {
                    model: std::sync::Arc::from(model),
                    seg,
                    cur: std::collections::BTreeMap::new(),
                });
                self.models.last_mut().expect("just pushed")
            }
        };
        for (k, v) in units {
            if *v == 0 {
                continue;
            }
            let slot = cell.cur.entry(k.clone()).or_insert(0);
            *slot = slot.saturating_add(*v);
        }
    }

    /// THE CELL, PRICED, each segment at the card of the entry it carries (the legacy remainder at
    /// the card covering the window's start), and — with `include_fee` — the fee base per segment,
    /// through the one function. A present card silent about a held class, an overflow, or an entry
    /// this node does not hold REFUSES — never a silent 0.
    fn spend(
        &self,
        cost: &crate::cost::CostModel,
        include_fee: bool,
    ) -> Result<busbar_kernel_ledger::cost::Money, busbar_kernel_ledger::cost::MoneyError> {
        let history = crate::rate_apply::dated_history();
        let now_ms = crate::store::now_ms();
        let fees = (self.fee_segs.split(self.billable_requests)).filter(|_| include_fee);
        let rows = self.models.iter().map(|m| (&*m.model, m.seg, &m.cur));
        let start_ms = self.window_start.saturating_mul(1_000);
        busbar_kernel_ledger::usage::price_segments(
            rows,
            fees,
            start_ms,
            cost.card(),
            history.as_deref().map(|h| (h, now_ms)),
        )
    }

    /// Add `counts` (non-negative: hydrated, foreign or dead-lettered) to the cell.
    fn add_counts(&mut self, counts: &crate::posting::record::CellCount) {
        self.requests = self
            .requests
            .saturating_add(u64::try_from(counts.requests).unwrap_or(0));
        for (seg, n) in &counts.billable {
            let n = u64::try_from(*n).unwrap_or(0);
            self.billable_requests = self.billable_requests.saturating_add(n);
            self.fee_segs.add(seg_parse(seg), n);
        }
        for (seg, models) in &counts.units {
            for (model, classes) in models {
                let units = classes
                    .iter()
                    .map(|(c, n)| (c.clone(), u64::try_from(*n).unwrap_or(0)))
                    .collect();
                self.accrue(model, seg_parse(seg), &units);
            }
        }
    }

    /// The cell with `foreign` counts (other nodes', from the fleet snapshot) added: what the cap
    /// test and the views price. Allocates only when there is foreign spend.
    fn with_foreign(&self, foreign: &crate::posting::record::CellCount) -> BudgetCell {
        let mut out = self.clone();
        out.add_counts(foreign);
        out
    }

    /// Drop DEAD `ModelCell`s (no current counts) so the `models` Vec cannot grow without bound in
    /// a long-lived, never-rolled cell. A model that later reappears is simply re-interned.
    fn prune_dead_models(&mut self) {
        self.models.retain(|m| units_total(&m.cur) != 0);
    }

    /// Total current TOKENS across models — every token-family class (the scalar view for admin
    /// reads and the `tokens:` cap). A class in another family rides the same map to be PRICED, but
    /// it is not a token and never counts as one.
    fn total_tokens(&self) -> u64 {
        token_total(self.models.iter().map(|m| &m.cur))
    }

    /// Current summed count of one reserved tier across models — a per-tier cap's counter.
    fn total_tier(&self, unit: &str) -> u64 {
        self.models.iter().fold(0u64, |acc, m| {
            acc.saturating_add(m.cur.get(unit).copied().unwrap_or(0))
        })
    }
}

/// A BUCKET'S PENDING DELTAS (MONEY-DESIGN §3c), per window: what RAM `cur` applied since the
/// writer's last take, net, by segment. They live ON THE CELL (under its shard's lock, so a
/// mutation and its emit are one critical section with no lookup at all), and in the shard's
/// [`Pending`] map once the cell is removed (a deleted key or group: nothing is discarded). A string
/// is allocated only on a segment's or class's FIRST sight in a window.
#[derive(Clone, Default)]
pub(crate) struct PendCells(Vec<PendCell>);

/// One window's pending delta.
#[derive(Clone, Default)]
pub(crate) struct PendCell {
    window: u64,
    requests: i64,
    billable: Vec<(Seg, i64)>,
    units: Vec<PendUnit>,
}

/// One (segment, model, class)'s pending count.
#[derive(Clone)]
pub(crate) struct PendUnit {
    seg: Seg,
    model: String,
    class: String,
    n: i64,
}

impl PendCell {
    fn unit(&mut self, seg: Seg, model: &str, class: &str, n: i64) {
        if n == 0 {
            return;
        }
        match self
            .units
            .iter_mut()
            .find(|u| u.seg == seg && u.model == model && u.class == class)
        {
            Some(u) => u.n = u.n.saturating_add(n),
            None => self.units.push(PendUnit {
                seg,
                model: model.to_string(),
                class: class.to_string(),
                n,
            }),
        }
    }

    fn fee(&mut self, seg: Seg, n: i64) {
        match self.billable.iter_mut().find(|(s, _)| *s == seg) {
            Some((_, have)) => *have = have.saturating_add(n),
            None => self.billable.push((seg, n)),
        }
    }
}

impl PendCells {
    fn at(&mut self, window: u64) -> &mut PendCell {
        match self.0.iter().position(|c| c.window == window) {
            Some(i) => &mut self.0[i],
            None => {
                self.0.push(PendCell {
                    window,
                    ..PendCell::default()
                });
                self.0.last_mut().expect("just pushed")
            }
        }
    }

    /// ONE CHARGE: `requests +1` and the fee (`billable +1` in `seg`, or the fee lane's unit in
    /// `seg`).
    fn charged(
        &mut self,
        window: u64,
        seg: Seg,
        fee_lane: Option<(&str, &std::collections::BTreeMap<String, u64>)>,
    ) {
        let c = self.at(window);
        c.requests = c.requests.saturating_add(1);
        match fee_lane {
            None => c.fee(seg, 1),
            Some((lane, one)) => {
                for (class, n) in one {
                    c.unit(seg, lane, class, signed(*n));
                }
            }
        }
    }

    /// `requests` changed by `n` (-1 at an uncharge).
    fn admitted(&mut self, window: u64, n: i64) {
        let c = self.at(window);
        c.requests = c.requests.saturating_add(n);
    }

    /// The flat fee base of `seg` changed by `n`.
    fn billable(&mut self, window: u64, seg: Seg, n: i64) {
        self.at(window).fee(seg, n);
    }

    /// `units` of `model` in `seg`, signed by `sign`.
    fn units(
        &mut self,
        window: u64,
        (model, seg): (&str, Seg),
        units: &std::collections::BTreeMap<String, u64>,
        sign: i64,
    ) {
        let c = self.at(window);
        for (class, n) in units {
            c.unit(seg, model, class, signed(*n).saturating_mul(sign));
        }
    }

    /// Whether anything is pending for `window`.
    fn holds(&self, window: u64) -> bool {
        self.0.iter().any(|c| c.window == window)
    }

    /// Whether anything is pending.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add `other` (a removed cell's pending) into these.
    fn adopt(&mut self, other: PendCells) {
        for c in other.0 {
            let into = self.at(c.window);
            into.requests = into.requests.saturating_add(c.requests);
            for (seg, n) in c.billable {
                into.fee(seg, n);
            }
            for u in c.units {
                into.unit(u.seg, &u.model, &u.class, u.n);
            }
        }
    }

    /// THE TAKE: every window's delta as the spool's cells of `bucket` (zero ones dropped).
    fn take(&mut self, bucket: &str) -> Vec<crate::posting::record::CellCount> {
        let mut out = Vec::new();
        for c in std::mem::take(&mut self.0) {
            let mut cell = crate::posting::record::CellCount::new(bucket, c.window);
            cell.requests = c.requests;
            for (seg, n) in c.billable {
                cell.add_billable(&seg_hex(seg), n);
            }
            for u in c.units {
                cell.add_unit(&seg_hex(u.seg), &u.model, &u.class, u.n);
            }
            cell.tidy();
            if !cell.is_zero() {
                out.push(cell);
            }
        }
        out
    }

    /// `cell` (a spool cell) back into pending (a test's undelivered delivery).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn merge_cell(&mut self, cell: &crate::posting::record::CellCount) {
        self.admitted(cell.window, cell.requests);
        for (seg, n) in &cell.billable {
            self.billable(cell.window, seg_parse(seg), *n);
        }
        for (seg, models) in &cell.units {
            for (model, classes) in models {
                for (class, n) in classes {
                    self.at(cell.window).unit(seg_parse(seg), model, class, *n);
                }
            }
        }
    }
}

/// THE SHARD'S PENDING DELTAS OF REMOVED CELLS (a deleted key or group): taken with the cells'.
#[derive(Default)]
pub(crate) struct Pending(HashMap<String, PendCells>);

impl Pending {
    /// `bucket`'s orphaned pending deltas.
    fn of(&mut self, bucket: &str) -> &mut PendCells {
        if !self.0.contains_key(bucket) {
            self.0.insert(bucket.to_string(), PendCells::default());
        }
        self.0.get_mut(bucket).expect("just ensured")
    }

    /// Whether `bucket` has orphaned pending deltas for `window`.
    fn holds(&self, bucket: &str, window: u64) -> bool {
        self.0.get(bucket).is_some_and(|p| p.holds(window))
    }
}

/// Clamp a u64 counter into the signed delta domain.
fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Whether `class` counts toward a `tokens:` cap: a reserved token tier, or a class an installed
/// plane declares in the token family (a streaming plane's `audio_tokens_in` is as much a token as
/// an LLM's `input`). The one predicate every token total in this module reads.
pub fn is_token_class(class: &str) -> bool {
    use crate::plane::registry::{plane_decls, TOKEN_FAMILY};
    busbar_contract::records::RESERVED_UNITS.contains(&class)
        || plane_decls().iter().any(|d| {
            (d.billable_classes.iter()).any(|c| c.family == TOKEN_FAMILY && c.class == class)
        })
}

/// THE TOKEN SERIES OF ONE LANE'S COUNTS, in the order the scrape names them: first every
/// token-family class the lane's own plane declares, in its declared order and at 0 when the lane
/// counted none of it (the plane that owns a `"<plane>\u{1f}<subject>"` lane, the fallback plane
/// for an unqualified one); then every other class in `counts` that [`is_token_class`] counts as a
/// token, in name order. Fee units are no token series. The kernel reads the class names from the
/// declarations and names none itself.
pub fn token_series(
    lane: &str,
    counts: &std::collections::BTreeMap<String, u64>,
) -> Vec<(String, u64)> {
    use crate::plane::registry::{plane_decls, TOKEN_FAMILY};
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

/// Saturating sum of the token-family counts across name-keyed unit maps.
fn token_total<'a>(maps: impl Iterator<Item = &'a std::collections::BTreeMap<String, u64>>) -> u64 {
    maps.flat_map(|m| m.iter())
        .filter(|(k, _)| is_token_class(k))
        .fold(0u64, |acc, (_, v)| acc.saturating_add(*v))
}

/// Saturating sum of every count in a name-keyed unit map — the scalar "total tokens" view over the
/// dissolved reserved-four-plus-opens ledger.
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
/// era it was charged under (`effective_from_at` of the admission instant). Read back only by
/// [`GovState::refund_charge`]; a refund never re-derives any of it from a clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeCharge {
    lane: Option<String>,
    /// The card entry the fee was charged under.
    seg: Seg,
    cells: Vec<(String, u64)>,
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
    /// STRICT MODE (`advanced.strict_spend_recording`): why spend could not be recorded, collected
    /// in PASS 1 and raised by the caller only after every 1.5.5 refusal (MONEY-DESIGN §3c).
    strict: Option<crate::posting::Closed>,
}

impl AdmitGrant {
    /// What this admission's fee charge reached: the one input its refund reads.
    pub fn charge(&self) -> &FeeCharge {
        &self.charge
    }

    /// Under strict mode, why this admission's spend cannot be recorded: the caller undoes it with
    /// [`GovState::uncharge`] and answers 503 `DurabilityUnavailable`. `None` with strict mode off.
    pub fn unrecordable(&self) -> Option<crate::posting::Closed> {
        self.strict
    }

    /// TEST-ONLY: how many gauges this grant holds.
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

// A derived (read-time) usage view for admin/metrics consumers: `spend_cents` is COMPUTED from
// the token ledger, each era at the card in force when it was earned, at the moment of the read -
// never stored.
//
// Re-export BY IDENTITY of its canonical home, `busbar_kernel::governance::DerivedUsage`: the
// figure is three integers with no engine dependency, so it belongs to the neutral governance
// vocabulary a plane reads it back through. `crate::governance::DerivedUsage` resolves to the very
// same type it always did.
//
// The re-export is `pub`: the canonical public spelling is the substrate's own, and a
// caller outside this crate names it there. Nothing outside busbar-core reaches this path.

/// THE REVOCATION STALENESS WINDOW (seconds). The in-memory denylist is a CACHE of the durable
/// store's revocation set, not the truth: every auth path re-reads the store denylist when its copy
/// is older than this, so a revoke performed on ANOTHER NODE of a fleet sharing one store — or
/// written out-of-band directly against the store — is honoured here within at most this many
/// seconds. A revoke performed on THIS node is applied to the in-memory set synchronously by
/// [`GovState::revoke`] and takes effect on the very next check (zero window).
///
/// The re-read is SCHEDULED by the request path, not performed by it (see
/// [`revocation::RevocationSync`]), so a peer's revoke lands within roughly two of these windows on
/// a healthy store — the price of never parking a reactor thread inside a store call.
///
/// WHY 5s: the re-read costs ONE small store query per node per window regardless of request rate
/// (single-flighted by a CAS on the attempt stamp), so at 5s even a 50k-RPS node adds 0.2
/// queries/sec — negligible — while bounding the worst case that matters (a compromised credential
/// still authenticating after the operator revoked it) to seconds rather than the lifetime of the
/// process. Shorter windows buy little (a revoke is an operator action measured in seconds anyway)
/// and start to matter for a network-backed store plugin; longer windows re-open the hole this
/// closes. It is deliberately a CONSTANT, not a knob: an operator cannot accidentally widen a
/// security window, and there is no deployment for which "revocation lands within 5 seconds" is
/// wrong.
pub const REVOCATION_SYNC_TTL_SECS: u64 = 5;

/// Number of shards for the per-key enforcement maps (`rate`, `budget`, `token_spend_carry`). A
/// power of two so `hash & (N-1)` selects the shard with a mask (no modulo). 64 keeps lock
/// contention low well past typical core counts while adding trivial fixed memory (64 small empty
/// maps + 64 atomics per `GovState`). Each key deterministically maps to ONE shard, so a key's
/// read-modify-write (rate window, budget charge, spend carry) stays atomic within that shard's lock
/// exactly as it was under the single global lock — sharding only removes CROSS-key serialization,
/// never a per-key invariant.
const GOV_SHARDS: usize = 64;

/// One shard of a [`Sharded`] map: the key→value map plus its OWN amortized-sweep ticker (the sweep
/// is per-shard, so a shard scans only its own — ~1/64th — of the keys when it fires).
struct MapShard<V> {
    map: RwLock<ShardMap<V>>,
    sweep_ticker: AtomicU32,
}

/// One shard's cells and, under the SAME lock, its [`Pending`] deltas: a mutation and its emitted
/// delta are one critical section. Derefs to the cell map.
pub(crate) struct ShardMap<V> {
    cells: HashMap<String, V>,
    pending: Pending,
    /// `posted_hi` per bucket (MONEY-DESIGN §3d): for its window, the hydrated counts, plus every
    /// positive delta handed to the recorder, plus every negative one once READY (less what a
    /// `refused` dead letter holds). An upper bound on this node's share of any store read of the
    /// row. Kept apart from the cells, so it outlives a reclaimed group's cell (a re-created group
    /// never reads its old rows as foreign spend); pruned by window age.
    posted: HashMap<String, crate::posting::record::CellCount>,
}

impl<V> ShardMap<V> {
    /// `delta` (signed) into `posted_hi` of its bucket: a newer window replaces an older one; an
    /// older window's delta is skipped.
    pub(crate) fn posted_add(&mut self, delta: &crate::posting::record::CellCount) {
        let entry = self
            .posted
            .entry(delta.bucket.clone())
            .or_insert_with(|| crate::posting::record::CellCount::new(&delta.bucket, delta.window));
        if entry.window < delta.window {
            *entry = crate::posting::record::CellCount::new(&delta.bucket, delta.window);
        }
        if entry.window == delta.window {
            let mut d = delta.clone();
            d.bucket.clone_from(&entry.bucket);
            entry.merge(&d);
        }
    }
}

impl<V> std::ops::Deref for ShardMap<V> {
    type Target = HashMap<String, V>;
    fn deref(&self) -> &Self::Target {
        &self.cells
    }
}

impl<V> std::ops::DerefMut for ShardMap<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cells
    }
}

impl<V> Default for MapShard<V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(ShardMap {
                cells: HashMap::new(),
                pending: Pending::default(),
                posted: HashMap::new(),
            }),
            sweep_ticker: AtomicU32::new(0),
        }
    }
}

/// A key-id-sharded `HashMap`, replacing a single `RwLock<HashMap>` that every governed request
/// contended. A key always resolves to the SAME shard (`stable_hash(key_id) & (GOV_SHARDS-1)`), so
/// per-key semantics (window straddle, atomic check-and-charge, spend carry) are byte-identical to
/// the single-lock version — only requests for DIFFERENT keys whose ids land in different shards no
/// longer serialize on one lock. Whole-map operations (flush / hydrate / usage sweep) iterate every
/// shard.
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

    /// The shard owning `key_id`. `GOV_SHARDS` is a power of two, so this masks the stable hash — a
    /// process-stable hash (NOT `DefaultHasher`) so a key maps to the same shard across restarts,
    /// which is irrelevant to correctness (the maps are ephemeral) but keeps behaviour deterministic.
    #[inline]
    fn shard_for(&self, key_id: &str) -> &MapShard<V> {
        &self.shards[self.shard_index(key_id)]
    }

    /// The shard INDEX owning `key_id` - for the budget-chain charge, which must acquire SEVERAL
    /// shards' locks in ascending index order (a canonical order makes the multi-shard critical
    /// section deadlock-free).
    #[inline]
    fn shard_index(&self, key_id: &str) -> usize {
        (busbar_kernel::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)
    }

    /// The shard at a known index (see [`Sharded::shard_index`]).
    #[inline]
    fn shard_at(&self, idx: usize) -> &MapShard<V> {
        &self.shards[idx]
    }

    /// Acquire this key's shard for writing (poison-recovering — a panic under any holder must not
    /// cascade into a governance outage on the request path; the maps' invariants are re-established
    /// per call, so the recovered guard is safe to use).
    #[inline]
    fn write(&self, key_id: &str) -> std::sync::RwLockWriteGuard<'_, ShardMap<V>> {
        self.shard_for(key_id)
            .map
            .write()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire this key's shard for reading (poison-recovering, same rationale as [`Sharded::write`]).
    #[inline]
    fn read(&self, key_id: &str) -> std::sync::RwLockReadGuard<'_, ShardMap<V>> {
        self.shard_for(key_id)
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Every shard's write guard, in shard order — for the whole-map operations that must visit ALL
    /// keys (the write-behind flush snapshot). Each guard is acquired lazily by the iterator, so only
    /// one shard is locked at a time (no cross-shard deadlock, and a concurrent per-key op contends
    /// only for the single shard the iterator currently holds).
    fn write_all(&self) -> impl Iterator<Item = std::sync::RwLockWriteGuard<'_, ShardMap<V>>> {
        self.shards
            .iter()
            .map(|s| s.map.write().unwrap_or_else(|p| p.into_inner()))
    }

    /// TEST-ONLY: the sweep ticker for the shard owning `key_id`, so a test can drive the amortized
    /// sweep cadence for a specific key exactly as it did against the old single global ticker.
    #[cfg(test)]
    fn sweep_ticker_for(&self, key_id: &str) -> &AtomicU32 {
        &self.shard_for(key_id).sweep_ticker
    }

    /// TEST-ONLY: the raw shard lock owning `key_id`, for the poison-recovery test (it panics inside
    /// the write guard to poison exactly the shard the key resolves to, then asserts the hot path
    /// recovers for that same key).
    #[cfg(test)]
    fn shard_lock_for(&self, key_id: &str) -> &RwLock<ShardMap<V>> {
        &self.shard_for(key_id).map
    }
}

/// The two auth-path caches, held together under `GovState::caches`'s single `RwLock` so `refresh`
/// can swap both in one critical section. `by_id` is the subject-id → key index; it backs
/// `lookup_by_sub` (the signed-token verify hot path — 1.5.0 has exactly one bearer-credential
/// shape, so this is the only key index needed — bearer auth is never represented in
/// `by_credential`, see that field's doc). `by_credential` is the ROW-LOOKED-UP credential index
/// (today: SigV4 only) for inbound resolution on the SigV4-credential verify hot path, generalized from the
/// old AWS-specific `by_access_key_id`/`AwsKeyEntry` — see [`busbar_contract::records::CredentialMeta`]'s doc for
/// why a kind belongs here at all. Both are rebuilt by `refresh` from the SAME store snapshot, so a
/// disabled/deleted/re-minted key or revoked credential is reflected in both — visible to readers
/// atomically (the one lock guarantees no reader sees a half-applied swap).
struct GovCaches {
    /// Subject id (the key id / token `sub`) → key. Values are `Arc<VirtualKey>` so the per-request
    /// signed-token resolution (on the request hot path) is a REFCOUNT BUMP rather than a deep clone of
    /// a multi-`String` `VirtualKey` under the read lock — the resolved key is immutable for the
    /// life of the request and threaded read-only through governance/routing, so sharing it via
    /// `Arc` is exact.
    by_id: HashMap<String, Arc<VirtualKey>>,
    /// `(kind, public_id)` → the resolved credential secret PLUS its owning key. The wire-supplied
    /// public identifier (SigV4: the AccessKeyId, plaintext in the `Authorization` header's
    /// `Credential=` field — a lookup handle, not a secret) is the lookup key; the value bundles the
    /// full [`CredentialSecret`] (its own `revoked_at`/`expires_at`) with the owning
    /// `Arc<VirtualKey>` so the verify path resolves both key-level and credential-level admission
    /// state in one lookup, no second index hop. Only keys with at least one live credential appear
    /// here.
    by_credential: CredentialIndex,
}

/// `(kind, public_id)` -> the resolved credential secret plus its owning key — see
/// [`GovCaches::by_credential`]'s doc for the shape's reasoning. Named so clippy's
/// `type_complexity` lint (and every future reader) sees one name instead of the raw nested type
/// at every call site.
pub type CredentialIndex = HashMap<(String, String), (Arc<VirtualKey>, CredentialSecret)>;

/// Per-instance governance runtime: the durable `Store` plus an in-memory key cache (hashed-secret
/// → key) so validation on the hot path is a map lookup, not a DB round-trip. Held in `App`
/// (always `Some` in a running engine — governance is always constructed; `None` only in tests that
/// omit it) — NOT a process-global, so tests stay isolated.
pub struct GovState {
    store: Arc<dyn RecordStore>,
    /// Both auth-path caches under ONE lock so `refresh` swaps them atomically — a reader can never
    /// observe a new `by_hash` against a stale `by_access_key_id`. See `GovCaches`.
    caches: RwLock<GovCaches>,
    /// Per-GROUP in-flight gauges for the `concurrent` limit metric (instantaneous - no window).
    /// Keyed by group NAME (stable across config applies, while `CostModel` group indices are
    /// not); values are `Arc`ed atomics so an [`AdmitGrant`] holds its release handles without
    /// touching the map again. Read-locked on the hot path (atomics mutate through a shared ref);
    /// write-locked only to materialise a gauge on first sight.
    concurrent: RwLock<HashMap<String, Arc<std::sync::atomic::AtomicI64>>>,
    /// SHA-256 hex digest of the configured /admin bearer token. The plaintext token is NOT retained
    /// — only its digest, which is all the constant-time compare on the /admin path needs (less
    /// plaintext secret held in memory). `None` = admin API disabled.
    ///
    /// RE-SETTABLE (`set_admin_token`): `GovState` is process-lifetime and is REUSED across every
    /// config apply/reload (the key cache, ledgers and rate windows must survive one), so a digest
    /// frozen at construction meant rotating `auth.admin_auth`'s token secret and reloading had NO
    /// effect — the process kept accepting the boot-time credential forever.
    admin_token_hash: RwLock<Option<String>>,
    /// AUTHORITATIVE in-memory TOKEN-LEDGER cells - the hard-cap admission state consulted (and
    /// charged) on the request hot path with NO await and NO store round-trip. Keyed by BUCKET id:
    /// a virtual key's id, or `group:<name>` for a budget-group bucket - key buckets and group
    /// buckets are the same machinery. One `BudgetCell` per bucket for its CURRENT window (reset on
    /// rollover), so the map is bucket-count-bounded (keys + group-window buckets). The durable store is a
    /// WRITE-BEHIND layer: `flush_budgets` pushes each dirty cell's per-model TOKEN deltas
    /// additively off the request path, and boot `hydrate_budgets` re-loads accrued ledgers so a
    /// restart forgets nothing. The atomic chain check-and-charge acquires every involved shard
    /// lock in ascending shard order (deadlock-free), so admission against the whole chain is one
    /// indivisible critical section per node.
    /// NOTE (perf): the old `token_spend_carry` sub-cent carry map is GONE - the ledger
    /// stores raw tokens and spend derives at read time, so there is no remainder to carry and no
    /// O(n) carry sweep to amortize.
    budget: Sharded<BudgetCell>,
    /// The PENDING metering rows, keyed by the stores' own upsert key `(key_id, bucket, model,
    /// provider, priced_from_ms)` and SHARDED [`GOV_SHARDS`] ways (see [`PendingMetering`]) so
    /// concurrent request-completion accruals contend only within a shard. The recorder takes them
    /// every flush window into its unsent accumulator (MONEY-DESIGN §3c), whose RAM high-water alarm
    /// covers them; nothing is coalesced or dropped.
    pending_metering: PendingMetering,
    /// Each bucket's last derived figure, read by the `/metrics` scrape (see [`money_view`]).
    money_view: state::money_view::MoneyView,
    /// The busbar SIGNING material (1.5.0) — the mint-side signer paired with the
    /// verify-side public keyset, held together so they can never drift. `Some` once a signing key
    /// is resolved/generated at boot; `None` in the (test) path that constructs GovState without
    /// signing (SigV4-only / legacy-hash tests).
    ///
    /// RE-SETTABLE (`set_signing_key`) for the same reason as `admin_token_hash`: `auth.signing_key`
    /// is a SecretRef, and a reused `GovState` never re-resolved it, so rotating the underlying
    /// secret and reloading silently kept minting and accepting tokens under the old key. Read as an
    /// `Arc` clone on the verify hot path, so the lock is held only for the clone.
    signing: RwLock<Option<Arc<SigningMaterial>>>,
    /// The revocation DENYLIST as an in-memory set of subject ids, hydrated from the store at boot,
    /// updated live on revoke, and RE-HYDRATED from the store on a bounded TTL (see
    /// [`REVOCATION_SYNC_TTL_SECS`]). A verified token whose `sub` is present is rejected - the ONLY
    /// state the otherwise-stateless verify path reads.
    ///
    /// The re-hydration is a blocking store round-trip and the auth path is an `async fn` on a Tokio
    /// worker, so the set and its refresh live in [`revocation::RevocationSync`], which keeps the
    /// read OFF the reactor and BOUNDS it. The request path only ever reads the set; see that
    /// module's docs for why, and for what the offload costs.
    denylist: Arc<revocation::RevocationSync>,
    /// Serializes `refresh` so a slow reader-load cannot clobber a newer swap (lost-update guard).
    /// `refresh` loads the full key set from the store OUTSIDE the `caches` write lock (to keep that
    /// critical section short), then swaps. Without serialization, two concurrent refreshes could
    /// interleave load-A, load-B, swap-B, swap-A where load-A predates B's committed mutation — so
    /// the final cache is missing B's key until the next mutation. Holding this mutex across the
    /// ENTIRE load→swap means a later refresh's load begins only after the earlier refresh's swap
    /// has committed, so it can never contain strictly-older store state. Guarded data is `()`;
    /// a poisoned lock is recovered with `into_inner()` (serializing is strictly better than not).
    refresh_lock: std::sync::Mutex<()>,
    /// Serializes the SELF-SERVE mint upsert (`issue_self`/`refresh_self`): each does a
    /// current-binding CHECK then a write, and without this an issue racing a refresh could strand a
    /// second enabled binding for the same `user:<sub>` (breaking the one-key-per-sub invariant that
    /// justifies excluding self-keys from the anti-sprawl cap). Guarded data is `()`; a poisoned lock
    /// is recovered with `into_inner()`. (The deterministic id already makes two concurrent *issues*
    /// idempotent by id; this closes the issue/refresh interleaving and non-idempotent stores.)
    self_mint_lock: std::sync::Mutex<()>,
    /// Whether the self-serve mint holds an admin's state and the minting provider
    /// ([`SELF_MINT_HOLDS_ADMIN_AND_PROVIDER_STATE`]); set from that const at construction.
    self_mint_holds: std::sync::atomic::AtomicBool,
    /// The configured store's store v3 slots (its typed records among them), when it was opened
    /// through a door ([`busbar_contract::store_calls::OpenedStore::calls`]): what the kernel's host
    /// services serve plane records over ([`Self::attach_store_calls`]).
    store_calls: std::sync::OnceLock<Arc<dyn busbar_contract::store_calls::StoreCalls>>,
    /// THE CALLER-REFERENCE KEY a verified principal's units are lent their reference under, live
    /// ([`crate::plane_driver::CallerRefs`]): derived from the signing material when the node has
    /// one, else from the deployment keyset the book binds (row 159 H2), so every verified principal
    /// gets a stable, non-empty reference whatever its auth chain.
    caller_refs: crate::plane_driver::CallerRefs,
    /// The deployment keyset's caller-reference material, once the book binds the keyset.
    deployment_caller_ref: RwLock<Option<[u8; 32]>>,
    /// This boot's random caller-reference key: the last resort when the node has neither signing
    /// material nor a deployment keyset, so a verified principal is never lent the empty reference.
    /// Zeroised on drop and never logged (`GovState` has no `Debug`).
    boot_caller_ref: zeroize::Zeroizing<[u8; 32]>,
    /// THE RECORDER of the configured store (MONEY-DESIGN §3c), attached once at boot: it takes
    /// the shards' pending deltas off the request path and posts them.
    recorder: std::sync::OnceLock<Arc<crate::posting::recorder::Recorder>>,
    /// `advanced.strict_spend_recording`: refuse (503) an admission whose spend cannot be recorded.
    strict: std::sync::atomic::AtomicBool,
    /// THE FLEET SNAPSHOT (MONEY-DESIGN §3d): other nodes' counts per capped bucket, refreshed by a
    /// background tick, read by admission without a lock or an await.
    foreign: arc_swap::ArcSwap<recording::Snapshot>,
    /// Wakes the snapshot task when a capped bucket is touched with no fresh snapshot.
    snapshot_wake: tokio::sync::Notify,
    /// The snapshot task runs (only then is it worth waking).
    snapshot_running: std::sync::atomic::AtomicBool,
    /// The snapshot holds a reading that matters to admission (foreign counts, or a failing read):
    /// on one node never, so admission pays one atomic load and no snapshot read at all.
    snapshot_live: std::sync::atomic::AtomicBool,
}

/// Recording counts off the request path: the recorder, strict mode and the fleet snapshot.
#[path = "recording.rs"]
pub mod recording;

use state::state_rows;

/// The busbar signing key as ONE unit: the mint-side signer and the verify-side keyset derived
/// from it. Swapped atomically by `GovState::set_signing_key`, so a reload can never leave the
/// engine minting under one key while verifying under another.
pub struct SigningMaterial {
    signer: crate::governance::signing::TokenSigner,
    verifier: crate::governance::signing::TokenVerifier,
}

impl SigningMaterial {
    /// Derive the verifier from the signer (the only construction path — they cannot drift).
    fn new(signer: crate::governance::signing::TokenSigner) -> Self {
        let verifier =
            crate::governance::signing::TokenVerifier::single(signer.kid(), signer.verifying_key());
        Self { signer, verifier }
    }
}

/// What `POST /keys/{id}/rotate` re-issued: a 1.5.0 signed-token binding at a freshly-minted
/// generation. Every token issued before the rotation is now rejected by `verify_token`. (1.5.0 has
/// exactly one bearer-credential shape — a signed token — so rotation has exactly one outcome; the
/// legacy hashed-secret rotation arm this type used to carry was removed with the legacy verify
/// path itself.)
pub struct RotatedCredential {
    pub key: VirtualKey,
    pub token: busbar_contract::redacted::Secret<String>,
    pub exp: u64,
}

// The mint-parameter struct (`NewKeySpec`) — pure auth data, no `App`/`Store` — moved to the neutral
// substrate so a plane crate names it without reaching into busbar-core; re-exported here so every
// `crate::governance::NewKeySpec` construction site is unchanged. `pub`: the canonical
// public spelling is the substrate's own, and nothing outside busbar-core reaches this path.

pub mod revocation;
// The RESOLVED runtime mint policy (`auth.policy:`) — de-aliased out of `admin` (1.6.0, stage 2a):
// core governance/config infrastructure read on the hot mint path, not admin-API surface.
pub mod mint_policy;
// Group auto-provisioning (`plan_mint_group`/`persist_provisioned_group`/`build_with_group`) — the
// config-apply-transaction's governance-group-provisioning LOGIC, de-aliased out of `admin` (1.6.0,
// stage 2a) so `auth::self_keys` (core) no longer reaches into the admin namespace to provision a
// self-serve key's personal budget group.
pub mod group_provision;
// The busbar-SIGNED token crypto (signer, stateless verifier, claims, prefix/kid constants) lives
// in the neutral substrate. This crate held a one-line `signing.rs` that re-exported it `pub`; the
// module itself is re-exported here instead, `pub`, so every in-core
// `crate::governance::signing::…` path resolves to exactly the same items and nothing outside
// busbar-core reaches them through this crate.
mod state;

/// Which self-serve mint operation [`mint_self_offloaded`] should run on the blocking pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfMintOp {
    Issue,
    Refresh,
}

/// Whether the self-serve mint holds an admin's state and the minting provider across a login (K3
/// #17, #21): a subject whose binding an admin disabled, or that another identity provider minted,
/// is refused (403), and the epoch probe treats ANY existing row as occupied, so a login never
/// writes over a disabled, rotated or moved row. `false` is 1.5.5's behaviour, which this build keeps
/// until the owner signs the change (Q128 u31): no refusal, and the probe skips only tombstoned rows,
/// so a login re-enables an admin-disabled binding at its derived id (v1.5.5
/// crates/busbar/src/governance/state.rs:431 skips only tombstones; :560 mints). The owner's
/// signature flips this one line.
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

/// THE single async door onto the self-serve mint path (`GovState::issue_self` /
/// `GovState::refresh_self`). Both mint fns take `self_mint_lock` — a plain
/// `std::sync::Mutex`, NOT a `tokio::sync::Mutex` — and, still holding it, perform SYNCHRONOUS
/// store I/O (`write_self_binding` -> `store.put_key`, and on refresh `store.delete_key`). A
/// durable `Store` plugin implements those with real network/disk I/O. Calling either fn directly
/// from an `async fn` therefore runs a blocking critical section INLINE on whatever Tokio worker
/// is executing the handler: under concurrent logins against a slow store, that worker stalls
/// every other task queued on it, including unrelated data-plane requests. `spawn_blocking` moves
/// the ENTIRE lock+I/O critical section onto the blocking pool instead, so the mutex is only ever
/// held on a blocking thread — mirrors `admin/mod.rs`'s `rotate_key`/`config_transaction` pattern
/// exactly (the `Arc<GovState>` cloned into the closure, the sync call made there, a `JoinError`
/// on `.await` mapped to a `StoreError` rather than panicking or unwrapping).
///
/// REQUEST-PATH CALLERS (today: the `POST /auth/token` token-exchange handlers in
/// `auth/self_keys.rs`) MUST route through this — never call `GovState::issue_self` /
/// `GovState::refresh_self` directly from an `async fn` on the reactor. This is NOT for the hot
/// data-plane proxy path: that path performs no per-request store I/O (metering is write-behind,
/// flushed on its own `spawn_blocking` tick), so it must never be wrapped in `spawn_blocking`.
pub async fn mint_self_offloaded(
    gov: Arc<GovState>,
    op: SelfMintOp,
    user_sub: String,
    provider: String,
    allowed_pools: Option<Vec<String>>,
    exp: u64,
    now: u64,
) -> Result<(VirtualKey, String), SelfMintError> {
    tokio::task::spawn_blocking(move || match op {
        SelfMintOp::Issue => gov.issue_self(&user_sub, &provider, allowed_pools, exp, now),
        SelfMintOp::Refresh => gov.refresh_self(&user_sub, &provider, allowed_pools, exp, now),
    })
    .await
    .unwrap_or_else(|e| {
        Err(SelfMintError::Store(RecordStoreError(format!(
            "self-serve mint task failed to join: {e}"
        ))))
    })
}

/// THE GOVERNANCE RE-KEY for a ROLE-CARRYING principal (an external auth module's verdict): a
/// synthesized `VirtualKey` built from the principal's roles under the identifying MODULE's
/// `role_bindings` table (bindings are nested by module - `bindings` here is
/// `role_bindings.<identifying module>`; a role asserted by another module never rides it).
/// An SSO user and a virtual key then get identical enforcement (pool ACL, group limits, usage
/// attribution, the hook `send_user` projection) through identical code.
///
/// Fail-closed: `None` when no role of the principal is bound (an unbound role grants nothing),
/// or when the bound pool grants union to the EMPTY SET (`allowed_pools: []` = NO pools).
/// Pool semantics: a binding that OMITS `allowed_pools` grants ALL pools; lists union.
/// Limits come ONLY from the bound `group:` (keys/principals carry no inline caps); with several
/// bound groups the first in role order wins (one group per principal - the chain is a tree).
pub fn synthesize_principal_key(
    principal: &crate::auth::Principal,
    bindings: Option<&std::collections::BTreeMap<String, crate::config::RoleBindingCfg>>,
) -> Option<Arc<VirtualKey>> {
    synthesize_key(principal, bindings).map(Arc::new)
}

/// The `generation_hash` prefix of a key SYNTHESIZED from `role_bindings` (never a registry row:
/// every registry key carries [`BINDING_MARKER_PREFIX`]). Like that marker it authenticates nothing;
/// it records HOW the key was admitted, so a long-lived response can re-check it the same way.
pub const PRINCIPAL_MARKER_PREFIX: &str = "principal:";

/// THE DATA-PLANE RE-KEY THROUGH A MODULE'S BINDINGS: [`synthesize_principal_key`] over
/// `role_bindings.<module>`, with the key's marker recording the admission — the identifying
/// `module` and the principal's `roles` — so [`bound_admission`] can read it back and a
/// `Standing` opened on this key re-checks it against the LIVE bindings rather than the registry
/// (which a synthesized key is never in). Same grant, same fail-closed `None`, as the bare synthesis.
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

/// HOW A BOUND KEY WAS ADMITTED, read back off a key [`synthesize_bound_key`] minted: the
/// identifying module and the principal as the verdict asserted it (id, the key's display name, its
/// roles). `None` for every other key — a registry row, or a marker whose recorded id is not the
/// key's own (a stamp this function did not write is not trusted to re-route the re-check).
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

/// The LIVE re-resolution a `Standing` needs on the host: the governance registry for a registry
/// key, and the CURRENT `role_bindings` for a bound one. Built per re-ask from the live snapshot,
/// so a binding removed or narrowed by a config apply is what the next frame is judged against.
pub struct LiveResolve<'a> {
    /// The live registry; `None` where governance is disabled (a registry key then lapses).
    pub governance: Option<&'a GovState>,
    /// The live `auth.role_bindings` table.
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

/// The principal's granting bindings in one module's `role_bindings` table, in role order (ALL of
/// them, not just the first role that has a binding).
pub(crate) fn granting_bindings<'a>(
    principal: &crate::auth::Principal,
    table: &'a std::collections::BTreeMap<String, crate::config::RoleBindingCfg>,
) -> Vec<&'a crate::config::RoleBindingCfg> {
    principal
        .roles
        .iter()
        .filter_map(|role| table.get(role))
        .collect()
}

/// The pool union across granting bindings. OMITTED `allowed_pools` on any granting binding widens
/// the union to ALL pools (`None`, the runtime encoding too); otherwise the union is the
/// de-duplicated concatenation of every binding's explicit list (an explicit `[]` contributes
/// nothing, so an every-binding-`[]` union is `Some(vec![])`).
pub(crate) fn pool_union(granting: &[&crate::config::RoleBindingCfg]) -> Option<Vec<String>> {
    let mut pool_names: Vec<String> = Vec::new();
    for b in granting {
        let list = b.allowed_pools.as_deref()?;
        for p in list {
            if !pool_names.contains(p) {
                pool_names.push(p.clone());
            }
        }
    }
    Some(pool_names)
}

/// A pool grant as key scopes, intent carried intact: `None` = all pools; `Some([])` = none.
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
    // BUCKET-NAMESPACE GUARD: the synthesized key's `id` becomes its LEDGER
    // BUCKET id, and group buckets live in the same store namespace as `group:<name>`. A
    // principal id (attacker-influenced at the IdP) literally starting with `group:` would alias a
    // group's cell - charging it, reading it, and corrupting group enforcement. Fail closed:
    // such a principal gets NO synthetic key (no data-plane access), never a colliding bucket.
    //
    // The SAME hazard applies to the `vk_` prefix: a real virtual key's id is `vk_<16 hex>` and is
    // its ledger/rate bucket id. An IdP subject shaped `vk_<...>` would alias a real virtual key's
    // ledger + rate bucket (charging/reading it, or riding its rate window). Reserve `vk_` too.
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
    // An all-bindings-empty union = the EMPTY SET = no data-plane access (fail closed: no key at
    // all - nothing to admit).
    let allowed_pools = match pool_union(&granting) {
        Some(list) if list.is_empty() => return None,
        union => union,
    };
    // The bound group (first in role order). Group limits are enforced through the group chain;
    // the key itself carries NO inline caps (keys are pure auth).
    let group = granting.iter().find_map(|b| b.group.clone());
    Some(VirtualKey {
        id: principal.id.clone(),
        // NOT a credential hash — a marker. The synthetic key never authenticates anything (the
        // auth module already did); it exists purely to carry grants through enforcement.
        generation_hash: format!("principal:{}", principal.id),
        name: principal
            .name
            .clone()
            .unwrap_or_else(|| principal.id.clone()),
        allowed_scopes: pool_scopes(allowed_pools),
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

/// The per-request context a plane handler receives: the resolved caller identity attached to each
/// request by the auth middleware, in a form any plane crate can name without reaching for
/// a core-private governance type. Relocated to `busbar-api` in Phase-B B0-a (beside [`VirtualKey`])
/// so an extracted plane crate names it without a path back to core; re-exported here so every
/// in-core call site (`governance::PlaneRequestCtx`, and the [`GovCtx`] alias) is unchanged.
///
/// The re-export is `pub`: the canonical public spelling is `busbar_contract::records::PlaneRequestCtx`,
/// and a caller outside this crate names it there. Nothing outside busbar-core reaches this path.
pub use busbar_contract::records::PlaneRequestCtx;

/// The name core uses internally for the resolved governance context. Core owns the governance
/// concept and keeps its own spelling; a plane names [`busbar_contract::records::PlaneRequestCtx`] instead so an
/// extracted plane carries no core-private governance type.
pub type GovCtx = busbar_contract::records::PlaneRequestCtx;

/// Generate a virtual-key secret from 32 bytes of the OS CSPRNG (portable across Unix/Windows via
/// getrandom). 256 bits — parity with the AWS secret access key beside it, raised from the old 128-bit
/// width (still brute-force-infeasible, but 128 was the one credential axis below the project's own
/// bar). Fails closed: if the OS exposes no entropy source we refuse to mint a key rather than fall
/// back to a guessable (time-derived) secret. getrandom failure is near-impossible on supported
/// platforms; on failure we return the error so the caller (`create_key`) surfaces a 500 instead of
/// panicking the process — the server stays up.
///
/// Gated with its two callers. Once `create_key`/`create_key_with_aws` are test-only, the HASHED
/// BEARER SECRET has no production minting path left at all — which is the shape 1.5.0 retired
/// (every live key is a signed-token binding; see `docs/migration-1.5.md`). The compiler said so
/// the moment the doors closed, and the answer is to close this too rather than to silence it.
#[cfg(any(test, feature = "test-support"))]
fn generate_secret() -> Result<String, getrandom::Error> {
    // Portable OS CSPRNG via getrandom: /dev/urandom on Unix, BCryptGenRandom on Windows, etc.
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)?;
    Ok(format!("{SK_SECRET_PREFIX}{}", hex::encode(buf)))
}

/// `n` symbols of `alphabet`, each picked by one byte of the OS CSPRNG (`byte % len`, the alphabet
/// at most 256 symbols long, as the loader admits it). Fails closed (the error surfaces as a 500,
/// never a panic) when the OS exposes no entropy.
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

/// THE ISSUED CREDENTIAL over `shape` (the verifier's Statement's issued-shape marks): the public
/// id, its prefix then symbols of its alphabet up to its length, and the secret, symbols of its
/// alphabet. The host names no format of its own; every symbol is a CSPRNG draw. The public id is
/// the lookup handle and travels in the clear; the secret is shown once.
pub(crate) fn issue_credential(
    shape: &busbar_contract::auth_calls::IssuedShape,
) -> Result<(String, String), getrandom::Error> {
    let tail = shape.id_len.saturating_sub(shape.id_prefix.len());
    let id = format!("{}{}", shape.id_prefix, draw(&shape.id_alphabet, tail)?);
    Ok((id, draw(&shape.secret_alphabet, shape.secret_len)?))
}

/// Whether `key` may target `pool` (an OMITTED grant = all pools; an explicit list is
/// exhaustive; an explicit `[]` = NO pools). Delegates to the contract crate's encoding.
pub fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.scope_allowed("pool", pool)
}

/// The epoch start of the window containing `now` for a given window word (nouns): `total` = a
/// single all-time window (0); `day` = UTC midnight; `month` = UTC first-of-month.
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
        WINDOW_TOTAL => 0, // explicit all-time window (the documented sentinel)
        // An unrecognized window word can only arise from a corrupt/foreign store row (config
        // parse rejects it). Fail SAFE to the all-time window (0), the tightest enforcement,
        // never wider, with a diagnostic so the corruption is visible instead of silent.
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

/// The epoch at which `period`'s window containing `now` ROLLS to the next window - the
/// `Retry-After` source for a windowed-limit rejection. `None` for `total` (never rolls) and for
/// an unrecognized word (backstopped to `total` above).
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

// Public-domain civil-date algorithms (same approach as sigv4); self-contained, no date crate.
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

// `Store` and `VirtualKey` were re-exported `pub` for extracted-plane in-test store doubles and a
// relocated plane's credential lowering. Neither reaches this path any
// more — every caller outside busbar-core names `busbar_contract::records::{RecordStore, VirtualKey}` directly — so the
// two join the crate-internal list below rather than standing as a second public name for one type.
pub use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, RecordStore, RecordStoreError,
    RecordStoreResult, SecretForm, UsageDelta, VirtualKey,
};
// The full-ledger record is consumed only by TEST assertions (production reads go through the
// derived views); scoping the re-export keeps the release build warning-free.
#[cfg(test)]
pub use busbar_contract::records::UsageLedger;
// `ScopeRef` is constructed directly via `busbar_contract::records::ScopeRef` on every production call site
// (cost.rs, config/groups.rs, governance/state.rs); this re-export exists only so test code that
// does `use super::*` from within `governance::tests` can name it unqualified, same reasoning as
// `UsageLedger` above.
#[cfg(test)]
pub use busbar_contract::records::ScopeRef;
/// The lane qualifier a non-llm plane keys its budget rows with, so the view resolves THAT plane's
/// card (#42/#47) — keying, not pricing: the plane names its own lane, the ledger crate prices it.
pub use busbar_kernel_ledger::cost::PLANE_LANE_SEP;

// The metering-bucket time base (`METERING_BUCKET_SECS` + the `metering_bucket` floor fn below) is
// pure arithmetic — moved to the neutral substrate so a plane crate names it without reaching into
// busbar-core; both re-exported here so every `crate::governance::…` caller is unchanged.
// `pub`: the canonical public spelling is the substrate's own, and nothing outside
// busbar-core reaches this path.

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
    /// ONE METERED REQUEST whose count columns are read from `units` by class name. The metering
    /// row's four count columns are the contract's reserved classes
    /// ([`busbar_contract::records::RESERVED_UNITS`], in its canonical order), so which classes the
    /// columns hold is the row's own fact, read from the contract, never a plane's. Every other
    /// class rides the row's `usage_units` through the ledger's class mirror, not here.
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

    /// Accumulate `other` into `self`, saturating each counter — the one place metering cells are
    /// merged, so accrual and flush-retry both add usage the same way and neither can wrap.
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

    /// Nothing counted at all — a cell the flush has nothing to write for.
    pub fn is_zero(&self) -> bool {
        self.requests == 0
            && self.tokens_input == 0
            && self.tokens_output == 0
            && self.tokens_cache_read == 0
            && self.tokens_cache_write == 0
            && self.usage_units.values().all(|n| *n == 0)
    }
}

/// The upsert key every metering cell is aggregated under:
/// `(key_id, bucket, model, provider, priced_from_ms)`, the store's own metering key. Named so the
/// accumulator and its flush read as one type, not a raw tuple repeated at every call site.
///
/// THE FIFTH MEMBER IS WHAT SPLITS A DAY. A bucket is a UTC day, so before it the read had no
/// instant between midnight and midnight to resolve the dated rate-card history at, and a card
/// published at noon either repriced the whole day or none of it (DECISION #79). The
/// `effective_from` of the entry in force AT ACCRUAL joins the key, so a card edit opens a second
/// cell and each half of the day prices against the card it was actually earned under. It is a
/// timestamp and not a version precisely so a back-dated correction can still reach it. Cardinality
/// grows by the number of card edits in a day and by nothing else — a deployment that never edits a
/// price has one value here forever and the key is arithmetically the previous release's.
pub type MeterKey = (String, u64, String, String, u64);

/// THE WRITE-BEHIND METERING ACCUMULATOR, sharded [`GOV_SHARDS`] ways exactly like the `budget` map
/// beside it and for the same reason: metering accrual runs on the REQUEST-COMPLETION hot path, and a
/// single process-wide `Mutex` serialized every concurrent response's accrual against every other's.
/// A metering key is sharded by its `key_id` (the accrual-cardinality driver, and the same field the
/// budget map shards on), so a given cell always lives in exactly ONE shard and per-cell accumulation
/// is byte-identical to the single-lock version — only accruals whose key_ids land in DIFFERENT
/// shards stop serializing.
///
/// EXACTLY ONCE, preserved: the single-lock design leaned on `mem::take` being an atomic full-map
/// swap so two concurrent flushes partition the arrivals and never double-send. Here each shard is
/// `mem::take`n under its OWN lock, and a key never migrates shards, so that same partition argument
/// holds per shard: every cell belongs to exactly one drain, and [`drain`](Self::drain) visits ALL
/// shards so nothing is stranded. Accrual and drain on the same shard serialize on that shard's lock,
/// so an accrual is either wholly before a drain (flushed this tick) or wholly after (next tick),
/// never split.
pub struct PendingMetering {
    shards: Box<[std::sync::Mutex<HashMap<MeterKey, MeterCounts>>]>,
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
        }
    }

    /// The shard owning `key_id`. `GOV_SHARDS` is a power of two, so this masks the same
    /// process-stable hash the budget map uses.
    #[inline]
    fn shard_for(&self, key_id: &str) -> &std::sync::Mutex<HashMap<MeterKey, MeterCounts>> {
        &self.shards[(busbar_kernel::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)]
    }

    /// Accrue on the hot path: lock ONLY the shard owning `key.0`, bounded to that shard's slice of
    /// the cap. Poison-recovering — a panic under some other holder must not wedge accrual for a whole
    /// shard of keys (the cells' invariant is re-established per call).
    pub fn accrue(&self, key: MeterKey, add: MeterCounts) {
        let mut map = self
            .shard_for(&key.0)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Unbounded here: the recorder's accumulator alarms on its RAM high-water mark, metering
        // included (MONEY-DESIGN §3c), and nothing is coalesced or dropped.
        map.entry(key).or_default().merge(add);
    }

    /// DRAIN every shard, returning all pending cells. Each shard is emptied under its own lock; a
    /// concurrent accrual either landed before this shard's swap (drained now) or lands after
    /// (next tick). Iterating every shard is what makes the sharding invisible to the flush's
    /// exactly-once accounting.
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

    /// TEST-ONLY: total unflushed cell count and their SUMMED counts, across every shard.
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
        (len, sum)
    }
}

// The durable-store contract (the `Store` trait, its records, and `StoreError`) now lives in the
// `busbar-api` contract crate, re-exported above so the rest of the engine names them unchanged.
// getrandom errors convert into the api's backend-agnostic `StoreError` HERE via a local
// extension trait (the contract crate stays dependency-light). The SQLite backend lives in its own
// plugin crate (`busbar-store-sqlite`); the engine only names the `Store` contract + the re-exported type.
trait IntoStoreResult<T> {
    fn store(self) -> RecordStoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, getrandom::Error> {
    fn store(self) -> RecordStoreResult<T> {
        self.map_err(|e| RecordStoreError(format!("OS CSPRNG (getrandom) unavailable: {e}")))
    }
}

// The universal test double: the in-crate R-FIX3 store double (`test_support::store_double`), which a
// test build also links as its stand-in store row. The kernel names no store crate.
#[cfg(any(test, feature = "test-support"))]
pub use crate::test_support::store_double::MemoryStore;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod limits_tests;

#[cfg(test)]
#[path = "tests/budget_cell_tests.rs"]
mod budget_cell_tests;

#[cfg(test)]
#[path = "../tests/key_expires_at_tests.rs"]
mod key_expires_at_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
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

/// Seconds in a metering day bucket. Metering is a TIME SERIES in fixed UTC-day buckets —
/// deliberately decoupled from the per-key budget windows the enforcement counters use, so
/// per-model aggregation ACROSS keys has one well-defined time base.
pub const METERING_BUCKET_SECS: u64 = 86_400;

/// Floor an epoch to its UTC-day metering bucket start.
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

/// Seconds in a UTC day — the day boundary the budget windows and the metering buckets are floored
/// to. A bare calendar constant with no engine dependency, so it lives here in the neutral
/// governance vocabulary; the engine re-exports it as `busbar_kernel::governance::SECS_PER_DAY`.
pub const SECS_PER_DAY: u64 = 86_400;
