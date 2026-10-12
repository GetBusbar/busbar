// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION MONEY SEAM (`BUSBAR-1.6.0.md` THE DESIGN, §7; Part 3, §12 "The route pump" and
//! "Cancel"): the kernel's budget and ledger decisions behind the driver's [`MoneySeam`]. The plane
//! reports; the kernel writes. Nothing here prices a stored figure or posts a sealed line of its own:
//!
//! * the unit's spend is its far-end-REPORTED counts (never an estimate), ledgered once, at the end,
//!   through the governance book's one accrual (`GovState::record_usage`), which files it in the
//!   window of the unit's ARRIVAL epoch (THE DESIGN, section 7: "same balance, same window, same row");
//! * the unit's flat request fee is refunded as a separate act from the ledgering
//!   (`GovState::refund_charge`, over the admission's own charge), decided by the unit's
//!   [`FeeRefund`] rule: 1.5.5's non-2xx caller status, or, for a plane new in 1.6.0, the plane's
//!   own fee-unit report;
//! * a cancelled unit's bill (the four 1.5.5 cancel rules, computed by the driver) is ledgered the
//!   same way, and the unit's later end ledgers nothing twice;
//! * `on_exhaustion: finish-unit` (the default, 1.5.5) never cuts. `cut-stream` (new in 1.6.0) cuts
//!   a running unit once its reported counts, priced by the one money function at the card in
//!   force, reach what its tightest applicable budget has left; a count the card cannot price cuts
//!   (fail closed);
//! * an abandoned unit's sealed end goes to the composition root's one posting site
//!   ([`EndPost`]); this file seals nothing;
//! * a duplex session is ONE unit with ONE line (THE DESIGN §7, "A session is one unit with one
//!   line"): its turns' cumulative counts are checkpoints, a cancel on either side bills nothing of
//!   its own, and the session's one cleanup ([`MoneySeam::session_ended`]) ledgers the last
//!   far-end-reported (or floor) cumulative counts once, however the session ended.
//!
//! * a running unit's cumulative counts are CHECKPOINTS (THE DESIGN §7: "a checkpoint is a
//!   durability `unit.accrued` record"; "running reports are crash-safe checkpoints, never ledger
//!   lines"): the piece path only marks the unit dirty, and the composition root's flush tick
//!   ([`PlaneMoney::flush_checkpoints`], once per [`FlushEpoch`]) hands each dirty open unit's last
//!   counts to its [`Checkpointer`], at most once per epoch. Nothing is journaled, and the root's
//!   book is never locked, on the piece path.
//!
//! The kernel names no plane here: a unit's class names, model, pool and key are handed in by the
//! composition root when it opens the unit ([`PlaneMoney::open`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{units_bill, UnitCount};
use busbar_contract::caps::ReasonCode;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
use super::epoch::FlushEpoch;
use crate::config::groups::ExhaustionMode;
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::teller::{Ended, UnitCtx};

/// Micro-units per nano-unit of the one money function's answer.
const NANOS_PER_MICRO: u128 = 1_000;

/// Where an abandoned unit's sealed end is posted: the composition root's one posting site, onto
/// the book, balance and window a returned end settles on.
pub trait EndPost: Send + Sync {
    /// Post `ended`, the end the loop sealed for the unit whose caller went away. Runs inside a
    /// `Drop`: it must not panic, await or cross a plugin.
    fn post(&self, ctx: &UnitCtx, ended: Ended);
}

/// A unit's accrual so far, as its durability checkpoint carries it: counts, never a figure (#71).
/// The same reading the unit's one line is priced from (the root's `report_of`): its billing
/// counts (far-end-reported or floor, never an estimate) by class name with the fee units set
/// aside, whether a fee unit was incurred, and the key it is ledgered under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accrued {
    /// The key the unit is ledgered, metered and priced under ([`PlaneMoney::serving`]).
    pub lane: String,
    /// `1` when the plane reported a fee unit above zero, else `0`.
    pub fee_count: u64,
    /// The billing count per class name; a class at zero is left off.
    pub classes: BTreeMap<String, u64>,
}

/// WHERE A RUNNING UNIT'S CHECKPOINT IS JOURNALED: the composition root's book, as a durability
/// `unit.accrued` record on the hold the unit's admission opened (THE DESIGN §7). Called from the
/// root's flush tick alone ([`PlaneMoney::flush_checkpoints`]), never on the piece path.
pub trait Checkpointer: Send + Sync {
    /// Journal unit `key`'s accrual so far. A unit the root holds no facts for journals nothing.
    fn checkpoint(&self, key: UnitKey, accrued: &Accrued);
}

/// One unit's money facts, as the composition root knows them when it admits the unit.
#[derive(Clone)]
pub struct UnitMoney {
    /// The caller's key (the balance and the budget chain).
    pub key: Arc<VirtualKey>,
    /// The generation's cost model (the card and the budget chain).
    pub cost: Arc<CostModel>,
    /// The pool the unit routes over (a pool-scoped budget applies only to it).
    pub pool: String,
    /// The model the unit's counts are priced under.
    pub model: String,
    /// The plane's billable class names, in its tail's order: a [`UnitCount::class`] indexes them.
    pub classes: Arc<[String]>,
    /// The unit's arrival epoch, seconds: the window every figure of the unit files under.
    pub arrived: u64,
    /// The unit's budget mode, resolved by the root from its governing limits.
    pub mode: ExhaustionMode,
    /// Who decides the unit's flat-fee refund, chosen by the root for the unit's plane.
    pub fee: FeeRefund,
    /// What the unit's admission charged ([`AdmitGrant::charge`](crate::governance::AdmitGrant::charge)):
    /// the one input its fee refund reads.
    pub charge: crate::governance::FeeCharge,
}

/// WHO DECIDES A UNIT'S FLAT-FEE REFUND. The design's money section: the plane reports the units it
/// did "and whether a fee unit was incurred"; the one fee decider is the plane's report. The llm
/// plane keeps 1.5.5's caller-status rule byte-identical until it runs on the driver, where it
/// moves to its fee-unit report, so the end state has one decider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeRefund {
    /// 1.5.5's rule (`busbar-kernel/src/ingress/mod.rs`, the finish's `refund_on_non_2xx`): an end
    /// whose caller status is not a success refunds the fee charged at admission.
    CallerStatus,
    /// The plane decides: these indices into [`UnitMoney::classes`] are its declared fee units,
    /// each also a billable class (the tail check holds `fee_units ⊆ billable_classes`) reported as a
    /// billing count ([`units_bill`]) of 0 or 1. An end whose fee units report no count above zero
    /// refunds the fee. A fee unit's count is never ledgered as usage: the fee itself was charged
    /// at admission (#21).
    PlaneFeeUnits(Arc<[u32]>),
}

impl FeeRefund {
    /// Whether `class` is one of the plane's fee units (never ledgered as usage).
    fn is_fee(&self, class: u32) -> bool {
        match self {
            FeeRefund::CallerStatus => false,
            FeeRefund::PlaneFeeUnits(fees) => fees.contains(&class),
        }
    }

    /// Whether the end refunds the fee: `caller_status` under 1.5.5's rule, else the plane's report
    /// in `last` (no fee unit reported above zero).
    fn refunds(&self, caller_status: u32, last: &[UnitCount]) -> bool {
        match self {
            FeeRefund::CallerStatus => !(200..=299).contains(&caller_status),
            FeeRefund::PlaneFeeUnits(fees) => !last
                .iter()
                .any(|u| units_bill(u.source) && u.amount > 0 && fees.contains(&u.class)),
        }
    }
}

/// One open unit: its facts, its last cumulative counts, whether it has been ledgered, and whether
/// its caller went away (its end then waits only for the driver's cancel bill).
struct Open {
    money: UnitMoney,
    last: Vec<UnitCount>,
    ledgered: bool,
    abandoned: bool,
    /// The route step ended without a cancel: no bill will come.
    finished: bool,
    /// A duplex session opened on the unit ([`MoneySeam::session_opened`]): its line is the
    /// session end's, never a side's cancel bill.
    session: bool,
    /// The provider of the member that served the unit, once its answering attempt committed
    /// ([`MoneySeam::served`]); `None` while no member has answered. The served model replaces
    /// [`UnitMoney::model`] in `money` at the same moment, unless the plane named the unit's lane.
    provider: Option<String>,
    /// The plane named the unit's ledger lane ([`MoneySeam::laned`]): it is [`UnitMoney::model`]
    /// in `money` from then on, and a serving member no longer replaces it.
    laned: bool,
    /// The plane reported counts since the unit's last checkpoint was handed to the root.
    dirty: bool,
    /// The flush epoch the unit's last checkpoint was handed over in: at most one per epoch.
    flushed: Option<u64>,
}

/// THE KERNEL'S MONEY STEPS for one plane instance's units.
pub struct PlaneMoney {
    gov: Arc<GovState>,
    post: Arc<dyn EndPost>,
    units: Mutex<HashMap<UnitKey, Open>>,
    /// The root's flush epoch: a unit's checkpoint is handed over at most once per epoch.
    epoch: FlushEpoch,
}

impl PlaneMoney {
    /// The money steps over the governance book `gov`, posting abandoned ends through `post`.
    #[must_use]
    pub fn new(gov: Arc<GovState>, post: Arc<dyn EndPost>) -> Self {
        PlaneMoney {
            gov,
            post,
            units: Mutex::new(HashMap::new()),
            epoch: FlushEpoch::new(),
        }
    }

    /// The same money steps, their checkpoints paced by `epoch`: the composition root's flush
    /// epoch, bumped by its flush tick, shared by every plane it composes.
    #[must_use]
    pub fn with_epoch(mut self, epoch: FlushEpoch) -> Self {
        self.epoch = epoch;
        self
    }

    /// THE CHECKPOINT FLUSH, run by the composition root's flush tick (never the piece path): every
    /// open unit the plane reported counts for since its last checkpoint, and not yet checkpointed
    /// in this flush epoch, hands its last counts ([`Accrued`]) to `site`, once. A unit with no new
    /// counts writes nothing; a unit checkpointed in this epoch waits for the next; estimates alone
    /// are no accrual. The units' lock is released before `site` is called. Answers how many
    /// checkpoints were handed over.
    pub fn flush_checkpoints(&self, site: &dyn Checkpointer) -> usize {
        let now = self.epoch.now();
        let due: Vec<(UnitKey, Accrued)> = {
            let mut all = self.lock();
            all.iter_mut()
                .filter(|(_, open)| open.dirty && open.flushed != Some(now))
                .filter_map(|(key, open)| {
                    open.dirty = false;
                    let accrued = accrued(&open.money, &open.last);
                    // Estimates alone are no accrual: nothing to journal.
                    if accrued.classes.is_empty() && accrued.fee_count == 0 {
                        return None;
                    }
                    open.flushed = Some(now);
                    Some((*key, accrued))
                })
                .collect()
        };
        for (key, accrued) in &due {
            site.checkpoint(*key, accrued);
        }
        due.len()
    }

    /// The key its book lends a unit's caller reference under ([`GovState::caller_ref_key`]);
    /// `None` when the book signs nothing.
    #[must_use]
    pub fn caller_refs(&self) -> Option<Arc<crate::auth::CallerRefKey>> {
        self.gov.caller_ref_key().map(Arc::new)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UnitKey, Open>> {
        self.units
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Open unit `key`'s money facts, at its admission.
    pub fn open(&self, key: UnitKey, money: UnitMoney) {
        self.lock().insert(
            key,
            Open {
                money,
                last: Vec::new(),
                ledgered: false,
                abandoned: false,
                finished: false,
                session: false,
                provider: None,
                laned: false,
                dirty: false,
                flushed: None,
            },
        );
    }

    /// THE UNIT'S END, returned to its caller with `caller_status`: ledger its last far-end-
    /// reported counts (unless its cancel bill already did), and refund its flat request fee as
    /// the unit's [`FeeRefund`] rule decides: under [`FeeRefund::CallerStatus`] when that status is
    /// not a success, exactly 1.5.5's rule (`busbar-kernel/src/ingress/mod.rs`, the finish's
    /// `refund_on_non_2xx && !is_success` arm: "REFUND it for a request that produced no usable
    /// upstream result"); under [`FeeRefund::PlaneFeeUnits`] when the plane reported no fee unit.
    /// A unit whose caller went away before any answer returns through [`MoneySeam::abandoned`],
    /// never here, and is refunded nothing, as 1.5.5's dropped request never reached that arm. The
    /// unit's facts are closed either way.
    pub fn settle_end(&self, key: UnitKey, caller_status: u32) {
        let Some(open) = self.lock().remove(&key) else {
            return;
        };
        let m = &open.money;
        if !open.ledgered {
            let counts = reported(&open.last);
            self.ledger(m, &counts);
            // A DELIVERED end meters one request against the serving member, tokens or none
            // (v1.5.5 proxy/usage.rs:31-40 and :99-106).
            if (200..=299).contains(&caller_status) {
                self.meter(m, open.provider.as_deref(), &counts);
            }
        }
        if m.fee.refunds(caller_status, &open.last) {
            match &m.fee {
                FeeRefund::CallerStatus => self.gov.refund_charge(&m.charge),
                // A PLANE'S REFUND RETURNS ITS OWN FEE UNIT (TODO row 17, Q17-6): a session's
                // `per_session` comes back from the plane's fee lane by its class name.
                // The admission's charge (its request fee) comes back as it was charged; any other
                // fee unit the plane declares by its own name.
                FeeRefund::PlaneFeeUnits(fees) => {
                    self.gov.refund_charge(&m.charge);
                    for unit in fees
                        .iter()
                        .filter_map(|c| m.classes.get(*c as usize))
                        .filter(|u| u.as_str() != busbar_contract::plane::PER_REQUEST)
                    {
                        self.gov
                            .refund_fee_unit(&m.cost, &m.key, &m.pool, m.arrived, unit);
                    }
                }
            }
        }
    }

    /// Unit `key`'s last cumulative counts, as the plane reported them.
    #[must_use]
    pub fn last_counts(&self, key: UnitKey) -> Vec<UnitCount> {
        self.lock()
            .get(&key)
            .map(|o| o.last.clone())
            .unwrap_or_default()
    }

    /// The key unit `key` is ledgered, metered and priced under: the ledger lane its plane named
    /// ([`MoneySeam::laned`]), else its serving member's once its answer committed
    /// ([`MoneySeam::served`]), else the member it was opened with; `None` when no money facts are
    /// open for it.
    #[must_use]
    pub fn serving(&self, key: UnitKey) -> Option<String> {
        self.lock().get(&key).map(|o| o.money.model.clone())
    }

    /// How many units' money facts are open (a witness: every end closes its unit).
    #[must_use]
    pub fn open_units(&self) -> usize {
        self.lock().len()
    }

    /// Ledger `counts` (class index, amount) under the unit's model, pool and arrival window. A sum
    /// that would overflow bills the saturated figure, never a wrapped or zero one (fail closed);
    /// the plane check refuses a class counted twice, so a validated report never gets here.
    fn ledger(&self, m: &UnitMoney, counts: &[(u32, u64)]) {
        let counts = &usage_only(m, counts);
        let units = named(&m.classes, counts, u64::checked_add)
            .or_else(|| named(&m.classes, counts, |a, b| Some(a.saturating_add(b))))
            .unwrap_or_default();
        self.gov
            .record_usage(&m.cost, &m.key, &m.pool, &m.model, &units, m.arrived);
    }

    /// THE METERING ROW for a delivered (or reported-billed) unit: one request against the serving
    /// member, with the reported token tiers when the plane reported any — v1.5.5
    /// `crates/busbar/src/proxy/usage.rs` `ledger_and_meter` (:99-106: "even a zero-token delivered
    /// response counts its request") and `record_resp_usage` (:31-40: "A delivered response with NO
    /// token usage ... still METERS as one request against the serving model").
    ///
    /// The row is the one `GovState::record_usage`'s class mirror keys the same lane by, so nothing
    /// splits across two rows: an unqualified (pools) lane is `(model, served provider)` with the
    /// token split (no serving member, no row: 1.5.5's unresolvable lane metered nothing); a
    /// plane-qualified lane `"<plane>\u{1f}<subject>"` is `(subject, plane)` with no token split,
    /// its classes carried by the mirror.
    fn meter(&self, m: &UnitMoney, provider: Option<&str>, counts: &[(u32, u64)]) {
        use busbar_contract::records::{
            UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
        };
        let units = named(&m.classes, &usage_only(m, counts), u64::checked_add).unwrap_or_default();
        let tier = |unit: &str| units.get(unit).copied();
        let tokens = [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE]
            .iter()
            .any(|u| units.contains_key(*u))
            .then(|| crate::billing::TokenUsage {
                input: tier(UNIT_INPUT).unwrap_or(0),
                output: tier(UNIT_OUTPUT).unwrap_or(0),
                cache_read: tier(UNIT_CACHE_READ),
                cache_creation: tier(UNIT_CACHE_WRITE),
                ..Default::default()
            });
        self.gov
            .record_lane_metering(&m.key.id, &m.model, provider, tokens.as_ref(), m.arrived);
    }

    /// Whether `counts`, priced at the card in force, reach what the unit's tightest applicable
    /// budget has left. A count the card cannot price reaches it (fail closed).
    fn dry(&self, m: &UnitMoney, counts: &[(u32, u64)]) -> bool {
        let remaining = self
            .gov
            .budget_state(&m.cost, &m.key, m.arrived)
            .into_iter()
            .filter(|b| b.pool.as_deref().is_none_or(|p| p == m.pool))
            .filter_map(|b| b.remaining_micros)
            .min();
        let Some(remaining) = remaining else {
            return false; // no budget applies: nothing to run dry
        };
        let Some(usage_units) = named(&m.classes, &usage_only(m, counts), u64::checked_add) else {
            return true; // a report that does not add up is a plane fault: fail closed
        };
        let usage = busbar_contract::billing::Usage { usage_units };
        match m.cost.price_usage_nanos(&m.model, &usage) {
            Some(nanos) => {
                let micros = nanos.div_ceil(NANOS_PER_MICRO);
                micros >= u128::try_from(remaining.max(0)).unwrap_or(0)
            }
            None => true,
        }
    }
}

/// A unit's last counts as its checkpoint carries them: the billing counts by class name, the fee
/// units set aside (a class at zero left off, a sum that will not add up saturated, as the ledger
/// bills it), whether a fee unit was reported above zero, and its ledger key.
fn accrued(m: &UnitMoney, last: &[UnitCount]) -> Accrued {
    let counts = reported(last);
    let mut classes = named(&m.classes, &usage_only(m, &counts), |a, b| {
        Some(a.saturating_add(b))
    })
    .unwrap_or_default();
    classes.retain(|_, n| *n > 0);
    let fee = counts
        .iter()
        .any(|(class, amount)| *amount > 0 && m.fee.is_fee(*class));
    Accrued {
        lane: m.model.clone(),
        fee_count: u64::from(fee),
        classes,
    }
}

/// `counts` without the unit's fee units: a fee unit's count says whether the fee was incurred and
/// is never usage (the fee was charged at admission, #21).
fn usage_only(m: &UnitMoney, counts: &[(u32, u64)]) -> Vec<(u32, u64)> {
    counts
        .iter()
        .copied()
        .filter(|(class, _)| !m.fee.is_fee(*class))
        .collect()
}

/// `counts` under the plane's class names, each class's sum added by `add`; a class index the
/// plane never declared is not billed. With `u64::checked_add`, `None` when a class's counts do not
/// add up in a `u64` (a plane fault; never a wrapped sum); saturating, the figure a fail-closed
/// ledger bills.
fn named(
    classes: &[String],
    counts: &[(u32, u64)],
    add: fn(u64, u64) -> Option<u64>,
) -> Option<BTreeMap<String, u64>> {
    let mut units: BTreeMap<String, u64> = BTreeMap::new();
    for (class, amount) in counts {
        if let Some(name) = classes.get(*class as usize) {
            let n = units.entry(name.clone()).or_insert(0);
            *n = add(*n, *amount)?;
        }
    }
    Some(units)
}

/// The counts that bill ([`units_bill`]: reported or floor, never an estimate), as `(class, amount)`:
/// what a bill ledgers.
pub(super) fn reported(units: &[UnitCount]) -> Vec<(u32, u64)> {
    units
        .iter()
        .filter(|u| units_bill(u.source))
        .map(|u| (u.class, u.amount))
        .collect()
}

impl MoneySeam for PlaneMoney {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let mut all = self.lock();
        let Some(open) = all.get_mut(&ctx.key) else {
            return Checkpoint::Continue;
        };
        let all_counts: Vec<(u32, u64)> = units.iter().map(|u| (u.class, u.amount)).collect();
        if named(&open.money.classes, &all_counts, u64::checked_add).is_none() {
            // A report whose counts do not add up is a plane fault: it is not kept, and the unit
            // is cut (fail closed) rather than run on a figure nothing can bill.
            return Checkpoint::Cut;
        }
        open.last.clear();
        open.last.extend_from_slice(units);
        // THE CHECKPOINT, marked: the root's flush tick journals it, once per epoch. No I/O here.
        open.dirty = true;
        if open.money.mode != ExhaustionMode::CutStream {
            return Checkpoint::Continue;
        }
        let money = open.money.clone();
        drop(all);
        if self.dry(&money, &reported(units)) {
            Checkpoint::Cut
        } else {
            Checkpoint::Continue
        }
    }

    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill) {
        let (money, provider) = {
            let mut all = self.lock();
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            // A session's side bills nothing of its own: the session's one line is written at
            // its end from its last cumulative counts ([`MoneySeam::session_ended`]).
            if open.ledgered || open.session {
                return;
            }
            open.ledgered = true;
            let money = (open.money.clone(), open.provider.clone());
            if open.abandoned {
                // The caller went away and its end is posted: this bill was all it waited for.
                all.remove(&ctx.key);
            }
            money
        };
        self.ledger(&money, &bill.billed);
        // A cancelled stream meters only when it bills a reported count (1.5.5's drop path billed
        // the usage the far end had reported through the same ledger_and_meter; none, no row).
        if bills(&money, &bill.billed) {
            self.meter(&money, provider.as_deref(), &bill.billed);
        }
    }

    /// The caller went away: the loop's sealed end goes to the root's posting site, and the unit's
    /// money facts close. A unit the driver's pump had reported counts for still owes its cancel
    /// bill (the sweep's, by the four 1.5.5 rules): its facts close when that bill is ledgered, or
    /// here when it already was. A unit with no count closes here. Nothing is refunded (1.5.5's
    /// dropped request never reached its refund arm).
    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let owed = {
            let mut all = self.lock();
            match all.get_mut(&ctx.key) {
                Some(open) if !open.ledgered && open.finished => {
                    // The route ended on its own and the caller left during the exit: the last
                    // reported counts are the bill, ledgered here, once.
                    let open = all.remove(&ctx.key);
                    open.map(|o| {
                        let counts = reported(&o.last);
                        (o.money, o.provider, counts)
                    })
                }
                Some(open) if open.ledgered || open.last.is_empty() => {
                    all.remove(&ctx.key);
                    None
                }
                Some(open) => {
                    open.abandoned = true;
                    None
                }
                None => None,
            }
        };
        if let Some((money, provider, counts)) = owed {
            // Safe inside the loop's `Drop` guard: GovState::record_usage is an in-memory accrual
            // (the bucket cells and the metering row are write-behind; the durable write is the
            // flusher's, never a store call on this thread), and it neither awaits nor crosses a
            // plugin. record_metering is the same in-memory, sharded accumulator.
            self.ledger(&money, &counts);
            if bills(&money, &counts) {
                self.meter(&money, provider.as_deref(), &counts);
            }
        }
        self.post.post(ctx, ended);
    }

    fn finished(&self, ctx: &UnitCtx) {
        if let Some(open) = self.lock().get_mut(&ctx.key) {
            open.finished = true;
        }
    }

    /// The session opens under the unit's one admission: its money facts must be open (a unit
    /// the root admitted with no facts runs no session unbilled), and from here its line is the
    /// session end's.
    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        match self.lock().get_mut(&ctx.key) {
            Some(open) if !open.ledgered => {
                open.session = true;
                Ok(())
            }
            _ => Err(ReasonCode::Unpriced),
        }
    }

    /// THE SESSION'S ONE LINE: its last billing cumulative counts (far-end-reported or floor,
    /// never an estimate), ledgered once and metered when they bill, in the window of the unit's
    /// arrival, however the session ended (its own end, a cut, a cancel on either side, its caller
    /// gone). The unit's own end then ledgers nothing twice and still decides the fee refund. A unit
    /// whose caller already went away closes here. Runs inside the session's cleanup `Drop`: the
    /// accrual is in memory and neither awaits nor crosses a plugin.
    fn session_ended(&self, ctx: &UnitCtx) {
        let owed = {
            let mut all = self.lock();
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.ledgered || !open.session {
                return;
            }
            open.ledgered = true;
            let owed = (
                open.money.clone(),
                open.provider.clone(),
                reported(&open.last),
            );
            if open.abandoned {
                all.remove(&ctx.key);
            }
            owed
        };
        let (money, provider, counts) = owed;
        self.ledger(&money, &counts);
        if bills(&money, &counts) {
            self.meter(&money, provider.as_deref(), &counts);
        }
    }

    /// The member that served the unit: from here every ledgering, metering and cut-stream pricing
    /// of the unit is under ITS config model and provider, as 1.5.5 attributed a delivered response
    /// to the serving lane after failover (`proxy/usage.rs` `ledger_and_meter`: "THE ONE PLACE a
    /// delivered response is attributed to a model ... `lane` is the SERVING lane").
    fn served(&self, ctx: &UnitCtx, model: &str, provider: &str) {
        if let Some(open) = self.lock().get_mut(&ctx.key) {
            if !open.laned {
                open.money.model = model.to_string();
            }
            open.provider = Some(provider.to_string());
        }
    }

    /// THE LEDGER LANE THE PLANE NAMED (ARCHITECT SEAM-L(j): the ledger lane is not the route
    /// entry): from here every ledgering, metering and cut-stream pricing of the unit is under it,
    /// qualified by the same plane key the unit was opened under (`"<plane>\u{1f}<lane>"`), so a
    /// plane names lanes of its own card alone. A lane that is empty, or carries a control
    /// character (the qualifier's separator among them), names nothing.
    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        if lane.is_empty() || lane.chars().any(char::is_control) {
            return;
        }
        if let Some(open) = self.lock().get_mut(&ctx.key) {
            let (plane, _) = busbar_kernel_ledger::cost::split_plane_lane(&open.money.model);
            open.money.model = if plane.is_empty() {
                lane.to_string()
            } else {
                format!("{plane}{}{lane}", crate::governance::PLANE_LANE_SEP)
            };
            open.laned = true;
        }
    }
}

/// Whether `counts` bill anything once the fee units are set aside: a reported count above zero.
fn bills(m: &UnitMoney, counts: &[(u32, u64)]) -> bool {
    usage_only(m, counts).iter().any(|(_, n)| *n > 0)
}

#[cfg(test)]
#[path = "tests/money_tests.rs"]
mod tests;
