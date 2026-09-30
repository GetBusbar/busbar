// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION MONEY SEAM (`BUSBAR-1.6.0.md` THE DESIGN, §7; Part 3, §12 "The route pump" and
//! "Cancel"): the kernel's budget and ledger decisions behind the driver's [`MoneySeam`]. The plane
//! reports; the kernel writes. Nothing here prices a stored figure or posts a sealed line of its own:
//!
//! * the unit's spend is its far-end-REPORTED counts (never an estimate), ledgered once, at the end,
//!   through the governance book's one accrual (`GovState::record_usage`), which files it in the
//!   window of the unit's ARRIVAL epoch (THE DESIGN, section 7: "same balance, same window, same row");
//! * a far end that did not deliver refunds the unit's flat request fee (`GovState::refund_request`,
//!   1.5.5's non-2xx refund), a separate act from the ledgering;
//! * a cancelled unit's bill (the four 1.5.5 cancel rules, computed by the driver) is ledgered the
//!   same way, and the unit's later end ledgers nothing twice;
//! * `on_exhaustion: finish-unit` (the default, 1.5.5) never cuts. `cut-stream` (new in 1.6.0) cuts
//!   a running unit once its reported counts, priced by the one money function at the card in
//!   force, reach what its tightest applicable budget has left; a count the card cannot price cuts
//!   (fail closed);
//! * an abandoned unit's sealed end goes to the composition root's one posting site
//!   ([`EndPost`]); this file seals nothing.
//!
//! The kernel names no plane here: a unit's class names, model, pool and key are handed in by the
//! composition root when it opens the unit ([`PlaneMoney::open`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{UnitCount, UNITS_REPORTED};
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
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
}

impl std::fmt::Debug for UnitMoney {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitMoney")
            .field("key", &self.key.id)
            .field("pool", &self.pool)
            .field("model", &self.model)
            .field("arrived", &self.arrived)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
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
}

/// THE KERNEL'S MONEY STEPS for one plane instance's units.
pub struct PlaneMoney {
    gov: Arc<GovState>,
    post: Arc<dyn EndPost>,
    units: Mutex<HashMap<UnitKey, Open>>,
}

impl std::fmt::Debug for PlaneMoney {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneMoney").finish_non_exhaustive()
    }
}

impl PlaneMoney {
    /// The money steps over the governance book `gov`, posting abandoned ends through `post`.
    #[must_use]
    pub fn new(gov: Arc<GovState>, post: Arc<dyn EndPost>) -> Self {
        PlaneMoney {
            gov,
            post,
            units: Mutex::new(HashMap::new()),
        }
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
            },
        );
    }

    /// THE UNIT'S END, returned to its caller with `caller_status`: ledger its last far-end-
    /// reported counts (unless its cancel bill already did), and refund its flat request fee when
    /// that status is not a success, exactly 1.5.5's rule (`busbar-kernel/src/ingress/mod.rs`, the
    /// finish's `refund_on_non_2xx && !is_success` arm: "REFUND it for a request that produced no
    /// usable upstream result"). A unit whose caller went away before any answer returns through
    /// [`MoneySeam::abandoned`], never here, and is refunded nothing, as 1.5.5's dropped request
    /// never reached that arm. The unit's facts are closed either way.
    pub fn settle_end(&self, key: UnitKey, caller_status: u32) {
        let Some(open) = self.lock().remove(&key) else {
            return;
        };
        let m = &open.money;
        if !open.ledgered {
            let counts: Vec<(u32, u64)> = open
                .last
                .iter()
                .filter(|u| u.source == UNITS_REPORTED)
                .map(|u| (u.class, u.amount))
                .collect();
            self.ledger(m, &counts);
        }
        if !(200..=299).contains(&caller_status) {
            self.gov.refund_request(&m.cost, &m.key, &m.pool, m.arrived);
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

    /// How many units' money facts are open (a witness: every end closes its unit).
    #[must_use]
    pub fn open_units(&self) -> usize {
        self.lock().len()
    }

    /// Ledger `counts` (class index, amount) under the unit's model, pool and arrival window. A sum
    /// that would overflow bills the saturated figure, never a wrapped or zero one (fail closed);
    /// the plane check refuses a class counted twice, so a validated report never gets here.
    fn ledger(&self, m: &UnitMoney, counts: &[(u32, u64)]) {
        let units = named(&m.classes, counts).unwrap_or_else(|| saturated(&m.classes, counts));
        self.gov
            .record_usage(&m.cost, &m.key, &m.pool, &m.model, &units, m.arrived);
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
        let Some(usage_units) = named(&m.classes, counts) else {
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

/// `counts` under the plane's class names; a class index the plane never declared is not billed.
/// `None` when a class's counts do not add up in a `u64` (a plane fault; never a wrapped sum).
fn named(classes: &[String], counts: &[(u32, u64)]) -> Option<BTreeMap<String, u64>> {
    let mut units: BTreeMap<String, u64> = BTreeMap::new();
    for (class, amount) in counts {
        if let Some(name) = classes.get(*class as usize) {
            let n = units.entry(name.clone()).or_insert(0);
            *n = n.checked_add(*amount)?;
        }
    }
    Some(units)
}

/// [`named`], each class's sum saturated at `u64::MAX`: the figure a fail-closed ledger bills.
fn saturated(classes: &[String], counts: &[(u32, u64)]) -> BTreeMap<String, u64> {
    let mut units: BTreeMap<String, u64> = BTreeMap::new();
    for (class, amount) in counts {
        if let Some(name) = classes.get(*class as usize) {
            let n = units.entry(name.clone()).or_insert(0);
            *n = n.saturating_add(*amount);
        }
    }
    units
}

impl MoneySeam for PlaneMoney {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let mut all = self.lock();
        let Some(open) = all.get_mut(&ctx.key) else {
            return Checkpoint::Continue;
        };
        let all_counts: Vec<(u32, u64)> = units.iter().map(|u| (u.class, u.amount)).collect();
        if named(&open.money.classes, &all_counts).is_none() {
            // A report whose counts do not add up is a plane fault: it is not kept, and the unit
            // is cut (fail closed) rather than run on a figure nothing can bill.
            return Checkpoint::Cut;
        }
        open.last.clear();
        open.last.extend_from_slice(units);
        if open.money.mode != ExhaustionMode::CutStream {
            return Checkpoint::Continue;
        }
        let money = open.money.clone();
        drop(all);
        let reported: Vec<(u32, u64)> = units
            .iter()
            .filter(|u| u.source == UNITS_REPORTED)
            .map(|u| (u.class, u.amount))
            .collect();
        if self.dry(&money, &reported) {
            Checkpoint::Cut
        } else {
            Checkpoint::Continue
        }
    }

    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill) {
        let money = {
            let mut all = self.lock();
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.ledgered {
                return;
            }
            open.ledgered = true;
            let money = open.money.clone();
            if open.abandoned {
                // The caller went away and its end is posted: this bill was all it waited for.
                all.remove(&ctx.key);
            }
            money
        };
        self.ledger(&money, &bill.billed);
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
                        let counts: Vec<(u32, u64)> = o
                            .last
                            .iter()
                            .filter(|u| u.source == UNITS_REPORTED)
                            .map(|u| (u.class, u.amount))
                            .collect();
                        (o.money, counts)
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
        if let Some((money, counts)) = owed {
            self.ledger(&money, &counts);
        }
        self.post.post(ctx, ended);
    }

    fn finished(&self, ctx: &UnitCtx) {
        if let Some(open) = self.lock().get_mut(&ctx.key) {
            open.finished = true;
        }
    }
}

#[cfg(test)]
#[path = "tests/money_tests.rs"]
mod tests;
