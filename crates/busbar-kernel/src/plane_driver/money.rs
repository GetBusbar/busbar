// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::plane::{units_bill, UnitCount};
use busbar_contract::caps::ReasonCode;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
use crate::config::groups::ExhaustionMode;
use crate::cost::CostModel;
use crate::governance::GovState;
use crate::teller::{Ended, UnitCtx};

const NANOS_PER_MICRO: u128 = 1_000;

pub trait EndPost: Send + Sync {
    fn post(&self, ctx: &UnitCtx, ended: Ended);
}

/// HOW A UNIT'S ANSWER ENDED, as the composition root hands it to [`PlaneMoney::settle_end_as`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitEnd {
    /// The status the unit's caller was answered with (its head's, once a head went out).
    pub caller_status: u32,
    /// The far end CUT the unit's streamed answer after its head: its connection failed, or its
    /// send's deadline passed, before it completed (the driver's `cut` fact,
    /// `DriverSteps::answered`, on a unit whose caller asked for a stream). It never changes the
    /// bill: what the plane ledgered for the unit is final, cut or not (owner ruling 2026-10-20:
    /// "spend is what it is. if spend occurred it occurred").
    pub cut: bool,
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
    /// The lane the unit's counts are priced, ledgered and metered under: the serving member's
    /// name, or the ledger lane the plane named ([`MoneySeam::laned`]). An opaque key to the
    /// kernel; the card and the metering row are keyed by it.
    pub lane: String,
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
/// did "and whether a fee unit was incurred"; the one fee decider is the plane's report. A plane
/// that kept 1.5.5's caller-status rule keeps it byte-identical until it runs on the driver, where
/// it moves to its fee-unit report, so the end state has one decider.
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
    fn is_fee(&self, class: u32) -> bool {
        match self {
            FeeRefund::CallerStatus => false,
            FeeRefund::PlaneFeeUnits(fees) => fees.contains(&class),
        }
    }

    fn refunds(&self, caller_status: u32, last: &[UnitCount]) -> bool {
        match self {
            FeeRefund::CallerStatus => !(200..=299).contains(&caller_status),
            FeeRefund::PlaneFeeUnits(fees) => !last
                .iter()
                .any(|u| units_bill(u.source) && u.amount > 0 && fees.contains(&u.class)),
        }
    }
}

struct Open {
    money: Arc<UnitMoney>,
    last: Vec<UnitCount>,
    ledgered: bool,
    abandoned: bool,

    finished: bool,

    session: bool,

    provider: Option<String>,

    laned: bool,
}

const SHARDS: usize = 16;

type Shard = HashMap<UnitKey, Open>;

pub struct PlaneMoney {
    gov: Arc<GovState>,
    post: Arc<dyn EndPost>,

    units: [Mutex<Shard>; SHARDS],
}

impl PlaneMoney {
    #[must_use]
    pub fn new(gov: Arc<GovState>, post: Arc<dyn EndPost>) -> Self {
        PlaneMoney {
            gov,
            post,
            units: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn caller_refs(&self) -> Option<super::CallerRefs> {
        Some(self.gov.caller_ref_slot())
    }

    fn shard(&self, key: UnitKey) -> std::sync::MutexGuard<'_, Shard> {
        locked(&self.units[(key.get() % SHARDS as u64) as usize])
    }

    pub fn open(&self, key: UnitKey, money: UnitMoney) {
        self.shard(key).insert(
            key,
            Open {
                money: Arc::new(money),
                last: Vec::new(),
                ledgered: false,
                abandoned: false,
                finished: false,
                session: false,
                provider: None,
                laned: false,
            },
        );
    }

    pub fn settle_end(&self, key: UnitKey, caller_status: u32) {
        self.settle_end_as(
            key,
            UnitEnd {
                caller_status,
                cut: false,
            },
        );
    }

    pub fn settle_end_as(&self, key: UnitKey, end: UnitEnd) {
        let UnitEnd { caller_status, .. } = end;
        let Some(open) = self.shard(key).remove(&key) else {
            return;
        };
        let m = &open.money;
        if !open.ledgered {
            let delivered = (200..=299).contains(&caller_status);
            self.bill(m, open.provider.as_deref(), &reported(&open.last), |_| {
                delivered
            });
        }
        if m.fee.refunds(caller_status, &open.last) {
            match &m.fee {
                FeeRefund::CallerStatus => self.gov.refund_charge(&m.charge),

                FeeRefund::PlaneFeeUnits(fees) => {
                    self.gov.refund_charge(&m.charge);
                    for unit in fees
                        .iter()
                        .filter_map(|c| m.classes.get(*c as usize))
                        .filter(|u| u.as_str() != busbar_contract::plane::PER_REQUEST)
                    {
                        self.gov.refund_fee_unit_in_era(
                            &m.cost,
                            &m.key,
                            &m.pool,
                            m.arrived,
                            unit,
                            Some(m.charge.raw_era()),
                        );
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn last_counts(&self, key: UnitKey) -> Vec<UnitCount> {
        self.shard(key)
            .get(&key)
            .map(|o| o.last.clone())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn serving(&self, key: UnitKey) -> Option<String> {
        self.shard(key).get(&key).map(|o| o.money.lane.clone())
    }

    #[must_use]
    pub fn open_units(&self) -> usize {
        self.units.iter().map(|shard| locked(shard).len()).sum()
    }

    fn bill(
        &self,
        m: &UnitMoney,
        provider: Option<&str>,
        counts: &[(u32, u64)],
        metered: impl FnOnce(&[(u32, u64)]) -> bool,
    ) {
        let counts = &usage_only(m, counts);
        let checked = named(&m.classes, counts, u64::checked_add);
        let saturated;
        let units = match &checked {
            Some(units) => units,
            None => {
                saturated =
                    named(&m.classes, counts, |a, b| Some(a.saturating_add(b))).unwrap_or_default();
                &saturated
            }
        };
        self.gov.record_usage_served_in_era(
            &m.cost,
            &m.key,
            &m.pool,
            &m.lane,
            provider,
            units,
            m.arrived,
            m.charge.raw_era(),
        );
        if metered(counts) {
            let units = checked.unwrap_or_default();
            self.gov.record_lane_metering_in_era(
                &m.key,
                &m.lane,
                provider,
                &units,
                m.arrived,
                m.charge.raw_era(),
            );
        }
    }

    fn dry(&self, m: &UnitMoney, counts: &[(u32, u64)]) -> bool {
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&m.pool);
        let remaining = self
            .gov
            .budget_state(&m.cost, &m.key, m.arrived)
            .into_iter()
            .filter(|b| b.pool.as_deref().is_none_or(|p| p == pool))
            .filter_map(|b| b.remaining_micros)
            .min();
        let Some(remaining) = remaining else {
            return false;
        };
        let Some(usage_units) = named(&m.classes, &usage_only(m, counts), u64::checked_add) else {
            return true;
        };
        let usage = busbar_contract::billing::Usage { usage_units };
        match m.cost.price_usage_nanos(&m.lane, &usage) {
            Some(nanos) => {
                let micros = nanos.div_ceil(NANOS_PER_MICRO);
                micros >= u128::try_from(remaining.max(0)).unwrap_or(0)
            }
            None => true,
        }
    }
}

fn adds_up(classes: &[String], units: &[UnitCount]) -> bool {
    let name = |u: &UnitCount| classes.get(u.class as usize);
    units.iter().enumerate().all(|(at, u)| {
        let Some(this) = name(u) else {
            return true;
        };
        if units[..at].iter().any(|v| name(v) == Some(this)) {
            return true;
        }
        units[at..]
            .iter()
            .filter(|&v| name(v) == Some(this))
            .try_fold(0u64, |sum, v| sum.checked_add(v.amount))
            .is_some()
    })
}

fn usage_only(m: &UnitMoney, counts: &[(u32, u64)]) -> Vec<(u32, u64)> {
    counts
        .iter()
        .copied()
        .filter(|(class, _)| !m.fee.is_fee(*class))
        .collect()
}

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

pub(super) fn reported(units: &[UnitCount]) -> Vec<(u32, u64)> {
    units
        .iter()
        .filter(|u| units_bill(u.source))
        .map(|u| (u.class, u.amount))
        .collect()
}

impl MoneySeam for PlaneMoney {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let mut all = self.shard(ctx.key);
        let Some(open) = all.get_mut(&ctx.key) else {
            return Checkpoint::Continue;
        };
        if !adds_up(&open.money.classes, units) {
            return Checkpoint::Cut;
        }
        open.last.clear();
        open.last.extend_from_slice(units);
        if open.money.mode != ExhaustionMode::CutStream {
            return Checkpoint::Continue;
        }
        let money = Arc::clone(&open.money);
        drop(all);
        if self.dry(&money, &reported(units)) {
            Checkpoint::Cut
        } else {
            Checkpoint::Continue
        }
    }

    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill) {
        let (money, provider) = {
            let mut all = self.shard(ctx.key);
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };

            if open.ledgered || open.session {
                return;
            }
            open.ledgered = true;
            let money = (open.money.clone(), open.provider.clone());
            if open.abandoned {
                all.remove(&ctx.key);
            }
            money
        };

        self.bill(&money, provider.as_deref(), &bill.billed, bills);
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let owed = {
            let mut all = self.shard(ctx.key);
            match all.get_mut(&ctx.key) {
                Some(open) if !open.ledgered && open.finished => {
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
            self.bill(&money, provider.as_deref(), &counts, bills);
        }
        self.post.post(ctx, ended);
    }

    fn finished(&self, ctx: &UnitCtx) {
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            open.finished = true;
        }
    }

    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        match self.shard(ctx.key).get_mut(&ctx.key) {
            Some(open) if !open.ledgered => {
                open.session = true;
                Ok(())
            }
            _ => Err(ReasonCode::Unpriced),
        }
    }

    fn session_ended(&self, ctx: &UnitCtx) {
        let owed = {
            let mut all = self.shard(ctx.key);
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
        self.bill(&money, provider.as_deref(), &counts, bills);
    }

    fn served(&self, ctx: &UnitCtx, member: &str, provider: &str) {
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            if !open.laned {
                Arc::make_mut(&mut open.money).lane = member.to_string();
            }
            open.provider = Some(provider.to_string());
        }
    }

    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        if lane.is_empty() || lane.chars().any(char::is_control) {
            return;
        }
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            let (plane, _) = busbar_kernel_ledger::cost::split_plane_lane(&open.money.lane);
            let qualified = if plane.is_empty() {
                lane.to_string()
            } else {
                format!("{plane}{}{lane}", crate::governance::PLANE_LANE_SEP)
            };
            Arc::make_mut(&mut open.money).lane = qualified;
            open.laned = true;
        }
    }
}

fn locked(shard: &Mutex<Shard>) -> std::sync::MutexGuard<'_, Shard> {
    shard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bills(usage: &[(u32, u64)]) -> bool {
    usage.iter().any(|(_, n)| *n > 0)
}

#[cfg(test)]
#[path = "tests/money_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/qualified_pool_tests.rs"]
mod qualified_pool_tests;
