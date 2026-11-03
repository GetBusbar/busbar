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
use crate::governance::{AdmitGrant, GovState};
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
    /// bill: what the plane ledgered for the unit is final, cut or not.
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

/// Host-held provenance of a live admission. It cannot be constructed from a billing key.
#[derive(Clone)]
pub struct ParentMoney {
    parent: UnitKey,
    identity: Arc<()>,
    money: Arc<UnitMoney>,
    grant: Arc<AdmitGrant>,
    account: Arc<FeeAccount>,
}

struct FeeState {
    children: usize,
    parent_refund: Option<bool>,
    child_incurred: bool,
}

struct FeeAccount {
    gov: Arc<GovState>,
    money: Arc<UnitMoney>,
    state: Mutex<FeeState>,
}

struct FeeParticipation {
    account: Arc<FeeAccount>,
    owner: bool,
    refundable: bool,
}

impl Drop for FeeParticipation {
    fn drop(&mut self) {
        let refund = {
            let mut state = locked(&self.account.state);
            if self.owner {
                state.parent_refund = Some(self.refundable);
            } else {
                state.children -= 1;
                state.child_incurred |= !self.refundable;
            }
            state.children == 0 && state.parent_refund == Some(true) && !state.child_incurred
        };
        if refund {
            let m = &self.account.money;
            self.account.gov.refund_charge(&m.charge);
            if let FeeRefund::PlaneFeeUnits(fees) = &m.fee {
                for unit in fees
                    .iter()
                    .filter_map(|c| m.classes.get(*c as usize))
                    .filter(|u| u.as_str() != busbar_contract::plane::PER_REQUEST)
                {
                    self.account.gov.refund_fee_unit_in_era(
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

struct Open {
    identity: Arc<()>,
    grant: Option<Arc<AdmitGrant>>,
    fee: FeeParticipation,
    money: Arc<UnitMoney>,
    last: Vec<UnitCount>,
    ledgered: bool,
    abandoned: bool,

    finished: bool,

    session: bool,

    provider: Option<String>,

    laned: bool,
}

impl Open {
    fn new(money: Arc<UnitMoney>, grant: Option<Arc<AdmitGrant>>, fee: FeeParticipation) -> Self {
        Self {
            identity: Arc::new(()),
            grant,
            fee,
            money,
            last: Vec::new(),
            ledgered: false,
            abandoned: false,
            finished: false,
            session: false,
            provider: None,
            laned: false,
        }
    }
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
        self.open_with_grant(key, money, None);
    }

    /// Register the actual governor admission, retaining its concurrency custody.
    pub fn open_admitted(&self, key: UnitKey, mut money: UnitMoney, grant: Arc<AdmitGrant>) {
        money.charge = grant.charge().clone();
        self.open_with_grant(key, money, Some(grant));
    }

    fn open_with_grant(&self, key: UnitKey, money: UnitMoney, grant: Option<Arc<AdmitGrant>>) {
        let money = Arc::new(money);
        let account = Arc::new(FeeAccount {
            gov: self.gov.clone(),
            money: money.clone(),
            state: Mutex::new(FeeState {
                children: 0,
                parent_refund: None,
                child_incurred: false,
            }),
        });
        let open = Open::new(
            money,
            grant,
            FeeParticipation {
                account,
                owner: true,
                refundable: false,
            },
        );
        let replaced = {
            let mut all = self.shard(key);
            all.insert(key, open)
        };
        drop(replaced);
    }

    /// Capture a live, governor-backed parent for an already authenticated matching key.
    /// The composition root also verifies its session's principal and route authority.
    pub fn parent_money(
        &self,
        parent: UnitKey,
        expected_key: &VirtualKey,
    ) -> Result<ParentMoney, ReasonCode> {
        let all = self.shard(parent);
        let open = all.get(&parent).ok_or(ReasonCode::Unpriced)?;
        if open.finished
            || open.ledgered
            || open.abandoned
            || !open.fee.owner
            || open.money.key.as_ref() != expected_key
        {
            return Err(ReasonCode::Unpriced);
        }
        let grant = open.grant.as_ref().ok_or(ReasonCode::Unpriced)?;
        Ok(ParentMoney {
            parent,
            identity: open.identity.clone(),
            money: open.money.clone(),
            grant: grant.clone(),
            account: open.fee.account.clone(),
        })
    }

    /// Revalidate the captured parent's actual live admission and complete billing identity.
    pub fn validate_parent(
        &self,
        parent: &ParentMoney,
        expected_key: &VirtualKey,
    ) -> Result<(), ReasonCode> {
        let all = self.shard(parent.parent);
        let open = all.get(&parent.parent).ok_or(ReasonCode::Unpriced)?;
        if open.finished
            || open.ledgered
            || open.abandoned
            || !open.fee.owner
            || open.money.key.as_ref() != expected_key
            || !Arc::ptr_eq(&open.identity, &parent.identity)
            || !Arc::ptr_eq(&open.fee.account, &parent.account)
            || !open
                .grant
                .as_ref()
                .is_some_and(|g| Arc::ptr_eq(g, &parent.grant))
        {
            return Err(ReasonCode::Unpriced);
        }
        Ok(())
    }

    /// A registered child keeps its real admission after the parent closes. The driver marks
    /// it finished before the teller's terminal authority check, so finished is permitted here.
    /// The actual unsettled registration must still exist; a token alone cannot satisfy this.
    pub fn validate_child(
        &self,
        parent: &ParentMoney,
        child: UnitKey,
        expected_key: &VirtualKey,
    ) -> Result<(), ReasonCode> {
        let all = self.shard(child);
        let open = all.get(&child).ok_or(ReasonCode::Unpriced)?;
        if open.ledgered
            || open.abandoned
            || open.fee.owner
            || open.money.key.as_ref() != expected_key
            || !Arc::ptr_eq(&open.fee.account, &parent.account)
            || !open
                .grant
                .as_ref()
                .is_some_and(|g| Arc::ptr_eq(g, &parent.grant))
        {
            return Err(ReasonCode::Unpriced);
        }
        Ok(())
    }

    /// Register ordinary child usage under the actual parent's admission and rate era.
    /// Parent and child registration are checked under ordered shard locks.
    pub fn open_child(
        &self,
        parent: &ParentMoney,
        child: UnitKey,
        lane: String,
        classes: Arc<[String]>,
        fee: FeeRefund,
    ) -> Result<(), ReasonCode> {
        if parent.parent == child {
            return Err(ReasonCode::Unpriced);
        }
        let make_child = |open: &Open| -> Result<Open, ReasonCode> {
            if !Arc::ptr_eq(&open.identity, &parent.identity)
                || open.finished
                || open.ledgered
                || open.abandoned
                || !open.fee.owner
                || !open
                    .grant
                    .as_ref()
                    .is_some_and(|g| Arc::ptr_eq(g, &parent.grant))
            {
                return Err(ReasonCode::Unpriced);
            }
            let mut money = parent.money.as_ref().clone();
            money.lane = lane;
            money.classes = classes;
            money.fee = fee;
            let account = open.fee.account.clone();
            locked(&account.state).children += 1;
            Ok(Open::new(
                Arc::new(money),
                Some(parent.grant.clone()),
                FeeParticipation {
                    account,
                    owner: false,
                    refundable: false,
                },
            ))
        };
        let parent_shard = (parent.parent.get() % SHARDS as u64) as usize;
        let child_shard = (child.get() % SHARDS as u64) as usize;
        if parent_shard == child_shard {
            let mut all = self.shard(child);
            if all.contains_key(&child) {
                return Err(ReasonCode::Unpriced);
            }
            let open = make_child(all.get(&parent.parent).ok_or(ReasonCode::Unpriced)?)?;
            all.insert(child, open);
        } else {
            let (mut first, mut second) = if parent_shard < child_shard {
                (self.shard(parent.parent), self.shard(child))
            } else {
                (self.shard(child), self.shard(parent.parent))
            };
            let (parents, children) = if parent_shard < child_shard {
                (&mut first, &mut second)
            } else {
                (&mut second, &mut first)
            };
            if children.contains_key(&child) {
                return Err(ReasonCode::Unpriced);
            }
            let open = make_child(parents.get(&parent.parent).ok_or(ReasonCode::Unpriced)?)?;
            children.insert(child, open);
        }
        Ok(())
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
        let removed = {
            let mut all = self.shard(key);
            all.remove(&key)
        };
        let Some(mut open) = removed else {
            return;
        };
        let m = &open.money;
        if !open.ledgered {
            let delivered = (200..=299).contains(&caller_status);
            self.bill(m, open.provider.as_deref(), &reported(&open.last), |_| {
                delivered
            });
        }
        open.fee.refundable = m.fee.refunds(caller_status, &open.last);
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
        let (money, provider, removed) = {
            let mut all = self.shard(ctx.key);
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.ledgered || open.session {
                return;
            }
            open.ledgered = true;
            let money = open.money.clone();
            let provider = open.provider.clone();
            let removed = if open.abandoned {
                all.remove(&ctx.key)
            } else {
                None
            };
            (money, provider, removed)
        };
        self.bill(&money, provider.as_deref(), &bill.billed, bills);
        drop(removed);
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let removed = {
            let mut all = self.shard(ctx.key);
            match all.get_mut(&ctx.key) {
                Some(open) if !open.ledgered && open.finished => {
                    all.remove(&ctx.key).map(|open| (open, true))
                }
                Some(open) if open.ledgered || open.last.is_empty() => {
                    all.remove(&ctx.key).map(|open| (open, false))
                }
                Some(open) => {
                    open.abandoned = true;
                    None
                }
                None => None,
            }
        };
        if let Some((open, owed)) = removed {
            if owed {
                self.bill(
                    &open.money,
                    open.provider.as_deref(),
                    &reported(&open.last),
                    bills,
                );
            }
            // Fee participation and the actual grant always close outside the shard lock.
            drop(open);
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
        let (money, provider, counts, removed) = {
            let mut all = self.shard(ctx.key);
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.ledgered || !open.session {
                return;
            }
            open.ledgered = true;
            let money = open.money.clone();
            let provider = open.provider.clone();
            let counts = reported(&open.last);
            let removed = if open.abandoned {
                all.remove(&ctx.key)
            } else {
                None
            };
            (money, provider, counts, removed)
        };
        self.bill(&money, provider.as_deref(), &counts, bills);
        drop(removed);
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

fn locked<T>(shard: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
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
