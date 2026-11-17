// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::host_services::VerifiedTicketIdentity;
use crate::persistence::facade::CoreStore;
use busbar_contract::abi::plane::{units_bill, UnitCount};
use busbar_contract::caps::{Admittance, CallId, Grant, PrincipalId, ReasonCode};
use busbar_contract::records::VirtualKey;
use busbar_contract::{Count, UnitKey};

use super::cancel::{CancelBill, Checkpoint, MoneySeam};
use crate::config::groups::ExhaustionMode;
use crate::cost::CostModel;
use crate::governance::{AdmitGrant, GovState};
use crate::teller::{Ended, UnitCtx};

mod native_admission;
pub(super) mod native_attempt;
pub use native_admission::{AdmissionRollback, NativeAdmissionError};
mod native_fee;
mod native_terminal;
pub use native_terminal::SelectedTerminalReceipt;
mod selected_view;
pub use selected_view::UsageView;
mod observations;
pub(crate) use observations::budget_id as observation_budget_id;
pub use observations::{ObservationPolicy, ObservationRuntimeError};

const NANOS_PER_MICRO: u128 = 1_000;

pub trait EndPost: Send + Sync {
    fn post(&self, ctx: &UnitCtx, ended: Ended);
    fn checkpoint_facts(&self, _key: UnitKey) -> Option<Vec<u8>> {
        None
    }
    fn checkpoint_decoded(&self, _key: UnitKey, _class: busbar_contract::caps::OpClassId) {}
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
    /// THE UNIT WAS REFUSED WITH NOTHING SPENT (R10 grant ruling): the plane's first answer to it
    /// was a refusal it audited (an `AUDIT_REJECTED` `RECORD_AUDIT` row written with the answer that
    /// carried the caller's head), and nothing was dialled for it before that answer
    /// ([`super::PlaneUnits::refused_unspent`]). With no units reported, its end releases the
    /// request count admission took ([`crate::governance::GovState::release_request`]).
    pub refused_unspent: bool,
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
    /// The unit's in-flight exhaustion mode: the root always supplies `FinishUnit` (no config key selects `CutStream`).
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

impl ParentMoney {
    /// The frozen monetary generation a child inherits, independently of its destination route.
    pub fn cost(&self) -> &Arc<CostModel> {
        &self.money.cost
    }

    pub(in crate::plane_driver) fn matches_child_money(
        &self,
        money: &UnitMoney,
        grant: &Arc<AdmitGrant>,
    ) -> bool {
        Arc::ptr_eq(&self.money.key, &money.key)
            && Arc::ptr_eq(&self.money.cost, &money.cost)
            && Arc::ptr_eq(&self.grant, grant)
            && self.money.pool == money.pool
            && self.money.arrived == money.arrived
            && self.money.charge == money.charge
            && self.money.mode == money.mode
    }
}

/// One actual admission reserved for a later child. Its financial participation is linear:
pub struct ReservationMoney {
    money: Arc<UnitMoney>,
    grant: Arc<AdmitGrant>,
    fee: FeeParticipation,
    book: Arc<()>,
}

/// Linear host reservation bound to a verified ticket and actual source provenance.
pub struct TicketReservation {
    money: ReservationMoney,
    id: String,
    expires_at: u64,
    key: Arc<VirtualKey>,
    store: Arc<CoreStore>,
    source_call: CallId,
    source_unit: UnitKey,
    node_nonce: Arc<()>,
    instance_nonce: Arc<()>,
}

/// Durable redemption has succeeded. Only kernel authentication can mint this wrapper.
pub struct SpentTicketReservation(TicketReservation);

pub struct ReturnedTicketReservation {
    reason: ReasonCode,
    reservation: Box<TicketReservation>,
}

impl ReturnedTicketReservation {
    pub fn into_parts(self) -> (ReasonCode, TicketReservation) {
        (self.reason, *self.reservation)
    }
}

/// Proof of an already committed reserved admission, usable by one terminal posting.
pub struct ReservedRequestLineage {
    call: CallId,
    unit: UnitKey,
    principal: PrincipalId,
}

impl ReservedRequestLineage {
    pub fn consume(self, ctx: &UnitCtx, principal: &PrincipalId) -> Result<(), ReasonCode> {
        if self.call == ctx.call && self.unit == ctx.key && &self.principal == principal {
            Ok(())
        } else {
            Err(ReasonCode::Unpriced)
        }
    }
}

impl TicketReservation {
    pub fn matches(&self, identity: &VerifiedTicketIdentity) -> bool {
        self.id == identity.id()
            && self.expires_at == identity.expires_at()
            && self.key.as_ref() == identity.principal().as_ref()
            && Arc::ptr_eq(&self.store, identity.store())
    }
}

impl SpentTicketReservation {
    pub(crate) fn after_redemption(
        reservation: TicketReservation,
        principal: &VirtualKey,
    ) -> Result<Self, ReturnedTicketReservation> {
        if reservation.key.as_ref() != principal {
            return Err(ReturnedTicketReservation {
                reason: ReasonCode::Unpriced,
                reservation: Box::new(reservation),
            });
        }
        Ok(Self(reservation))
    }

    pub fn adopt(
        self,
        money: &PlaneMoney,
        ctx: &UnitCtx,
        admit: &Grant<Admittance>,
        principal: &PrincipalId,
        expected_key: &VirtualKey,
        lane: String,
        classes: Arc<[String]>,
        fee: FeeRefund,
        node_nonce: &Arc<()>,
        instance_nonce: &Arc<()>,
        store: &Arc<CoreStore>,
    ) -> Result<ReservedRequestLineage, ReturnedTicketReservation> {
        let reservation = self.0;
        if !admit.bound_to(ctx.call)
            || reservation.source_call == CallId::UNBOUND
            || reservation.source_unit == ctx.key
            || reservation.source_call == ctx.call
            || principal != &PrincipalId::new(expected_key.id.clone())
            || reservation.key.as_ref() != expected_key
            || !Arc::ptr_eq(&reservation.node_nonce, node_nonce)
            || !Arc::ptr_eq(&reservation.instance_nonce, instance_nonce)
            || !Arc::ptr_eq(&reservation.store, store)
            || !Arc::ptr_eq(&reservation.money.book, &money.book)
        {
            return Err(ReturnedTicketReservation {
                reason: ReasonCode::Unpriced,
                reservation: Box::new(reservation),
            });
        }
        let TicketReservation {
            money: reserved,
            id,
            expires_at,
            key,
            store,
            source_call,
            source_unit,
            node_nonce,
            instance_nonce,
        } = reservation;
        match money.adopt_reserved(reserved, ctx.key, lane, classes, fee, expected_key) {
            Ok(()) => Ok(ReservedRequestLineage {
                call: ctx.call,
                unit: ctx.key,
                principal: principal.clone(),
            }),
            Err(returned) => {
                let (reason, reserved) = returned.into_parts();
                Err(ReturnedTicketReservation {
                    reason,
                    reservation: Box::new(TicketReservation {
                        money: reserved,
                        id,
                        expires_at,
                        key,
                        store,
                        source_call,
                        source_unit,
                        node_nonce,
                        instance_nonce,
                    }),
                })
            }
        }
    }
}

/// An unsuccessful adoption returns the unchanged financial reservation for retry or cleanup.
pub struct ReturnedReservation {
    reason: ReasonCode,
    reservation: ReservationMoney,
}

impl ReturnedReservation {
    pub fn into_parts(self) -> (ReasonCode, ReservationMoney) {
        (self.reason, self.reservation)
    }
}

struct FeeState {
    children: usize,
    parent_refund: Option<bool>,
    child_incurred: bool,
    completed: Option<crate::governance::unit_checkpoint::partitions::FeeResult>,
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
        use crate::governance::unit_checkpoint::partitions::FeeResult;
        let result = {
            let mut state = locked(&self.account.state);
            if self.owner {
                state.parent_refund = Some(self.refundable);
            } else {
                state.children -= 1;
                state.child_incurred |= !self.refundable;
            }
            (state.children == 0 && state.parent_refund.is_some()).then(|| {
                if state.parent_refund == Some(true) && !state.child_incurred {
                    FeeResult::Refunded
                } else {
                    FeeResult::Charged
                }
            })
        };
        if result == Some(FeeResult::Refunded) {
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
        // Counts alone are not completion: publish only after the existing refund mutations.
        if let Some(result) = result {
            locked(&self.account.state).completed = Some(result);
        }
    }
}

struct Open {
    native: Option<native_attempt::NativeMoney>,
    spend_ceiling_micros: Option<u64>,
    observation: Option<Arc<crate::persistence::observations::BoundScope>>,
    observation_started: bool,
    observation_pending: Option<observations::PendingObservation>,
    observation_classes: std::collections::BTreeSet<u32>,
    checkpoint_id: [u8; 16],
    checkpoint_audit: Option<Vec<u8>>,
    identity: Arc<()>,
    grant: Option<Arc<AdmitGrant>>,
    fee: FeeParticipation,
    money: Arc<UnitMoney>,
    last: Vec<UnitCount>,
    /// Bumped whenever a checkpoint replaces [`Self::last`].
    rev: u32,
    /// The fold of [`Self::last`] at the revision it was taken (SP-M1).
    fold: Option<(u32, Arc<UsageFold>)>,
    /// The last changed piece's running checkpoint could not be built (SP-M2): an equal piece
    /// is judged again rather than passed as unchanged.
    snapshot_refused: bool,
    ledgered: bool,
    abandoned: bool,

    finished: bool,

    session: bool,

    provider: Option<String>,

    laned: bool,
}

impl Open {
    fn new(
        money: Arc<UnitMoney>,
        grant: Option<Arc<AdmitGrant>>,
        fee: FeeParticipation,
        checkpoint_audit: Option<Vec<u8>>,
    ) -> Self {
        Self {
            native: None,
            spend_ceiling_micros: None,
            observation: None,
            observation_started: false,
            observation_pending: None,
            observation_classes: Default::default(),
            checkpoint_id: crate::door::op_id().0,
            checkpoint_audit,
            identity: Arc::new(()),
            grant,
            fee,
            money,
            last: Vec::new(),
            rev: 0,
            fold: None,
            snapshot_refused: false,
            ledgered: false,
            abandoned: false,
            finished: false,
            session: false,
            provider: None,
            laned: false,
        }
    }

    /// The unit's usage folded at its current revision: the cached fold while no checkpoint has
    /// replaced the counts since, else a fresh fold that replaces the cache.
    fn usage_fold(&mut self) -> Arc<UsageFold> {
        if let Some((rev, fold)) = &self.fold {
            if *rev == self.rev {
                return Arc::clone(fold);
            }
        }
        let fold = Arc::new(UsageFold::of(&self.last));
        self.fold = Some((self.rev, Arc::clone(&fold)));
        fold
    }
}

/// ONE UNIT'S LAST REPORTED USAGE, FOLDED ONCE (SP-M1). The meter gate folds it; the late
/// accrual's report and the settlement carry it while the unit's counts have not moved since.
pub struct UsageFold {
    /// The billing counts, in report order: what the settlement ledgers.
    counts: Vec<(u32, Count)>,
    /// Each billing class's checked sum; `None` when the sum does not fit a `Count`.
    by_class: BTreeMap<u32, Option<Count>>,
}

impl UsageFold {
    fn of(last: &[UnitCount]) -> Self {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::UsageFold);
        let counts = reported(last);
        let mut by_class = BTreeMap::<u32, Option<Count>>::new();
        for (class, count) in &counts {
            let sum = by_class.entry(*class).or_insert(Some(Count::ZERO));
            *sum = (*sum).and_then(|n| n.checked_add(*count).ok());
        }
        Self { counts, by_class }
    }

    /// The billing counts, in report order.
    #[must_use]
    pub fn counts(&self) -> &[(u32, Count)] {
        &self.counts
    }

    /// Each billing class with its checked sum, in class order; `None` when the sum overflowed.
    pub fn by_class(&self) -> impl Iterator<Item = (u32, Option<Count>)> + '_ {
        self.by_class.iter().map(|(class, sum)| (*class, *sum))
    }
}

const SHARDS: usize = 16;

#[derive(Default)]
struct Shard {
    units: foldhash::HashMap<UnitKey, Open>,
    measurement_requests: foldhash::HashMap<UnitKey, Arc<()>>,
}
impl std::ops::Deref for Shard {
    type Target = foldhash::HashMap<UnitKey, Open>;
    fn deref(&self) -> &Self::Target {
        &self.units
    }
}
impl std::ops::DerefMut for Shard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.units
    }
}
impl Shard {
    fn remove(&mut self, key: &UnitKey) -> Option<Open> {
        self.measurement_requests.remove(key);
        self.units.remove(key)
    }
}

/// A root-issued live request scope, distinct from a governor admission.
/// Drop retires its measurement authority even if the driving future is cancelled.
pub struct MeasurementRequestGuard {
    money: Arc<PlaneMoney>,
    key: UnitKey,
    identity: Arc<()>,
}
impl Drop for MeasurementRequestGuard {
    fn drop(&mut self) {
        let mut shard = self.money.shard(self.key);
        if shard
            .measurement_requests
            .get(&self.key)
            .is_some_and(|identity| Arc::ptr_eq(identity, &self.identity))
        {
            shard.measurement_requests.remove(&self.key);
        }
    }
}

pub enum MeasurementRequestState {
    PendingAdmission,
    Admitted(crate::host_measurement::MeasurementContext),
    Retired,
}

pub struct PlaneMoney {
    book: Arc<()>,
    gov: Arc<GovState>,
    post: Arc<dyn EndPost>,

    units: [Mutex<Shard>; SHARDS],
}

impl PlaneMoney {
    #[must_use]
    pub fn new(gov: Arc<GovState>, post: Arc<dyn EndPost>) -> Self {
        PlaneMoney {
            book: Arc::new(()),
            gov,
            post,
            units: std::array::from_fn(|_| Mutex::new(Shard::default())),
        }
    }

    #[must_use]
    pub fn caller_refs(&self) -> Option<super::CallerRefs> {
        Some(self.gov.caller_ref_slot())
    }

    /// Register the actual root request lifetime before ARRIVE/ROUTE/hooks. This
    /// does not admit it, select a budget, or reconstruct a missing money entry.
    pub fn begin_measurement_request(
        self: &Arc<Self>,
        _seal: &busbar_contract::caps::KernelSeal,
        key: UnitKey,
    ) -> Result<MeasurementRequestGuard, crate::host_measurement::Refusal> {
        use crate::host_measurement::Refusal;
        let mut shard = self.shard(key);
        if key.get() == 0
            || shard.contains_key(&key)
            || shard.measurement_requests.contains_key(&key)
        {
            return Err(Refusal::Conflict);
        }
        shard
            .measurement_requests
            .try_reserve(1)
            .map_err(|_| Refusal::Unavailable)?;
        let identity = Arc::new(());
        shard.measurement_requests.insert(key, identity.clone());
        Ok(MeasurementRequestGuard {
            money: self.clone(),
            key,
            identity,
        })
    }

    /// Missing/closed authority is always Retired. Only an explicitly registered
    /// live request with no money entry can be PendingAdmission.
    pub fn measurement_request_state(
        &self,
        seal: &busbar_contract::caps::KernelSeal,
        key: UnitKey,
    ) -> MeasurementRequestState {
        let shard = self.shard(key);
        if !shard.measurement_requests.contains_key(&key) {
            return MeasurementRequestState::Retired;
        }
        match shard.get(&key) {
            None => MeasurementRequestState::PendingAdmission,
            Some(open) => match Self::measurement_context_of(seal, key, open) {
                Ok(context) => MeasurementRequestState::Admitted(context),
                Err(_) => MeasurementRequestState::Retired,
            },
        }
    }

    /// Capture only the host's original, still-live admission. No caller-supplied
    /// account, targets, or current rate lookup participates in this attribution.
    pub fn measurement_context(
        &self,
        seal: &busbar_contract::caps::KernelSeal,
        key: UnitKey,
    ) -> Result<crate::host_measurement::MeasurementContext, crate::host_measurement::Refusal> {
        let units = self.shard(key);
        let open = units
            .get(&key)
            .ok_or(crate::host_measurement::Refusal::Unavailable)?;
        Self::measurement_context_of(seal, key, open)
    }

    fn measurement_context_of(
        seal: &busbar_contract::caps::KernelSeal,
        key: UnitKey,
        open: &Open,
    ) -> Result<crate::host_measurement::MeasurementContext, crate::host_measurement::Refusal> {
        use crate::host_measurement::{MeasurementContext, Refusal};
        if open.finished || open.ledgered || open.abandoned || open.grant.is_none() {
            return Err(Refusal::Unavailable);
        }
        let money = &open.money;
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&money.pool);
        let chain = money
            .cost
            .chain_carried(&money.key, money.charge.chain())
            .map_err(|_| Refusal::Unavailable)?;
        let targets = chain
            .iter()
            .filter(|bucket| bucket.applies_to_pool(pool))
            .map(|bucket| crate::governance::unit_checkpoint::UnitTarget {
                bucket: bucket.bucket_id.to_string(),
                window: crate::governance::budget_window(bucket.window, money.arrived),
                group: bucket.group_name.map(str::to_string),
            })
            .collect();
        MeasurementContext::request(
            seal,
            key.get(),
            money.key.id.clone(),
            money.key.group.clone().unwrap_or_default(),
            targets,
            money.arrived,
            money.charge.raw_era(),
        )
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

    /// Bound additional dispatch/output for one admitted unit. Actual incurred usage is
    /// still settled even if a provider response crosses the configured ceiling.
    pub fn limit_unit_spend(&self, key: UnitKey, ceiling_micros: u64) -> Result<(), ReasonCode> {
        let mut units = self.shard(key);
        let open = units.get_mut(&key).ok_or(ReasonCode::Unpriced)?;
        if ceiling_micros == 0
            || open.spend_ceiling_micros.is_some()
            || open.ledgered
            || open.finished
            || !open.last.is_empty()
        {
            return Err(ReasonCode::Unpriced);
        }
        open.spend_ceiling_micros = Some(ceiling_micros);
        Ok(())
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
                completed: None,
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
            self.post.checkpoint_facts(key),
        );
        let replaced = {
            let mut all = self.shard(key);
            all.insert(key, open)
        };
        drop(replaced);
    }

    /// Capture a live, governor-backed parent for an already authenticated matching key.
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

    /// Reserve real admission custody while the original unit remains live. The reservation
    pub fn reserve_admission(
        &self,
        parent: UnitKey,
        expected_key: &VirtualKey,
    ) -> Result<ReservationMoney, ReasonCode> {
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
        let account = open.fee.account.clone();
        locked(&account.state).children += 1;
        Ok(ReservationMoney {
            money: open.money.clone(),
            grant: grant.clone(),
            fee: FeeParticipation {
                account,
                owner: false,

                refundable: true,
            },
            book: self.book.clone(),
        })
    }

    /// Must run inside the source cell's `with_admitted_call` transaction and once latch.
    pub fn reserve_ticket_admission(
        &self,
        parent: UnitKey,
        source_call: CallId,
        expected_key: &VirtualKey,
        identity: &VerifiedTicketIdentity,
        node_nonce: Arc<()>,
        instance_nonce: Arc<()>,
    ) -> Result<TicketReservation, ReasonCode> {
        if source_call == CallId::UNBOUND || identity.principal().as_ref() != expected_key {
            return Err(ReasonCode::Unpriced);
        }
        let reserved = self.reserve_admission(parent, expected_key)?;
        Ok(TicketReservation {
            money: reserved,
            id: identity.id().to_owned(),
            expires_at: identity.expires_at(),
            key: identity.principal().clone(),
            store: identity.store().clone(),
            source_call,
            source_unit: parent,
            node_nonce,
            instance_nonce,
        })
    }

    /// Consume a real reserved admission once, without another governor admission. Errors
    pub fn adopt_reserved(
        &self,
        reservation: ReservationMoney,
        child: UnitKey,
        lane: String,
        classes: Arc<[String]>,
        fee: FeeRefund,
        expected_key: &VirtualKey,
    ) -> Result<(), ReturnedReservation> {
        if !Arc::ptr_eq(&self.book, &reservation.book)
            || reservation.money.key.as_ref() != expected_key
        {
            return Err(ReturnedReservation {
                reason: ReasonCode::Unpriced,
                reservation,
            });
        }
        let mut all = self.shard(child);
        if all.contains_key(&child) {
            drop(all);
            return Err(ReturnedReservation {
                reason: ReasonCode::Unpriced,
                reservation,
            });
        }
        let mut money = reservation.money.as_ref().clone();
        money.lane = lane;
        money.classes = classes;
        money.fee = fee;
        let ReservationMoney { grant, mut fee, .. } = reservation;

        fee.refundable = false;
        let open = Open::new(
            Arc::new(money),
            Some(grant),
            fee,
            self.post.checkpoint_facts(child),
        );
        all.insert(child, open);
        drop(all);
        Ok(())
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

    /// Verify a unit's own governor admission at the teller's terminal authority check.
    pub fn validate_admitted(
        &self,
        unit: UnitKey,
        expected_key: &VirtualKey,
        grant: &Arc<AdmitGrant>,
    ) -> Result<(), ReasonCode> {
        let all = self.shard(unit);
        let open = all.get(&unit).ok_or(ReasonCode::Unpriced)?;
        if open.ledgered
            || open.abandoned
            || !open.fee.owner
            || open.money.key.as_ref() != expected_key
            || !open.grant.as_ref().is_some_and(|g| Arc::ptr_eq(g, grant))
        {
            return Err(ReasonCode::Unpriced);
        }
        Ok(())
    }

    /// A registered child keeps its real admission after the parent closes. The driver marks
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
    pub fn open_child(
        &self,
        parent: &ParentMoney,
        child: UnitKey,
        lane: String,
        classes: Arc<[String]>,
        fee: FeeRefund,
    ) -> Result<(), ReasonCode> {
        self.install_child_with(parent, child, lane, classes, fee, |_, _, _| Ok(()))
    }

    /// The same checked parent/child transaction, with activation before the child is visible.
    fn install_child_with<R, E: From<ReasonCode>>(
        &self,
        parent: &ParentMoney,
        child: UnitKey,
        lane: String,
        classes: Arc<[String]>,
        fee: FeeRefund,
        activate: impl FnOnce(Arc<UnitMoney>, Arc<AdmitGrant>, Arc<()>) -> Result<R, E>,
    ) -> Result<R, E> {
        if parent.parent == child {
            return Err(ReasonCode::Unpriced.into());
        }
        let checkpoint_audit = self.post.checkpoint_facts(child);
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
            {
                let mut state = locked(&account.state);
                state.children = state.children.checked_add(1).ok_or(ReasonCode::Unpriced)?;
            }
            Ok(Open::new(
                Arc::new(money),
                Some(parent.grant.clone()),
                FeeParticipation {
                    account,
                    owner: false,
                    // No child effects are admitted until activation succeeds. A failed
                    // insertion must not mark an otherwise refundable parent fee incurred.
                    refundable: true,
                },
                checkpoint_audit,
            ))
        };
        let mut removed = None;
        let install = |children: &mut Shard, open: Open| {
            let money = open.money.clone();
            let grant = open.grant.as_ref().expect("parent-backed child").clone();
            let identity = open.identity.clone();
            children.insert(child, open);
            match activate(money, grant, identity) {
                Ok(receipt) => {
                    children
                        .get_mut(&child)
                        .expect("new locked child")
                        .fee
                        .refundable = false;
                    Ok(receipt)
                }
                Err(error) => {
                    removed = children.remove(&child);
                    Err(error)
                }
            }
        };
        let parent_shard = (parent.parent.get() % SHARDS as u64) as usize;
        let child_shard = (child.get() % SHARDS as u64) as usize;
        let result = if parent_shard == child_shard {
            let mut all = self.shard(child);
            if all.contains_key(&child) {
                return Err(ReasonCode::Unpriced.into());
            }
            let open = make_child(all.get(&parent.parent).ok_or(ReasonCode::Unpriced)?)?;
            install(&mut all, open)
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
                return Err(ReasonCode::Unpriced.into());
            }
            let open = make_child(parents.get(&parent.parent).ok_or(ReasonCode::Unpriced)?)?;
            install(children, open)
        };
        // Dropping a child can finalize/refund the parent account. Never do it under shards.
        drop(removed);
        result
    }

    pub fn settle_end(&self, key: UnitKey, caller_status: u32) {
        self.settle_end_as(
            key,
            UnitEnd {
                caller_status,
                cut: false,
                refused_unspent: false,
            },
        );
    }

    pub fn settle_end_as(&self, key: UnitKey, end: UnitEnd) {
        let removed = {
            busbar_contract::stage_probe::tick(
                busbar_contract::stage_probe::Derive::MoneyShardLock,
            );
            let mut all = self.shard(key);
            if all.get(&key).is_some_and(|open| open.native.is_some()) {
                return;
            }
            all.remove(&key)
        };
        let Some(open) = removed else {
            return;
        };
        self.settle_removed(key, open, end);
    }

    /// Terminal cleanup checks and removes the exact admitted Open in the same critical section.
    /// Retiring its invocation cannot prevent cleanup, and reusing a numeric unit cannot redirect it.
    pub fn settle_admitted(
        &self,
        request: &super::request_admission::AdmittedRequest,
        end: UnitEnd,
    ) -> Result<bool, NativeAdmissionError> {
        let removed = {
            let mut all = self.shard(request.unit());
            let Some(open) = all.get(&request.unit()) else {
                return Ok(false);
            };
            let Some(grant) = &open.grant else {
                return Err(NativeAdmissionError::NotLive);
            };
            if !request.matches_money_identity(&self.book, &open.identity, grant)
                || !request.matches_governance(&self.gov)
            {
                return Err(NativeAdmissionError::NotLive);
            }
            if open.native.is_some() {
                return Err(NativeAdmissionError::SelectedTerminalRequired);
            }
            all.remove(&request.unit())
        };
        if let Some(open) = removed {
            self.settle_removed(request.unit(), open, end);
        }
        Ok(true)
    }

    fn settle_removed(&self, key: UnitKey, mut open: Open, end: UnitEnd) {
        let UnitEnd {
            caller_status,
            refused_unspent,
            ..
        } = end;
        // A REFUSED, UNSPENT UNIT IS NOT COUNTED: no units reported (nor a cancel bill ledgered).
        if refused_unspent && !open.ledgered && open.last.iter().all(|u| u.amount == 0) {
            self.gov.release_request(&open.money.charge);
        }
        if !open.ledgered {
            let delivered = (200..=299).contains(&caller_status);
            let fold = open.usage_fold();
            let counts = fold.counts();
            if !self.finish_checkpoint(key, &open, counts, delivered) {
                self.bill(&open.money, open.provider.as_deref(), counts, |_| delivered);
            }
        }
        open.fee.refundable = open.money.fee.refunds(caller_status, &open.last);
    }

    #[must_use]
    pub fn last_counts(&self, key: UnitKey) -> Option<Vec<(u32, Count)>> {
        self.usage_fold(key)?
            .by_class()
            .map(|(class, count)| count.map(|count| (class, count)))
            .collect()
    }

    /// The unit's last reported usage, folded once per revision (SP-M1): the meter gate's input.
    #[must_use]
    pub fn usage_fold(&self, key: UnitKey) -> Option<Arc<UsageFold>> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::MoneyShardLock);
        self.shard(key).get_mut(&key).and_then(|open| {
            if let Some(native) = &open.native {
                UsageFold::selected(native.checkpoint(), &open.money.classes).map(Arc::new)
            } else {
                Some(open.usage_fold())
            }
        })
    }

    /// The unit's serving lane with its usage fold, under one shard lock: the late accrual's
    /// report.
    #[must_use]
    pub fn usage(&self, key: UnitKey) -> Option<(String, Arc<UsageFold>)> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::MoneyShardLock);
        self.shard(key).get_mut(&key).and_then(|open| {
            if open.native.is_some() {
                None
            } else {
                Some((open.money.lane.clone(), open.usage_fold()))
            }
        })
    }

    /// [`PlaneMoney::usage`] with the unit's sealed attribution (ADMIN-API-1.6 §3.2): its key's
    /// `group`, its `pool` and its serving `provider`, the fields the settlement meters
    /// with, joined into one text — one allocation per unit.
    #[must_use]
    pub fn attributed_usage(&self, key: UnitKey) -> Option<(String, String, Arc<UsageFold>)> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::MoneyShardLock);
        self.shard(key).get_mut(&key).and_then(|open| {
            if open.native.is_some() {
                return None;
            }
            let m = &open.money;
            let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&m.pool);
            let attribution = busbar_kernel_audit::attribution(
                m.key.group.as_deref().unwrap_or_default(),
                pool,
                open.provider.as_deref().unwrap_or_default(),
            );
            Some((m.lane.clone(), attribution, open.usage_fold()))
        })
    }

    #[must_use]
    pub fn serving(&self, key: UnitKey) -> Option<String> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::MoneyShardLock);
        self.shard(key).get(&key).and_then(|open| {
            if let Some(native) = &open.native {
                let parts = native.checkpoint().partitions.as_ref()?;
                let target = parts.final_target?;
                return parts
                    .attempts
                    .iter()
                    .find(|attempt| attempt.preparation == target)
                    .map(|attempt| attempt.usage.lane.clone());
            }
            Some(open.money.lane.clone())
        })
    }

    #[must_use]
    pub fn open_units(&self) -> usize {
        self.units.iter().map(|shard| locked(shard).len()).sum()
    }

    pub fn checkpoint_decoded(&self, key: UnitKey, class: busbar_contract::caps::OpClassId) {
        self.post.checkpoint_decoded(key, class);
    }

    fn checkpoint_snapshot(
        &self,
        key: UnitKey,
        open: &Open,
        counts: &[(u32, busbar_contract::Count)],
        metered: bool,
    ) -> Option<crate::governance::unit_checkpoint::UnitCheckpoint> {
        if open.native.is_some() {
            return None;
        }
        use crate::governance::unit_checkpoint::{UnitCheckpoint, UnitTarget};
        let m = &open.money;
        let mut units = BTreeMap::<String, busbar_contract::Count>::new();
        for (class, count) in counts {
            if m.fee.is_fee(*class) {
                continue;
            }
            let name = m.classes.get(*class as usize)?;
            let previous = units.entry(name.clone()).or_default();
            *previous = previous.checked_add(*count).ok()?;
        }
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&m.pool);
        let targets = match m.cost.chain_carried(&m.key, m.charge.chain()) {
            Ok(chain) => chain
                .iter()
                .filter(|bucket| bucket.applies_to_pool(pool))
                .map(|bucket| UnitTarget {
                    bucket: bucket.bucket_id.to_string(),
                    window: crate::governance::budget_window(bucket.window, m.arrived),
                    group: bucket.group_name.map(str::to_string),
                })
                .collect(),
            Err(_) => vec![UnitTarget {
                bucket: m.key.id.clone(),
                window: 0,
                group: None,
            }],
        };
        let era = m.charge.raw_era();
        Some(UnitCheckpoint {
            id: open.checkpoint_id,
            revision: 0,
            unit: key.get(),
            principal: m.key.id.clone(),
            group: m.key.group.clone().unwrap_or_default(),
            arrived: m.arrived,
            lane: m.lane.clone(),
            provider: open.provider.clone(),
            era_at: era.effective_from,
            era_entry: era.entry_id.map(|entry| entry.0),
            units,
            targets,
            metered,
            ended: false,
            terminal: None,
            measurement: None,
            unread: None,
            partitions: None,
            audit: self
                .post
                .checkpoint_facts(key)
                .or_else(|| open.checkpoint_audit.clone()),
        })
    }

    fn finish_checkpoint(
        &self,
        key: UnitKey,
        open: &Open,
        counts: &[(u32, busbar_contract::Count)],
        metered: bool,
    ) -> bool {
        self.finish_checkpoint_unread(key, open, counts, metered, None)
    }

    fn finish_checkpoint_unread(
        &self,
        key: UnitKey,
        open: &Open,
        counts: &[(u32, busbar_contract::Count)],
        metered: bool,
        unread: Option<ReasonCode>,
    ) -> bool {
        if !self.gov.unit_checkpoints_enabled() {
            return false;
        }
        if let Some(mut snapshot) = self.checkpoint_snapshot(key, open, counts, metered) {
            snapshot.unread = unread.map(|reason| reason.as_str().to_string());
            busbar_contract::stage_probe::tick(
                busbar_contract::stage_probe::Derive::CheckpointStage,
            );
            self.gov.finish_unit_checkpoint(snapshot);
        } else {
            tracing::error!(unit = key.get(), checkpoint = %hex::encode(open.checkpoint_id),
                "terminal unit count conversion failed; running custody remains unresolved");
        }
        // An invalid terminal report cannot fall back to an independently owned ordinary bill.
        true
    }

    fn bill(
        &self,
        m: &UnitMoney,
        provider: Option<&str>,
        counts: &[(u32, Count)],
        metered: impl FnOnce(&[(u32, Count)]) -> bool,
    ) {
        let counts = &usage_only(m, counts);
        let Some(units) = named(&m.classes, counts) else {
            tracing::error!("exact unit count overflow refused at settlement");
            return;
        };
        if let Err(error) = self.gov.record_counts_served_on(
            &m.cost,
            &m.key,
            m.charge.chain(),
            &m.pool,
            &m.lane,
            provider,
            &units,
            m.arrived,
            m.charge.raw_era(),
        ) {
            tracing::error!(%error, "exact usage accrual refused");
            return;
        }
        if metered(counts) {
            if let Err(error) = self.gov.record_lane_counts_in_era(
                &m.key,
                &m.lane,
                provider,
                &units,
                m.arrived,
                m.charge.raw_era(),
            ) {
                tracing::error!(%error, "exact metering accrual refused");
            }
        }
    }

    fn dry(&self, m: &UnitMoney, counts: &[(u32, Count)]) -> bool {
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
        let Some(usage_units) = named(&m.classes, &usage_only(m, counts)) else {
            return true;
        };
        match m.cost.price_counts_nanos(&m.lane, &usage_units) {
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
        let billed = units_bill(u.source);
        if units[..at]
            .iter()
            .any(|v| name(v) == Some(this) && units_bill(v.source) == billed)
        {
            return true;
        }
        units[at..]
            .iter()
            .filter(|&v| name(v) == Some(this) && units_bill(v.source) == billed)
            .try_fold(Count::ZERO, |sum, v| sum.checked_add(v.count()?))
            .is_ok_and(Count::fits_a_64_bit_column)
    })
}

/// Whether a piece's counts are exactly the counts last taken.
fn same_counts(last: &[UnitCount], units: &[UnitCount]) -> bool {
    last.len() == units.len()
        && last
            .iter()
            .zip(units)
            .all(|(a, b)| a.class == b.class && a.source == b.source && a.amount == b.amount)
}

fn usage_only(m: &UnitMoney, counts: &[(u32, Count)]) -> Vec<(u32, Count)> {
    counts
        .iter()
        .copied()
        .filter(|(class, _)| !m.fee.is_fee(*class))
        .collect()
}

fn named(classes: &[String], counts: &[(u32, Count)]) -> Option<BTreeMap<String, Count>> {
    let mut units: BTreeMap<String, Count> = BTreeMap::new();
    for (class, amount) in counts {
        if let Some(name) = classes.get(*class as usize) {
            let n = units.entry(name.clone()).or_insert(Count::ZERO);
            *n = n.checked_add(*amount).ok()?;
        }
    }
    Some(units)
}

pub(super) fn reported(units: &[UnitCount]) -> Vec<(u32, Count)> {
    units
        .iter()
        .filter(|u| units_bill(u.source))
        .map(|u| (u.class, u.count().expect("validated unit source")))
        .collect()
}

impl MoneySeam for PlaneMoney {
    /// SHUTDOWN-HANG F4: every open unit of the 16 shards, read once at exit. Each entry shares
    /// the unit's money facts and, for a governed unit, a clone of its grant.
    fn open_units(&self, out: &mut Vec<super::OpenUnitEvidence>) {
        for shard in &self.units {
            let all = locked(shard);
            for (key, open) in all.iter() {
                let mut reported = Vec::with_capacity(open.last.len());
                reported.extend_from_slice(&open.last);
                out.push(super::OpenUnitEvidence {
                    unit: *key,
                    checkpoint: open.checkpoint_id,
                    money: Arc::clone(&open.money),
                    reported,
                    ledgered: open.ledgered,
                    finished: open.finished,
                    grant: open.grant.clone(),
                });
            }
        }
    }

    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        let mut all = self.shard(ctx.key);
        let Some(open) = all.get_mut(&ctx.key) else {
            return Checkpoint::Continue;
        };
        if open.native.is_some() {
            return Checkpoint::Unpriced;
        }
        if !adds_up(&open.money.classes, units)
            || units.iter().any(|u| {
                units_bill(u.source) && u.amount != 0 && open.observation_classes.contains(&u.class)
            })
        {
            return Checkpoint::Unpriced;
        }
        // CHECKPOINT ONLY ON CHANGE (SP-M2): a piece whose counts and checkpoint facts equal the
        // last ones taken replaces nothing and stages nothing; the budget is still asked below.
        let facts = self.post.checkpoint_facts(ctx.key);
        let unchanged = open.rev != 0
            && !open.snapshot_refused
            && same_counts(&open.last, units)
            && facts
                .as_ref()
                .is_none_or(|audit| open.checkpoint_audit.as_ref() == Some(audit));
        if !unchanged {
            open.last.clear();
            open.last.extend_from_slice(units);
            open.rev = open.rev.wrapping_add(1);
            if let Some(audit) = facts {
                open.checkpoint_audit = Some(audit);
            }
        }
        if !unchanged && self.gov.unit_checkpoints_enabled() && !open.ledgered {
            let counts = reported(units);
            let Some(snapshot) = self.checkpoint_snapshot(
                ctx.key,
                open,
                &counts,
                bills(&usage_only(&open.money, &counts)),
            ) else {
                open.snapshot_refused = true;
                return Checkpoint::Unpriced;
            };
            open.snapshot_refused = false;
            busbar_contract::stage_probe::tick(
                busbar_contract::stage_probe::Derive::CheckpointStage,
            );
            self.gov.stage_unit_checkpoint(snapshot);
        }
        if let Some(ceiling) = open.spend_ceiling_micros {
            let counts = reported(units);
            let (plane, _) = busbar_kernel_ledger::cost::split_plane_lane(&open.money.lane);
            let fee = u128::try_from(open.money.cost.request_fee_on(plane))
                .ok()
                .and_then(|n| n.checked_mul(busbar_kernel_ledger::cost::NANOS_PER_CENT));
            let total = named(&open.money.classes, &usage_only(&open.money, &counts))
                .and_then(|counts| {
                    open.money
                        .cost
                        .price_counts_nanos(&open.money.lane, &counts)
                })
                .zip(fee)
                .and_then(|(usage, fee)| usage.checked_add(fee));
            match total {
                None => return Checkpoint::Unpriced,
                Some(total) if total >= u128::from(ceiling) * 1_000 => return Checkpoint::Cut,
                Some(_) => {}
            }
        }
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
        let (money, provider, removed, durable) = {
            let mut all = self.shard(ctx.key);
            all.measurement_requests.remove(&ctx.key);
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.native.is_some() || open.ledgered || open.session {
                return;
            }
            open.ledgered = true;
            let durable = self.finish_checkpoint_unread(
                ctx.key,
                open,
                &bill.billed,
                bills(&usage_only(&open.money, &bill.billed)),
                bill.unread,
            );
            let money = open.money.clone();
            let provider = open.provider.clone();
            let removed = if open.abandoned {
                all.remove(&ctx.key)
            } else {
                None
            };
            (money, provider, removed, durable)
        };
        if !durable {
            self.bill(&money, provider.as_deref(), &bill.billed, bills);
        }
        drop(removed);
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        let removed = {
            let mut all = self.shard(ctx.key);
            all.measurement_requests.remove(&ctx.key);
            match all.get_mut(&ctx.key) {
                Some(open) if open.native.is_some() => None,
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
                let counts = reported(&open.last);
                if !self.finish_checkpoint(
                    ctx.key,
                    &open,
                    &counts,
                    bills(&usage_only(&open.money, &counts)),
                ) {
                    self.bill(&open.money, open.provider.as_deref(), &counts, bills);
                }
            } else if !open.ledgered {
                // Empty abandoned units still retire their last running snapshot.
                self.finish_checkpoint(ctx.key, &open, &[], false);
            }

            drop(open);
        }
        self.post.post(ctx, ended);
    }

    fn finished(&self, ctx: &UnitCtx) {
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            if open.native.is_some() {
                return;
            }
            open.finished = true;
        }
    }

    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        match self.shard(ctx.key).get_mut(&ctx.key) {
            Some(open) if !open.ledgered && open.native.is_none() => {
                open.session = true;
                Ok(())
            }
            _ => Err(ReasonCode::Unpriced),
        }
    }

    fn session_ended(&self, ctx: &UnitCtx) {
        let (money, provider, counts, removed, durable) = {
            let mut all = self.shard(ctx.key);
            let Some(open) = all.get_mut(&ctx.key) else {
                return;
            };
            if open.native.is_some() || open.ledgered || !open.session {
                return;
            }
            open.ledgered = true;
            let money = open.money.clone();
            let provider = open.provider.clone();
            let counts = reported(&open.last);
            let durable = self.finish_checkpoint(
                ctx.key,
                open,
                &counts,
                bills(&usage_only(&open.money, &counts)),
            );
            let removed = if open.abandoned {
                all.remove(&ctx.key)
            } else {
                None
            };
            (money, provider, counts, removed, durable)
        };
        if !durable {
            self.bill(&money, provider.as_deref(), &counts, bills);
        }
        drop(removed);
    }

    fn served(&self, ctx: &UnitCtx, member: &str, provider: &str) {
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            if open.native.is_some() {
                return;
            }
            if !open.laned {
                let lane = &mut Arc::make_mut(&mut open.money).lane;
                lane.clear();
                lane.push_str(member);
            }
            let kept = open.provider.get_or_insert_with(String::new);
            kept.clear();
            kept.push_str(provider);
        }
    }

    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        if lane.is_empty() || lane.chars().any(char::is_control) {
            return;
        }
        if let Some(open) = self.shard(ctx.key).get_mut(&ctx.key) {
            if open.native.is_some() {
                return;
            }
            let money = Arc::make_mut(&mut open.money);
            // `<plane><SEP><lane>`, keeping the plane prefix already there, in the lane's own buffer.
            let plane = busbar_kernel_ledger::cost::split_plane_lane(&money.lane)
                .0
                .len();
            if plane == 0 {
                money.lane.clear();
            } else {
                money.lane.truncate(plane);
                money.lane.push(crate::governance::PLANE_LANE_SEP);
            }
            money.lane.push_str(lane);
            open.laned = true;
        }
    }
}

fn locked<T>(shard: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    shard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bills(usage: &[(u32, Count)]) -> bool {
    usage.iter().any(|(_, n)| *n > Count::ZERO)
}

#[cfg(test)]
#[path = "tests/money_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/qualified_pool_tests.rs"]
mod qualified_pool_tests;

#[cfg(test)]
#[path = "tests/checkpoint_change_tests.rs"]
mod checkpoint_change_tests;
