// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WALK: the one stepper that answers, attempt by attempt, which member is next or what the

use std::time::Duration;

use busbar_contract::caps::{Pass, Route};
use busbar_ports::clock::{Deadline, HostClock, Reading};
use foldhash::HashMap;

use crate::exhaustion::{least_bad, retry_after_secs};
use crate::pool::{Member, OnExhausted, Pool};
use crate::ports::{Breaker, Capacity, DestinationId, Permit, Telemetry, Unavailable};
use crate::select::{pick_among, PickInput, RequestCtx};
use crate::wire::Shed;

/// Everything the walk reads, borrowed for one step. Shared across every unit of the generation;
pub struct WalkPorts<'p> {
    /// The breaker unit.
    pub breaker: &'p dyn Breaker,
    /// The pools' permit store.
    pub capacity: &'p dyn Capacity,
    /// The host clock: the walk's waits sleep on it; the walk reads it only as the wake of a wait.
    pub clock: &'p HostClock,
    /// The counters.
    pub telemetry: &'p dyn Telemetry,
    /// The pools, by name.
    pub pools: &'p HashMap<String, Pool>,
}

/// THE SHAPE A UNIT'S HOOKS PUT ON ITS PICKS (the design's route pump, "Hooks": the routing-stage policy
pub trait Shape {
    /// `members` of a pick, as the unit's hooks leave them: the walk's own pool (`primary`) or a
    fn shape(
        &self,
        pool: &str,
        members: Vec<Member>,
        primary: bool,
    ) -> Option<(Vec<Member>, Vec<DestinationId>)>;
}

/// The walk's whole budget over `pool`, seconds: the pool's request timeout, `0` for a pool that is
#[must_use]
pub fn budget_secs(pools: &HashMap<String, Pool>, pool: &str) -> u64 {
    pools.get(pool).map_or(0, |p| p.failover().timeout_secs)
}

/// Where the walk is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The ordered walk over the unit's pool.
    Primary(String),
    /// The pool's members are spent: its terminal runs next. `true` = the walk's own pool,
    /// `false` = a pool it spilled into; the terminal shapes the members as that pool's picks did.
    Terminal(String, bool),
    /// A spill into this pool (degraded).
    Spill(String),
    /// Every path is spent: every step from here answers this shed.
    Shed(Shed),
}

/// A member the walk took for the next attempt. It is excluded from every pick of the unit after it,
/// and the caller owns its permit and the probe it may have won until the attempt records an
/// outcome.
#[derive(Debug)]
pub struct Taken {
    /// The pool it was taken from.
    pub pool: String,
    /// The member.
    pub member: Member,
    /// Its concurrency slot.
    pub permit: Permit,
    /// The recovery probe this take won, owned by the attempt until it records an outcome.
    pub probe: Option<u64>,
    /// A terminal's dispatch (a spill, the one breaker bypass, a queued slot): an answered failure
    /// is relayed, never failed over.
    pub degraded: bool,
    /// The dispatch record's attempt number, counted from one across every member the walk takes
    /// (its own pool and every terminal), as 1.5.5 numbered its attempts (v1.5.5
    /// `crates/busbar/src/proxy/engine/mod.rs:1364`, `:1448`).
    pub attempt: u32,
}

/// The pool's bounded wait, answered by [`Walk::next`] for the caller to run outside its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wait {
    pool: String,
    max_ms: u64,
    /// The pool's members as the unit's hooks kept them: the shed this wait may end on reads its
    /// wait off these and no others.
    members: Vec<Member>,
}

/// What one step of the walk answers.
#[derive(Debug)]
pub enum Step {
    /// The member to attempt next.
    Take(Taken),
    /// The refusal the caller is told.
    Shed(Shed),
    /// The queue terminal: [`Walk::park`], then [`Parked::wait`], then [`Walk::waited`].
    Wait(Wait),
}

/// A parked wait: the members passed over AT CAPACITY on the last pick, the bound, and when it
pub struct Parked<'p> {
    /// The pool's name, as the walk keys it.
    name: String,
    pool: &'p Pool,
    /// The members the hooks kept ([`Wait`]'s), handed on to the shed.
    members: Vec<Member>,
    waiting: Vec<DestinationId>,
    /// When the wait gives up: the pool's bound from the park, capped by the walk's deadline.
    until: Deadline,
    /// The reading the park was made at.
    at: Reading,
}

/// What a wait came back with: the member that freed a slot, its permit and the probe its breaker
pub struct Waited<'p> {
    name: String,
    pool: &'p Pool,
    members: Vec<Member>,
    won: Option<(Member, Permit, Option<u64>)>,
    /// The reading of the wake that ended the wait: the wake's own, or the deadline's time when it ran out.
    at: Reading,
}

impl Waited<'_> {
    /// The reading of the wake that ended the wait (the deadline's time when the wait ran out): the time
    /// [`Walk::waited`] is judged at.
    #[must_use]
    pub fn at(&self) -> Reading {
        self.at
    }
}

/// ONE UNIT'S WALK: its request context (deadline, every member tried, every pool visited), where
/// it is, and how many hops it has taken.
#[derive(Debug, Clone)]
pub struct Walk {
    ctx: RequestCtx,
    phase: Phase,
    hops: usize,
    /// Members taken so far, every path counted.
    taken: u32,
}

impl Walk {
    /// A walk over `pool` starting now: its budget is the pool's request timeout.
    #[must_use]
    pub fn start(ports: &WalkPorts<'_>, pool: &str, at: Reading) -> Self {
        Self {
            ctx: RequestCtx::new(budget_secs(ports.pools, pool), secs(at), millis(at)),
            phase: Phase::Primary(pool.to_string()),
            hops: 0,
            taken: 0,
        }
    }

    /// A walk with no pool to walk, bounded by `budget_secs` from now: one health probe's. Its one
    #[must_use]
    pub fn pinned(budget_secs: u64, at: Reading) -> Self {
        Self {
            ctx: RequestCtx::new(budget_secs, secs(at), millis(at)),
            phase: Phase::Shed(Shed::empty_pool()),
            hops: 0,
            taken: 0,
        }
    }

    /// The request context: the deadline and everything the walk has excluded.
    #[must_use]
    pub fn ctx(&self) -> &RequestCtx {
        &self.ctx
    }

    /// The pool the walk is in and whether it is the walk's own (`true`) rather than a spill;
    #[must_use]
    pub fn walking(&self) -> Option<(&str, bool)> {
        match &self.phase {
            Phase::Primary(name) => Some((name, true)),
            Phase::Spill(name) | Phase::Terminal(name, _) => Some((name, false)),
            Phase::Shed(_) => None,
        }
    }

    /// The walk ends here, before its pool's terminal: every step from now answers `shed`.
    pub fn refuse(&mut self, shed: Shed) {
        self.phase = Phase::Shed(shed);
    }

    /// A refusal for size from `failed` of `pool`: every ADMISSIBLE member whose window is at or
    pub fn refused_for_size(&mut self, ports: &WalkPorts<'_>, pool: &str, failed: &Member) {
        if let Some(pool) = ports.pools.get(pool) {
            exclude_smaller_windows(pool.admissible_members(), failed, &mut self.ctx);
        }
    }

    /// THE WALK'S NEXT STEP: a member, the pool's terminal's refusal, or its bounded wait.
    pub fn next(
        &mut self,
        ports: &WalkPorts<'_>,
        affinity: Option<u64>,
        token: &Pass<Route>,
        at: Reading,
    ) -> Step {
        self.next_shaped(ports, affinity, None, token, at)
    }

    /// [`Self::next`], each pick's members as the unit's hooks `shape` them.
    pub fn next_shaped(
        &mut self,
        ports: &WalkPorts<'_>,
        affinity: Option<u64>,
        shape: Option<&dyn Shape>,
        token: &Pass<Route>,
        at: Reading,
    ) -> Step {
        let now = secs(at);
        loop {
            if self.ctx.expired(now) {
                return Step::Shed(Shed::request_timeout());
            }
            match self.phase.clone() {
                Phase::Shed(shed) => return Step::Shed(shed),
                Phase::Primary(name) => {
                    let Some(pool) = ports.pools.get(&name) else {
                        return Step::Shed(Shed::empty_pool());
                    };
                    if pool.admissible_members().is_empty() {
                        return Step::Shed(Shed::empty_pool());
                    }
                    if self.hops <= pool.failover().max_hops {
                        match self.pick(
                            ports,
                            pool,
                            PickAt {
                                affinity,
                                shape,
                                primary: true,
                                now,
                            },
                            token,
                        ) {
                            Ok(Some(taken)) => {
                                self.hops += 1;
                                return Step::Take(taken);
                            }
                            Ok(None) => {}
                            Err(shed) => return Step::Shed(shed),
                        }
                    }
                    self.phase = Phase::Terminal(name, true);
                }
                Phase::Spill(name) => {
                    let Some(pool) = ports.pools.get(&name) else {
                        return Step::Shed(pool_shed(ports, &name, &[], now, token));
                    };
                    match self.pick(
                        ports,
                        pool,
                        PickAt {
                            affinity: None,
                            shape,
                            primary: false,
                            now,
                        },
                        token,
                    ) {
                        Ok(Some(taken)) => return Step::Take(taken),
                        Ok(None) => {}
                        Err(shed) => return Step::Shed(shed),
                    }
                    self.phase = Phase::Terminal(name, false);
                }
                Phase::Terminal(name, primary) => {
                    self.ctx.mark_pool_visited(&name);
                    let Some(pool) = ports.pools.get(&name) else {
                        return Step::Shed(pool_shed(ports, &name, &[], now, token));
                    };

                    let kept = |walk: &mut Self| {
                        walk.shaped(pool, shape, primary)
                            .map(|(members, _)| members)
                    };
                    match &pool.on_exhausted {
                        OnExhausted::Status503 => {
                            return Step::Shed(match kept(self) {
                                Ok(members) => pool_shed(ports, &name, &members, now, token),
                                Err(shed) => shed,
                            });
                        }
                        OnExhausted::FallbackPool(target) => {
                            if self.ctx.is_pool_visited(target) || !ports.pools.contains_key(target)
                            {
                                let secs = retry_after_secs(ports.breaker, &[], target, now, token);
                                return Step::Shed(Shed::overloaded(secs));
                            }
                            self.ctx.mark_pool_visited(target);
                            self.phase = Phase::Spill(target.clone());
                        }
                        OnExhausted::LeastBad => {
                            let members = match kept(self) {
                                Ok(members) => members,
                                Err(shed) => return Step::Shed(shed),
                            };

                            let shed = pool_shed(ports, &name, &members, now, token);
                            self.phase = Phase::Shed(shed.clone());
                            return match least_bad(ports, pool, &members, now, token) {
                                Some((member, permit)) => {
                                    Step::Take(self.take(&pool.name, member, permit, None, true))
                                }
                                None => Step::Shed(shed),
                            };
                        }
                        OnExhausted::Queue { max_ms } => {
                            return match kept(self) {
                                Ok(members) => Step::Wait(Wait {
                                    pool: name,
                                    max_ms: *max_ms,
                                    members,
                                }),
                                Err(shed) => Step::Shed(shed),
                            };
                        }
                    }
                }
            }
        }
    }

    /// Admit a new exchange on a completed exchange's destination, without treating it as
    /// failover. The caller supplies only its previously admitted member. Capacity, breaker,
    /// hook restrictions and the original deadline all apply again.
    pub fn continue_member(
        &mut self,
        ports: &WalkPorts<'_>,
        pool_name: &str,
        destination: DestinationId,
        shape: &dyn Shape,
        token: &Pass<Route>,
        at: Reading,
    ) -> Option<Taken> {
        let now = secs(at);
        if matches!(self.phase, Phase::Shed(_))
            || self.ctx.expired(now)
            || !self.ctx.is_excluded(destination)
        {
            return None;
        }
        let pool = ports.pools.get(pool_name)?;
        let primary = matches!(&self.phase, Phase::Primary(name) if name == pool_name);
        let (members, _) = self.shaped(pool, Some(shape), primary).ok()?;
        let member = members.into_iter().find(|m| m.destination == destination)?;
        let mut ctx = self.ctx.continuing(destination);
        let mut picked = pick_among(
            &PickInput {
                breaker: ports.breaker,
                capacity: ports.capacity,
                floor: &pool.floor,
                pool: pool_name,
                members: std::slice::from_ref(&member),
                affinity: None,
                preference: None,
                now,
                token,
            },
            &mut ctx,
        )?;
        let probe = picked.take_probe_epoch();
        Some(self.take(pool_name, member.clone(), picked.permit, probe, !primary))
    }

    /// THE ONE PICK, over `pool`'s members this unit has not tried: the walk's own pool
    fn pick(
        &mut self,
        ports: &WalkPorts<'_>,
        pool: &Pool,
        at: PickAt<'_>,
        token: &Pass<Route>,
    ) -> Result<Option<Taken>, Shed> {
        let PickAt {
            affinity,
            shape,
            primary,
            now,
        } = at;
        let (members, order) = self.shaped(pool, shape, primary)?;
        let Some(mut picked) = pick_among(
            &PickInput {
                breaker: ports.breaker,
                capacity: ports.capacity,
                floor: &pool.floor,
                pool: &pool.name,
                members: &members,
                affinity,
                preference: (!order.is_empty()).then_some(order.as_slice()),
                now,
                token,
            },
            &mut self.ctx,
        ) else {
            return Ok(None);
        };
        let Some(member) = members
            .iter()
            .find(|m| m.destination == picked.destination)
            .cloned()
        else {
            return Ok(None);
        };
        let probe = picked.take_probe_epoch();
        Ok(Some(self.take(
            &pool.name,
            member,
            picked.permit,
            probe,
            !primary,
        )))
    }

    /// `pool`'s admissible members as the unit's hooks `shape` them for a pick of the walk's own
    fn shaped(
        &mut self,
        pool: &Pool,
        shape: Option<&dyn Shape>,
        primary: bool,
    ) -> Result<(Vec<Member>, Vec<DestinationId>), Shed> {
        let admissible = pool.admissible_members().to_vec();
        let Some(shape) = shape else {
            return Ok((admissible, Vec::new()));
        };
        shape.shape(&pool.name, admissible, primary).ok_or_else(|| {
            let shed = Shed::restrict_no_lane();
            self.phase = Phase::Shed(shed.clone());
            shed
        })
    }

    /// Take `member` of `pool` for the next attempt: excluded from every pick of the unit after it.
    fn take(
        &mut self,
        pool: &str,
        member: Member,
        permit: Permit,
        probe: Option<u64>,
        degraded: bool,
    ) -> Taken {
        self.ctx.exclude(member.destination);
        self.taken = self.taken.saturating_add(1);
        Taken {
            pool: pool.to_string(),
            member,
            permit,
            probe,
            degraded,
            attempt: self.taken,
        }
    }

    /// Park the queue terminal's wait: the members the last pick passed over AT CAPACITY (a held
    pub fn park<'p>(
        &mut self,
        ports: &WalkPorts<'p>,
        wait: &Wait,
        token: &Pass<Route>,
        at: Reading,
    ) -> Result<Parked<'p>, Shed> {
        let now = secs(at);
        let Some(pool) = ports.pools.get(&wait.pool) else {
            return Err(pool_shed(ports, &wait.pool, &[], now, token));
        };
        let mut waiting: Vec<DestinationId> = Vec::new();
        for (destination, reason) in self.ctx.excluded_reasons() {
            if matches!(reason, Unavailable::AtCapacity { .. }) && !waiting.contains(destination) {
                waiting.push(*destination);
            }
        }
        if waiting.is_empty() {
            let shed = pool_shed(ports, &wait.pool, &wait.members, now, token);
            self.phase = Phase::Shed(shed.clone());
            return Err(shed);
        }
        let until =
            Deadline::after(at, Duration::from_millis(wait.max_ms)).min(self.ctx.deadline());
        Ok(Parked {
            name: wait.pool.clone(),
            pool,
            members: wait.members.clone(),
            waiting,
            until,
            at,
        })
    }

    /// The wait is over: a member it won is taken (degraded), and from here every step
    pub fn waited(
        &mut self,
        ports: &WalkPorts<'_>,
        waited: Waited<'_>,
        token: &Pass<Route>,
        at: Reading,
    ) -> Result<Taken, Shed> {
        let taken = waited.won.map(|(member, permit, probe)| {
            self.take(&waited.pool.name, member, permit, probe, true)
        });
        let shed = pool_shed(ports, &waited.name, &waited.members, secs(at), token);
        self.phase = Phase::Shed(shed.clone());
        taken.ok_or(shed)
    }
}

impl<'p> Parked<'p> {
    /// THE BOUNDED WAIT for a slot on a member passed over AT CAPACITY, then the breaker re-asked
    pub async fn wait(mut self, ports: &WalkPorts<'_>) -> Waited<'p> {
        let pool = self.pool;
        let members = pool.admissible_members();
        let _parked = QueuedGuard::park(ports.telemetry, &pool.name);
        let mut at = self.at;
        let won = loop {
            if self.waiting.is_empty() {
                break None;
            }
            let Ok(woke) = busbar_ports::clock::until(
                ports.clock,
                self.until,
                ports.capacity.acquire_any(&self.waiting),
            )
            .await
            else {
                // The deadline's timer finished first: the time is the deadline's, read nowhere.
                at = due(at, self.until);
                break None;
            };
            at = woke.at;
            let Some((destination, permit)) = woke.value else {
                break None;
            };
            let now = secs(woke.at);
            match ports.breaker.try_admit(&pool.name, destination, now) {
                Ok(admit) => {
                    let Some(member) = members.iter().find(|m| m.destination == destination) else {
                        if let Some(epoch) = admit.probe_epoch {
                            ports
                                .breaker
                                .release_probe(&pool.name, destination, epoch, now);
                        }
                        break None;
                    };
                    break Some((member.clone(), permit, admit.probe_epoch));
                }
                Err(_) => {
                    drop(permit);
                    self.waiting.retain(|d| *d != destination);
                }
            }
        };
        Waited {
            name: self.name,
            pool,
            members: self.members,
            won,
            at,
        }
    }
}

/// The time a deadline names, as a reading: its monotonic point, and the wall clock moved on from `from` by as much.
fn due(from: Reading, until: Deadline) -> Reading {
    let by = until.mono_ns().saturating_sub(from.mono_ns);
    Reading {
        wall_ns: from.wall_ns.saturating_add(by),
        mono_ns: from.mono_ns.max(until.mono_ns()),
    }
}

/// What one [`Walk::pick`] is over: the affinity and the hooks' shape, whether the pool is the walk's
/// own, and the step's one clock reading.
#[derive(Clone, Copy)]
struct PickAt<'s> {
    affinity: Option<u64>,
    shape: Option<&'s dyn Shape>,
    primary: bool,
    now: u64,
}

/// One parked waiter's place in the depth gauge, given back on drop. The increment and the
struct QueuedGuard<'a> {
    telemetry: &'a dyn Telemetry,
    pool: &'a str,
}

impl<'a> QueuedGuard<'a> {
    /// Count one waiter in.
    fn park(telemetry: &'a dyn Telemetry, pool: &'a str) -> Self {
        telemetry.queued(pool, 1);
        Self { telemetry, pool }
    }
}

impl Drop for QueuedGuard<'_> {
    fn drop(&mut self) {
        self.telemetry.queued(self.pool, -1);
    }
}

/// The shed for `pool`: refuse, with the wait its `members` justify (the ones the unit's hooks
fn pool_shed(
    ports: &WalkPorts<'_>,
    pool: &str,
    members: &[Member],
    now: u64,
    token: &Pass<Route>,
) -> Shed {
    Shed::overloaded(retry_after_secs(ports.breaker, members, pool, now, token))
}

/// Exclude every member of `members` (the pool's ADMISSIBLE members) whose window is at or below
pub(crate) fn exclude_smaller_windows(members: &[Member], failed: &Member, ctx: &mut RequestCtx) {
    let Some(failed_limit) = failed.context_max else {
        return;
    };
    for member in members {
        if let Some(limit) = member.context_max {
            if limit <= failed_limit {
                ctx.exclude(member.destination);
            }
        }
    }
}

/// A reading's whole wall seconds: the scale every deadline of the walk is stated in.
fn secs(at: Reading) -> u64 {
    at.wall_ns / 1_000_000_000
}

/// A reading's monotonic milliseconds: the scale the walk's bounded wait is measured in.
fn millis(at: Reading) -> u128 {
    u128::from(at.mono_ns / 1_000_000)
}
