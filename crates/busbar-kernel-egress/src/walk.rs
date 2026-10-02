// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk over the verified set: the deadline, the pick, the one attempt, and what a failure
//! means for the next hop.
//!
//! This loop is deliberately thin. It owns four decisions and no others: whether there is still
//! time, which member is next, what a failed attempt does to the candidate set, and when the walk
//! is over. The sending is the attempt's, the ordering is the order's, the admission is the
//! breaker's, and what happens when there is nowhere left to send is the pool's own terminal.
//!
//! Three properties of it are load-bearing and each is one line below.
//!
//! The deadline is checked BEFORE every attempt, unconditionally, including a streaming one. It is
//! not a per-attempt timeout that a stream is excused from; it is the whole walk's budget, and a
//! request that has spent it is refused with the timeout words rather than being given one more
//! hop.
//!
//! The walk runs `max_hops` PLUS ONE attempts. The cap counts hops, and the first attempt is not a
//! hop — a pool that permits three hops attempts four members.
//!
//! Failover happens only before the first byte reaches the client. Once an attempt has relayed a
//! frame the answer belongs to that member: the walk returns it, and a later failure ends the
//! answer rather than starting another attempt.

use std::collections::HashMap;

use busbar_contract::caps::{Pass, Route};
use busbar_contract::{Ctx, Transport, Unit, VerifiedDestination};

use crate::attempt::{attempt, AttemptInput, AttemptOutcome, Hop, PlaneRef};
use crate::exhaustion::{handle_exhaustion_for_pool, least_bad, retry_after_secs};
use crate::pool::{Member, OnExhausted, Pool, PoolTable};
use crate::ports::{
    Breaker, Capacity, Clock, DestinationId, Disposition, EgressAuth, Journal, Permit, Telemetry,
    Unavailable,
};
use crate::race;
use crate::select::{pick_among, PickInput, Preference, RequestCtx, WeightedFloor};
use crate::wire::{RouteOutcome, Shed};

/// Everything one route reads. Borrowed for the length of the walk and never mutated by it — the
/// mutable state of a request is the [`RequestCtx`], which is passed separately for exactly that
/// reason.
pub struct RouteRequest<'a> {
    /// The breaker unit.
    pub breaker: &'a dyn Breaker,
    /// The capability token proving the loop is at the route step for this unit right now
    /// (`busbar-caps`'s `&Pass<Route>`): a unit may only act at the step its token names, and
    /// the token is the proof of that rather than a convention. Threaded down to
    /// every [`crate::ports::Breaker::observe`] call the walk and its terminals make.
    pub token: &'a Pass<Route>,
    /// The pool's permit store.
    pub capacity: &'a dyn Capacity,
    /// The write-ahead journal.
    pub journal: &'a dyn Journal,
    /// The egress-auth unit.
    pub egress_auth: &'a dyn EgressAuth,
    /// The node's clock.
    pub clock: &'a dyn Clock,
    /// The counters.
    pub telemetry: &'a dyn Telemetry,
    /// The transport that dials these destinations.
    pub transport: &'a dyn Transport,
    /// The plane that says what the bytes mean. A plane that keeps codec state per upstream is
    /// handed over in that shape, so each attempt opens its own half and the encode and every
    /// frame's decode share it.
    pub plane: PlaneRef<'a>,
    /// The transport's key material.
    pub keys: &'a busbar_contract::TransportKeyHandle,
    /// The verified set, indexed by the destination ids the pool's members carry.
    pub verified: &'a [VerifiedDestination],
    /// Every pool this node has, for the spill terminal.
    pub pools: &'a PoolTable,
    /// Which pool this route walks.
    pub pool: &'a str,
    /// The unit, as the plane reads it.
    pub unit: &'a Unit<'a>,
    /// The context the plane is called with.
    pub ctx: &'a Ctx<'a>,
    /// The session-affinity hash, where the request carries one.
    pub affinity: Option<u64>,
    /// A ranking hook's preference, where one was resolved before the walk.
    pub preference: Preference<'a>,
    /// Which leg of the route plan this is.
    pub leg: u8,
    /// Whether the client asked for an incremental answer.
    pub wants_stream: bool,
    /// The client-level ceiling that bounds a streamed answer.
    pub stream_ceiling_secs: u64,
    /// The envelope field the lane name is carried in.
    pub lane_field: Option<&'a str>,
    /// Which stream of the connection the request goes out on.
    pub stream: busbar_contract::StreamId,
    /// The weighted floor's memory, which belongs to the unit rather than to a request.
    pub floor: &'a WeightedFloor,
}

impl<'a> RouteRequest<'a> {
    /// The sealed destination for one member.
    pub(crate) fn destination(
        &self,
        id: crate::ports::DestinationId,
    ) -> Option<&'a VerifiedDestination> {
        self.verified.get(id.get() as usize)
    }

    /// The metric label for one hop. On a named pool it is the pool; on the default cell it is the
    /// member's own name, so the series lines up with the request counter, which labels routed
    /// traffic by member and not by the empty pool name.
    pub(crate) fn metric_pool(&'a self, pool: &'a str, member: &'a Member) -> &'a str {
        if pool.is_empty() {
            &member.name
        } else {
            pool
        }
    }
}

/// Walk one pool's verified set.
pub async fn walk(request: &RouteRequest<'_>, ctx: &mut RequestCtx) -> RouteOutcome {
    let Some(pool) = request.pools.get(request.pool) else {
        return RouteOutcome::Refused(Shed::empty_pool());
    };
    // The blocklist is applied once, here, before anything reads the membership — so a blocklisted
    // member is unreachable by the walk, by the least-bad terminal, and by the retry hint alike.
    let members = pool.admissible_members();
    let max_hops = pool.failover.max_hops;

    let mut last_disposition: Option<Disposition> = None;

    // `max_hops` hops after the first attempt: the range is inclusive, so a cap of three attempts
    // four members.
    for attempt_no in 0..=max_hops {
        let now = request.clock.now_secs();
        if ctx.expired(now) {
            return RouteOutcome::Refused(Shed::request_timeout());
        }

        let pick = pick_among(
            &PickInput {
                breaker: request.breaker,
                capacity: request.capacity,
                floor: request.floor,
                pool: &pool.name,
                members: &members,
                affinity: request.affinity,
                preference: request.preference,
                now,
                token: request.token,
            },
            ctx,
        );
        let Some(mut pick) = pick else {
            if members.is_empty() {
                return RouteOutcome::Refused(Shed::empty_pool());
            }
            // Nowhere to send this hop — whether the members were suppressed before this request
            // arrived or burned through by its own earlier hops. The pool's terminal decides what
            // the client is told, with the visited guard already in place.
            return handle_exhaustion_for_pool(request, ctx, pool, &members).await;
        };

        let Some(position) = members
            .iter()
            .position(|m| m.destination == pick.destination)
        else {
            return RouteOutcome::Refused(Shed::internal());
        };
        let member = &members[position];
        let Some(dest) = request.destination(pick.destination) else {
            return RouteOutcome::Refused(Shed::internal());
        };

        // Mark this member as tried before the attempt runs, so a failure never re-offers it.
        ctx.exclude(pick.destination);

        // Past the last resolution step that can shed: the probe now belongs to the attempt, which
        // records an outcome for it. Every shed above this line dropped the pick and gave it back.
        let probe_epoch = pick.take_probe_epoch();
        let metric_pool = request.metric_pool(&pool.name, member);
        let outcome = attempt(AttemptInput {
            hop: Hop {
                breaker: request.breaker,
                token: request.token,
                capacity: request.capacity,
                journal: request.journal,
                egress_auth: request.egress_auth,
                clock: request.clock,
                telemetry: request.telemetry,
                transport: request.transport,
                plane: request.plane,
                keys: request.keys,
                dest,
                destination: pick.destination,
                pool: &pool.name,
                metric_pool,
                leg: request.leg,
                attempt_no: u32::try_from(attempt_no.saturating_add(1)).unwrap_or(u32::MAX),
                attempt_timeout_ms: member.attempt_timeout_ms,
                wants_stream: request.wants_stream,
                remaining_secs: ctx.remaining_secs(request.clock.now_secs()),
                stream_ceiling_secs: request.stream_ceiling_secs,
                lane_field: request.lane_field,
                stream: request.stream,
                degraded: false,
            },
            permit: pick.permit,
            probe_epoch,
            unit: request.unit,
            ctx: request.ctx,
        })
        .await;

        match outcome {
            // A delivered answer — including a relayed client fault — ends the walk. This is the
            // before-first-byte boundary: the client has the answer, so there is no failing over.
            AttemptOutcome::Delivered(delivered) => return RouteOutcome::Delivered(delivered),
            AttemptOutcome::Bail(shed) => return RouteOutcome::Refused(shed),
            AttemptOutcome::Failed {
                disposition,
                err_type,
                ..
            } => {
                if matches!(disposition, Disposition::ContextLength) {
                    // The request is too large for THIS member's window, so every member that
                    // shares or undercuts the limit that just refused it would refuse it too.
                    // Exclude them, so the failover lands on a larger window or an unknown one. An
                    // unknown limit on the member that failed excludes only that member, which was
                    // already excluded above.
                    exclude_smaller_windows(&members, member, ctx);
                }
                request.telemetry.failover(metric_pool, err_type);
                last_disposition = Some(disposition);
                continue;
            }
        }
    }

    let _ = last_disposition;
    // Every hop the pool allows has been spent. Same terminal as finding nowhere to send: the pool
    // decides what the client is told.
    handle_exhaustion_for_pool(request, ctx, pool, &members).await
}

/// Everything the walk reads, borrowed for one step. Shared across every unit of the generation;
/// the mutable state of one unit is its [`Walk`].
pub struct WalkPorts<'p> {
    /// The breaker unit.
    pub breaker: &'p dyn Breaker,
    /// The pools' permit store.
    pub capacity: &'p dyn Capacity,
    /// The clock and its sleep.
    pub clock: &'p dyn Clock,
    /// The counters.
    pub telemetry: &'p dyn Telemetry,
    /// The weighted floor's rotation memory.
    pub floor: &'p WeightedFloor,
    /// The pools, by name.
    pub pools: &'p HashMap<String, Pool>,
}

/// The walk's whole budget over `pool`, seconds: the pool's request timeout, `0` for a pool that is
/// not configured.
#[must_use]
pub fn budget_secs(pools: &HashMap<String, Pool>, pool: &str) -> u64 {
    pools.get(pool).map_or(0, |p| p.failover.timeout_secs)
}

/// Where the walk is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The ordered walk over the unit's pool.
    Primary(String),
    /// The pool's members are spent: its terminal runs next.
    Terminal(String),
    /// A spill into this pool (degraded).
    Spill(String),
    /// Every path is spent: every later step answers this shed.
    Shed(Shed),
}

/// A member the walk took for the next attempt. It is excluded from every later pick of the unit,
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
    /// The dispatch record's attempt number: the hops the walk had taken when it took this member.
    pub attempt: u32,
}

/// The pool's bounded wait, answered by [`Walk::next`] for the caller to run outside its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wait {
    pool: String,
    max_ms: u64,
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
/// started.
pub struct Parked<'p> {
    /// The pool's name, as the walk keys it.
    name: String,
    pool: &'p Pool,
    waiting: Vec<DestinationId>,
    bound_ms: u64,
    started: u128,
}

/// What a wait came back with: the member that freed a slot, its permit and the probe its breaker
/// handed over, or nothing.
pub struct Waited<'p> {
    name: String,
    pool: &'p Pool,
    won: Option<(Member, Permit, Option<u64>)>,
}

/// ONE UNIT'S WALK: its request context (deadline, every member tried, every pool visited), where
/// it is, and how many hops it has taken.
#[derive(Debug)]
pub struct Walk {
    ctx: RequestCtx,
    phase: Phase,
    hops: usize,
}

impl Walk {
    /// A walk over `pool` starting now: its budget is the pool's request timeout.
    #[must_use]
    pub fn start(ports: &WalkPorts<'_>, pool: &str) -> Self {
        Self {
            ctx: RequestCtx::new(
                budget_secs(ports.pools, pool),
                ports.clock.now_secs(),
                ports.clock.now_millis(),
            ),
            phase: Phase::Primary(pool.to_string()),
            hops: 0,
        }
    }

    /// The request context: the deadline and everything the walk has excluded.
    #[must_use]
    pub fn ctx(&self) -> &RequestCtx {
        &self.ctx
    }

    /// A refusal for size from `failed` of `pool`: every ADMISSIBLE member whose window is at or
    /// below the one that refused would refuse too, so the walk excludes them.
    pub fn refused_for_size(&mut self, ports: &WalkPorts<'_>, pool: &str, failed: &Member) {
        if let Some(pool) = ports.pools.get(pool) {
            exclude_smaller_windows(&pool.admissible_members(), failed, &mut self.ctx);
        }
    }

    /// THE WALK'S NEXT STEP: a member, the pool's terminal's refusal, or its bounded wait.
    pub fn next(
        &mut self,
        ports: &WalkPorts<'_>,
        affinity: Option<u64>,
        token: &Pass<Route>,
    ) -> Step {
        loop {
            if self.ctx.expired(ports.clock.now_secs()) {
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
                    if self.hops <= pool.failover.max_hops {
                        if let Some(taken) = self.pick(ports, pool, affinity, token, true) {
                            self.hops += 1;
                            return Step::Take(taken);
                        }
                    }
                    self.phase = Phase::Terminal(name);
                }
                Phase::Spill(name) => {
                    let Some(pool) = ports.pools.get(&name) else {
                        return Step::Shed(pool_shed(ports, &name, token));
                    };
                    if let Some(taken) = self.pick(ports, pool, None, token, false) {
                        return Step::Take(taken);
                    }
                    self.phase = Phase::Terminal(name);
                }
                Phase::Terminal(name) => {
                    self.ctx.mark_pool_visited(&name);
                    let Some(pool) = ports.pools.get(&name) else {
                        return Step::Shed(pool_shed(ports, &name, token));
                    };
                    match &pool.on_exhausted {
                        OnExhausted::Status503 => {
                            return Step::Shed(pool_shed(ports, &name, token))
                        }
                        OnExhausted::FallbackPool(target) => {
                            if self.ctx.is_pool_visited(target) || !ports.pools.contains_key(target)
                            {
                                // The loop guard, or a target never configured: the shed with the
                                // empty-set floor.
                                let secs = retry_after_secs(
                                    ports.breaker,
                                    &[],
                                    target,
                                    ports.clock.now_secs(),
                                    token,
                                );
                                return Step::Shed(Shed::overloaded(secs));
                            }
                            self.ctx.mark_pool_visited(target);
                            self.phase = Phase::Spill(target.clone());
                        }
                        OnExhausted::LeastBad => {
                            // A least-bad dispatch that brings no answer is the shed.
                            let shed = pool_shed(ports, &name, token);
                            self.phase = Phase::Shed(shed.clone());
                            return match least_bad(ports, pool, token) {
                                Some((member, permit)) => {
                                    Step::Take(self.take(&pool.name, member, permit, None, true))
                                }
                                None => Step::Shed(shed),
                            };
                        }
                        OnExhausted::Queue { max_ms } => {
                            return Step::Wait(Wait {
                                pool: name,
                                max_ms: *max_ms,
                            })
                        }
                    }
                }
            }
        }
    }

    /// THE ONE PICK, over `pool`'s members this unit has not tried: the walk's own pool
    /// (`primary`, with the unit's affinity) and every pool it spills into (degraded).
    fn pick(
        &mut self,
        ports: &WalkPorts<'_>,
        pool: &Pool,
        affinity: Option<u64>,
        token: &Pass<Route>,
        primary: bool,
    ) -> Option<Taken> {
        let members = pool.admissible_members();
        let now = ports.clock.now_secs();
        let mut picked = pick_among(
            &PickInput {
                breaker: ports.breaker,
                capacity: ports.capacity,
                floor: ports.floor,
                pool: &pool.name,
                members: &members,
                affinity,
                preference: None,
                now,
                token,
            },
            &mut self.ctx,
        )?;
        let member = members
            .iter()
            .find(|m| m.destination == picked.destination)?
            .clone();
        let probe = picked.take_probe_epoch();
        Some(self.take(&pool.name, member, picked.permit, probe, !primary))
    }

    /// Take `member` of `pool` for the next attempt: excluded from every later pick of the unit.
    fn take(
        &mut self,
        pool: &str,
        member: Member,
        permit: Permit,
        probe: Option<u64>,
        degraded: bool,
    ) -> Taken {
        self.ctx.exclude(member.destination);
        Taken {
            pool: pool.to_string(),
            member,
            permit,
            probe,
            degraded,
            attempt: u32::try_from(self.hops).unwrap_or(u32::MAX),
        }
    }

    /// Park the queue terminal's wait: the members the last pick passed over AT CAPACITY (a held
    /// slot can drop; nothing else waiting can cure), and the bound, the lesser of the pool's
    /// setting and what the walk has left. `Err` is the shed, for a pool that is not configured.
    ///
    /// # Errors
    /// The shed for a wait over a pool the walk does not have.
    pub fn park<'p>(
        &self,
        ports: &WalkPorts<'p>,
        wait: &Wait,
        token: &Pass<Route>,
    ) -> Result<Parked<'p>, Shed> {
        let Some(pool) = ports.pools.get(&wait.pool) else {
            return Err(pool_shed(ports, &wait.pool, token));
        };
        let mut waiting: Vec<DestinationId> = Vec::new();
        for (destination, reason) in self.ctx.excluded_reasons() {
            if matches!(reason, Unavailable::AtCapacity { .. }) && !waiting.contains(destination) {
                waiting.push(*destination);
            }
        }
        let started = ports.clock.now_millis();
        Ok(Parked {
            name: wait.pool.clone(),
            pool,
            waiting,
            bound_ms: wait.max_ms.min(self.ctx.remaining_ms(started)),
            started,
        })
    }

    /// The wait is over: a member it won is taken (degraded), and from here every later step
    /// answers the pool's shed. `Err` is that shed, when the wait won nothing.
    ///
    /// # Errors
    /// The pool's shed, when no slot freed within the bound.
    pub fn waited(
        &mut self,
        ports: &WalkPorts<'_>,
        waited: Waited<'_>,
        token: &Pass<Route>,
    ) -> Result<Taken, Shed> {
        let taken = waited.won.map(|(member, permit, probe)| {
            self.take(&waited.pool.name, member, permit, probe, true)
        });
        let shed = pool_shed(ports, &waited.name, token);
        self.phase = Phase::Shed(shed.clone());
        taken.ok_or(shed)
    }
}

impl<'p> Parked<'p> {
    /// THE BOUNDED WAIT for a slot on a member passed over AT CAPACITY, then the breaker re-asked
    /// on the member that freed one; nothing when no slot frees within the bound. The depth gauge
    /// counts the waiter in for the length of the wait.
    pub async fn wait(mut self, ports: &WalkPorts<'_>) -> Waited<'p> {
        let pool = self.pool;
        let members = pool.admissible_members();
        ports.telemetry.queued(&pool.name, 1);
        let won = loop {
            if self.waiting.is_empty() {
                break None;
            }
            let spent = ports.clock.now_millis().saturating_sub(self.started);
            let left = self
                .bound_ms
                .saturating_sub(u64::try_from(spent).unwrap_or(u64::MAX));
            let raced = race::deadline_first(
                ports.capacity.acquire_any(&self.waiting),
                ports.clock.sleep(left),
            )
            .await;
            let Ok(Some((destination, permit))) = raced else {
                break None;
            };
            match ports
                .breaker
                .try_admit(&pool.name, destination, ports.clock.now_secs())
            {
                Ok(admit) => {
                    let Some(member) = members.iter().find(|m| m.destination == destination) else {
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
        ports.telemetry.queued(&pool.name, -1);
        Waited {
            name: self.name,
            pool,
            won,
        }
    }
}

/// The shed for `pool`: refuse, with the wait its own members justify.
fn pool_shed(ports: &WalkPorts<'_>, pool: &str, token: &Pass<Route>) -> Shed {
    let members = ports
        .pools
        .get(pool)
        .map(|p| p.admissible_members().into_owned())
        .unwrap_or_default();
    Shed::overloaded(retry_after_secs(
        ports.breaker,
        &members,
        pool,
        ports.clock.now_secs(),
        token,
    ))
}

/// Exclude every member of `members` (the pool's ADMISSIBLE members) whose window is at or below
/// the one that just refused the request. The walk and the plane driver's far end both exclude
/// here.
pub fn exclude_smaller_windows(members: &[Member], failed: &Member, ctx: &mut RequestCtx) {
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
