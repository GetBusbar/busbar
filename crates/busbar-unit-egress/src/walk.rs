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

use busbar_contract::{Ctx, Plane, Transport, Unit, VerifiedDestination};

use crate::attempt::{attempt, AttemptInput, AttemptOutcome, Hop};
use crate::exhaustion::handle_exhaustion_for_pool;
use crate::pool::{Member, PoolTable};
use crate::ports::{Breaker, Capacity, Clock, Disposition, EgressAuth, Journal, Telemetry};
use crate::select::{pick_among, PickInput, Preference, RequestCtx, WeightedFloor};
use crate::wire::{RouteOutcome, Shed};

/// Everything one route reads. Borrowed for the length of the walk and never mutated by it — the
/// mutable state of a request is the [`RequestCtx`], which is passed separately for exactly that
/// reason.
pub struct RouteRequest<'a> {
    /// The breaker unit.
    pub breaker: &'a dyn Breaker,
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
    /// The plane that says what the bytes mean.
    pub plane: &'a dyn Plane,
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
            },
            ctx,
        );
        let Some(pick) = pick else {
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

        let metric_pool = request.metric_pool(&pool.name, member);
        let outcome = attempt(AttemptInput {
            hop: Hop {
                breaker: request.breaker,
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
            probe_epoch: pick.probe_epoch,
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

/// Exclude every member whose window is at or below the one that just refused the request.
fn exclude_smaller_windows(members: &[Member], failed: &Member, ctx: &mut RequestCtx) {
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
