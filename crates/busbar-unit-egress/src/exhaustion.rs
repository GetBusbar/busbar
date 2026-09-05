// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pool does AFTER the walk finds nowhere to send.
//!
//! Nothing in this module is a second selection loop and nothing here decides who is healthy. The
//! spill re-enters the same pick against another pool; the wait parks for a bounded time and then
//! re-asks the same admission every path asks; the last-resort route is the ONE documented breaker
//! bypass in the unit and it says so by owning no probe; and the shed is a refusal with an honest
//! wait computed from the pool's own members. Every one of the four dispatches through the same
//! attempt the walk runs, and each maps its result the degraded way: an upstream's own answer is
//! relayed to the client as it came, and only an attempt that produced no answer at all moves on
//! to the next member.

use crate::attempt::{attempt, AttemptInput, AttemptOutcome, Hop};
use crate::pool::{Member, OnExhausted, Pool};
use crate::ports::{Breaker, DestinationId, Permit, Unavailable};
use crate::race;
use crate::select::{pick_among, PickInput, RequestCtx};
use crate::walk::RouteRequest;
use crate::wire::{RouteOutcome, Shed};

/// The wait a shed advertises when nothing else justifies a longer one, in whole seconds.
///
/// A busy concurrency slot has no scheduled recovery the way a cooldown does, so there is no
/// window to quote. Advertising the bare one-second floor reads to a rate-aware client as "retry
/// immediately", which just collides with the same saturation again; a small non-trivial floor
/// asks it to back off briefly instead. Saturation is the COMMON shed, so this must not be one.
pub const AT_CAPACITY_RETRY_AFTER_SECS: u64 = 2;

/// The wait a shed advertises, reflecting the actual reason the pool had nowhere to send.
///
/// Exhaustion has two causes and they want different backoff, so they are separated here.
///
/// If any usable member has a GENUINE cooldown still to run, advertise the soonest of them: the
/// client should come back when a benched member is due to be probed again. A member that is
/// merely at capacity reports no cooldown, and its zero is ignored here rather than being taken as
/// the minimum — which is what used to let one busy member mask a sibling in a long cooldown.
///
/// Otherwise advertise the floor above. That covers saturation, and it also covers the case where
/// there are no members to read at all — a spill that looped back on itself, or one aimed at a
/// pool that was never configured. An empty candidate set is exactly where least is known about
/// when a slot frees, so it gets the honest floor and never the deceptive bare one.
///
/// Always at least one second, because a zero-second wait means nothing.
pub fn retry_after_secs(breaker: &dyn Breaker, members: &[Member], pool: &str, now: u64) -> u64 {
    members
        .iter()
        // A member that is dead or out of lifetime budget sits outside the cooldown machinery
        // entirely and reports zero, so filter to the usable ones exactly as the shed always did.
        .filter(|m| breaker.admissible(m.destination))
        .map(|m| breaker.cooldown_remaining(pool, m.destination, now))
        .filter(|remaining| *remaining > 0)
        .min()
        .unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS)
        .max(1)
}

/// The shed: refuse, with the wait the pool's own members justify.
pub fn handle_status_503(
    breaker: &dyn Breaker,
    members: &[Member],
    pool: &str,
    now: u64,
) -> RouteOutcome {
    RouteOutcome::Refused(Shed::overloaded(retry_after_secs(
        breaker, members, pool, now,
    )))
}

/// Run this pool's terminal.
///
/// The visited mark is taken HERE, before the terminal is even looked up, because this is the one
/// point every pool's exhaustion flows through. Marking it inside the spill would only mark the
/// pool being spilled INTO, so a chain that came back round to its origin would not be recognised
/// on the second hop and would walk the origin's members a second time before terminating.
pub async fn handle_exhaustion_for_pool<'a>(
    request: &RouteRequest<'a>,
    ctx: &mut RequestCtx,
    pool: &Pool,
    members: &[Member],
) -> RouteOutcome {
    ctx.mark_pool_visited(&pool.name);
    let now = request.clock.now_secs();
    match &pool.on_exhausted {
        OnExhausted::Status503 => handle_status_503(request.breaker, members, &pool.name, now),
        OnExhausted::FallbackPool(target) => {
            Box::pin(handle_fallback_pool(request, ctx, target)).await
        }
        OnExhausted::LeastBad => handle_least_bad(request, ctx, pool, members).await,
        OnExhausted::Queue { max_ms } => handle_queue(request, ctx, pool, members, *max_ms).await,
    }
}

/// One degraded dispatch: the same attempt the walk runs, in the degraded posture, mapped the
/// degraded way.
///
/// `Ok` is an answer for the client — a delivered body, a relayed upstream refusal, or a bail
/// before anything was sent. `Err` means the upstream produced no answer at all, which is the only
/// case in which a degraded caller may try another member.
#[allow(clippy::too_many_arguments)]
async fn dispatch_degraded<'a>(
    request: &RouteRequest<'a>,
    ctx: &RequestCtx,
    pool: &Pool,
    member: &Member,
    permit: Permit,
    probe_epoch: Option<u64>,
) -> Result<RouteOutcome, ()> {
    let Some(dest) = request.destination(member.destination) else {
        return Ok(RouteOutcome::Refused(Shed::internal()));
    };
    let now = request.clock.now_secs();
    let metric_pool = if pool.name.is_empty() {
        member.name.as_str()
    } else {
        pool.name.as_str()
    };
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
            destination: member.destination,
            pool: &pool.name,
            metric_pool,
            leg: request.leg,
            attempt_no: u32::MAX,
            attempt_timeout_ms: member.attempt_timeout_ms,
            wants_stream: request.wants_stream,
            remaining_secs: ctx.remaining_secs(now),
            stream_ceiling_secs: request.stream_ceiling_secs,
            lane_field: request.lane_field,
            stream: request.stream,
            degraded: true,
        },
        permit,
        probe_epoch,
        unit: request.unit,
        ctx: request.ctx,
    })
    .await;
    match outcome {
        AttemptOutcome::Delivered(delivered) => Ok(RouteOutcome::Delivered(delivered)),
        AttemptOutcome::Bail(shed) => Ok(RouteOutcome::Refused(shed)),
        // The upstream answered and the breaker was told: relay that answer as it came.
        AttemptOutcome::Failed {
            relay: Some(delivered),
            ..
        } => Ok(RouteOutcome::Delivered(delivered)),
        // Nothing came back at all: the caller may try the next member, so this is a failover.
        AttemptOutcome::Failed {
            relay: None,
            err_type,
            ..
        } => {
            request.telemetry.failover(metric_pool, err_type);
            Err(())
        }
    }
}

// ── the spill ───────────────────────────────────────────────────────────────────────────────────

/// Send the request to another pool's healthy member, with multi-level chains and a loop guard.
///
/// A spill target is an independent pool, and everything that follows from that is here: it
/// re-applies its OWN blocklist, because the primary pool's says nothing about it; when it is
/// itself exhausted it consults its OWN terminal, which is what makes a chain work; and a chain
/// that comes back round to a pool this request has already been through terminates with the shed
/// rather than recursing.
async fn handle_fallback_pool<'a>(
    request: &RouteRequest<'a>,
    ctx: &mut RequestCtx,
    target: &str,
) -> RouteOutcome {
    // The deadline travels across hops. A spill is not a fresh request.
    if ctx.expired(request.clock.now_secs()) {
        return RouteOutcome::Refused(Shed::request_timeout());
    }

    // The loop guard: if this request already routed through this pool, stop.
    if ctx.is_pool_visited(target) {
        return handle_status_503(request.breaker, &[], target, request.clock.now_secs());
    }

    let Some(pool) = request.pools.get(target) else {
        // The target is not configured: the shed, with the empty-set floor.
        return handle_status_503(request.breaker, &[], target, request.clock.now_secs());
    };
    let members = pool.admissible_members();

    // Mark before re-entering, so a chain that comes back here is recognised.
    ctx.mark_pool_visited(target);

    loop {
        let now = request.clock.now_secs();
        if ctx.expired(now) {
            return RouteOutcome::Refused(Shed::request_timeout());
        }

        // The spill selects with the plain weighted floor by design: a ranking hook applies to the
        // PRIMARY pool, where it shapes the normal choice. A spill is already the degraded
        // overflow path, so it is not re-ranked over the members it spilled into.
        let pick = pick_among(
            &PickInput {
                breaker: request.breaker,
                capacity: request.capacity,
                floor: request.floor,
                pool: &pool.name,
                members: &members,
                affinity: None,
                preference: None,
                now,
            },
            ctx,
        );
        let Some(pick) = pick else {
            // The spill target is itself exhausted: consult ITS terminal. The visited set is what
            // guarantees this recursion ends.
            return Box::pin(handle_exhaustion_for_pool(request, ctx, pool, &members)).await;
        };
        let Some(member) = members.iter().find(|m| m.destination == pick.destination) else {
            return RouteOutcome::Refused(Shed::internal());
        };
        ctx.exclude(pick.destination);

        match dispatch_degraded(request, ctx, pool, member, pick.permit, pick.probe_epoch).await {
            Ok(outcome) => return outcome,
            // No answer at all: try the next member of this pool.
            Err(()) => continue,
        }
    }
}

// ── the last resort ─────────────────────────────────────────────────────────────────────────────

/// Send to the member with the soonest cooldown even though it is suppressed.
///
/// This is the ONE documented breaker bypass in the unit, and two details of it matter.
///
/// It ranks by soonest cooldown and then takes the first member with a FREE slot, rather than
/// insisting on the single best one. The soonest member may itself be at capacity, and refusing
/// outright because the best member is momentarily busy — while a slightly worse sibling is idle —
/// defeats the whole point of a last resort. Members that are dead or out of budget are filtered
/// first, so their zero cooldown never sorts them to the front.
///
/// It owns NO probe and passes none, so no guard is built at all. Handing it the cell's current
/// epoch instead would be actively unsafe: if the cell is half-open because a peer legitimately
/// won the probe, that epoch is the PEER's, and an owner-checked release keyed on it would revert
/// the peer's live probe.
async fn handle_least_bad<'a>(
    request: &RouteRequest<'a>,
    ctx: &RequestCtx,
    pool: &Pool,
    members: &[Member],
) -> RouteOutcome {
    let now = request.clock.now_secs();
    let mut ranked: Vec<&Member> = members
        .iter()
        .filter(|m| request.breaker.admissible(m.destination))
        .collect();
    ranked.sort_by_key(|m| {
        request
            .breaker
            .cooldown_remaining(&pool.name, m.destination, now)
    });

    let mut dispatch: Option<(&Member, Permit)> = None;
    for member in ranked {
        if let Some(permit) = request.capacity.try_acquire(member.destination) {
            dispatch = Some((member, permit));
            break;
        }
    }
    let Some((member, permit)) = dispatch else {
        // Nothing usable at all, or every usable member is at capacity: no degraded dispatch is
        // possible, so shed.
        return handle_status_503(request.breaker, members, &pool.name, now);
    };

    match dispatch_degraded(request, ctx, pool, member, permit, None).await {
        Ok(outcome) => outcome,
        Err(()) => handle_status_503(
            request.breaker,
            members,
            &pool.name,
            request.clock.now_secs(),
        ),
    }
}

// ── the wait ────────────────────────────────────────────────────────────────────────────────────

/// Wait a bounded time for a slot to free, dispatch on the member that freed one, else shed.
///
/// It lives here, in the terminal, and never inside the pick — selection stays non-blocking, so
/// "no unbounded await in the pick path" is a structural fact rather than a rule to remember.
///
/// Waiting only helps if some member was passed over because it was AT CAPACITY: a held slot can
/// drop. If every exclusion was dead, out of budget, suppressed or a lost probe race, nothing will
/// free a slot and waiting is pointless, so the shed comes now.
///
/// Winning a slot proves capacity, not admission. The winner's breaker is re-asked — it may have
/// tripped while the request was parked — and only then is anything dispatched. A member whose
/// cell opened while queued can never be served by waiting longer, so it is dropped from the wait
/// set and the wait continues on the rest against the SAME deadline, which is why a re-entry can
/// never extend the budget.
async fn handle_queue<'a>(
    request: &RouteRequest<'a>,
    ctx: &mut RequestCtx,
    pool: &Pool,
    members: &[Member],
    max_ms: u64,
) -> RouteOutcome {
    // Dedup by member: the affinity fast path may have recorded a member the rest of the pick
    // recorded again, which is deliberate and documented in the order.
    let mut waiting: Vec<DestinationId> = Vec::new();
    for (destination, reason) in ctx.excluded_reasons() {
        if matches!(reason, Unavailable::AtCapacity { .. }) && !waiting.contains(destination) {
            waiting.push(*destination);
        }
    }
    if waiting.is_empty() {
        return handle_status_503(
            request.breaker,
            members,
            &pool.name,
            request.clock.now_secs(),
        );
    }

    // The bound is the lesser of what the operator allowed and what the walk has left, in
    // milliseconds so a sub-second bound is representable and a budget near a second boundary does
    // not collapse to zero. It is captured ONCE, as an absolute point, so a re-entry after a
    // won-but-suppressed slot waits against the same bound.
    let started = request.clock.now_millis();
    let bound_ms = max_ms.min(ctx.remaining_ms(started));

    request.telemetry.queued(&pool.name, 1);
    let outcome = queue_wait(request, ctx, pool, members, &mut waiting, started, bound_ms).await;
    request.telemetry.queued(&pool.name, -1);
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn queue_wait<'a>(
    request: &RouteRequest<'a>,
    ctx: &RequestCtx,
    pool: &Pool,
    members: &[Member],
    waiting: &mut Vec<DestinationId>,
    started: u128,
    bound_ms: u64,
) -> RouteOutcome {
    loop {
        if waiting.is_empty() {
            return handle_status_503(
                request.breaker,
                members,
                &pool.name,
                request.clock.now_secs(),
            );
        }
        let spent = request.clock.now_millis().saturating_sub(started);
        let left = bound_ms.saturating_sub(u64::try_from(spent).unwrap_or(u64::MAX));

        // The deadline is polled FIRST: if the bound has passed the request sheds even when a slot
        // becomes free in the same instant. Never block past the budget.
        let won = race::deadline_first(
            request.capacity.acquire_any(waiting),
            request.clock.sleep(left),
        )
        .await;

        let (destination, permit) = match won {
            Ok(Some(pair)) => pair,
            // The bound passed, or every queue is closed: shed with the same honest wait the
            // immediate shed would have used.
            Ok(None) | Err(race::Elapsed) => {
                return handle_status_503(
                    request.breaker,
                    members,
                    &pool.name,
                    request.clock.now_secs(),
                )
            }
        };

        // Capacity is held but the breaker has not been passed. Ask it — and only it — on the
        // member that freed a slot. A probe won here is owned by the dispatch, exactly as on every
        // other path.
        let now = request.clock.now_secs();
        match request.breaker.try_admit(&pool.name, destination, now) {
            Ok(admit) => {
                let Some(member) = members.iter().find(|m| m.destination == destination) else {
                    drop(permit);
                    return RouteOutcome::Refused(Shed::internal());
                };
                return match dispatch_degraded(
                    request,
                    ctx,
                    pool,
                    member,
                    permit,
                    admit.probe_epoch,
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(()) => handle_status_503(
                        request.breaker,
                        members,
                        &pool.name,
                        request.clock.now_secs(),
                    ),
                };
            }
            Err(_) => {
                // The member's cell opened, or it lost a probe race, while the request was parked.
                // Give the slot back — never hold one on a member nothing will be sent to — and
                // drop it from the wait set: waiting cannot make a suppressed member serveable,
                // and dropping it also stops a tight re-acquire spin on the slot just released.
                drop(permit);
                waiting.retain(|d| *d != destination);
                continue;
            }
        }
    }
}
