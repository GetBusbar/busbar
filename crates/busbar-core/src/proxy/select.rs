use super::*;

/// Slack ε for the [`RequestCtx::debug_assert_within_budget`] failover-budget guard. Generous
/// on purpose: the guard is a regression tripwire for a path that blocks PAST the whole failover
/// budget (seconds), so a multi-second ε cannot mask that class of bug while it does absorb scheduler
/// jitter / a slow CI box. The meaningful, tight bound lives in the property + budget TESTS.
const BUDGET_ASSERT_EPSILON: std::time::Duration = std::time::Duration::from_secs(5);

/// A compliance restrict captured on the PRIMARY pool that must persist across every failover hop —
/// including a `fallback_pool` spill to an independent pool. `tags_any` is the eligible tag set,
/// `on_empty` decides what happens when a hop's candidates carry none of them (fail-closed reject vs
/// advisory weighted-escape), and `name` is the gate name for logs/metrics.
#[derive(Debug, Clone)]
pub(crate) struct RestrictConstraint {
    pub(crate) tags_any: Vec<String>,
    pub(crate) on_empty: crate::config::PolicyOnError,
    pub(crate) name: &'static str,
}

/// Context for request lifecycle: deadline, accumulated exclusions, and visited pools.
#[derive(Debug, Clone)]
pub(crate) struct RequestCtx {
    /// Computed once at start; each hop checks remaining time against this.
    deadline: u64,
    /// The SAME failover deadline as `deadline`, captured as a monotonic wall-clock instant so the
    /// `on_exhausted: queue` bound has MILLISECOND precision. `deadline`/`remaining()` are whole
    /// EPOCH SECONDS — a 250ms `max_ms` is unrepresentable there and a near-second-boundary
    /// `remaining()` collapses to 0 — so the queue wait budgets against `remaining_ms()` instead.
    deadline_wall: std::time::Instant,
    /// Accumulated excluded lane indices across hops (already tried).
    pub(crate) excluded: std::collections::HashSet<usize>,
    /// Visited pool names for loop prevention in fallback chains (e.g., A→B→A).
    visited_pools: std::collections::HashSet<String>,
    /// Compliance restricts in force for this request (captured at the primary pool's gate
    /// reconcile). Re-applied on every downstream hop so a `Restrict` gate's "only these lanes,
    /// ever" guarantee holds across a `fallback_pool` spill — see [`RequestCtx::enforce_restricts`].
    pub(crate) active_restricts: Vec<RestrictConstraint>,
    /// Why each lane was excluded on the MOST RECENT `pick_among` attempt, in the shared
    /// [`Unavailable`] taxonomy — recorded by the single exclusion arm (and the sticky fast path) so
    /// `on_exhausted` dispatch can see the REAL reasons a pool exhausted (queue pre-check, honest
    /// `Retry-After`). Advisory/observational: it never influences selection (that is the separate
    /// `local_excluded` set inside `pick_among`), so writing it does not violate the within-pick
    /// "don't mutate the caller's exclusion set" rule. Cleared at the start of every `pick_among` call
    /// so it reflects that hop's exhaustion, not a stale earlier one.
    //
    // Consumed by the queue/least_bad/Retry-After wiring in a later phase; populated and asserted by
    // the taxonomy/refactor unit tests now — silence the release-build dead-code lint meanwhile.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) excluded_reasons: Vec<(usize, crate::store::Unavailable)>,
    /// This request's correlation id — a single `u64` `fetch_add`'d off [`App::next_request_id`]
    /// ONCE at ingress (see `forward_with_pool_parsed`), Copy-threaded everywhere `RequestCtx`
    /// already flows for the lifetime of the request (including every failover hop — it is NOT
    /// re-stamped per hop). Exists so a routing DECISION (the hook seam's `RoutingRequest`) can be
    /// joined to its OUTCOME (the completion-tap notification) and so a per-request tracing span /
    /// log line is correlatable, WITHOUT a UUID/String allocation on the hot path: generation is one
    /// relaxed atomic increment, carried as a plain `Copy` scalar, and serialized only where a hook
    /// JSON payload or `tracing`'s native u64 field already pay a cost (never a new allocation on
    /// the default path). Deliberately internal-only — never surfaced as a response header (busbar
    /// stays invisible-by-default).
    pub(crate) request_id: u64,
}

impl RequestCtx {
    pub(crate) fn new(deadline_secs: u64, request_id: u64) -> Self {
        let start = now();
        Self {
            deadline: start.saturating_add(deadline_secs),
            // Overflow-safe: `Instant`'s `Add` impl PANICS on overflow (it `.expect()`s internally, in
            // release too). `deadline_secs` is operator-controlled (`failover.timeout_secs`), so a huge
            // value would panic the serving task on every request. `checked_add` + a defensive fallback
            // keeps the data plane crash-free even if config_validate's upper bound is ever bypassed; the
            // sibling `deadline` above is already saturating for the same reason.
            //
            // The fallback is UNREACHABLE in practice — `config_validate` caps `failover.timeout_secs` at
            // `MAX_FAILOVER_DEADLINE_SECS` (86_400s), far below the `Instant` overflow point — so it is a
            // pure defensive floor. It is set to the SAME cap (not a smaller stopgap like 3600s) so that
            // if a huge value ever DID reach here, the fallback never SHORTENS the real budget below what
            // a valid config could legitimately request.
            deadline_wall: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(deadline_secs))
                .unwrap_or_else(|| {
                    std::time::Instant::now()
                        + std::time::Duration::from_secs(crate::config::MAX_FAILOVER_DEADLINE_SECS)
                }),
            excluded: std::collections::HashSet::new(),
            visited_pools: std::collections::HashSet::new(),
            active_restricts: Vec::new(),
            excluded_reasons: Vec::new(),
            request_id,
        }
    }

    /// Re-apply the captured compliance restricts against a DOWNSTREAM pool's candidate set, keyed by
    /// THAT pool's own member tags (lane `idx` are global; `pool_runtime.members` is idx-keyed). The
    /// primary-pool gate reconcile shrinks `cands` in place, which keeps the restriction across
    /// in-pool failover — but a `fallback_pool` hop rebuilds candidates from an INDEPENDENT pool's
    /// full membership, so without re-applying here a compliance (e.g. BAA-only) restrict would be
    /// silently dropped at the pool boundary. Mirrors Reconcile-2 exactly: a `Weighted` on_empty is an
    /// advisory escape (skip this restrict on this hop); the fail-closed default returns `Err(name)`
    /// so the caller REJECTS rather than spilling to an ineligible lane.
    pub(crate) fn enforce_restricts(
        &self,
        app: &App,
        pool_name: &str,
        cands: Vec<WeightedLane>,
    ) -> Result<Vec<WeightedLane>, &'static str> {
        let mut cands = cands;
        for r in &self.active_restricts {
            let members = app.pool_runtime.get(pool_name).map(|rt| &rt.members);
            let restricted: Vec<WeightedLane> = cands
                .iter()
                .filter(|wl| {
                    members.and_then(|m| m.get(&wl.idx)).is_some_and(|meta| {
                        meta.tags.iter().any(|t| r.tags_any.iter().any(|w| w == t))
                    })
                })
                .cloned()
                .collect();
            if restricted.is_empty() {
                if matches!(r.on_empty, crate::config::PolicyOnError::Weighted) {
                    continue; // advisory escape — skip this restrict on this hop
                }
                return Err(r.name); // fail closed — no eligible lane satisfies a required restrict
            }
            cands = restricted;
        }
        Ok(cands)
    }

    /// Check if deadline has been exceeded.
    pub(crate) fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }

    /// Remaining time until deadline in seconds.
    pub(crate) fn remaining(&self, now: u64) -> u64 {
        self.deadline.saturating_sub(now)
    }

    /// Remaining failover budget in MILLISECONDS until the deadline. Used by the `on_exhausted:
    /// queue` wait so a sub-second `max_ms` is representable and a near-second-boundary budget does not
    /// collapse to 0 the way `remaining(now) * 1000` would. Saturates to 0 once the deadline passes.
    pub(crate) fn remaining_ms(&self) -> u64 {
        self.deadline_wall
            .saturating_duration_since(std::time::Instant::now())
            .as_millis() as u64
    }

    /// The budget contract, as an asserted invariant. `deadline_wall` is captured at ingress as
    /// `ingress + failover.timeout`, so requiring the wall clock at THIS disposition to be within
    /// `deadline_wall` plus ε is exactly "wall-clock ingress→disposition ≤ failover.timeout + ε". A
    /// `debug_assert!` so it runs in dev/CI (test + debug builds) and is compiled out of the release
    /// request path — it exists to CATCH a selection / queue path that regresses to blocking past the
    /// failover budget (a park under saturation), never to change production behaviour. ε is
    /// deliberately generous ([`BUDGET_ASSERT_EPSILON`]) so the guard never false-fires on scheduler
    /// jitter or a slow CI box; the property/budget TESTS assert a tighter, meaningful bound.
    pub(crate) fn debug_assert_within_budget(&self, context: &str) {
        debug_assert!(
            std::time::Instant::now() <= self.deadline_wall + BUDGET_ASSERT_EPSILON,
            "failover budget exceeded at `{context}`: disposition landed more than {}ms past the \
             failover deadline — a selection/queue path blocked past the budget",
            BUDGET_ASSERT_EPSILON.as_millis(),
        );
    }

    /// Add a lane to the exclusion set (mark as already tried).
    pub(crate) fn exclude(&mut self, idx: usize) {
        self.excluded.insert(idx);
    }

    /// Fill `out` with candidates minus exclusions (clears `out` first).
    pub(crate) fn fill_candidates<'a>(
        &self,
        cands: &'a [WeightedLane],
        out: &mut Vec<&'a WeightedLane>,
    ) {
        out.clear();
        out.extend(cands.iter().filter(|wl| !self.excluded.contains(&wl.idx)));
    }

    /// Mark a pool as visited for loop prevention.
    pub(crate) fn mark_pool_visited(&mut self, pool_name: &str) {
        self.visited_pools.insert(pool_name.to_string());
    }

    /// Check if a pool has already been visited (loop detection).
    pub(crate) fn is_pool_visited(&self, pool_name: &str) -> bool {
        self.visited_pools.contains(pool_name)
    }
}

/// RAII release for a WON single-flight recovery probe, covering an async DISPATCH window.
///
/// Once a probe is won the cell is HalfOpen + `probe_in_flight == true`; the flag is normally cleared
/// only when a request records an outcome. If the future holding the probe is DROPPED mid-dispatch
/// (client disconnect while the upstream call is in flight) no early-return cleanup runs, so without a
/// Drop guard the cell stays HalfOpen + probe_in_flight and the lane is benched until the slow
/// out-of-band prober resets it.
///
/// `Drop` calls the owner-checked `release_probe_owned_in` (CAS HalfOpen→Open + clear flag) while
/// `armed`. A path that hands the probe to a dispatched request that will record its own outcome
/// DISARMS the guard (sets `armed = false`) first, because that request now owns the probe.
///
/// Where it is used: the on_exhausted degraded dispatch, `engine::walk::forward_once`, constructs one
/// covering its whole dispatch window — but ONLY when that dispatch actually WON a probe (its
/// `probe_epoch` arg is `Some`: the `pick_among`/`try_admit_breaker` paths). The least-bad path bypasses
/// the breaker and owns no probe, so it passes `None` and NO guard is built — it can therefore never
/// release/revert a probe (in particular, never a probe a concurrent peer won on the same cell). When
/// built, the guard is armed across every early-return error path (each records a transient first, which
/// already transitions the cell, so the guard's release is a safe owner-checked no-op) and disarmed the
/// moment the request records a legitimate SUCCESS (`record_success_in`). Its
/// only OTHER exerciser is `probe_guard_tests`, the canonical statement of the release/disarm/
/// owner-check semantics. (The pre-refactor `pick_among` parking loop that once constructed this guard
/// is gone — `try_admit` is now a single non-async admission that releases a won-but-undispatched probe
/// internally, with no await between winning the probe and returning.)
pub(crate) struct ProbeGuard<'a> {
    pub(crate) store: &'a dyn crate::store::LaneRuntime,
    pub(crate) pool: &'a str,
    pub(crate) lane: usize,
    pub(crate) armed: bool,
    /// The probe-epoch (owner token) captured when the probe was won. Because a guard can be dropped
    /// LATE — after the dispatched request already recorded an outcome and a peer won a NEWER probe on
    /// the same cell — the drop uses the OWNER-CHECKED `release_probe_owned_in` so a stale release
    /// cannot revert that newer probe. It is a strict no-op unless the cell's epoch still
    /// matches this captured value.
    pub(crate) probe_epoch: u64,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store
                .release_probe_owned_in(self.pool, self.lane, self.probe_epoch);
        }
    }
}

/// Pick a lane from `cands` using session affinity (if any) then weighted selection (SWRR) over
/// the healthy subset, returning the chosen lane index, its acquired concurrency permit, and the
/// probe-epoch owner token captured at the moment of the win (mirroring `ProbeGuard`'s own capture,
/// same field, same reasoning: a caller that must abandon dispatch AFTER an `.await` — a yield
/// point where a successor could win a NEWER probe on the same cell — releases via the
/// owner-checked `release_probe_owned_in(pool, lane, epoch)` instead of the unowned
/// `release_probe_in`, which would revert whichever probe is live at release time regardless of
/// which one this call actually won. Safe to use even when this pick's `acquire_for_dispatch_in`
/// did not win a NEW probe (a normal Closed-cell dispatch): the epoch is simply whatever the cell's
/// current value is, and `cell_release_probe_owned`'s CAS is a no-op on a non-HalfOpen cell either
/// way.
/// `cands` is a `&[WeightedLane]` slice where each lane carries its configured weight.
/// `request_ctx` provides accumulated exclusions to avoid retrying failed lanes.
/// `affinity_key_hash` enables sticky routing as a preference (not a hard constraint). It is the
/// PRE-COMPUTED [`stable_hash`] of the session key (header value or the body-derived `system` string),
/// hashed once at the ingress boundary from BORROWED bytes — so the sticky preference costs no
/// per-request `String` allocation here (the hash is the only thing this function ever needed from the
/// key). `None` = no sticky preference (pure SWRR).
pub(crate) async fn pick_among(
    app: &Arc<App>,
    cands: &[WeightedLane],
    request_ctx: &mut RequestCtx,
    affinity_key_hash: Option<u64>,
    pool_name: &str,
    // The routing policy's ranked preference for this request, resolved ONCE before the failover loop
    // (see the ROUTING-POLICY SEAM in `forward_with_pool`). `None` is the ZERO-COST default: pure
    // SWRR, byte-identical to pre-feature behavior. `Some(order)` makes selection walk the ranked
    // lanes through the unchanged breaker filter instead of the blind SWRR pick (see SELECTION below).
    policy_order: Option<&[usize]>,
) -> Option<(usize, Permit, u64)> {
    // THE MODEL PLANE'S CANDIDATE VIEW, for the ONE selection loop. Built once per pick (never inside
    // the walk's retry hops) and borrowed for its whole life: `wl` is the pool member as configured,
    // `model` is the operator-facing name a refusal must be able to say, and `pool_name` is this
    // plane's PIN — see `LaneCandidate::interchange_key`.
    let members: Vec<LaneCandidate<'_>> = cands
        .iter()
        .map(|wl| LaneCandidate {
            wl,
            model: app.lanes[wl.idx].model.as_str(),
            pool: pool_name,
        })
        .collect();

    // The positions this request has ALREADY dispatched to on an earlier failover hop — the seam's
    // `Attempt::tried`, spelled from the caller's accumulated cross-hop exclusion set.
    let tried: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, c)| request_ctx.excluded.contains(&c.wl.idx))
        .map(|(position, _)| position)
        .collect();

    let attempt = crate::failover::Attempt {
        tried: &tried,
        // THE MODEL PLANE'S REPEAT POSTURE, STATED RATHER THAN ASSUMED. A hop after the first is a
        // genuine `AfterDispatch` retry — the previous lane may already have received the request —
        // and the model plane has always permitted it, because a completion is a read: it charges the
        // caller twice and can never send a second email. That is why `Repeatable::Yes` here is a
        // description and not an exemption. The MCP/A2A planes hand the seam `Repeatable::No` unless
        // the operator names the operation in `repeatable:`, and the SAME rule in the SAME loop then
        // refuses their after-dispatch hop. The rule is one; the answer differs because the operations
        // differ, which is exactly what the rule is for.
        stage: if tried.is_empty() {
            crate::failover::Stage::BeforeFirstByte
        } else {
            crate::failover::Stage::AfterDispatch
        },
        repeatable: crate::failover::Repeatable::Yes,
        operation: "completion",
    };

    let mut order = SwrrOrder {
        app,
        cands,
        request_ctx,
        pool_name,
        policy_order,
        sticky: affinity_key_hash.and_then(|h| {
            if cands.is_empty() {
                return None;
            }
            {
                let pos = (h as usize) % cands.len();
                // DRAIN (`weight: 0`): an operator weights a member to 0 to bleed it off before
                // decommission. SWRR (`select_weighted_for`) and the routing-policy preferred walk
                // both already exclude a 0-weight candidate; this sticky fast path must too, else a
                // session whose hash lands on a drained-but-breaker-healthy member keeps pinning to
                // it on the NORMAL path — silently defeating drain. The admission only consults
                // dead/budget/breaker/permits, never weight, so gate on the candidate's weight (and
                // the caller's cross-hop exclusion set) here — those are selection-policy skips, NOT
                // `Unavailable` reasons, so they are never recorded.
                (cands[pos].weight != 0 && !request_ctx.excluded.contains(&cands[pos].idx))
                    .then_some(pos)
            }
        }),
        sticky_offered: false,
        sticky_grace: false,
        local_excluded: std::collections::HashSet::new(),
        // Pre-sized to the candidate count and reused across the walk's retry hops (`.clear()` +
        // re-`.extend()`), so a HalfOpen-probe-race re-selection costs no allocation and no growth
        // realloc. The filter can only DROP entries, so `cands.len()` is an upper bound.
        candidates: Vec::with_capacity(cands.len()),
        weights: Vec::with_capacity(cands.len()),
    };

    // THE ONE SELECTION LOOP — `failover::walk_with`, the same function `failover::walk` hands the
    // MCP and A2A planes' candidates to. This plane supplies exactly two things and owns no loop:
    // the ORDER (SWRR / routing policy / session affinity, above) and the ADMISSION (`try_admit`,
    // which is `try_admit_breaker` plus this plane's concurrency permit — one FSM, one cell, one
    // single-flight probe). Everything the loop decides — is there anything here, is this a repeat
    // and is that allowed, do the pins agree, will the breaker have it, and what is the refusal —
    // is decided in core, identically for all three planes.
    let mut passed_over: Vec<(usize, crate::store::Unavailable)> = Vec::new();
    let admitted = crate::failover::walk_with(
        pool_name,
        &members,
        &attempt,
        &mut order,
        &mut passed_over,
        &mut |_position, c: &LaneCandidate<'_>| app.store.try_admit(pool_name, c.wl.idx, now()),
    );

    // Fresh exclusion reasons for THIS pick attempt (advisory; fed to `on_exhausted`), replaced
    // wholesale so a fallback-pool hop that re-runs `pick_among` reports its OWN exhaustion and never
    // a stale earlier one. The walk hands back POSITIONS; `excluded_reasons` speaks lane indices.
    request_ctx.excluded_reasons.clear();
    request_ctx.excluded_reasons.extend(
        passed_over
            .iter()
            .filter_map(|(position, why)| cands.get(*position).map(|wl| (wl.idx, *why))),
    );

    match admitted {
        Ok(adm) => {
            let idx = adm.candidate().wl.idx;
            let admit = adm.into_token();
            Some((idx, admit.permit, admit.probe_epoch))
        }
        // Every refusal the loop can produce is "there is nowhere to send this hop", which is what
        // `None` has always meant here: the caller falls through to `on_exhausted`, which renders the
        // operator-facing answer from `excluded_reasons` above. The model plane therefore adds no
        // second refusal vocabulary — `Refusal` is rendered by the planes that have somewhere to
        // render it (MCP's `-32030`, A2A's task refusal).
        Err(_) => None,
    }
}

/// THE MODEL PLANE'S [`crate::failover::Candidate`] — a pool member, borrowed for one selection.
struct LaneCandidate<'a> {
    wl: &'a WeightedLane,
    model: &'a str,
    pool: &'a str,
}

impl crate::failover::Candidate for LaneCandidate<'_> {
    fn name(&self) -> &str {
        self.model
    }
    fn lane(&self) -> usize {
        self.wl.idx
    }
    /// THE MODEL PLANE HAS NO DIGEST TO CHECK, AND THIS SAYS SO IN THE ONE PLACE THE CHECK RUNS.
    ///
    /// On the MCP plane the pin is an approved tool-schema digest and on A2A an approved card
    /// fingerprint — values busbar itself computed, so "these two are the same deployment" is a fact
    /// it can VERIFY and refuse on. A model endpoint has no such artifact: two members of a `pools:`
    /// entry are interchangeable because the operator wrote them in one pool, and that has been this
    /// plane's semantics since long before the seam existed. Returning the POOL NAME states exactly
    /// that and nothing more — every member of one pool agrees, so the shared pin check passes.
    ///
    /// What this deliberately does NOT do is skip the check for this plane. The check runs; it is
    /// run against the only pin this plane has. The difference between "verified same deployment"
    /// and "the operator's declaration" is now a visible one-line answer in the candidate type,
    /// instead of an unstated absence in a second selection loop.
    fn interchange_key(&self) -> Option<&str> {
        Some(self.pool)
    }
}

/// THE MODEL PLANE'S [`crate::failover::Order`]: session affinity first, then SWRR — or the routing
/// policy's ranked walk — over what is left.
///
/// ORDER ONLY. Nothing here admits anything: `ready_in` and `select_weighted_in` are read-only peeks
/// (no Open→HalfOpen transition, no single-flight probe CAS), and the SOLE mutating admission is the
/// `try_admit` the walk calls on whatever this yields. That is why weighting, routing policy, drain
/// and stickiness can live on this plane without being a second selection loop — they answer "who is
/// asked first", never "who is allowed".
struct SwrrOrder<'a> {
    app: &'a Arc<App>,
    /// This pool's membership, in the SAME order as the walk's `members` slice — so a position here
    /// is a position there.
    cands: &'a [WeightedLane],
    request_ctx: &'a RequestCtx,
    pool_name: &'a str,
    policy_order: Option<&'a [usize]>,
    /// The session-affinity position, offered FIRST and exactly once. `None` = no sticky preference,
    /// a drained sticky member, or one this request already tried (pure SWRR).
    sticky: Option<usize>,
    sticky_offered: bool,
    /// Set for exactly one `next` call after the sticky position was offered. See its use below: a
    /// refused STICKY is deliberately not locally excluded.
    sticky_grace: bool,
    /// Positions this order will not offer again — a lane that was selected but could not be admitted
    /// (HalfOpen probe race, at capacity). Local to the pick: it never mutates the caller's
    /// cross-hop exclusion set.
    local_excluded: std::collections::HashSet<usize>,
    candidates: Vec<usize>,
    weights: Vec<u32>,
}

impl crate::failover::Order for SwrrOrder<'_> {
    fn next(&mut self, refused: Option<usize>) -> Option<usize> {
        if let Some(position) = refused {
            // A REFUSED STICKY IS NOT LOCALLY EXCLUDED, and that is this plane's long-standing
            // behaviour preserved exactly, not an oversight inherited: the sticky fast path records
            // its `Unavailable` reason and falls THROUGH to SWRR, which may legitimately pick the
            // same lane again and attempt it a second time. `handle_queue` is written against that —
            // it dedups the doubled at-capacity reason by lane and says so in its comment. Keeping it
            // means the model plane's byte-identical behaviour survives the move onto the one loop;
            // it now lives in this plane's ORDER, where it is one visible branch, instead of being an
            // untidy fall-through in a selection loop of its own.
            if !(self.sticky_grace && Some(position) == self.sticky) {
                self.local_excluded.insert(position);
            }
        }
        self.sticky_grace = false;

        // 1. SESSION AFFINITY, offered before anything else and before the deadline guard — exactly
        //    where the fast path sat. The hash was taken with `stable_hash` (NOT `DefaultHasher`,
        //    whose seed is randomized per process) at the ingress boundary, so a session pins to the
        //    same lane across restarts.
        if !self.sticky_offered {
            self.sticky_offered = true;
            if let Some(position) = self.sticky {
                self.sticky_grace = true;
                return Some(position);
            }
        }

        // 2. Deadline guard: never spin or re-select past the request deadline.
        if self.request_ctx.expired(now()) {
            return None;
        }

        // 3. This hop's candidate set: the pool minus the caller's cross-hop exclusions minus the
        //    positions this order has already burned.
        self.candidates.clear();
        self.weights.clear();
        for (position, wl) in self.cands.iter().enumerate() {
            if self.request_ctx.excluded.contains(&wl.idx)
                || self.local_excluded.contains(&position)
            {
                continue;
            }
            self.candidates.push(wl.idx);
            self.weights.push(wl.weight);
        }
        if self.candidates.is_empty() {
            return None;
        }

        // 4. SELECTION. Two paths, and ONLY two:
        //
        //  • `policy_order == None` (the ZERO-COST DEFAULT, `route: weighted` / absent): a single
        //    `select_weighted_in` call, the unchanged inline SWRR.
        //
        //  • `policy_order == Some(order)` (a routing policy returned `Prefer`): an ORDERED WALK.
        //    Honor EXACTLY the same health filter SWRR honors — `select_weighted_in` admits a
        //    candidate iff it is lane-admissible (not dead / in budget) AND its per-pool breaker cell
        //    is ready (the side-effect-FREE `ready_in`, the SAME predicate SWRR's filter uses). So:
        //    pick the FIRST lane in the policy's ranked `order` that is (a) still in this hop's
        //    candidate set and (b) `ready_in`. A preferred lane that is tripped / dead / excluded /
        //    at-capacity-by-breaker fails this check and we walk to the next. If NO ranked lane
        //    qualifies — every preferred lane is unhealthy/excluded, OR the policy ranked only a
        //    subset and those are exhausted — we fall THROUGH to `select_weighted_in` over the same
        //    candidate set, which both (i) preserves the contract's "an omitted/unranked candidate is
        //    lowest-priority but still REACHABLE, never stranded" guarantee, and (ii) keeps
        //    `Abstain` ⇒ today's SWRR exact (Abstain resolves to `policy_order == None`, so it never
        //    reaches this arm at all).
        let picked_lane_idx = match self.policy_order {
            Some(order) => {
                let now_t = now();
                // First ranked lane that is in this hop's candidate set, NOT drained, AND
                // breaker-ready.
                //
                // Weight-0 drain: SWRR's `select_weighted_in` skips `weight == 0` members (the
                // operator drain signal — see store.rs). The side-effect-free `ready_in` does NOT
                // check weight, so without this filter the ordered walk could rank a DRAINED lane #1
                // and yield it, violating operator drain intent. Mirror SWRR here: a candidate
                // weighted to 0 is excluded from the preferred walk. It still falls through to
                // `select_weighted_in` below if no ranked lane qualifies — which itself re-skips
                // weight-0 — so a fully-drained candidate set strands nothing it shouldn't.
                let preferred = order.iter().copied().find(|idx| {
                    self.candidates
                        .iter()
                        .position(|c| c == idx)
                        .is_some_and(|pos| self.weights[pos] != 0)
                        && self.app.store.ready_in(self.pool_name, *idx, now_t)
                });
                match preferred {
                    Some(idx) => idx,
                    None => self.app.store.select_weighted_in(
                        self.pool_name,
                        &self.candidates,
                        &self.weights,
                        now_t,
                    )?,
                }
            }
            // Zero-cost default: today's exact inline SWRR, one predictable branch.
            None => self.app.store.select_weighted_in(
                self.pool_name,
                &self.candidates,
                &self.weights,
                now(),
            )?,
        };

        // The walk indexes `members` by POSITION; SWRR answers with a LANE INDEX. Map back through
        // this pool's membership. A lane can appear at most once in a pool's `members:` (config
        // rejects a duplicate), so the first match is THE match.
        self.cands.iter().position(|wl| wl.idx == picked_lane_idx)
    }
}

/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream). Both
/// must engage the streaming body path rather than being buffered.
pub(crate) fn is_streaming_content_type(ct: &str) -> bool {
    // A CT is "streaming" iff SOME declared protocol declared it as its streaming `Content-Type`
    // (SSE protocols → `text/event-stream`; Bedrock → `application/vnd.amazon.eventstream`). The
    // set is a registry aggregate folded once at boot from the declarations, so naming no
    // protocol/MIME literal here keeps the agnostic core clean.
    crate::proto::streaming_content_types()
        .iter()
        .any(|p| ct.starts_with(p))
}

/// The streaming `Content-Type` the INGRESS client expects, by ingress protocol. On a cross-protocol
/// reframe the streamed body is re-encoded into the client's framing, so the response header must
/// describe the CLIENT's wire format — copying the upstream CT verbatim would mislabel the body
/// (e.g. a Bedrock-egress `application/vnd.amazon.eventstream` reaching an SSE client, or vice
/// versa). Returns `None` for an unrecognized protocol name so the caller keeps the upstream CT
/// rather than guessing.
///
/// Reads `ProtocolDecl::streaming_content_type` (SSE protocols → `text/event-stream`; Bedrock →
/// `application/vnd.amazon.eventstream`) so this function carries no `"bedrock"` branch — the CT is
/// a fact the protocol DECLARED, not the name string, and reading a declaration allocates nothing
/// where building a writer to ask it allocated two boxes.
pub(crate) fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    crate::proto::decl_for(ingress).and_then(|d| d.streaming_content_type)
}
