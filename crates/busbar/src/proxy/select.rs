use super::*;

/// Slack ε for the [`RequestCtx::debug_assert_within_budget`] failover-budget guard (R6/§5). Generous
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
    /// `on_exhausted: queue` bound has MILLISECOND precision (R8). `deadline`/`remaining()` are whole
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
}

impl RequestCtx {
    pub(crate) fn new(deadline_secs: u64) -> Self {
        let start = now();
        Self {
            deadline: start.saturating_add(deadline_secs),
            // Overflow-safe: `Instant`'s `Add` impl PANICS on overflow (it `.expect()`s internally, in
            // release too). `deadline_secs` is operator-controlled (`failover.timeout_secs`), so a huge
            // value would panic the serving task on every request. `checked_add` + a far-future fallback
            // keeps the data plane crash-free even if config_validate's upper bound is ever bypassed; the
            // sibling `deadline` above is already saturating for the same reason.
            deadline_wall: std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(deadline_secs))
                .unwrap_or_else(|| {
                    std::time::Instant::now() + std::time::Duration::from_secs(3600)
                }),
            excluded: std::collections::HashSet::new(),
            visited_pools: std::collections::HashSet::new(),
            active_restricts: Vec::new(),
            excluded_reasons: Vec::new(),
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

    /// Remaining failover budget in MILLISECONDS until the deadline (R8). Used by the `on_exhausted:
    /// queue` wait so a sub-second `max_ms` is representable and a near-second-boundary budget does not
    /// collapse to 0 the way `remaining(now) * 1000` would. Saturates to 0 once the deadline passes.
    pub(crate) fn remaining_ms(&self) -> u64 {
        self.deadline_wall
            .saturating_duration_since(std::time::Instant::now())
            .as_millis() as u64
    }

    /// R6 / §5 budget contract, as an asserted invariant. `deadline_wall` is captured at ingress as
    /// `ingress + failover.timeout`, so requiring the wall clock at THIS disposition to be within
    /// `deadline_wall` plus ε is exactly "wall-clock ingress→disposition ≤ failover.timeout + ε". A
    /// `debug_assert!` so it runs in dev/CI (test + debug builds) and is compiled out of the release
    /// request path — it exists to CATCH a selection / queue path that regresses to blocking past the
    /// failover budget (the exact Bug-1 park pathology), never to change production behaviour. ε is
    /// deliberately generous ([`BUDGET_ASSERT_EPSILON`]) so the guard never false-fires on scheduler
    /// jitter or a slow CI box; the property/budget TESTS assert a tighter, meaningful bound.
    pub(crate) fn debug_assert_within_budget(&self, context: &str) {
        debug_assert!(
            std::time::Instant::now() <= self.deadline_wall + BUDGET_ASSERT_EPSILON,
            "failover budget exceeded at `{context}`: disposition landed more than {}ms past the \
             failover deadline — a selection/queue path blocked past the budget (R6/§5)",
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
/// out-of-band prober resets it (the HIGH this fixes).
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
    pub(crate) store: &'a dyn crate::store::StateStore,
    pub(crate) pool: &'a str,
    pub(crate) lane: usize,
    pub(crate) armed: bool,
    /// The probe-epoch (owner token) captured when the probe was won. Because a guard can be dropped
    /// LATE — after the dispatched request already recorded an outcome and a peer won a NEWER probe on
    /// the same cell — the drop uses the OWNER-CHECKED `release_probe_owned_in` so a stale release
    /// cannot revert that newer probe (P2 #4). It is a strict no-op unless the cell's epoch still
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
    let t = now();

    // Fresh exclusion reasons for THIS pick attempt (advisory; fed to `on_exhausted`). Cleared here so
    // a fallback-pool hop that re-runs `pick_among` reports its OWN exhaustion, not a stale earlier one.
    request_ctx.excluded_reasons.clear();

    // Session affinity preference - try sticky lane first if usable (in this pool's breaker view).
    // The hash was taken with `stable_hash` (NOT DefaultHasher, whose seed is randomized per process)
    // at the ingress boundary, so a session pins to the same lane across restarts.
    if let Some(h) = affinity_key_hash {
        if !cands.is_empty() {
            let pos = (h as usize) % cands.len();
            let sticky = cands[pos].idx;

            // DRAIN (`weight: 0`): an operator weights a member to 0 to bleed it off before
            // decommission. SWRR (`select_weighted_for`) and the routing-policy preferred walk both
            // already exclude a 0-weight candidate; this sticky fast-path must too, else a session
            // whose hash lands on a drained-but-breaker-healthy member keeps pinning to it on the
            // NORMAL path — silently defeating drain. `try_admit`/`lane_admissible` only consult
            // dead/budget/breaker/permits, never weight, so gate on the candidate's weight (and the
            // caller's cross-hop exclusion set) here — those are selection-policy skips, NOT
            // `Unavailable` reasons, so they are not recorded.
            if cands[pos].weight != 0 && !request_ctx.excluded.contains(&sticky) {
                // R6: the sticky fast path uses the SAME admission primitive as the main loop —
                // `try_admit` wins-or-releases the single-flight probe and grabs-or-fails the permit
                // atomically (probe ownership transfers via `Admit.probe_epoch` on success; on failure
                // it releases the probe internally, EXACTLY, so nothing wedges HalfOpen). On
                // fall-through we RECORD the `Unavailable` reason instead of dropping it silently.
                match app.store.try_admit(pool_name, sticky, t) {
                    Ok(admit) => return Some((sticky, admit.permit, admit.probe_epoch)),
                    Err(reason) => request_ctx.excluded_reasons.push((sticky, reason)),
                }
            }
        }
    }

    // Filter out already-tried lanes (accumulated exclusions across hops). A locally-tracked
    // exclusion set lets us skip a lane we selected but couldn't probe-acquire (HalfOpen race),
    // without mutating the caller's RequestCtx for what is a within-pick retry.
    let mut local_excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // Hoisted out of the retry loop and pre-sized to the candidate count: the loop body re-runs on
    // every within-pick retry hop (HalfOpen-probe race), so reusing these buffers (`.clear()` +
    // re-`.extend()` each iteration) avoids both per-iteration allocation AND growth reallocation.
    // The filter can only DROP entries, so `cands.len()` is an upper bound (capacity, not fill);
    // selection semantics are unchanged. `filtered_cands` borrows `cands`, which outlives the loop.
    let mut filtered_cands: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    let mut candidates: Vec<usize> = Vec::with_capacity(cands.len());
    let mut weights: Vec<u32> = Vec::with_capacity(cands.len());

    loop {
        // Deadline guard: never spin or re-select past the request deadline.
        if request_ctx.expired(now()) {
            return None;
        }

        request_ctx.fill_candidates(cands, &mut filtered_cands);
        filtered_cands.retain(|wl| !local_excluded.contains(&wl.idx));
        if filtered_cands.is_empty() {
            return None;
        }

        // Extract lane indices and weights for select_weighted call
        candidates.clear();
        candidates.extend(filtered_cands.iter().map(|wl| wl.idx));
        weights.clear();
        weights.extend(filtered_cands.iter().map(|wl| wl.weight));

        // SELECTION. Two paths, and ONLY two:
        //
        //  • `policy_order == None` (the ZERO-COST DEFAULT, `route: weighted` / absent): byte-identical
        //    to pre-feature behavior — a single `select_weighted_in` call, the unchanged inline SWRR.
        //
        //  • `policy_order == Some(order)` (a routing policy returned `Prefer`): an ORDERED WALK.
        //    Honor EXACTLY the same health filter SWRR honors — `select_weighted_in` admits a candidate
        //    iff it is lane-admissible (not dead / in budget) AND its per-pool breaker cell is ready
        //    (the side-effect-FREE `ready_in`, the SAME predicate SWRR's filter uses). So: pick the
        //    FIRST lane in the policy's ranked `order` that is (a) still in this hop's candidate set
        //    (`candidates` is already exclusions- and local_excluded-filtered) and (b) `ready_in`. A
        //    preferred lane that is tripped / dead / excluded / at-capacity-by-breaker fails this check
        //    and we walk to the next. If NO ranked lane qualifies — every preferred lane is
        //    unhealthy/excluded, OR the policy ranked only a subset and those are exhausted — we fall
        //    THROUGH to `select_weighted_in` over the same candidate set, which both (i) preserves the
        //    contract's "an omitted/unranked candidate is lowest-priority but still REACHABLE, never
        //    stranded" guarantee, and (ii) keeps `Abstain` ⇒ today's SWRR exact (Abstain resolves to
        //    `policy_order == None`, so it never reaches this arm at all).
        //
        // The walk only ORDERS. It does NOT touch the breaker/probe/failover machinery: `ready_in` is
        // a read-only peek (no Open→HalfOpen transition, no single-flight probe CAS), and the SOLE
        // mutating admission — `acquire_for_dispatch_in` below — still runs EXACTLY ONCE on the chosen
        // lane, identically to the SWRR path. A preferred lane that then loses the HalfOpen probe race
        // is `local_excluded` + re-walked just like an SWRR pick, so it falls to the next preferred
        // lane (or to SWRR) with no change to breaker, failover, or translation behavior.
        let picked_lane_idx = match policy_order {
            Some(order) => {
                let now_t = now();
                // First ranked lane that is in this hop's candidate set, NOT drained, AND breaker-ready.
                //
                // C2 (weight:0 drain): SWRR's `select_weighted_in` skips `weight == 0` members (the
                // operator drain signal — see store.rs). The side-effect-free `ready_in` does NOT
                // check weight, so without this filter the ordered walk could rank a DRAINED lane #1
                // and dispatch to it, violating operator drain intent. Mirror SWRR here: a candidate
                // weighted to 0 is excluded from the preferred walk. It still falls through to
                // `select_weighted_in` below if no ranked lane qualifies — which itself re-skips
                // weight-0 — so a fully-drained candidate set strands nothing it shouldn't.
                let preferred = order.iter().copied().find(|idx| {
                    candidates
                        .iter()
                        .position(|c| c == idx)
                        .is_some_and(|pos| weights[pos] != 0)
                        && app.store.ready_in(pool_name, *idx, now_t)
                });
                match preferred {
                    Some(idx) => idx,
                    // No ranked lane qualifies: fall through to SWRR over the same candidates so an
                    // unranked-but-healthy lane is still reachable (never stranded by the policy).
                    None => {
                        match app
                            .store
                            .select_weighted_in(pool_name, &candidates, &weights, now_t)
                        {
                            Some(i) => i,
                            None => return None,
                        }
                    }
                }
            }
            // Zero-cost default: today's exact inline SWRR, one predictable branch.
            None => match app
                .store
                .select_weighted_in(pool_name, &candidates, &weights, now())
            {
                Some(i) => i,
                None => return None,
            },
        };

        // ONE admission path, ONE exclusion arm (design §2). `try_admit` is the thin composition over
        // the breaker check + `try_acquire`: it wins-or-loses the single-flight probe and
        // grabs-or-fails the permit atomically, handing back the held resources on success or the
        // shared `Unavailable` taxonomy on failure. The two former `insert;continue` sites
        // (breaker-lost @ the old ~330, at-capacity @ the old ~379) are now the SAME `Err(reason)` arm
        // — they were always the same kind of thing (a lane that can't take this request), differing
        // only in the reason carried forward. `try_admit` also owns the probe lifecycle: on the
        // at-capacity path it releases the won-but-undispatched probe EXACTLY (owner-checked, no leak,
        // no double-release), and on success the probe ownership transfers out via `admit.probe_epoch`
        // (the dispatched request releases it after recording its outcome). So no `ProbeGuard` is
        // needed here anymore — there is no await between winning the probe and returning/excluding,
        // and the release that `ProbeGuard::drop` used to perform now happens inside `try_admit`.
        match app.store.try_admit(pool_name, picked_lane_idx, now()) {
            Ok(admit) => return Some((picked_lane_idx, admit.permit, admit.probe_epoch)),
            Err(reason) => {
                local_excluded.insert(picked_lane_idx);
                // Record WHY (fed to `on_exhausted`); does not affect selection.
                request_ctx.excluded_reasons.push((picked_lane_idx, reason));
                continue;
            }
        }
    }
}

/// True for content types that carry an incremental streamed response: SSE (text/event-stream,
/// used by Anthropic/OpenAI/Gemini-SSE) and AWS event-stream (Bedrock ConverseStream). Both
/// must engage the streaming body path rather than being buffered.
pub(crate) fn is_streaming_content_type(ct: &str) -> bool {
    // Read the cached streaming-CT set instead of re-sweeping the registry per request: a CT is
    // "streaming" iff it is the streaming `Content-Type` of SOME registered protocol's writer (SSE
    // protocols → `text/event-stream`; Bedrock → `application/vnd.amazon.eventstream`). The cache
    // (`proto::streaming_content_types`) reads those MIMEs from the writer vtable, so naming no
    // protocol/MIME literal here keeps the agnostic core clean. The detected set is unchanged:
    // `text/event-stream` + `application/vnd.amazon.eventstream`.
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
/// Dispatches through `ProtocolWriter::streaming_content_type` (SSE protocols → `text/event-stream`;
/// Bedrock → `application/vnd.amazon.eventstream`) so this function carries no `"bedrock"` branch —
/// the CT is a property of the writer vtable, not the name string.
pub(crate) fn ingress_stream_content_type(ingress: &str) -> Option<&'static str> {
    crate::proto::protocol_for(ingress).map(|p| p.writer().streaming_content_type())
}
