// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EQUIVALENCE CELLS — `busbar-unit-breaker` against the legacy `LaneRuntime`, one recorded
//! sequence driven into both books, one normalized observation compared.
//!
//! ROUTE-design §3.5 measured [FSM-EQUIV] and the answer was NO: the unit is a *narrower* unit than
//! `LaneRuntime`, in TEN named ways, five of them wire-visible on the first failure. The route step
//! cannot be served by the unit until those ten close. These cells are the proof budget for that
//! closing: each one drives the legacy book (`busbar_core::store::HealthState` behind
//! `busbar_substrate::store::LaneRuntime`) and the unit book (`busbar_unit_breaker::BreakerUnit`)
//! through the SAME recorded sequence and asserts the SAME answer.
//!
//! They live in the root crate because the root is the only crate that may name both books: the
//! unit crate's manifest forbids it every workspace dependency but `busbar-caps`/`busbar-contract`,
//! and that constraint is the point — the two books meet in the composition root, exactly where
//! `BreakerAdapter` already binds them (`crates/busbar/src/root/adapters.rs`).
//!
//! ## The shims, and why they exist
//!
//! Six of the ten differences are a MISSING VERB, not a wrong answer: there is no unit call to make.
//! Rather than leave those cells uncompilable on the base — a red nobody can run — each is driven
//! through a shim in [`shim`] below that does *the closest thing the unit can do today*, with the
//! gap stated in its doc comment. The cell above the shim never changes; the commit that moves the
//! legacy code into the unit repoints the shim at the real verb and the cell goes green. What a shim
//! must never do is *implement* the missing behaviour — it stands in for the call, not for the code.

#![allow(clippy::items_after_test_module)]

use std::collections::HashMap;

use busbar_caps::{KernelSeal, Route, UnitToken};
use busbar_core::store::{HealthState, LaneData};
use busbar_substrate::store::{
    BreakerCfg as LegacyCfg, LaneRuntime, TripConfig as LegacyTrip, TripMode as LegacyTripMode,
    Unavailable,
};
use busbar_unit_breaker::cfg::{
    BreakerCfg as UnitCfg, TripConfig as UnitTrip, TripMode as UnitTripMode,
};
use busbar_unit_breaker::{Breaker, BreakerUnit, DestinationId, LaneState, Outcome};

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The two books, side by side
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The lane index the legacy book keys on, and the destination the unit keys on: ONE pool member,
/// named twice. `Candidate::interchange_key` is the pool name and the lane is `c.wl.idx`
/// (ROUTE-design §3.2), so the translation is total and mechanical — these cells pin it.
const LANE: usize = 0;
const DEST: DestinationId = DestinationId::new(0);

/// A fresh `UnitToken<Route>` for one `observe`/`state` call.
fn tok() -> UnitToken<Route> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// The legacy book with one lane of `max` permits.
fn legacy(max: usize) -> HealthState {
    HealthState::new(vec![LaneData::for_test("m", "p", max)])
}

/// The unit book.
fn unit() -> BreakerUnit {
    BreakerUnit::new()
}

/// The SAME resolved breaker configuration, spelled in each book's own vocabulary. `cfg.rs` is a
/// byte-identical move of `substrate::store::{BreakerCfg, TripConfig, TripMode}` (ROUTE-design §3.5,
/// "SAME, byte-identical"), so this is a field-for-field rename and nothing else.
fn cfgs(base: u64, max: u64) -> (LegacyCfg, UnitCfg) {
    let trip = LegacyTrip {
        mode: LegacyTripMode::Consecutive,
        window_s: 30,
        threshold: 0.5,
        min_requests: 5,
        consecutive_n: 3,
    };
    let legacy = LegacyCfg {
        base_cooldown_secs: base,
        max_cooldown_secs: max,
        honor_retry_after: true,
        trip,
        bench_below_trip_threshold: true,
    };
    let unit = UnitCfg {
        base_cooldown_secs: base,
        max_cooldown_secs: max,
        honor_retry_after: true,
        trip: UnitTrip {
            mode: UnitTripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        },
        bench_below_trip_threshold: true,
    };
    (legacy, unit)
}

/// The whole second the legacy book will stamp its own records with. Every legacy mutator reads its
/// own wall clock (`HealthState::now_secs`), so a comparison against the unit — which takes `now` as
/// a parameter, as a unit must — is only meaningful inside ONE second. Cells that compare absolute
/// deadlines re-read this and retry if the second turned under them.
fn wall_secs() -> u64 {
    busbar_unit_breaker::clock::unix_time_secs()
}

/// ONE availability answer, in the vocabulary BOTH books can be read into: the `Unavailable`
/// taxonomy's own `variant_name` (`substrate/store.rs`), plus the exact recovery deadline where the
/// reason carries one. This is the normalizer every cell compares through — a cell never compares a
/// legacy type against a unit type directly, because the whole question is whether the two answer
/// the same thing while spelling it differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Avail {
    name: &'static str,
    until: Option<u64>,
}

fn from_legacy(r: Result<(), Unavailable>) -> Avail {
    match r {
        Ok(()) => Avail {
            name: "available",
            until: None,
        },
        Err(u) => Avail {
            name: u.variant_name(),
            until: match u {
                Unavailable::BreakerOpen { until } => Some(until),
                _ => None,
            },
        },
    }
}

fn from_unit(s: LaneState) -> Avail {
    Avail {
        name: s.variant_name(),
        until: match s {
            LaneState::Suppressed { until } => Some(until),
            _ => None,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 1. Every cooldown value changes — the jitter seed
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 1 (wire-visible).** The legacy seeds the ±10% cooldown jitter from
/// `SystemTime::now().as_nanos()` (`busbar-core/src/store/in_memory/breaker.rs:518-524`); the unit
/// seeds it from the caller's `now` **in whole seconds** (`cell.rs:358`). Same FNV-1a mix, same
/// band, different numbers — so every `Retry-After` and every `/stats` `until` differs, and cells
/// tripping inside one second stop decorrelating on anything but their own address.
///
/// The observation that separates the two seeds without depending on either's value: hold the CELL
/// and the STREAK fixed and trip repeatedly inside one wall-clock second. A nanos seed spreads; a
/// whole-seconds seed cannot move at all. `[ROUTE-1]` ruling (2): the seed stays nanos, because a
/// move and a behaviour change must not land in one commit.
#[test]
fn d1_cooldown_jitter_seed_is_wallclock_nanos() {
    // A wide band so a coincidental collision across eight rounds is not a story: base 1000 gives
    // `jitter_range = 100`, i.e. 201 reachable values.
    let (lcfg, ucfg) = cfgs(1000, 100_000);

    // Up to three attempts, because the legacy book stamps itself from its own clock and a second
    // boundary crossing mid-loop would spread the unit too, for a reason that is not the seed.
    for attempt in 0..3 {
        let l = legacy(4);
        let u = unit();
        let start = wall_secs();
        let mut legacy_cooldowns = Vec::new();
        let mut unit_cooldowns = Vec::new();

        for _ in 0..8 {
            // One sub-threshold transient benches the cell with a jittered cooldown; the success
            // that follows resets the streak (never the cooldown), so the next round recomputes the
            // SAME streak on the SAME cell — leaving the time seed as the only moving input.
            let _ = l.record_transient_in("p", LANE, "5xx", &lcfg, None);
            legacy_cooldowns.push(l.cooldown_remaining_in("p", LANE, start));
            l.record_success_in("p", LANE);

            shim::observe(
                &u,
                "p",
                DEST,
                Outcome::Transient { retry_after: None },
                &ucfg,
                start,
            );
            unit_cooldowns.push(match u.state("p", DEST, start, &tok()) {
                LaneState::Suppressed { until } => until.saturating_sub(start),
                other => panic!("the unit did not bench a sub-threshold transient: {other:?}"),
            });
            shim::observe(&u, "p", DEST, Outcome::Success, &ucfg, start);
        }

        if wall_secs() != start {
            assert!(attempt < 2, "the wall second turned under every attempt");
            continue;
        }

        legacy_cooldowns.sort_unstable();
        legacy_cooldowns.dedup();
        unit_cooldowns.sort_unstable();
        unit_cooldowns.dedup();

        assert!(
            legacy_cooldowns.len() > 1,
            "the legacy book must spread eight same-second trips of one cell across its jitter \
             band; it produced {legacy_cooldowns:?}"
        );
        assert!(
            unit_cooldowns.len() > 1,
            "the unit must seed its jitter from the SAME wall-clock nanos the legacy book seeds \
             from, so eight same-second trips of one cell spread the same way. It produced \
             {unit_cooldowns:?} — one value, i.e. a whole-seconds seed (cell.rs:358)"
        );
        return;
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 2. A passthrough 401/403 becomes a hard-down
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 2 (wire-visible, live customer path).**
/// `busbar-llm/src/engine/attempt/classify.rs:203-210` exempts a 401/403 answered to a *caller's
/// own* key from any breaker penalty: it is the caller's credential failing, not busbar's, so the
/// answer is relayed and nothing is recorded. The unit has no notion of credential provenance
/// (`port.rs`), so the same response classifies `Auth → HardDown` and trips EVERY pool cell for the
/// destination. `[ROUTE-1]` ruling (3): the exemption is ported into the classify input.
#[test]
fn d2_passthrough_401_is_not_a_hard_down() {
    let u = unit();
    let _now = wall_secs();

    // Busbar's OWN key refused: a hard-down, in both books. This half must stay true.
    let owned = shim::classify(&u, DEST, 401, false, None, None, None);
    assert_eq!(
        owned.outcome,
        Outcome::HardDown,
        "a 401 against busbar's own credential is the destination's fault and must hard-down it"
    );

    // The CALLER's key refused: no breaker penalty at all.
    let passthrough = shim::classify(&u, DEST, 401, true, None, None, None);
    assert_eq!(
        passthrough.outcome,
        Outcome::RecordNothing,
        "a passthrough 401 is the caller's own key failing (classify.rs:203-210): relay it, record \
         nothing. Recording it hard-downs the destination in every pool for every other caller"
    );

    // And the same for 403, the other half of the exempted pair.
    assert_eq!(
        shim::classify(&u, DEST, 403, true, None, None, None).outcome,
        Outcome::RecordNothing,
        "the exemption covers 403 as well as 401 (classify.rs:205)"
    );

    // The exemption is scoped to those two statuses and nothing else: a passthrough 429 is still a
    // transient the breaker records, or a caller could suppress every penalty by relaying its key.
    assert!(
        matches!(
            shim::classify(&u, DEST, 429, true, None, None, None).outcome,
            Outcome::Transient { .. }
        ),
        "the passthrough exemption is 401/403 ONLY; a passthrough 429 is still a transient"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 3. The `error_map` keyspace silently changes
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 3 (wire-visible).** The legacy runs the dialect's `extract_error(status, body)` and
/// hands the resulting BODY-DERIVED provider code and structured type to `normalize_raw_error`
/// (`busbar-llm/src/engine/attempt/classify.rs:214-220`). The unit's port hardcodes
/// `provider_code = http_status.to_string()` and `structured_type: None` (`port.rs:153-158`), so
/// every operator rule keyed on a provider code stops firing. `[ROUTE-1]`: `error_map` keys stay
/// body-derived.
#[test]
fn d3_error_map_keys_stay_body_derived() {
    let mut map = HashMap::new();
    // The shape operators actually write: a provider's own code, mapped to a class that overrides
    // what the bare HTTP status would have said. A 500 that the provider calls `insufficient_quota`
    // is a billing fact about the credential, not a transient outage.
    map.insert("insufficient_quota".to_string(), "billing".to_string());
    // A structured `type` slot, the second signal `normalize_raw_error` checks.
    map.insert("overloaded_error".to_string(), "overloaded".to_string());

    let legacy_answer = |raw: busbar_substrate::breaker::RawUpstreamError| {
        busbar_substrate::breaker::classify(&busbar_substrate::breaker::normalize_raw_error(
            &raw, &map,
        ))
    };

    let u = unit();
    u.set_error_map(DEST, map.clone());

    // (a) the provider CODE slot.
    let legacy_code = legacy_answer(busbar_substrate::breaker::RawUpstreamError {
        http_status: 500,
        provider_code: Some("insufficient_quota".to_string()),
        structured_type: None,
        retry_after_secs: None,
    });
    let unit_code = shim::classify(&u, DEST, 500, false, Some("insufficient_quota"), None, None);
    assert_eq!(
        format!("{:?}", unit_code.disposition),
        format!("{legacy_code:?}"),
        "an operator rule keyed on the provider code `insufficient_quota` must still fire. The \
         unit hardcodes `provider_code = \"500\"` (port.rs:153-158), so the rule never matches and \
         a billing exhaustion reads as a transient outage"
    );

    // (b) the structured TYPE slot.
    let legacy_type = legacy_answer(busbar_substrate::breaker::RawUpstreamError {
        http_status: 400,
        provider_code: None,
        structured_type: Some("overloaded_error".to_string()),
        retry_after_secs: None,
    });
    let unit_type = shim::classify(&u, DEST, 400, false, None, Some("overloaded_error"), None);
    assert_eq!(
        format!("{:?}", unit_type.disposition),
        format!("{legacy_type:?}"),
        "the structured `type` slot is the second signal `normalize_raw_error` reads; the unit \
         passes `structured_type: None` and never offers it"
    );

    // (c) the plain HTTP-status key the config grammar also accepts must keep working — the widening
    // is body-derived codes IN ADDITION to, never INSTEAD OF, the status string.
    let mut status_map = HashMap::new();
    status_map.insert("503".to_string(), "client_error".to_string());
    let u2 = unit();
    u2.set_error_map(DEST, status_map.clone());
    let legacy_status =
        busbar_substrate::breaker::classify(&busbar_substrate::breaker::normalize_raw_error(
            &busbar_substrate::breaker::RawUpstreamError {
                http_status: 503,
                provider_code: Some("503".to_string()),
                structured_type: None,
                retry_after_secs: None,
            },
            &status_map,
        ));
    assert_eq!(
        format!(
            "{:?}",
            shim::classify(&u2, DEST, 503, false, None, None, None).disposition
        ),
        format!("{legacy_status:?}"),
        "a bare HTTP-status `error_map` key must keep firing when no body-derived code is present"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 4. Body-derived context-length detection is lost
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 4.** Several dialects synthesise `context_length_exceeded` from free text in the
/// body (`busbar-llm-codec/src/cohere/reader.rs:28-70` is the plainest case) — the legacy's
/// `extract_error` puts it in the provider-code slot and `normalize_raw_error` recognises it
/// built-in, gated to the request-size statuses 400/413. With `provider_code` hardcoded to the
/// status string, that recognition can never fire and the request becomes a `ClientError`/400
/// instead of a no-penalty failover to a wider-window sibling.
#[test]
fn d4_body_derived_context_length_is_a_no_penalty_failover() {
    let empty = HashMap::new();
    let u = unit();

    for status in [400u16, 413] {
        let legacy_sig = busbar_substrate::breaker::normalize_raw_error(
            &busbar_substrate::breaker::RawUpstreamError {
                http_status: status,
                provider_code: Some(
                    busbar_unit_breaker::classify::PROVIDER_CODE_CONTEXT_LENGTH.to_string(),
                ),
                structured_type: None,
                retry_after_secs: None,
            },
            &empty,
        );
        let legacy_disposition = busbar_substrate::breaker::classify(&legacy_sig);
        let unit_answer = shim::classify(
            &u,
            DEST,
            status,
            false,
            Some(busbar_unit_breaker::classify::PROVIDER_CODE_CONTEXT_LENGTH),
            None,
            None,
        );
        assert_eq!(
            format!("{:?}", unit_answer.disposition),
            format!("{legacy_disposition:?}"),
            "a {status} whose BODY says the context window was exceeded is a no-penalty failover, \
             not a client error against this destination"
        );
        assert_eq!(
            unit_answer.outcome,
            Outcome::RecordNothing,
            "a context-length answer records nothing: the destination is healthy"
        );
    }

    // The gate the legacy applies stays applied: a 500 carrying the same code is a real outage and
    // must still be penalised, or a hostile body could suppress every breaker penalty.
    let five_hundred = shim::classify(
        &u,
        DEST,
        500,
        false,
        Some(busbar_unit_breaker::classify::PROVIDER_CODE_CONTEXT_LENGTH),
        None,
        None,
    );
    assert!(
        matches!(five_hundred.outcome, Outcome::Transient { .. }),
        "context-length recognition is gated to 400/413; a 5xx carrying that code is an outage"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 5. RFC-850 / asctime `Retry-After` stops parsing
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 5.** The legacy parses `Retry-After` through `httpdate`
/// (`busbar-substrate-values/src/breaker.rs:148`), which accepts all three HTTP-date forms RFC 9110
/// permits for parsing. The unit hand-rolls IMF-fixdate only (`classify.rs:304-334`), so an upstream
/// sending the obsolete RFC-850 or asctime form has its stated cooldown floor silently discarded
/// and the breaker guesses instead.
#[test]
fn d5_retry_after_parses_every_http_date_form() {
    // One instant, spelled the three ways RFC 9110 §5.6.7 permits a parser to receive it.
    const IMF: &str = "Sun, 06 Nov 2044 08:49:37 GMT";
    const RFC850: &str = "Sunday, 06-Nov-44 08:49:37 GMT";
    const ASCTIME: &str = "Sun Nov  6 08:49:37 2044";

    let now = wall_secs();
    let legacy_parse = |v: &str| {
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::RETRY_AFTER, v.parse().unwrap());
        busbar_substrate::breaker::parse_retry_after(&h)
    };

    for form in [IMF, RFC850, ASCTIME] {
        let legacy = legacy_parse(form).unwrap_or_else(|| {
            panic!("the legacy book parses every HTTP-date form; it refused {form:?}")
        });
        let unit =
            busbar_unit_breaker::classify::parse_retry_after(form, now).unwrap_or_else(|| {
                panic!(
                "the unit must honour the same `Retry-After` forms the legacy book honours; it \
                 refused {form:?} and the upstream's stated cooldown floor was discarded"
            )
            });
        // Both books answer "seconds from now"; the legacy reads its own clock a beat later, so a
        // second of slack is the honest comparison, not a defect.
        assert!(
            legacy.abs_diff(unit) <= 2,
            "{form:?}: legacy {legacy}s vs unit {unit}s"
        );
    }

    // The integer form, which ignores the clock entirely, must stay exact in both.
    assert_eq!(legacy_parse("120"), Some(120));
    assert_eq!(
        busbar_unit_breaker::classify::parse_retry_after("120", now),
        Some(120)
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 6. The out-of-band prober protocol is absent
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 6 (wire-visible; the direct blocker on PROBE-1's schedule).** A health probe tests
/// the shared UPSTREAM, so the legacy fans its answer across every cell naming that lane —
/// `recover_lane` (`availability.rs:595`), `record_probe_success_all_cells` (`:434`),
/// `record_probe_failure_all_cells` with its per-pool `resolve_cfg` callback (`:641-682`), and
/// `lane_needs_probe` (`:684`). The unit ships the primitive (`cell.rs:457-468`) and nothing that
/// applies it across the N pool cells naming a destination: *a lane recovered today by one
/// successful probe across N pool cells would, under the unit, recover in zero.*
#[test]
fn d6_one_probe_answer_reaches_every_cell_for_the_destination() {
    let (lcfg, ucfg) = cfgs(30, 120);
    let l = legacy(4);
    let u = unit();
    let now = wall_secs();

    // Two pools front the same upstream, plus the default ("") cell direct routes read.
    for pool in ["", "pool-a", "pool-b"] {
        let _ = l.record_transient_in(pool, LANE, "5xx", &lcfg, None);
        shim::observe(
            &u,
            pool,
            DEST,
            Outcome::Transient { retry_after: None },
            &ucfg,
            now,
        );
    }

    // (a) the schedule's own filter: a suppressed cell ANYWHERE means the destination is due.
    assert!(
        l.lane_needs_probe(LANE, now),
        "the legacy book reports a lane with any suppressed cell as due for a probe"
    );
    assert!(
        shim::needs_probe(&u, DEST, now),
        "the unit must answer `is this destination due for a probe` over ALL its cells — this is \
         the filter `ProbeMode::Dead` reads and PROBE-1's `probes_due(now)` composes on"
    );

    // (b) a FAILED probe is recorded against every cell, each against ITS OWN pool's resolved cfg.
    let resolve = |_pool: &str| lcfg.clone();
    l.record_probe_failure_all_cells(LANE, "5xx", &resolve, None);
    shim::probe_failure_all(&u, DEST, now, &|_pool: &str| ucfg.clone(), None);

    // (c) one SUCCESSFUL probe recovers the destination everywhere, in both books.
    l.record_probe_success_all_cells(LANE);
    l.recover_lane(LANE);
    shim::probe_success_all(&u, DEST, now);

    for pool in ["", "pool-a", "pool-b"] {
        let legacy_after = from_legacy(l.classify(pool, LANE, now));
        let unit_after = from_unit(u.state(pool, DEST, now, &tok()));
        assert_eq!(
            legacy_after.name, "available",
            "the legacy book recovers {pool:?} on one successful probe"
        );
        assert_eq!(
            unit_after.name, legacy_after.name,
            "one successful probe against the shared upstream must recover cell {pool:?} too. \
             Recovering only the pool the probe happened to run through leaves organic traffic \
             benched against a destination that is demonstrably healthy"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 7. `try_admit` has no permit gate
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 7 (wire-visible).** The legacy peeks the concurrency permit BEFORE the probe CAS and
/// returns `AtCapacity` without ever touching the probe (`availability.rs:277-287`, whose comment
/// names the regression it fixed: a tripped-and-saturated lane won the single-flight probe, reverted
/// it when `try_acquire` failed, and so never observed a real dispatch outcome — forever). The unit
/// has no permit concept (`lib.rs:454-482`), which reintroduces exactly that wedge. `[ROUTE-1]`:
/// `try_admit` gets the permit gate.
#[test]
fn d7_an_at_capacity_admission_preserves_the_probe() {
    let l = legacy(1);
    let u = unit();
    let now = wall_secs();

    // A tripped cell whose cooldown has already expired: the next admission would win the recovery
    // probe — if it could dispatch.
    l.force_open_in("p", LANE, now.saturating_sub(1));
    shim::force_open(&u, "p", DEST, now.saturating_sub(1));

    // Saturate the lane. One permit, one holder.
    let held = l
        .try_acquire(LANE)
        .expect("the fresh lane has its one permit");

    let legacy_refusal = from_legacy(l.try_admit("p", LANE, now).map(|_| ()));
    let unit_refusal = from_unit(
        shim::try_admit(&u, "p", DEST, now, false).map_or_else(|s| s, |_| LaneState::Ready),
    );
    assert_eq!(legacy_refusal.name, "at_capacity");
    assert_eq!(
        unit_refusal.name, legacy_refusal.name,
        "a saturated lane refuses with the capacity reason, not the breaker's"
    );

    // The load-bearing half: the probe must be UNTOUCHED, so the moment a permit frees the very
    // next admission can win it.
    drop(held);
    assert!(
        l.try_admit("p", LANE, now).is_ok(),
        "the legacy book preserved the probe across the at-capacity refusal"
    );
    assert!(
        shim::try_admit(&u, "p", DEST, now, true).is_ok(),
        "the at-capacity refusal must not consume the single-flight recovery probe. Winning it and \
         dropping it leaves the cell HalfOpen with nobody probing: tripped and saturated, never \
         recovering"
    );

    // The queue path's own admission — a caller that already holds a permit from the lane's own
    // semaphore and needs the breaker re-checked, never a second permit
    // (`availability.rs:324-359`).
    let l2 = legacy(1);
    let u2 = unit();
    l2.force_open_in("p", LANE, now.saturating_add(600));
    shim::force_open(&u2, "p", DEST, now.saturating_add(600));
    assert_eq!(
        from_legacy(l2.try_admit_breaker("p", LANE, now).map(|_| ())).name,
        "breaker_open"
    );
    assert_eq!(
        from_unit(shim::try_admit_breaker(&u2, "p", DEST, now).map_or_else(|s| s, |_| LaneState::Ready)).name,
        "breaker_open",
        "a queued caller re-checks the breaker before dispatching, so a lane that tripped while it \
         waited is never dispatched onto"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 8. The lane-global aggregate and every counter disappear
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 8.** `lane_breaker_verdict`'s best-of fold (`availability.rs:14-43`) feeds `/stats`;
/// `LaneState.{ok, err, client_fault, trips, last_trip_at}` carry the two asymmetry rules the fold
/// depends on — `ok` bumps ONCE per probe, not once per cell (`availability.rs:474-476`), and `err`
/// is named-pool-only. `record_client_fault` has no unit verb at all. Without them `/stats` cannot
/// be rendered from the served book.
#[test]
fn d8_lane_global_counters_and_the_best_of_fold() {
    let (lcfg, ucfg) = cfgs(30, 120);
    let l = legacy(4);
    let u = unit();
    let now = wall_secs();

    // One pool tripped hard, one pool healthy. The lane-global fold is BEST-of, so the lane still
    // reads as usable — the aggregate must match `usable`, or `/stats` contradicts routing.
    let _ = l.record_transient_in("bad", LANE, "5xx", &lcfg, None);
    shim::observe(
        &u,
        "bad",
        DEST,
        Outcome::Transient { retry_after: None },
        &ucfg,
        now,
    );
    l.record_success_in("good", LANE);
    shim::observe(&u, "good", DEST, Outcome::Success, &ucfg, now);

    let snap = l.snapshot(LANE, now);
    assert_eq!(from_legacy(snap.availability).name, "available");
    assert_eq!(
        shim::lane_availability(&u, DEST, now).map(|a| a.name),
        Some("available"),
        "the unit must fold its cells into ONE lane-global verdict, best-of, so `/stats` cannot \
         drift from the per-cell routing verdict it is rendered beside"
    );

    // A client fault is counted, and counted SEPARATELY: it is not an error against the upstream.
    l.record_client_fault(LANE);
    shim::client_fault(&u, DEST);
    let after = l.snapshot(LANE, now);
    let unit_counters = shim::lane_counters(&u, DEST).expect(
        "the unit must carry the lane-global counters `/stats` renders: ok, err, client_fault, \
         trips, last_trip_at",
    );
    assert_eq!(unit_counters.client_fault, after.client_fault);
    assert_eq!(
        unit_counters.err, after.err,
        "`err` is named-pool-only in the legacy book (availability.rs:474-476); counting the \
         default cell too would double every pool-routed failure"
    );
    assert_eq!(unit_counters.trips, after.trips);
    assert_eq!(unit_counters.ok, after.ok);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 9. The `Unavailable` taxonomy is narrower in the unit
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 9.** `Unavailable::{Dead, AtCapacity, Shedding}` and the ONE `recovery_hint_ms`
/// every consumer reads (`substrate/store.rs:47-88`) have no unit representation, so `dead` gating
/// and the honest at-capacity floor vanish from every path that reads a refusal. The taxonomy is
/// what `Retry-After`, least-bad ranking, queue budgeting and `/stats` ALL consume — a narrower one
/// is four consumers quietly disagreeing.
#[test]
fn d9_the_unavailable_taxonomy_and_its_one_recovery_hint() {
    let now = wall_secs();
    // Every reason the legacy taxonomy can give, with the hint it gives for it. The unit must be
    // able to name each one and answer the same hint — this is a table, not a walk of the FSM,
    // because the point is the vocabulary's width, not any one transition.
    let taxonomy = [
        Unavailable::Dead,
        Unavailable::BudgetExhausted,
        Unavailable::BreakerOpen { until: now + 45 },
        Unavailable::ProbeInFlight,
        Unavailable::AtCapacity {
            drain_hint_ms: None,
        },
        Unavailable::Shedding,
    ];
    for reason in taxonomy {
        let mirrored =
            shim::lane_state_named(reason.variant_name(), now + 45).unwrap_or_else(|| {
                panic!(
                    "the unit has no way to say {:?}; a refusal it cannot name is a refusal its \
                 callers cannot rank, budget or render",
                    reason.variant_name()
                )
            });
        assert_eq!(
            shim::recovery_hint_ms(mirrored, now),
            reason.recovery_hint_ms(now),
            "{}: one definition of `when could this plausibly serve again`, or the four consumers \
             that read it disagree",
            reason.variant_name()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// 10. `hard_down_all` carries no reason
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **Difference 10.** The legacy's `record_hard_down_all_cells(lane, reason)`
/// (`availability.rs:535-593`) records the reason lane-wide and emits an operator diagnostic; the
/// unit's `hard_down_all` (`lib.rs:429-448`) carries neither, so the one event an operator most
/// needs to explain — "this destination went dark, and here is what it said" — arrives blank.
#[test]
fn d10_a_hard_down_carries_its_reason() {
    let l = legacy(4);
    let u = unit();
    let now = wall_secs();

    let fresh = l.record_hard_down_all_cells(LANE, "billing exhausted");
    let unit_fresh = shim::hard_down_all(&u, DEST, "billing exhausted", now);
    assert!(
        fresh && unit_fresh,
        "both books report the first hard-down as a fresh trip"
    );

    assert_eq!(
        shim::hard_down_reason(&u, DEST).as_deref(),
        Some(l.snapshot(LANE, now).dead_reason.as_str()),
        "the reason a destination was hard-downed is recorded against it, not discarded at the \
         call site (availability.rs:543)"
    );

    // A second hard-down is not a second trip, in either book — a persistently dead destination
    // must not re-count on every recovery-probe cycle.
    assert!(!l.record_hard_down_all_cells(LANE, "billing exhausted"));
    assert!(!shim::hard_down_all(&u, DEST, "billing exhausted", now));
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE SHIMS — what the unit can be asked TODAY, and what it cannot
// ─────────────────────────────────────────────────────────────────────────────────────────────────

mod shim {
    //! One function per call the cells above want to make. Where the unit has the verb, the shim is
    //! the call. Where it does not, the shim is the closest thing the unit can do and its doc
    //! comment names the gap — the cell then fails on the DIFFERENCE, which is the red we want,
    //! rather than on a missing symbol, which is a red nobody can run.
    //!
    //! A shim never implements the missing behaviour. Moving the legacy code into the unit means
    //! repointing the shim at the real verb and deleting the note.

    use super::{DestinationId, LaneState, Outcome, UnitCfg};
    use busbar_unit_breaker::port::{Classified, CredentialOrigin, UpstreamCode, UpstreamStatus};
    use busbar_unit_breaker::{Breaker, BreakerUnit};

    /// The lane-global counters `/stats` renders (difference 8).
    pub struct Counters {
        pub ok: u64,
        pub err: u64,
        pub client_fault: u64,
        pub trips: u64,
    }

    /// `observe`, with the jitter seed the legacy reads at exactly this point — the same reading
    /// `BreakerAdapter` takes on the root's side of the seam.
    pub fn observe(
        u: &BreakerUnit,
        pool: &str,
        dest: DestinationId,
        outcome: Outcome,
        cfg: &UnitCfg,
        now: u64,
    ) -> bool {
        u.observe(
            pool,
            dest,
            outcome,
            cfg,
            now,
            busbar_unit_breaker::clock::unix_time_nanos(),
            &super::tok(),
        )
    }

    /// Classify one upstream answer, carrying the credential provenance and the body-derived
    /// signals the recording holds.
    #[allow(clippy::too_many_arguments)]
    pub fn classify(
        u: &BreakerUnit,
        dest: DestinationId,
        status: u16,
        passthrough: bool,
        provider_code: Option<&str>,
        structured_type: Option<&str>,
        retry_after: Option<u64>,
    ) -> Classified {
        u.classify(
            dest,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(status)),
                credential: if passthrough {
                    CredentialOrigin::Passthrough
                } else {
                    CredentialOrigin::Declared
                },
                provider_code,
                structured_type,
                retry_after,
            },
        )
    }

    /// Is this destination due for a health probe?
    pub fn needs_probe(u: &BreakerUnit, dest: DestinationId, now: u64) -> bool {
        u.needs_probe(dest, now)
    }

    /// A failed out-of-band probe, recorded against every cell for the destination, each against its
    /// own pool's resolved config.
    pub fn probe_failure_all(
        u: &BreakerUnit,
        dest: DestinationId,
        now: u64,
        resolve_cfg: &dyn Fn(&str) -> UnitCfg,
        retry_after: Option<u64>,
    ) {
        u.record_probe_failure_all(
            dest,
            now,
            busbar_unit_breaker::clock::unix_time_nanos(),
            resolve_cfg,
            retry_after,
        );
    }

    /// A successful out-of-band probe: the destination is demonstrably healthy, so every cell
    /// naming it recovers.
    pub fn probe_success_all(u: &BreakerUnit, dest: DestinationId, now: u64) {
        u.record_probe_success_all(dest, now);
    }

    /// Park a cell Open with an explicit deadline (the legacy's `force_open_in`), so a cell can be
    /// put in the state a test needs without walking the FSM to it.
    pub fn force_open(u: &BreakerUnit, pool: &str, dest: DestinationId, until: u64) {
        u.force_open(pool, dest, until);
    }

    /// Admission, with the concurrency permit peeked BEFORE the probe CAS.
    pub fn try_admit(
        u: &BreakerUnit,
        pool: &str,
        dest: DestinationId,
        now: u64,
        has_permit: bool,
    ) -> Result<Option<u64>, LaneState> {
        u.try_admit_gated(pool, dest, now, || has_permit.then_some(()))
            .map(|(a, ())| a.probe_epoch)
    }

    /// The queue path's admission: re-check the breaker, never take a second permit.
    pub fn try_admit_breaker(
        u: &BreakerUnit,
        pool: &str,
        dest: DestinationId,
        now: u64,
    ) -> Result<Option<u64>, LaneState> {
        u.try_admit_breaker(pool, dest, now)
    }

    /// The lane-global availability the best-of fold produces.
    ///
    pub fn lane_availability(
        u: &BreakerUnit,
        dest: DestinationId,
        now: u64,
    ) -> Option<super::Avail> {
        Some(super::from_unit(u.lane_state(dest, now)))
    }

    /// Record a client fault — the caller's own bad input, counted apart from upstream errors.
    pub fn client_fault(u: &BreakerUnit, dest: DestinationId) {
        u.record_client_fault(dest);
    }

    /// The lane-global counters.
    pub fn lane_counters(u: &BreakerUnit, dest: DestinationId) -> Option<Counters> {
        let c = u.destination_counters(dest);
        Some(Counters {
            ok: c.ok,
            err: c.err,
            client_fault: c.client_fault,
            trips: c.trips,
        })
    }

    /// The unit's own name for a legacy `Unavailable` variant. Asked by NAME, so the two taxonomies
    /// are compared on the vocabulary an operator actually reads rather than on arm order.
    pub fn lane_state_named(name: &str, until: u64) -> Option<LaneState> {
        [
            LaneState::Ready,
            LaneState::Dead,
            LaneState::Suppressed { until },
            LaneState::ProbeInFlight,
            LaneState::BudgetExhausted,
            LaneState::AtCapacity {
                drain_hint_ms: None,
            },
            LaneState::Shedding,
        ]
        .into_iter()
        .find(|s| s.variant_name() == name)
    }

    /// When could this plausibly serve again, in ms.
    pub fn recovery_hint_ms(s: LaneState, now: u64) -> Option<u64> {
        s.recovery_hint_ms(now)
    }

    /// Hard-down every cell for the destination, recording why.
    pub fn hard_down_all(u: &BreakerUnit, dest: DestinationId, reason: &str, now: u64) -> bool {
        u.hard_down_all_with_reason(dest, reason, now)
    }

    /// Why this destination was hard-downed.
    pub fn hard_down_reason(u: &BreakerUnit, dest: DestinationId) -> Option<String> {
        u.hard_down_reason(dest)
    }
}
