// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTANCE TESTS FOR THE FAILOVER SEAM.
//!
//! Five claims, and each one is checked rather than asserted in prose:
//!
//! 1. a dead upstream fails fast and is NAMED, on both planes, through the SAME breaker;
//! 2. a caller reaches an equivalent upstream when the first is Open, with no client-visible error;
//! 3. a non-repeatable call is NOT retried, by default;
//! 4. a THIRD plane costs a candidate type and nothing else;
//! 5. the pins are CHECKED, so "interchangeable" is a fact and not a claim.

use super::*;
use crate::store::{BreakerCfg, HealthState, LaneRuntime};

/// A store with `n` lanes and nothing else. `make_lane_data_with_weight` is the model plane's own
/// test lane constructor, reused verbatim: the LANE TABLE is the same table, which is half the reason
/// the breaker below is provably the same breaker.
fn store_with(n: usize) -> HealthState {
    let lanes = (0..n)
        .map(|i| crate::store::make_lane_data_with_weight(i, 8).0)
        .collect();
    HealthState::new(lanes)
}

// ══ THE MCP CANDIDATE ════════════════════════════════════════════════════════════════════════════
//
// One MCP server, deployed twice. `pin` is the APPROVED SCHEMA DIGEST of the tool being called on
// that server — a value busbar already computes and stores; nothing here is a new artifact.

struct ToolServer {
    name: &'static str,
    lane: usize,
    pin: Option<&'static str>,
}

impl Candidate for ToolServer {
    fn name(&self) -> &str {
        self.name
    }
    fn lane(&self) -> usize {
        self.lane
    }
    fn interchange_key(&self) -> Option<&str> {
        self.pin
    }
}

// ══ THE A2A CANDIDATE ════════════════════════════════════════════════════════════════════════════
//
// Two registrations of the same agent, verified against the same card. `pin` is the approved
// canonical CARD FINGERPRINT — again, a value that already exists.

struct AgentReg {
    name: &'static str,
    lane: usize,
    card_fingerprint: Option<&'static str>,
}

impl Candidate for AgentReg {
    fn name(&self) -> &str {
        self.name
    }
    fn lane(&self) -> usize {
        self.lane
    }
    fn interchange_key(&self) -> Option<&str> {
        self.card_fingerprint
    }
}

/// The same image in two regions: the digests agree because the artifact is the same artifact.
const SEARCH_DIGEST: &str =
    "sha256:1f9c0e6b5a4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0918273645566";

fn two_regions() -> Vec<ToolServer> {
    vec![
        ToolServer {
            name: "search-eu",
            lane: 0,
            pin: Some(SEARCH_DIGEST),
        },
        ToolServer {
            name: "search-us",
            lane: 1,
            pin: Some(SEARCH_DIGEST),
        },
    ]
}

fn two_agent_regions() -> Vec<AgentReg> {
    vec![
        AgentReg {
            name: "planner@eu",
            lane: 0,
            card_fingerprint: Some("sha256:cafe0000"),
        },
        AgentReg {
            name: "planner@us",
            lane: 1,
            card_fingerprint: Some("sha256:cafe0000"),
        },
    ]
}

// ══ PROOF 1 — A DEAD UPSTREAM FAILS FAST AND IS NAMED, ON BOTH PLANES ════════════════════════════

/// MCP. The primary's breaker cell is Open with a cooldown that has NOT expired, and there is nothing
/// else in the pool. The seam does not hang, does not dispatch, and NAMES the candidate and the
/// reason.
#[test]
fn mcp_a_dead_upstream_fails_fast_and_is_named() {
    let store = store_with(2);
    let now = 1_000;
    store.force_open_in("mcp/pool:search", 0, now + 60);

    let members = vec![ToolServer {
        name: "search-eu",
        lane: 0,
        pin: Some(SEARCH_DIGEST),
    }];
    let err = walk(
        &store,
        "mcp/pool:search",
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search-eu/search_code",
        },
        now,
    )
    .expect_err("an Open primary with no sibling has nowhere to go");

    match &err {
        Refusal::NoneAdmissible { pool, tried } => {
            assert_eq!(pool, "mcp/pool:search");
            assert_eq!(tried.len(), 1, "the one candidate is named: {tried:?}");
            assert_eq!(tried[0].0, "search-eu", "the DEAD upstream is named");
            assert!(
                matches!(
                    tried[0].1,
                    crate::store::Unavailable::BreakerOpen { until } if until == now + 60
                ),
                "and WHY, with the exact recovery deadline: {:?}",
                tried[0].1
            );
        }
        other => panic!("expected NoneAdmissible, got {other}"),
    }
    assert_eq!(err.reason(), crate::audit::vocab::REASON_NO_UPSTREAM_LEFT);
}

/// A2A, through the identical call. Same seam, same breaker, a different candidate type and nothing
/// else — which is the claim the whole unit rests on.
#[test]
fn a2a_a_dead_upstream_fails_fast_and_is_named() {
    let store = store_with(2);
    let now = 2_000;
    store.force_open_in("a2a/pool:planner", 0, now + 30);

    let members = vec![AgentReg {
        name: "planner@eu",
        lane: 0,
        card_fingerprint: Some("sha256:cafe0000"),
    }];
    let err = walk(
        &store,
        "a2a/pool:planner",
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "planner@eu/message:send",
        },
        now,
    )
    .expect_err("an Open primary with no sibling has nowhere to go");

    match &err {
        Refusal::NoneAdmissible { tried, .. } => {
            assert_eq!(tried[0].0, "planner@eu");
            assert!(matches!(
                tried[0].1,
                crate::store::Unavailable::BreakerOpen { until } if until == now + 30
            ));
        }
        other => panic!("expected NoneAdmissible, got {other}"),
    }
    assert_eq!(err.reason(), crate::audit::vocab::REASON_NO_UPSTREAM_LEFT);
}

/// IT IS THE SAME BREAKER, shown rather than asserted. The seam only ever reaches the breaker through
/// `LaneRuntime::try_admit_breaker`, so this test drives that method DIRECTLY against the same
/// `(pool, lane)` cell the seam used and shows the two agree — the same Open verdict, the same
/// deadline. If the seam had grown a second breaker, the cell it tripped would not be this cell.
#[test]
fn the_seam_and_the_model_plane_share_one_breaker_cell() {
    let store = store_with(2);
    let now = 3_000;
    const POOL: &str = "mcp/pool:search";
    store.force_open_in(POOL, 0, now + 45);

    // The model plane's queue-dispatch admission, called exactly as `proxy/engine/walk.rs:275` calls
    // it, on the cell the seam is about to consult.
    let direct = store.try_admit_breaker(POOL, 0, now);
    assert!(
        matches!(direct, Err(crate::store::Unavailable::BreakerOpen { until }) if until == now + 45),
        "the model plane's own admission sees the cell Open: {direct:?}"
    );

    // The seam, on the same pool and the same lane, reaches the same verdict — because it IS that
    // call. A second breaker would have its own state and would admit here.
    let members = vec![ToolServer {
        name: "search-eu",
        lane: 0,
        pin: Some(SEARCH_DIGEST),
    }];
    match walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search_code",
        },
        now,
    ) {
        Err(Refusal::NoneAdmissible { tried, .. }) => assert!(
            matches!(tried[0].1, crate::store::Unavailable::BreakerOpen { until } if until == now + 45),
            "the seam reads the SAME cell: {:?}",
            tried[0].1
        ),
        other => panic!("expected the same Open verdict, got {other:?}"),
    }
}

// ══ PROOF 2 — REROUTE ════════════════════════════════════════════════════════════════════════════

/// **THE SENTENCE THIS UNIT EXISTS TO MAKE TRUE:** your search MCP server, deployed in two regions;
/// one goes down mid-run, the call completes on the other, and the agent never learns it happened.
///
/// The EU deployment's breaker is Open. Nothing has been sent. The seam reroutes to the US
/// deployment, and the caller receives an `Admitted` — not an error, not a degraded answer, not a
/// retry it has to perform. The pins agree because it is the same image, so busbar CHECKED that the
/// two are the same deployment rather than taking the operator's word for it.
#[test]
fn your_search_server_in_two_regions_one_dies_and_the_agent_never_learns() {
    let store = store_with(2);
    let now = 4_000;
    const POOL: &str = "mcp/pool:search";
    store.force_open_in(POOL, 0, now + 60);

    let members = two_regions();
    let admitted = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            // NOT declared repeatable, and it does not need to be: nothing has been sent, so this
            // is a reroute and not a retry. That is the entire point of the `Stage` split.
            repeatable: Repeatable::No,
            operation: "search-eu/search_code",
        },
        now,
    )
    .expect("the second region takes the call");

    // `candidate()` returns a `&'a C` borrowed from the members slice, NOT from `admitted`, so it
    // stays valid after `into_token()` consumes the admission below.
    let cand = admitted.candidate();
    assert_eq!(cand.name(), "search-us");
    assert_eq!(admitted.position(), 1, "a reroute happened");
    // The reroute lands on the HEALTHY (Closed-ready) US region, which wins NO single-flight recovery
    // probe — so the admission token is `None`, not the cell's current epoch. This is the phantom-token
    // fix: an armed guard/release built on a non-probe admit could revert a probe a peer legitimately
    // won on the same cell; representing "won no probe" as `None` means no guard is ever built here.
    // (Before the fix this returned `Some(<cell's current epoch>)`.)
    assert_eq!(
        admitted.into_token(),
        None,
        "a reroute to a healthy Closed lane wins no probe, so it owns no owner token to release"
    );

    // No client-visible error: the caller got a candidate, and the successful outcome closes the
    // cell it was admitted on, exactly as any model-plane dispatch would.
    record_success(&store, POOL, cand);
    assert_eq!(
        store.breaker_state_in(POOL, 1),
        crate::store::BreakerState::Closed
    );
}

/// The A2A analogue, which is the same shape and therefore the same test: two registrations of one
/// agent verified against one card.
#[test]
fn two_registrations_of_one_agent_reroute_the_same_way() {
    let store = store_with(2);
    let now = 5_000;
    const POOL: &str = "a2a/pool:planner";
    store.force_open_in(POOL, 0, now + 60);

    let members = two_agent_regions();
    let admitted = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::No,
            operation: "planner/message:send",
        },
        now,
    )
    .expect("the second registration takes the call");
    assert_eq!(admitted.candidate().name(), "planner@us");
}

/// A TRANSIENT FAILURE ON THE PRIMARY IS WHAT EVENTUALLY OPENS THE CELL, and the next request
/// reroutes before its first byte. This is the end-to-end shape: dispatch, fail, trip, reroute —
/// through the ONE classifier (`crate::breaker::classify`) and the ONE breaker.
#[test]
fn a_transient_failure_trips_the_primary_and_the_next_request_reroutes() {
    let store = store_with(2);
    let now = crate::store::now();
    const POOL: &str = "mcp/pool:search";
    let members = two_regions();
    // A cooldown long enough that the trip is still in force on the follow-up request.
    let cfg = BreakerCfg {
        base_cooldown_secs: 600,
        ..BreakerCfg::default()
    };

    // Request one lands on the primary.
    let first = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search_code",
        },
        now,
    )
    .expect("a healthy pool admits its primary");
    assert_eq!(first.candidate().name(), "search-eu");

    // …and the upstream 503s. ONE classifier decides what that means.
    let signal = crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::ServerError,
        provider_signal: Some("503".into()),
        retry_after: None,
    };
    // Enough consecutive transients to cross the trip threshold whatever it is configured to.
    let mut disposition = crate::breaker::Disposition::ClientFault;
    for _ in 0..16 {
        disposition = record_outcome(&store, POOL, first.candidate(), &signal, &cfg);
    }
    assert_eq!(disposition, crate::breaker::Disposition::TransientUpstream);
    assert!(
        matches!(
            store.breaker_state_in(POOL, 0),
            crate::store::BreakerState::Open { .. }
        ),
        "the primary's cell tripped: {:?}",
        store.breaker_state_in(POOL, 0)
    );

    // Request two — a NEW request, nothing sent — reroutes before its first byte.
    let second = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::No,
            operation: "search_code",
        },
        now,
    )
    .expect("the surviving region takes it");
    assert_eq!(second.candidate().name(), "search-us");
}

// ══ PROOF 3 — THE SAFETY RULE ════════════════════════════════════════════════════════════════════

/// **A NON-REPEATABLE CALL IS NOT RETRIED, BY DEFAULT.** `send_email` went out, the dispatch failed,
/// and there is a perfectly healthy second deployment sitting right there. busbar does NOT use it.
///
/// This is the assertion the whole unit is safety-gated on: blind the `Repeatable::No` arm in
/// `walk` and this test goes red naming the second email.
#[test]
fn a_non_repeatable_call_is_not_retried_by_default() {
    let store = store_with(2);
    let now = 6_000;
    const POOL: &str = "mcp/pool:mailer";
    let members = vec![
        ToolServer {
            name: "mailer-eu",
            lane: 0,
            pin: Some(SEARCH_DIGEST),
        },
        ToolServer {
            name: "mailer-us",
            lane: 1,
            pin: Some(SEARCH_DIGEST),
        },
    ];
    // The second deployment is HEALTHY. Nothing about the upstreams stops this hop; the RULE does.
    assert!(store.try_admit_breaker(POOL, 1, now).is_ok());
    store.release_probe_in(POOL, 1);

    let err = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            // Position 0 was dispatched to and it failed.
            tried: &[0],
            stage: Stage::AfterDispatch,
            // Nothing was declared, so this is the DEFAULT for every operation an operator has not
            // spoken about.
            repeatable: Repeatable::No,
            operation: "mailer-eu/send_email",
        },
        now,
    )
    .expect_err("send_email must not be sent twice");

    match &err {
        Refusal::NotRepeatable { pool, operation } => {
            assert_eq!(pool, POOL);
            assert_eq!(operation, "mailer-eu/send_email");
        }
        other => panic!(
            "a second send_email was permitted — busbar just sent the customer two emails: {other}"
        ),
    }
    assert_eq!(err.reason(), crate::audit::vocab::REASON_NOT_REPEATABLE);
    assert_eq!(err.pool(), POOL, "and the audit resource names the pool");
    assert!(
        err.to_string().contains("a second effect"),
        "the operator is told WHY, not just no: {err}"
    );
}

/// The safe half, so the rule is a rule and not a ban. A READ is declared repeatable by the operator
/// who vouched for the tool, and it does move to the second deployment after a failed dispatch.
#[test]
fn a_declared_repeatable_read_is_retried_after_a_failed_dispatch() {
    let store = store_with(2);
    let now = 7_000;
    const POOL: &str = "mcp/pool:search";
    let members = two_regions();

    let admitted = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[0],
            stage: Stage::AfterDispatch,
            repeatable: Repeatable::Yes,
            operation: "search-eu/search_code",
        },
        now,
    )
    .expect("a read declared safe to repeat may be repeated");
    assert_eq!(admitted.candidate().name(), "search-us");
}

/// The rule is about a REPEAT, not about the stage word. A request that has dispatched to NOTHING yet
/// is not repeating anything, so an empty `tried` is admitted whatever the stage says.
#[test]
fn the_first_selection_is_never_a_repeat() {
    let store = store_with(2);
    let now = 8_000;
    let members = two_regions();
    let admitted = walk(
        &store,
        "mcp/pool:search",
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::AfterDispatch,
            repeatable: Repeatable::No,
            operation: "send_email",
        },
        now,
    )
    .expect("nothing has been tried, so nothing is being repeated");
    assert_eq!(admitted.position(), 0);
}

// ══ PROOF 5 — INTERCHANGEABILITY IS CHECKED, NOT CLAIMED ═════════════════════════════════════════

/// Two DIFFERENT servers that both offer a tool called `search`. The operator put them in one pool.
/// Their approved digests differ, so busbar refuses to move a request between them and says exactly
/// which fingerprints disagreed — rather than routing an agent's call to a tool carrying different
/// instructions.
#[test]
fn two_different_servers_are_refused_however_the_operator_declared_them() {
    let store = store_with(2);
    let now = 9_000;
    const POOL: &str = "mcp/pool:search";
    store.force_open_in(POOL, 0, now + 60);

    let members = vec![
        ToolServer {
            name: "acme-search",
            lane: 0,
            pin: Some(SEARCH_DIGEST),
        },
        ToolServer {
            name: "globex-search",
            lane: 1,
            pin: Some("sha256:deadbeef"),
        },
    ];
    let err = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search",
        },
        now,
    )
    .expect_err("different artifacts are not one deployment");

    match &err {
        Refusal::NotInterchangeable { primary, other, .. } => {
            assert_eq!(primary, "acme-search");
            assert_eq!(other, "globex-search");
        }
        other => panic!("expected NotInterchangeable, got {other}"),
    }
    assert_eq!(
        err.reason(),
        crate::audit::vocab::REASON_NOT_INTERCHANGEABLE
    );
}

/// NOTHING APPROVED YET IS NOT A WILDCARD, and two of them are not a match. A pending registration
/// can never be failed over to, and two pending registrations are two unknowns rather than one fact.
#[test]
fn an_unapproved_candidate_never_matches_not_even_another_unapproved_one() {
    let store = store_with(2);
    let now = 10_000;
    const POOL: &str = "mcp/pool:search";
    store.force_open_in(POOL, 0, now + 60);

    let members = vec![
        ToolServer {
            name: "fresh-a",
            lane: 0,
            pin: None,
        },
        ToolServer {
            name: "fresh-b",
            lane: 1,
            pin: None,
        },
    ];
    let err = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search",
        },
        now,
    )
    .expect_err("two unknowns are not one fact");
    assert!(matches!(err, Refusal::NotInterchangeable { .. }), "{err}");
    assert!(
        err.to_string().contains("<nothing approved>"),
        "the operator is told the registration is pending, not that it is wrong: {err}"
    );
}

/// An EMPTY pool is an operator error and is reported as one, not as an outage.
#[test]
fn an_empty_pool_is_an_operator_error_and_says_so() {
    let store = store_with(1);
    let members: Vec<ToolServer> = Vec::new();
    let err = walk(
        &store,
        "mcp/pool:nothing",
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "search",
        },
        11_000,
    )
    .expect_err("a pool with no members admits nothing");
    assert!(matches!(err, Refusal::Empty { .. }), "{err}");
    assert_eq!(err.reason(), crate::audit::vocab::REASON_NO_UPSTREAM_LEFT);
}

// ══ PROOF 4 — A THIRD PLANE COSTS A CANDIDATE TYPE AND NOTHING ELSE ══════════════════════════════
//
// The analogue of `audit`'s `a_fourth_stream_costs_a_record_type_and_nothing_else`. Everything below
// this line is what a plane busbar DOES NOT HAVE would have to write in order to select, admit, trip
// and reroute. It is one struct and one three-method impl. There is no breaker here, no walk, no
// error type, no config parser and no retry policy — those are inherited, and if they were not, this
// file would not compile without them.

/// A plane busbar does not have: a satellite ground-station link. Two dishes pointed at the same
/// bird, which is the same "one deployment, two places" shape MCP and A2A have — and the only thing
/// this plane has to say about it.
struct GroundStation {
    name: &'static str,
    lane: usize,
    /// This plane's pin: the ephemeris the two dishes are tracking. Two stations tracking the same
    /// ephemeris are talking to the same spacecraft.
    ephemeris: Option<&'static str>,
}

impl Candidate for GroundStation {
    fn name(&self) -> &str {
        self.name
    }
    fn lane(&self) -> usize {
        self.lane
    }
    fn interchange_key(&self) -> Option<&str> {
        self.ephemeris
    }
}

/// THE ACCEPTANCE TEST FOR THE SEAM. The throwaway plane above selects, admits, trips and reroutes,
/// and every one of those verbs is core's.
#[test]
fn a_third_plane_costs_a_candidate_type_and_nothing_else() {
    let store = store_with(2);
    let now = crate::store::now();
    const POOL: &str = "sat/pool:downlink";
    let members = vec![
        GroundStation {
            name: "goldstone",
            lane: 0,
            ephemeris: Some("tle:25544"),
        },
        GroundStation {
            name: "madrid",
            lane: 1,
            ephemeris: Some("tle:25544"),
        },
    ];

    // SELECT + ADMIT — inherited.
    let first = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "downlink",
        },
        now,
    )
    .expect("a healthy pool admits its primary");
    assert_eq!(first.candidate().name(), "goldstone");

    // TRIP — inherited, through the one classifier and the one breaker.
    let cfg = BreakerCfg {
        base_cooldown_secs: 600,
        ..BreakerCfg::default()
    };
    let signal = crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::Network,
        provider_signal: Some("link_loss".into()),
        retry_after: None,
    };
    for _ in 0..16 {
        record_outcome(&store, POOL, first.candidate(), &signal, &cfg);
    }
    assert!(matches!(
        store.breaker_state_in(POOL, 0),
        crate::store::BreakerState::Open { .. }
    ));

    // REROUTE — inherited.
    let second = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::No,
            operation: "downlink",
        },
        now,
    )
    .expect("the other dish takes it");
    assert_eq!(second.candidate().name(), "madrid");

    // …and so is the SAFETY RULE, without this plane writing a retry policy.
    let err = walk(
        &store,
        POOL,
        &members,
        &Attempt {
            tried: &[0],
            stage: Stage::AfterDispatch,
            repeatable: Repeatable::No,
            operation: "uplink_command",
        },
        now,
    )
    .expect_err("a command that already went up is not sent again");
    assert!(matches!(err, Refusal::NotRepeatable { .. }), "{err}");

    // …and so is the PIN CHECK: a dish tracking a different bird is refused.
    let wrong = vec![
        GroundStation {
            name: "goldstone",
            lane: 0,
            ephemeris: Some("tle:25544"),
        },
        GroundStation {
            name: "canberra",
            lane: 1,
            ephemeris: Some("tle:43013"),
        },
    ];
    let err = walk(
        &store,
        POOL,
        &wrong,
        &Attempt {
            tried: &[],
            stage: Stage::BeforeFirstByte,
            repeatable: Repeatable::Yes,
            operation: "downlink",
        },
        now,
    )
    .expect_err("a different spacecraft is not the same deployment");
    assert!(matches!(err, Refusal::NotInterchangeable { .. }), "{err}");
}

// ══ THE DISPOSITION IS CAUSE-ATTRIBUTED, on these planes too ═════════════════════════════════════

/// A CALLER'S BAD ARGUMENTS DO NOT PENALISE AN UPSTREAM. This is the property the model plane has had
/// since ADR-0002 and the one an MCP plane most needs: a client looping on a malformed `tools/call`
/// would otherwise trip a healthy server out of the pool.
#[test]
fn a_client_fault_never_trips_a_plane_upstream() {
    let store = store_with(2);
    const POOL: &str = "mcp/pool:search";
    let members = two_regions();
    let cfg = BreakerCfg::default();
    let signal = crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::ClientError,
        provider_signal: Some("400".into()),
        retry_after: None,
    };
    for _ in 0..64 {
        assert_eq!(
            record_outcome(&store, POOL, &members[0], &signal, &cfg),
            crate::breaker::Disposition::ClientFault
        );
    }
    assert_eq!(
        store.breaker_state_in(POOL, 0),
        crate::store::BreakerState::Closed,
        "sixty-four malformed calls must not bench a healthy server"
    );
}

/// AN AUTH FAILURE IS A HARD DOWN, not a slow bleed — and it is hard down in EVERY cell, because a
/// credential the upstream rejects is rejected for every pool fronting it.
#[test]
fn an_auth_failure_hard_downs_the_plane_upstream_everywhere() {
    let store = store_with(2);
    const POOL: &str = "mcp/pool:search";
    let members = two_regions();
    let cfg = BreakerCfg::default();
    let signal = crate::breaker::CanonicalSignal {
        class: crate::breaker::StatusClass::Auth,
        provider_signal: Some("401".into()),
        retry_after: None,
    };
    assert_eq!(
        record_outcome(&store, POOL, &members[0], &signal, &cfg),
        crate::breaker::Disposition::HardDown
    );
    assert!(matches!(
        store.breaker_state_in(POOL, 0),
        crate::store::BreakerState::Open { .. }
    ));
    assert!(
        matches!(
            store.breaker_state_in("mcp/pool:other", 0),
            crate::store::BreakerState::Open { .. }
        ),
        "a rejected credential is rejected in every pool fronting the same upstream"
    );
}
