//! Tests for `meter.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use busbar_caps::{KernelSeal, StepName};
use busbar_substrate::testkit::engine_kit::{EngineTestKit as _, TestAppKit};

/// The literal token figures every identity here is pinned on: eleven uncached input tokens and
/// seven output tokens, reported by the upstream and normalized by the dialect's reader.
const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// One OpenAI chat completion carrying that usage.
fn completion() -> MockResponse {
    MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "chatcmpl-meter",
            "object": "chat.completion",
            "created": 0,
            "model": "m0",
            "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                "total_tokens": INPUT + OUTPUT}
        }),
    }
}

/// What the accrual left behind, on both surfaces at once: the raw metering row the flush
/// writes, and the token ledger the budget chain enforces against.
#[derive(Debug, PartialEq, Eq)]
struct Accrued {
    row: busbar_api::MeteringRow,
    ledger_tokens: u64,
    ledger_spend_cents: i64,
}

/// A governed rig: one lane, one pool, one key, a fresh in-memory registry, and one queued
/// upstream response. Each leg of an identity gets its own, so the two accruals are compared
/// rather than summed.
async fn rig() -> (
    std::sync::Arc<crate::test_support::BuiltApp>,
    std::sync::Arc<busbar_api::VirtualKey>,
    MockServer,
) {
    crate::testkit::install_test_seams();
    let state = std::sync::Arc::new(MockServerState::new());
    state.push(completion());
    let server = MockServer::new(state).await;
    let store: std::sync::Arc<dyn busbar_api::Store> =
        std::sync::Arc::new(busbar_store_memory::MemoryStore::new());
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _) = gov_kit
        .create_key(
            busbar_substrate::governance::NewKeySpec {
                name: "meter".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let mut builder = TestApp::new()
        .lane(
            LaneSpec::new("m0", crate::proto_codec::PROTO_OPENAI, &server.base_url())
                .provider("zai"),
        )
        .pool("p", &[(0, 1)]);
    TestAppKit::set_governance(&mut builder, gov_kit);
    (builder.build(), std::sync::Arc::new(key), server)
}

/// The sink the admit step builds and every accrual site carries to the end of the response.
fn sink(
    host: &Arc<dyn EngineHost>,
    key: &std::sync::Arc<busbar_api::VirtualKey>,
    charged_at: u64,
) -> crate::engine::UsageSink {
    crate::engine::UsageSink {
        gov: host.governance().expect("governance is configured"),
        cost: host.cost(),
        key: key.clone(),
        pool: std::sync::Arc::from("p"),
        charged_at,
        admit: None,
    }
}

/// Read both accrual surfaces for one key.
fn accrued(
    app: &std::sync::Arc<crate::test_support::BuiltApp>,
    key_id: &str,
    charged_at: u64,
) -> Accrued {
    let gov = app.governance.clone().expect("governance is configured");
    let derived = gov
        .usage_for(&app.cost, key_id, charged_at)
        .expect("usage read")
        .expect("the key exists");
    gov.flush_metering();
    let rows = gov
        .metering_for(busbar_substrate::governance::metering_bucket(charged_at))
        .expect("metering read");
    let mut mine: Vec<_> = rows.into_iter().filter(|r| r.key_id == key_id).collect();
    assert_eq!(mine.len(), 1, "one response, one metering cell");
    Accrued {
        row: mine.remove(0),
        ledger_tokens: derived.tokens,
        ledger_spend_cents: derived.spend_cents,
    }
}

/// A kernel seal for the length of one test.
fn tokens() -> (KernelSeal, UnitToken<Meter>, UsageToken) {
    let seal = KernelSeal::acquire_for_kernel();
    let unit = UnitToken::mint(&seal);
    let usage = UsageToken::mint(&seal);
    (seal, unit, usage)
}

/// THE METERED IDENTITY. The row a delivered response leaves behind is the same row whether the
/// live buffered tap accrued it or this step did — field for field, on a separate registry
/// each, so nothing is being compared with itself.
///
/// The literal: one row for `(key, m0, zai)` carrying `tokens_input = 11`, `tokens_output = 7`,
/// both cache tiers `0`, and `requests = billable_requests = 1`; and a token ledger of 18
/// tokens at zero cents, because a rig with no rate card prices every tier at zero and the fee
/// is the door's, not the meter's.
#[tokio::test]
async fn the_step_accrues_the_same_metering_row_as_the_live_tap() {
    // LEG 1 — a real forwarded request, metered by the live tap at the end of the response.
    let (app, key, server) = rig().await;
    let charged_at = busbar_substrate::store::now();
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let resp = crate::engine::forward_with_pool(
        &app,
        vec![crate::engine::WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(&serde_json::json!({
            "model": "p", "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap()
        .into(),
        None,
        "p",
        None,
        crate::proto_codec::PROTO_OPENAI,
        crate::test_support::CHAT,
        Some(sink(&host, &key, charged_at)),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "the response is served");
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    let live = accrued(&app, &key.id, charged_at);
    assert_eq!(
        live,
        Accrued {
            row: busbar_api::MeteringRow {
                key_id: key.id.clone(),
                model: "m0".to_string(),
                provider: "zai".to_string(),
                tokens_input: INPUT,
                tokens_output: OUTPUT,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
            },
            ledger_tokens: INPUT + OUTPUT,
            ledger_spend_cents: 0,
        },
        "the live tap's row and ledger, in full"
    );
    server.shutdown().await;

    // LEG 2 — the step, on its own registry, over the same reported usage.
    let (app2, key2, server2) = rig().await;
    let (host2, rt2) = crate::engine::test_host_rt(&app2);
    let reported = busbar_substrate::billing::TokenUsage {
        input: INPUT,
        output: OUTPUT,
        ..Default::default()
    };
    let sink2 = sink(&host2, &key2, charged_at);
    let tables = crate::engine::EngineTables::new(&rt2);
    let lane = &tables.lanes()[0];
    let ctx = MeterCtx::new(
        &host2,
        Some(&sink2),
        Some(lane),
        Some(&reported),
        200,
        true,
        false,
    );
    let (seal, unit_token, usage_token) = tokens();
    let metered = meter(&unit_token, &usage_token, &ctx, None, &Outcome::Completed);

    assert_eq!(
        metered.row.as_ref().expect("a served response is metered"),
        &busbar_api::MeteringRow {
            key_id: key2.id.clone(),
            model: "m0".to_string(),
            provider: "zai".to_string(),
            tokens_input: INPUT,
            tokens_output: OUTPUT,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
        },
        "the step reports the row it accrued"
    );
    let step = accrued(&app2, &key2.id, charged_at);
    assert_eq!(
        step.row.model, live.row.model,
        "both metered the SERVING lane's config name"
    );
    assert_eq!(step.row.provider, live.row.provider);
    assert_eq!(
        (
            step.row.tokens_input,
            step.row.tokens_output,
            step.row.tokens_cache_read,
            step.row.tokens_cache_write,
            step.row.requests,
            step.row.billable_requests
        ),
        (
            live.row.tokens_input,
            live.row.tokens_output,
            live.row.tokens_cache_read,
            live.row.tokens_cache_write,
            live.row.requests,
            live.row.billable_requests
        ),
        "field for field, the step's row is the live tap's row"
    );
    assert_eq!(step.ledger_tokens, live.ledger_tokens);
    assert_eq!(step.ledger_spend_cents, live.ledger_spend_cents);

    // Read BEFORE the decision is taken out of the answer: `into_result` moves that field, and a
    // partially moved value cannot be asked a question about itself afterwards.
    let compensating = metered.compensating();
    let fee_count = metered.fee_count;

    // The usage report the posting is made against: one line per non-zero tier, summing to
    // exactly what was metered.
    let usage = metered
        .decision
        .into_result(&seal)
        .expect("a delivered response proceeds");
    assert_eq!(usage.total(), INPUT + OUTPUT);
    assert_eq!(usage.lines().len(), 2, "two tiers reported, two lines");
    assert!(!usage.is_estimated(), "the destination reported this");
    assert_eq!(
        fee_count, 1,
        "a delivered 2xx from an upstream posts the flat fee"
    );
    assert!(
        !compensating,
        "a delivered unit posts its one line and asks for nothing to be undone"
    );
    server2.shutdown().await;
}

/// THE FAILED-TRANSFER IDENTITY. The fee is decided by the LEG and the client-facing status, and
/// by nothing else — and a unit that did not earn it simply never earns it.
///
/// Read the rows together: they are the whole fee rule, and it is now the whole money rule for an
/// ended unit. A 2xx from an upstream leg earns the flat fee; a 502 does not; a 404 raised after
/// the door does not; and a 2xx that never dialled an upstream does not, because a kernel verb is
/// not a proxied request. The admission count the door drew is untouched by all of it, so a cap
/// still cannot be escaped by failing.
///
/// The door's `charged` used to be a column here, because a failure had to reverse a fee the door
/// had already taken. It is not an input any more: the fee is a line of the unit's own end-of-unit
/// posting, so there is nothing standing for a failure to take back and no shape of an ending that
/// asks for one.
#[test]
fn the_fee_is_decided_by_the_status_and_the_leg() {
    let host: Arc<dyn EngineHost> =
        busbar_substrate::testkit::engine_host(&crate::test_support::TestApp::new().build());
    let (_seal, unit_token, usage_token) = tokens();
    for (status, upstream_leg, fee, why) in [
        (
            200u16,
            true,
            1u32,
            "delivered over an upstream leg earns the fee",
        ),
        (502, true, 0, "a failed transfer never earns it"),
        (
            200,
            false,
            0,
            "no upstream leg, so no flat fee: a kernel verb is not a proxied request",
        ),
        (
            404,
            true,
            0,
            "a post-admission 404 delivered nothing, so it earns nothing",
        ),
    ] {
        let ctx = MeterCtx::new(&host, None, None, None, status, upstream_leg, false);
        let metered = meter(&unit_token, &usage_token, &ctx, None, &Outcome::Completed);
        assert_eq!(metered.fee_count, fee, "{why}: fee_count");
        assert!(!metered.compensating(), "{why}: nothing is ever taken back");
        assert!(
            metered.row.is_none(),
            "{why}: nothing to attribute, so nothing metered"
        );
    }
}

/// A stream that ended in an error bills ZERO tokens — the accrual is skipped, not floored —
/// and the fee it already earned is not taken back.
///
/// The two halves are deliberately different: the tokens follow the evidence (there is none
/// that survived the error), and the fee follows the status that was settled at the first frame
/// relayed to the client, which a later abort does not reverse.
#[test]
fn a_stream_that_died_bills_zero_tokens_and_keeps_the_fee_it_earned() {
    let host: Arc<dyn EngineHost> =
        busbar_substrate::testkit::engine_host(&crate::test_support::TestApp::new().build());
    let (seal, unit_token, usage_token) = tokens();
    let reported = busbar_substrate::billing::TokenUsage {
        input: INPUT,
        output: OUTPUT,
        ..Default::default()
    };
    let ctx = MeterCtx::new(&host, None, None, Some(&reported), 200, true, true);
    let metered = meter(
        &unit_token,
        &usage_token,
        &ctx,
        None,
        &Outcome::Failed(
            StepName::Route,
            busbar_caps::ReasonCode::DestinationUnreachable,
        ),
    );
    assert_eq!(
        metered.fee_count, 1,
        "the 2xx that went out is not reversed"
    );
    assert!(
        !metered.compensating(),
        "the client saw a success, and nothing about this end is a correction"
    );
    assert!(metered.row.is_none(), "nothing was accrued");
    let usage = metered.decision.into_result(&seal).expect("still a report");
    assert_eq!(
        usage.total(),
        0,
        "the tokens seen before the error are evidence, not a charge"
    );
    assert!(usage.lines().is_empty());
}

/// The step is the `Units::meter` row's shape, as a value.
#[test]
fn the_step_has_the_meters_shape() {
    let _: MeterStep = meter;
}

/// The two token figures the priced accrual is pinned on, chosen so no arithmetic over them
/// coincides with their sum: a hundred in and fifty out.
const PRICED_INPUT: u64 = 100;
const PRICED_OUTPUT: u64 = 50;

/// The card the accrual is priced against, keyed by the SERVING lane's config name — the only
/// key space a rate card is allowed to use, and the same key the metering row attributes to.
///
/// Two micro-units per input token and six per output token, which the one config-to-integer
/// projection turns into 2_000 and 6_000 nano-units per token. The two tiers are priced
/// DIFFERENTLY on purpose: a card that priced them alike could not tell a money figure from a
/// token count, which is the whole thing under test.
fn priced_card() -> busbar_core::cost::CostModel {
    busbar_core::cost::CostModel::resolve_parts(
        Some(&std::collections::BTreeMap::from([(
            "m0".to_string(),
            busbar_core::config::RateEntryCfg {
                input_utok: 2.0,
                output_utok: 6.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
            },
        )])),
        0,
        &Default::default(),
    )
}

/// A rig whose deployment carries [`priced_card`], one lane named for it, and governance — so
/// the sink the door pins carries a card that actually prices something. No upstream is dialled
/// here: this test drives the step directly over a usage report the reader already produced.
fn priced_rig() -> (
    std::sync::Arc<busbar_core::state::App>,
    std::sync::Arc<busbar_api::VirtualKey>,
) {
    crate::testkit::install_test_seams();
    let store: std::sync::Arc<dyn busbar_api::Store> =
        std::sync::Arc::new(busbar_store_memory::MemoryStore::new());
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _) = gov_kit
        .create_key(
            busbar_substrate::governance::NewKeySpec {
                name: "priced".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("create key");
    let mut builder = TestApp::new()
        .lane(
            LaneSpec::new("m0", crate::proto_codec::PROTO_OPENAI, "http://127.0.0.1:9")
                .provider("zai"),
        )
        .pool("p", &[(0, 1)])
        .cost(priced_card());
    TestAppKit::set_governance(&mut builder, gov_kit);
    (builder.build(), std::sync::Arc::new(key))
}

/// THE STEP PRICES NOTHING, AND THE HOLD RIDES THROUGH UNTOUCHED.
///
/// Money model ruling 3: PRICE IS NEVER STORED. Money is a read-time conversion - quantity times
/// the rate row in force for (lane, class) at the line's instant - so a plane does not carry an
/// amount and cannot spend one against a reservation. Ruling 6 says what the reservation is FOR:
/// an in-memory hold that gives an exact cap under concurrency, released when the line is written,
/// and never itself a ledger line.
///
/// So a hold handed to this step comes back exactly as it arrived. Nothing is accrued against it
/// here, because the figure that would be accrued does not exist on this side of the seam.
///
/// THIS TEST REPLACES `a_spend_past_the_reservation_is_carried_out_as_an_overdraft`, and the
/// replacement is the point rather than a casualty of it. That test pinned the step asking a
/// `Worth` closure what its report came to, spending the answer with `h.spend(priced, 0)`, and
/// carrying whatever ran past the reservation out as an overdraft note. Every one of those three
/// acts is the plane holding a money figure, which is what ruling 3 removes: the overdraft it
/// measured was an artefact of pricing against a reservation sized by a guess made at the door
/// before a single upstream token existed. Priced at read time there is no guess to run past.
///
/// It failed before this commit with the hold coming back accrued by the priced total and its
/// remaining reservation at zero.
#[test]
fn the_step_spends_nothing_against_the_hold() {
    use busbar_caps::{step::Admit as AdmitStep, AdmitToken, KernelSeal, PrincipalId};

    let (app, key) = priced_rig();
    let (host, rt) = crate::engine::test_host_rt(&app);
    let reported = busbar_substrate::billing::TokenUsage {
        input: PRICED_INPUT,
        output: PRICED_OUTPUT,
        ..Default::default()
    };
    let sink = sink(&host, &key, busbar_substrate::store::now());
    let tables = crate::engine::EngineTables::new(&rt);
    let ctx = MeterCtx::new(
        &host,
        Some(&sink),
        Some(&tables.lanes()[0]),
        Some(&reported),
        200,
        true,
        false,
    );

    let seal = KernelSeal::acquire_for_kernel();
    // Deliberately SMALLER than what the old pricing seam would have made of this response, so a
    // step that priced anything at all could not come back clean.
    const RESERVED: u64 = 100_000;
    let hold = busbar_caps::Hold::open(
        &AdmitToken::<AdmitStep>::mint(&seal),
        PrincipalId::new(&key.id),
        RESERVED,
    );
    let metered = meter(
        &UnitToken::<Meter>::mint(&seal),
        &UsageToken::mint(&seal),
        &ctx,
        Some(hold),
        &Outcome::Completed,
    );

    let hold = metered.hold.expect("the hold rides back out to the exit");
    assert_eq!(
        hold.accrued(),
        0,
        "the step accrues nothing: what a line is worth is answered when it is READ, not here"
    );
    assert_eq!(
        hold.overdraft(),
        0,
        "and with nothing spent there is nothing to run past the reservation"
    );
    assert_eq!(
        hold.remaining(),
        RESERVED,
        "the whole reservation is still there for the exit to release"
    );

    // AND THE REPORT IS STILL THERE, in the classes' own units. This is the half the superseded
    // `the_accrual_against_the_reservation_is_the_priced_total_not_the_token_count` also pinned,
    // kept because it is the other side of the same law: dropping the money figure must not drop
    // the QUANTITIES, which are what the posting is evidence for and what a read-time conversion
    // has to have to convert at all. A step that reported nothing would come back with a clean
    // hold too, and the two must be tellable apart.
    let usage = metered
        .decision
        .into_result(&seal)
        .expect("a delivered response proceeds");
    assert_eq!(usage.lines().len(), 2, "two tiers reported, two lines");
    assert_eq!(
        usage.total(),
        PRICED_INPUT + PRICED_OUTPUT,
        "the quantity sum is still there to be read; it is simply not the money"
    );
}

/// SEALING IS NOT POSTING, and the step has to say which it did.
///
/// A unit reaches this step in one of two states. Either the walk was handed the admission's
/// meter half and its tap has already made this unit's one accrual — in which case the step
/// SEALS: it reports the row and spends the money, and it must not touch the ledger a second
/// time. Or the walk held no meter half, and the step IS the accrual. `MeterFacts::accrued` is
/// the fact that separates them, and the walk carries the answer forward as `posted_here` so the
/// rehearsal can assert one posting per unit.
///
/// The instrument it carries it on is `Metered::row`, and a row is not that fact. A row is a
/// truthful report of what the response consumed and it is filled on BOTH sides of the branch —
/// deliberately, because sealing is not a reason to report nothing. So `row.is_some()` answers
/// "there was something to attribute", which is a different question, and it answers `true` for
/// a unit whose accrual was made somewhere else entirely.
///
/// Two legs, each on its own registry so neither reads the other's rows. Same host, same sink,
/// same lane, same reported usage; the only difference is which side of the branch the unit is
/// on. The registries prove the branch itself works — one accrual on the posting leg, none on
/// the sealing leg. The pair the walk reads has to tell them apart too.
#[test]
fn the_step_says_whether_it_posted_or_only_sealed() {
    let reported = busbar_substrate::billing::TokenUsage {
        input: INPUT,
        output: OUTPUT,
        ..Default::default()
    };
    let (_seal, unit_token, usage_token) = tokens();

    // LEG 1 — the walk held no meter half, so this step is the accrual.
    let (app1, key1) = priced_rig();
    let charged_at = busbar_substrate::store::now();
    let (host1, rt1) = crate::engine::test_host_rt(&app1);
    let sink1 = sink(&host1, &key1, charged_at);
    let tables1 = crate::engine::EngineTables::new(&rt1);
    let posting = meter(
        &unit_token,
        &usage_token,
        &MeterCtx::new(
            &host1,
            Some(&sink1),
            Some(&tables1.lanes()[0]),
            Some(&reported),
            200,
            true,
            false,
        ),
        None,
        &Outcome::Completed,
    );
    assert_eq!(
        accrued(&app1, &key1.id, charged_at).ledger_tokens,
        INPUT + OUTPUT,
        "the walk held no sink, so the step made the unit's one accrual"
    );

    // LEG 2 — the walk's tap already accrued this unit, so this step only seals.
    let (app2, key2) = priced_rig();
    let (host2, rt2) = crate::engine::test_host_rt(&app2);
    let sink2 = sink(&host2, &key2, charged_at);
    let tables2 = crate::engine::EngineTables::new(&rt2);
    let facts = MeterFacts {
        lane: Some(0),
        usage: Some(reported.clone()),
        status: 200,
        billing_failed: false,
        upstream_leg: true,
        accrued: true,
    };
    let sealing = meter(
        &unit_token,
        &usage_token,
        &MeterCtx::bind(&host2, Some(&sink2), Some(&tables2.lanes()[0]), &facts),
        None,
        &Outcome::Completed,
    );
    let gov2 = app2.governance.clone().expect("governance is configured");
    gov2.flush_metering();
    assert!(
        gov2.metering_for(busbar_substrate::governance::metering_bucket(charged_at))
            .expect("metering read")
            .iter()
            .all(|r| r.key_id != key2.id),
        "the tap owns this unit's accrual, so the step posted nothing on top of it"
    );

    // Both legs report a row, because both had something to attribute — which is exactly why a
    // row cannot be the answer to "who posted".
    assert!(posting.row.is_some(), "the posting leg reports its row");
    assert!(
        sealing.row.is_some(),
        "the sealing leg reports the same row"
    );

    // What the walk carries forward as `posted_here`.
    assert_eq!(
        (posting.posted, sealing.posted),
        (true, false),
        "the step that made the accrual says so; the step that only sealed one says it did not"
    );
}

/// A UNIT ASKS FOR NO COMPENSATING POSTING - the money model's ruling 2, as a property of the step.
///
/// "You hand me the item, I pay the exact amount": a unit posts ONE line when it ends, carrying
/// what it actually delivered. There is no earlier charge for that line to correct, so there is
/// nothing for the end of a unit to take back.
///
/// The property is stated over EVERY ending this step can produce rather than over one of them,
/// because "nothing is ever reversed" is a claim about the whole surface and a single row cannot
/// carry it. Delivered, failed, refused-after-the-door, and never-dialled: none of them asks for a
/// second act against the books.
///
/// WHAT IT CAUGHT. Before this commit the step answered a `refund` beside its fee, and the answer
/// depended on the door's `charged`: two units that ended the same way - a 502 that delivered
/// nothing over an upstream leg - were distinguishable, and the charged one was carrying a
/// compensating posting for a fee the door had taken as a lookahead. Run against that code this
/// test failed on the charged 502, `left: (0, false, true)` against `right: (0, false, false)`.
/// The door's answer is not an input to this step any more, so the difference cannot be spelled.
#[test]
fn no_ended_unit_asks_for_a_compensating_posting() {
    let host: Arc<dyn EngineHost> =
        busbar_substrate::testkit::engine_host(&crate::test_support::TestApp::new().build());
    let (_seal, unit_token, usage_token) = tokens();

    for (status, upstream_leg, billing_failed, why) in [
        (200u16, true, false, "delivered over an upstream leg"),
        (502, true, false, "a failed transfer that delivered nothing"),
        (
            404,
            true,
            false,
            "refused after the door, so charged but undelivered",
        ),
        (200, false, false, "a 2xx that never dialled an upstream"),
        (
            200,
            true,
            true,
            "a stream whose end carried a terminal error",
        ),
    ] {
        let ctx = MeterCtx::new(
            &host,
            None,
            None,
            None,
            status,
            upstream_leg,
            billing_failed,
        );
        let metered = meter(&unit_token, &usage_token, &ctx, None, &Outcome::Completed);
        assert!(
            !metered.compensating(),
            "{why}: the unit posts one line at its end and asks for nothing to be undone"
        );
    }
}
