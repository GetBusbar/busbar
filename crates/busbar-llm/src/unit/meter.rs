// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 6 — **Meter**: what the unit actually used, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::meter` row: the step's own unit token, the usage
//! token the report is sealed with, the request's context and the provisional end, answering with
//! `Decision<Meter>` carrying the `Usage` the exit path settles against.
//!
//! # The body is today's accrual, unchanged
//!
//! One call: `engine::usage::ledger_and_meter`, with the same four arguments the live taps pass —
//! the stream-end tap in `FirstByteBody`, its drop-time partial, and the buffered tap on the
//! cross-protocol path. Behind it are the two host seams, `meter_ledger` (the tier split against
//! the key's budget chain, in the window the pinned arrival epoch names) and `meter_series` (the
//! raw per-model consumption row). This step calls them once, in that order, exactly as today.
//!
//! # Where the money is
//!
//! **The fee basis is the client-facing status, decided once.** The flat per-request fee posts on a
//! 2xx and on nothing else, and it is decided at the first frame relayed to the CLIENT — which is
//! why a buffered cross-protocol response whose upstream 2xx became a client 502 posts no fee and
//! no tokens. Once decided it is never reversed by a later abort: a 2xx stream that dies mid-way
//! posts its fee, because the caller got the value that was on the wire when the status was
//! settled. The fee is a lookahead at the door and a posting here, and this step reports which.
//!
//! **The refund rule is one counter, not two.** A non-2xx end refunds the fee base
//! (`billable_requests`) and never the admission count (`requests`). That asymmetry is the whole
//! design: the caller is not billed a flat fee for a failure outside its control, and a thousand
//! failed requests still consume a thousand slots, so a cap cannot be escaped by hammering
//! failures. A refund is only ever issued for a request whose charge LANDED — the admit step's
//! `charged` — because the refund is a blind decrement of a shared window counter, and issuing one
//! for a request that never charged erodes some other request's spend in the same window. It lands
//! in the window the pinned arrival epoch names, which is the window the charge landed in, so a
//! request that straddles a boundary refunds where it charged.
//!
//! **A stream that ends in an error bills ZERO tokens.** Not the tokens observed before the error,
//! and not a floor: the accrual is skipped entirely, exactly as the live taps skip it when the
//! translator reports a terminal error or an abort. The figures observed either side of it are
//! evidence, and evidence is not a charge.
//!
//! **A response that reports no usage bills ZERO and still counts its request.** The token ledger
//! is untouched — nothing is charged to the key's budget — and the metering series records one
//! request for the serving model with every tier at zero. Dropping the row because the tiers were
//! empty would make the request count and the consumption disagree about the same response.
//!
//! # The hold, and the settle that is not here
//!
//! Meter computes; the exit path settles. There are exactly two places a hold is taken out of its
//! cell — the exit and the node's sweep — and a third would be a unit that could post twice. So
//! this step takes the hold, accrues against it, and hands it straight back for the exit to close;
//! it never builds a `Posted`. What it does own is the report the posting is made against.

use std::sync::Arc;

use busbar_caps::{
    step::Meter, Decision, Hold, MeterClassId, Outcome, QuantitySource, UnitToken, Usage,
    UsageLine, UsageToken,
};
use busbar_contract::ClassDirection;
use busbar_substrate::plane_host::EngineHost;

/// What the accrual needs that the step shape has nowhere to put.
///
/// Built by the Route step out of what the response actually was, so every figure here is observed
/// rather than assumed: the status the CLIENT saw, the lane that actually answered post-failover,
/// and the usage the dialect's reader found — or did not.
pub struct MeterCtx<'a> {
    host: &'a Arc<dyn EngineHost>,
    sink: Option<&'a crate::engine::UsageSink>,
    lane: Option<&'a crate::engine::Lane>,
    usage: Option<&'a busbar_substrate::billing::TokenUsage>,
    status: u16,
    charged: bool,
    upstream_leg: bool,
    billing_failed: bool,
}

impl<'a> MeterCtx<'a> {
    /// Bind the step to one response.
    ///
    /// `status` is the status the CLIENT saw, never the upstream's — the fee is decided from the
    /// client-facing frame. `charged` is the admit step's: whether the admission charge landed, and
    /// therefore whether there is anything a non-2xx could refund. `upstream_leg` says the unit
    /// routed to an upstream, which is what makes it a fee-bearing client request rather than a
    /// kernel verb or a delivery. `billing_failed` is the terminal-error/abort fact the stream taps
    /// read off the translator.
    ///
    /// `allow(dead_code)` while the module is dark: the Route step is what builds one of these on
    /// the request path, and it does not exist yet.
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn new(
        host: &'a Arc<dyn EngineHost>,
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        usage: Option<&'a busbar_substrate::billing::TokenUsage>,
        status: u16,
        charged: bool,
        upstream_leg: bool,
        billing_failed: bool,
    ) -> Self {
        MeterCtx {
            host,
            sink,
            lane,
            usage,
            status,
            charged,
            upstream_leg,
            billing_failed,
        }
    }

    /// Whether the client saw a success. The one reading the fee and the refund both key off.
    #[must_use]
    pub fn delivered(&self) -> bool {
        matches!(self.status, 200..=299)
    }
}

/// The step's answer, plus what the Audit step and the exit path read.
///
/// [`Metered::decision`] is exactly what the kernel's `Units::meter` returns. The hold rides back
/// out untouched by anything but its accrual, because settling it is the exit's and only the
/// exit's.
pub struct Metered {
    /// The sealed step-6 answer: the usage report the posting is made against.
    pub decision: Decision<Meter>,
    /// The unit's reservation, handed back for the exit path to settle. Never settled here: there
    /// are two places a hold leaves its cell and this is not one of them.
    pub hold: Option<Hold>,
    /// The metering row this response accrued — one request for the serving model, with the token
    /// split preserved. `None` when there was no key or no serving lane to attribute it to, which
    /// is the only case in which nothing is metered at all.
    pub row: Option<busbar_api::MeteringRow>,
    /// Whether the flat per-request fee posts: 1 on a delivered 2xx from an upstream leg, 0
    /// otherwise. Decided here, from the client-facing status, and never reversed later.
    pub fee_count: u32,
    /// Whether the Audit step must refund the fee base. True exactly when the admission charge
    /// landed and the client did not see a 2xx.
    pub refund: bool,
}

impl Metered {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Meter> {
        self.decision
    }
}

/// The shape of this step, as a value — the `Units::meter` row with the plane's own context.
///
/// The kernel's row also takes the hold implicitly, through the cell; here it is passed and
/// returned explicitly, because a plane holds no cell and the point is that the hold leaves this
/// step exactly as it arrived plus its accrual.
pub type MeterStep =
    for<'a> fn(&UnitToken<Meter>, &UsageToken, &MeterCtx<'a>, Option<Hold>, &Outcome) -> Metered;

/// The four reserved meter classes, in the canonical order the pricer prices them.
///
/// Named from the neutral reserved-unit spellings rather than any dialect's wire field, because the
/// readers already normalize every dialect onto them: input is UNCACHED input, and the two cache
/// tiers are ADDITIVE, so the four partition what the response consumed on every provider.
const CLASS_INPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_INPUT);
const CLASS_OUTPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_OUTPUT);
const CLASS_CACHE_READ: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_READ);
const CLASS_CACHE_WRITE: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_WRITE);

/// Step 6. Fold what the legs reported, accrue it, and say what the posting is made against.
///
/// The provisional end is carried for the record and does not lower the fee: the fee was decided
/// at the frame that carried the status, and a unit that ended badly after that still delivered
/// what the caller was billed for.
pub fn meter(
    unit_token: &UnitToken<Meter>,
    usage_token: &UsageToken,
    ctx: &MeterCtx<'_>,
    hold: Option<Hold>,
    _provisional: &Outcome,
) -> Metered {
    let delivered = ctx.delivered();
    // A stream whose end carried a terminal error, or whose translation aborted, bills ZERO: the
    // accrual is skipped, not floored. The figures seen before the error are evidence only.
    let bills = !ctx.billing_failed;
    let reported = if bills { ctx.usage } else { None };

    // THE LIVE ACCRUAL, unchanged: the tier split onto the key's budget chain in the pinned
    // window, then the raw per-model series row. Both through the one seam the stream-end tap,
    // its drop-time partial and the buffered tap already call.
    let mut row = None;
    if bills {
        if let (Some(sink), Some(lane)) = (ctx.sink, ctx.lane) {
            let tier = reported
                .map(crate::engine::usage::tier_usage)
                .unwrap_or_default();
            crate::engine::usage::ledger_and_meter(ctx.host, sink, lane, reported, &tier);
            row = Some(metering_row(sink, lane, reported));
        }
    }

    // The report the posting is made against: one line per non-zero tier, in canonical order. A
    // response that reported nothing reports no lines — zero, not a floor, because that is what the
    // older release bills when an upstream tells it nothing.
    let mut lines = Vec::new();
    if let Some(u) = reported {
        push_line(&mut lines, CLASS_INPUT, ClassDirection::Input, u.input);
        push_line(&mut lines, CLASS_OUTPUT, ClassDirection::Response, u.output);
        push_line(
            &mut lines,
            CLASS_CACHE_READ,
            ClassDirection::CacheRead,
            u.cache_read.unwrap_or(0),
        );
        push_line(
            &mut lines,
            CLASS_CACHE_WRITE,
            ClassDirection::CacheWrite,
            u.cache_creation.unwrap_or(0),
        );
    }
    let usage = Usage::report(usage_token, lines).expect("four tiers fit any record");

    // The hold, accrued against and handed straight back. Nothing settles here.
    let hold = hold.map(|mut h| {
        let _ = h.accrue(usage.total());
        h
    });

    Metered {
        decision: Decision::proceed(unit_token, usage),
        hold,
        row,
        // The fee is the KIND of leg and the client-facing status, and nothing else: one per
        // delivered client request that routed to an upstream.
        fee_count: u32::from(delivered && ctx.upstream_leg),
        // The refund is owed only where a charge landed and the client did not see a 2xx — and it
        // is owed against the fee base alone.
        refund: ctx.charged && !delivered,
    }
}

/// One line, if the tier carries anything. A zero-quantity line is not a fact about anything.
fn push_line(
    lines: &mut Vec<UsageLine>,
    class: MeterClassId,
    direction: ClassDirection,
    quantity: u64,
) {
    if quantity == 0 {
        return;
    }
    lines.push(UsageLine {
        class,
        quantity,
        // The figure came from the destination's own response, read at the locator the dialect's
        // reader knows — not from a byte count of ours. The four directions are what partitions the
        // tiers: uncached input, the response, and the two additive cache sides.
        source: QuantitySource::Locator {
            direction,
            ptr: busbar_caps::LocatorPtr::new(class.as_str()),
        },
        estimated: false,
    });
}

/// The metering row this response accrues, in the shape the flush writes to the store.
///
/// The MODEL is the config name of the SERVING lane — the lane that actually answered, after any
/// failover — because that is the key the rate card is written against; the wire name a lane sends
/// upstream is not an accounting key. A delivered response always counts its request, whatever it
/// consumed.
fn metering_row(
    sink: &crate::engine::UsageSink,
    lane: &crate::engine::Lane,
    usage: Option<&busbar_substrate::billing::TokenUsage>,
) -> busbar_api::MeteringRow {
    busbar_api::MeteringRow {
        key_id: sink.key.id.clone(),
        model: lane.model.clone(),
        provider: lane.provider.clone(),
        tokens_input: usage.map(|u| u.input).unwrap_or(0),
        tokens_output: usage.map(|u| u.output).unwrap_or(0),
        tokens_cache_read: usage.and_then(|u| u.cache_read).unwrap_or(0),
        tokens_cache_write: usage.and_then(|u| u.cache_creation).unwrap_or(0),
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    }
}

#[cfg(test)]
mod tests {
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
        std::sync::Arc<busbar_core::state::App>,
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
        app: &std::sync::Arc<busbar_core::state::App>,
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
            metered.fee_count, 1,
            "a delivered 2xx from an upstream posts the flat fee"
        );
        assert!(!metered.refund, "a 2xx refunds nothing");
        server2.shutdown().await;
    }

    /// THE FAILED-TRANSFER IDENTITY. A charged request that did not deliver a 2xx refunds the fee
    /// base and NEVER the admission count, and it refunds only where the charge landed.
    ///
    /// Read the four rows together: they are the whole refund rule. A 502 on a charged request owes
    /// a refund; the same 502 on a request admitted without charging owes none, because the refund
    /// is a blind decrement that would erode another request's spend in the same window; and a 2xx
    /// owes none either way. The fee is the mirror image, and it is the LEG plus the client-facing
    /// status that decides it, never the refund.
    #[test]
    fn the_fee_and_the_refund_are_decided_by_the_status_and_the_charge() {
        let host: Arc<dyn EngineHost> = busbar_substrate::testkit::engine_host(
            &busbar_core::test_support::TestApp::new().build(),
        );
        let (_seal, unit_token, usage_token) = tokens();
        for (status, charged, upstream_leg, fee, refund, why) in [
            (200u16, true, true, 1u32, false, "delivered and charged"),
            (
                502,
                true,
                true,
                0,
                true,
                "a failed transfer refunds the fee base",
            ),
            (
                502,
                false,
                true,
                0,
                false,
                "admitted without charging, so there is nothing to refund",
            ),
            (
                200,
                true,
                false,
                0,
                false,
                "no upstream leg, so no flat fee: a kernel verb is not a proxied request",
            ),
            (
                404,
                true,
                true,
                0,
                true,
                "a post-admission 404 is charged, unbilled and refunded",
            ),
        ] {
            let ctx = MeterCtx::new(
                &host,
                None,
                None,
                None,
                status,
                charged,
                upstream_leg,
                false,
            );
            let metered = meter(&unit_token, &usage_token, &ctx, None, &Outcome::Completed);
            assert_eq!(metered.fee_count, fee, "{why}: fee_count");
            assert_eq!(metered.refund, refund, "{why}: refund");
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
        let host: Arc<dyn EngineHost> = busbar_substrate::testkit::engine_host(
            &busbar_core::test_support::TestApp::new().build(),
        );
        let (seal, unit_token, usage_token) = tokens();
        let reported = busbar_substrate::billing::TokenUsage {
            input: INPUT,
            output: OUTPUT,
            ..Default::default()
        };
        let ctx = MeterCtx::new(&host, None, None, Some(&reported), 200, true, true, true);
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
        assert!(!metered.refund, "the client saw a success");
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
}
