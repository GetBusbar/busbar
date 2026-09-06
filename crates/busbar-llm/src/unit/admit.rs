// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 4 — **Admit**: the door, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::admit` row. The signature below is that row's,
//! argument for argument — the step's own unit token, the admit token the hold is opened with, the
//! request's context, the principal and the verified set — and it hands back the same sealed
//! answer, `Decision<Admit>`, alongside the plane-side facts the Route, Meter and Audit steps read.
//!
//! # The body is today's door, unchanged
//!
//! One call: `EngineHost::admission_check`, with the same arguments the live path passes to
//! `EngineHost::admission_door` at `native_ingress.rs`'s `drive`, minus the one the door needs only
//! to post its own refusal. Behind that seam is core's `admit_check` →
//! `GovState::try_admit`, which is the check-then-charge at the tag: pass one tests every bucket of
//! the pool-filtered chain and returns on the first blocking one having charged nothing, pass two
//! charges `requests` and `billable_requests` on every bucket under the same shard guards. Nothing
//! here re-implements any part of that, and nothing here may: a request the older release admitted
//! is admitted here, and one it refused is refused here, at the same bucket, on the same metric,
//! with the same retry hint.
//!
//! # Where the money is
//!
//! **The charge point is here and nowhere earlier.** Everything before this step — the pool ACL,
//! the fallback-pool ACL, the no-rate check — turns a request away having charged nothing, and
//! ends through the not-charged terminal. Everything from this step onward has been charged, and
//! ends through the charged terminal. That line is what makes the two refusal doors mean different
//! things, and moving a check across it changes what a caller is billed. In particular candidate
//! resolution and the model-miss 404 stay *after* this call, in the Route step: a 404 for a name
//! that resolved to no lane is a charged 404, and resolving names earlier would silently make it
//! free.
//!
//! **The refusal is free.** A door refusal has charged nothing, so nothing is refunded and nothing
//! may be. The refund is a blind decrement of a shared window counter; issuing one for a request
//! that never charged erodes another request's spend in the same window. The door has already
//! RENDERED the refusal by the time it returns it — those are the bytes the client gets, and this
//! step carries them through untouched rather than re-deriving them from the reason code.
//!
//! **It has not POSTED it.** That is what `admission_check` is for and what `admission_door` is
//! not: the door's own arm finishes its refusal through the not-charged terminal, which for a plane
//! whose terminal is its own Audit step would put a second link on a unit that ends at that step
//! anyway. This step takes the check, carries the unposted bytes out on [`Admitted::refusal`], and
//! the Audit step is the single place any unit of this plane is sealed — the over-budget path
//! included.
//!
//! **The fee is a lookahead, not a posting.** The flat per-request fee enters the budget
//! comparison inside `try_admit` (derived spend plus the fee against the cap) and is *posted* by
//! the billable count this step charges. A non-2xx end refunds that count — the fee base — and
//! never the admission `requests` count, so a caller cannot escape a request cap by failing.
//!
//! # The hold
//!
//! The hold this step opens is accounting. It sizes a reservation; it never refuses a unit the
//! decision admitted, and an under-sized one tops up or posts an overdraft rather than turning
//! anyone away. That is why it is opened at zero here: the pricer that sizes it against the
//! verified set is the ledger phase's, and a hold sized wrong is invisible to a caller, whereas a
//! hold that gated admission would not be. What the hold does carry from this step is the identity
//! it was opened for and the fact that the door said yes — which is what the exit path needs to
//! settle it exactly once.

use std::sync::Arc;

use axum::response::Response;
use busbar_caps::{
    step::Admit, Admission, AdmitToken, Decision, Hold, PrincipalId, ReasonCode, Refusal,
    UnitToken, VerifiedDestination,
};
use busbar_substrate::plane_host::EngineHost;

/// What one destination name resolves to, as the accrual scope has to read it.
///
/// The three arms are the shipped candidate resolution's three answers, and they are kept apart
/// because the accrual scope differs between the first two: a configured pool accrues under its own
/// name, and a bare model lane belongs to no pool and accrues under the DEFAULT (empty) cell, which
/// is the cell the shipped release charges it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// A configured pool. `has_lane` is false for a pool with no member left to route to — which is
    /// admitted rather than refused, and draws a slot, exactly as the shipped release charges it.
    Pool {
        /// Whether the pool has any member to route to.
        has_lane: bool,
    },
    /// A bare model name that names one lane directly.
    Lane,
    /// The name names nothing this node has. The charged model-miss 404 is the Route step's, and it
    /// is charged precisely because this step already ran.
    Miss,
}

impl Resolved {
    /// The cell an accrual on this destination scopes to, given the name that resolved.
    fn cell(self, name: &str) -> &str {
        match self {
            // A bare lane routes on the default cell, exactly as the shipped path opens its sink.
            Resolved::Lane => "",
            Resolved::Pool { .. } | Resolved::Miss => name,
        }
    }

    /// Whether there is an upstream to route to — the fact that makes a client unit draw a request
    /// slot and post the flat fee.
    fn has_lane(self) -> bool {
        match self {
            Resolved::Pool { has_lane } => has_lane,
            Resolved::Lane => true,
            Resolved::Miss => false,
        }
    }
}

/// The deployment, as this step reads it.
pub trait DestinationCells {
    /// What one name resolves to.
    fn resolve(&self, name: &str) -> Resolved;
}

/// THE DEPLOYMENT, as the door reads one on a live node.
///
/// Read through the Route step's own candidate resolution rather than through a second reading of
/// the tables: the cell this answers with is the cell the walk will route on, because it is the same
/// call that produces it.
impl DestinationCells for crate::engine::NativeRuntime {
    fn resolve(&self, name: &str) -> Resolved {
        match crate::unit::route::candidates(self, name) {
            // The pool cell rides back as the destination's own name for a pool and as the empty
            // default cell for a bare lane, which is the one bit that tells the two apart.
            Some((cands, "")) => {
                debug_assert_eq!(cands.len(), 1, "a bare model name names exactly one lane");
                Resolved::Lane
            }
            Some((cands, _)) => Resolved::Pool {
                has_lane: !cands.is_empty(),
            },
            None => Resolved::Miss,
        }
    }
}

/// What the door needs that the step shape has nowhere to put.
///
/// The pinned arrival epoch is the important one: both the flat fee charged here and the token fee
/// charged at stream end are attributed to the window this epoch implies, so a request whose
/// response completes in a later window than its headers arrived cannot split its two charges
/// across two windows.
///
/// There is no start instant here, and that absence is the point: the only thing the door ever
/// needed one for was observing the finish-stage latency of the refusal it posted itself, and it no
/// longer posts one. The instant travels with the step that does.
pub struct AdmitCtx<'a> {
    /// The neutral host seam the door is reached through.
    pub host: &'a Arc<dyn EngineHost>,
    /// The ONE question this step asks of the deployment: what the destination the charge landed on
    /// RESOLVES to. Two answers this step hands on are the resolution's and not the caller's
    /// spelling — the cell the sink accrues under, and whether there is an upstream to route to at
    /// all — and asking here is what keeps them from being read off the pre-downgrade name.
    ///
    /// A view rather than the tables themselves, for the same reason the Verify step's guards take
    /// one: the engine's runtime is this crate's own machinery and a step's context is named by the
    /// composition root, which may not name it.
    pub cells: &'a dyn DestinationCells,
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The ingress protocol name, for the refusal's native error envelope.
    pub proto: &'static str,
    /// The destination the caller named: a pool, or a model that resolves to one lane.
    pub destination: &'a str,
    /// The pinned header-arrival epoch every charge and every refund lands in.
    pub charged_at: u64,
}

/// The door's answer, plus what the later steps read.
///
/// [`Admitted::decision`] is exactly what the kernel's `Units::admit` returns. The rest is the
/// plane's own: which pool the charge actually landed on, whether it landed at all, the meter half
/// of the hold, and — on a refusal — the bytes the door already rendered.
pub struct Admitted {
    /// The sealed step-4 answer.
    pub decision: Decision<Admit>,
    /// Whether the charge LANDED. `false` means the request was admitted without charging
    /// (governance off, or no key resolved), and a non-2xx end must NOT refund: the refund is a
    /// blind decrement that would erode another request's spend in the same window.
    pub charged: bool,
    /// `Some` when a budget `on_exhaust: downgrade` re-pooled the admission. The charge landed on
    /// THIS pool's buckets, so the dispatch follows it — accounting follows the traffic.
    pub effective_pool: Option<String>,
    /// Whether the verified set offered an upstream to route to, which is what makes a client unit
    /// draw a request slot and post the flat fee.
    pub upstream_candidate: bool,
    /// The stream-end metering sink: the hold's meter half. It carries the admission's in-flight
    /// concurrency gauges, which release when its last clone drops — i.e. when the response stream
    /// completes or the request unwinds — so it is built here, with the admission, and never later.
    ///
    /// Read by the Route step, which carries it to every accrual site, and by Meter — both of which
    /// now exist, so the `allow(dead_code)` this field used to carry has been deleted rather than
    /// left to cover a reader that arrived.
    pub(crate) sink: Option<crate::engine::UsageSink>,
    /// The door's own rendered refusal — bytes, not a posted record. Present exactly when the
    /// decision refuses, and handed to the Audit step's not-charged terminal there and nowhere
    /// else, so this path has the same single terminal every other path has.
    pub refusal: Option<Response>,
}

impl Admitted {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Admit> {
        self.decision
    }
}

/// The shape of this step, as a value — the `Units::admit` row with the plane's own context.
///
/// The kernel's row takes a `UnitCtx` the kernel owns and this crate cannot name: a plane is a
/// plugin on the neutral ABI and does not depend on the kernel. So the context is the plane's, and
/// everything else — the two tokens, the principal, the verified set, the sealed answer — is the
/// kernel's own vocabulary, named at `busbar-caps` where a plugin is entitled to name it.
pub type AdmitStep = for<'a, 'b> fn(
    &UnitToken<Admit>,
    &AdmitToken<Admit>,
    &AdmitCtx<'a>,
    &PrincipalId,
    &'b [VerifiedDestination],
) -> Admitted;

/// Step 4. Ask the door, and open the hold its yes entitles the unit to.
///
/// Two of the facts this step hands on are about the destination the charge LANDED on, and the door
/// is where that stops being the caller's spelling: a budget `on_exhaust: downgrade` re-pools the
/// admission, and the verified set this step is handed was built over the pre-downgrade name. So
/// "which cell does the accrual scope to" and "is there an upstream to route to" are both asked of
/// the effective name, through the same resolution the Route step walks with.
///
/// The verified set is therefore NOT what says whether there is an upstream: it answers about a pool
/// the charge may no longer be on. Every destination this plane verifies is an upstream lane, so the
/// two agree wherever nothing was downgraded — which is every request that is not re-pooled, and is
/// why the difference is invisible until one is.
pub fn admit(
    unit_token: &UnitToken<Admit>,
    admit_token: &AdmitToken<Admit>,
    ctx: &AdmitCtx<'_>,
    principal: &PrincipalId,
    // The set the Verify step sealed, over the name the caller asked for. It is the loop's row and
    // it is deliberately not read here: see this function's header for why the two facts that used
    // to be read off it are asked of the effective destination instead.
    _destinations: &[VerifiedDestination],
) -> Admitted {
    // THE door, taken without its terminal. Its `Err` is the refusal ALREADY rendered in the
    // ingress protocol's native envelope and NOT yet posted — nothing was charged, so nothing is
    // refunded on the way out, and the one place it is sealed is the Audit step.
    match ctx
        .host
        .admission_check(ctx.gov, ctx.proto, ctx.destination, ctx.charged_at)
    {
        Err(resp) => refused(unit_token, *resp),
        Ok((admit, downgraded)) => {
            // `Some` iff the charge landed. Governance off or no resolved key admits without
            // charging, and that request must finish with `charged = false`.
            let charged = admit.is_some();
            // A budget downgrade re-pooled the admission: the accrual scope is the pool the charge
            // landed on, not the one the caller asked for, so the effective name is the one
            // resolved below.
            let effective = downgraded.as_deref().unwrap_or(ctx.destination);
            // WHAT THE EFFECTIVE NAME RESOLVES TO, asked once and read twice — the same resolution
            // the shipped path runs before it opens its own sink, so the two cannot answer
            // differently about one name.
            //
            // THE ACCRUAL SCOPE IS THE CELL, not the caller's spelling of the destination. Opening
            // the sink on the raw name instead attributes a by-model request's token accrual to a
            // pool bucket named after the model — a bucket the shipped release never charges.
            let resolved = ctx.cells.resolve(effective);
            let sink = crate::native_ingress::usage_sink(
                ctx.host,
                ctx.gov,
                resolved.cell(effective),
                ctx.charged_at,
                admit,
            );
            Admitted {
                // The hold is opened at zero: it is accounting, and sizing it is the ledger
                // phase's. See this module's header for why a small hold cannot refuse anyone.
                decision: Decision::proceed(
                    unit_token,
                    Admission::Own(Hold::open(admit_token, principal.clone(), 0)),
                ),
                charged,
                upstream_candidate: resolved.has_lane(),
                effective_pool: downgraded,
                sink,
                refusal: None,
            }
        }
    }
}

/// A door refusal: no hold, no charge, no refund, no posted link, and the door's own bytes carried
/// through to the one step that posts.
///
/// The reason code is the record's closed vocabulary, and it is READ off the answer rather than
/// assumed: the door stamps which bucket blocked on the refusal it hands back, so an administratively
/// frozen group and a saturated in-flight cap are filed as what they are rather than both as a spent
/// budget. Filing all three under one reason makes a record that cannot tell an operator whether a
/// key was frozen or a caller was simply too fast — and those need different answers.
///
/// NOTHING THE CLIENT SEES MOVES. The stamp rides on the response's extensions, which are dropped
/// when the response is written; the byte-exact refusal — the status, the `kind`, the message and
/// the retry hint an SDK reads — is the response itself, carried through untouched rather than
/// re-derived from the code. The retry hint is lifted onto the refusal so the record carries the
/// same number the wire does.
///
/// A refusal carrying no stamp is filed as over-budget, which is what this step filed before there
/// was a stamp to read and is the honest reading of a door that did not say.
fn refused(unit_token: &UnitToken<Admit>, resp: Response) -> Admitted {
    let reason = match resp
        .extensions()
        .get::<busbar_substrate::plane_host::AdmissionBlock>()
    {
        Some(busbar_substrate::plane_host::AdmissionBlock::GroupFrozen) => ReasonCode::GroupFrozen,
        Some(busbar_substrate::plane_host::AdmissionBlock::RateLimited) => ReasonCode::RateLimited,
        Some(busbar_substrate::plane_host::AdmissionBlock::OverBudget) | None => {
            ReasonCode::OverBudget
        }
    };
    let mut refusal = Refusal::new(reason);
    if let Some(secs) = retry_after_secs(&resp) {
        refusal = refusal.retry_after(secs);
    }
    Admitted {
        decision: Decision::refuse(unit_token, refusal),
        charged: false,
        effective_pool: None,
        upstream_candidate: false,
        sink: None,
        refusal: Some(resp),
    }
}

/// The `Retry-After` the door rendered, in whole seconds.
fn retry_after_secs(resp: &Response) -> Option<u32> {
    resp.headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestApp;
    use busbar_api::Store as _;
    use busbar_caps::{KernelSeal, LedgerToken, Posted, StepName, Usage, UsageToken};
    use busbar_store_memory::MemoryStore;
    use busbar_substrate::testkit::engine_kit::EngineTestKit as _;
    use std::collections::BTreeMap;
    use std::time::Instant;

    /// A deployment that resolves every name the same way. One answer is all any case here needs:
    /// what the step does with the answer is the whole question, and the resolution itself is the
    /// Route step's and is proven there.
    struct Cells(Resolved);

    impl DestinationCells for Cells {
        fn resolve(&self, _name: &str) -> Resolved {
            self.0
        }
    }

    /// The three ledger figures every identity here is pinned on.
    ///
    /// `requests` is the admission count — drawn at the door and never released, which is the rule
    /// that makes a request cap impossible to escape by failing. `billable_requests` is the fee
    /// base — the counter a non-2xx end refunds. `spend_cents` is the derived figure the door
    /// itself compares against a budget cap: tokens priced at the current card, plus the flat fee
    /// per billable request, truncated once to whole cents.
    #[derive(Debug, PartialEq, Eq)]
    struct Ledger {
        requests: u64,
        billable_requests: u64,
        spend_cents: i64,
    }

    /// The flat per-request fee every rig here prices, in whole cents. One cent makes the fee
    /// arithmetic readable: derived spend in cents IS the billable count.
    const FEE_CENTS: i64 = 1;

    /// A governed app with one key, a one-cent flat fee, and whatever groups the caller declares.
    fn governed(
        groups: BTreeMap<String, busbar_substrate::config::groups::GroupCfg>,
        group: Option<&str>,
        seed: Option<(&str, u64)>,
    ) -> (
        std::sync::Arc<crate::test_support::BuiltApp>,
        std::sync::Arc<busbar_api::VirtualKey>,
    ) {
        busbar_substrate::metrics::init();
        let store = std::sync::Arc::new(MemoryStore::new());
        if let Some((bucket, requests)) = seed {
            store
                .put_usage(
                    bucket,
                    0,
                    &busbar_api::UsageLedger {
                        requests,
                        billable_requests: requests,
                        models: vec![],
                    },
                )
                .expect("seed the durable bucket");
        }
        let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
            .governance(store, None, None)
            .expect("governance");
        let (key, _) = gov
            .create_key(
                busbar_substrate::governance::NewKeySpec {
                    name: "identity".to_string(),
                    allowed_pools: None,
                    group: group.map(str::to_string),
                    labels: Default::default(),
                    ..Default::default()
                },
                1_700_000_000,
            )
            .expect("create key");
        let cost =
            crate::test_support::engine_kit::CORE_ENGINE_KIT.cost_parts(None, FEE_CENTS, &groups);
        // Enforcement is in-memory and authoritative, so the seeded durable spend has to be
        // hydrated into the cells exactly as boot hydrates it; without this the door would not see
        // it and would admit.
        gov.hydrate_budgets(cost.as_ref(), 0).expect("hydrate");
        let app = TestApp::new().governance_kit(gov).cost_kit(cost).build();
        (app, std::sync::Arc::new(key))
    }

    /// Read one bucket's three figures off the same surfaces the enforcer and the dashboards read.
    fn ledger(
        app: &std::sync::Arc<crate::test_support::BuiltApp>,
        bucket: &str,
        now: u64,
    ) -> Ledger {
        let gov = app.governance.clone().expect("governance is configured");
        let derived = gov
            .derived_bucket_usage(&app.cost, bucket, "total", true, now)
            .expect("usage read");
        Ledger {
            requests: derived.requests,
            billable_requests: derived.requests,
            spend_cents: derived.spend_cents,
        }
    }

    /// The fee base apart from the admission count, off the durable row the flush writes.
    fn durable(app: &std::sync::Arc<crate::test_support::BuiltApp>, bucket: &str) -> (u64, u64) {
        let gov = app.governance.clone().expect("governance is configured");
        gov.flush_budgets();
        let row = gov.store().get_usage(bucket, 0).expect("ledger row");
        (row.requests, row.billable_requests)
    }

    /// A kernel seal for the length of one test: the tokens the step is lent are minted from it
    /// and dropped when the call returns, exactly as the loop lends them.
    fn tokens() -> (KernelSeal, UnitToken<Admit>, AdmitToken<Admit>) {
        let seal = KernelSeal::acquire_for_kernel();
        let unit = UnitToken::mint(&seal);
        let admit = AdmitToken::mint(&seal);
        (seal, unit, admit)
    }

    /// THE ADMITTED IDENTITY. One admitted request charges ONE admission slot and ONE fee-base
    /// unit on the key's bucket, and derives ONE cent of spend — and the step charges exactly the
    /// same figures, on the same counters, as the live door.
    ///
    /// The two legs run against one registry, so the second leg's figures are the first's plus the
    /// same delta: `(1, 1, 1)` after the live door, `(2, 2, 2)` after the step. A step that charged
    /// a different bucket, charged twice, or skipped the fee lookahead would move one of the three
    /// and not the others.
    #[tokio::test]
    async fn the_step_charges_the_same_slot_fee_base_and_cent_as_the_live_door() {
        let (app, key) = governed(BTreeMap::new(), None, None);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let gov = busbar_api::PlaneRequestCtx {
            key: Some(key.clone()),
        };
        let charged_at = busbar_substrate::store::now();

        // LEG 1 — the live door, reached through the very seam the plane's step calls.
        let live = match host.admission_door(
            &gov,
            crate::proto_codec::PROTO_OPENAI,
            "p",
            Instant::now(),
            charged_at,
        ) {
            Ok(admitted) => admitted,
            Err(resp) => panic!(
                "an uncapped key is under every cap; the door refused with {}",
                resp.status()
            ),
        };
        assert!(
            live.0.is_some(),
            "governance is on and a key resolved, so the charge landed"
        );
        assert!(live.1.is_none(), "no budget was exhausted, so no downgrade");
        drop(live);
        assert_eq!(
            ledger(&app, &key.id, charged_at),
            Ledger {
                requests: 1,
                billable_requests: 1,
                spend_cents: 1
            },
            "one admitted request: one slot, one fee-base unit, one cent of fee"
        );
        assert_eq!(
            durable(&app, &key.id),
            (1, 1),
            "and the durable row records the two counters apart"
        );

        // LEG 2 — the same door, through the step.
        let (seal, unit_token, admit_token) = tokens();
        let ctx = AdmitCtx {
            host: &host,
            cells: &Cells(Resolved::Pool { has_lane: true }),
            gov: &gov,
            proto: crate::proto_codec::PROTO_OPENAI,
            destination: "p",
            charged_at,
        };
        let admitted = admit(
            &unit_token,
            &admit_token,
            &ctx,
            &PrincipalId::new(key.id.clone()),
            &[],
        );
        assert!(admitted.charged, "the step's charge landed too");
        assert!(
            admitted.refusal.is_none(),
            "an admitted unit renders nothing"
        );
        assert!(
            admitted.effective_pool.is_none(),
            "nothing was downgraded, so the dispatch pool is the one the caller named"
        );
        assert!(
            admitted.sink.is_some(),
            "the admission's meter half is built here, with the admission"
        );
        assert_eq!(
            ledger(&app, &key.id, charged_at),
            Ledger {
                requests: 2,
                billable_requests: 2,
                spend_cents: 2
            },
            "the step charged the second request by the same delta on the same three figures"
        );
        assert_eq!(durable(&app, &key.id), (2, 2));

        // The hold the yes entitled the unit to, and the posting that closes it. Settling here is
        // this test standing in for the exit path: what matters is that the hold reaches one, that
        // it is opened for this principal, and that it reserves nothing it could refuse anyone
        // with.
        let admission = admitted
            .decision
            .into_result(&seal)
            .expect("the door said yes");
        let hold = match admission {
            Admission::Own(hold) => hold,
            Admission::Accrual(_) => {
                panic!("a client unit holds its own admission, not a parent's")
            }
            Admission::ZeroHold => panic!("an admitted client unit carries a hold"),
        };
        assert_eq!(hold.principal().as_str(), key.id.as_str());
        assert_eq!(
            hold.reserved(),
            0,
            "the hold is accounting; sizing it is later"
        );
        assert_eq!(hold.accrued(), 0, "nothing has been spent against it yet");
        let usage_token = UsageToken::mint(&seal);
        let posted = Posted::settle(
            hold,
            // Nothing was routed, so the priced total is zero — and it is passed as money rather
            // than derived from the report, which carries no lines to derive one from.
            0,
            &Usage::report(&usage_token, Vec::new()).expect("no lines is a legal report"),
            &LedgerToken::mint(&seal),
        );
        assert_eq!(posted.principal().as_str(), key.id.as_str());
        assert_eq!(
            posted.settled(),
            0,
            "nothing was routed, so nothing settled"
        );
    }

    /// THE REFUSED IDENTITY. An over-budget key is turned away with a 429 that charges NOTHING —
    /// and because nothing was charged there is nothing to refund, on either path.
    ///
    /// The rig seeds the group's total bucket with 250 requests, which at a one-cent flat fee
    /// derives to 250 cents against a 100-cent cap. Pass one of check-then-charge returns on that
    /// first blocking bucket having charged nothing, so all three figures on both the group bucket
    /// and the key bucket are the same before and after each refusal: `(250, 250, 250)` on the
    /// group, `(0, 0, 0)` on the key. A refund issued here would decrement a counter some other,
    /// legitimately-charged request in the same window put there.
    #[tokio::test]
    async fn over_budget_refuses_with_no_charge_and_nothing_to_refund() {
        let groups = BTreeMap::from([(
            "bgrp".to_string(),
            busbar_substrate::config::groups::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_substrate::config::groups::LimitCfg {
                    metric: busbar_substrate::config::groups::LimitMetric::Budget,
                    amount: 100,
                    per: Some(busbar_substrate::config::groups::LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        )]);
        let (app, key) = governed(groups, Some("bgrp"), Some(("group:bgrp@total", 250)));
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let gov = busbar_api::PlaneRequestCtx {
            key: Some(key.clone()),
        };
        let charged_at = busbar_substrate::store::now();

        let group_before = ledger(&app, "group:bgrp@total", charged_at);
        assert_eq!(
            group_before,
            Ledger {
                requests: 250,
                billable_requests: 250,
                spend_cents: 250
            },
            "250 seeded requests at a one-cent fee derive to 250 cents, over the 100-cent cap"
        );
        let key_before = ledger(&app, &key.id, charged_at);
        assert_eq!(
            key_before,
            Ledger {
                requests: 0,
                billable_requests: 0,
                spend_cents: 0
            },
            "this key has not been charged for anything yet"
        );

        // LEG 1 — the live door.
        let live = match host.admission_door(
            &gov,
            crate::proto_codec::PROTO_OPENAI,
            "p",
            Instant::now(),
            charged_at,
        ) {
            Err(resp) => resp,
            Ok(_) => panic!("the group's budget is exhausted; the door must refuse"),
        };
        assert_eq!(live.status().as_u16(), 429, "an exhausted budget is a 429");
        assert_eq!(ledger(&app, "group:bgrp@total", charged_at), group_before);
        assert_eq!(ledger(&app, &key.id, charged_at), key_before);

        // LEG 2 — the step. Same status, same untouched counters, no hold and no meter half.
        let (seal, unit_token, admit_token) = tokens();
        let ctx = AdmitCtx {
            host: &host,
            cells: &Cells(Resolved::Pool { has_lane: true }),
            gov: &gov,
            proto: crate::proto_codec::PROTO_OPENAI,
            destination: "p",
            charged_at,
        };
        let refused = admit(
            &unit_token,
            &admit_token,
            &ctx,
            &PrincipalId::new(key.id.clone()),
            &[],
        );
        assert!(!refused.charged, "nothing was charged");
        assert!(refused.sink.is_none(), "no admission, so no meter half");
        assert_eq!(
            refused
                .refusal
                .as_ref()
                .expect("the door rendered and finished its own bytes")
                .status()
                .as_u16(),
            429,
            "the step carries the door's status through untouched"
        );
        assert_eq!(
            ledger(&app, "group:bgrp@total", charged_at),
            group_before,
            "the step's refusal moved nothing on the blocking bucket"
        );
        assert_eq!(
            ledger(&app, &key.id, charged_at),
            key_before,
            "nor on the key's own"
        );

        let refusal = refused
            .decision
            .into_result(&seal)
            .expect_err("the door said no");
        assert_eq!(refusal.reason(), ReasonCode::OverBudget);
        assert_eq!(
            refusal.step(),
            Some(StepName::Admit),
            "the decision stamps the step, so the record cannot claim it stopped elsewhere"
        );
    }

    /// WHAT THE CHARGE LANDED ON, not what the caller spelled — on both facts the door hands out.
    ///
    /// **The cell.** A configured pool accrues under its own name and a bare model lane under the
    /// default (empty) cell, which is where the shipped path opens its own sink: it resolves the
    /// effective name first and passes the cell that resolution produced, and that cell is the empty
    /// one for a by-model lane. A sink opened on the caller's spelling instead would put a by-model
    /// request's token accrual on a pool bucket named after the model — a bucket nothing else in the
    /// deployment writes to, so a pool-scoped budget would never see the spend.
    ///
    /// **The slot.** A budget `on_exhaust: downgrade` re-pools the admission AFTER the verified set
    /// was sealed, and the set was sealed over the pool the caller asked for. So the set cannot say
    /// whether the unit has an upstream to route to: the pool the charge landed on is a different
    /// pool with a different membership. Here the set is EMPTY and the effective pool has a lane, and
    /// the door draws the slot, because the destination the charge is on is the one that can be
    /// dialled.
    #[tokio::test]
    async fn the_cell_and_the_slot_are_the_effective_destinations_and_not_the_callers() {
        let (app, key) = governed(BTreeMap::new(), None, None);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let gov = busbar_api::PlaneRequestCtx {
            key: Some(key.clone()),
        };
        let charged_at = busbar_substrate::store::now();
        let (_seal, unit_token, admit_token) = tokens();

        let admitted_on = |resolved: Resolved| {
            let cells = Cells(resolved);
            let ctx = AdmitCtx {
                host: &host,
                cells: &cells,
                gov: &gov,
                proto: crate::proto_codec::PROTO_OPENAI,
                destination: "m-openai-chat",
                charged_at,
            };
            admit(
                &unit_token,
                &admit_token,
                &ctx,
                &PrincipalId::new(key.id.clone()),
                &[],
            )
        };

        let lane = admitted_on(Resolved::Lane);
        assert_eq!(
            &*lane
                .sink
                .as_ref()
                .expect("governance is on and a key resolved")
                .pool,
            "",
            "a bare model lane belongs to no pool, so it accrues on the default cell"
        );
        assert!(
            lane.upstream_candidate,
            "a bare model name names one lane, so there is one to route to"
        );

        let pool = admitted_on(Resolved::Pool { has_lane: true });
        assert_eq!(
            &*pool
                .sink
                .as_ref()
                .expect("governance is on and a key resolved")
                .pool,
            "m-openai-chat",
            "a configured pool accrues under its own name"
        );
        assert!(
            pool.upstream_candidate,
            "the pool the charge landed on has a member, and the empty verified set was sealed \
             over a pool the charge is no longer on"
        );

        let empty = admitted_on(Resolved::Pool { has_lane: false });
        assert!(
            !empty.upstream_candidate,
            "an all-excluded pool is admitted and retains its slot, but there is nothing to dial"
        );
        assert!(
            !admitted_on(Resolved::Miss).upstream_candidate,
            "a name that resolves to nothing has no upstream; its 404 is charged, at the next step"
        );
    }

    /// EVERY DOOR REFUSAL IS FILED AS WHAT IT WAS, and served as what it always was.
    ///
    /// Three ways to be turned away at the door, and they are three different facts about a
    /// deployment: a group an administrator froze, a group at its in-flight ceiling, and a group
    /// whose budget is spent. A record that files all three as a spent budget cannot tell an
    /// operator which of the three happened, and the three need different answers — unfreeze the
    /// group, add capacity, raise the cap.
    ///
    /// The other half is that NOTHING THE CALLER SEES MOVES. Each case is driven through the live
    /// door and through the step against the same deployment, and the status and the whole rendered
    /// body are compared byte for byte: the reason the record carries rides beside those bytes and
    /// never in them.
    #[tokio::test]
    async fn each_door_refusal_is_filed_as_itself_and_served_as_it_always_was() {
        async fn body_of(resp: Response) -> Vec<u8> {
            use http_body_util::BodyExt;
            resp.into_body()
                .collect()
                .await
                .expect("an in-memory error body")
                .to_bytes()
                .to_vec()
        }

        // The three blocking shapes, each as the one group the key belongs to.
        let frozen = busbar_substrate::config::groups::GroupCfg {
            enabled: false,
            ..Default::default()
        };
        let one_limit = |metric, amount, per| busbar_substrate::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_substrate::config::groups::LimitCfg {
                metric,
                amount,
                per,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        };
        let saturated = one_limit(
            busbar_substrate::config::groups::LimitMetric::Concurrent,
            0,
            None,
        );
        let spent = one_limit(
            busbar_substrate::config::groups::LimitMetric::Budget,
            100,
            Some(busbar_substrate::config::groups::LimitWindow::Total),
        );

        for (name, cfg, seed, want) in [
            ("frozen", frozen, None, ReasonCode::GroupFrozen),
            ("saturated", saturated, None, ReasonCode::RateLimited),
            (
                "spent",
                spent,
                Some(("group:g@total", 250u64)),
                ReasonCode::OverBudget,
            ),
        ] {
            let groups = BTreeMap::from([("g".to_string(), cfg)]);
            let (app, key) = governed(groups, Some("g"), seed);
            let (host, _rt) = crate::engine::test_host_rt(&app);
            let gov = busbar_api::PlaneRequestCtx {
                key: Some(key.clone()),
            };
            let charged_at = busbar_substrate::store::now();

            // LEG 1 — the live door, which is what a client is served today.
            let live = host
                .admission_door(
                    &gov,
                    crate::proto_codec::PROTO_OPENAI,
                    "p",
                    Instant::now(),
                    charged_at,
                )
                .err()
                .unwrap_or_else(|| panic!("{name}: the door must refuse"));
            let live_status = live.status().as_u16();
            let live_body = body_of(*live).await;

            // LEG 2 — the step.
            let (seal, unit_token, admit_token) = tokens();
            let cells = Cells(Resolved::Pool { has_lane: true });
            let ctx = AdmitCtx {
                host: &host,
                cells: &cells,
                gov: &gov,
                proto: crate::proto_codec::PROTO_OPENAI,
                destination: "p",
                charged_at,
            };
            let refused = admit(
                &unit_token,
                &admit_token,
                &ctx,
                &PrincipalId::new(key.id.clone()),
                &[],
            );
            let served = refused
                .refusal
                .expect("the door rendered and finished its own bytes");
            assert_eq!(served.status().as_u16(), live_status, "{name}: status");
            assert_eq!(body_of(served).await, live_body, "{name}: body");

            let refusal = refused
                .decision
                .into_result(&seal)
                .expect_err("the door said no");
            assert_eq!(
                refusal.reason(),
                want,
                "{name}: the journal carries the bucket that actually blocked"
            );
            assert_eq!(
                refusal.step(),
                Some(StepName::Admit),
                "{name}: and the step it blocked at"
            );
        }
    }

    /// The step is the `Units::admit` row's shape, as a value: a mismatch in the tokens, the
    /// principal, the verified set or the answer stops compiling here rather than at the root.
    #[test]
    fn the_step_has_the_doors_shape() {
        let _: AdmitStep = admit;
    }
}
