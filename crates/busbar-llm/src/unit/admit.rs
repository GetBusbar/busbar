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
//! One call: `EngineHost::admission_door`, with the same five arguments the live path passes at
//! `native_ingress.rs`'s `drive`. Behind that seam is core's `admission_door` → `admit_check` →
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
//! rendered and finished the refusal by the time it returns it — those are the bytes the client
//! gets, and this step carries them through untouched rather than re-deriving them from the reason
//! code.
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
use std::time::Instant;

use axum::response::Response;
use busbar_caps::{
    step::Admit, Admission, AdmitToken, Decision, Hold, PrincipalId, ReasonCode, Refusal,
    UnitToken, VerifiedDestination,
};
use busbar_substrate::plane_host::EngineHost;

/// What the door needs that the step shape has nowhere to put.
///
/// The pinned arrival epoch is the important one: both the flat fee charged here and the token fee
/// charged at stream end are attributed to the window this epoch implies, so a request whose
/// response completes in a later window than its headers arrived cannot split its two charges
/// across two windows.
pub struct AdmitCtx<'a> {
    /// The neutral host seam the door is reached through.
    pub host: &'a Arc<dyn EngineHost>,
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The ingress protocol name, for the refusal's native error envelope.
    pub proto: &'static str,
    /// The destination the caller named: a pool, or a model that resolves to one lane.
    pub destination: &'a str,
    /// When the request started, for the finish-stage latency observation.
    pub started: Instant,
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
    /// Read by the Route step, which carries it to every accrual site, and by Meter. `allow` while
    /// the module is dark: nothing installs these steps yet, so the reader does not exist to the
    /// compiler until the Route step lands.
    #[allow(dead_code)]
    pub(crate) sink: Option<crate::engine::UsageSink>,
    /// The door's own rendered refusal, already finished through the not-charged terminal. Present
    /// exactly when the decision refuses.
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
/// The verified set is read for one fact only: whether there is an upstream to route to. Every
/// destination this plane verifies is an upstream lane, so a non-empty set is that fact; the kind
/// tag that would say so directly is not on a verified destination yet.
pub fn admit(
    unit_token: &UnitToken<Admit>,
    admit_token: &AdmitToken<Admit>,
    ctx: &AdmitCtx<'_>,
    principal: &PrincipalId,
    destinations: &[VerifiedDestination],
) -> Admitted {
    // THE door. Its `Err` is the refusal ALREADY rendered in the ingress protocol's native
    // envelope and already finished through the not-charged terminal — nothing was charged, so
    // nothing is refunded on the way out.
    match ctx.host.admission_door(
        ctx.gov,
        ctx.proto,
        ctx.destination,
        ctx.started,
        ctx.charged_at,
    ) {
        Err(resp) => refused(unit_token, *resp),
        Ok((admit, downgraded)) => {
            // `Some` iff the charge landed. Governance off or no resolved key admits without
            // charging, and that request must finish with `charged = false`.
            let charged = admit.is_some();
            // A budget downgrade re-pooled the admission: the accrual scope is the pool the charge
            // landed on, not the one the caller asked for, so the sink is built against it.
            let pool = downgraded.as_deref().unwrap_or(ctx.destination);
            let sink =
                crate::native_ingress::usage_sink(ctx.host, ctx.gov, pool, ctx.charged_at, admit);
            Admitted {
                // The hold is opened at zero: it is accounting, and sizing it is the ledger
                // phase's. See this module's header for why a small hold cannot refuse anyone.
                decision: Decision::proceed(
                    unit_token,
                    Admission::Own(Hold::open(admit_token, principal.clone(), 0)),
                ),
                charged,
                effective_pool: downgraded,
                upstream_candidate: !destinations.is_empty(),
                sink,
                refusal: None,
            }
        }
    }
}

/// A door refusal: no hold, no charge, no refund, and the door's own bytes carried through.
///
/// The reason code is the record's closed vocabulary, and the seam this step reaches the door
/// through hands back a rendered response rather than the blocking bucket, so the code cannot be
/// narrowed past "a budget in the chain had no headroom" from here. The byte-exact refusal — the
/// status, the `kind`, the message and the retry hint an SDK reads — is the response itself, which
/// is why it is carried rather than re-derived. The retry hint is lifted onto the refusal so the
/// record carries the same number the wire does.
fn refused(unit_token: &UnitToken<Admit>, resp: Response) -> Admitted {
    let mut refusal = Refusal::new(ReasonCode::OverBudget);
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
    use busbar_api::Store as _;
    use busbar_caps::{KernelSeal, LedgerToken, Posted, StepName, Usage, UsageToken};
    use busbar_core::governance::{GovState, MemoryStore};
    use busbar_core::test_support::TestApp;
    use std::collections::BTreeMap;

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
        groups: BTreeMap<String, busbar_core::config::GroupCfg>,
        group: Option<&str>,
        seed: Option<(&str, u64)>,
    ) -> (
        std::sync::Arc<busbar_core::state::App>,
        std::sync::Arc<busbar_api::VirtualKey>,
    ) {
        busbar_core::metrics::init();
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
        let gov =
            std::sync::Arc::new(GovState::new_with_signer(store, None, None).expect("governance"));
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
        let cost = busbar_core::cost::CostModel::resolve_parts(None, FEE_CENTS, &groups);
        // Enforcement is in-memory and authoritative, so the seeded durable spend has to be
        // hydrated into the cells exactly as boot hydrates it; without this the door would not see
        // it and would admit.
        gov.hydrate_budgets(&cost, 0).expect("hydrate");
        let app = TestApp::new().governance(gov).cost(cost).build();
        (app, std::sync::Arc::new(key))
    }

    /// Read one bucket's three figures off the same surfaces the enforcer and the dashboards read.
    fn ledger(app: &std::sync::Arc<busbar_core::state::App>, bucket: &str, now: u64) -> Ledger {
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
    fn durable(app: &std::sync::Arc<busbar_core::state::App>, bucket: &str) -> (u64, u64) {
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
            gov: &gov,
            proto: crate::proto_codec::PROTO_OPENAI,
            destination: "p",
            started: Instant::now(),
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
            busbar_core::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_core::config::groups::LimitCfg {
                    metric: busbar_core::config::groups::LimitMetric::Budget,
                    amount: 100,
                    per: Some(busbar_core::config::groups::LimitWindow::Total),
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
            gov: &gov,
            proto: crate::proto_codec::PROTO_OPENAI,
            destination: "p",
            started: Instant::now(),
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
            StepName::Admit,
            "the decision stamps the step, so the record cannot claim it stopped elsewhere"
        );
    }

    /// The step is the `Units::admit` row's shape, as a value: a mismatch in the tokens, the
    /// principal, the verified set or the answer stops compiling here rather than at the root.
    #[test]
    fn the_step_has_the_doors_shape() {
        let _: AdmitStep = admit;
    }
}
