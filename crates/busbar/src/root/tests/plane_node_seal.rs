// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A unit's one audit record names where the unit went and the controls it ran under (audit
//! root-R1#1; THE DESIGN §1: "what (unit key, op class, verified destination) ... controls
//! (hold/settle seqs, slice, hooks applied)"). Driven through the node both ways a unit reaches it:
//! handed by a plane's arrival ([`Node::answer`]) and borrowed by a plane driver
//! ([`Node::drive_borrowed`]).

use super::*;
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival, Authenticate, Consumption, Decode, Dial, Encode, Meter,
    Refusal, SeatVerdict, Verify,
};
use busbar_kernel::slice::GroupLeaseSlip;

use busbar_contract::caps::{
    Admission, ArrivalRecord, Authenticated, Frame, ReasonCode, RoutePlan, ScopeFacts, Usage,
};

/// The one destination Verify seals for the unit: the lane its record must name.
const DESTINATION: &str = "seal-dest-d";

/// A unit that passes every step and routes to [`DESTINATION`], the one destination it seals.
struct ToDestination;

impl ToDestination {
    fn op_class() -> OpClassId {
        OpClassId::new("call")
    }
}

impl busbar_kernel::teller::DoorSeats for ToDestination {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        SeatVerdict::proceed(
            token,
            ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: Vec::new(),
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        SeatVerdict::proceed(token, Self::op_class())
    }

    fn authenticate(
        &self,
        token: &Pass<Authenticate>,
        _ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(
            token,
            Authenticated::Principal(PrincipalId::new("acct:seal")),
        )
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        SeatVerdict::proceed(
            token,
            vec![VerifiedDestination::seal(trust, LaneId::new(DESTINATION))],
        )
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        _admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        // The arrival hold is the hold the exit settles: the unit runs under it.
        SeatVerdict::proceed(token, Admission::ZeroHold)
    }
}

impl busbar_kernel::teller::UnitEnds for ToDestination {
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        // Reached through the awaited leg below, never here.
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::TaskLost))
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        SeatVerdict::proceed(
            token,
            Usage::report(usage, Vec::new()).expect("an empty usage report never overflows"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Complete,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::AuditFacts {
                op_class: Self::op_class(),
                finish: busbar_contract::FinishClass::Error,
            },
        )
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        SeatVerdict::proceed(
            token,
            Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

impl RouteAwait for ToDestination {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(async move { SeatVerdict::proceed(token, RoutePlan::default()) })
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
}

/// The unit, as a plane's arrival hands it to the node.
fn handed() -> Handed {
    let build: crate::root::linked::node::Build = Box::new(
        |_lent: crate::root::linked::node::Lent| -> crate::root::linked::node::Built {
            let units: Arc<dyn busbar_kernel::teller::SeatedUnits + Send + Sync> =
                Arc::new(ToDestination);
            let route: Arc<dyn RouteAwait + Send + Sync> = Arc::new(ToDestination);
            let finish: crate::root::linked::node::Finish =
                Box::new(|| -> (Option<PlaneAnswer>, Option<Late>) { (None, None) });
            (units, route, finish)
        },
    );
    (
        PrincipalId::new("acct:seal"),
        ToDestination::op_class(),
        "seal-test",
        build,
    )
}

/// The one record the node sealed names [`DESTINATION`], and no hold or settlement: the journal
/// carries none (MONEY-DESIGN §2c, PR-C).
fn assert_sealed_with_destination_and_controls(book: &crate::root::durability::NodeBook) {
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 1, "one record for the one unit: {records:?}");
    let record = &records[0];
    assert_eq!(
        record.what.destination.as_deref(),
        Some(DESTINATION),
        "the record names the verified destination the unit routed to"
    );
    assert_eq!(record.controls.hold_ref, None, "no hold is journalled");
    assert_eq!(
        record.controls.settle_ref, None,
        "no settlement is journalled"
    );
}

/// A HANDED unit that routes to destination D seals a record whose destination is D. RED before
/// root-R1#1: the record carried `destination: None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handed_unit_seals_its_verified_destination() {
    let node = Node::new();
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let _answer = node.answer(handed()).await;
    assert_sealed_with_destination_and_controls(&book);
}

/// The same, for a unit a plane driver lends the node ([`Node::drive_borrowed`]): its facts ride the
/// posting site's open entry to the seal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_borrowed_unit_seals_its_verified_destination() {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let outcome = node
        .drive_borrowed(
            node.mint(),
            node.arrived(),
            &PrincipalId::new("acct:seal"),
            &post,
            &ToDestination,
            Box::new(|| -> Option<Reported> { None }),
            None,
            None,
            OpClassId::new("seal"),
        )
        .await;
    assert!(outcome.is_some(), "the table took the unit and it ended");
    assert_eq!(post.open_units(), 0, "its facts closed at its end");
    assert_sealed_with_destination_and_controls(&book);
}

/// [`ToDestination`], refused at its approve step: a session whose door says no.
struct RefusedAtApprove;

impl busbar_kernel::teller::DoorSeats for RefusedAtApprove {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        ToDestination.arrival(token, ctx)
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode> {
        ToDestination.decode(token, ctx)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        ToDestination.authenticate(token, ctx)
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        ToDestination.verify(token, trust, ctx, principal)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::refuse(token, Refusal::new(ReasonCode::ScopeDenied))
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        ToDestination.admit(token, admit, ctx, principal, destinations, leases)
    }
}

impl busbar_kernel::teller::UnitEnds for RefusedAtApprove {
    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        ToDestination.route(token, ctx, destinations)
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        ToDestination.meter(token, usage, ctx, provisional, destinations)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        ToDestination.audit(token, ctx, outcome)
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        ToDestination.audit_refused(token, ctx, refusal)
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        ToDestination.encode(token, ctx, outcome)
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        ToDestination.evidence(ctx)
    }
}

/// Open one session on `node` through `units`, end it on its own path, and hand back its key.
async fn open_and_finish<U: Units>(
    node: &Arc<Node>,
    post: &NodeEndPost,
    units: &U,
) -> (UnitKey, bool) {
    let key = node.mint();
    let (opened, _ctx, slot) = node
        .open_borrowed(
            key,
            node.arrived(),
            &PrincipalId::new("acct:seal"),
            post,
            units,
            None,
            OpClassId::new("seal"),
        )
        .await
        .expect("the table took the session");
    let admitted = matches!(opened, busbar_kernel::teller::SessionOpen::Admitted { .. });
    slot.finish(post);
    (key, admitted)
}

/// AN ADMITTED DUPLEX SESSION seals its one fixed record when it ends (audit R1#2; THE DESIGN §1
/// "The audit step writes one fixed record, for every plane"): the session's key, how its audit step
/// said it went, and the destination its open sealed. RED before the fix: the session's audit pass
/// was handed back at its open and dropped at `SessionSlot::finish`, so nothing reached the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_session_seals_one_record_when_it_ends() {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let (key, admitted) = open_and_finish(&node, &post, &ToDestination).await;
    assert!(admitted, "the door passed the session");
    assert_eq!(post.open_units(), 0, "its facts closed at its end");
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(
        records.len(),
        1,
        "one record for the one session: {records:?}"
    );
    let record = &records[0];
    assert_eq!(record.what.unit_key, key);
    assert_eq!(record.outcome.unit_end, Outcome::Completed);
    assert_eq!(
        record.what.destination.as_deref(),
        Some(DESTINATION),
        "the record names the destination the session's open sealed"
    );
    assert!(durability.retained_audit_findings().is_empty());
}

/// A SESSION REFUSED AT ITS OPEN gets a record too (THE DESIGN §7 U14: "a refused unit gets a record
/// too"): outcome refused, with the refusal's reason, and no amount. RED before audit R1#2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_refused_at_its_open_seals_a_refused_record() {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let (key, admitted) = open_and_finish(&node, &post, &RefusedAtApprove).await;
    assert!(!admitted, "the door refused the session");
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(
        records.len(),
        1,
        "a refused session gets a record: {records:?}"
    );
    let record = &records[0];
    assert_eq!(record.what.unit_key, key);
    assert!(
        matches!(
            record.outcome.unit_end,
            Outcome::Refused(_, ReasonCode::ScopeDenied)
        ),
        "the record says the session was refused, and why: {:?}",
        record.outcome
    );
    assert!(
        record.usage.lines.is_empty(),
        "a refused unit has no amount"
    );
}

/// [`ToDestination`], whose route leg's hook stage ran `hooks`: the kernel's hook stage reports
/// them to the node at the head of the leg, through the port a driver is built with
/// ([`busbar_kernel::plane_driver::HookJournal`], audit root#3). `None`: no hook bound, and a
/// stage that ran none reports nothing.
struct Hooked<'p> {
    post: &'p NodeEndPost,
    hooks: Option<Vec<busbar_kernel_audit::HookApplied>>,
}

impl busbar_kernel::teller::DoorSeats for Hooked<'_> {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        ToDestination.arrival(token, ctx)
    }

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode> {
        ToDestination.decode(token, ctx)
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        ToDestination.authenticate(token, ctx)
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        ToDestination.verify(token, trust, ctx, principal)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        ToDestination.approve(token, ctx, principal, destinations)
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        ToDestination.admit(token, admit, ctx, principal, destinations, leases)
    }
}

impl busbar_kernel::teller::UnitEnds for Hooked<'_> {
    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        ToDestination.route(token, ctx, destinations)
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        ToDestination.meter(token, usage, ctx, provisional, destinations)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        ToDestination.audit(token, ctx, outcome)
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        ToDestination.audit_refused(token, ctx, refusal)
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        ToDestination.encode(token, ctx, outcome)
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        ToDestination.evidence(ctx)
    }
}

impl RouteAwait for Hooked<'_> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        // THE HOOK STAGE, at the head of the leg: what ran is reported under the unit's key.
        if let Some(hooks) = &self.hooks {
            busbar_kernel::plane_driver::HookJournal::hooks_ran(
                self.post,
                &busbar_kernel::plane_driver::HooksRan {
                    unit: ctx.key,
                    hooks: hooks.clone(),
                },
            );
        }
        ToDestination.route_leg(token, ctx, destinations)
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
}

/// One hook that ran, keyed `hook`.
fn ran(
    hook: &str,
    head: busbar_kernel_audit::HookHead,
    failed: bool,
) -> busbar_kernel_audit::HookApplied {
    busbar_kernel_audit::HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

/// Drive one borrowed unit whose hook stage ran `hooks` (none: a unit no hook binds, which reports
/// nothing) and hand back the one record the node sealed for it.
async fn sealed_after(
    hooks: Option<Vec<busbar_kernel_audit::HookApplied>>,
) -> busbar_kernel_audit::AuditRecord {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let hooked = Hooked { post: &post, hooks };
    let outcome = node
        .drive_borrowed(
            node.mint(),
            node.arrived(),
            &PrincipalId::new("acct:seal"),
            &post,
            &hooked,
            Box::new(|| -> Option<Reported> { None }),
            None,
            None,
            OpClassId::new("seal"),
        )
        .await;
    assert!(outcome.is_some(), "the table took the unit and it ended");
    assert_eq!(post.open_units(), 0, "its facts closed at its end");
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 1, "one record for the one unit: {records:?}");
    records.into_iter().next().expect("one record")
}

/// A UNIT THAT PASSED TWO SEATED HOOKS seals a record whose "hooks applied" lists both, in the
/// order they ran, each by its key with its decision head (audit root#3; THE DESIGN §1: "controls
/// (hold/settle seqs, slice, hooks applied)"). RED before the fix: the node sealed
/// `hooks_applied: []` whatever the unit's hook stage ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_that_passed_two_hooks_seals_both_in_order_with_their_heads() {
    use busbar_kernel_audit::HookHead;
    let record = sealed_after(Some(vec![
        ran("screen", HookHead::Pass, false),
        ran("compress", HookHead::Modify, false),
    ]))
    .await;
    assert_eq!(
        record.controls.hooks_applied,
        vec![
            ran("screen", HookHead::Pass, false),
            ran("compress", HookHead::Modify, false),
        ],
        "the record lists every hook that ran, in order, with its head"
    );
    assert!(!record.outcome.hook_failed, "no hook failed");
}

/// A HOOK THAT FAILED is recorded failed, never dropped: the record lists it with its failure, and
/// says a hook failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_whose_hook_failed_seals_it_as_failed() {
    use busbar_kernel_audit::HookHead;
    let record = sealed_after(Some(vec![
        ran("screen", HookHead::Pass, true),
        ran("compress", HookHead::Modify, false),
    ]))
    .await;
    assert_eq!(
        record.controls.hooks_applied,
        vec![
            ran("screen", HookHead::Pass, true),
            ran("compress", HookHead::Modify, false),
        ],
        "the failed hook is in the record, marked failed"
    );
    assert!(record.outcome.hook_failed, "the record says a hook failed");
}

/// A UNIT NO HOOK RAN FOR seals an empty "hooks applied": the record never invents one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_with_no_hooks_seals_an_empty_hook_list() {
    let record = sealed_after(None).await;
    assert!(
        record.controls.hooks_applied.is_empty(),
        "no hook ran, none is listed: {:?}",
        record.controls.hooks_applied
    );
    assert!(!record.outcome.hook_failed, "no hook failed");
}

/// A card history pinned at its head: one entry per `(effective_from_ms, author)`, in append order,
/// each holding the absent card (these units report nothing, so no price is read off it).
fn pinned(
    entries: Vec<(u64, busbar_kernel_ledger::cost::Author)>,
) -> crate::root::kernel::PinnedHistory {
    let mut history = busbar_kernel_ledger::cost::History::new();
    let mut head = busbar_kernel_ledger::cost::HistorySeq::OPENING;
    for (effective_from, author) in entries {
        head = history.append(busbar_kernel_ledger::cost::CardEntryDraft {
            effective_from,
            effective_until: None,
            card: crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                false,
            ),
            appended_at: effective_from,
            author,
        });
    }
    crate::root::kernel::PinnedHistory::for_test(Arc::new(history), head)
}

/// A configuration write's entry, produced by policy generation `policy_epoch`.
fn configured(policy_epoch: u64) -> busbar_kernel_ledger::cost::Author {
    busbar_kernel_ledger::cost::Author::Config { policy_epoch }
}

/// Drive one borrowed [`ToDestination`] unit admitted under the history `history` builds for its
/// arrival instant (in milliseconds), and hand back the one record the node sealed for it.
async fn sealed_under(
    history: impl FnOnce(u64) -> Option<crate::root::kernel::PinnedHistory>,
) -> busbar_kernel_audit::AuditRecord {
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    let arrived = node.arrived();
    let outcome = node
        .drive_borrowed(
            node.mint(),
            arrived,
            &PrincipalId::new("acct:seal"),
            &post,
            &ToDestination,
            Box::new(|| -> Option<Reported> { None }),
            history(arrived.ms()),
            None,
            OpClassId::new("seal"),
        )
        .await;
    assert!(outcome.is_some(), "the table took the unit and it ended");
    assert_eq!(post.open_units(), 0, "its facts closed at its end");
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let records = durability.audit_records.clone();
    assert_eq!(records.len(), 1, "one record for the one unit: {records:?}");
    records.into_iter().next().expect("one record")
}

/// A UNIT SEALS THE POLICY GENERATION IT RAN UNDER: the policy epoch of the configuration whose
/// card was in force when it ARRIVED, off the history pinned at its door — not the head's, when a
/// later configuration takes effect after the arrival (audit root r4 B-4; THE DESIGN §1,
/// `BUSBAR-1.6.0.md` l.190-193: the fixed record's "controls", "never optional"). Its card version
/// is read off the same entry at the same instant, as it always was. RED before the fix: the node
/// sealed `Controls::default()` beside the hold and settle refs, so `policy_epoch` was 0 whatever
/// generation the unit ran under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_seals_the_policy_epoch_of_the_configuration_in_force_when_it_arrived() {
    let record = sealed_under(|arrived_ms| {
        Some(pinned(vec![
            (0, configured(3)),
            (arrived_ms.saturating_add(60_000), configured(5)),
        ]))
    })
    .await;
    assert_eq!(
        record.controls.policy_epoch, 3,
        "the record names the generation of the configuration in force at the unit's arrival"
    );
    assert_eq!(
        record.usage.rate_card_version, 0,
        "and its card is the entry in force at that same instant, not the head"
    );
}

/// AN AMENDMENT IS NO POLICY GENERATION: a unit whose arrival an amendment re-prices still ran under
/// the configuration beneath it, and its record names that configuration's epoch, while its card
/// version names the amendment that priced it (audit root r4 B-4; THE DESIGN §1, l.190-193). RED
/// before the fix: `policy_epoch` was 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_under_an_amended_card_seals_the_configuration_beneath_it() {
    let record = sealed_under(|_| {
        Some(pinned(vec![
            (0, configured(4)),
            (
                0,
                busbar_kernel_ledger::cost::Author::Amend {
                    reason_hash: [7; 32],
                },
            ),
        ]))
    })
    .await;
    assert_eq!(
        record.controls.policy_epoch, 4,
        "an amendment corrects a price; the generation is the configuration's"
    );
    assert_eq!(
        record.usage.rate_card_version, 1,
        "the card version is the amendment that priced the arrival"
    );
}

/// GREEN TWIN: a unit admitted under NO card history names no policy generation (0, the journal's
/// "no epoch to report") and the opening card, exactly as before the fix — the record never invents
/// a generation (audit root r4 B-4; THE DESIGN §1, l.190-193).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_admitted_under_no_history_seals_no_policy_generation() {
    let record = sealed_under(|_| None).await;
    assert_eq!(record.controls.policy_epoch, 0, "no history, no generation");
    assert_eq!(
        record.usage.rate_card_version,
        busbar_kernel_ledger::cost::HistorySeq::OPENING.get(),
        "and the opening card, as before"
    );
}
