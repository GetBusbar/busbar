//! Tests for `kernel.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The fee an apply carries reaches the head, and the snapshot a reader already pinned is
/// unmoved.
///
/// The two halves of the append, asserted together because either alone is a half-truth. A
/// holder that took the new fee but let its existing readers see it would bill a request on
/// rates it was never admitted under; a holder that left its readers alone by never taking the
/// new fee at all would pass the second assertion and be the boot-bound card this replaced. The
/// fee is read as the card's own unit price for its flat line, which is where a configured fee
/// ends up.
#[test]
fn an_apply_moves_the_head_and_leaves_a_pinned_reader_on_the_snapshot_it_took() {
    let holder = RootHistory::default();
    assert!(
        holder.pin().is_none(),
        "a holder that has heard no apply prices nothing"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    let admitted = holder.pin().expect("the first apply put an entry in place");
    assert_eq!(
        fee_at(&admitted, 1_000),
        30_000_000,
        "the first apply's fee did not reach the entry a reader resolves to"
    );

    // The apply a request in flight must not feel.
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    assert_eq!(
        fee_at(&admitted, 5_000),
        30_000_000,
        "a reader that pinned before the apply was repriced by it, at every instant of its life"
    );
    let next = holder
        .pin()
        .expect("the second apply put an entry in place");
    assert_eq!(
        fee_at(&next, 5_000),
        110_000_000,
        "the apply did not reach the next admission's snapshot"
    );
}

/// The flat fee the entry in force at `at` names. The one reading the tests below compare cards
/// by, so that a comparison is a lookup rather than a field peek.
fn fee_at(pinned: &PinnedHistory, at: u64) -> u128 {
    pinned
        .view()
        .card_at(at)
        .expect("an entry covers the instant")
        .1
        .fee_unit_price_nanos()
}

/// **APPEND, NEVER REWRITE.** A reload puts a SECOND entry on the history and leaves the first
/// exactly as it was written.
///
/// This is the invariant the whole design rests on and it is the one the previous holder broke
/// by construction: it stored one card and a second apply overwrote it, so every posting the
/// node had ever taken silently re-priced at the new figure on the next read. Three assertions,
/// because two of them alone would pass on a holder that replaced: the count MOVES, the first
/// entry's card is UNCHANGED, and the first entry's number is unchanged too — a history that
/// renumbered would break every invoice that named a snapshot.
#[test]
fn a_reload_appends_and_never_rewrites_the_entry_before_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(29), 3_000);

    assert_eq!(
        holder.len(),
        3,
        "three applies left fewer than three entries, so one of them overwrote another"
    );

    let head = holder.pin().expect("three applies put a head in place");
    let view = head.view();
    let entries = view.entries();
    assert_eq!(
        entries[0].card().fee_unit_price_nanos(),
        30_000_000,
        "the entry the first apply wrote was rewritten by a later one"
    );
    assert_eq!(
        entries[0].seq(),
        busbar_kernel_ledger::cost::HistorySeq(0),
        "the first entry was renumbered, which unmakes every invoice that named a snapshot"
    );
    assert_eq!(entries[1].card().fee_unit_price_nanos(), 110_000_000);
    assert_eq!(entries[2].card().fee_unit_price_nanos(), 290_000_000);
}

/// **AN ENTRY PRICES WHAT HAPPENS AFTER IT.** An instant before a reload resolves to the entry
/// that was in force then, and an instant after it resolves to the new one — on the same
/// snapshot, read at the same moment.
///
/// The heart of the model stated as one lookup: the answer depends on WHEN the unit arrived and
/// not on when the question is asked. A holder that replaced its card answers the same figure
/// for both instants, which is exactly the recorded 1.5.5 behaviour this replaces.
#[test]
fn an_instant_before_a_reload_resolves_to_the_entry_that_was_in_force_then() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);

    let head = holder.pin().expect("two applies put a head in place");
    assert_eq!(
        fee_at(&head, 1_500),
        30_000_000,
        "a unit that arrived before the reload was re-priced at the card that replaced it"
    );
    assert_eq!(
        fee_at(&head, 2_500),
        110_000_000,
        "a unit that arrived after the reload was priced at the card it superseded"
    );
}

/// **THE FIRST ENTRY COVERS EVERY INSTANT BEFORE IT**, because a hole is a refusal and a request
/// the node dated a millisecond before its own boot is not a free request.
///
/// A first entry effective from the boot instant would leave instant zero — and every legacy row
/// carrying nothing finer than a UTC day — resolving to nothing, which the lookup reports as
/// unpriceable and the settlement posts as no row at all.
#[test]
fn the_first_entry_covers_every_instant_before_the_boot_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 9_000_000);
    let head = holder.pin().expect("the apply put an entry in place");
    assert_eq!(
        fee_at(&head, 0),
        30_000_000,
        "instant zero fell in a hole, so a pre-boot row prices at nothing"
    );
    assert_eq!(fee_at(&head, 8_999_999), 30_000_000);
}

/// Every entry a config apply writes says so, and says which generation of the configuration
/// wrote it. The boot resolution is epoch 0 and each apply after it is the next.
#[test]
fn every_config_apply_records_the_generation_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let head = holder.pin().expect("two applies put a head in place");
    let view = head.view();
    let epochs: Vec<busbar_kernel_ledger::cost::Author> =
        view.entries().iter().map(|e| e.author().clone()).collect();
    assert_eq!(
        epochs,
        vec![
            busbar_kernel_ledger::cost::Author::Config { policy_epoch: 0 },
            busbar_kernel_ledger::cost::Author::Config { policy_epoch: 1 },
        ]
    );
}

/// **THE CARD A CONFIG APPLY BUILDS CARRIES THE FEE IT WAS CONFIGURED WITH, AT THE ONE SCALE.**
///
/// This stands where `the_card_an_apply_builds_prices_the_currency_the_node_reads_it_in` stood.
/// That case caught a card built in one denomination and read in another — the lookup would report
/// `CurrencyNotPriced`, which a caller that mapped errors to zero would post as a free request.
/// #66 (`BUSBAR-1.6.0.md:528`) removes the denomination, so the mismatch cannot be CONSTRUCTED
/// rather than merely refused; what is left to assert is that the configured figure reaches the
/// card unmoved and at the one scale.
#[test]
fn the_card_an_apply_builds_carries_its_configured_fee_at_the_one_scale() {
    let holder = RootHistory::default();
    holder.apply(
        super::card_from_config(
            std::iter::empty::<(&str, busbar_substrate_values::billing::RawTierRates)>(),
            7,
            true,
        ),
        1_000,
    );
    let head = holder.pin().expect("the apply put an entry in place");
    let view = head.view();
    let (_, card) = view.card_at(1_000).expect("an entry covers it");
    assert_eq!(card.fee(), 7, "the configured fee reached the card unmoved");
    assert_eq!(
        card.fee_unit_price_nanos(),
        7 * busbar_kernel_ledger::cost::NANOS_PER_CENT,
        "the fee lifts to nano-units at the one scale and no other"
    );
}

/// **EVERY DATED CARD PRICES THE OPEN CLASSES THE LIVE ONE DOES** (item 123 × Q14, P2-rootfollow).
///
/// A rerank lane prices `search_units` at 5 µ/unit, then an edit mid-window moves it to 3 µ/unit.
/// 1,000,000 units were earned under the first card and 2,000,000 under the second. The history
/// entry each era resolves to is built by the SAME builder a rate apply uses, so the older era's
/// card carries the open-class cell: 5,000,000 + 6,000,000 = 11,000,000 micro (1,100 minor), and
/// nothing refuses. Before the builder carried `units`, the older era's card had no
/// `search_units` cell and the whole read REFUSED with `ClassUnpriced`.
#[test]
fn a_card_edit_mid_window_prices_an_open_class_in_both_eras_and_refuses_neither() {
    let zero = busbar_substrate_values::billing::RawTierRates {
        input: 0.0,
        output: 0.0,
        cache_read: 0.0,
        cache_write: 0.0,
    };
    let lanes = [("rerank".to_string(), zero)];
    let era = |nanos: u64| [("rerank".to_string(), "search_units".to_string(), nanos)];
    let (before, after) = (era(5_000), era(3_000));
    let no_fees = busbar_kernel::config::PlaneFeesMap::new();
    let raw = |units| busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units,
        flat_minor: 0,
        present: true,
        plane_fees: &no_fees,
    };

    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));

    let earned_before = std::collections::BTreeMap::from([("search_units".to_string(), 1_000_000)]);
    let earned_after = std::collections::BTreeMap::from([("search_units".to_string(), 2_000_000)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [
            ("rerank", 0, &earned_before),
            ("rerank", 2_000, &earned_after),
        ],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("an open class the older era's card priced must price, not refuse");
    assert_eq!(
        priced.micros(),
        11_000_000,
        "each era at the open-class rate in force when it was earned"
    );
}

/// **A PLANE'S FEES ARE DATED WITH THE CARD** (#47 × Q14, OWNER RULING Q32). Plane `tp` charges 3
/// minor units a request, then an edit mid-window moves it to 7. 2 requests were earned under the
/// first card and 1 under the second: 2 × 3 + 1 × 7 = 13 minor units — each era at the fees in force
/// when it was earned, because every dated entry is built with the plane fees its apply carried.
#[test]
fn a_fee_edit_mid_window_prices_each_era_at_the_plane_fee_in_force() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PlaneFees, PER_REQUEST};
    let fees = |per_request| {
        let f = PlaneFees {
            per_request,
            per_session: 0,
        };
        busbar_kernel::config::PlaneFeesMap::from([("tp".to_string(), f)])
    };
    let (before, after) = (fees(3), fees(7));
    let raw = |plane_fees| busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 5,
        present: false,
        plane_fees,
    };
    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));
    let lane = plane_fee_lane("tp");
    let two = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 2)]);
    let one = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 1)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [(lane.as_str(), 0, &two), (lane.as_str(), 2_000, &one)],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("a plane's fee units price");
    assert_eq!(priced.minor(), 13, "each era at the plane fee in force");
}

/// A chain with one module in it, so the front door is CLOSED without needing a governance state
/// to close it. What the grant reads is the posture, not the module, so a module that answers
/// nothing is enough to state the posture with.
struct NeverIdentifies;

impl busbar_kernel_identity::module::AuthModule for NeverIdentifies {
    fn name(&self) -> &'static str {
        "never"
    }
    fn authenticate(
        &self,
        _candidate: Option<&str>,
    ) -> busbar_kernel_identity::module::AuthOutcome {
        busbar_kernel_identity::module::AuthOutcome::Pass
    }
}

fn a_closed_door() -> AuthChain {
    AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "never".to_string(),
            module: Box::new(NeverIdentifies),
        }],
        false,
    )
}

/// THE GRANT'S THREE ARMS, which used to be one.
///
/// `Full` was returned to every caller without reading who it was, which is right for exactly
/// one of the three postures below and wrong for the other two. The third arm is the one that
/// matters: a principal some other module identified, carrying no roles and therefore nothing
/// bound to read a scope out of, used to be handed the operator's own ceiling.
#[cfg(feature = "root-admin")]
#[test]
fn the_admin_grant_is_the_previous_releases_three_arms() {
    let open = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ));
    assert_eq!(
        open.admin_grant(&PrincipalId::new("anonymous")),
        Some(busbar_core_admin::VerbScope::Full),
        "the explicit open posture — no credential configured — is full, as it has always been"
    );

    let closed = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ))
    .with_auth_chain(a_closed_door());
    assert_eq!(
        closed.admin_grant(&PrincipalId::new(
            crate::root::auth_bindings::ADMIN_PRINCIPAL_ID
        )),
        Some(busbar_core_admin::VerbScope::Full),
        "the operator credential is the root credential, and carries the full tier by definition"
    );
    assert_eq!(
        closed.admin_grant(&PrincipalId::new("somebody-else")),
        None,
        "a roleless principal that is not the operator holds NO grant — not a narrower one, \
         which would still be authority this deployment never wrote down"
    );
}

/// A unit no plane on this node composed is not sealed as an administrative read.
///
/// Both audit doors are asked, because both used to answer with the admin plane's word for a
/// verb that did not resolve: a plane unit refused at the root came out of the record as an
/// operator reading a page. The assertion is written as an inequality against that word as well
/// as an equality on the right one, because what matters is not which class replaced it but
/// that no unit of another plane wears the admin plane's.
#[cfg(feature = "root-admin")]
#[test]
fn a_unit_this_root_did_not_compose_is_not_sealed_as_an_admin_read() {
    let units = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ));
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    let ctx = UnitCtx {
        key: busbar_contract::ids::UnitKey::new(9),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    assert!(
        !units.is_admin(&ctx),
        "the fixture must be a unit the admin plane never claimed"
    );
    let admin_read = busbar_contract::ids::OpClassId::new("admin_read");

    let token: Pass<Audit> = Pass::mint(&seal);
    let refused = units
        .audit_refused(
            &token,
            &ctx,
            &Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
        .into_result(&seal)
        .expect("the door seals a record for a unit it did not compose");
    assert_ne!(refused.op_class, admin_read);
    assert_eq!(
        refused.op_class,
        busbar_contract::ids::OpClassId::new(OP_UNCLAIMED)
    );
    assert_eq!(refused.finish, busbar_contract::FinishClass::Error);

    let token: Pass<Audit> = Pass::mint(&seal);
    let ended = units
        .audit(&token, &ctx, &Outcome::Completed)
        .into_result(&seal)
        .expect("the other door seals one too");
    assert_ne!(ended.op_class, admin_read);
    assert_eq!(
        ended.op_class,
        busbar_contract::ids::OpClassId::new(OP_UNCLAIMED)
    );
    assert_eq!(ended.finish, busbar_contract::FinishClass::Complete);
}

/// The point of the skeleton: the shape compiles against the real trait, and the real trait is
/// the kernel's. A `ProductionUnits` that did not satisfy `Units` would be a plan, not a root.
#[test]
fn production_units_is_the_kernels_units_trait() {
    fn assert_units<U: Units>() {}
    assert_units::<ProductionUnits>();
}

/// The arrival door is the admission unit's, and a hold it opens reserves nothing — the point
/// of the arrival hold is that even a refusal is an event with a cell of its own to settle.
#[test]
fn the_arrival_door_opens_a_hold_that_reserves_nothing() {
    let kernel = new_kernel();
    let door = AdmissionDoor;
    let hold = busbar_kernel::inflight::arrival_hold(&kernel, &door, PrincipalId::new("k-7"));
    assert_eq!(hold.reserved(), 0);
    assert_eq!(hold.principal(), &PrincipalId::new("k-7"));
}

/// The whole assembly, end to end: a kernel, a durability stack that opened nothing, the
/// configured breaker ladders and a scope policy that permits only what it was told about —
/// composed into the one type the loop reaches a unit through.
///
/// Every argument is a value configuration decided. That is the shape that makes it impossible
/// to build these units and forget one: there is no constructor that fills a policy in from a
/// default.
#[test]
fn the_units_assemble_from_values_configuration_decided() {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let units = ProductionUnits::new(
        &kernel,
        AuthChain::new(Vec::new(), false),
        durability,
        crate::root::adapters::BreakerPolicy::new(),
        crate::root::policy::ScopePolicy::new(),
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(std::sync::Arc::new(
            crate::root::units_admin::RefusingDispatch,
        )),
        std::sync::Arc::new(RefusingStore),
    );

    // Nothing is in flight before anything arrives, which is the machine-checkable half of
    // "an entry that outlived its unit would be a leak per request".
    #[cfg(feature = "root-admin")]
    assert!(units.admin.units.is_empty());

    // The journal opened nothing, the ledger is dual-writing, and the scope policy permits
    // nothing until it is told to. All three are the safe end of a choice that had an unsafe
    // end, and all three are checkable here rather than at the first request.
    let durability = units.durability.lock().expect("durability lock");
    assert!(!durability.on_disk());
    assert!(durability.ledger.is_dual_writing());
    assert!(units.scope_policy.is_empty());
}

/// **The units carry no metering policy, and the root has no pool-expansion boot check** (items
/// 239/246).
///
/// `ProductionUnits.meter_policy` was built from `MeterPolicyConfig::default()` at its one
/// production site and read by nothing, and `pools_without_expansion` — the check written to guard
/// it — had no production caller. Neither priced anything: what prices a unit is the rate card,
/// through the one function Tally governs. A policy field on the assembly is a second place a
/// reader would look for how a unit is priced, and it would answer with an empty default. So the
/// assembly holds none, and the check that guarded it is gone with it.
#[test]
fn the_units_carry_no_metering_policy_and_the_root_names_no_pool_check() {
    fn code(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    let kernel = code(include_str!("../kernel.rs"));
    let start = kernel
        .find("pub struct ProductionUnits {")
        .expect("the assembly is declared in kernel.rs");
    let body = &kernel[start..];
    let body = &body[..body.find("\n}").expect("the struct closes")];
    assert!(
        !body.contains("meter_policy") && !body.contains("MeterPolicyHandle"),
        "ProductionUnits carries a metering policy again"
    );
    assert!(
        !code(include_str!("../policy.rs")).contains("fn pools_without_expansion"),
        "the root grew its unread pool-expansion check back"
    );
}

/// The breaker unit the root assembles reports an unrecognized `error_map` class rather than
/// swallowing it.
///
/// The unit's own default sink is a noop, which is 1.5.5's behaviour for the classification
/// RESULT and also for the warning — the mapping is ignored either way, and before this
/// binding nothing said so. What is asserted here is the composition: the sink the root builds
/// is reached from the unit the root assembled, through the port the egress unit classifies
/// over, without any test double standing in for either side.
///
/// The sink is a recording one rather than the tracing one, because what needs proving is that
/// the value ARRIVES; where it goes afterwards is `adapters::TracingDiagnostics`, and asserting
/// on a log line would be asserting on the subscriber a test happened to install.
#[test]
fn an_unrecognized_error_map_class_reaches_the_roots_sink() {
    #[derive(Debug, Default)]
    struct RecordingSink(Mutex<Vec<String>>);

    impl busbar_kernel_breaker::classify::Diagnostics for RecordingSink {
        fn unrecognized_error_map_value(&self, value: &str) {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(value.to_string());
        }
    }

    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let mut units = ProductionUnits::new(
        &kernel,
        AuthChain::new(Vec::new(), false),
        durability,
        crate::root::adapters::BreakerPolicy::new(),
        crate::root::policy::ScopePolicy::new(),
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(Arc::new(
            crate::root::units_admin::RefusingDispatch,
        )),
        Arc::new(RefusingStore),
    );

    // The same assembly the constructor performs, over a sink this test can read back. The
    // production sink is `adapters::root_diagnostics()`; the width is the same one, which is
    // what makes the substitution a substitution rather than a different composition.
    let sink = Arc::new(RecordingSink::default());
    units.breaker = crate::root::adapters::BreakerAdapter::with_diagnostics(
        Arc::clone(&sink) as crate::root::adapters::DiagnosticsSink,
        crate::root::adapters::BreakerPolicy::new(),
    );

    let destination = busbar_kernel_breaker::DestinationId::new(11);
    units.breaker.unit().set_error_map(
        destination,
        std::collections::HashMap::from([("503".to_string(), "rate_limt".to_string())]),
    );

    let classified = busbar_kernel_egress::ports::Breaker::classify(
        &units.breaker,
        destination,
        busbar_kernel_egress::ports::UpstreamStatus {
            code: Some(busbar_contract::WireStatus::new(
                busbar_contract::transport::status_ns::HTTP,
                503,
            )),
            class: None,
            retry_after: None,
        },
    );

    assert_eq!(
        sink.0.lock().expect("sink lock").as_slice(),
        ["rate_limt".to_string()],
        "the unrecognized class reached the sink the root bound"
    );
    assert_eq!(
        classified.disposition,
        busbar_kernel_egress::ports::Disposition::TransientUpstream,
        "and the mapping stayed ignored: the 503 classified from its HTTP status"
    );
}

/// The interner is idempotent, which is what makes "leaked exactly once" a property of the
/// type rather than of the caller's discipline.
#[test]
fn the_interner_leaks_a_repeated_key_once() {
    let mut registration = new_registration();
    let first = registration
        .key("lane-a")
        .expect("an unfrozen image interns a key");
    let second = registration
        .key("lane-a")
        .expect("a repeated key is the same key");
    assert!(std::ptr::eq(first, second));
    assert_eq!(registration.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE USAGE READ'S DATED-HISTORY SEAM (DECISION #79)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The holder hands a reader the WHOLE history, and hands a node that has resolved nothing
/// NOTHING.
///
/// [`RootHistory::pin`] fixes the head for a request's whole life; a ledger READ wants the
/// entries and its own choice of snapshot, so it takes the `Arc` instead. The absent arm is the
/// half worth asserting: a node that has read no configuration must answer "no history" rather
/// than an empty one, because an empty history prices every instant at nothing and nothing is a
/// price.
#[test]
fn the_holder_hands_a_reader_the_whole_history_and_an_unresolved_node_none() {
    let holder = RootHistory::default();
    assert!(
        holder.history().is_none(),
        "a node that has resolved no configuration has no history to hand over"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let history = holder.history().expect("two applies are a history");
    assert_eq!(
        history.len(),
        2,
        "the reader sees every entry, not just the head"
    );
    assert_eq!(
        history.head(),
        Some(busbar_kernel_ledger::cost::HistorySeq(1)),
        "and the numbers are the holder's own, so a snapshot names the same entry twice"
    );
}

/// The seam the usage read asks through answers with the PROCESS history and nothing of its own.
///
/// A delegation is the whole implementation, so the assertion is that the two readings agree —
/// an implementor that built its own history would answer a different length the moment the
/// process's moved, and an invoice would be priced against a history no apply ever reached.
#[test]
fn the_usage_seam_answers_with_the_process_history() {
    use busbar_core_admin::v1::service::UsageRateHistory as _;
    assert_eq!(
        RootUsageHistory.history().map(|h| h.len()),
        ROOT_CARD.history().map(|h| h.len()),
        "the seam answers from a history the process never resolved"
    );
    assert_eq!(
        RootUsageHistory.history().and_then(|h| h.head()),
        ROOT_CARD.history().and_then(|h| h.head()),
        "the seam and the holder disagree about which entry is the head"
    );
}

/// **THE WIRING WITNESS.** The boot install raises BOTH halves of the rate seam, and the binary
/// calls it.
///
/// The apply half without the read half is precisely the defect #79 names: a node that dates its
/// prices and then reports them off the newest card anyway. The date half without the other two
/// stamps an instant nothing reads. And any of them without a caller is dead code that looks live.
/// So the body of `install_card_repricer` is read for all three names, and `main.rs` is read for
/// the call — four facts that have to hold together for the seam to be reachable in the shipped
/// binary, and no one of which implies the others.
#[test]
fn the_boot_install_raises_both_halves_of_the_rate_seam_and_main_calls_it() {
    let kernel = include_str!("../kernel.rs");
    let body = kernel
        .split("pub fn install_card_repricer() {")
        .nth(1)
        .expect("install_card_repricer is declared")
        .split("\n}")
        .next()
        .expect("its body closes");
    assert!(
        body.contains("install_rate_apply"),
        "the boot install stopped raising the APPLY half: {body}"
    );
    assert!(
        body.contains("install_rate_epoch"),
        "the boot install stopped raising the DATE half — a metering cell would carry no instant \
         finer than its UTC day and a mid-day card edit would reprice the whole day (#79): {body}"
    );
    assert!(
        body.contains("install_usage_rate_history"),
        "the boot install stopped raising the READ half — the usage read would price off the \
         newest card again (#79): {body}"
    );
    let main = include_str!("../../main.rs");
    assert!(
        main.contains("install_card_repricer()"),
        "nothing in the binary calls the boot install, so neither half is ever raised"
    );
}

// ---------------------------------------------------------------------------------------------
// The dated history, journalled (#79, OWNER RULING Q14 "date everything")
// ---------------------------------------------------------------------------------------------

/// The flat lane the history tests price.
const FLAT_LANE: &str = "gpt";
/// The `mcp` plane's own lane (#47): its card prices it, at twice the flat card's rate.
const PLANE_LANE: &str = "mcp\u{1f}search";

/// When the history tests' events land, in wall-clock milliseconds.
const BOOT_A: u64 = 1_000;
const EARNED_A: u64 = 10_000;
const APPLIED_B: u64 = 20_000;
const EARNED_B: u64 = 30_000;
const REBOOT: u64 = 40_000;
const REBOOT_CHANGED: u64 = 50_000;

fn tiers(input: f64) -> busbar_substrate_values::billing::RawTierRates {
    busbar_substrate_values::billing::RawTierRates {
        input,
        output: 0.0,
        cache_read: 0.0,
        cache_write: 0.0,
    }
}

/// The deployment's lanes at one price: [`FLAT_LANE`] at `price` micro-units an input token, and
/// the `mcp` plane's card (its presence key and [`PLANE_LANE`]) at twice that.
fn lanes_at(price: f64) -> Vec<(String, busbar_substrate_values::billing::RawTierRates)> {
    vec![
        (FLAT_LANE.to_string(), tiers(price)),
        ("mcp\u{1f}".to_string(), tiers(0.0)),
        (PLANE_LANE.to_string(), tiers(2.0 * price)),
    ]
}

fn plane_fees() -> busbar_kernel::config::PlaneFeesMap {
    busbar_kernel::config::PlaneFeesMap::from([(
        "mcp".to_string(),
        busbar_kernel_ledger::cost::PlaneFees {
            per_request: 7,
            per_session: 11,
        },
    )])
}

/// The engine resolving the deployment at `price`, heard by `holder` at `at`.
fn apply_at(holder: &RootHistory, price: f64, at: u64) {
    let lanes = lanes_at(price);
    let fees = plane_fees();
    holder.apply_rates(
        &busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[("gpt".to_string(), "search_units".to_string(), 2_000)],
            flat_minor: 4,
            present: true,
            plane_fees: &fees,
        },
        at,
    );
}

/// A PROCESS'S holder: fresh, armed as the production boot arms `ROOT_CARD`, and `'static` as the
/// process holder is.
fn process_holder() -> &'static RootHistory {
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    holder
}

/// A directory of the test's own for a node's journal.
fn journal_dir(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-root-card-history-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

/// The boot's book over `dir`, rebuilding `holder`'s dated history from its chain and pricing the
/// replay through it — `build_for_node` with the holder named.
fn boot_book(
    holder: &'static RootHistory,
    dir: &std::path::Path,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let book = crate::root::durability::build_with_cards(
        &crate::root::durability::DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(move || holder.pin()),
        Some(holder),
    )
    .expect("the journal opens");
    let book = Arc::new(Mutex::new(book));
    holder.bind_journal(&book);
    book
}

fn bucket(name: &str) -> busbar_kernel_ledger::totals::TotalsKey {
    use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};
    TotalsKey::new(
        BucketId::new(name),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// One unit of `input` tokens on `lane`, arriving at `arrived_ms` and settled at `amount` — the
/// figure the unit's exit priced at the card it pinned.
fn settle(
    book: &Arc<Mutex<crate::root::durability::Durability>>,
    name: &str,
    lane: &str,
    input: u64,
    amount: u64,
    arrived_ms: u64,
) {
    use busbar_contract::caps::{DurableWrite, HoldAccrual, KernelSeal, Posted, WriteMoney};
    let seal = KernelSeal::acquire_for_kernel();
    let money = Grant::<WriteMoney>::mint(&seal);
    let posted = Posted::settle_late(
        HoldAccrual::after_terminal(PrincipalId::new(name), amount, &money),
        &money,
    );
    let token = Grant::<DurableWrite>::mint(&seal);
    let key = bucket(name);
    book.lock()
        .expect("the book")
        .settle_counted(
            &crate::root::durability::Settling {
                key: &key,
                window: 86_400,
                durability: &token,
                step: busbar_contract::caps::StepName::Meter,
                stamp: crate::root::durability::PostingStamp {
                    rate_card_version: 0,
                    wall: arrived_ms / 1_000,
                    mono: arrived_ms,
                },
            },
            posted,
            &crate::root::durability::UnitCounts {
                lane: lane.to_string(),
                fee_count: 0,
                classes: std::collections::BTreeMap::from([("input".to_string(), input)]),
            },
            arrived_ms,
        )
        .expect("the journal takes the posting");
}

/// The settled figure on `name`'s balance, in nano-units.
fn settled(book: &Arc<Mutex<crate::root::durability::Durability>>, name: &str) -> i128 {
    book.lock()
        .expect("the book")
        .ledger
        .book()
        .get(&bucket(name), 86_400)
        .settled
}

/// How many applied cards the chain holds.
fn cards_on_chain(book: &Arc<Mutex<crate::root::durability::Durability>>) -> usize {
    book.lock()
        .expect("the book")
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter(|r| super::CardApplied::from_body(&r.body).is_some())
        .count()
}

/// `GET /admin/usage`'s dated derivation of one metering row of `input` tokens on [`FLAT_LANE`]
/// dated `priced_from_ms`, through `holder`'s history — the history the read is handed
/// (`RootUsageHistory` hands the process holder's).
fn usage_row_micros(holder: &RootHistory, priced_from_ms: u64, input: u64) -> i64 {
    let history = holder.history().expect("a resolved history");
    let live = history
        .current()
        .card_at(u64::MAX)
        .map(|(_, card)| card.clone())
        .expect("a head card");
    let cost = busbar_kernel::cost::CostModel::resolve_parts(
        Some(&std::collections::BTreeMap::from([(
            FLAT_LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                ..Default::default()
            },
        )])),
        0,
        &std::collections::BTreeMap::new(),
    );
    busbar_core_admin::v1::service::read_path_money::derive_spend_micros_row_at_card(
        &history.current(),
        priced_from_ms,
        &live,
        &cost,
        FLAT_LANE,
        &busbar_kernel::admin::v1::contract::UsageBreakdown {
            tokens_input: input,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 0,
            spend_micros: 0,
        },
    )
    .expect("the row prices")
}

/// **A RESTART NEVER REPRICES WHAT ALREADY HAPPENED** (#79, OWNER RULING Q14).
///
/// Card A prices [`FLAT_LANE`] at 3 micro-units an input token (the `mcp` plane's lane at 6); a
/// million tokens are earned on each. Card B is applied live — 5 (plane 10) — and another million is
/// earned on each. The node restarts. Every posting on the chain is replayed at the card in force
/// when it ARRIVED: flat 3,000,000,000 + 5,000,000,000 = 8,000,000,000 nano-units, plane
/// 6,000,000,000 + 10,000,000,000 = 16,000,000,000 — the figures the node served before the
/// restart. Before the applied cards were journalled, the rebuilt history was the boot card B from
/// instant zero and the same chain replayed as 10,000,000,000 and 20,000,000,000.
///
/// The usage read resolves through the same rebuilt history: the A-era row (dated 0, the opening
/// entry) at 3,000,000 micro-units and the B-era row (dated at B's apply) at 5,000,000 —
/// 8,000,000 in all, where the restart used to read 10,000,000.
///
/// A second restart with no price change appends nothing and moves nothing; a third that changes
/// the price to C prices from its boot forward and leaves every earlier figure where it was.
#[test]
fn a_restart_prices_every_posting_at_the_card_in_force_when_it_arrived() {
    let dir = journal_dir("restart");

    // THE FIRST PROCESS: boots at A, earns, applies B live, earns again.
    let figures_before = {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &dir);
        settle(&book, "flat", FLAT_LANE, 1_000_000, 3_000_000_000, EARNED_A);
        settle(
            &book,
            "plane",
            PLANE_LANE,
            1_000_000,
            6_000_000_000,
            EARNED_A,
        );
        apply_at(holder, 5.0, APPLIED_B);
        settle(&book, "flat", FLAT_LANE, 1_000_000, 5_000_000_000, EARNED_B);
        settle(
            &book,
            "plane",
            PLANE_LANE,
            1_000_000,
            10_000_000_000,
            EARNED_B,
        );
        assert_eq!(cards_on_chain(&book), 2, "the boot card and the live apply");
        (settled(&book, "flat"), settled(&book, "plane"))
    };
    assert_eq!(figures_before, (8_000_000_000, 16_000_000_000));

    // THE RESTART, at the price B already set.
    let holder = process_holder();
    apply_at(holder, 5.0, REBOOT);
    let book = boot_book(holder, &dir);
    assert_eq!(
        (settled(&book, "flat"), settled(&book, "plane")),
        figures_before,
        "a restart repriced a posting at a card that was not in force when it arrived"
    );
    assert!(book.lock().expect("the book").restart_findings.is_empty());
    assert_eq!(
        holder.len(),
        2,
        "a restart that changed no price appends no entry"
    );
    assert_eq!(cards_on_chain(&book), 2, "and journals none");
    assert_eq!(
        (
            usage_row_micros(holder, 0, 1_000_000),
            usage_row_micros(holder, APPLIED_B, 1_000_000),
        ),
        (3_000_000, 5_000_000),
        "the usage read prices each era at its own card after a restart"
    );
    drop(book);

    // A RESTART THAT CHANGES THE PRICE prices from its boot forward, and nothing before it.
    let holder = process_holder();
    apply_at(holder, 7.0, REBOOT_CHANGED);
    let book = boot_book(holder, &dir);
    assert_eq!(
        (settled(&book, "flat"), settled(&book, "plane")),
        figures_before
    );
    assert_eq!(holder.len(), 3);
    assert_eq!(cards_on_chain(&book), 3);
    let history = holder.history().expect("a history");
    let price_at = |lane: &str, at: u64| {
        history
            .current()
            .card_at(at)
            .and_then(|(_, card)| card.lane_rates(lane).map(|r| r.nanos_per_unit("input")))
    };
    assert_eq!(
        [EARNED_A, EARNED_B, REBOOT_CHANGED].map(|at| price_at(FLAT_LANE, at)),
        [Some(3_000), Some(5_000), Some(7_000)]
    );
    assert_eq!(
        [EARNED_A, EARNED_B, REBOOT_CHANGED].map(|at| price_at(PLANE_LANE, at)),
        [Some(6_000), Some(10_000), Some(14_000)],
        "the plane's own card is dated with the rest"
    );
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A holder that was not armed — every test holder, and a build with no root ledger — rebuilds
/// nothing and journals nothing; a node with NO data directory keeps the boot card from instant
/// zero exactly as the previous release did, and writes no card anywhere.
#[test]
fn no_data_dir_or_no_arming_keeps_the_boot_card_and_journals_nothing() {
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = crate::root::durability::build_with_cards(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(move || holder.pin()),
        Some(holder),
    )
    .expect("memory-buffered cannot fail");
    let book = Arc::new(Mutex::new(book));
    holder.bind_journal(&book);
    apply_at(holder, 5.0, APPLIED_B);
    assert_eq!(
        cards_on_chain(&book),
        0,
        "no data directory, no card journalled"
    );
    assert_eq!(holder.len(), 2);
    assert_eq!(
        holder
            .history()
            .expect("a history")
            .entries()
            .first()
            .map(busbar_kernel_ledger::cost::CardEntry::effective_from),
        Some(0),
        "the boot card opens the history from instant zero"
    );

    let unarmed: &'static RootHistory = Box::leak(Box::default());
    apply_at(unarmed, 3.0, BOOT_A);
    let dir = journal_dir("unarmed");
    let book = crate::root::durability::build_with_cards(
        &crate::root::durability::DurabilityConfig {
            data_dir: Some(dir.clone()),
        },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(move || unarmed.pin()),
        Some(unarmed),
    )
    .expect("the journal opens");
    let book = Arc::new(Mutex::new(book));
    unarmed.bind_journal(&book);
    apply_at(unarmed, 5.0, APPLIED_B);
    assert_eq!(
        cards_on_chain(&book),
        0,
        "an unarmed holder journals nothing"
    );
    drop(book);
    let _ = std::fs::remove_dir_all(&dir);
}

/// **AN APPLIED CARD ROUND-TRIPS THE JOURNAL AS THE SAME CARD, EVERY PLANE INCLUDED** (#47): the
/// flat lane's four classes and its open class, the plane's own lane, an unconfigured lane on each
/// (refused, #42), and each plane's fees read back identically off the rebuilt card.
#[test]
fn an_applied_card_round_trips_the_journal_as_the_same_card_on_every_plane() {
    let lanes = lanes_at(3.0);
    let fees = plane_fees();
    let units = [("gpt".to_string(), "search_units".to_string(), 2_000)];
    let raw = busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 4,
        present: true,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&raw);
    let applied = super::CardApplied {
        effective_from: APPLIED_B,
        appended_at: APPLIED_B,
        policy_epoch: 3,
        form: super::CardForm::of(&raw, &card),
    };
    let read = super::CardApplied::from_body(&applied.body()).expect("the body reads back");
    assert_eq!(read, applied);
    let rebuilt = read.form.card();
    let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane("mcp");
    for lane in [
        FLAT_LANE,
        PLANE_LANE,
        "other",
        "mcp\u{1f}other",
        fee_lane.as_str(),
    ] {
        assert_eq!(
            rebuilt.lane_unpriced(lane),
            card.lane_unpriced(lane),
            "{lane}"
        );
        for class in [
            "input",
            "output",
            "cache_read",
            "cache_write",
            "search_units",
        ] {
            let of = |c: &busbar_kernel_ledger::cost::RateCard| {
                c.lane_rates(lane)
                    .map(|r| (r.nanos_per_unit(class), r.class_priced(class)))
            };
            assert_eq!(of(&rebuilt), of(&card), "{lane} {class}");
        }
        for class in ["per_request", "per_session"] {
            assert_eq!(
                rebuilt.plane_lane(lane).0.fee_of(class),
                card.plane_lane(lane).0.fee_of(class),
                "{lane} {class}"
            );
        }
    }
    assert_eq!(rebuilt.fee(), card.fee());
    assert_eq!(rebuilt.pricing_enabled(), card.pricing_enabled());
    assert!(
        super::CardApplied::from_body(b"not a card").is_none(),
        "another Policy record is not read as a card"
    );

    // An ABSENT card round-trips absent, fee and plane fees included.
    let absent = busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 9,
        present: false,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&absent);
    let rebuilt = super::CardForm::of(&absent, &card).card();
    assert!(!rebuilt.pricing_enabled());
    assert_eq!(rebuilt.fee(), 9);
    assert_eq!(
        rebuilt.plane_lane(&fee_lane).0.fee_of("per_session"),
        Some(11)
    );
}
